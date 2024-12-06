use super::message::*;
use super::MessageChannels;
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tokio::{task, try_join};

pub struct Config<F = DefaultIPv4TcpSocketFactory>
where
    F: TcpSocketFactory,
{
    pub max_outstanding_requests: usize,
    pub connection_keep_alive: Duration,
    pub socket_factory: F,
}

impl Default for Config<DefaultIPv4TcpSocketFactory> {
    fn default() -> Self {
        Config {
            max_outstanding_requests: 10,
            connection_keep_alive: Duration::from_secs(300),
            socket_factory: DefaultIPv4TcpSocketFactory,
        }
    }
}

pub fn setup_tcp<T: TcpSocketFactory>(config: Config<T>) -> (MessageChannels, ConnectionPool<T>) {
    let (ingress_sender, ingress_receiver) = mpsc::channel(config.max_outstanding_requests);
    let (egress_sender, egress_receiver) = mpsc::channel(1);
    (
        MessageChannels {
            egress_sink: egress_sender,
            ingress_source: ingress_receiver,
        },
        ConnectionPool {
            connections: Default::default(),
            egress_source: egress_receiver,
            ingress_sink: ingress_sender,
            config,
        },
    )
}

pub trait TcpSocketFactory {
    fn new_socket(&mut self) -> io::Result<TcpSocket>;
}

pub struct DefaultIPv4TcpSocketFactory;

impl TcpSocketFactory for DefaultIPv4TcpSocketFactory {
    fn new_socket(&mut self) -> io::Result<TcpSocket> {
        let socket = TcpSocket::new_v4()?;
        socket.set_nodelay(true)?;
        Ok(socket)
    }
}

pub struct ConnectionPool<F: TcpSocketFactory> {
    connections: HashMap<SocketAddr, mpsc::Sender<Message>>,
    egress_source: mpsc::Receiver<(Message, SocketAddr)>,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    config: Config<F>,
}

impl<F: TcpSocketFactory> ConnectionPool<F> {
    pub async fn run(mut self) {
        while let Some((message, remote_addr)) = self.egress_source.recv().await {
            if let Entry::Occupied(occupied_entry) = self.connections.entry(remote_addr) {
                match occupied_entry.get().try_reserve() {
                    Ok(sender) => {
                        sender.send(message);
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::error!("Dropping message to {remote_addr}: tx channel is full");
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        log::info!("Reconnecting to {remote_addr}");
                    }
                }
                occupied_entry.remove();
            }
            // if we ended up here, we need to create a new connection
            match self.launch_new_connection(remote_addr) {
                Ok(egress_sink) if egress_sink.try_send(message).is_ok() => {
                    self.connections.insert(remote_addr, egress_sink);
                }
                _ => log::error!("Failed to connect to {remote_addr}, dropping tx message"),
            }
        }
    }

    fn launch_new_connection(
        &mut self,
        remote_addr: SocketAddr,
    ) -> io::Result<mpsc::Sender<Message>> {
        let socket = self.config.socket_factory.new_socket().inspect_err(|e| {
            log::error!("Failed to create TCP socket: {e}");
        })?;
        let (egress_sender, egress_receiver) = mpsc::channel(self.config.max_outstanding_requests);
        let ingress_sink = self.ingress_sink.clone();
        let inactivity_timeout = self.config.connection_keep_alive;
        task::spawn_local(async move {
            run_connection(
                socket,
                remote_addr,
                ingress_sink,
                egress_receiver,
                inactivity_timeout,
            )
            .await
            .inspect_err(|e| log::warn!("Connection to {remote_addr} closed: {e}"))
        });
        Ok(egress_sender)
    }
}

async fn run_connection(
    socket: TcpSocket,
    remote_addr: SocketAddr,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    egress_source: mpsc::Receiver<Message>,
    inactivity_timeout: Duration,
) -> io::Result<()> {
    log::trace!("Connecting to {remote_addr}");
    let mut stream = time::timeout(IO_TIMEOUT, socket.connect(remote_addr)).await??;
    log::debug!("Successfully connected to {remote_addr}");

    let (rx, tx) = stream.split();
    let last_active = Cell::new(Instant::now());
    try_join!(
        process_ingress(rx, ingress_sink, remote_addr, &last_active),
        process_egress(tx, egress_source, &last_active),
        detect_inactivity(inactivity_timeout, &last_active),
    )?;
    Ok(())
}

const BUFFER_LEN: usize = 1500;
const IO_TIMEOUT: Duration = Duration::from_secs(39);

async fn process_ingress(
    socket: impl AsyncRead + Unpin,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    remote_addr: SocketAddr,
    last_active: &Cell<Instant>,
) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(BUFFER_LEN, socket);
    let mut buffer = [0u8; BUFFER_LEN];
    loop {
        reader.fill_buf().await?;

        let header_buffer = &mut buffer[..Header::SIZE];
        time::timeout(IO_TIMEOUT, reader.read_exact(header_buffer)).await??;
        let header = Header::decode_from(&mut &*header_buffer)?;

        let tlvs_len = header.length as usize;
        let tlvs_buffer = &mut buffer[..tlvs_len];
        time::timeout(IO_TIMEOUT, reader.read_exact(tlvs_buffer)).await??;

        let mut tlvs_buffer = &*tlvs_buffer;
        let attributes = Vec::decode_from(&mut tlvs_buffer)?;

        last_active.set(Instant::now());
        if let Err(e) = ingress_sink.try_send((Message { header, attributes }, remote_addr)) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    log::error!("Dropping message from {remote_addr}: rx channel is full");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Channel closed"));
                }
            }
        }
    }
}

async fn process_egress(
    mut socket: impl AsyncWrite + Unpin,
    mut egress_source: mpsc::Receiver<Message>,
    last_active: &Cell<Instant>,
) -> io::Result<()> {
    let mut buffer = [0u8; BUFFER_LEN];
    loop {
        let message = egress_source
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Channel closed"))?;

        let mut remaining_buffer = &mut buffer[..];
        message.header.encode_into(&mut remaining_buffer)?;
        message.attributes.encode_into(&mut remaining_buffer)?;

        let encoded_bytes = BUFFER_LEN - remaining_buffer.len();
        time::timeout(IO_TIMEOUT, socket.write_all(&buffer[..encoded_bytes])).await??;
        last_active.set(Instant::now());
    }
}

async fn detect_inactivity(timeout: Duration, last_active: &Cell<Instant>) -> io::Result<()> {
    loop {
        let idle_period = last_active.get().elapsed();
        if idle_period >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "inactivity timeout",
            ));
        }
        time::sleep(timeout - idle_period).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutils::*;
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::{join, net::TcpStream};

    struct SocketFactory;

    impl TcpSocketFactory for SocketFactory {
        fn new_socket(&mut self) -> io::Result<TcpSocket> {
            let socket = TcpSocket::new_v4()?;
            socket.set_nodelay(true)?;
            socket.set_linger(Some(Duration::ZERO))?;
            socket.set_reuseaddr(true)?;
            #[cfg(not(windows))]
            socket.set_reuseport(true)?;
            Ok(socket)
        }
    }

    fn local_addr(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    fn setup() -> MessageChannels {
        let (channels, pool) = setup_tcp(Config {
            max_outstanding_requests: 10,
            connection_keep_alive: Duration::from_secs(5),
            socket_factory: SocketFactory,
        });
        task::spawn_local(pool.run());
        channels
    }

    macro_rules! verify_egress {
        ($receiver_sock:expr, $expected_bytes:expr) => {{
            let mut read_buffer = vec![0u8; $expected_bytes.len()];
            $receiver_sock.read_exact(&mut read_buffer).await.unwrap();
            assert_eq!(read_buffer, $expected_bytes);
            assert_eq!(
                $receiver_sock
                    .try_read(&mut read_buffer)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }};
    }

    macro_rules! verify_ingress {
        ($channels:expr, $expected_message:expr, $farend_addr:expr) => {{
            let (message, source) = $channels.ingress_source.recv().await.unwrap();
            assert_eq!(source, $farend_addr);
            assert_eq!(message, $expected_message);
            assert!($channels.ingress_source.try_recv().is_err());
        }};
    }

    async fn accept(listener_addr: SocketAddr) -> TcpStream {
        let socket = SocketFactory.new_socket().unwrap();
        socket.bind(listener_addr).unwrap();
        time::timeout(Duration::from_secs(5), socket.listen(1).unwrap().accept())
            .await
            .expect("timeout")
            .expect("IO error")
            .0
    }

    #[tokio::test]
    async fn send_and_receive_with_single_connection() {
        local_test!({
            let mut channels = setup();
            let farend_addr = local_addr(7000);
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            farend_sock.write_all(&BIND_RESPONSE_BYTES).await.unwrap();
            verify_ingress!(channels, bind_response_msg(), farend_addr);

            farend_sock.write_all(&BIND_INDICATION_BYTES).await.unwrap();
            verify_ingress!(channels, bind_indication_msg(), farend_addr);

            channels
                .egress_sink
                .send((bind_indication_msg(), farend_addr))
                .await
                .unwrap();
            verify_egress!(farend_sock, BIND_INDICATION_BYTES);
        });
    }

    #[tokio::test]
    async fn multiple_concurrenct_connections() {
        local_test!({
            let mut channels = setup();
            let farend1_addr = local_addr(7001);
            let farend2_addr = local_addr(7002);
            let accept_task =
                task::spawn_local(async move { join!(accept(farend1_addr), accept(farend2_addr)) });

            channels
                .egress_sink
                .send((bind_indication_msg(), farend1_addr))
                .await
                .unwrap();

            channels
                .egress_sink
                .send((bind_request_msg(), farend2_addr))
                .await
                .unwrap();

            let (mut farend_sock1, mut farend_sock2) = accept_task.await.unwrap();
            verify_egress!(farend_sock1, BIND_INDICATION_BYTES);
            verify_egress!(farend_sock2, BIND_REQUEST_BYTES);

            farend_sock2.write_all(&BIND_RESPONSE_BYTES).await.unwrap();
            farend_sock1
                .write_all(&BIND_INDICATION_BYTES)
                .await
                .unwrap();

            let (message, source) = channels.ingress_source.recv().await.unwrap();
            assert_eq!(source, farend2_addr);
            assert_eq!(message, bind_response_msg());

            let (message, source) = channels.ingress_source.recv().await.unwrap();
            assert_eq!(source, farend1_addr);
            assert_eq!(message, bind_indication_msg());

            assert!(channels.ingress_source.try_recv().is_err());
        });
    }

    #[tokio::test]
    async fn reconnect_after_farend_disconnected() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test!({
            let channels = setup();
            let farend_addr = local_addr(7003);
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            drop(farend_sock);
            task::yield_now().await;
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_indication_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_INDICATION_BYTES);
        });
    }

    #[tokio::test]
    async fn reconnect_after_malformed_response() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test!({
            let mut channels = setup();
            let farend_addr = local_addr(7004);
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            farend_sock.write_all(&[0xff; Header::SIZE]).await.unwrap();
            task::yield_now().await;
            assert!(channels.ingress_source.try_recv().is_err());

            let accept_task = task::spawn_local(accept(farend_addr));
            channels
                .egress_sink
                .send((bind_indication_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_INDICATION_BYTES);
        });
    }

    #[tokio::test]
    async fn drop_incoming_message_when_channel_is_full() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test!({
            let (mut channels, pool) = setup_tcp(Config {
                max_outstanding_requests: 1,
                connection_keep_alive: Duration::from_secs(1),
                socket_factory: SocketFactory,
            });
            task::spawn_local(pool.run());

            let farend_addr = local_addr(7005);
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            farend_sock.write_all(&BIND_RESPONSE_BYTES).await.unwrap();
            farend_sock.write_all(&BIND_INDICATION_BYTES).await.unwrap();
            verify_ingress!(channels, bind_response_msg(), farend_addr);

            farend_sock.write_all(&BIND_RESPONSE_BYTES).await.unwrap();
            verify_ingress!(channels, bind_response_msg(), farend_addr);
        });
    }
}
