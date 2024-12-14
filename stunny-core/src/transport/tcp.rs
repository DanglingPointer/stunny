use super::connection_pool::*;
use super::*;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

pub fn setup_tcp(
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    socket_factory: impl Fn() -> io::Result<TcpSocket> + 'static,
) -> (MessageChannels, TcpConnectionPool) {
    let (channels, pool) = setup_connection_pool(
        max_outstanding_requests,
        connection_keep_alive,
        TcpStreamFactory {
            socket_factory: Rc::new(socket_factory),
        },
    );
    (channels, TcpConnectionPool(pool))
}

pub struct TcpConnectionPool(ConnectionPool<TcpStreamFactory>);

impl TcpConnectionPool {
    pub async fn run(self) {
        self.0.run().await;
    }
}

impl Connection for TcpStream {
    async fn run(
        mut self,
        remote_addr: SocketAddr,
        ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
        egress_source: mpsc::Receiver<Message>,
        inactivity_timeout: Duration,
    ) -> io::Result<()> {
        let io = self.split();
        run_connection(
            io,
            remote_addr,
            ingress_sink,
            egress_source,
            inactivity_timeout,
        )
        .await
    }
}

#[derive(Clone)]
struct TcpStreamFactory {
    socket_factory: Rc<dyn Fn() -> io::Result<TcpSocket>>,
}

impl StreamFactory for TcpStreamFactory {
    type ConnectionStream = TcpStream;

    async fn new_connected_stream(
        &mut self,
        remote_addr: SocketAddr,
    ) -> io::Result<Self::ConnectionStream> {
        let socket = (self.socket_factory)()?;
        socket.connect(remote_addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutils::*;
    use super::*;
    use local_async_utils::sec;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::{join, net::TcpStream, task, time};

    fn new_socket() -> io::Result<TcpSocket> {
        let socket = TcpSocket::new_v4()?;
        socket.set_nodelay(true)?;
        socket.set_linger(Some(Duration::ZERO))?;
        socket.set_reuseaddr(true)?;
        #[cfg(not(windows))]
        socket.set_reuseport(true)?;
        Ok(socket)
    }

    fn local_addr(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    fn setup() -> MessageChannels {
        let (channels, pool) = setup_tcp(10, Duration::from_secs(5), new_socket);
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
        let socket = new_socket().unwrap();
        socket.bind(listener_addr).unwrap();
        time::timeout(Duration::from_secs(5), socket.listen(1).unwrap().accept())
            .await
            .expect("timeout")
            .expect("IO error")
            .0
    }

    #[tokio::test]
    async fn send_and_receive_with_single_connection() {
        local_test! {
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
        }
    }

    #[tokio::test]
    async fn multiple_concurrenct_connections() {
        local_test! {
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
        }
    }

    #[tokio::test]
    async fn reconnect_after_farend_disconnected() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test! {
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
        }
    }

    #[tokio::test]
    async fn reconnect_after_malformed_response() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test! {
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
        }
    }

    #[tokio::test]
    async fn drop_incoming_message_when_channel_is_full() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test! {
            let (mut channels, pool) = setup_tcp(1, Duration::from_secs(1), new_socket);
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
        }
    }

    #[tokio::test(start_paused = true)]
    async fn close_idle_connection() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        local_test! {
            const INACTIVITY_TIMEOUT: Duration = sec!(2);

            let (channels, pool) = setup_tcp(1, INACTIVITY_TIMEOUT, new_socket);
            task::spawn_local(pool.run());

            let farend_addr = local_addr(7006);
            let accept_task = task::spawn_local(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            time::sleep(INACTIVITY_TIMEOUT).await;
            task::yield_now().await;
            assert_eq!(farend_sock.try_read(&mut [0u8]).unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        }
    }
}
