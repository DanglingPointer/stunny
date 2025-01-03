use super::connection_pool::*;
use super::*;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

pub fn setup_tcp_client<F>(
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    socket_factory: F,
) -> (MessageChannels, TcpConnectionPool)
where
    F: Fn() -> io::Result<TcpSocket> + Send + 'static,
{
    let (channels, pool) = setup_connection_pool(
        max_outstanding_requests,
        connection_keep_alive,
        TcpConnectionFactory(Box::new(socket_factory)),
    );
    (channels, TcpConnectionPool(PoolVariant::Client(pool)))
}

pub fn setup_tcp_server(
    max_pending_requests: usize,
    max_pending_connections: u32,
    connection_keep_alive: Duration,
    bound_socket: TcpSocket,
) -> io::Result<(MessageChannels, TcpConnectionPool)> {
    let listener = bound_socket.listen(max_pending_connections)?;
    let (channels, pool) = setup_connection_pool(
        max_pending_requests,
        connection_keep_alive,
        TcpConnectionAcceptor(listener),
    );
    Ok((channels, TcpConnectionPool(PoolVariant::Server(pool))))
}

pub struct TcpConnectionPool(PoolVariant);

impl TcpConnectionPool {
    pub async fn run(self) {
        match self.0 {
            PoolVariant::Client(pool) => {
                pool.run_client().await;
            }
            PoolVariant::Server(pool) => {
                pool.run_server()
                    .await
                    .unwrap_or_else(|e| log::error!("TCP server exited with error {e}"));
            }
        }
    }
}

// ----------------------------------------------

enum PoolVariant {
    Client(ConnectionPool<TcpConnectionFactory>),
    Server(ConnectionPool<TcpConnectionAcceptor>),
}

impl ConnectionStream for TcpStream {
    fn split(&mut self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        self.split()
    }
}

// ----------------------------------------------

struct TcpConnectionFactory(Box<dyn Fn() -> io::Result<TcpSocket> + Send>);

impl ConnectionFactory for TcpConnectionFactory {
    type Connection = TcpStream;

    fn new_outbound<'f>(
        &mut self,
        remote_addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Connection>> + 'f {
        let socket_result = (self.0)();
        async move {
            let socket = socket_result?;
            socket.connect(remote_addr).await
        }
    }
}

// ----------------------------------------------

struct TcpConnectionAcceptor(TcpListener);

impl ConnectionAcceptor for TcpConnectionAcceptor {
    type Connection = TcpStream;

    async fn new_inbound(&mut self) -> io::Result<(Self::Connection, SocketAddr)> {
        self.0.accept().await
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutils::*;
    use super::*;
    use futures_util::{stream, StreamExt};
    use local_async_utils::sec;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::{join, net::TcpStream, task, time};

    macro_rules! with_timeout {
        ($($arg:tt)+) => {{
            time::timeout(sec!(5), async { $($arg)+ }).await.expect("test timeout");
        }}
    }

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
        let (channels, pool) = setup_tcp_client(10, Duration::from_secs(5), new_socket);
        task::spawn(pool.run());
        channels
    }

    fn server_setup(server_addr: SocketAddr) -> MessageChannels {
        let server_sock = new_socket().unwrap();
        server_sock.bind(server_addr).unwrap();
        let (channels, pool) = setup_tcp_server(10, 10, sec!(20), server_sock).unwrap();
        task::spawn(pool.run());
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
        with_timeout! {
            let mut channels = setup();
            let farend_addr = local_addr(7000);
            let accept_task = task::spawn(accept(farend_addr));

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
    async fn serve_single_connection() {
        with_timeout! {
            let server_addr = local_addr(8000);
            let mut channels = server_setup(server_addr);
            task::yield_now().await;

            let mut farend_sock = new_socket()
                .unwrap()
                .connect(server_addr)
                .await
                .expect("failed to connect to server");
            let farend_addr = farend_sock.local_addr().unwrap();

            farend_sock.write_all(&BIND_REQUEST_BYTES).await.unwrap();
            verify_ingress!(channels, bind_request_msg(), farend_addr);

            channels
                .egress_sink
                .send((bind_response_msg(), farend_addr))
                .await
                .unwrap();
            verify_egress!(farend_sock, BIND_RESPONSE_BYTES);

            farend_sock.write_all(&BIND_INDICATION_BYTES).await.unwrap();
            verify_ingress!(channels, bind_indication_msg(), farend_addr);
        }
    }

    #[tokio::test]
    async fn multiple_concurrent_connections() {
        with_timeout! {
            let mut channels = setup();
            let farend1_addr = local_addr(7001);
            let farend2_addr = local_addr(7002);
            let accept_task =
                task::spawn(async move { join!(accept(farend1_addr), accept(farend2_addr)) });

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
    async fn serve_multiple_concurrent_connections() {
        with_timeout! {
            let server_addr = local_addr(8001);
            let mut channels = server_setup(server_addr);
            task::yield_now().await;

            let mut farend_sock1 = new_socket()
                .unwrap()
                .connect(server_addr)
                .await
                .expect("failed to connect to server");
            let farend_addr1 = farend_sock1.local_addr().unwrap();

            let mut farend_sock2 = new_socket()
                .unwrap()
                .connect(server_addr)
                .await
                .expect("failed to connect to server");
            let farend_addr2 = farend_sock2.local_addr().unwrap();

            // when
            farend_sock2
                .write_all(&BIND_INDICATION_BYTES)
                .await
                .unwrap();
            farend_sock1.write_all(&BIND_REQUEST_BYTES).await.unwrap();

            // then
            let msgs: Vec<_> = stream::poll_fn(|cx| channels.ingress_source.poll_recv(cx))
                .take(2)
                .collect()
                .await;
            assert!(channels.ingress_source.try_recv().is_err());
            assert!(msgs
                .iter()
                .any(|(msg, src)| src == &farend_addr2 && msg == &bind_indication_msg()));
            assert!(msgs
                .iter()
                .any(|(msg, src)| src == &farend_addr1 && msg == &bind_request_msg()));

            // when
            channels
                .egress_sink
                .send((bind_response_msg(), farend_addr1))
                .await
                .unwrap();

            channels
                .egress_sink
                .send((bind_indication_msg(), farend_addr2))
                .await
                .unwrap();

            // then
            verify_egress!(farend_sock1, BIND_RESPONSE_BYTES);
            verify_egress!(farend_sock2, BIND_INDICATION_BYTES);
        }
    }

    #[tokio::test]
    async fn reconnect_after_farend_disconnected() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init();
        with_timeout! {
            let channels = setup();
            let farend_addr = local_addr(7003);
            let accept_task = task::spawn(accept(farend_addr));

            channels
                .egress_sink
                .send((bind_request_msg(), farend_addr))
                .await
                .unwrap();
            let mut farend_sock = accept_task.await.unwrap();
            verify_egress!(farend_sock, BIND_REQUEST_BYTES);

            drop(farend_sock);
            task::yield_now().await;
            let accept_task = task::spawn(accept(farend_addr));

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
        with_timeout! {
            let mut channels = setup();
            let farend_addr = local_addr(7004);
            let accept_task = task::spawn(accept(farend_addr));

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

            let accept_task = task::spawn(accept(farend_addr));
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
        with_timeout! {
            let (mut channels, pool) = setup_tcp_client(1, Duration::from_secs(1), new_socket);
            task::spawn(pool.run());

            let farend_addr = local_addr(7005);
            let accept_task = task::spawn(accept(farend_addr));

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
        const INACTIVITY_TIMEOUT: Duration = sec!(2);

        let (channels, pool) = setup_tcp_client(1, INACTIVITY_TIMEOUT, new_socket);
        task::spawn(pool.run());

        let farend_addr = local_addr(7006);
        let accept_task = task::spawn(accept(farend_addr));
        task::yield_now().await;

        with_timeout! {
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
