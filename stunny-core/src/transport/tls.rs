use super::connection_pool::*;
use super::MessageChannels;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::{rc::Rc, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub fn setup_tls(
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    socket_factory: impl Fn() -> io::Result<TcpSocket> + 'static,
    tls_config: Arc<ClientConfig>,
) -> (MessageChannels, TlsConnectionPool) {
    let (channels, pool) = setup_connection_pool(
        max_outstanding_requests,
        connection_keep_alive,
        TlsStreamFactory {
            tls_connector: TlsConnector::from(tls_config),
            socket_factory: Rc::new(socket_factory),
        },
    );
    (channels, TlsConnectionPool(pool))
}

pub struct TlsConnectionPool(ConnectionPool<TlsStreamFactory>);

impl TlsConnectionPool {
    pub async fn run(self) {
        self.0.run().await;
    }
}

impl ConnectionStream for TlsStream<TcpStream> {
    fn split(&mut self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        tokio::io::split(self)
    }
}

#[derive(Clone)]
struct TlsStreamFactory {
    tls_connector: TlsConnector,
    socket_factory: Rc<dyn Fn() -> io::Result<TcpSocket>>,
}

impl ConnectionFactory for TlsStreamFactory {
    type Connection = TlsStream<TcpStream>;

    async fn new_outbound(
        &mut self,
        remote_addr: SocketAddr,
    ) -> io::Result<Self::Connection> {
        let socket = (self.socket_factory)()?;
        let stream = socket.connect(remote_addr).await?;
        let stream = self
            .tls_connector
            .connect(ServerName::IpAddress(remote_addr.ip().into()), stream)
            .await?;
        Ok(stream)
    }
}
