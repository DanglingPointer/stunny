use super::connection_pool::*;
use super::MessageChannels;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig, ServerConfig};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

pub fn setup_tls_client(
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    socket_factory: impl Fn() -> io::Result<TcpSocket> + 'static,
    tls_config: Arc<ClientConfig>,
) -> (MessageChannels, TlsConnectionPool) {
    let (channels, pool) = setup_connection_pool(
        max_outstanding_requests,
        connection_keep_alive,
        TlsConnectionFactory {
            tls_connector: TlsConnector::from(tls_config),
            socket_factory: Box::new(socket_factory),
        },
    );
    (channels, TlsConnectionPool(PoolVariant::Client(pool)))
}

pub fn setup_tls_server(
    max_pending_requests: usize,
    max_pending_connections: u32,
    connection_keep_alive: Duration,
    bound_socket: TcpSocket,
    tls_config: Arc<ServerConfig>,
) -> io::Result<(MessageChannels, TlsConnectionPool)> {
    let listener = bound_socket.listen(max_pending_connections)?;
    let (channels, pool) = setup_connection_pool(
        max_pending_requests,
        connection_keep_alive,
        TlsConnectionAcceptor {
            listener,
            acceptor: TlsAcceptor::from(tls_config),
        },
    );
    Ok((channels, TlsConnectionPool(PoolVariant::Server(pool))))
}

pub struct TlsConnectionPool(PoolVariant);

impl TlsConnectionPool {
    pub async fn run(self) {
        match self.0 {
            PoolVariant::Client(pool) => {
                pool.run_client().await;
            }
            PoolVariant::Server(pool) => {
                pool.run_server()
                    .await
                    .unwrap_or_else(|e| log::error!("TLS server exited with error {e}"));
            }
        }
    }
}

enum PoolVariant {
    Client(ConnectionPool<TlsConnectionFactory>),
    Server(ConnectionPool<TlsConnectionAcceptor>),
}

// ----------------------------------------------

impl ConnectionStream for client::TlsStream<TcpStream> {
    fn split(
        &mut self,
    ) -> (
        impl AsyncRead + Send + Unpin,
        impl AsyncWrite + Send + Unpin,
    ) {
        split(self)
    }
}

impl ConnectionStream for server::TlsStream<TcpStream> {
    fn split(
        &mut self,
    ) -> (
        impl AsyncRead + Send + Unpin,
        impl AsyncWrite + Send + Unpin,
    ) {
        split(self)
    }
}

// ----------------------------------------------

struct TlsConnectionFactory {
    tls_connector: TlsConnector,
    socket_factory: Box<dyn Fn() -> io::Result<TcpSocket>>,
}

impl ConnectionFactory for TlsConnectionFactory {
    type Connection = client::TlsStream<TcpStream>;

    fn new_outbound<'f>(
        &mut self,
        remote_addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Connection>> + 'f {
        let socket_result = (self.socket_factory)();
        let tls_connector = self.tls_connector.clone();
        async move {
            let socket = socket_result?;
            let stream = socket.connect(remote_addr).await?;
            let stream = tls_connector
                .connect(ServerName::IpAddress(remote_addr.ip().into()), stream)
                .await?;
            Ok(stream)
        }
    }
}

// ----------------------------------------------

struct TlsConnectionAcceptor {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl ConnectionAcceptor for TlsConnectionAcceptor {
    type Connection = server::TlsStream<TcpStream>;

    async fn new_inbound(&mut self) -> io::Result<(Self::Connection, SocketAddr)> {
        let (tcp_stream, remote_addr) = self.listener.accept().await?;
        let tls_stream = self.acceptor.accept(tcp_stream).await?;
        Ok((tls_stream, remote_addr))
    }
}
