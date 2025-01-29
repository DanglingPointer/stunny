use super::*;
use futures_util::{FutureExt, TryFutureExt};
use std::collections::HashMap;
use std::future::{ready, Future};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tokio::{select, task, try_join};

pub(super) fn setup_connection_pool<C>(
    max_pending_requests: usize,
    connection_keep_alive: Duration,
    connector: C,
) -> (MessageChannels, ConnectionPool<C>) {
    let (ingress_sender, ingress_receiver) = mpsc::channel(max_pending_requests);
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
            egress_queue_capacity: max_pending_requests,
            connection_keep_alive,
            connector,
        },
    )
}

pub(super) struct ConnectionPool<C> {
    connections: HashMap<SocketAddr, mpsc::Sender<Message>>,
    egress_source: mpsc::Receiver<(Message, SocketAddr)>,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    egress_queue_capacity: usize,
    connection_keep_alive: Duration,
    connector: C,
}

pub(super) trait ConnectionStream: Send {
    fn split(
        &mut self,
    ) -> (
        impl AsyncRead + Send + Unpin,
        impl AsyncWrite + Send + Unpin,
    );
}

pub(super) trait ConnectionFactory {
    type Connection: ConnectionStream + 'static;

    fn new_outbound<'f>(
        &mut self,
        remote_addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::Connection>> + Send + 'f;
}

pub(super) trait ConnectionAcceptor {
    type Connection: ConnectionStream + 'static;

    fn new_inbound(&mut self) -> impl Future<Output = io::Result<(Self::Connection, SocketAddr)>>;
}

impl<A: ConnectionAcceptor> ConnectionPool<A> {
    pub(super) async fn run_server(mut self) -> io::Result<()> {
        loop {
            select! {
                biased;
                egress = self.egress_source.recv() => match egress {
                    Some(egress) => self.route_egress(egress),
                    None => break,
                },
                connection = self.connector.new_inbound() => {
                    self.add_connection(connection?);
                },
            }
        }
        Ok(())
    }

    fn route_egress(&mut self, (message, remote_addr): (Message, SocketAddr)) {
        let egress_sink = match self.connections.get(&remote_addr) {
            Some(sink) => sink,
            None => return log::warn!("Dropping message to {remote_addr}: connection not found"),
        };
        match egress_sink.try_send(message) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::warn!("Dropping message to {remote_addr}: tx channel is full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                log::warn!("Dropping message to {remote_addr}: connection closed");
            }
        }
    }

    fn add_connection(&mut self, (connection, remote_addr): (A::Connection, SocketAddr)) {
        let (egress_sink, egress_source) = mpsc::channel(self.egress_queue_capacity);
        self.connections.insert(remote_addr, egress_sink);
        task::spawn(
            connection_task(
                ready(Ok(connection)),
                remote_addr,
                self.ingress_sink.clone(),
                egress_source,
                self.connection_keep_alive,
            )
            .inspect_err(move |e| log::warn!("Connection to {remote_addr} exited with error: {e}")),
        );
        // clean up stale entries
        self.connections.retain(|_, ch| !ch.is_closed());
    }
}

impl<F: ConnectionFactory> ConnectionPool<F> {
    pub(super) async fn run_client(mut self) {
        while let Some((message, remote_addr)) = self.egress_source.recv().await {
            if let Some(egress_sink) = self.connections.get(&remote_addr) {
                match egress_sink.try_reserve() {
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
            }
            // if we ended up here, we need to create a new outbound connection
            let (egress_sink, egress_source) = mpsc::channel(self.egress_queue_capacity);
            let _ = egress_sink.try_send(message);
            self.connections.insert(remote_addr, egress_sink);
            task::spawn(
                connection_task(
                    time::timeout(IO_TIMEOUT, self.connector.new_outbound(remote_addr)).map(|r| r?),
                    remote_addr,
                    self.ingress_sink.clone(),
                    egress_source,
                    self.connection_keep_alive,
                )
                .inspect_err(move |e| {
                    log::warn!("Connection to {remote_addr} exited with error: {e}")
                }),
            );
            // clean up stale entries
            self.connections.retain(|_, ch| !ch.is_closed());
        }
    }
}

async fn connection_task<C: ConnectionStream>(
    get_stream: impl Future<Output = io::Result<C>>,
    remote_addr: SocketAddr,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    egress_source: mpsc::Receiver<Message>,
    inactivity_timeout: Duration,
) -> io::Result<()> {
    let mut connection_stream = get_stream.await?;
    log::debug!("New connection to {remote_addr}");
    let (rx, tx) = connection_stream.split();
    let last_active = LastActive::new();
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
    last_active: &LastActive,
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

        last_active.update();
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
    last_active: &LastActive,
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
        last_active.update();
    }
}

async fn detect_inactivity(timeout: Duration, last_active: &LastActive) -> io::Result<()> {
    loop {
        let deadline = last_active.get() + timeout;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "inactivity timeout",
            ));
        }
        time::sleep_until(deadline).await;
    }
}

struct LastActive {
    start: Instant,
    ms_since_start: AtomicU64,
}

impl LastActive {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            ms_since_start: AtomicU64::new(0),
        }
    }

    fn update(&self) {
        let elapsed_since_start = self.start.elapsed().as_millis();
        self.ms_since_start
            .store(elapsed_since_start as u64, Ordering::Relaxed);
    }

    fn get(&self) -> Instant {
        self.start + Duration::from_millis(self.ms_since_start.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use local_async_utils::sec;
    use time::sleep;

    #[tokio::test(start_paused = true)]
    async fn last_active() {
        let la = LastActive::new();
        assert_eq!(la.get().elapsed(), Duration::ZERO);

        sleep(sec!(3)).await;
        assert_eq!(la.get().elapsed(), sec!(3));

        la.update();
        assert_eq!(la.get().elapsed(), Duration::ZERO);

        sleep(sec!(3)).await;
        assert_eq!(la.get().elapsed(), sec!(3));

        la.update();
        sleep(sec!(1)).await;
        la.update();
        sleep(sec!(1)).await;
        assert_eq!(la.get().elapsed(), sec!(1));
    }
}
