use super::{message::*, MessageChannels};
use futures_util::TryFutureExt;
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{split, AsyncBufReadExt, BufReader};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use tokio::{task, try_join};

pub(super) trait StreamFactory {
    type ConnectionStream: Connection;

    fn new_connected_stream(
        &mut self,
        remote_addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::ConnectionStream>>;
}

pub(super) trait Connection: AsyncRead + AsyncWrite + Sized {
    fn run(
        self,
        remote_addr: SocketAddr,
        ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
        egress_source: mpsc::Receiver<Message>,
        inactivity_timeout: Duration,
    ) -> impl Future<Output = io::Result<()>> {
        let io = split(self);
        run_connection(
            io,
            remote_addr,
            ingress_sink,
            egress_source,
            inactivity_timeout,
        )
    }
}

pub(super) async fn run_connection(
    (rx, tx): (impl AsyncRead + Unpin, impl AsyncWrite + Unpin),
    remote_addr: SocketAddr,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    egress_source: mpsc::Receiver<Message>,
    inactivity_timeout: Duration,
) -> io::Result<()> {
    let last_active = Cell::new(Instant::now());
    try_join!(
        process_ingress(rx, ingress_sink, remote_addr, &last_active),
        process_egress(tx, egress_source, &last_active),
        detect_inactivity(inactivity_timeout, &last_active),
    )?;
    Ok(())
}

pub(super) fn setup_connection_pool<F: StreamFactory>(
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    stream_factory: F,
) -> (MessageChannels, ConnectionPool<F>) {
    let (ingress_sender, ingress_receiver) = mpsc::channel(max_outstanding_requests);
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
            max_outstanding_requests,
            connection_keep_alive,
            stream_factory,
        },
    )
}

pub(super) struct ConnectionPool<F: StreamFactory> {
    connections: HashMap<SocketAddr, mpsc::Sender<Message>>,
    egress_source: mpsc::Receiver<(Message, SocketAddr)>,
    ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
    max_outstanding_requests: usize,
    connection_keep_alive: Duration,
    stream_factory: F,
}

impl<F: StreamFactory + Clone + 'static> ConnectionPool<F> {
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
        let (egress_sink, egress_source) = mpsc::channel(self.max_outstanding_requests);
        let ingress_sink = self.ingress_sink.clone();
        let mut stream_factory = self.stream_factory.clone();
        let inactivity_timeout = self.connection_keep_alive;
        task::spawn_local(
            async move {
                log::trace!("Connecting to {remote_addr}");
                let stream =
                    time::timeout(IO_TIMEOUT, stream_factory.new_connected_stream(remote_addr))
                        .await??;
                log::debug!("Successfully connected to {remote_addr}");
                stream
                    .run(remote_addr, ingress_sink, egress_source, inactivity_timeout)
                    .await?;
                io::Result::Ok(())
            }
            .inspect_err(move |e| log::warn!("Connection to {remote_addr} exited with error: {e}")),
        );
        Ok(egress_sink)
    }
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
