use message::Message;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[cfg(test)]
#[macro_use]
mod testutils;

pub mod message;

#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "udp")]
pub mod udp;

pub struct MessageChannels {
    pub(crate) egress_sink: mpsc::Sender<(Message, SocketAddr)>,
    pub(crate) ingress_source: mpsc::Receiver<(Message, SocketAddr)>,
}
