use crate::message::*;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[cfg(test)]
#[macro_use]
mod testutils;

#[cfg(any(feature = "tcp", feature = "tls"))]
mod connection_pool;

#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "udp")]
pub mod udp;

pub struct MessageChannels {
    pub egress_sink: mpsc::Sender<(Message, SocketAddr)>,
    pub ingress_source: mpsc::Receiver<(Message, SocketAddr)>,
}
