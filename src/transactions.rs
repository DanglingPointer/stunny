use crate::msgs::*;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub struct MessageChannels(
    pub mpsc::Sender<(Message, SocketAddr)>,
    pub mpsc::Receiver<(Message, SocketAddr)>,
);
