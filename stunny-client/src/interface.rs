use super::*;
use derive_more::Debug;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::{mpsc, oneshot, Semaphore};

#[derive(Debug)]
pub struct Response {
    pub success: bool,
    pub attributes: Vec<Tlv>,
    pub time_elapsed: Duration,
}

#[derive(Debug)]
pub struct Indication {
    pub farend_addr: SocketAddr,
    #[debug("{method:#06x}")]
    pub method: u16,
    pub attributes: Vec<Tlv>,
}

#[derive(Clone)]
pub struct RequestSender {
    sink: mpsc::Sender<Request>,
    request_slots: Rc<Semaphore>,
}

impl RequestSender {
    pub(super) fn new(
        sink: mpsc::Sender<Request>,
        max_outstanding_requests: usize,
    ) -> RequestSender {
        RequestSender {
            sink,
            request_slots: Rc::new(Semaphore::const_new(max_outstanding_requests)),
        }
    }

    pub async fn send_request(
        &self,
        destination: SocketAddr,
        method: u16,
        attributes: Vec<Tlv>,
    ) -> Result<Response, TransactionError> {
        let _slot = self.request_slots.acquire().await;
        let (tx, rx) = oneshot::channel();
        self.sink
            .send(Request::new(destination, method, attributes, tx))
            .await?;
        let response = rx.await.map_err(|_e| TransactionError::Timeout)??;
        Ok(response)
    }

    async fn send_request_to_addrs(
        &self,
        addrs: impl IntoIterator<Item = SocketAddr>,
        method: u16,
        attributes: Vec<Tlv>,
    ) -> Result<Response, TransactionError> {
        for addr in addrs {
            match self.send_request(addr, method, attributes.clone()).await {
                Err(TransactionError::Timeout) => continue,
                result => return result,
            }
        }
        Err(TransactionError::Timeout)
    }
}

pub struct CompositeRequestSender {
    pub udp: RequestSender,
    pub tcp: RequestSender,
    pub tls: Option<RequestSender>,
}

impl CompositeRequestSender {
    pub async fn udp_request<U: AsRef<str>>(
        &self,
        stun_uri: U,
        method: u16,
        attributes: Vec<Tlv>,
    ) -> Result<Response, TransactionError> {
        let addrs = dns::resolve_uri(stun_uri).await?;
        self.udp
            .send_request_to_addrs(addrs, method, attributes)
            .await
    }

    pub async fn tcp_request<U: AsRef<str>>(
        &self,
        stun_uri: U,
        method: u16,
        attributes: Vec<Tlv>,
    ) -> Result<Response, TransactionError> {
        if let Ok(addrs) = dns::resolve_uri(stun_uri.as_ref()).await {
            return self
                .tcp
                .send_request_to_addrs(addrs, method, attributes)
                .await;
        }
        if let Some(tls) = self.tls.as_ref() {
            if let Ok(addrs) = dns::resolve_secure_uri(stun_uri.as_ref()).await {
                return tls.send_request_to_addrs(addrs, method, attributes).await;
            }
        }
        Err(io::Error::from(io::ErrorKind::HostUnreachable).into())
    }
}

#[derive(Clone)]
pub struct IndicationSender {
    sink: mpsc::Sender<Indication>,
}

impl IndicationSender {
    pub(super) fn new(sink: mpsc::Sender<Indication>) -> IndicationSender {
        IndicationSender { sink }
    }

    pub async fn send_indication(
        &self,
        destination: SocketAddr,
        method: u16,
        attributes: Vec<Tlv>,
    ) -> Result<(), TransactionError> {
        self.sink
            .send(Indication {
                farend_addr: destination,
                method,
                attributes,
            })
            .await?;
        Ok(())
    }
}

pub struct IndicationReceiver {
    source: mpsc::Receiver<Indication>,
}

impl IndicationReceiver {
    pub(super) fn new(source: mpsc::Receiver<Indication>) -> IndicationReceiver {
        IndicationReceiver { source }
    }

    pub async fn receive_next(&mut self) -> Result<Indication, TransactionError> {
        self.source
            .recv()
            .await
            .ok_or(TransactionError::ChannelClosed)
    }
}

impl futures_util::Stream for IndicationReceiver {
    type Item = Indication;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.source.poll_recv(cx)
    }
}
