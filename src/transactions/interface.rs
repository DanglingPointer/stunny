use super::*;
use derive_more::Debug;
use std::net::SocketAddr;
use std::rc::Rc;
use tokio::sync::{mpsc, oneshot, Semaphore};

#[derive(Debug)]
pub enum Response {
    Success(Vec<Tlv>),
    Error(Vec<Tlv>),
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
