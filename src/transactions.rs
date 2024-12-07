use crate::transport::{message::*, MessageChannels};
use manager::{Manager, Request};
use std::future::pending;
use std::net::SocketAddr;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

mod error;
mod interface;
mod manager;
mod rto;

#[cfg(test)]
mod tests;

pub use error::*;
pub use interface::*;
pub use rto::*;

pub fn setup_transactions<P: RtoPolicy>(
    message_channels: MessageChannels,
    max_outstanding_requests: usize,
    rto_policy: P,
) -> (
    RequestSender,
    IndicationSender,
    IndicationReceiver,
    Processor<P>,
) {
    let (inbound_ind_sink, inbound_ind_source) = mpsc::channel(1);
    let (outbound_ind_sink, outbound_ind_source) = mpsc::channel(1);
    let (outbound_req_sink, outbound_req_source) = mpsc::channel(1);

    let manager = Manager::new(rto_policy, message_channels.egress_sink, inbound_ind_sink);
    (
        RequestSender::new(outbound_req_sink, max_outstanding_requests),
        IndicationSender::new(outbound_ind_sink),
        IndicationReceiver::new(inbound_ind_source),
        Processor {
            manager,
            ingress_source: message_channels.ingress_source,
            outbound_req_source,
            outbound_ind_source,
        },
    )
}

pub struct Processor<P> {
    manager: Manager<P>,
    ingress_source: mpsc::Receiver<(Message, SocketAddr)>,
    outbound_req_source: mpsc::Receiver<Request>,
    outbound_ind_source: mpsc::Receiver<Indication>,
}

impl<P: RtoPolicy> Processor<P> {
    pub async fn run(mut self) -> Result<(), TransactionError> {
        loop {
            let next_timeout = self.manager.next_timeout();
            select! {
                biased;
                inbound = self.ingress_source.recv() => {
                    let msg_and_src = inbound.ok_or(TransactionError::ChannelClosed)?;
                    self.manager.handle_incoming_message(msg_and_src).await?;
                }
                Some(request) = self.outbound_req_source.recv() => {
                    self.manager.handle_outgoing_request(request).await?;
                }
                Some(indication) = self.outbound_ind_source.recv() => {
                    self.manager.handle_outgoing_indication(indication).await?;
                }
                _ = Self::sleep_until(next_timeout), if next_timeout.is_some() => {
                    self.manager.handle_timeouts().await?;
                }
            }
        }
    }

    async fn sleep_until(deadline: Option<Instant>) {
        #[cfg(not(test))]
        match deadline {
            Some(deadline) => sleep_until(deadline).await,
            _ => pending::<()>().await,
        }

        #[cfg(test)]
        match deadline {
            Some(deadline) if tests::SLEEP_ENABLED.get() => sleep_until(deadline).await,
            _ => pending::<()>().await,
        }
    }
}
