use super::*;
use rand::Rng;
use std::cmp::Ordering;
use std::collections::binary_heap::PeekMut;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::mem;
use std::net::SocketAddr;
use std::time::Duration;
use stunny_core::attributes::{Attribute, XorMappedAddress};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

pub(super) struct Request {
    destination_addr: SocketAddr,
    method: u16,
    attributes: Vec<Tlv>,
    response_sink: oneshot::Sender<Result<Response, TransactionError>>,
    attempts_made: usize,
    start_time: Instant,
}

impl Request {
    pub(super) fn new(
        destination_addr: SocketAddr,
        method: u16,
        attributes: Vec<Tlv>,
        response_sink: oneshot::Sender<Result<Response, TransactionError>>,
    ) -> Self {
        Self {
            destination_addr,
            method,
            attributes,
            response_sink,
            attempts_made: 0,
            start_time: Instant::now(),
        }
    }
}

type TransactionId = [u8; 12];

struct PendingTimeout {
    timeout_at: Instant,
    tid: TransactionId,
}

pub(super) struct Manager<P> {
    pending_timeouts: BinaryHeap<PendingTimeout>,
    outstanding_requests: HashMap<TransactionId, Request>,
    egress_sink: mpsc::Sender<(Message, SocketAddr)>,
    incoming_indications_sink: mpsc::Sender<Indication>,
    rto_policy: P,
    rand_gen: rand::rngs::ThreadRng,
}

impl<P: RtoPolicy> Manager<P> {
    pub(super) fn new(
        rto_policy: P,
        egress_sink: mpsc::Sender<(Message, SocketAddr)>,
        incoming_indications_sink: mpsc::Sender<Indication>,
    ) -> Self {
        Self {
            pending_timeouts: Default::default(),
            outstanding_requests: Default::default(),
            egress_sink,
            incoming_indications_sink,
            rto_policy,
            rand_gen: rand::thread_rng(),
        }
    }

    pub(super) fn next_timeout(&self) -> Option<Instant> {
        self.pending_timeouts.peek().map(|pt| pt.timeout_at)
    }

    pub(super) async fn handle_timeouts(&mut self) -> Result<(), TransactionError> {
        loop {
            // extract the earliest timeout, exit if it's in the future
            let mut timeout = match self.pending_timeouts.peek_mut() {
                Some(timeout) if timeout.timeout_at <= Instant::now() => PeekMut::pop(timeout),
                _ => break,
            };
            // fetch the corresponding request entry
            let mut outstanding = match self.outstanding_requests.entry(timeout.tid) {
                Entry::Occupied(occupied_entry) => occupied_entry,
                Entry::Vacant(_) => unreachable!("no request for pending timeout"),
            };
            let request = outstanding.get();
            match self
                .rto_policy
                .calculate_rto(request.destination_addr, request.attempts_made)
            {
                None => {
                    // erase entry and invoke callback with error
                    let _ = outstanding
                        .remove()
                        .response_sink
                        .send(Err(TransactionError::Timeout));
                }
                Some(next_rto) => {
                    let request = outstanding.get_mut();
                    // retransmit request
                    let msg =
                        Message::request(request.method, timeout.tid, request.attributes.clone());
                    log::trace!("Re-sending request to {:?}", request.destination_addr);
                    self.egress_sink
                        .send((msg, request.destination_addr))
                        .await?;
                    // schedule next timeout
                    request.attempts_made += 1;
                    timeout.timeout_at = Instant::now() + next_rto;
                    self.pending_timeouts.push(timeout);
                }
            }
        }
        Ok(())
    }

    pub(super) async fn handle_outgoing_indication(
        &mut self,
        indication: Indication,
    ) -> Result<(), TransactionError> {
        let tid = self.rand_gen.gen::<TransactionId>();
        let msg = Message::indication(indication.method, tid, indication.attributes)
            .xor_socket_addr(XorMappedAddress::ID);
        log::trace!("Sending indication to {:?}", indication.farend_addr);
        self.egress_sink.send((msg, indication.farend_addr)).await?;
        Ok(())
    }

    pub(super) async fn handle_outgoing_request(
        &mut self,
        mut request: Request,
    ) -> Result<(), TransactionError> {
        let tid = self.rand_gen.gen::<TransactionId>();
        let msg = Message::request(request.method, tid, mem::take(&mut request.attributes))
            .xor_socket_addr(XorMappedAddress::ID);
        request.attributes = msg.attributes.clone();
        log::trace!("Sending request to {:?}", request.destination_addr);
        match self.egress_sink.send((msg, request.destination_addr)).await {
            Ok(_) => {
                let now = Instant::now();

                let initial_rto = self
                    .rto_policy
                    .calculate_rto(request.destination_addr, 0)
                    .unwrap_or(DEFAULT_RTO);
                self.pending_timeouts.push(PendingTimeout {
                    timeout_at: now + initial_rto,
                    tid,
                });

                request.attempts_made = 1;
                request.start_time = now;
                self.outstanding_requests.insert(tid, request);
                Ok(())
            }
            Err(e) => {
                let _ = request
                    .response_sink
                    .send(Err(TransactionError::ChannelClosed));
                Err(e.into())
            }
        }
    }

    pub(super) async fn handle_incoming_message(
        &mut self,
        (message, source_addr): (Message, SocketAddr),
    ) -> Result<(), TransactionError> {
        let message = message.xor_socket_addr(XorMappedAddress::ID);
        match message.header.class {
            Class::Request => {
                log::error!("Ignoring incoming request: handling of requests is not supported");
            }
            Class::Indication => {
                if let Ok(sender) = self.incoming_indications_sink.reserve().await {
                    sender.send(Indication {
                        farend_addr: source_addr,
                        method: message.header.method,
                        attributes: message.attributes,
                    });
                } else {
                    log::debug!("Dropping received indication: no listener");
                }
            }
            Class::Response | Class::Error => {
                let request = match self
                    .outstanding_requests
                    .remove(&message.header.transaction_id)
                {
                    Some(request) => request,
                    None => {
                        log::warn!("Received orphaned response from {source_addr}");
                        return Ok(());
                    }
                };
                self.pending_timeouts
                    .retain(|pt| pt.tid != message.header.transaction_id);

                if request.attempts_made == 1 {
                    self.rto_policy
                        .submit_rtt(source_addr, request.start_time.elapsed());
                }

                let request_method = request.method;
                let response_method = message.header.method;

                let result = if request_method != response_method {
                    Err(TransactionError::MethodMismatch {
                        request_method,
                        response_method,
                    })
                } else {
                    Ok(Response {
                        success: matches!(message.header.class, Class::Response),
                        attributes: message.attributes,
                        time_elapsed: request.start_time.elapsed(),
                    })
                };
                let _ = request.response_sink.send(result);
            }
        }
        Ok(())
    }
}

const DEFAULT_RTO: Duration = Duration::from_millis(1500);

impl PartialEq for PendingTimeout {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_at == other.timeout_at
    }
}

impl Eq for PendingTimeout {}

impl PartialOrd for PendingTimeout {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTimeout {
    fn cmp(&self, other: &Self) -> Ordering {
        // reverse order for min-BinaryHeap
        other.timeout_at.cmp(&self.timeout_at)
    }
}
