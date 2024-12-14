use super::TransactionError;
use super::{attributes::*, message::*};
use derive_more::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use stunny_core::transport::MessageChannels;
use tokio::sync::mpsc;

type TransactionId = [u8; 12];

#[derive(Debug)]
pub struct Request {
    source_addr: SocketAddr,
    transaction_id: TransactionId,
    #[debug("{method:#06x}")]
    method: u16,
    attributes: Vec<Tlv>,
    #[debug(skip)]
    response_sink: mpsc::Sender<(Message, SocketAddr)>,
}

impl Request {
    fn new(
        (message, source_addr): (Message, SocketAddr),
        response_sink: mpsc::Sender<(Message, SocketAddr)>,
    ) -> Self {
        debug_assert!(message.header.class == Class::Request);
        let message = message.xor_socket_addr(XorMappedAddress::ID);
        Self {
            source_addr,
            transaction_id: message.header.transaction_id,
            method: message.header.method,
            attributes: message.attributes,
            response_sink,
        }
    }

    pub fn source_addr(&self) -> SocketAddr {
        self.source_addr
    }

    pub fn method(&self) -> u16 {
        self.method
    }

    pub fn attrs(&mut self) -> &mut Vec<Tlv> {
        &mut self.attributes
    }

    pub fn build_response(self) -> Response {
        Response {
            request: self,
            attributes: Vec::new(),
        }
    }
}

pub struct Response {
    request: Request,
    attributes: Vec<Tlv>,
}

impl Response {
    pub fn with_attribute<A: Attribute>(mut self, attribute: A) -> Self {
        self.attributes.append_attribute(attribute);
        self
    }

    pub async fn send(self) -> Result<(), TransactionError> {
        let response_message = Message::response(
            self.request.method,
            self.request.transaction_id,
            self.attributes,
        )
        .xor_socket_addr(XorMappedAddress::ID);
        self.request
            .response_sink
            .send((response_message, self.request.source_addr))
            .await?;
        Ok(())
    }

    pub async fn send_error(self) -> Result<(), TransactionError> {
        let response_message = Message::error(
            self.request.method,
            self.request.transaction_id,
            self.attributes,
        );
        self.request
            .response_sink
            .send((response_message, self.request.source_addr))
            .await?;
        Ok(())
    }
}

pub(crate) struct RequestReceiver(MessageChannels);

impl From<MessageChannels> for RequestReceiver {
    fn from(channels: MessageChannels) -> Self {
        Self(channels)
    }
}

impl futures_util::Stream for RequestReceiver {
    type Item = Request;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let MessageChannels {
            egress_sink,
            ingress_source,
        } = &mut self.get_mut().0;
        loop {
            let msg_addr = match ready!(ingress_source.poll_recv(cx)) {
                None => return Poll::Ready(None),
                Some(msg_addr) => msg_addr,
            };
            if msg_addr.0.header.class == Class::Request {
                let request = Request::new(msg_addr, egress_sink.clone());
                return Poll::Ready(Some(request));
            }
            let (msg, addr) = msg_addr;
            log::debug!("Ignoring incoming {:?} from {}", msg.header.class, addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio_test::{assert_pending, assert_ready, task::spawn};

    #[test]
    fn receive_request_and_send_response() {
        let (egress_sink, mut egress_source) = mpsc::channel(10);
        let (ingress_sink, ingress_source) = mpsc::channel(10);
        let request_receiver = RequestReceiver(MessageChannels {
            egress_sink,
            ingress_source,
        });
        let mut receive_fut = spawn(request_receiver);
        assert_pending!(receive_fut.poll_next());

        let mut egress_source_fut = spawn(egress_source.recv());
        assert_pending!(egress_source_fut.poll());

        // when
        let ip = SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 5349);
        let bind_request = Message::request(0x0001, [0xaf; 12], vec![]);
        ingress_sink.try_send((bind_request, ip)).unwrap();

        // then
        assert!(receive_fut.is_woken());
        let request = assert_ready!(receive_fut.poll_next()).unwrap();
        assert_eq!(request.transaction_id, [0xaf; 12]);
        assert_eq!(request.source_addr(), ip);
        assert_eq!(request.method(), 0x0001);

        // when
        let response = request
            .build_response()
            .with_attribute(XorMappedAddress(ip));
        assert_ready!(spawn(response.send()).poll()).unwrap();

        // then
        assert!(egress_source_fut.is_woken());
        let (response_message, response_addr) = assert_ready!(egress_source_fut.poll()).unwrap();
        assert_eq!(response_addr, ip);
        assert_eq!(response_message.header.transaction_id, [0xaf; 12]);
        assert_eq!(response_message.header.class, Class::Response);
        assert_eq!(response_message.header.method, 0x0001);
        let xor_mapped_attr = response_message
            .xor_socket_addr(XorMappedAddress::ID)
            .attributes
            .extract_attribute::<XorMappedAddress>()
            .unwrap();
        assert_eq!(xor_mapped_attr.0, ip);
    }

    #[test]
    fn ignore_indication_and_response() {
        let (egress_sink, _egress_source) = mpsc::channel(10);
        let (ingress_sink, ingress_source) = mpsc::channel(10);
        let request_receiver = RequestReceiver(MessageChannels {
            egress_sink,
            ingress_source,
        });
        let mut receive_fut = spawn(request_receiver);
        assert_pending!(receive_fut.poll_next());

        // when
        let ip = SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 5349);
        let indication = Message::indication(0x0001, [0xad; 12], vec![]);
        ingress_sink.try_send((indication, ip)).unwrap();

        // then
        assert!(receive_fut.is_woken());
        assert_pending!(receive_fut.poll_next());

        // when
        let response = Message::response(0x0001, [0xae; 12], vec![]);
        ingress_sink.try_send((response, ip)).unwrap();

        // then
        assert!(receive_fut.is_woken());
        assert_pending!(receive_fut.poll_next());

        // when
        let bind_request = Message::request(0x0001, [0xaf; 12], vec![]);
        ingress_sink.try_send((bind_request, ip)).unwrap();

        // then
        assert!(receive_fut.is_woken());
        let request = assert_ready!(receive_fut.poll_next()).unwrap();
        assert_eq!(request.transaction_id, [0xaf; 12]);
        assert_eq!(request.source_addr(), ip);
        assert_eq!(request.method(), 0x0001);

        assert_pending!(receive_fut.poll_next());
    }
}
