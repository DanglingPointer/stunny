use crate::transactions::{Request, RequestReceiver};
use async_trait::async_trait;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use stunny_core::attributes::*;
use tokio::task;

pub struct Processor {
    handlers: HashMap<u16, Arc<dyn Handler>>,
    default_handler: Arc<dyn Handler>,
    receiver: RequestReceiver,
}

impl Processor {
    pub(crate) fn new(receiver: RequestReceiver) -> Self {
        Self {
            handlers: [(0x0001u16, Arc::new(DefaultBindHandler) as Arc<dyn Handler>)].into(),
            default_handler: Arc::new(UnrecognizedMethodHandler),
            receiver,
        }
    }

    pub fn set_handler(&mut self, method: u16, handler: Arc<dyn Handler>) {
        self.handlers.insert(method, handler);
    }

    pub fn set_default_handler(&mut self, default_handler: Arc<dyn Handler>) {
        self.default_handler = default_handler;
    }

    pub async fn run(mut self) {
        while let Some(request) = self.receiver.next().await {
            let handler = match self.handlers.get(&request.method()) {
                Some(h) => h.clone(),
                None => self.default_handler.clone(),
            };
            task::spawn(async move {
                log::debug!("Serving {:?}", request);
                handler.handle_request(request).await;
            });
        }
    }
}

#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle_request(&self, request: Request);
}

// ------------------------------------------------------------------------------------------------

struct UnrecognizedMethodHandler;

#[async_trait]
impl Handler for UnrecognizedMethodHandler {
    async fn handle_request(&self, request: Request) {
        let _ = request
            .build_response()
            .with_attribute(ErrorCode {
                code: 400,
                reason: "unsupported".into(),
            })
            .send_error()
            .await;
    }
}

struct DefaultBindHandler;

#[async_trait]
impl Handler for DefaultBindHandler {
    async fn handle_request(&self, request: Request) {
        let client_addr = request.source_addr();
        let _ = request
            .build_response()
            .with_attribute(XorMappedAddress(client_addr))
            .with_attribute(MappedAddress(client_addr))
            .send()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use stunny_core::attributes::{Attribute, AttributeCollection};
    use stunny_core::{message::*, transport::MessageChannels};
    use tokio::sync::mpsc;

    struct Test {
        egress_source: mpsc::Receiver<(Message, SocketAddr)>,
        ingress_sink: mpsc::Sender<(Message, SocketAddr)>,
        processor: Processor,
    }

    fn setup() -> Test {
        let (egress_sink, egress_source) = mpsc::channel(10);
        let (ingress_sink, ingress_source) = mpsc::channel(10);
        let request_receiver = RequestReceiver::from(MessageChannels {
            egress_sink,
            ingress_source,
        });
        Test {
            egress_source,
            ingress_sink,
            processor: Processor::new(request_receiver),
        }
    }

    #[tokio::test]
    async fn default_response_to_bind_request() {
        let Test {
            mut egress_source,
            ingress_sink,
            processor,
        } = setup();
        task::spawn(processor.run());

        // when
        let ip = SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 3478);
        ingress_sink
            .try_send((Message::request(0x0001, [0xaf; 12], Vec::new()), ip))
            .unwrap();
        task::yield_now().await;

        // then
        let (response, addr) = egress_source.try_recv().unwrap();
        assert_eq!(addr, ip);
        assert_eq!(response.header.transaction_id, [0xaf; 12]);
        assert_eq!(response.header.class, Class::Response);
        assert_eq!(response.header.method, 0x0001);
        let mut attributes = response.xor_socket_addr(XorMappedAddress::ID).attributes;
        let xor_mapped_addr = attributes.extract_attribute::<XorMappedAddress>().unwrap();
        assert_eq!(xor_mapped_addr.0, ip);
        let mapped_addr = attributes.extract_attribute::<MappedAddress>().unwrap();
        assert_eq!(mapped_addr.0, ip);
        assert!(attributes.is_empty());
    }

    #[tokio::test]
    async fn default_response_to_unknown_method() {
        let Test {
            mut egress_source,
            ingress_sink,
            processor,
        } = setup();
        task::spawn(processor.run());

        // when
        let ip = SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 3478);
        ingress_sink
            .try_send((Message::request(0x0002, [0xfa; 12], Vec::new()), ip))
            .unwrap();
        task::yield_now().await;

        // then
        let (mut response, addr) = egress_source.try_recv().unwrap();
        assert_eq!(addr, ip);
        assert_eq!(response.header.transaction_id, [0xfa; 12]);
        assert_eq!(response.header.class, Class::Error);
        assert_eq!(response.header.method, 0x0002);
        let error_code = response
            .attributes
            .extract_attribute::<ErrorCode>()
            .unwrap();
        assert_eq!(error_code.code, 400);
        assert_eq!(error_code.reason, "unsupported");
        assert!(response.attributes.is_empty());
    }
}
