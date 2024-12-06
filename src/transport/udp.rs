use super::message::*;
use super::MessageChannels;
use bytes::{Buf, BufMut};
use std::future::Future;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::try_join;

pub fn setup_udp(socket: UdpSocket, max_outstanding_requests: usize) -> (MessageChannels, Runner) {
    let (ingress_sender, ingress_receiver) = mpsc::channel(max_outstanding_requests);
    let (egress_sender, egress_receiver) = mpsc::channel(max_outstanding_requests);
    (
        MessageChannels {
            egress_sink: egress_sender,
            ingress_source: ingress_receiver,
        },
        Runner {
            socket,
            ingress_sender,
            egress_receiver,
        },
    )
}

pub struct Runner {
    socket: UdpSocket,
    ingress_sender: mpsc::Sender<(Message, SocketAddr)>,
    egress_receiver: mpsc::Receiver<(Message, SocketAddr)>,
}

impl Runner {
    pub async fn run(self) -> io::Result<()> {
        let ingress = Ingress {
            socket: &self.socket,
            buffer: [MaybeUninit::uninit(); BUFFER_LEN],
            sink: self.ingress_sender,
        };
        let egress = Egress {
            socket: &self.socket,
            buffer_pos: ([0u8; BUFFER_LEN], 0),
            pending_recipient: None,
            source: self.egress_receiver,
        };
        try_join!(ingress, egress)?;
        Ok(())
    }
}

const BUFFER_LEN: usize = 1500;

struct Ingress<'s> {
    socket: &'s UdpSocket,
    buffer: [MaybeUninit<u8>; BUFFER_LEN],
    sink: mpsc::Sender<(Message, SocketAddr)>,
}

struct Egress<'s> {
    socket: &'s UdpSocket,
    buffer_pos: ([u8; BUFFER_LEN], usize),
    pending_recipient: Option<SocketAddr>,
    source: mpsc::Receiver<(Message, SocketAddr)>,
}

impl Future for Ingress<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        fn decode_msg(mut buffer: &[u8]) -> Result<Message, ParseError> {
            let header = Header::decode_from(&mut buffer)?;
            let mut buffer = Buf::take(buffer, header.length as usize);
            let mut attributes = Vec::new();
            while buffer.has_remaining() {
                attributes.push(Tlv::decode_from(&mut buffer)?);
            }
            Ok(Message { header, attributes })
        }

        let Ingress {
            socket,
            buffer,
            sink,
        } = self.get_mut();
        let mut buffer = ReadBuf::uninit(buffer);
        loop {
            buffer.clear();
            let src_addr = ready!(socket.poll_recv_from(cx, &mut buffer))
                .inspect_err(|e| log::error!("Failed to receive UDP packet: {e}"))?;
            let message = match decode_msg(buffer.filled()) {
                Err(e) => {
                    log::error!("Discarding message from {src_addr}: {e}");
                    continue;
                }
                Ok(msg) => msg,
            };
            match sink.try_send((message, src_addr)) {
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Channel closed",
                    )));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    log::error!("Dropping message from {src_addr}: rx channel is full");
                    continue;
                }
                Ok(()) => continue,
            }
        }
    }
}

impl Future for Egress<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        fn encode_msg(msg: &Message, buffer_ref: &mut impl BufMut) -> Result<(), io::Error> {
            msg.header.encode_into(buffer_ref)?;
            for tlv in &msg.attributes {
                tlv.encode_into(buffer_ref)?;
            }
            Ok(())
        }

        let Egress {
            socket,
            buffer_pos: (buffer, pos),
            pending_recipient,
            source,
        } = self.get_mut();
        loop {
            match pending_recipient {
                None => match ready!(source.poll_recv(cx)) {
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Channel closed",
                        )));
                    }
                    Some((message, dest_addr)) => {
                        let mut remaining_buffer = buffer.as_mut_slice();
                        match encode_msg(&message, &mut remaining_buffer) {
                            Ok(_) => {
                                *pos = BUFFER_LEN - remaining_buffer.len();
                                *pending_recipient = Some(dest_addr);
                            }
                            Err(e) => {
                                log::error!("Failed to encode message to {dest_addr}: {e}");
                                *pos = 0;
                            }
                        }
                    }
                },
                Some(dest_addr) => {
                    let dest_addr = *dest_addr;
                    let data_len = *pos;
                    let send_result = ready!(socket.poll_send_to(cx, &buffer[..*pos], dest_addr));
                    *pending_recipient = None;
                    *pos = 0;

                    match send_result {
                        Err(e) => {
                            log::error!("Failed to send message to {dest_addr}: {e}");
                        }
                        Ok(bytes_sent) if bytes_sent != data_len => {
                            log::error!("Sent only {bytes_sent}/{data_len} to {dest_addr}");
                        }
                        Ok(_) => (),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutils::*;
    use super::*;
    use local_async_utils::sec;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::{task, time::timeout};

    async fn create_ipv4_socket(port: u16) -> io::Result<UdpSocket> {
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await
    }

    #[tokio::test]
    async fn receive_messages() {
        let sender_port = 7784u16;
        let receiver_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7785);

        let sender_sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_port))
            .await
            .unwrap();

        let socket = create_ipv4_socket(receiver_addr.port()).await.unwrap();
        let (
            MessageChannels {
                egress_sink: _tx_channel,
                ingress_source: mut rx_channel,
            },
            runner,
        ) = setup_udp(socket, 10);
        task::spawn(runner.run());

        sender_sock
            .send_to(&BIND_REQUEST_BYTES, receiver_addr)
            .await
            .unwrap();
        let (receved_msg, src_addr) = timeout(sec!(5), rx_channel.recv()).await.unwrap().unwrap();
        assert_eq!(
            src_addr,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), sender_port)
        );
        assert_eq!(receved_msg, bind_request_msg());

        sender_sock
            .send_to(&BIND_INDICATION_BYTES, receiver_addr)
            .await
            .unwrap();
        let (receved_msg, src_addr) = timeout(sec!(5), rx_channel.recv()).await.unwrap().unwrap();
        assert_eq!(
            src_addr,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), sender_port)
        );
        assert_eq!(receved_msg, bind_indication_msg());
    }

    #[tokio::test]
    async fn receive_valid_message_after_malformed() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Info)
            .init();

        let bad_sender_port = 6667u16;
        let good_sender_port = 6668u16;
        let receiver_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7778u16);

        let bad_sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, bad_sender_port))
            .await
            .unwrap();

        let good_sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, good_sender_port))
            .await
            .unwrap();

        let socket = create_ipv4_socket(receiver_addr.port()).await.unwrap();
        let (
            MessageChannels {
                egress_sink: _tx_channel,
                ingress_source: mut rx_channel,
            },
            runner,
        ) = setup_udp(socket, 10);
        task::spawn(runner.run());

        bad_sender
            .send_to(b"malformed", receiver_addr)
            .await
            .unwrap();

        good_sender
            .send_to(&BIND_RESPONSE_BYTES, receiver_addr)
            .await
            .unwrap();

        let (receved_msg, src_addr) = timeout(sec!(5), rx_channel.recv()).await.unwrap().unwrap();
        assert_eq!(
            src_addr,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), good_sender_port)
        );
        assert_eq!(receved_msg, bind_response_msg());
    }

    #[tokio::test]
    async fn send_messages() {
        let sender_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7786);
        let receiver_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7787);

        let receiver_sock = UdpSocket::bind(receiver_addr).await.unwrap();

        let socket = create_ipv4_socket(sender_addr.port()).await.unwrap();
        let (
            MessageChannels {
                egress_sink: tx_channel,
                ingress_source: _rx_channel,
            },
            runner,
        ) = setup_udp(socket, 10);
        task::spawn(runner.run());

        tx_channel
            .send((bind_indication_msg(), receiver_addr.into()))
            .await
            .unwrap();

        let mut buf = [0u8; 1500];
        let (len, src_addr) = timeout(sec!(5), receiver_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(src_addr, sender_addr.into());
        assert_eq!(&buf[..len], &BIND_INDICATION_BYTES);

        tx_channel
            .send((bind_response_msg(), receiver_addr.into()))
            .await
            .unwrap();

        let mut buf = [0u8; 1500];
        let (len, src_addr) = timeout(sec!(5), receiver_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(src_addr, sender_addr.into());
        assert_eq!(&buf[..len], &BIND_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn successful_send_after_failed_send() {
        let non_existent_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7781);
        let sender_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7782);
        let receiver_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7783);

        let receiver_sock = UdpSocket::bind(receiver_addr).await.unwrap();

        let socket = create_ipv4_socket(sender_addr.port()).await.unwrap();
        let (
            MessageChannels {
                egress_sink: tx_channel,
                ingress_source: _rx_channel,
            },
            runner,
        ) = setup_udp(socket, 10);
        task::spawn(runner.run());

        // send a message to nowhere
        tx_channel
            .send((bind_request_msg(), non_existent_addr.into()))
            .await
            .unwrap();

        // send a message to somewhere
        tx_channel
            .send((bind_indication_msg(), receiver_addr.into()))
            .await
            .unwrap();

        let mut buf = [0u8; 1500];
        let (len, src_addr) = timeout(sec!(5), receiver_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(src_addr, sender_addr.into());
        assert_eq!(&buf[..len], &BIND_INDICATION_BYTES);
    }

    #[tokio::test]
    async fn drop_incoming_message_when_channel_is_full() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Info)
            .init();

        let first_sender_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7788);
        let second_sender_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7789);
        let receiver_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7791);

        let first_sender = UdpSocket::bind(first_sender_addr).await.unwrap();
        let second_sender = UdpSocket::bind(second_sender_addr).await.unwrap();

        let socket = create_ipv4_socket(receiver_addr.port()).await.unwrap();

        // given: channel with capacity 1
        let (
            MessageChannels {
                egress_sink: _tx_channel,
                ingress_source: mut rx_channel,
            },
            runner,
        ) = setup_udp(socket, 1);
        task::spawn(runner.run());

        // when: 2 messages are sent to us
        first_sender
            .send_to(&BIND_INDICATION_BYTES, receiver_addr)
            .await
            .unwrap();
        second_sender
            .send_to(&BIND_RESPONSE_BYTES, receiver_addr)
            .await
            .unwrap();

        // then: the first message is received, the second one is dropped
        let (receved_msg, src_addr) = timeout(sec!(5), rx_channel.recv()).await.unwrap().unwrap();
        assert_eq!(src_addr, first_sender_addr.into());
        assert_eq!(receved_msg, bind_indication_msg());

        // when: one more message
        second_sender
            .send_to(&BIND_REQUEST_BYTES, receiver_addr)
            .await
            .unwrap();

        // then: the last message is processed
        let (receved_msg, src_addr) = timeout(sec!(5), rx_channel.recv()).await.unwrap().unwrap();
        assert_eq!(src_addr, second_sender_addr.into());
        assert_eq!(receved_msg, bind_request_msg());
    }
}
