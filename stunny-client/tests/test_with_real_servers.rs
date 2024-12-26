#![cfg(all(feature = "udp", feature = "tcp"))]
use futures::StreamExt;
use local_async_utils::{local_sync, millisec, sec};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use stunny_client::*;
use stunny_core::attributes::*;
use stunny_core::transport::tcp::setup_tcp_client;
use stunny_core::transport::udp::setup_udp;
use tokio::net::{lookup_host, TcpSocket, UdpSocket};
use tokio::{join, task, time};

macro_rules! local_test {
    ($($arg:tt)+) => {{
        task::LocalSet::new().run_until(time::timeout(sec!(10), async { $($arg)+ })).await.expect("test timeout");
    }}
}

const UDP_SERVERS: [&str; 4] = [
    "stun:stunserver2024.stunprotocol.org:3478",
    "stun:stun.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
    "stun:stun4.l.google.com:19302",
];

const TCP_SERVERS: [&str; 3] = [
    "stun:stunserver2024.stunprotocol.org:3478",
    "stun:stun.sipnet.net:3478",
    "stun:stun.sipnet.ru:3478",
];

async fn parse_server_addrs<'a>(
    urls: impl IntoIterator<Item = &'a str> + 'a,
) -> HashSet<SocketAddr> {
    let mut ret = HashSet::new();
    for host in urls.into_iter().filter_map(|url| url.strip_prefix("stun:")) {
        if let Ok(addrs) = lookup_host(host).await {
            ret.extend(addrs.filter(SocketAddr::is_ipv4));
        }
    }
    ret
}

async fn do_bind_request(
    request_sender: RequestSender,
    addr: SocketAddr,
    result_sender: local_sync::channel::Sender<Result<Response, TransactionError>>,
) {
    println!("Sending request to {:?}", addr);
    let result = request_sender.send_request(addr, 0x0001, vec![]).await;
    println!("Response from {}:\n{:?}", addr, result);
    if let Ok(response) = &result {
        let mut attributes = response.attributes.clone();
        macro_rules! print_attrs {
            ($( $attr_name:ident ),+) => {
                $(
                    if let Ok(attr_value) = attributes.extract_attribute::<$attr_name>() {
                        println!("{}: {:?}", stringify!($attr_name), attr_value);
                    }
                )+
            };
        }
        print_attrs!(
            MappedAddress,
            XorMappedAddress,
            ResponseOrigin,
            Software,
            ErrorCode
        );
    }
    result_sender.send(result);
}

fn parse_mapped_addr(mut response: Response) -> Option<SocketAddr> {
    if response.success {
        let mapped_addr = response.attributes.extract_attribute::<MappedAddress>();
        let xor_mapped_addr = response.attributes.extract_attribute::<XorMappedAddress>();
        match (mapped_addr, xor_mapped_addr) {
            (Ok(MappedAddress(mapped)), Ok(XorMappedAddress(xor_mapped))) => {
                assert_eq!(mapped, xor_mapped);
                Some(mapped)
            }
            (Ok(MappedAddress(mapped)), Err(_)) => Some(mapped),
            (Err(_), Ok(XorMappedAddress(xor_mapped))) => Some(xor_mapped),
            (Err(_), Err(_)) => None,
        }
    } else {
        None
    }
}

#[tokio::test]
async fn send_bind_request_over_udp() {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .init();
    local_test! {
        const MAX_CONCURRENT_REQUESTS: usize = 10;

        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let (message_channels, driver) = setup_udp(socket, MAX_CONCURRENT_REQUESTS);

        let (request_sender, _, _, processor) = setup_transactions(
            message_channels,
            MAX_CONCURRENT_REQUESTS,
            DefaultExponentialBackoffFixedRtt::new(millisec!(100)),
        );

        task::spawn_local(async move {
            let _result = join!(driver.run(), processor.run());
        });

        let (result_sender, result_receiver) = local_sync::channel();

        for addr in parse_server_addrs(UDP_SERVERS).await {
            task::spawn_local(do_bind_request(
                request_sender.clone(),
                addr,
                result_sender.clone(),
            ));
        }
        drop(result_sender);

        let results: Vec<_> = result_receiver.collect().await;
        assert!(
            results
                .iter()
                .any(|result| matches!(result, Ok(response) if response.success)),
            "{results:?}"
        );
        let addrs: Vec<_> = results
            .into_iter()
            .filter_map(|result| result.ok())
            .filter_map(parse_mapped_addr)
            .collect();
        assert!(!addrs.is_empty(), "{addrs:?}");
    }
}

#[tokio::test]
async fn send_bind_request_over_tcp() {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .init();
    local_test! {
        const MAX_CONCURRENT_REQUESTS: usize = 10;

        let (message_channels, connection_pool) =
            setup_tcp_client(MAX_CONCURRENT_REQUESTS, Duration::from_secs(10), || {
                TcpSocket::new_v4().inspect(|s| s.set_nodelay(true).unwrap())
            });

        let (request_sender, _, _, processor) = setup_transactions(
            message_channels,
            MAX_CONCURRENT_REQUESTS,
            NoRetransmissionsConstTimeout::new(sec!(1)),
        );

        task::spawn_local(async move {
            let _result = join!(connection_pool.run(), processor.run());
        });

        let (result_sender, result_receiver) = local_sync::channel();

        for addr in parse_server_addrs(TCP_SERVERS).await {
            task::spawn_local(do_bind_request(
                request_sender.clone(),
                addr,
                result_sender.clone(),
            ));
        }
        drop(result_sender);

        let results: Vec<_> = result_receiver.collect().await;
        assert!(
            results
                .iter()
                .any(|result| matches!(result, Ok(response) if response.success)),
            "{results:?}"
        );
        let addrs: Vec<_> = results
            .into_iter()
            .filter_map(|result| result.ok())
            .filter_map(parse_mapped_addr)
            .collect();
        assert!(!addrs.is_empty(), "{addrs:?}");
    }
}
