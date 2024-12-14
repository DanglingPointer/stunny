use futures_util::TryFutureExt;
use local_async_utils::sec;
use std::net::{Ipv4Addr, SocketAddrV4};
use stunny_client::{attributes::*, transport::udp::setup_udp};
use stunny_client::{setup_transactions, DefaultExponentialBackoffFixedRtt, TransactionError};
use tokio::{net::UdpSocket, task};
use tokio::{time, try_join};

/// Single-threaded UDP client that sends BIND requests to localhost:3478 every second.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init();

    task::LocalSet::new()
        .run_until(async move {
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .await
                .unwrap();

            let (message_channels, io_driver) = setup_udp(socket, 1024);

            let (request_sender, _, _, processor) = setup_transactions(
                message_channels,
                10,
                DefaultExponentialBackoffFixedRtt::default(),
            );

            task::spawn_local(async move {
                try_join!(io_driver.run().map_err(TransactionError::from), processor.run())
                    .inspect_err(|e| log::error!("Client exited with error: {e}"))
            });

            loop {
                let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3478);
                log::info!("Sending request to {}", addr);
                let result = request_sender
                    .send_request(addr.into(), 0x0001, vec![])
                    .await;
                log::info!("Response received: {:?}", result);
                if let Ok(response) = &result {
                    let mut attributes = response.attributes.clone();
                    macro_rules! print_attrs {
                        ($( $attr_name:ident ),+) => {
                            $(
                                if let Ok(attr_value) = attributes.extract_attribute::<$attr_name>() {
                                    log::info!("Attribute found: {:?}", attr_value);
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
                } else {
                    break;
                }
                time::sleep(sec!(1)).await;
            }
        })
        .await;
    Ok(())
}
