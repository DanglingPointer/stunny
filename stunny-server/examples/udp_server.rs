use futures_util::TryFutureExt;
use std::net::{Ipv4Addr, SocketAddrV4};
use stunny_server::setup_transactions;
use stunny_server::transport::udp::setup_udp;
use tokio::{net::UdpSocket, task};

/// Multi-threaded UDP server that serves BIND requests on port 3478
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .init()?;

    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3478)).await?;

    log::info!("Starting server on port 3478");

    let (message_channels, io_driver) = setup_udp(socket, 1024);
    task::spawn(
        io_driver
            .run()
            .inspect_err(|e| log::error!("Server exited with error: {e}")),
    );

    let processor = setup_transactions(message_channels);
    processor.run().await;

    Ok(())
}
