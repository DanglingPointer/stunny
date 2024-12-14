mod error;
mod processor;
mod transactions;

pub use error::*;
pub use processor::*;
pub use transactions::*;

// re-export core
pub use stunny_core::*;

pub fn setup_transactions(message_channels: transport::MessageChannels) -> Processor {
    let request_receiver = RequestReceiver::from(message_channels);
    Processor::new(request_receiver)
}
