use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("transaction channel is closed")]
    ChannelClosed,
}

impl<T> From<mpsc::error::SendError<T>> for TransactionError {
    fn from(_value: mpsc::error::SendError<T>) -> Self {
        TransactionError::ChannelClosed
    }
}
