use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("transaction timed out")]
    Timeout,

    #[error("transaction channel is closed")]
    ChannelClosed,

    #[error(
        "transaction method mismatch (request={request_method:#x}, response={response_method:#x}"
    )]
    MethodMismatch {
        request_method: u16,
        response_method: u16,
    },
}

impl<T> From<mpsc::error::SendError<T>> for TransactionError {
    fn from(_value: mpsc::error::SendError<T>) -> Self {
        TransactionError::ChannelClosed
    }
}
