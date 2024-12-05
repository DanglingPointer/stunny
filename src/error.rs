use crate::{attributes, message};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    MalformedMessage(#[from] message::ParseError),

    #[error(transparent)]
    MalformedAttribute(#[from] attributes::ParseError),
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(e) => e,
            Error::MalformedMessage(_) | Error::MalformedAttribute(_) => {
                io::Error::new(io::ErrorKind::InvalidData, Box::new(value))
            }
        }
    }
}
