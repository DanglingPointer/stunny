use std::{borrow::Cow, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to parse message ({0})")]
    Parse(Cow<'static, str>),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Parse(_) => io::Error::new(io::ErrorKind::InvalidData, Box::new(value)),
            Error::Io(e) => e,
        }
    }
}
