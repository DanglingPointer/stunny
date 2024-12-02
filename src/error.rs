use std::{borrow::Cow, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to parse message ({0})")]
    Parse(Cow<'static, str>),
    #[error(transparent)]
    Io(#[from] io::Error),
}
