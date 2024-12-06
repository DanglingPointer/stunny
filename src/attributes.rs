use core::str;
use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to parse attribute {attribute_name} ({inner})")]
pub struct ParseError {
    attribute_name: &'static str,
    #[source]
    inner: Box<dyn Error + Send + Sync>,
}

impl ParseError {
    pub fn new<E>(name: &'static str, error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            attribute_name: name,
            inner: Box::new(error),
        }
    }
}

pub trait Attribute: Sized {
    const ID: u16;

    fn encode_value(self) -> Vec<u8>;
    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError>;
}

pub struct SoftwareAttribute(pub String);

impl Attribute for SoftwareAttribute {
    const ID: u16 = 0x8022;

    fn encode_value(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        let text =
            str::from_utf8(&tlv_value).map_err(|e| ParseError::new("SoftwareAttribute", e))?;
        Ok(Self(text.to_owned()))
    }
}
