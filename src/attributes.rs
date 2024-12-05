use core::str;
use std::fmt::Display;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to parse attribute {attribute_name} ({error_msg})")]
pub struct ParseError {
    attribute_name: &'static str,
    error_msg: String,
}

impl ParseError {
    pub fn new(name: &'static str, error: impl Display) -> Self {
        Self {
            attribute_name: name,
            error_msg: error.to_string(),
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
