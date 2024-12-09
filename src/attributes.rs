use crate::transport::message::{Tlv, MAGIC_COOKIE};
use bytes::{Buf, BufMut};
use core::str;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

// ------------------------------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum LookupError {
    #[error("attribute type {0:#06x} not found")]
    NotFound(u16),

    #[error(transparent)]
    Malformed(#[from] ParseError),
}

pub trait AttributeCollection {
    fn append<A: Attribute>(&mut self, attribute: A);
    fn extract<A: Attribute>(&mut self) -> Result<A, LookupError>;
}

impl AttributeCollection for Vec<Tlv> {
    fn append<A: Attribute>(&mut self, attribute: A) {
        self.push(Tlv {
            attribute_type: A::ID,
            value: attribute.encode_value(),
        });
    }

    fn extract<A: Attribute>(&mut self) -> Result<A, LookupError> {
        let mut i = 0;
        while i < self.len() {
            if self[i].attribute_type == A::ID {
                return Ok(A::decode_value(self.remove(i).value)?);
            }
            i += 1;
        }
        Err(LookupError::NotFound(A::ID))
    }
}

// ------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct MappedAddress(pub SocketAddr);

impl Attribute for MappedAddress {
    const ID: u16 = 0x0001;

    fn encode_value(self) -> Vec<u8> {
        let mut value = Vec::new();
        value.put_u8(0);
        match self.0 {
            SocketAddr::V4(addr) => {
                value.put_u8(0x01);
                value.put_u16(addr.port());
                value.put_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                value.put_u8(0x02);
                value.put_u16(addr.port());
                value.put_slice(&addr.ip().octets());
            }
        }
        value
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        fn parse_error(what: impl ToString) -> ParseError {
            ParseError {
                attribute_name: "MAPPED-ADDRESS",
                inner: what.to_string().into(),
            }
        }

        let mut buffer = tlv_value.as_slice();

        if buffer.remaining() < 4 {
            return Err(parse_error("buffer too short"));
        }

        if buffer.get_u8() != 0x00 {
            return Err(parse_error("incorrect prefix byte"));
        }

        let family = buffer.get_u8();
        let port = buffer.get_u16();

        let ip = match family {
            0x01 => {
                if buffer.remaining() < 4 {
                    return Err(parse_error("not enough bytes for IPv4 address"));
                }
                let mut octets = [0u8; 4];
                buffer.copy_to_slice(octets.as_mut_slice());
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            0x02 => {
                if buffer.remaining() < 16 {
                    return Err(parse_error("not enough bytes for IPv6 address"));
                }
                let mut octets = [0u8; 16];
                buffer.copy_to_slice(octets.as_mut_slice());
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(parse_error(format!(
                    "unexpected ip version {:#04x}",
                    family
                )));
            }
        };

        Ok(Self(SocketAddr::new(ip, port)))
    }
}

#[derive(Debug)]
pub struct XorMappedAddress(pub SocketAddr);

impl Attribute for XorMappedAddress {
    const ID: u16 = 0x0020;

    fn encode_value(self) -> Vec<u8> {
        let mut value = Vec::new();
        value.put_u8(0);
        match self.0 {
            SocketAddr::V4(addr) => {
                value.put_u8(0x01);
                value.put_u16(addr.port() ^ 0x2112u16);
                value.put_u32(addr.ip().to_bits() ^ MAGIC_COOKIE);
            }
            SocketAddr::V6(_addr) => {
                unimplemented!("XOR-MAPPED-ADDRESS is not implemented for IPv6");
            }
        }
        value
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        fn parse_error(what: impl ToString) -> ParseError {
            ParseError {
                attribute_name: "XOR-MAPPED-ADDRESS",
                inner: what.to_string().into(),
            }
        }

        let mut buffer = tlv_value.as_slice();

        if buffer.remaining() < 4 {
            return Err(parse_error("buffer too short"));
        }

        if buffer.get_u8() != 0x00 {
            return Err(parse_error("incorrect prefix byte"));
        }

        let family = buffer.get_u8();
        let port = buffer.get_u16() ^ 0x2112u16;

        let ip = match family {
            0x01 => {
                if buffer.remaining() < 4 {
                    return Err(parse_error("not enough bytes for IPv4 address"));
                }
                let octets = buffer.get_u32();
                IpAddr::V4(Ipv4Addr::from_bits(octets ^ MAGIC_COOKIE))
            }
            0x02 => {
                if buffer.remaining() < 16 {
                    return Err(parse_error("not enough bytes for IPv6 address"));
                }
                unimplemented!("XOR-MAPPED-ADDRESS is not implemented for IPv6");
            }
            _ => {
                return Err(parse_error(format!(
                    "unexpected ip version {:#04x}",
                    family
                )));
            }
        };

        Ok(Self(SocketAddr::new(ip, port)))
    }
}

pub struct Software(pub String);

impl Attribute for Software {
    const ID: u16 = 0x8022;

    fn encode_value(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        let text = str::from_utf8(&tlv_value).map_err(|e| ParseError::new("SOFTWARE", e))?;
        Ok(Self(text.to_owned()))
    }
}
