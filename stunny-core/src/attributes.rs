use crate::message::Tlv;
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
        E: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        Self {
            attribute_name: name,
            inner: error.into(),
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

pub fn encode_socket_addr(addr: SocketAddr) -> Vec<u8> {
    let mut value = Vec::new();
    value.put_u8(0);
    match addr {
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

pub fn decode_socket_addr(
    tlv_value: Vec<u8>,
    attribute_name: &'static str,
) -> Result<SocketAddr, ParseError> {
    macro_rules! parse_error {
        ($what:expr) => {
            ParseError::new(attribute_name, $what)
        };
    }

    let mut buffer = tlv_value.as_slice();

    if buffer.remaining() < 4 {
        return Err(parse_error!("buffer too short"));
    }

    if buffer.get_u8() != 0x00 {
        return Err(parse_error!("incorrect prefix byte"));
    }

    let family = buffer.get_u8();
    let port = buffer.get_u16();

    let ip = match family {
        0x01 => {
            if buffer.remaining() < 4 {
                return Err(parse_error!("not enough bytes for IPv4 address"));
            }
            let mut octets = [0u8; 4];
            buffer.copy_to_slice(octets.as_mut_slice());
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x02 => {
            if buffer.remaining() < 16 {
                return Err(parse_error!("not enough bytes for IPv6 address"));
            }
            let mut octets = [0u8; 16];
            buffer.copy_to_slice(octets.as_mut_slice());
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            return Err(parse_error!(format!(
                "unexpected ip version {:#04x}",
                family
            )));
        }
    };

    Ok(SocketAddr::new(ip, port))
}

#[derive(Debug)]
pub struct MappedAddress(pub SocketAddr);

impl Attribute for MappedAddress {
    const ID: u16 = 0x0001;

    fn encode_value(self) -> Vec<u8> {
        encode_socket_addr(self.0)
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        Ok(Self(decode_socket_addr(tlv_value, "MAPPED-ADDRESS")?))
    }
}

#[derive(Debug)]
pub struct XorMappedAddress(pub SocketAddr);

// For encoding and decoding IPv6, we need access to transaction id which we don't have here.
// Instead, `transactions::Manager` will perform the XOR operations, converting all XOR-MAPPED-ADDRESS attributes
// to MAPPED-ADDRESS
impl Attribute for XorMappedAddress {
    const ID: u16 = 0x0020;

    fn encode_value(self) -> Vec<u8> {
        encode_socket_addr(self.0)
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        Ok(Self(decode_socket_addr(tlv_value, "XOR-MAPPED-ADDRESS")?))
    }
}

#[derive(Debug)]
pub struct ResponseOrigin(pub SocketAddr);

impl Attribute for ResponseOrigin {
    const ID: u16 = 0x802b;

    fn encode_value(self) -> Vec<u8> {
        encode_socket_addr(self.0)
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        Ok(Self(decode_socket_addr(tlv_value, "RESPONSE-ORIGIN")?))
    }
}

#[derive(Debug)]
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
