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
    fn append_attribute<A: Attribute>(&mut self, attribute: A);
    fn extract_attribute<A: Attribute>(&mut self) -> Result<A, LookupError>;
}

impl AttributeCollection for Vec<Tlv> {
    fn append_attribute<A: Attribute>(&mut self, attribute: A) {
        self.push(Tlv {
            attribute_type: A::ID,
            value: attribute.encode_value(),
        });
    }

    fn extract_attribute<A: Attribute>(&mut self) -> Result<A, LookupError> {
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

fn encode_socket_addr(addr: SocketAddr) -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
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

fn decode_socket_addr(
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
// Instead, we rely on `Message::xor_socket_addr()` being called elsewhere earlier.
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

#[derive(Debug)]
pub struct ErrorCode {
    pub code: u16,
    pub reason: String,
}

impl Attribute for ErrorCode {
    const ID: u16 = 0x0009;

    fn encode_value(self) -> Vec<u8> {
        let mut value = Vec::with_capacity(4 + self.reason.len());
        value.put_bytes(0, 2);
        value.put_u8((self.code / 100) as u8);
        value.put_u8((self.code % 100) as u8);
        value.put_slice(self.reason.as_bytes());
        value
    }

    fn decode_value(tlv_value: Vec<u8>) -> Result<Self, ParseError> {
        macro_rules! err {
            ($what:expr) => {
                ParseError::new("ERROR-CODE", $what)
            };
        }
        let mut buffer = tlv_value.as_slice();

        if buffer.remaining() < 4 {
            return Err(err!("buffer too short"));
        }

        if buffer.get_u16() != 0 {
            return Err(err!("non-zero prefix bytes"));
        }

        let class = buffer.get_u8();
        if !(3..=6).contains(&class) {
            return Err(err!(format!("invalid error class {class}")));
        }

        let number = buffer.get_u8();
        if !(0..100).contains(&number) {
            return Err(err!(format!("invalid error number {number}")));
        }

        let reason = str::from_utf8(buffer.chunk()).map_err(|e| err!(e))?;

        Ok(Self {
            code: class as u16 * 100 + number as u16,
            reason: reason.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_mapped_ipv4_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let tlv = MappedAddress(addr).encode_value();
        assert_eq!(tlv, vec![0, 1, 48, 57, 192, 168, 1, 1]);

        let decoded = MappedAddress::decode_value(tlv).unwrap();
        assert_eq!(decoded.0, addr);
    }

    #[test]
    fn test_encode_decode_mapped_ipv6_address() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 1)), 12345);
        let tlv = MappedAddress(addr).encode_value();
        assert_eq!(
            tlv,
            vec![0, 2, 48, 57, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 1]
        );

        let decoded = MappedAddress::decode_value(tlv).unwrap();
        assert_eq!(decoded.0, addr);
    }

    #[test]
    fn test_encode_decode_software() {
        let software = Software("stunny".to_owned());
        let tlv = software.encode_value();
        assert_eq!(tlv, b"stunny");

        let decoded = Software::decode_value(tlv).unwrap();
        assert_eq!(decoded.0, "stunny");
    }

    #[test]
    fn test_encode_decode_error_code() {
        let error = ErrorCode {
            code: 400,
            reason: "FAILED".to_owned(),
        };
        let tlv = error.encode_value();
        assert_eq!(tlv, b"\x00\x00\x04\x00FAILED");

        let decoded = ErrorCode::decode_value(tlv).unwrap();
        assert_eq!(decoded.code, 400);
        assert_eq!(decoded.reason, "FAILED");

        let error = ErrorCode {
            code: 420,
            reason: String::new(),
        };
        let tlv = error.encode_value();
        assert_eq!(tlv, b"\x00\x00\x04\x14");

        let decoded = ErrorCode::decode_value(tlv).unwrap();
        assert_eq!(decoded.code, 420);
        assert_eq!(decoded.reason, "");
    }
}
