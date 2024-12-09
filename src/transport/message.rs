use bitvec::prelude::*;
use bytes::{Buf, BufMut};
use derive_more::Debug;
use std::borrow::Cow;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("failed to parse message ({0})")]
pub struct ParseError(Cow<'static, str>);

impl<T: Into<Cow<'static, str>>> From<T> for ParseError {
    fn from(value: T) -> Self {
        ParseError(value.into())
    }
}

impl From<ParseError> for io::Error {
    fn from(e: ParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, Box::new(e))
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Message {
    pub header: Header,
    pub attributes: Vec<Tlv>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Header {
    pub method: u16,
    pub class: Class,
    pub transaction_id: [u8; 12],
    pub length: u16,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Class {
    Request,
    Response,
    Error,
    Indication,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Tlv {
    #[debug("{attribute_type:#06x}")]
    pub attribute_type: u16,
    pub value: Vec<u8>,
}

macro_rules! ceil_mul_4 {
    ($x:expr) => {
        ($x + 3) & !0x3
    };
}

impl Message {
    pub fn request(method: u16, transaction_id: [u8; 12], attributes: Vec<Tlv>) -> Self {
        Self {
            header: Header {
                method,
                class: Class::Request,
                transaction_id,
                length: Self::calculate_len(&attributes),
            },
            attributes,
        }
    }

    pub fn response(method: u16, transaction_id: [u8; 12], attributes: Vec<Tlv>) -> Self {
        Self {
            header: Header {
                method,
                class: Class::Response,
                transaction_id,
                length: Self::calculate_len(&attributes),
            },
            attributes,
        }
    }

    pub fn error(method: u16, transaction_id: [u8; 12], attributes: Vec<Tlv>) -> Self {
        Self {
            header: Header {
                method,
                class: Class::Error,
                transaction_id,
                length: Self::calculate_len(&attributes),
            },
            attributes,
        }
    }

    pub fn indication(method: u16, transaction_id: [u8; 12], attributes: Vec<Tlv>) -> Self {
        Self {
            header: Header {
                method,
                class: Class::Indication,
                transaction_id,
                length: Self::calculate_len(&attributes),
            },
            attributes,
        }
    }

    fn calculate_len<'t>(attributes: impl IntoIterator<Item = &'t Tlv>) -> u16 {
        let len: usize = attributes
            .into_iter()
            .map(|tlv| ceil_mul_4!(tlv.value.len()) + Tlv::HEADER_SIZE)
            .sum();
        len as u16
    }
}

pub trait EncodeDecode: Sized {
    fn decode_from<B: Buf>(buffer: &mut B) -> Result<Self, ParseError>;

    fn encode_into<B: BufMut>(&self, buffer: &mut B) -> Result<(), io::Error>;
}

pub(crate) const MAGIC_COOKIE: u32 = 0x2112A442;

impl Header {
    pub(super) const SIZE: usize = 20;
}

impl Tlv {
    pub(super) const HEADER_SIZE: usize = 4;
}

impl EncodeDecode for Header {
    fn decode_from<B: Buf>(buffer: &mut B) -> Result<Self, ParseError> {
        if buffer.remaining() < Self::SIZE {
            return Err("incorrect header length".into());
        }

        let mut buffer = buffer.take(Self::SIZE);

        let method_class_bytes = buffer.get_u16();
        let length = buffer.get_u16();
        let magic_cookie = buffer.get_u32();

        if magic_cookie != MAGIC_COOKIE {
            return Err("incorrect magic cookie".into());
        }

        let mut method_class_bits = BitArray::<u16, Lsb0>::from(method_class_bytes);
        if method_class_bits[14..].any() {
            return Err("non-zero first bits".into());
        }
        //
        //  0                 1
        //  2  3  4 5 6 7 8 9 0 1 2 3 4 5
        // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
        // |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
        // |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
        // +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

        let class = match (method_class_bits[8], method_class_bits[4]) {
            (true, true) => Class::Error,
            (true, false) => Class::Response,
            (false, true) => Class::Indication,
            (false, false) => Class::Request,
        };

        let method = {
            method_class_bits.copy_within(5..8, 4);
            method_class_bits.copy_within(9.., 7);
            method_class_bits[12..].fill(false);
            method_class_bits.data
        };

        let mut ret = Self {
            method,
            class,
            transaction_id: [0u8; 12],
            length,
        };

        buffer.copy_to_slice(&mut ret.transaction_id);

        Ok(ret)
    }

    fn encode_into<B: BufMut>(&self, buffer: &mut B) -> Result<(), io::Error> {
        if buffer.remaining_mut() < Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "not enough bytes to write header",
            ));
        }

        let method_bits = self.method.view_bits();
        let mut method_class_bits = BitArray::<u16, Lsb0>::from(0u16);
        method_class_bits[..4].copy_from_bitslice(&method_bits[0..4]);
        method_class_bits.set(4, matches!(self.class, Class::Error | Class::Indication));
        method_class_bits[5..8].copy_from_bitslice(&method_bits[4..7]);
        method_class_bits.set(8, matches!(self.class, Class::Error | Class::Response));
        method_class_bits[9..14].copy_from_bitslice(&method_bits[7..12]);
        method_class_bits[14..].fill(false);
        buffer.put_u16(method_class_bits.data);

        buffer.put_u16(self.length);
        buffer.put_u32(MAGIC_COOKIE);
        buffer.put_slice(&self.transaction_id);

        Ok(())
    }
}

impl EncodeDecode for Tlv {
    fn decode_from<B: Buf>(buffer: &mut B) -> Result<Self, ParseError> {
        if buffer.remaining() < Self::HEADER_SIZE {
            return Err("buffer not long enough to read TLV".into());
        }

        let attribute_type = buffer.get_u16();
        let value_len = buffer.get_u16() as usize;
        let real_value_len = ceil_mul_4!(value_len);

        if buffer.remaining() < real_value_len {
            return Err(format!(
                "TLV length exceeds buffer size ({} > {})",
                real_value_len,
                buffer.remaining()
            )
            .into());
        }

        let mut value = vec![0u8; value_len];
        buffer.copy_to_slice(&mut value);
        buffer.advance(real_value_len - value_len);

        Ok(Self {
            attribute_type,
            value,
        })
    }

    fn encode_into<B: BufMut>(&self, buffer: &mut B) -> Result<(), io::Error> {
        let real_value_len = ceil_mul_4!(self.value.len());

        if buffer.remaining_mut() < Self::HEADER_SIZE + real_value_len {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "not enough bytes to write TLV",
            ));
        }

        buffer.put_u16(self.attribute_type);
        buffer.put_u16(self.value.len() as u16);
        buffer.put_slice(&self.value);
        buffer.put_bytes(0u8, real_value_len - self.value.len());

        Ok(())
    }
}

impl EncodeDecode for Vec<Tlv> {
    fn decode_from<B: Buf>(buffer: &mut B) -> Result<Self, ParseError> {
        let mut ret = Vec::new();
        while buffer.has_remaining() {
            ret.push(Tlv::decode_from(buffer)?);
        }
        Ok(ret)
    }

    fn encode_into<B: BufMut>(&self, buffer: &mut B) -> Result<(), io::Error> {
        for tlv in self {
            tlv.encode_into(buffer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    const BIND_REQUEST_HEADER: [u8; 20] = [
        0x00, 0x01, 0x00, 0x0c,
        0x21, 0x12, 0xA4, 0x42,
        0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa,
    ];

    #[rustfmt::skip]
    const BIND_RESPONSE_HEADER: [u8; 20] = [
        0x01, 0x01, 0x01, 0x00,
        0x21, 0x12, 0xA4, 0x42,
        0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb,
    ];

    #[rustfmt::skip]
    const SOFTWARE_ATTRIBUTE: [u8; 8] = [
        0x80, 0x22, 0x00, 0x03,
        b'U', b'g', b'h', 0x00,
    ];

    #[test]
    fn decode_bind_request_header() {
        let mut buffer = &BIND_REQUEST_HEADER[..];
        let header = Header::decode_from(&mut buffer).unwrap();
        assert_eq!(header.method, 0b000000000001);
        assert_eq!(header.class, Class::Request);
        assert_eq!(header.length, 12);
        assert_eq!(header.transaction_id, [0xaa; 12]);
    }

    #[test]
    fn encode_bind_request_header() {
        let mut buffer = [0u8; Header::SIZE];
        let header = Header {
            method: 0b000000000001,
            class: Class::Request,
            transaction_id: [0xaa; 12],
            length: 12,
        };
        header.encode_into(&mut buffer.as_mut_slice()).unwrap();
        assert_eq!(buffer, BIND_REQUEST_HEADER);
    }

    #[test]
    fn decode_bind_response_header() {
        let mut buffer = &BIND_RESPONSE_HEADER[..];
        let header = Header::decode_from(&mut buffer).unwrap();
        assert_eq!(header.method, 0b000000000001);
        assert_eq!(header.class, Class::Response);
        assert_eq!(header.length, 256);
        assert_eq!(header.transaction_id, [0xbb; 12]);
    }

    #[test]
    fn encode_bind_response_header() {
        let mut buffer = [0u8; Header::SIZE];
        let header = Header {
            method: 0b000000000001,
            class: Class::Response,
            transaction_id: [0xbb; 12],
            length: 256,
        };
        header.encode_into(&mut buffer.as_mut_slice()).unwrap();
        assert_eq!(buffer, BIND_RESPONSE_HEADER);
    }

    #[test]
    fn decode_software_attribute() {
        let mut buffer = &SOFTWARE_ATTRIBUTE[..];
        let tlv = Tlv::decode_from(&mut buffer).unwrap();
        assert_eq!(tlv.attribute_type, 0x8022);
        assert_eq!(tlv.value, b"Ugh");
    }

    #[test]
    fn encode_software_attribute() {
        let mut buffer = Vec::new();
        let tlv = Tlv {
            attribute_type: 0x8022,
            value: b"Ugh".to_vec(),
        };
        tlv.encode_into(&mut buffer).unwrap();
        assert_eq!(buffer, SOFTWARE_ATTRIBUTE);
    }

    #[test]
    fn decode_multiple_attributes() {
        #[rustfmt::skip]
        let buffer = [
            0x80, 0x22, 0x00, 0x03,
            b'U', b'h', b'm', 0x00,
            0x80, 0x22, 0x00, 0x04,
            b'U', b'g', b'h', b'!',
        ];
        let mut buffer = &buffer[..];

        let tlv = Tlv::decode_from(&mut buffer).unwrap();
        assert_eq!(tlv.attribute_type, 0x8022);
        assert_eq!(tlv.value, b"Uhm");

        let tlv = Tlv::decode_from(&mut buffer).unwrap();
        assert_eq!(tlv.attribute_type, 0x8022);
        assert_eq!(tlv.value, b"Ugh!");
    }

    #[test]
    fn decode_bind_request_with_software_attribute() {
        #[rustfmt::skip]
        let buffer = [
            0x00, 0x01, 0x00, 0x08,
            0x21, 0x12, 0xA4, 0x42,
            0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa,
            0x80, 0x22, 0x00, 0x03,
            b'U', b'g', b'h', 0x00,
        ];

        let mut buffer = &buffer[..];
        let header = Header::decode_from(&mut buffer).unwrap();
        assert_eq!(header.method, 0b000000000001);
        assert_eq!(header.class, Class::Request);
        assert_eq!(header.length, 8);
        assert_eq!(header.transaction_id, [0xaa; 12]);

        let tlv = Tlv::decode_from(&mut buffer).unwrap();
        assert_eq!(tlv.attribute_type, 0x8022);
        assert_eq!(tlv.value, b"Ugh");
    }

    #[test]
    fn encode_bind_response_with_software_attribute() {
        let mut buffer = Vec::new();
        let header = Header {
            method: 0b000000000001,
            class: Class::Response,
            transaction_id: [0xbb; 12],
            length: 8,
        };
        header.encode_into(&mut buffer).unwrap();

        let tlv = Tlv {
            attribute_type: 0x8022,
            value: b"Ugh!".to_vec(),
        };
        tlv.encode_into(&mut buffer).unwrap();

        #[rustfmt::skip]
        let expected = [
            0x01, 0x01, 0x00, 0x08,
            0x21, 0x12, 0xA4, 0x42,
            0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb,
            0x80, 0x22, 0x00, 0x04,
            b'U', b'g', b'h', b'!',
        ];
        assert_eq!(buffer, expected);
    }

    #[test]
    fn calculate_message_length() {
        let attributes = [
            Tlv {
                attribute_type: 0x8022,
                value: b"Ugh!".to_vec(),
            },
            Tlv {
                attribute_type: 0x8022,
                value: Vec::new(),
            },
            Tlv {
                attribute_type: 0x8022,
                value: b"A".to_vec(),
            },
            Tlv {
                attribute_type: 0x8022,
                value: b"B".to_vec(),
            },
        ];
        assert_eq!(Message::calculate_len(attributes.iter()), 28);
    }
}
