use super::message::*;

#[rustfmt::skip]
pub(super) const BIND_REQUEST_BYTES: [u8; 28] = [
    0x00, 0x01, 0x00, 0x08,
    0x21, 0x12, 0xA4, 0x42,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa,
    0x80, 0x22, 0x00, 0x03,
    b'U', b'g', b'h', 0x00,
];

#[rustfmt::skip]
pub(super) const BIND_RESPONSE_BYTES: [u8; 36] = [
    0x01, 0x01, 0x00, 0x10,
    0x21, 0x12, 0xA4, 0x42,
    0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb,
    0x80, 0x22, 0x00, 0x03,
    b'U', b'h', b'm', 0x00,
    0x80, 0x22, 0x00, 0x04,
    b'U', b'g', b'h', b'!',
];

#[rustfmt::skip]
pub(super) const BIND_INDICATION_BYTES: [u8; 20] = [
    0x00, 0x11, 0x00, 0x00,
    0x21, 0x12, 0xA4, 0x42,
    0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc,
];

pub(super) fn bind_request_msg() -> Message {
    Message {
        header: Header {
            method: 0b000000000001,
            class: Class::Request,
            transaction_id: [0xaa; 12],
            length: 8,
        },
        attributes: vec![Tlv {
            attribute_type: 0x8022,
            value: b"Ugh".to_vec(),
        }],
    }
}

pub(super) fn bind_response_msg() -> Message {
    Message {
        header: Header {
            method: 0b000000000001,
            class: Class::Response,
            transaction_id: [0xbb; 12],
            length: 16,
        },
        attributes: vec![
            Tlv {
                attribute_type: 0x8022,
                value: b"Uhm".to_vec(),
            },
            Tlv {
                attribute_type: 0x8022,
                value: b"Ugh!".to_vec(),
            },
        ],
    }
}

pub(super) fn bind_indication_msg() -> Message {
    Message {
        header: Header {
            method: 0b000000000001,
            class: Class::Indication,
            transaction_id: [0xcc; 12],
            length: 0,
        },
        attributes: Vec::new(),
    }
}

macro_rules! local_test {
    ($($arg:tt)+) => {{
        task::LocalSet::new().run_until(time::timeout(Duration::from_secs(5), async $($arg)+)).await.expect("test timeout");
    }}
}
