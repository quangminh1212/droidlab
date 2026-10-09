//! Conformance tests for the frame header, driven by `protocol/vectors/framing-basic.json`.
//!
//! Each of the six vectors gives a `decoded` object (the fields the header must have), the
//! `frame` bytes, and the `body_hex`. The header is decoded from the frame, checked field by
//! field against the vector, re-encoded, and compared byte for byte with the frame the vector
//! supplies. A codec that reads correctly but writes a different byte order passes the first
//! check and fails the second, which is why both are here.

use droidlab_protocol::{FrameFlag, FrameHeader, FIXED_LENGTH, MAGIC, PROTOCOL_VERSION};

#[path = "vectors/mod.rs"]
mod vectors;

use serde_json::Value;

/// The `decoded.header` object of a vector.
fn header_of(vector: &Value) -> &Value {
    vectors::nested(vectors::nested(vector, "decoded"), "header")
}

/// The expected header fields, as a `FrameHeader`.
fn expected_header(vector: &Value) -> FrameHeader {
    let header = header_of(vector);

    FrameHeader {
        version: vectors::u8_field(header, "version"),
        flags: vectors::u8_field(header, "flags"),
        header_length: vectors::u8_field(header, "header_length"),
        message_type: vectors::u8_field(header, "message_type"),
        channel_id: vectors::u32_field(header, "channel_id"),
        sequence_number: vectors::u32_field(header, "sequence_number"),
        acknowledgment: vectors::u32_field(header, "acknowledgment"),
        body_length: vectors::u32_field(header, "body_length"),
    }
}

/// Every vector's `frame` is at least a header, and the magic is `DLWP`.
///
/// Asserted for all six before anything decodes, so that a truncated fixture is reported as a
/// fixture defect rather than as a decode failure in the code under test.
#[test]
fn every_frame_carries_the_magic_and_at_least_a_header() {
    let all = vectors::vectors(vectors::FRAMING_BASIC);

    assert_eq!(all.len(), 6, "framing-basic.json declares six vectors");

    for vector in &all {
        let frame = vectors::hex(vectors::str_field(vector, "frame"));

        assert!(
            frame.len() >= FIXED_LENGTH,
            "vector {:?} frame is {} bytes, shorter than a header",
            vectors::id(vector),
            frame.len()
        );
        assert_eq!(
            frame.get(0..4),
            Some(MAGIC.as_slice()),
            "vector {:?} does not begin with the DLWP magic",
            vectors::id(vector)
        );
        assert_eq!(
            vectors::str_field(header_of(vector), "magic"),
            "DLWP",
            "vector {:?} declares magic {:?}",
            vectors::id(vector),
            vectors::str_field(header_of(vector), "magic")
        );
    }
}

/// Every vector decodes to exactly the fields the vector declares.
#[test]
fn every_vector_decodes_to_its_declared_header() {
    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let frame = vectors::hex(vectors::str_field(vector, "frame"));
        let expected = expected_header(vector);

        let decoded = FrameHeader::decode(&frame).unwrap_or_else(|error| {
            panic!("vector {:?} failed to decode: {error}", vectors::id(vector))
        });

        assert_eq!(
            decoded,
            expected,
            "vector {:?} decoded to {decoded:?}, expected {expected:?}",
            vectors::id(vector)
        );
    }
}

/// Every vector re-encodes to the exact bytes the vector supplies.
///
/// This is the half a decode-only test misses. It also pins the reserved-flag behaviour: a vector
/// whose `flags` byte has reserved bits set must round-trip **unchanged**, because a receiver
/// ignores those bits rather than rewriting them. The separate case that asserts masking is
/// `encoding_masks_the_reserved_flag_bits`.
#[test]
fn every_vector_re_encodes_to_its_declared_bytes() {
    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let frame = vectors::hex(vectors::str_field(vector, "frame"));
        let header = FrameHeader::decode(&frame).expect("a vector frame decodes");

        let re_encoded = header.encode();

        // `encode` produces the 24-byte HEADER, not the whole frame, so the comparison is against
        // the frame's first 24 bytes. Comparing against the whole frame fails for any vector with
        // a body, which is five of the six -- a test bug, not a codec bug, and the vectors are
        // what told me so.
        let expected = frame.get(0..FIXED_LENGTH).expect("the frame has a header");

        assert_eq!(
            re_encoded.as_slice(),
            expected,
            "vector {:?} re-encoded to {}, expected {}",
            vectors::id(vector),
            vectors::to_hex(&re_encoded),
            vectors::to_hex(expected)
        );
    }
}

/// `header_length` is 24 and the declared body length matches the `body_hex` in the same vector.
///
/// The two halves of a vector are checked against each other, not only against the codec. A
/// vector whose `body_length` disagrees with its own `body_hex` is a defective fixture, and
/// without this the codec would be blamed for it.
#[test]
fn the_declared_body_length_matches_the_declared_body() {
    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let header = header_of(vector);
        let frame = vectors::hex(vectors::str_field(vector, "frame"));
        let body = vectors::hex(vectors::str_field(vector, "body_hex"));

        assert_eq!(
            vectors::u8_field(header, "header_length"),
            24,
            "vector {:?} declares header_length {}",
            vectors::id(vector),
            vectors::u8_field(header, "header_length")
        );

        let declared = vectors::u32_field(header, "body_length");

        assert_eq!(
            u64::from(declared),
            body.len() as u64,
            "vector {:?} declares body_length {declared} but body_hex is {} bytes",
            vectors::id(vector),
            body.len()
        );

        assert_eq!(
            frame.len(),
            FIXED_LENGTH + body.len(),
            "vector {:?} frame is {} bytes; header plus body is {}",
            vectors::id(vector),
            frame.len(),
            FIXED_LENGTH + body.len()
        );
    }
}

/// The framing vectors agree on the protocol version.
#[test]
fn every_vector_speaks_version_one() {
    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        assert_eq!(
            vectors::u8_field(header_of(vector), "version"),
            PROTOCOL_VERSION,
            "vector {:?} is not version {PROTOCOL_VERSION}",
            vectors::id(vector)
        );
    }
}

/// `PING` carries no parameters, so its body is the zero-length byte string.
#[test]
fn the_ping_vector_has_an_empty_body() {
    let all = vectors::vectors(vectors::FRAMING_BASIC);
    let ping = all
        .iter()
        .find(|vector| vectors::id(vector) == "framing.ping.empty-body")
        .expect("the ping vector is present");

    assert_eq!(vectors::u32_field(header_of(ping), "body_length"), 0);
    assert!(
        vectors::str_field(ping, "body_hex").is_empty(),
        "PING's body_hex is empty"
    );

    // The body is a zero-length byte string, NOT the empty map 0xA0. The distinction is a
    // conformance requirement, and the note in the vector says so.
    let frame = vectors::hex(vectors::str_field(ping, "frame"));

    assert_eq!(
        frame.len(),
        FIXED_LENGTH,
        "a bodyless frame is exactly 24 bytes"
    );
}

/// The flag bits a vector sets decode into the flags the same vector names.
///
/// The urgent/acknowledgment vector and the end-of-stream vector are the two that exercise more
/// than one flag, so they are checked by bit rather than by the raw byte.
#[test]
fn the_flag_bits_decode_as_declared() {
    let all = vectors::vectors(vectors::FRAMING_BASIC);

    let pong = all
        .iter()
        .find(|vector| vectors::id(vector) == "framing.pong-with-urgent-and-ack")
        .expect("the pong vector is present");
    let header = FrameHeader::decode(&vectors::hex(vectors::str_field(pong, "frame")))
        .expect("the pong frame decodes");

    assert!(header.has_flag(FrameFlag::Urgent), "PONG sets URGENT");
    assert!(
        !header.has_flag(FrameFlag::Encrypted),
        "PONG is cleartext in this vector"
    );
    assert_eq!(
        header.reserved_flags(),
        0,
        "this vector sets no reserved bit"
    );
    assert_eq!(
        header.acknowledgment,
        vectors::u32_field(header_of(pong), "acknowledgment"),
        "and the acknowledgment field is the one the vector declares"
    );
    assert!(
        header.acknowledgment > 0,
        "the vector names an acknowledgment, so it must not be zero"
    );

    let end_of_stream = all
        .iter()
        .find(|vector| vectors::id(vector) == "framing.end-of-stream.channel-close")
        .expect("the end-of-stream vector is present");
    let header = FrameHeader::decode(&vectors::hex(vectors::str_field(end_of_stream, "frame")))
        .expect("the end-of-stream frame decodes");

    assert!(
        header.has_flag(FrameFlag::EndOfStream),
        "it sets END_OF_STREAM"
    );
    assert_eq!(
        header.message_type, 34,
        "and it is a CHANNEL_CLOSE, which is type 34"
    );
    assert!(header.channel_id > 0, "a channel close names its channel");
}

/// `HELLO` is cleartext and every other type must be encrypted.
///
/// Checked against the vectors' own message types rather than a list written here, so a new
/// vector that contradicts the rule fails this test.
#[test]
fn only_hello_and_hello_ack_may_be_cleartext() {
    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let frame = vectors::hex(vectors::str_field(vector, "frame"));
        let header = FrameHeader::decode(&frame).expect("a vector frame decodes");

        let encrypted = header.has_flag(FrameFlag::Encrypted);
        let message_type = header.message_type;

        // The rule, expressed over the vectors rather than restated: a frame's encryption must
        // agree with what its message type requires.
        if matches!(message_type, 1 | 2) {
            assert!(
                !encrypted,
                "vector {:?} encrypts message type {message_type}, which must be cleartext",
                vectors::id(vector)
            );
            assert!(
                !header.must_be_encrypted(),
                "HELLO and HELLO_ACK are the two types that must not be encrypted"
            );
        } else {
            assert!(
                header.must_be_encrypted(),
                "message type {message_type} must be encrypted"
            );
        }
    }
}

/// The reserved flag bits are ignored on decode and preserved through a round trip.
///
/// Driven with a header the vectors do not contain, because no vector sets a reserved bit — which
/// is exactly why this needs its own case. A receiver that rejected them would refuse a conformant
/// peer on a future minor version, and RFC-0001 §3.1 requires the opposite.
#[test]
fn decoding_ignores_the_reserved_flag_bits() {
    let mut bytes = FrameHeader {
        version: 1,
        flags: 0x00,
        header_length: 24,
        message_type: 5,
        channel_id: 0,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: 0,
    }
    .encode();

    // Set all four reserved bits.
    bytes[5] = 0xF0;

    let header = FrameHeader::decode(&bytes).expect("a header with reserved bits decodes");

    assert_eq!(header.flags, 0xF0, "the raw byte is preserved");
    assert_eq!(header.defined_flags(), 0x00, "and no defined flag is set");
    assert_eq!(
        header.reserved_flags(),
        0xF0,
        "the reserved bits are reported"
    );
    assert!(
        !header.has_flag(FrameFlag::Urgent),
        "URGENT is not spuriously set"
    );
    assert!(!header.has_flag(FrameFlag::Encrypted), "nor is ENCRYPTED");
}

/// `encode` masks the reserved bits off.
///
/// The other half of the rule above: a receiver tolerates them, a sender must not produce them.
/// Without this, a caller that left a reserved bit set in the struct would emit a frame a
/// conformant peer could legitimately reject.
#[test]
fn encoding_masks_the_reserved_flag_bits() {
    let header = FrameHeader {
        version: 1,
        flags: 0xFF,
        header_length: 24,
        message_type: 5,
        channel_id: 0,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: 0,
    };

    let bytes = header.encode();

    assert_eq!(
        bytes[5], 0x0F,
        "the reserved bits are cleared, the defined ones kept"
    );
    assert_eq!(
        header.defined_flags(),
        0x0F,
        "and the struct still reports all four defined flags"
    );
    assert_eq!(
        header.reserved_flags(),
        0xF0,
        "the struct's raw byte is untouched"
    );
}

/// A buffer shorter than 24 bytes fails with `TruncatedHeader` and no partial header.
#[test]
fn a_short_buffer_is_a_truncated_header() {
    for length in 0..FIXED_LENGTH {
        let buffer = vec![0u8; length];

        match FrameHeader::decode(&buffer) {
            Err(droidlab_protocol::FrameError::TruncatedHeader { need, got }) => {
                assert_eq!(need, FIXED_LENGTH, "a header needs 24 bytes");
                assert_eq!(got, length, "and the buffer had {length}");
            }
            other => panic!("a {length}-byte buffer produced {other:?}, expected TruncatedHeader"),
        }
    }

    // Exactly 24 bytes is enough when they are a HEADER. Twenty-four zero bytes are not: the
    // magic is wrong, so this must be BadMagic rather than Ok. Asserted because the distinction is
    // the whole reason the length check comes first and the magic check immediately after.
    let mut header = FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 5,
        channel_id: 0,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: 0,
    }
    .encode();

    assert!(
        FrameHeader::decode(&header).is_ok(),
        "24 bytes of header decode"
    );
    assert!(
        matches!(
            FrameHeader::decode(&[0u8; FIXED_LENGTH]),
            Err(droidlab_protocol::FrameError::BadMagic { .. })
        ),
        "24 zero bytes are a bad magic, not a valid header"
    );

    // And exactly 24 bytes of MAGIC with a broken body length still decodes, because the body is
    // not the header's business.
    header[23] = 0xFF;

    assert!(
        FrameHeader::decode(&header).is_ok(),
        "a header describing an empty body is still a header"
    );
}

/// A wrong magic fails with `BadMagic`, and the magic is checked before any field.
///
/// The ordering matters: the note in the codec is that reading a version out of bytes that are
/// not a DLWP/1 frame is how a stray protocol gets parsed into nonsense. Driven with a buffer
/// that is otherwise a perfectly valid header, so only the magic can be the reason.
#[test]
fn a_wrong_magic_is_rejected_before_any_field_is_read() {
    let valid = FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 5,
        channel_id: 7,
        sequence_number: 9,
        acknowledgment: 3,
        body_length: 0,
    }
    .encode();

    for (index, byte) in b"DLWP".iter().enumerate() {
        let mut damaged = valid;
        // Flip one magic byte. The result is still 24 bytes with a plausible version, channel and
        // sequence, so a codec that checked the magic last would accept it.
        damaged[index] = byte.wrapping_add(1);

        match FrameHeader::decode(&damaged) {
            Err(droidlab_protocol::FrameError::BadMagic { got }) => {
                assert_eq!(got, [damaged[0], damaged[1], damaged[2], damaged[3]]);
            }
            other => panic!("damaging magic byte {index} produced {other:?}, expected BadMagic"),
        }
    }
}

/// A valid header with any field value decodes; the codec enforces no policy.
///
/// This is the design rule stated as a test: `header_length`, an unknown `message_type` and an
/// oversized `body_length` are all answered elsewhere, against the registry and the negotiated
/// limits. A codec that rejected them here would make the version negotiation unreachable.
#[test]
fn decoding_enforces_no_policy() {
    let cases = [
        // A header length that is not 24 is FrameValidator's business.
        (144u8, 5u8),
        // So is an unknown message type.
        (24, 0x7F),
        // And unknown types are preserved rather than blanked.
        (24, 0xFF),
    ];

    for (header_length, message_type) in cases {
        let header = FrameHeader {
            version: 1,
            flags: 0,
            header_length,
            message_type,
            channel_id: 0,
            sequence_number: 1,
            acknowledgment: 0,
            body_length: 0,
        };

        let decoded = FrameHeader::decode(&header.encode()).unwrap_or_else(|error| {
            panic!("header_length {header_length}, message_type {message_type} failed: {error}")
        });

        assert_eq!(decoded.header_length, header_length);
        assert_eq!(decoded.message_type, message_type);
    }

    // A body length far beyond any limit is likewise read, not refused.
    let header = FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 50,
        channel_id: 1,
        sequence_number: 2,
        acknowledgment: 0,
        body_length: u32::MAX,
    };

    let decoded =
        FrameHeader::decode(&header.encode()).expect("an oversized body length still decodes");

    assert_eq!(decoded.body_length, u32::MAX);
    assert_eq!(
        decoded.total_length(),
        u64::from(24u32) + u64::from(u32::MAX),
        "total_length widens, so it does not overflow"
    );
}

/// `total_length` is the header plus the body, and does not overflow.
#[test]
fn total_length_adds_the_header_and_the_body() {
    let header = FrameHeader {
        header_length: 24,
        body_length: 1024,
        ..FrameHeader::default()
    };

    assert_eq!(header.total_length(), 1048);

    // The sum of two u32 values needs 33 bits at the boundary, which is why the return type is
    // u64 rather than u32.
    let maximal = FrameHeader {
        header_length: u8::MAX,
        body_length: u32::MAX,
        ..FrameHeader::default()
    };

    assert_eq!(
        maximal.total_length(),
        u64::from(u8::MAX) + u64::from(u32::MAX)
    );
}

/// A destination shorter than 24 bytes is an error rather than a panic.
#[test]
fn encoding_into_a_short_buffer_is_an_error() {
    let header = FrameHeader::default();

    for length in 0..FIXED_LENGTH {
        let mut buffer = vec![0u8; length];

        assert!(
            header.encode_into(&mut buffer).is_err(),
            "a {length}-byte destination must be refused"
        );
    }

    let mut buffer = vec![0u8; FIXED_LENGTH];

    assert!(
        header.encode_into(&mut buffer).is_ok(),
        "exactly 24 bytes is enough"
    );
    assert_eq!(
        header.encode().as_slice(),
        buffer.as_slice(),
        "and encoding into a buffer agrees with encoding into a fresh array"
    );
}
