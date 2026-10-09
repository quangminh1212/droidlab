//! Conformance tests for the frame-level error model.
//!
//! The vectors for this are the `malformed` file's first two entries: a bad magic and a truncated
//! header. They are checked here, at the layer that owns the decision, rather than in the
//! classifier tests, so that a failure names the codec rather than the classifier.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::{FrameError, FrameHeader, FIXED_LENGTH, MAGIC};

/// A buffer shorter than a header reports the exact number of bytes it needed and had.
///
/// Both numbers are asserted, because an error that says "too short" without saying how short is
/// an error a caller cannot act on, and the C# codec's message carries them for the same reason.
#[test]
fn a_truncated_header_reports_both_lengths() {
    let short = vec![0x44u8, 0x4C, 0x57];

    match FrameHeader::decode(&short) {
        Err(FrameError::TruncatedHeader { need, got }) => {
            assert_eq!(need, FIXED_LENGTH);
            assert_eq!(got, 3);
        }
        other => panic!("three magic bytes produced {other:?}, expected TruncatedHeader"),
    }

    // A buffer that is one byte short is still short, which a `>` written where a `>=` belongs
    // would get wrong.
    let nearly = vec![0u8; FIXED_LENGTH - 1];

    assert!(matches!(
        FrameHeader::decode(&nearly),
        Err(FrameError::TruncatedHeader {
            need: FIXED_LENGTH,
            got: 23
        })
    ));
}

/// An empty buffer is a truncated header rather than a panic.
#[test]
fn an_empty_buffer_is_a_truncated_header() {
    assert!(matches!(
        FrameHeader::decode(&[]),
        Err(FrameError::TruncatedHeader { need: 24, got: 0 })
    ));
}

/// A bad magic reports the four bytes it found.
///
/// The bytes are part of the error rather than only a message, so a caller can log what actually
/// arrived — which is what a field engineer needs when a controller is pointed at the wrong port.
#[test]
fn a_bad_magic_reports_the_bytes_found() {
    // An HTTP request's opening bytes: the classic case of a client pointed at the wrong service.
    let http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

    match FrameHeader::decode(http) {
        Err(FrameError::BadMagic { got }) => assert_eq!(got, *b"GET "),
        other => panic!("an HTTP request produced {other:?}, expected BadMagic"),
    }

    // A STUN packet, which is the example the C# codec's comment names. It is padded to a full 24
    // bytes on purpose: an eight-byte buffer is a TRUNCATED HEADER, because the length check comes
    // first, and this test is about the magic. Getting that wrong is what the first version of
    // this test did -- it asserted BadMagic for a buffer that could not reach the magic check.
    let mut stun = [0x00u8; FIXED_LENGTH];
    stun[0] = 0x00;
    stun[1] = 0x01;
    stun[2] = 0x00;
    stun[3] = 0x08;
    stun[4] = 0x21;
    stun[5] = 0x12;
    stun[6] = 0xA4;
    stun[7] = 0x42;

    match FrameHeader::decode(&stun) {
        Err(FrameError::BadMagic { got }) => assert_eq!(got, [0x00, 0x01, 0x00, 0x08]),
        other => panic!("a STUN packet produced {other:?}, expected BadMagic"),
    }

    // And the eight-byte prefix on its own is a truncation, which is the ordering rule stated the
    // other way round.
    assert!(matches!(
        FrameHeader::decode(&stun[..8]),
        Err(FrameError::TruncatedHeader { need: 24, got: 8 })
    ));

    // And the magic is right in `MAGIC`, so the test above is checking the codec rather than a
    // constant this file wrote down twice.
    assert_eq!(MAGIC, *b"DLWP");
}

/// A bad magic is refused even when every other field is a valid header.
///
/// This is the ordering rule. A codec that read the fields first and validated the magic last
/// would return fields for a buffer that is not a DLWP/1 frame at all, and the version it read
/// would be a byte of somebody else's protocol.
#[test]
fn the_magic_is_checked_before_any_field_is_interpreted() {
    let mut bytes = FrameHeader {
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

    // Change only the magic. Everything else remains a header a decoder would happily accept.
    bytes[0] = b'X';

    assert!(
        matches!(
            FrameHeader::decode(&bytes),
            Err(FrameError::BadMagic { .. })
        ),
        "a valid header with a wrong magic must be refused"
    );
}

/// Every variant of the error model renders a message that names its own numbers.
///
/// The `Display` implementation is checked rather than assumed, because it is what ends up in a
/// log and an error that renders as an empty string is worse than no error.
#[test]
fn every_error_renders_its_own_numbers() {
    let cases = [
        FrameError::TruncatedHeader { need: 24, got: 3 },
        FrameError::BadMagic { got: *b"GET " },
        FrameError::UnsupportedHeaderLength { got: 16 },
        FrameError::VersionMismatch {
            offered: 2,
            supported: 1,
        },
        FrameError::FrameTooLarge {
            declared: 99,
            limit: 24,
        },
        FrameError::UnknownMessageType { message_type: 0x7F },
        FrameError::Malformed { reason: "test" },
        FrameError::EncryptionMismatch {
            message_type: 5,
            encrypted: true,
        },
    ];

    for error in cases {
        let rendered = error.to_string();

        assert!(!rendered.is_empty(), "{error:?} renders as an empty string");
        assert!(
            rendered.len() > 10,
            "{error:?} renders as {rendered:?}, which says too little to act on"
        );
    }

    // Spot-check the ones whose numbers matter most.
    assert!(FrameError::TruncatedHeader { need: 24, got: 3 }
        .to_string()
        .contains("24"));
    assert!(FrameError::BadMagic { got: *b"GET " }
        .to_string()
        .contains("0x47"));
    assert!(FrameError::VersionMismatch {
        offered: 9,
        supported: 1
    }
    .to_string()
    .contains('9'));
}
