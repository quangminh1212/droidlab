//! Conformance tests for the cbOR reader and writer.
//!
//! Driven by the `encoding_rules` block of `protocol/vectors/framing-basic.json` and by the bodies
//! of its six vectors. The rules are read from the file rather than restated, so a rule added to
//! the vectors is not silently unchecked.
//!
//! The cases that matter most are the shortest-encoding boundaries. cbOR can express the number 23
//! four different ways, and DLWP/1 permits exactly one of them; a reader that accepted the others
//! would let two byte sequences decode to the same message, which is precisely what breaks the
//! uniqueness the three implementations rely on.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::{CborErrorKind, MajorType, Value, FIXED_LENGTH, MAX_DEPTH};

use serde_json::Value as Json;

/// Reads one item, expecting success.
fn read(bytes: &[u8]) -> Value {
    let mut reader = droidlab_protocol::cbor::Reader::new(bytes);

    reader
        .read_document()
        .unwrap_or_else(|error| panic!("{bytes:02x?} failed to decode: {error}"))
}

/// Reads one item, expecting a specific failure kind.
fn read_err(bytes: &[u8]) -> CborErrorKind {
    let mut reader = droidlab_protocol::cbor::Reader::new(bytes);

    match reader.read_document() {
        Ok(value) => panic!("{bytes:02x?} decoded to {value:?}, expected a failure"),
        Err(error) => error.kind,
    }
}

/// The `encoding_rules` block of the framing vectors.
fn rules() -> Json {
    // Bound to a local rather than chained, because `nested` borrows the document it was given and
    // the document must outlive the call.
    let document = vectors::load(vectors::FRAMING_BASIC);

    vectors::nested(&document, "encoding_rules").clone()
}

/// Every rule the vectors declare is one this reader either implements or deliberately does not.
///
/// Asserted so that a rule added to the vector file without a decision here fails the suite rather
/// than being quietly ignored.
#[test]
fn every_declared_encoding_rule_is_accounted_for() {
    let rules = rules();
    let object = rules.as_object().expect("encoding_rules is an object");

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();

    // The rules this module implements, and the ones it is not responsible for.
    let implemented = [
        "body_cleartext",
        "body_encrypted",
        "byte_strings",
        "empty_body",
        "integer_encoding",
        "integers",
        "map_encoding",
        "map_key_order",
        "no_floats",
        "no_tags",
        "text_strings",
    ];

    // Owned by another module: this reader turns bytes into a tree, and does not know what a
    // header or an array-with-a-specific-meaning is.
    let elsewhere = [
        "array_encoding",
        "header_length",
        "header_magic",
        "big_endian_integers",
    ];

    assert!(
        !keys.is_empty(),
        "framing-basic.json declares no encoding rules"
    );

    for key in &keys {
        assert!(
            implemented.contains(key) || elsewhere.contains(key),
            "the vectors declare a rule {key:?} this test does not account for; \
             add it to `implemented` or to `elsewhere` with a reason"
        );
    }

    // And the reverse, so a rule this module claims to check cannot be deleted from the vectors
    // while the claim remains.
    for key in implemented {
        assert!(
            keys.contains(&key),
            "this test claims to check {key:?}, which the vectors no longer declare"
        );
    }
}

/// The empty body is canonical, and a receiver accepts an empty map too.
///
/// `empty_body` in the vectors: a message with no parameters has a zero-length body, and a
/// receiver must also accept `0xA0`. Both must read as an empty map, because treating them
/// differently would make the PING vector's body not equal to the empty map it means.
#[test]
fn the_empty_body_and_the_empty_map_are_equivalent() {
    // The canonical form: zero bytes.
    assert!(
        droidlab_protocol::cbor::is_well_formed_map(&[]),
        "the empty body is well-formed"
    );
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[]).expect("the empty body parses"),
        Vec::new(),
        "the empty body parses to an empty map"
    );

    // The tolerated form: 0xA0.
    assert!(droidlab_protocol::cbor::is_well_formed_map(&[0xA0]));
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[0xA0]).expect("0xA0 parses"),
        Vec::new()
    );

    // And they are the same value, which is the point.
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[]).expect("parses"),
        droidlab_protocol::cbor::parse_map(&[0xA0]).expect("parses"),
        "the two canonical empty forms must agree"
    );

    // Every other single byte is NOT an empty body.
    for byte in 0u8..=0xFF {
        if byte == 0xA0 {
            continue;
        }

        let buffer = [byte];
        let mut reader = droidlab_protocol::cbor::Reader::new(&buffer);

        if let Ok(value) = reader.read_document() {
            assert_ne!(
                value,
                Value::Map(Vec::new()),
                "byte {byte:#04x} decoded to an empty map, which only 0xA0 may"
            );
        }
    }
}

/// Shortest-form integers: the boundary below each encoding is refused.
///
/// The four boundaries a cbOR head has. Each is tested at the value that fits the shorter form —
/// which must be refused — and at the first value that needs the longer one, which must be
/// accepted. A reader that only checked the lower bound would accept `0x1817` for 23.
#[test]
fn integers_must_use_the_shortest_form() {
    // Inline form holds 0..=23. Value 23 inline is correct.
    assert_eq!(read(&[0x17]), Value::Unsigned(23));

    // 23 in one byte is not: 0x1817 must be refused.
    assert_eq!(read_err(&[0x18, 0x17]), CborErrorKind::NonShortestInteger);

    // 24 is the first value that needs one byte, and it is accepted.
    assert_eq!(read(&[0x18, 0x18]), Value::Unsigned(24));

    // 255 fits one byte; two bytes must be refused.
    assert_eq!(read(&[0x18, 0xFF]), Value::Unsigned(255));
    assert_eq!(
        read_err(&[0x19, 0x00, 0xFF]),
        CborErrorKind::NonShortestInteger
    );

    // 256 is the first value that needs two bytes, and it is accepted.
    assert_eq!(read(&[0x19, 0x01, 0x00]), Value::Unsigned(256));

    // 65535 fits two; four must be refused.
    assert_eq!(read(&[0x19, 0xFF, 0xFF]), Value::Unsigned(65535));
    assert_eq!(
        read_err(&[0x1A, 0x00, 0x00, 0xFF, 0xFF]),
        CborErrorKind::NonShortestInteger
    );

    // 65536 needs four, and is accepted.
    assert_eq!(
        read(&[0x1A, 0x00, 0x01, 0x00, 0x00]),
        Value::Unsigned(65536)
    );

    // 2^32 - 1 fits four; eight must be refused.
    assert_eq!(
        read(&[0x1A, 0xFF, 0xFF, 0xFF, 0xFF]),
        Value::Unsigned(4_294_967_295)
    );
    assert_eq!(
        read_err(&[0x1B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]),
        CborErrorKind::NonShortestInteger
    );

    // 2^32 needs eight, and is accepted.
    assert_eq!(
        read(&[0x1B, 0, 0, 0, 1, 0, 0, 0, 0]),
        Value::Unsigned(4_294_967_296)
    );

    // And the writer produces exactly the shortest form, so a round trip is byte-exact.
    for value in [
        0u64,
        23,
        24,
        255,
        256,
        65535,
        65536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX,
    ] {
        let encoded = Value::Unsigned(value).encode().expect("encodes");

        assert_eq!(
            read(&encoded),
            Value::Unsigned(value),
            "{value} did not round-trip; encoded as {encoded:02x?}"
        );

        // The writer produces the shortest form, so its own output must decode back to the same
        // number. Asserted by checking the decode result rather than by calling a helper that
        // expects a failure: the first version called `read_err` on its own valid input, which
        // panics by design. That is the sort of test bug that reads as a codec bug.
        let mut reader = droidlab_protocol::cbor::Reader::new(&encoded);

        assert_eq!(
            reader.read_document(),
            Ok(Value::Unsigned(value)),
            "the writer emitted {encoded:02x?} for {value}, which does not decode back to it"
        );
    }
}

/// Indefinite-length items are refused, for every major type that could carry one.
///
/// `map_encoding` and the reader's rule: DLWP/1 permits definite lengths only. The additional-
/// information value 31 is the indefinite marker, and it is refused regardless of major type.
#[test]
fn indefinite_length_items_are_refused() {
    for major_bits in 0u8..=7 {
        let initial = (major_bits << 5) | 0x1F;

        assert_eq!(
            read_err(&[initial]),
            CborErrorKind::IndefiniteLength,
            "major type {major_bits} with the indefinite marker was not refused"
        );
    }

    // And the break byte 0xFF is a simple value, not a terminator DLWP/1 accepts.
    assert_eq!(read_err(&[0x9F, 0xFF]), CborErrorKind::IndefiniteLength);
}

/// Tags are refused, and tag 2 and tag 3 in particular.
///
/// `no_tags` in the vectors names tags 2 and 3 explicitly: they are the bignum tags, so a peer
/// could otherwise present a value larger than 64 bits and have it silently truncated.
#[test]
fn tags_are_refused() {
    // Tag 0, tag 1, the bignums 2 and 3, and a large tag.
    for tag in [0u8, 1, 2, 3, 23, 24, 0x40] {
        let mut bytes = vec![0xC0 | (tag & 0x1F), 0x01];

        // Keep the tag's own argument encoding shortest.
        if tag >= 24 {
            bytes = vec![0xD8, tag, 0x01];
        }

        assert_eq!(
            read_err(&bytes),
            CborErrorKind::TagNotAllowed,
            "tag {tag} was not refused"
        );
    }

    // Tag 2 wrapping a byte string, which is what a bignum looks like on the wire.
    assert_eq!(
        read_err(&[0xC2, 0x42, 0x01, 0x00]),
        CborErrorKind::TagNotAllowed
    );

    // And the writer never produces a tag, because no `Value` can represent one.
    let value = Value::Unsigned(1);
    let encoded = value.encode().expect("encodes");

    assert_eq!(encoded, vec![0x01]);
}

/// Floats and simple values are refused.
///
/// `no_floats`: the protocol defines no floating-point field. Half, single and double precision
/// all carry the major type 7, as do the simple values.
#[test]
fn floats_and_simple_values_are_refused() {
    // Half, single and double precision, for the value 1.0.
    assert_eq!(
        read_err(&[0xF9, 0x3C, 0x00]),
        CborErrorKind::FloatNotAllowed
    );
    assert_eq!(
        read_err(&[0xFA, 0x3F, 0x80, 0x00, 0x00]),
        CborErrorKind::FloatNotAllowed
    );
    assert_eq!(
        read_err(&[0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0]),
        CborErrorKind::FloatNotAllowed
    );

    // `false`, `true`, `null` and `undefined` are simple values 20..=23, likewise refused.
    for simple in [0xF4u8, 0xF5, 0xF6, 0xF7] {
        assert_eq!(
            read_err(&[simple]),
            CborErrorKind::FloatNotAllowed,
            "simple value {simple:#04x} was not refused"
        );
    }

    // A one-byte simple value is also refused.
    assert_eq!(read_err(&[0xF8, 0x20]), CborErrorKind::FloatNotAllowed);

    // And the reserved additional-information values 28..=30 are refused as unsupported, for every
    // major type -- they are not a major type's property.
    for additional in [28u8, 29, 30] {
        for major_bits in 0u8..=7 {
            let initial = (major_bits << 5) | additional;

            assert_eq!(
                read_err(&[initial]),
                CborErrorKind::UnsupportedSimpleValue,
                "major type {major_bits} with additional {additional} was not refused"
            );
        }
    }
}

/// Text strings must be valid UTF-8.
///
/// A lone continuation byte and a truncated sequence are both invalid, and both would otherwise
/// become a `String` this crate cannot hold.
#[test]
fn text_strings_must_be_valid_utf8() {
    // A valid two-byte sequence.
    assert_eq!(read(&[0x62, 0xC3, 0xA9]), Value::Text("é".to_owned()));

    // A lone continuation byte.
    assert_eq!(
        read_err(&[0x61, 0x80]),
        CborErrorKind::InvalidUtf8,
        "a lone continuation byte is not UTF-8"
    );

    // A truncated three-byte sequence.
    assert_eq!(read_err(&[0x62, 0xE2, 0x82]), CborErrorKind::InvalidUtf8);

    // An overlong encoding of '/'.
    assert_eq!(read_err(&[0x62, 0xC0, 0xAF]), CborErrorKind::InvalidUtf8);

    // A UTF-16 surrogate, which UTF-8 forbids.
    assert_eq!(
        read_err(&[0x63, 0xED, 0xA0, 0x80]),
        CborErrorKind::InvalidUtf8
    );

    // And the empty text string is valid.
    assert_eq!(read(&[0x60]), Value::Text(String::new()));

    // Multi-byte text round-trips, so the writer's length is in BYTES and not characters.
    for text in ["", "a", "é", "日本", "🎉"] {
        let encoded = Value::Text(text.to_owned()).encode().expect("encodes");

        assert_eq!(
            read(&encoded),
            Value::Text(text.to_owned()),
            "{text:?} did not round-trip; encoded as {encoded:02x?}"
        );

        // The declared length is the byte length, which is what cbOR counts.
        assert_eq!(
            encoded.len(),
            1 + text.len(),
            "{text:?} encoded to {encoded:02x?}; the length prefix must be the byte length"
        );
    }
}

/// Strings and collections that declare more content than is present are refused.
///
/// Both are checked *before* allocating, so a hostile length cannot turn into a multi-gigabyte
/// allocation. A map declaring `2^64` pairs is the obvious attack.
#[test]
fn declared_lengths_cannot_exceed_the_input() {
    // A text string declaring 100 bytes with none present.
    assert_eq!(read_err(&[0x78, 0x64]), CborErrorKind::LengthMismatch);

    // A byte string declaring 255 bytes with one present.
    assert_eq!(read_err(&[0x58, 0xFF, 0x00]), CborErrorKind::LengthMismatch);

    // An array declaring 100 elements with none present.
    assert_eq!(read_err(&[0x98, 0x64]), CborErrorKind::LengthMismatch);

    // A map declaring 100 pairs with none present.
    assert_eq!(read_err(&[0xB8, 0x64]), CborErrorKind::LengthMismatch);

    // A map declaring 2^64 pairs, which must be refused without allocating.
    assert_eq!(
        read_err(&[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CborErrorKind::LengthMismatch
    );

    // An array declaring 2^64 elements, likewise.
    assert_eq!(
        read_err(&[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        CborErrorKind::LengthMismatch
    );

    // A text string declaring 2^32 bytes.
    assert_eq!(
        read_err(&[0x7A, 0xFF, 0xFF, 0xFF, 0xFF]),
        CborErrorKind::LengthMismatch
    );

    // A string that declares one byte more than remains is still refused, not truncated to fit.
    assert_eq!(read_err(&[0x63, 0x61, 0x62]), CborErrorKind::LengthMismatch);
}

/// Truncated input is reported as truncated, at the right offset.
#[test]
fn truncated_input_is_reported() {
    // An empty buffer.
    assert_eq!(read_err(&[]), CborErrorKind::Truncated);

    // A one-byte integer is complete.
    assert_eq!(read(&[0x01]), Value::Unsigned(1));

    // A two-byte integer with only one of its argument bytes present. The reader reports
    // `LengthMismatch`, not `Truncated`: `take` is the one place an over-declared length is
    // noticed, and it cannot distinguish a short head argument from a string that claims more
    // content than remains. Both map to ERR_MALFORMED and both are fatal, so no peer can
    // observe the difference -- only the diagnostic is coarser than the C# codec's. Recorded
    // rather than fixed, because narrowing it would split `take` in two for a message no peer
    // reads.
    assert_eq!(read_err(&[0x19, 0x01]), CborErrorKind::LengthMismatch);

    // The same holds for a four-byte head with three argument bytes present, and for an
    // eight-byte head with seven: both are an over-declared length, so both are LengthMismatch
    // rather than Truncated. Only a buffer that ends before an item can be measured at all is
    // reported as truncated.
    assert_eq!(
        read_err(&[0x1A, 0x00, 0x01, 0x00]),
        CborErrorKind::LengthMismatch
    );
    assert_eq!(
        read_err(&[0x1B, 0, 0, 0, 0, 0, 1, 0]),
        CborErrorKind::LengthMismatch
    );

    // And the offset points at where the reader stopped, which is what a diagnostic needs.
    let mut reader = droidlab_protocol::cbor::Reader::new(&[0x19, 0x01]);

    if let Err(error) = reader.read_document() {
        assert_eq!(
            error.offset, 0,
            "the failure is attributed to the item's start"
        );
    } else {
        panic!("a truncated two-byte integer decoded");
    }
}

/// Trailing bytes after the top-level item are refused.
///
/// This is what keeps the encoding unique. `0x01 0x02` and `0x01` would otherwise both "contain" 1,
/// and a receiver that ignored the tail could be made to disagree with the sender about a body's
/// length.
#[test]
fn trailing_bytes_are_refused() {
    assert_eq!(read(&[0x01]), Value::Unsigned(1));
    assert_eq!(read_err(&[0x01, 0x02]), CborErrorKind::TrailingBytes);

    // A valid map followed by junk.
    assert_eq!(read_err(&[0xA0, 0x00]), CborErrorKind::TrailingBytes);

    // And the empty body is the only zero-byte input that is accepted.
    assert_eq!(read_err(&[]), CborErrorKind::Truncated);
}

/// Maps preserve their key order and their duplicate keys.
///
/// Order is preserved because a receiver must accept any order while the *encoder* must produce
/// one; collapsing the distinction here would throw away the information a test needs to tell
/// "the sender used the canonical order" from "the sender used a different one".
#[test]
fn maps_preserve_order_and_duplicates() {
    // {"b": 1, "a": 2} -- not in the canonical order, and still readable.
    let out_of_order = read(&[0xA2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02]);

    let pairs = out_of_order.as_map().expect("a map");

    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].0.as_text(), Some("b"));
    assert_eq!(pairs[1].0.as_text(), Some("a"));

    // Lookup works regardless of order.
    assert_eq!(out_of_order.get("a"), Some(&Value::Unsigned(2)));
    assert_eq!(out_of_order.get("b"), Some(&Value::Unsigned(1)));
    assert_eq!(out_of_order.get("c"), None);

    // The canonical order round-trips to the same bytes it came from.
    let canonical = [0xA2, 0x61, 0x61, 0x02, 0x61, 0x62, 0x01];

    assert_eq!(
        read(&canonical).encode().expect("encodes"),
        canonical.to_vec(),
        "the writer preserves the order it was given"
    );

    // A duplicate key is preserved rather than collapsed. DLWP/1's schema check rejects it later;
    // the reader's job is to report what the bytes said.
    let duplicated = read(&[0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]);

    assert_eq!(
        duplicated.as_map().expect("a map").len(),
        2,
        "a duplicate key is not silently merged"
    );
}

/// Nesting deeper than the limit is refused rather than recursing without bound.
///
/// The limit bounds the *reader's* recursion, not a protocol field. Without it, a body of nested
/// arrays exhausts the stack, which is a denial of service that the length checks do not catch
/// because each nesting level is only one byte.
#[test]
fn nesting_is_bounded() {
    // A single array holding one integer is within the limit.
    assert_eq!(read(&[0x81, 0x01]), Value::Array(vec![Value::Unsigned(1)]));

    // MAX_DEPTH nested arrays, each holding one item, is the last accepted depth.
    let mut within = vec![0x81u8; MAX_DEPTH];
    within.push(0x01);

    assert!(
        {
            let mut reader = droidlab_protocol::cbor::Reader::new(&within);
            reader.read_document().is_ok()
        },
        "{MAX_DEPTH} levels of nesting must be accepted"
    );

    // One level deeper is refused, and refused as a schema violation rather than by overflowing
    // the stack.
    let mut beyond = vec![0x81u8; MAX_DEPTH + 2];
    beyond.push(0x01);

    assert_eq!(read_err(&beyond), CborErrorKind::SchemaViolation);

    // A very deep input is refused rather than crashing, which is the security property.
    let hostile: Vec<u8> = core::iter::repeat(0x81u8).take(10_000).collect();

    assert_eq!(read_err(&hostile), CborErrorKind::SchemaViolation);
}

/// `parse_map` accepts a map and refuses a non-map.
///
/// A DLWP/1 body is a map or empty. An array, an integer or a text string at the top level is a
/// type error, and reporting it as `WrongValueType` rather than as a generic parse failure lets a
/// caller distinguish "the peer sent something else" from "the peer sent a broken map".
#[test]
fn a_body_must_be_a_map_or_empty() {
    // A map is fine.
    assert!(droidlab_protocol::cbor::parse_map(&[0xA1, 0x61, 0x61, 0x01]).is_ok());

    // Empty is fine, in both forms.
    assert!(droidlab_protocol::cbor::parse_map(&[]).is_ok());
    assert!(droidlab_protocol::cbor::parse_map(&[0xA0]).is_ok());

    // An integer is not a map.
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[0x01])
            .expect_err("an integer is not a map")
            .kind,
        CborErrorKind::WrongValueType
    );

    // An array is not a map.
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[0x80])
            .expect_err("an array is not a map")
            .kind,
        CborErrorKind::WrongValueType
    );

    // A text string is not a map.
    assert_eq!(
        droidlab_protocol::cbor::parse_map(&[0x60])
            .expect_err("a text string is not a map")
            .kind,
        CborErrorKind::WrongValueType
    );

    // `is_well_formed_map` agrees with `parse_map` on all of the above.
    assert!(droidlab_protocol::cbor::is_well_formed_map(&[
        0xA1, 0x61, 0x61, 0x01
    ]));
    assert!(!droidlab_protocol::cbor::is_well_formed_map(&[0x01]));
    assert!(!droidlab_protocol::cbor::is_well_formed_map(&[0x80]));
    assert!(!droidlab_protocol::cbor::is_well_formed_map(&[0x00, 0x00]));
}

/// Every cbOR defect maps to `ERR_MALFORMED`, which is fatal.
///
/// The mapping is a protocol requirement, not a convenience: RFC-0001 §6.2 registers `ERR_MALFORMED`
/// as fatal, so a body that cannot be read closes the session. Checked for every kind, so a new
/// kind cannot be added with a different code by accident.
#[test]
fn every_cbor_defect_is_err_malformed() {
    let kinds = [
        CborErrorKind::Truncated,
        CborErrorKind::IndefiniteLength,
        CborErrorKind::NonShortestInteger,
        CborErrorKind::TagNotAllowed,
        CborErrorKind::FloatNotAllowed,
        CborErrorKind::InvalidUtf8,
        CborErrorKind::LengthMismatch,
        CborErrorKind::UnsupportedSimpleValue,
        CborErrorKind::SchemaViolation,
        CborErrorKind::MissingRequiredKey,
        CborErrorKind::WrongValueType,
        CborErrorKind::WrongWidth,
        CborErrorKind::TrailingBytes,
    ];

    for kind in kinds {
        let error = droidlab_protocol::CborError::new(kind, "test", 0);

        assert_eq!(
            error.code(),
            droidlab_protocol::ErrorCode::Malformed,
            "{kind:?} must map to ERR_MALFORMED"
        );
        assert!(
            error.code().is_fatal(),
            "{kind:?} must be fatal, as RFC-0001 section 6.2 registers it"
        );
    }
}

/// The major type of an initial byte is read correctly, and the writer agrees with the reader.
///
/// Every one of the 256 initial bytes is classified, and the classification is checked against what
/// the reader does with it. A major type read from the wrong bits would make `0x80` (an empty
/// array) look like something else.
#[test]
fn every_initial_byte_is_classified_consistently() {
    for initial in 0u8..=0xFF {
        let expected = match initial >> 5 {
            0 => MajorType::UnsignedInteger,
            1 => MajorType::NegativeInteger,
            2 => MajorType::ByteString,
            3 => MajorType::TextString,
            4 => MajorType::Array,
            5 => MajorType::Map,
            6 => MajorType::Tag,
            _ => MajorType::SimpleOrFloat,
        };

        // Bound to a local: `Reader` borrows the buffer, and `&[initial]` would be a temporary
        // that dies at the end of the statement.
        let buffer = [initial];
        let mut reader = droidlab_protocol::cbor::Reader::new(&buffer);

        assert_eq!(
            reader.peek_major_type(),
            Some(expected),
            "initial byte {initial:#04x} was classified wrongly"
        );

        // And an unknown message type is not confused with a decode failure: the reader either
        // succeeds or reports why, and never panics.
        let _ = reader.read_document();
    }
}

/// The vectors declare a body length that matches the bytes they carry.
///
/// This is deliberately **only** a length and self-consistency check. It does NOT assert that
/// `body_hex` parses as cbOR, because four of the six do not: their bytes are a truncated tail
/// of the body their own `decoded.body` describes, with one length prefix off by one.
///
/// That is a defect in `framing-basic.json`, verified by decoding every body and documented in
/// `docs/findings/framing-body-not-cbor.md`. It is asserted here rather than silently skipped so
/// that the day the vectors are corrected, this test fails and the cbOR assertions can be turned
/// back on. A test that quietly downgrades itself to match a broken fixture is how the defect
/// survived two implementations in the first place.
#[test]
fn every_vector_declares_a_body_length_that_matches_its_bytes() {
    let mut checked = 0;
    let mut with_body = 0;
    let mut flagged_but_plaintext = 0;

    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let header = vectors::nested(vectors::nested(vector, "decoded"), "header");
        let declared = vectors::u32_field(header, "body_length");
        let body = vectors::hex(vectors::str_field(vector, "body_hex"));
        let frame = vectors::hex(vectors::str_field(vector, "frame"));

        assert_eq!(
            u64::from(declared),
            body.len() as u64,
            "vector {:?}: body_length is {declared} but body_hex is {} bytes",
            vectors::id(vector),
            body.len()
        );

        // `body_hex` must be the frame's bytes from the header's end. This is the invariant that
        // holds, and it is why the defect is invisible: the body is consistent with the frame
        // even though it is not a valid body.
        assert_eq!(
            frame.get(FIXED_LENGTH..),
            Some(body.as_slice()),
            "vector {:?}: body_hex is not the frame's bytes after the header",
            vectors::id(vector)
        );

        // An encrypted body is nonce||ciphertext||tag, so well-formedness is uncheckable on it.
        // Counted so this test cannot pass vacuously if every vector later becomes encrypted.
        let encrypted = vectors::u8_field(header, "flags") & 0x01 == 0x01;

        if !body.is_empty() {
            with_body += 1;

            // Three of the four body-carrying vectors SET the ENCRYPTED flag while carrying
            // plaintext cbOR -- `framing.input-touch.normalised`'s body begins `74757265`, the
            // ASCII text `ture`, not a 12-byte nonce. So the flag and the body disagree as well.
            // Counted rather than asserted per vector, so the test states the shape of the
            // defect without hard-coding which vector has it.
            if encrypted {
                flagged_but_plaintext += 1;
            }
        }

        checked += 1;
    }

    assert_eq!(checked, 6, "all six framing vectors were checked");
    assert_eq!(with_body, 4, "four vectors carry a non-empty body");
    assert_eq!(
        flagged_but_plaintext, 3,
        "three of those four set ENCRYPTED while carrying a plaintext body"
    );
}

/// The four non-empty cleartext bodies are known NOT to parse as cbOR, and this pins that.
///
/// A test asserting a defect is unusual, and it is here on purpose. Without it the finding is a
/// paragraph in a document a future contributor will not read, and the obvious "fix" is to make
/// the reader permissive enough to accept these bytes -- which would be a real regression,
/// because a permissive reader breaks the uniqueness the whole vector approach depends on.
///
/// When the vectors are corrected this test fails, which is the signal to delete it and turn the
/// body assertions back on.
#[test]
fn the_cleartext_bodies_are_known_to_be_malformed() {
    let mut non_empty = 0;

    for vector in &vectors::vectors(vectors::FRAMING_BASIC) {
        let body = vectors::hex(vectors::str_field(vector, "body_hex"));

        if body.is_empty() {
            // The two empty bodies are correct and DO parse, which the earlier test shows.
            assert!(
                droidlab_protocol::cbor::is_well_formed_map(&body),
                "vector {:?} has an empty body, which is canonical",
                vectors::id(vector)
            );
            continue;
        }

        assert!(
            !droidlab_protocol::cbor::is_well_formed_map(&body),
            "vector {:?} now parses as cbOR. If the vectors were corrected, delete this test and",
            vectors::id(vector)
        );
        assert!(
            !droidlab_protocol::cbor::is_well_formed_map(&body),
            "turn the body assertions back on in the sibling test. See {} for the evidence.",
            "docs/findings/framing-body-not-cbor.md"
        );

        non_empty += 1;
    }

    assert_eq!(non_empty, 4, "four vectors carry a non-empty body");
}
