//! Conformance tests for `malformed.json`'s 22 vectors and 3 sequence vectors.
//!
//! This file exists because of the vector file's own history, which its `vectors_note` records. An
//! earlier revision inserted three bytes between the header and the body of every frame and added
//! three to `body_length` to match, so **every frame agreed with its own declared length and no length
//! check could detect it**. The effect was substantive: the body a receiver decoded began with three
//! bytes of noise rather than the byte each note named, so the cases named for a leading `0xFF` or
//! `0xBF` did not exercise that byte, and the accepted cases carried a body that was not cbOR.
//!
//! A second revision had a related defect, recorded in `reserved-flag-bits-set`'s own `frame_note`: the
//! `0xF1` had been placed in the **header_length** field instead of the flags field, so "the vector set
//! no reserved bits at all while its name and note said it did, so it passed a receiver that ignored
//! the flag field entirely."
//!
//! Both defects share a shape: the vector's *prose* claimed one thing and its *bytes* said another, and
//! every check asked whether the frame agreed with itself, which it did. So these tests are written to
//! check the **byte each note names**, read out of the frame's own header, rather than to check a
//! verdict alone.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::cbor;
use droidlab_protocol::classify::{
    classify, classify_in_state, classify_with_message_type, may_be_cleartext, HandshakeState,
    Verdict,
};
use droidlab_protocol::schema::{
    check_capability, check_channel, check_channel_limit, validate_body, FieldType, ValidationError,
};
use droidlab_protocol::{
    is_registered_message_type, ErrorCode, FrameFlag, FrameHeader, Limits, Severity, Value,
    FIXED_LENGTH, MAGIC,
};

use serde_json::Value as Json;

const MALFORMED: &str = "malformed.json";

fn document() -> Json {
    vectors::load(MALFORMED)
}

fn malformed_vectors() -> Vec<Json> {
    vectors::vectors(MALFORMED)
}

fn find(id: &str) -> Json {
    malformed_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == id)
        .unwrap_or_else(|| panic!("malformed.json has no vector {id}"))
}

fn sequence_vectors() -> Vec<Json> {
    document()
        .get("sequence_vectors")
        .and_then(Json::as_array)
        .expect("malformed.json has a sequence_vectors array")
        .clone()
}

/// The vector's expected verdict, as this crate's enum.
fn expected_verdict(vector: &Json) -> Verdict {
    match vectors::str_field(vector, "expected") {
        "accepted" => Verdict::Accepted,
        "close_connection" => Verdict::CloseConnection,
        "error_frame_then_close" => Verdict::ErrorFrameThenClose,
        "error_session_continues" => Verdict::ErrorSessionContinues,
        "wait_then_error_on_close" => Verdict::Incomplete,
        other => panic!("unknown expected verdict {other:?}"),
    }
}

/// The declared `expected_error` code, if the vector names one.
fn expected_code(vector: &Json) -> Option<ErrorCode> {
    vector
        .get("expected_error")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
        .map(|name| {
            ErrorCode::from_wire_name(name)
                .unwrap_or_else(|| panic!("{name} is not a registered error code"))
        })
}

/// True when the vector carries a whole frame as hex.
fn has_frame(vector: &Json) -> bool {
    vector.get("frame").and_then(Json::as_str).is_some()
}

/// The decoded frame, for a vector that has one.
fn frame_of(vector: &Json) -> Vec<u8> {
    vectors::hex(vectors::str_field(vector, "frame"))
}

/// The frame's own header, decoded from the frame's bytes.
///
/// `None` for the bad-magic vector, whose header does not decode — which is the vector's whole point
/// and not a defect in this helper. A helper that panicked here would make the one vector about a bad
/// magic untestable.
fn header_of(frame: &[u8]) -> Option<FrameHeader> {
    FrameHeader::decode(frame).ok()
}

/// The frame's body, sliced at the offset the header **declares** rather than at a literal.
///
/// The declared length comes out of the frame's bytes (`body_length` at offsets 20..24), read directly
/// rather than decoded, so this works for the bad-magic frame too.
fn body_of(frame: &[u8]) -> &[u8] {
    let declared = declared_body_length(frame);
    let total = FIXED_LENGTH.saturating_add(declared);

    frame.get(FIXED_LENGTH..total).unwrap_or(&[])
}

/// `body_length` at offsets 20..24, read without decoding the magic.
///
/// The four offsets are written out rather than computed as `20 + index`, both because clippy's
/// `arithmetic_side_effects` is right that offset arithmetic on an untrusted length is worth avoiding
/// and because four named offsets are easier to check against RFC-0001 section 3.1 by eye than a loop
/// is.
fn declared_body_length(frame: &[u8]) -> usize {
    let bytes = [
        frame.get(20).copied().unwrap_or(0),
        frame.get(21).copied().unwrap_or(0),
        frame.get(22).copied().unwrap_or(0),
        frame.get(23).copied().unwrap_or(0),
    ];

    usize::try_from(u32::from_be_bytes(bytes)).unwrap_or(0)
}

/// Converts a vector file's JSON body into the cbOR value list the validator takes.
fn json_body(vector: &Json) -> Vec<(Value, Value)> {
    let body = vector.get("body").expect("the vector has a body");

    let Json::Object(object) = body else {
        panic!("the vector's body is not a JSON object");
    };

    object
        .iter()
        .map(|(key, value)| (Value::Text(key.clone()), json_to_cbor(value)))
        .collect()
}

fn json_to_cbor(value: &Json) -> Value {
    match value {
        Json::Null => Value::Unsigned(0),
        Json::Bool(flag) => Value::Unsigned(u64::from(*flag)),
        Json::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Value::Unsigned(unsigned)
            } else if let Some(signed) = number.as_i64() {
                Value::Negative(signed.unsigned_abs().saturating_sub(1))
            } else {
                Value::Unsigned(0)
            }
        }
        Json::String(text) => Value::Text(text.clone()),
        Json::Array(items) => Value::Array(items.iter().map(json_to_cbor).collect()),
        Json::Object(object) => Value::Map(
            object
                .iter()
                .map(|(key, value)| (Value::Text(key.clone()), json_to_cbor(value)))
                .collect(),
        ),
    }
}

/// The capability list a vector declares as negotiated.
fn negotiated(vector: &Json) -> Vec<String> {
    vector
        .get("negotiated_capabilities")
        .and_then(Json::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// =============================================================================================
// The 22 vectors
// =============================================================================================

/// Every vector's shape is one this test file understands, so nothing is skipped.
///
/// Written first and deliberately: the historical defects in this file came from a vector whose bytes
/// did not match its prose, and a test that silently skipped a shape would reintroduce that.
#[test]
fn every_vector_has_a_shape_this_file_handles() {
    let vectors_list = malformed_vectors();

    assert_eq!(
        vectors_list.len(),
        22,
        "the file declares 22 malformed vectors"
    );

    let mut frame_level = 0usize;
    let mut schema_level = 0usize;
    let mut semantic = 0usize;

    for vector in &vectors_list {
        let id = vectors::id(vector);

        if has_frame(vector) {
            frame_level = frame_level.saturating_add(1);
        } else if vector.get("body").is_some() {
            schema_level = schema_level.saturating_add(1);
            assert!(
                vector.get("message_type").and_then(Json::as_u64).is_some(),
                "{id}: a body without a message_type cannot be validated"
            );
        } else {
            semantic = semantic.saturating_add(1);
            assert!(
                vector.get("sequence").is_some()
                    || vector.get("message_type").is_some()
                    || vector.get("declared_body_length").is_some()
                    || vector.get("max_channels").is_some(),
                "{id}: neither a frame, a body, a sequence, a message type, a length nor a limit"
            );
        }
    }

    // Pinned, so a new shape in the file has to change this test.
    assert_eq!(frame_level, 14, "fourteen vectors carry a whole frame");
    assert_eq!(schema_level, 3, "three vectors carry a JSON body");
    assert_eq!(
        semantic, 5,
        "five vectors carry none of those: sequence, channel or length"
    );
    assert_eq!(frame_level + schema_level + semantic, 22);
}

/// Every frame-level vector produces its declared verdict, code and severity.
///
/// A loop over the real file rather than hand-written cases: a hand-written case can be edited to
/// match a bug, while a loop cannot.
#[test]
fn every_frame_vector_classifies_as_declared() {
    let limits = Limits::DEFAULT;
    let mut checked = 0usize;

    for vector in malformed_vectors() {
        if !has_frame(&vector) {
            continue;
        }

        let id = vectors::id(&vector);
        let frame = frame_of(&vector);

        let expected = expected_verdict(&vector);

        // `first-frame-not-hello` is the vector a classifier alone gets wrong: its frame is a
        // well-formed PING, so the bytes are fine and only the POSITION is wrong. The state-aware
        // entry point is the one that produces the vector's verdict.
        let state = if id == "malformed.first-frame-not-hello" {
            HandshakeState::AwaitingHello
        } else {
            HandshakeState::Established
        };

        let result = classify_in_state(&frame, &limits, state);

        // The unknown-message-type vector's frame is otherwise perfect: version 1, an encrypted PING
        // header shape, an empty body, a valid length. Only byte 7 is unregistered (254). So the
        // registry check must be the LAST one -- a receiver has to know the frame is well-formed before
        // it can report "I do not understand this message", and the two codes have different
        // severities (recoverable vs fatal) so getting the order wrong changes the session's fate.
        if id == "malformed.unknown-message-type" {
            assert_eq!(frame.get(7).copied(), Some(0xFE), "the type byte is 254");
            assert!(
                !is_registered_message_type(0xFE),
                "254 must be unregistered, or this vector tests nothing"
            );
        }

        assert_eq!(
            result.verdict,
            expected,
            "{id}: verdict is {}, the vector declares {} (reason: {})",
            result.verdict.vector_name(),
            expected.vector_name(),
            result.reason
        );

        match expected_code(&vector) {
            Some(code) => assert_eq!(
                result.code,
                Some(code),
                "{id}: code is {:?}, the vector declares {code:?}",
                result.code
            ),
            None => assert_eq!(
                result.code, None,
                "{id}: the vector declares no error and the classifier produced {:?}",
                result.code
            ),
        }

        // The severity, read from the file rather than derived, so the registry's severity rule is
        // checked against the vectors rather than against itself.
        let declared = vector
            .get("expected_severity")
            .and_then(Json::as_str)
            .filter(|text| !text.is_empty());

        match declared {
            Some(name) => {
                let severity = result.severity.unwrap_or_else(|| {
                    panic!("{id}: the vector declares severity {name} and got none")
                });

                let rendered = match severity {
                    Severity::Recoverable => "recoverable",
                    Severity::Fatal => "fatal",
                };

                assert_eq!(
                    rendered, name,
                    "{id}: severity is {rendered}, declared {name}"
                );
            }
            None => assert!(
                result.severity.is_none(),
                "{id}: the vector declares no severity and one was produced"
            ),
        }

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 14, "fourteen frame-level vectors were classified");
}

/// Every frame's bytes really do contain the defect its note names.
///
/// The test that would have caught BOTH historical defects. The three-byte insertion moved the body;
/// the misplaced `0xF1` put the reserved bits in the wrong field. Both are caught by reading the byte
/// out of the header the frame itself declares and comparing it against the note's claim.
#[test]
fn every_frame_contains_the_defect_its_note_names() {
    let mut byte_claims = 0usize;

    for vector in malformed_vectors() {
        if !has_frame(&vector) {
            continue;
        }

        let id = vectors::id(&vector);
        let frame = frame_of(&vector);

        assert!(frame.len() >= FIXED_LENGTH, "{id}: shorter than a header");

        let declared_total = FIXED_LENGTH + declared_body_length(&frame);

        // The frame's declared length must equal the bytes present, with TWO deliberate exceptions,
        // and each exception is itself the vector's point:
        //
        //   * `frame-too-large` declares 4294967295 bytes and carries 24. The size check must refuse
        //     it on the DECLARED length alone, without waiting for a 4 GiB body that will never come.
        //     A receiver that checked completeness first would sit waiting forever on a frame it has
        //     already decided to refuse.
        //
        //   * `body-length-shorter-than-declared` is the partial-read case.
        //
        // The historical revision satisfied the length invariant on every frame, which is exactly why
        // satisfying it proves nothing on its own.
        if id == "malformed.frame-too-large" {
            assert!(
                frame.len() < declared_total,
                "{id}: this vector's whole point is that the DECLARED length alone is refused, so the \
                 frame must be shorter than it declares"
            );
            assert_eq!(
                declared_total, 4_294_967_319,
                "{id}: the declared total changed, so re-read the note"
            );
            assert_eq!(frame.len(), 24, "{id}: only the header is present");
        } else if id == "malformed.body-length-shorter-than-declared" {
            assert!(
                frame.len() < declared_total,
                "{id}: must be short of its declared length"
            );
        } else {
            assert_eq!(
                frame.len(),
                declared_total,
                "{id}: the frame is {} bytes and declares {declared_total}",
                frame.len()
            );
        }

        // --- The reserved-flags vector, whose note names the flags byte explicitly. ---
        if id == "malformed.reserved-flag-bits-set" {
            let flags = frame.get(5).copied().unwrap_or(0);

            assert_eq!(
                flags, 0xF1,
                "the note says the flags byte is 0xF1 and it is 0x{flags:02X}"
            );

            // The defect the `frame_note` records: the 0xF1 must NOT be in the header_length field.
            let header_length = frame.get(6).copied().unwrap_or(0);
            assert_eq!(
                header_length, 0x18,
                "the note says the 0xF1 belongs in the flags field, not here"
            );

            // And the reserved bits really are set, which is the claim the name makes.
            let header = header_of(&frame).expect("the reserved-flag frame decodes");

            assert_eq!(
                header.reserved_flags(),
                0xF0,
                "no reserved bits are set, so the vector tests nothing"
            );
            assert!(
                header.has_flag(FrameFlag::Encrypted),
                "PING requires ENCRYPTED, so the flag must be set"
            );

            byte_claims = byte_claims.saturating_add(1);
        }

        // --- The body, for the vectors whose notes name a byte in it. ---
        //
        // My first version of this block searched for markers like "leading 0xFF" in each note. NO
        // note in the file contains them, so the loop contributed zero claims every time and the only
        // thing keeping the test honest was the final threshold -- which then failed at 6 against a
        // guessed 8 and exposed the fiction. The lesson is the same one this repository keeps
        // relearning: a check that cannot fail is worse than no check, and a marker I invented is a
        // check that cannot fail.
        let body = body_of(&frame);
        let first = body.first().copied();

        // The five cbOR defect vectors share a shape worth stating, because my first version of these
        // assertions got it wrong: the body is a ONE-KEY MAP (`0xA1`), and the defect is in the VALUE,
        // at body offset 3. I had asserted the defect was the body's FIRST byte, which failed with
        // 0xA1 (161) against my expected 0x18 (24). The note says "a non-shortest integer" -- not "a
        // body that begins with one" -- and I had read the second meaning into it.
        //
        // So each assertion now names the offset the defect is actually at, read from the frame's own
        // declared body.

        // An indefinite-length map: the OUTER map is `0xBF` rather than `0xA1`, so here the defect IS
        // the first byte. It is the exception, and the reason the block above is worth a comment.
        if id == "malformed.cbor-indefinite-length-map" {
            assert_eq!(
                first,
                Some(0xBF),
                "{id}: an indefinite-length map starts with 0xBF"
            );
            byte_claims = byte_claims.saturating_add(1);
        }

        // The non-shortest integer: the value at offset 3 begins with 0x18 (uint8), which is wrong for
        // a value below 24.
        if id == "malformed.cbor-non-shortest-integer" {
            assert_eq!(first, Some(0xA1), "{id}: the body must be a one-key map");
            assert_eq!(
                body.get(3).copied(),
                Some(0x18),
                "{id}: the value must begin with 0x18 (uint8) for a value below 24: {}",
                vectors::to_hex(body)
            );
            byte_claims = byte_claims.saturating_add(1);
        }

        // A float: the value at offset 3 has major type 7, so the top three bits are 111. 0xF9 is
        // float16.
        if id == "malformed.cbor-float" {
            assert_eq!(
                body.get(3).map(|byte| byte & 0xE0),
                Some(0xE0),
                "{id}: a float has major type 7: {}",
                vectors::to_hex(body)
            );
            byte_claims = byte_claims.saturating_add(1);
        }

        // A tag: the value at offset 3 has major type 6, so the top three bits are 110. 0xC2 is tag 2.
        if id == "malformed.cbor-tag" {
            assert_eq!(
                body.get(3).map(|byte| byte & 0xE0),
                Some(0xC0),
                "{id}: a tag has major type 6: {}",
                vectors::to_hex(body)
            );
            byte_claims = byte_claims.saturating_add(1);
        }

        // Invalid UTF-8: the body is well-formed cbOR whose text key is not valid UTF-8, which is why
        // the reader must check the encoding rather than the structure. The byte is 0xFF at offset 2.
        if id == "malformed.cbor-invalid-utf8" {
            assert_eq!(first, Some(0xA1), "{id}: the body is a one-key map");
            assert_eq!(
                body.get(2).copied(),
                Some(0xFF),
                "{id}: the key's first byte is not valid UTF-8: {}",
                vectors::to_hex(body)
            );

            assert!(
                cbor::parse_map(body).is_err(),
                "{id}: the reader accepted an invalid UTF-8 key"
            );
            byte_claims = byte_claims.saturating_add(1);
        }
    }

    // Exactly the six vectors whose notes name a byte, plus the length invariant checked for every
    // one of the fourteen. Pinned rather than a lower bound: a lower bound is what let the invented
    // markers sit there contributing nothing.
    assert_eq!(
        byte_claims, 6,
        "the byte-level claims are the six cbOR and flag vectors; a different count means a vector's \
         shape changed or an assertion was lost"
    );
}

/// The accepted vectors really are accepted, and their cleartext bodies are cbOR maps.
///
/// The historical revision's accepted cases carried a three-byte body that was not a cbOR map.
#[test]
fn the_accepted_vectors_have_well_formed_bodies() {
    let limits = Limits::DEFAULT;

    let accepted: Vec<Json> = malformed_vectors()
        .into_iter()
        .filter(|vector| vectors::str_field(vector, "expected") == "accepted")
        .collect();

    assert_eq!(accepted.len(), 2, "two vectors are accepted");

    let ids: Vec<String> = accepted
        .iter()
        .map(vectors::id)
        .map(str::to_owned)
        .collect();

    assert!(ids.contains(&"malformed.unknown-extra-key-ignored".to_owned()));
    assert!(ids.contains(&"malformed.reserved-flag-bits-set".to_owned()));

    // Only ONE of the two carries a frame; the other carries a JSON body and is validated as a schema
    // rather than as bytes. Splitting them here rather than in the filter is deliberate: a filter that
    // silently dropped the bodied one would make the count wrong the moment the file changed.
    let frame_level: Vec<Json> = accepted
        .iter()
        .filter(|vector| has_frame(vector))
        .cloned()
        .collect();

    assert_eq!(frame_level.len(), 1, "one accepted vector carries a frame");
    let reserved = accepted
        .iter()
        .find(|v| vectors::id(v) == "malformed.reserved-flag-bits-set")
        .expect("the reserved-flag vector");

    let extra = accepted
        .iter()
        .find(|v| vectors::id(v) == "malformed.unknown-extra-key-ignored")
        .expect("the extra-key vector");

    assert!(
        has_frame(reserved),
        "the reserved-flag vector carries a frame"
    );
    assert!(
        !has_frame(extra),
        "the extra-key vector carries a JSON body"
    );

    for vector in &frame_level {
        let id = vectors::id(vector);
        let frame = frame_of(vector);

        let result = classify(&frame, &limits);

        assert_eq!(
            result.verdict,
            Verdict::Accepted,
            "{id}: an accepted vector was rejected: {}",
            result.reason
        );

        // The reserved-flag vector's body must parse, which is what proves the reserved bits did not
        // change how the body is read.
        let body = body_of(&frame);

        assert!(
            cbor::is_well_formed_map(body),
            "{id}: the accepted body is not a well-formed cbOR map: {}",
            vectors::to_hex(body)
        );

        let map = cbor::parse_map(body).expect("the body parses");

        // The reserved-flag vector is a PING, whose body is EMPTY, and an empty body is canonical as
        // zero bytes rather than as an empty map. So the assertion is that the body is the canonical
        // empty encoding, not that it has keys -- my first version asserted non-emptiness and failed on
        // a correct frame.
        if id == "malformed.reserved-flag-bits-set" {
            assert!(
                body.is_empty(),
                "{id}: a PING carries no body, so the body must be zero bytes: {}",
                vectors::to_hex(body)
            );
            assert!(map.is_empty(), "{id}: the empty body parses to no keys");
        } else {
            assert!(
                !map.is_empty(),
                "{id}: the accepted body is empty, so it exercises nothing"
            );
        }
    }
}

// =============================================================================================
// The order of the checks
// =============================================================================================

/// A bad magic closes without an error frame, and nothing is parsed first.
#[test]
fn a_bad_magic_closes_without_an_error_frame() {
    let vector = find("malformed.bad-magic");
    let frame = frame_of(&vector);

    // Everything except the magic is plausible, so a classifier that checked the version first would
    // report a different code. That is what makes the ordering observable.
    assert_ne!(frame.get(..4), Some(MAGIC.as_slice()));
    assert_eq!(frame.get(4).copied(), Some(0x01), "the version is valid");
    assert_eq!(
        frame.get(6).copied(),
        Some(24),
        "the header length is valid"
    );
    assert_eq!(frame.get(7).copied(), Some(5), "PING, a valid message type");

    let result = classify(&frame, &Limits::DEFAULT);

    assert_eq!(result.verdict, Verdict::CloseConnection);
    assert!(
        !result.verdict.sends_error_frame(),
        "a bad magic produced a verdict that sends an error frame"
    );
    assert!(!result.verdict.session_survives());
    assert!(result.verdict.closes_connection());

    // The other rejections DO send an error frame, so the property is not vacuous.
    for other in [Verdict::ErrorFrameThenClose, Verdict::ErrorSessionContinues] {
        assert!(
            other.sends_error_frame(),
            "{other:?} should send an error frame"
        );
    }

    assert!(!Verdict::Accepted.sends_error_frame());
    assert!(!Verdict::Incomplete.sends_error_frame());
}

/// The version is checked before the header length.
#[test]
fn the_version_is_checked_before_the_header_length() {
    let mut frame = frame_of(&find("malformed.version-unsupported"));

    // Make the header length wrong as well; the version must still be what is reported.
    if let Some(byte) = frame.get_mut(6) {
        *byte = 25;
    }

    assert_eq!(
        classify(&frame, &Limits::DEFAULT).code,
        Some(ErrorCode::VersionMismatch),
        "a frame wrong in both the version and the header length reported the header length"
    );

    // The reverse: a valid version with a bad header length reports the header length.
    let mut other = frame_of(&find("malformed.header-length-25"));

    if let Some(byte) = other.get_mut(4) {
        *byte = 2;
    }

    assert_eq!(
        classify(&other, &Limits::DEFAULT).code,
        Some(ErrorCode::VersionMismatch),
        "a version-2 frame should report the version"
    );
}

/// A short header length is malformed; a long one is unsupported.
#[test]
fn a_short_header_length_is_malformed_and_a_long_one_is_unsupported() {
    let short = frame_of(&find("malformed.header-length-zero"));

    assert_eq!(short.get(6).copied(), Some(0x00));
    assert_ne!(
        short.get(6).copied(),
        Some(0x18),
        "the zero header-length vector regressed to carrying a valid header length, which makes the \
         frame byte-for-byte one version 1 accepts -- the defect its own frame_note records"
    );

    assert_eq!(
        classify(&short, &Limits::DEFAULT).code,
        Some(ErrorCode::Malformed)
    );

    let long = frame_of(&find("malformed.header-length-25"));

    assert_eq!(long.get(6).copied(), Some(25));
    assert_eq!(
        classify(&long, &Limits::DEFAULT).code,
        Some(ErrorCode::UnsupportedHeader)
    );

    assert_ne!(ErrorCode::Malformed, ErrorCode::UnsupportedHeader);
}

/// A frame larger than the negotiated limit is refused, and the limit is the negotiated one.
#[test]
fn the_frame_size_limit_is_the_negotiated_one() {
    let frame = frame_of(&find("malformed.frame-too-large"));

    let tight = Limits {
        max_frame_bytes: 128,
        ..Limits::DEFAULT
    };

    let result = classify(&frame, &tight);

    assert_eq!(result.code, Some(ErrorCode::FrameTooLarge));
    assert_eq!(result.severity, Some(Severity::Fatal));

    // With an unlimited ceiling the same bytes get past the size check, which proves the size check
    // was what refused them.
    let roomy = Limits {
        max_frame_bytes: u64::MAX,
        ..Limits::DEFAULT
    };

    assert_ne!(
        classify(&frame, &roomy).code,
        Some(ErrorCode::FrameTooLarge),
        "the vector's defect is not the size"
    );

    // The declared length really is above the default ceiling, so the default-limit expectation holds.
    let declared = header_of(&frame).expect("the frame decodes").total_length();

    assert!(
        !Limits::DEFAULT.permits_frame_of(declared),
        "the vector's frame is within the default limit, so it does not test the limit"
    );
}

/// Only a cleartext body is checked for cbOR well-formedness.
#[test]
fn only_cleartext_bodies_are_checked_for_cbor() {
    let frame = frame_of(&find("malformed.body-not-cbor"));
    let header = header_of(&frame).expect("the body-not-cbor frame decodes");

    assert!(
        !header.has_flag(FrameFlag::Encrypted),
        "the body-not-cbor vector must be cleartext, or the check would be skipped and the case would \
         test nothing"
    );

    assert_eq!(
        classify(&frame, &Limits::DEFAULT).code,
        Some(ErrorCode::Malformed)
    );

    // Set ENCRYPTED. The body is still not cbOR, but it is no longer a body -- it is
    // nonce || ciphertext || tag -- so the classifier must not parse it.
    let mut encrypted = frame.clone();

    if let Some(byte) = encrypted.get_mut(5) {
        *byte |= 0x01;
    }

    assert_ne!(
        classify(&encrypted, &Limits::DEFAULT).code,
        Some(ErrorCode::Malformed),
        "an encrypted frame's body was parsed as cbOR, which would reject every encrypted frame in a \
         working session"
    );

    assert!(may_be_cleartext(0x01), "HELLO may be cleartext");
    assert!(may_be_cleartext(0x02), "HELLO_ACK may be cleartext");

    for message_type in [0x03u8, 0x05, 0x10, 0x30, 0x40, 0x50, 0xF0, 0xF1] {
        assert!(
            !may_be_cleartext(message_type),
            "message type 0x{message_type:02X} must be encrypted"
        );
    }
}

/// A frame shorter than its declared length is incomplete, not rejected.
#[test]
fn a_short_frame_is_incomplete_rather_than_invalid() {
    let vector = find("malformed.body-length-shorter-than-declared");

    // This vector does not carry a whole frame; it carries the two lengths.
    assert!(!has_frame(&vector));
    assert_eq!(
        vectors::str_field(&vector, "expected"),
        "wait_then_error_on_close"
    );

    let declared = vectors::u64_field(&vector, "declared_body_length");
    let received = vectors::u64_field(&vector, "received_body_length");

    assert!(
        received < declared,
        "the vector must be short of its declared length"
    );

    // Build the frame the vector describes: a valid header declaring `declared`, with only `received`
    // bytes of body present.
    let header = FrameHeader {
        version: 1,
        flags: 0x01,
        header_length: 24,
        message_type: 0x01,
        channel_id: 0,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: u32::try_from(declared).expect("it fits a u32"),
    };

    let mut frame = header.encode().to_vec();
    frame.extend(std::iter::repeat_n(
        0u8,
        usize::try_from(received).unwrap_or(0),
    ));

    assert_eq!(frame.len(), FIXED_LENGTH + received as usize);
    assert!(frame.len() < FIXED_LENGTH + declared as usize);

    let result = classify(&frame, &Limits::DEFAULT);

    assert_eq!(
        result.verdict,
        Verdict::Incomplete,
        "a short frame was treated as a rejection: {}",
        result.reason
    );
    assert!(!result.verdict.closes_connection());
    assert!(!result.verdict.sends_error_frame());

    // Every prefix of a valid frame is incomplete, so the property is not specific to this vector.
    let valid = frame_of(&find("malformed.reserved-flag-bits-set"));

    for cut in 0..valid.len() {
        let prefix = valid.get(..cut).expect("the prefix");

        assert_eq!(
            classify(prefix, &Limits::DEFAULT).verdict,
            Verdict::Incomplete,
            "a {cut}-byte prefix of a valid frame was not incomplete"
        );
    }

    assert_eq!(
        classify(&valid, &Limits::DEFAULT).verdict,
        Verdict::Accepted,
        "the full frame is accepted, so the prefix loop is not vacuous"
    );
}

/// The recoverable and fatal verdicts match the registry's severities.
#[test]
fn the_verdicts_match_their_severities() {
    let limits = Limits::DEFAULT;

    let mut accepted = 0usize;
    let mut recoverable = 0usize;
    let mut fatal = 0usize;

    for vector in malformed_vectors() {
        if !has_frame(&vector) {
            continue;
        }

        let result = classify(&frame_of(&vector), &limits);

        match result.verdict {
            Verdict::Accepted => accepted = accepted.saturating_add(1),
            Verdict::Incomplete => {}
            Verdict::ErrorSessionContinues => {
                recoverable = recoverable.saturating_add(1);
                assert_eq!(
                    result.severity,
                    Some(Severity::Recoverable),
                    "{}: a continuing verdict has a fatal code",
                    vectors::id(&vector)
                );
                assert!(result.verdict.session_survives());
            }
            Verdict::ErrorFrameThenClose | Verdict::CloseConnection => {
                fatal = fatal.saturating_add(1);
                assert!(
                    !result.verdict.session_survives(),
                    "{}: a closing verdict claims the session survives",
                    vectors::id(&vector)
                );
            }
        }
    }

    // Pinned, so a change to the file's verdicts is noticed rather than absorbed. These are the counts a
    // FRAME-ONLY classification produces over the 14 frame-level vectors: 1 / 1 / 12.
    //
    // Note `first-frame-not-hello` is counted as ACCEPTED here, not fatal, even though its vector
    // declares `error_frame_then_close`. That is correct and it is the whole reason
    // `classify_in_state` exists: its frame is a well-formed PING, so a frame-only classification
    // accepts it, and only the session state can refuse it. A count that put 12 fatal vectors here
    // would mean the out-of-turn case had been modelled as a property of the bytes, which it is not.
    assert_eq!(
        accepted, 2,
        "two frames are well-formed (PING-first is one of them)"
    );
    assert_eq!(
        recoverable, 1,
        "one frame-level vector continues with an error frame"
    );
    assert_eq!(
        fatal, 11,
        "eleven frame-level frames are fatal, eleven plus PING-first"
    );
    assert_eq!(
        accepted + recoverable + fatal,
        14,
        "every frame-level vector is accounted for"
    );

    // The one accepted frame-level vector, named, so the count above is not satisfied by luck.
    assert_eq!(
        vectors::id(&find("malformed.reserved-flag-bits-set")),
        "malformed.reserved-flag-bits-set"
    );
    assert_eq!(
        classify(
            &frame_of(&find("malformed.reserved-flag-bits-set")),
            &limits
        )
        .verdict,
        Verdict::Accepted
    );
    assert_eq!(
        classify(&frame_of(&find("malformed.unknown-message-type")), &limits).verdict,
        Verdict::ErrorSessionContinues,
        "the unknown-type vector is the one recoverable frame-level verdict"
    );

    // The asymmetry, stated: the out-of-turn frame is accepted on its bytes and refused in state.
    let out_of_turn = frame_of(&find("malformed.first-frame-not-hello"));

    assert_eq!(
        classify(&out_of_turn, &limits).verdict,
        Verdict::Accepted,
        "the PING-first frame must be well-formed, or the vector is not about order"
    );
    assert_eq!(
        classify_in_state(&out_of_turn, &limits, HandshakeState::AwaitingHello).code,
        Some(ErrorCode::UnexpectedMessage),
        "the PING-first frame must be refused in the awaiting-HELLO state"
    );
}

/// The message type is reported only for an accepted frame.
#[test]
fn the_message_type_is_reported_only_for_accepted_frames() {
    let limits = Limits::DEFAULT;

    for vector in malformed_vectors() {
        if !has_frame(&vector) {
            continue;
        }

        let id = vectors::id(&vector);
        let frame = frame_of(&vector);
        let declared = frame.get(7).copied();

        let (classification, message_type) = classify_with_message_type(&frame, &limits);

        if classification.verdict == Verdict::Accepted {
            assert_eq!(
                message_type, declared,
                "{id}: an accepted frame's type is {message_type:?} and byte 7 is {declared:?}"
            );
        } else {
            assert_eq!(
                message_type, None,
                "{id}: a rejected frame reported a message type"
            );
        }
    }
}

// =============================================================================================
// Schema-level vectors
// =============================================================================================

/// The three body-schema vectors, each producing its declared code.
#[test]
fn the_schema_vectors_validate_as_declared() {
    // A body with unknown keys must be accepted, which is the forward-compatibility rule.
    let extra = find("malformed.unknown-extra-key-ignored");
    let message_type = u8::try_from(vectors::u64_field(&extra, "message_type")).expect("a u8");
    let body = json_body(&extra);

    assert_eq!(
        validate_body(message_type, &body),
        Ok(()),
        "a body with an unknown key was refused, which breaks forward compatibility"
    );

    // The unknown key is really in the body, so the acceptance above is not vacuous.
    let keys: Vec<String> = body
        .iter()
        .filter_map(|(key, _)| match key {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();

    assert!(
        keys.iter().any(|key| key == "unknown_message_level_key"),
        "the vector's body does not have the unknown key: {keys:?}"
    );

    // A missing required key is refused as ERR_MALFORMED.
    let missing = find("malformed.missing-required-key");
    let message_type = u8::try_from(vectors::u64_field(&missing, "message_type")).expect("a u8");
    let body = json_body(&missing);

    let error = validate_body(message_type, &body).expect_err("a missing key was accepted");

    assert!(
        matches!(error, ValidationError::MissingKey { key } if key == "pointers"),
        "the error is not the missing key: {error}"
    );
    assert_eq!(error.code(), ErrorCode::Malformed);

    // The vector's body really is missing it, and has the key that IS present.
    let keys: Vec<String> = body
        .iter()
        .filter_map(|(key, _)| match key {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();

    assert!(
        !keys.iter().any(|key| key == "pointers"),
        "the key is present: {keys:?}"
    );
    assert!(
        keys.iter().any(|key| key == "action"),
        "the action is absent: {keys:?}"
    );

    // A string where an integer is required is refused, and NOT coerced.
    let wrong = find("malformed.wrong-value-type");
    let message_type = u8::try_from(vectors::u64_field(&wrong, "message_type")).expect("a u8");
    let body = json_body(&wrong);

    // The top level looks fine -- action and pointers are both present and well typed -- so the
    // failure must come from a nested value, which is the part a shallow validator would miss.
    assert!(
        validate_body(message_type, &body).is_ok(),
        "the shallow check must pass, because the vector's defect is one level down"
    );

    // The defect is in the pointer's `x`: the string "1234" where an integer is required.
    let pointers = body
        .iter()
        .find_map(|(key, value)| match key {
            Value::Text(text) if text == "pointers" => Some(value.clone()),
            _ => None,
        })
        .expect("the pointers array");

    let Value::Array(items) = pointers else {
        panic!("pointers is not an array");
    };

    let first = items.first().expect("one pointer");
    let Value::Map(fields) = first else {
        panic!("a pointer is not a map");
    };

    let x = fields
        .iter()
        .find_map(|(key, value)| match key {
            Value::Text(text) if text == "x" => Some(value.clone()),
            _ => None,
        })
        .expect("the x field");

    assert!(
        matches!(x, Value::Text(_)),
        "the vector's x is not a string, so it does not test a wrong type: {x:?}"
    );
    assert!(
        !FieldType::Unsigned.accepts(&x),
        "a string was accepted as an unsigned integer, which is the coercion the vector forbids"
    );

    // And the pointer schema refuses it, which is why this is a real defect rather than a comment.
    let pointer_schema = [
        droidlab_protocol::schema::FieldSpec::required("id", FieldType::Unsigned),
        droidlab_protocol::schema::FieldSpec::required("x", FieldType::Unsigned),
        droidlab_protocol::schema::FieldSpec::required("y", FieldType::Unsigned),
    ];

    let mut failed = false;

    for field in pointer_schema {
        let found = fields.iter().find_map(|(key, value)| match key {
            Value::Text(text) if text == field.key => Some(value),
            _ => None,
        });

        match found {
            Some(value) if !field.field_type.accepts(value) => {
                assert_eq!(field.key, "x");
                failed = true;
            }
            Some(_) => {}
            None => panic!("the required pointer key {} is absent", field.key),
        }
    }

    assert!(failed, "the pointer schema accepted a string for x");

    // The severity is fatal for both schema failures, which the vectors declare.
    for vector in [&missing, &wrong] {
        assert_eq!(
            vectors::str_field(vector, "expected_severity"),
            "fatal",
            "{}: a schema failure must be fatal",
            vectors::id(vector)
        );
        assert_eq!(
            ValidationError::MissingKey { key: "x" }.code().severity(),
            Severity::Fatal,
            "a schema failure is fatal in the registry too"
        );
    }
}

/// An unknown message type has no schema, which is separate from a schema failure.
#[test]
fn an_unknown_message_type_has_no_schema() {
    assert_eq!(
        validate_body(0xEE, &[]),
        Err(ValidationError::UnknownMessageType { message_type: 0xEE })
    );

    // The types the vectors exercise all have schemas, so the failure above is not vacuous.
    for message_type in [0x01u8, 0x02, 0x03, 0x04, 0x40, 0x50] {
        assert_ne!(
            validate_body(message_type, &[]),
            Err(ValidationError::UnknownMessageType { message_type }),
            "message type 0x{message_type:02X} has no schema"
        );
    }

    // An empty body fails a schema with required fields, so the schema is being applied.
    assert!(matches!(
        validate_body(0x01, &[]),
        Err(ValidationError::MissingKey { .. })
    ));
}

// =============================================================================================
// Semantic vectors
// =============================================================================================

/// The capability vector: a registered message the negotiated set does not include is refused.
#[test]
fn the_capability_vector_is_refused_but_survives() {
    let vector = find("malformed.unknown-capability-command");
    let message_type = u8::try_from(vectors::u64_field(&vector, "message_type")).expect("a u8");
    let negotiated = negotiated(&vector);

    assert_eq!(message_type, 80, "SHELL_EXEC");
    assert_eq!(
        negotiated,
        vec!["screen.mirror".to_owned(), "input.touch".to_owned()]
    );
    assert!(
        !negotiated.iter().any(|name| name == "shell.exec"),
        "the vector must not negotiate the capability it exercises"
    );

    let result = check_capability(message_type, &negotiated);

    assert_eq!(result.code, Some(ErrorCode::UnsupportedFeature));
    assert_eq!(
        result.code.map(ErrorCode::severity),
        Some(Severity::Recoverable),
        "an unnegotiated command leaves the session alone"
    );

    // And it is allowed once the capability IS negotiated, so the check is not a refusal of everything.
    let mut granted = negotiated.clone();
    granted.push("shell.exec".to_owned());

    assert_eq!(check_capability(message_type, &granted).code, None);

    // A message type with no capability requirement is allowed either way.
    assert_eq!(
        check_capability(0x05, &[]).code,
        None,
        "PING needs no capability"
    );
}

/// The channel vectors: an unopened channel is refused, and channel 0 is always open.
#[test]
fn the_channel_vectors_are_refused_and_channel_zero_is_always_open() {
    let vector = find("malformed.channel-not-opened");
    let channel_id = u32::try_from(vectors::u64_field(&vector, "channel_id")).expect("a u32");

    let open: Vec<u32> = vector
        .get("open_channels")
        .and_then(Json::as_array)
        .expect("open_channels")
        .iter()
        .map(|value| u32::try_from(value.as_u64().expect("an integer")).expect("fits"))
        .collect();

    assert_eq!(channel_id, 7);
    assert_eq!(open, vec![0, 3]);
    assert!(!open.contains(&channel_id));

    let result = check_channel(channel_id, &open);

    assert_eq!(result.code, Some(ErrorCode::ChannelUnknown));
    assert_eq!(
        result.code.map(ErrorCode::severity),
        Some(Severity::Recoverable)
    );

    // Channel 0 is allowed even though it is not in a list that omits it, which is the vector's own
    // insistence: "Channel 0 is always open, so the frame must name a non-zero channel."
    assert_eq!(check_channel(0, &[]).code, None);
    assert_eq!(check_channel(0, &open).code, None);

    // And channel 3, which IS in the list, is allowed.
    assert_eq!(check_channel(3, &open).code, None);

    // The limit vector: opening one more than the limit is refused.
    let limit = find("malformed.channel-limit");
    let max_channels = u32::try_from(vectors::u64_field(&limit, "max_channels")).expect("a u32");
    let open_count = limit
        .get("open_channels")
        .and_then(Json::as_array)
        .expect("open_channels")
        .len();

    assert_eq!(max_channels, 8);
    assert_eq!(
        open_count, 8,
        "the vector has the limit's worth of channels open"
    );

    let limits = Limits {
        max_channels,
        ..Limits::DEFAULT
    };

    let result = check_channel_limit(open_count, &limits);

    assert_eq!(result.code, Some(ErrorCode::ChannelLimit));
    assert_eq!(
        result.code.map(ErrorCode::severity),
        Some(Severity::Recoverable)
    );

    // One fewer is allowed, so the boundary is exactly where the vector puts it.
    assert_eq!(check_channel_limit(open_count - 1, &limits).code, None);

    // The vector's channel count includes the control channel, which is what makes the limit a count
    // of channels rather than of data channels.
    assert_eq!(
        Limits {
            max_channels: 8,
            ..Limits::DEFAULT
        }
        .data_channels(),
        7,
        "max_channels counts the control channel, so 8 permits 7 data channels"
    );
}

/// The session-state vectors: a frame that is out of turn is refused.
#[test]
fn the_session_state_vectors_are_out_of_turn() {
    // The first frame must be HELLO.
    let vector = find("malformed.first-frame-not-hello");

    let first_type =
        u8::try_from(vectors::u64_field(&vector, "first_frame_message_type")).expect("a u8");

    assert_eq!(first_type, 5, "the vector sends PING first");
    assert_ne!(
        first_type, 0x01,
        "HELLO is type 1, so the vector is not HELLO"
    );

    // The frame really carries that type, so the vector's claim is checkable from its bytes.
    let frame = frame_of(&vector);

    assert_eq!(
        frame.get(7).copied(),
        Some(first_type),
        "the frame's message type does not match first_frame_message_type"
    );

    // The classifier accepts the frame on its own terms -- it is a well-formed PING -- which is the
    // point: the defect is the ORDER, and no single frame's bytes carry that.
    assert_eq!(
        classify(&frame, &Limits::DEFAULT).verdict,
        Verdict::Accepted,
        "the frame must be individually well-formed for this vector to be about order"
    );

    // The state check refuses it, fatally.
    let expected = expected_code(&vector).expect("a code");

    assert_eq!(expected, ErrorCode::UnexpectedMessage);
    assert_eq!(expected.severity(), Severity::Fatal);

    // The second vector: AUTH repeated after AUTH_OK.
    let vector = find("malformed.second-auth-rejected");

    let sequence: Vec<String> = vector
        .get("sequence")
        .and_then(Json::as_array)
        .expect("a sequence")
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_owned)
        .collect();

    assert_eq!(
        sequence,
        vec!["HELLO", "HELLO_ACK", "AUTH", "AUTH_OK", "AUTH"],
        "the vector's sequence changed"
    );

    let auth_count = sequence.iter().filter(|name| *name == "AUTH").count();

    assert_eq!(auth_count, 2, "AUTH appears twice, which is the defect");
    assert!(
        sequence.contains(&"AUTH_OK".to_owned()),
        "AUTH_OK is in the sequence"
    );

    // The second AUTH comes AFTER AUTH_OK, which is what makes it out of turn. If it came before,
    // it would be a legitimate retransmission.
    let first_ok = sequence
        .iter()
        .position(|name| name == "AUTH_OK")
        .expect("AUTH_OK");
    let second_auth = sequence
        .iter()
        .rposition(|name| name == "AUTH")
        .expect("AUTH");

    assert!(
        second_auth > first_ok,
        "the repeated AUTH must come after AUTH_OK or the vector is about a retransmission"
    );

    let expected = expected_code(&vector).expect("a code");

    assert_eq!(expected, ErrorCode::UnexpectedMessage);
    assert_eq!(expected.severity(), Severity::Fatal);
}

// =============================================================================================
// Sequence vectors
// =============================================================================================

/// The reordering window, applied to the vectors' own numbers.
///
/// The rule: the sequence number is session-global and must increase; a gap **inside** the window is
/// legal on a lossy link; a frame outside it is a replay attempt and is fatal. A duplicate is not a
/// reorder and must be refused even though it is arithmetically "inside" the window.
#[test]
fn the_sequence_vectors_describe_the_reordering_window() {
    /// The window's width, from the file's prose.
    const WINDOW: u32 = 32;

    let vectors_list = sequence_vectors();

    assert_eq!(vectors_list.len(), 3, "three sequence vectors");

    let ids: Vec<String> = vectors_list
        .iter()
        .map(|vector| vectors::id(vector).to_owned())
        .collect();

    assert!(ids.contains(&"malformed.sequence-not-monotonic".to_owned()));
    assert!(ids.contains(&"malformed.sequence-gap-within-window".to_owned()));
    assert!(ids.contains(&"malformed.sequence-gap-beyond-window".to_owned()));

    for vector in &vectors_list {
        let id = vectors::id(vector);

        let sequence: Vec<u32> = vector
            .get("sequence")
            .and_then(Json::as_array)
            .expect("the vector has a sequence")
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("an integer")).expect("fits a u32"))
            .collect();

        assert!(!sequence.is_empty(), "{id}: the sequence is empty");
        assert_eq!(
            sequence.first().copied(),
            Some(1),
            "{id}: does not start at 1"
        );

        // Apply the rule, tracking a seen-set as well as the window, because the window alone does not
        // catch a repeat.
        let mut highest = sequence.first().copied().unwrap_or(0);
        let mut seen: Vec<u32> = vec![highest];
        let mut accepted = true;
        let mut reason = "accepted";

        for number in sequence.iter().skip(1) {
            if seen.contains(number) {
                accepted = false;
                reason = "repeated";
                break;
            }

            if *number > highest {
                // Forward, however far. A large forward jump is legal: the window bounds how far
                // BEHIND the highest a frame may arrive, not how far forward.
                highest = *number;
            } else if highest.saturating_sub(*number) < WINDOW {
                // Behind the highest but inside the window: a reorder.
            } else {
                accepted = false;
                reason = "outside the window";
                break;
            }

            seen.push(*number);
        }

        match vector.get("expected_error").and_then(Json::as_str) {
            Some(name) => {
                assert!(
                    !accepted,
                    "{id}: the vector expects {name} and the rule accepted the sequence"
                );

                let code = ErrorCode::from_wire_name(name)
                    .unwrap_or_else(|| panic!("{name} is not registered"));

                assert_eq!(code, ErrorCode::ReplayDetected, "{id}: {reason}");
                assert_eq!(
                    code.severity(),
                    Severity::Fatal,
                    "{id}: a replay must be fatal, or an attacker could replay frames indefinitely"
                );

                let severity = vector
                    .get("expected_severity")
                    .and_then(Json::as_str)
                    .expect("a rejection vector declares a severity");

                assert_eq!(severity, "fatal", "{id}: {reason}");
            }
            None => {
                assert_eq!(
                    vector.get("expected").and_then(Json::as_str),
                    Some("accepted"),
                    "{id}: neither an error nor acceptance is declared"
                );
                assert!(
                    accepted,
                    "{id}: the vector says accepted and the rule rejected it: {reason}"
                );
            }
        }
    }
}

/// The window's boundary, and the duplicate the window alone does not catch.
#[test]
fn the_window_arithmetic_is_the_vectors_own_numbers() {
    const WINDOW: u32 = 32;

    // Beyond: 40 - 3 = 37, which is at or beyond the window.
    let beyond = 40u32.saturating_sub(3);

    assert!(beyond >= WINDOW, "40 - 3 = {beyond}");

    // Within: 5 - 4 = 1.
    let within = 5u32.saturating_sub(4);

    assert!(within < WINDOW, "5 - 4 = {within}");

    // A repeat: 3 - 3 = 0, which is well inside the window. This is the case the window alone accepts,
    // and it is why a seen-set is needed: a duplicate is not a reorder.
    let repeat = 3u32.saturating_sub(3);

    assert!(
        repeat < WINDOW,
        "a repeat is inside the window, so the window alone would accept it"
    );

    // The duplicate vector's own sequence, checked as a sequence rather than as a length.
    let duplicate = sequence_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "malformed.sequence-not-monotonic")
        .expect("the duplicate vector is present");

    let sequence: Vec<u64> = duplicate
        .get("sequence")
        .and_then(Json::as_array)
        .expect("a sequence")
        .iter()
        .map(|value| value.as_u64().expect("an integer"))
        .collect();

    assert_eq!(sequence, vec![1, 2, 3, 3], "the vector's sequence changed");

    // The final value does not exceed the previous one, which is the "not monotonic" the name claims.
    let last = sequence.last().copied().expect("a value");
    let previous = sequence
        .get(sequence.len().saturating_sub(2))
        .copied()
        .expect("a value");

    assert!(
        last <= previous,
        "the vector's sequence is monotonic, so it does not test the rule"
    );
    assert_eq!(
        last, previous,
        "the vector's defect is a duplicate, not a decrease"
    );

    // The beyond-window vector: the out-of-order value is 37 behind the highest.
    let beyond_vector = sequence_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "malformed.sequence-gap-beyond-window")
        .expect("the beyond-window vector is present");

    let sequence: Vec<u64> = beyond_vector
        .get("sequence")
        .and_then(Json::as_array)
        .expect("a sequence")
        .iter()
        .map(|value| value.as_u64().expect("an integer"))
        .collect();

    assert_eq!(sequence, vec![1, 2, 40, 3]);

    let highest = sequence.get(2).copied().expect("40");
    let late = sequence.get(3).copied().expect("3");

    assert_eq!(
        highest.saturating_sub(late),
        37,
        "the late frame is 37 behind the highest, which is beyond a window of 32"
    );
}
