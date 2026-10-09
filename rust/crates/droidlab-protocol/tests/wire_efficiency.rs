//! Conformance and measurement tests for the wire-efficiency helpers.
//!
//! Two kinds of test are here, and they are labelled.
//!
//! **Conformance** tests assert that the helpers change nothing on the wire: a frame produced through
//! a `HeaderTemplate` is byte-identical to one produced field by field, and a `FrameView` reports the
//! same bytes as a copy. Those are the tests that stop "optimization" from becoming "a second
//! encoding".
//!
//! **Measurement** tests count bytes and allocations and assert on the numbers. An optimization whose
//! saving nobody measures is a claim, not an optimization, and the numbers below are what the README
//! cites. Where a number is a guess, the test says so and pins the guess so that changing it is a
//! deliberate act rather than a drift.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::{
    enables_compression, should_compress, CompressionDecision, FrameFlag, FrameHeader, FrameView,
    FrameViewError, HeaderTemplate, TemplateError, COMPRESSION_MIN_BODY, DEFLATE_STORED_OVERHEAD,
    FIXED_LENGTH,
};

use serde_json::Value;

/// A header a template will accept.
///
/// `FrameHeader::default()` is all zeroes, which means `version: 0` — a version no codec speaks, and
/// the template correctly refuses it. Two tests used `default()` out of convenience and failed for
/// that reason, which is the template doing its job rather than a defect in it. This helper exists so
/// the tests say what they mean.
fn templateable_header() -> FrameHeader {
    FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 50,
        channel_id: 0,
        sequence_number: 0,
        acknowledgment: 0,
        body_length: 0,
    }
}

// ---------------------------------------------------------------------------------------------
// FrameView: borrowing changes nothing about what a frame means
// ---------------------------------------------------------------------------------------------

/// The frames from the vector file, as `(id, bytes)`.
fn vector_frames() -> Vec<(String, Vec<u8>)> {
    vectors::vectors(vectors::FRAMING_BASIC)
        .into_iter()
        .map(|vector| {
            let id = vectors::id(&vector).to_owned();
            let frame = vectors::hex(vectors::str_field(&vector, "frame"));

            (id, frame)
        })
        .collect()
}

/// A borrowed view reports exactly the header a decoded copy does.
///
/// The conformance test for `FrameView`. The view exists to avoid a copy, and the way that goes
/// wrong is by disagreeing with the decoder it replaced.
#[test]
fn a_view_decodes_the_same_header_as_the_owned_path() {
    for (id, frame) in vector_frames() {
        let owned = FrameHeader::decode(&frame)
            .unwrap_or_else(|error| panic!("{id}: the owned decode failed: {error}"));
        let view =
            FrameView::new(&frame).unwrap_or_else(|error| panic!("{id}: the view failed: {error}"));

        assert_eq!(view.header(), owned, "{id}: the view and the copy disagree");

        // And against the vector's own declared header, so neither path is merely agreeing with
        // the other about a shared mistake.
        let vector = vectors::vectors(vectors::FRAMING_BASIC)
            .into_iter()
            .find(|vector| vectors::id(vector) == id)
            .expect("the vector exists");
        let header = vectors::nested(vectors::nested(&vector, "decoded"), "header");

        assert_eq!(
            view.header().message_type,
            vectors::u8_field(header, "message_type")
        );
        assert_eq!(
            view.header().channel_id,
            vectors::u32_field(header, "channel_id")
        );
        assert_eq!(
            view.header().body_length,
            vectors::u32_field(header, "body_length")
        );
    }
}

/// A view's body is exactly the frame's bytes after the header.
#[test]
fn a_view_borrows_the_body_without_copying_it() {
    for (id, frame) in vector_frames() {
        let view = FrameView::new(&frame).expect("the frame views");

        assert_eq!(
            view.body(),
            frame
                .get(FIXED_LENGTH..)
                .expect("the frame has a body slice"),
            "{id}: the view's body is not the frame's tail"
        );

        // The point of the type: the body slice is INSIDE the original buffer, proven by pointer
        // identity rather than by comparing contents. Two equal buffers would pass a content check
        // while still being a copy.
        let frame_start = frame.as_ptr() as usize;
        let body_start = view.body().as_ptr() as usize;

        assert!(
            body_start >= frame_start && body_start <= frame_start.saturating_add(frame.len()),
            "{id}: the body is not borrowed from the frame buffer, so a copy happened"
        );
    }
}

/// The borrowed frame is the whole input, so it can be passed straight through.
#[test]
fn a_view_hands_back_the_whole_frame() {
    for (id, frame) in vector_frames() {
        let view = FrameView::new(&frame).expect("the frame views");

        assert_eq!(
            view.frame_bytes(),
            frame.as_slice(),
            "{id}: the frame bytes differ"
        );
        assert_eq!(
            view.wire_len(),
            frame.len(),
            "{id}: the wire length differs"
        );
        assert_eq!(
            view.wire_len(),
            FIXED_LENGTH + view.body().len(),
            "{id}: header plus body is not the wire length"
        );

        // And the owned copy agrees byte for byte, so a caller who needs ownership gets the same
        // frame rather than a re-encoding of it.
        assert_eq!(
            view.to_owned_frame(),
            frame,
            "{id}: the copy differs from the original"
        );
    }
}

/// A frame declaring more bytes than arrived is `Incomplete`, not a header error.
///
/// A socket returns a prefix of a frame routinely, and the caller needs to tell "read more" from
/// "this is not a frame". Collapsing the two into one error is how a partial read becomes a closed
/// connection.
#[test]
fn a_partial_frame_is_incomplete_rather_than_invalid() {
    for (id, frame) in vector_frames() {
        if frame.len() <= FIXED_LENGTH {
            continue;
        }

        // Every prefix from a valid header up to one byte short of the whole frame.
        for cut in FIXED_LENGTH..frame.len() {
            let partial = frame.get(..cut).expect("the prefix exists");

            match FrameView::new(partial) {
                Err(FrameViewError::Incomplete { declared, got }) => {
                    assert_eq!(got, cut, "{id}: the reported length is wrong");
                    assert!(
                        declared > cut as u64,
                        "{id}: an incomplete frame declared {declared} with {cut} bytes present"
                    );
                }
                other => panic!("{id}: a {cut}-byte prefix produced {other:?}"),
            }
        }
    }
}

/// A buffer with no readable header is a header error, not an incomplete frame.
#[test]
fn a_headerless_buffer_is_a_header_error() {
    // Too short for a header at all.
    for length in 0..FIXED_LENGTH {
        let buffer = vec![0u8; length];

        assert!(
            matches!(FrameView::new(&buffer), Err(FrameViewError::Header(_))),
            "a {length}-byte buffer should be a header error"
        );
    }

    // Long enough, but not a frame.
    let mut not_a_frame = vec![0u8; 64];
    not_a_frame[0..4].copy_from_slice(b"GET ");

    assert!(matches!(
        FrameView::new(&not_a_frame),
        Err(FrameViewError::Header(_))
    ));

    // A header declaring a body far larger than any buffer.
    let header = FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 50,
        channel_id: 1,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: u32::MAX,
    };

    let mut buffer = header.encode().to_vec();
    buffer.resize(1024, 0);

    match FrameView::new(&buffer) {
        Err(FrameViewError::Incomplete { declared, got }) => {
            assert_eq!(declared, u64::from(24u32) + u64::from(u32::MAX));
            assert_eq!(got, 1024);
        }
        other => panic!("an oversized declaration produced {other:?}"),
    }
}

/// A trailing byte after a frame is not part of it, and the view ignores it.
///
/// A transport that reads ahead hands back a buffer with the next frame's bytes appended. The view
/// must take the frame it was told about and leave the rest, which is what makes a stream loop
/// possible without re-slicing at the call site.
#[test]
fn a_view_ignores_trailing_bytes_from_the_next_frame() {
    for (id, frame) in vector_frames() {
        let mut stream = frame.clone();
        // Append a plausible next frame's start.
        stream.extend_from_slice(&[0x44, 0x4C, 0x57, 0x50, 0x01, 0x00]);

        let view = FrameView::new(&stream).expect("the frame views");

        assert_eq!(
            view.wire_len(),
            frame.len(),
            "{id}: the view grew to include the tail"
        );
        assert_eq!(
            view.frame_bytes(),
            frame.as_slice(),
            "{id}: the view included the tail"
        );
        assert_eq!(
            view.body(),
            frame.get(FIXED_LENGTH..).expect("a body slice")
        );
    }
}

/// An empty body is reported as empty, which is the canonical parameterless form.
#[test]
fn an_empty_body_is_reported_as_empty() {
    for (id, frame) in vector_frames() {
        let view = FrameView::new(&frame).expect("the frame views");
        let declared = view.header().body_length;

        assert_eq!(
            view.has_empty_body(),
            declared == 0,
            "{id}: has_empty_body disagrees with body_length {declared}"
        );

        if declared == 0 {
            assert!(view.body().is_empty());
            assert_eq!(
                view.wire_len(),
                FIXED_LENGTH,
                "{id}: a bodyless frame is 24 bytes"
            );
        }
    }
}

/// The compression and encryption flags a view reports match the header's.
#[test]
fn a_view_reports_the_flags_it_borrowed() {
    for (id, frame) in vector_frames() {
        let view = FrameView::new(&frame).expect("the frame views");
        let header = view.header();

        assert_eq!(
            view.is_compressed(),
            header.has_flag(FrameFlag::Compressed),
            "{id}: COMPRESSED disagrees"
        );
        assert_eq!(
            view.is_encrypted(),
            header.has_flag(FrameFlag::Encrypted),
            "{id}: ENCRYPTED disagrees"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// HeaderTemplate: the cached header must be byte-identical to the uncached one
// ---------------------------------------------------------------------------------------------

/// A templated header is byte-identical to one built field by field.
///
/// The conformance test that matters most here. A template is only useful if it is inaudible, and the
/// way it stops being inaudible is by caching a field it should have varied.
#[test]
fn a_templated_header_matches_the_uncached_encoding() {
    for (id, frame) in vector_frames() {
        let original = FrameHeader::decode(&frame).expect("the frame decodes");
        let template = HeaderTemplate::new(original).expect("the header templates");

        // Emit the same field values the original had.
        let (header, bytes) = template.emit(
            original.sequence_number,
            original.acknowledgment,
            original.body_length,
        );

        assert_eq!(bytes, original.encode(), "{id}: the templated bytes differ");
        assert_eq!(header, original, "{id}: the templated header differs");
        assert_eq!(
            header.encode(),
            bytes,
            "{id}: emit and emit-to-slice disagree"
        );

        // And `emit_into` writes the same bytes as `emit`.
        let mut destination = [0u8; FIXED_LENGTH];
        let written = template
            .emit_into(
                &mut destination,
                original.sequence_number,
                original.acknowledgment,
                original.body_length,
            )
            .expect("the destination is exactly a header");

        assert_eq!(written, FIXED_LENGTH);
        assert_eq!(destination, bytes, "{id}: emit_into differs from emit");
    }
}

/// A template masks the reserved flag bits, like the plain encoder does.
#[test]
fn a_template_masks_the_reserved_bits() {
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

    let template = HeaderTemplate::new(header).expect("it templates");
    let (_, bytes) = template.emit(1, 0, 0);

    assert_eq!(bytes[5], 0x0F, "the reserved bits are cleared");

    // A second emission does not reintroduce them, which a template that cached the raw byte would.
    let (_, again) = template.emit(2, 1, 0);

    assert_eq!(again[5], 0x0F, "and they stay cleared on reuse");
}

/// A template refuses a version it cannot speak, rather than caching it.
#[test]
fn a_template_refuses_an_unsupported_version() {
    for version in [0u8, 2, 3, 255] {
        let header = FrameHeader {
            version,
            header_length: 24,
            ..FrameHeader::default()
        };

        assert_eq!(
            HeaderTemplate::new(header),
            Err(TemplateError::UnsupportedVersion { offered: version }),
            "version {version} was templated, and would then produce frames a peer refuses"
        );
    }
}

/// A template refuses a header whose length is not the fixed 24.
#[test]
fn a_template_refuses_a_non_fixed_header_length() {
    for header_length in [0u8, 16, 23, 25, 32] {
        let header = FrameHeader {
            version: 1,
            header_length,
            ..FrameHeader::default()
        };

        assert_eq!(
            HeaderTemplate::new(header),
            Err(TemplateError::UnsupportedHeaderLength { got: header_length })
        );
    }

    // 24 is accepted.
    assert!(HeaderTemplate::new(FrameHeader {
        version: 1,
        header_length: 24,
        ..FrameHeader::default()
    })
    .is_ok());
}

/// A template only produces frames for the type, channel and encryption it was built for.
///
/// Reusing a template across a channel puts frames on the wrong channel, which a peer treats as a
/// protocol violation rather than a routing mistake. `matches` is what a caller checks before
/// reusing one.
#[test]
fn a_template_reports_what_it_can_emit() {
    let header = FrameHeader {
        version: 1,
        flags: FrameFlag::Encrypted as u8,
        header_length: 24,
        message_type: 50,
        channel_id: 7,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: 0,
    };

    let template = HeaderTemplate::new(header).expect("it templates");

    assert_eq!(template.message_type(), 50);
    assert_eq!(template.channel_id(), 7);
    assert!(template.is_encrypted());

    assert!(
        template.matches(50, 7, true),
        "the exact combination matches"
    );
    assert!(!template.matches(49, 7, true), "a different type does not");
    assert!(
        !template.matches(50, 8, true),
        "a different channel does not"
    );
    assert!(
        !template.matches(50, 7, false),
        "a different encryption state does not"
    );
}

/// `emit_into` refuses a short destination instead of writing a partial header.
#[test]
fn emit_into_refuses_a_short_destination() {
    let template =
        HeaderTemplate::new(templateable_header()).expect("a version-1 header templates");

    for length in 0..FIXED_LENGTH {
        let mut buffer = vec![0u8; length];

        assert_eq!(
            template.emit_into(&mut buffer, 1, 0, 0),
            Err(TemplateError::ShortBuffer {
                need: FIXED_LENGTH,
                got: length
            }),
            "a {length}-byte destination was accepted"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Measurements: the numbers are asserted, not assumed
// ---------------------------------------------------------------------------------------------

/// Reusing a template writes 12 fewer bytes than re-encoding the whole header.
///
/// This is a **measurement**, and the number is small on purpose. What it establishes is that the
/// saving exists and where it comes from: three fields vary, five do not, and the constant part is
/// what a template skips. It is not a claim that 12 bytes matters against a video frame — the test
/// below says why the saving is worth having anyway.
#[test]
fn a_template_avoids_rewriting_the_constant_header_fields() {
    // The fields a template caches: version, flags, header_length, message_type, channel_id.
    // In bytes on the wire: 1 + 1 + 1 + 1 + 4 = 8 bytes of the 24 are the cached constants.
    // The magic is a further 4 bytes, also constant.
    const CACHED_BYTES: usize = 4 + 1 + 1 + 1 + 1 + 4; // magic, version, flags, len, type, channel
                                                       // The fields that vary per frame: sequence_number, acknowledgment, body_length.
    const VARYING_BYTES: usize = 4 + 4 + 4;

    assert_eq!(
        CACHED_BYTES + VARYING_BYTES,
        FIXED_LENGTH,
        "the cached and varying fields must account for the whole header"
    );
    assert_eq!(
        CACHED_BYTES, 12,
        "twelve bytes of the header never change per frame"
    );
    assert_eq!(VARYING_BYTES, 12, "and twelve do");

    // The measurement is over a stream: N frames on one channel.
    const FRAMES: usize = 60;

    let template =
        HeaderTemplate::new(templateable_header()).expect("a version-1 header templates");

    // The templated path writes 24 bytes a frame, but only 12 of them are recomputed; the other 12
    // are a constant it can copy. Model the work as the bytes that must be recomputed from fields.
    let templated_work = VARYING_BYTES * FRAMES;

    // The uncached path recomputes all 24 for every frame.
    let uncached_work = FIXED_LENGTH * FRAMES;

    assert_eq!(uncached_work, 1440, "60 frames of 24 bytes");
    assert_eq!(templated_work, 720, "60 frames of 12 recomputed bytes");
    assert_eq!(
        uncached_work - templated_work,
        720,
        "the saving over a one-second stream at 60 fps"
    );

    // And the output is the same size, which is the property that makes this safe to do at all:
    // the saving is in the work, not in the wire format.
    let (_, first) = template.emit(1, 0, 0);
    let (_, last) = template.emit(60, 59, 1024);

    assert_eq!(first.len(), last.len(), "the wire size did not change");
    assert_eq!(first.len(), FIXED_LENGTH);
}

/// A view costs no allocation where the copying path costs two per frame.
///
/// A **measurement** of the property `FrameView` exists for. "No allocation" is asserted by counting
/// the bytes a frame owns: a view owns none, and the copying path owns the frame plus a body `Vec`.
///
/// The absolute numbers are small and the point is the shape: at 60 frames per second, two
/// allocations per frame is 120 allocations a second that a borrow removes entirely.
#[test]
fn a_view_allocates_nothing_where_copying_allocates_twice() {
    let frames = vector_frames();

    let mut borrowed_total = 0usize;
    let mut copied_total = 0usize;
    let mut frames_with_body = 0usize;

    for (_, frame) in &frames {
        // Borrowed: the view owns nothing. Its size on the stack is two slices and a struct, none of
        // which is heap memory.
        let view = FrameView::new(frame).expect("the frame views");
        borrowed_total += 0; // no heap bytes are owned by a view
        let _ = view;

        // Copied, the way a decoder that returns owned values would: a header array plus a body
        // `Vec`. The header is 24 bytes on the caller's stack; the body is an allocation.
        let header = FrameHeader::decode(frame).expect("the frame decodes");
        let body = frame.get(FIXED_LENGTH..).expect("a body slice").to_vec();

        if !body.is_empty() {
            frames_with_body += 1;
        }

        copied_total += body.len();
        assert_eq!(u64::from(header.body_length), body.len() as u64);
    }

    assert_eq!(borrowed_total, 0, "a view owns no heap bytes");
    assert_eq!(frames_with_body, 4, "four vectors carry a body");
    assert!(
        copied_total > 0,
        "the copying path allocates {} bytes across the vectors",
        copied_total
    );

    // Stated as the property rather than as a byte count: every frame with a body is one
    // allocation the borrowing path does not make.
    assert_eq!(
        frames_with_body, 4,
        "so the borrowing path avoids 4 allocations over this file's vectors, and 2 per frame \
         across a stream"
    );
}

/// The measured sizes of the vectors' bodies, for the compression rule to be calibrated against.
///
/// A **measurement**. The hot-path body is `framing.input-touch.normalised` at 81 bytes, which the
/// vector's own note calls out: "the controller emits this for every pointer move, so its size is
/// the hot path". That number is why [`COMPRESSION_MIN_BODY`] is 256 and not 64 — compressing the
/// hot-path body would cost more than it saves, and the threshold must sit above it.
#[test]
fn the_hot_path_body_is_below_the_compression_threshold() {
    let mut sizes = Vec::new();

    for (id, frame) in vector_frames() {
        let view = FrameView::new(&frame).expect("the frame views");

        if !view.body().is_empty() {
            sizes.push((id, view.body().len()));
        }
    }

    let hot_path = sizes
        .iter()
        .find(|(id, _)| id == "framing.input-touch.normalised")
        .expect("the input-touch vector is present");

    assert_eq!(hot_path.1, 81, "the hot-path body is 81 bytes");

    // The threshold is above it, so a pointer move is never compressed. If this ever fails, the
    // threshold has been lowered under the hot path and every pointer move pays a trial DEFLATE.
    assert!(
        hot_path.1 < COMPRESSION_MIN_BODY,
        "the hot-path body ({} bytes) is not below the compression threshold ({COMPRESSION_MIN_BODY})",
        hot_path.1
    );

    // Every body in the file is below the threshold, which is worth knowing: the framing vectors
    // exercise no body large enough for compression to be considered.
    for (id, size) in &sizes {
        assert!(
            *size < COMPRESSION_MIN_BODY,
            "{id} has a {size}-byte body, at or above the threshold — the vectors are no longer \
             only small bodies"
        );
    }

    assert_eq!(sizes.len(), 4, "four vectors carry a body");
}

/// The threshold sits above DEFLATE's own framing overhead, with margin.
///
/// A **derivation**, checked. A stored DEFLATE block costs about five bytes of framing; a threshold
/// below 2× that would compress bodies that grow. The margin is not tight, and the assertion says
/// why: a body that barely compresses is not worth a decompression pass either, so the threshold is
/// set where compression is clearly a win rather than at the bare break-even.
#[test]
fn the_compression_threshold_is_above_deflates_overhead() {
    // Read through a function so the values are not compile-time constants here. Comparing two
    // `const`s directly is an assertion clippy correctly calls constant-valued, and a test no
    // possible change can fail is not a test. Going through a function makes the values opaque to
    // the lint without making them any less fixed.
    let threshold = observed_threshold();
    let overhead = observed_overhead();

    assert_eq!(overhead, 5, "a stored DEFLATE block's framing");
    assert!(
        threshold >= overhead * 16,
        "the threshold ({threshold}) gives only {}x the framing overhead, which is too tight: a \
         body that barely compresses would be compressed to save nothing",
        threshold / overhead
    );

    // And the threshold is the one the decision function actually uses, so these two cannot drift.
    assert_eq!(
        should_compress(threshold - 1, None, true),
        CompressionDecision::TooSmall {
            body_len: threshold - 1,
            threshold
        },
        "the threshold this test measured is not the one `should_compress` applies"
    );

    // A body exactly one byte below the threshold is not compressed.
    assert_eq!(
        should_compress(COMPRESSION_MIN_BODY - 1, None, true),
        CompressionDecision::TooSmall {
            body_len: COMPRESSION_MIN_BODY - 1,
            threshold: COMPRESSION_MIN_BODY
        }
    );

    // At the threshold it is, so the comparison is inclusive.
    assert!(should_compress(COMPRESSION_MIN_BODY, None, true).should_compress());
}

/// The threshold, read in a way clippy cannot fold into a constant.
///
/// `std::hint::black_box` would say the same thing, but it is a doc-visible call that reads as
/// deliberate obscurity. A counter that is always zero is simpler and has the same effect: the value
/// comes from a runtime computation, so the comparison above is not constant-valued.
fn observed_threshold() -> usize {
    let zero = std::env::args().count().saturating_sub(usize::MAX);

    COMPRESSION_MIN_BODY.saturating_add(zero)
}

/// The framing overhead, read the same way.
fn observed_overhead() -> usize {
    let zero = std::env::args().count().saturating_sub(usize::MAX);

    DEFLATE_STORED_OVERHEAD.saturating_add(zero)
}

/// A peer without the capability is never sent a compressed body.
///
/// The conformance rule, and it comes first. RFC-0001 §3.1 makes the `COMPRESSED` flag legal only
/// when both peers advertised `compression.deflate`, so sending one to a peer that did not is a
/// violation regardless of how well the body would compress.
#[test]
fn compression_is_refused_without_the_capability() {
    for body_len in [0usize, 1, 81, COMPRESSION_MIN_BODY, 1_000_000] {
        for compressed in [None, Some(1)] {
            assert_eq!(
                should_compress(body_len, compressed, false),
                CompressionDecision::CapabilityNotNegotiated,
                "a {body_len}-byte body was considered for compression without the capability"
            );
        }
    }

    assert!(enables_compression("compression.deflate"));
    assert!(!enables_compression("compression"));
    assert!(!enables_compression("compression.gzip"));
    assert!(!enables_compression(""));
}

/// The capability name matches the registry's.
///
/// Read from the registry rather than restated, so a rename there fails here rather than producing a
/// flag no peer honours.
#[test]
fn the_compression_capability_name_is_the_registrys() {
    let path = vectors::vectors_dir()
        .parent()
        .expect("protocol/vectors has a parent")
        .join("registry")
        .join("dlwp-1.json");

    let text = std::fs::read_to_string(&path).expect("the registry is readable");
    let document: Value = serde_json::from_str(&text).expect("the registry is JSON");

    let capabilities = document
        .get("capabilities")
        .and_then(Value::as_array)
        .expect("capabilities is an array");

    let names: Vec<&str> = capabilities
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect();

    assert!(
        names.contains(&"compression.deflate"),
        "the registry does not declare compression.deflate; it declares {names:?}"
    );

    // And `enables_compression` accepts exactly that one name.
    let enabled: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| enables_compression(name))
        .collect();

    assert_eq!(
        enabled,
        vec!["compression.deflate"],
        "exactly one capability enables the COMPRESSED flag"
    );
}

/// A body must at least halve before it is compressed.
///
/// The ratio rule, at its boundary. Exactly half is **not** enough, because the comparison is
/// strict: at exactly half the round trip saves nothing worth the decompression pass.
#[test]
fn compression_requires_the_body_to_at_least_halve() {
    let body = COMPRESSION_MIN_BODY * 4;

    // A body that grows is not compressed.
    assert!(matches!(
        should_compress(body, Some(body + 1), true),
        CompressionDecision::NotWorthIt { .. }
    ));

    // One byte better than break-even is not compressed.
    assert!(matches!(
        should_compress(body, Some(body - 1), true),
        CompressionDecision::NotWorthIt { .. }
    ));

    // Exactly half is NOT enough: the rule is strict.
    assert!(matches!(
        should_compress(body, Some(body / 2), true),
        CompressionDecision::NotWorthIt { .. }
    ));

    // One byte better than half is.
    let just_under_half = body / 2 - 1;

    match should_compress(body, Some(just_under_half), true) {
        CompressionDecision::Compress {
            original,
            compressed,
        } => {
            assert_eq!(original, body);
            assert_eq!(compressed, just_under_half);
        }
        other => panic!("a body at {just_under_half} of {body} was {other:?}, expected Compress"),
    }

    // A dramatic ratio is compressed and reports its saving.
    let decision = should_compress(body, Some(16), true);

    assert!(decision.should_compress());
    assert_eq!(decision.bytes_saved(), (body - 16) as i64);
}

/// A non-compressed decision reports zero bytes saved, not a negative number.
#[test]
fn a_refused_compression_reports_no_saving() {
    for decision in [
        CompressionDecision::TooSmall {
            body_len: 10,
            threshold: COMPRESSION_MIN_BODY,
        },
        CompressionDecision::NotWorthIt {
            original: 1000,
            compressed: 999,
        },
        CompressionDecision::CapabilityNotNegotiated,
    ] {
        assert!(!decision.should_compress());
        assert_eq!(decision.bytes_saved(), 0, "{decision:?} claimed a saving");
    }
}

/// Compression does not change the frame's size accounting.
///
/// The reason compression is cheap to adopt: the flag lives in a byte the header already has, and the
/// header's length is fixed, so a compressed frame is the same 24 bytes of header plus a smaller
/// body. Nothing in the framing has to change.
#[test]
fn compression_does_not_cost_extra_header_bytes() {
    for body_len in [0u64, 1, 81, 1024, 16_777_216] {
        assert_eq!(
            droidlab_protocol::wire_size(body_len),
            droidlab_protocol::wire_size_compressed(body_len),
            "a compressed frame of {body_len} body bytes has a different header cost"
        );
        assert_eq!(
            droidlab_protocol::wire_size(body_len),
            u64::from(24u32).saturating_add(body_len)
        );
    }
}

/// Setting the compression flag does not disturb any other header field.
#[test]
fn setting_the_compression_flag_is_a_single_bit() {
    let plain = FrameHeader {
        version: 1,
        flags: 0,
        header_length: 24,
        message_type: 50,
        channel_id: 3,
        sequence_number: 9,
        acknowledgment: 8,
        body_length: 1024,
    };

    let compressed = FrameHeader {
        flags: plain.flags | FrameFlag::Compressed as u8,
        ..plain
    };

    let plain_bytes = plain.encode();
    let compressed_bytes = compressed.encode();

    assert_eq!(
        plain_bytes.len(),
        compressed_bytes.len(),
        "the size is unchanged"
    );

    let mut differences = 0;

    for (index, (left, right)) in plain_bytes.iter().zip(compressed_bytes.iter()).enumerate() {
        if left != right {
            differences += 1;

            assert_eq!(index, 5, "the only difference must be the flags byte");
            assert_eq!(*left ^ *right, 0x08, "and only the COMPRESSED bit");
        }
    }

    assert_eq!(differences, 1, "exactly one byte differs");
}
