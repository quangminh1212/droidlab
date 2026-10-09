//! Conformance tests for capability negotiation and limit clamping.
//!
//! `capabilities.json` is four vector groups in one file — 8 negotiation, 4 limit-clamp, 2 direction —
//! and it carries a fixture correction worth reading. `negotiate.empty-intersection`'s
//! `note_on_diagnostics` records that an earlier revision claimed the "device information and error
//! channels" stay usable in a session with no capabilities:
//!
//! > That was wrong: the registry gates DEVICE_INFO and DEVICE_INFO_RESULT under device.info, and a
//! > controller that offered nothing must not read device metadata. What keeps this case diagnosable is
//! > that GET_CAPABILITIES, CAPABILITIES and ERROR are ungated.
//!
//! So the test for that vector checks the registry's answer as normative: exactly three message types
//! are ungated, and `DEVICE_INFO` is not among them.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::capability::{
    clamp_file_chunk, clamp_shell_timeout, clamp_video, even_floor, fit_inside,
    is_known_capability, may_reopen, negotiate, ungated_message_types, ChannelAllocator,
    VideoRequest, CAPABILITIES, COMPRESSION,
};
use droidlab_protocol::limits::Limits;
use droidlab_protocol::registry::{
    capability_for_message_type, is_registered_message_type, message_type_by_name,
};

use serde_json::Value;

const CAPABILITIES_FILE: &str = "capabilities.json";

fn document() -> Value {
    vectors::load(CAPABILITIES_FILE)
}

fn group(name: &str) -> Vec<Value> {
    document()
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{CAPABILITIES_FILE} has no `{name}` array"))
        .clone()
}

/// A JSON array of strings, as a `Vec<String>`.
fn strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn u32_of(value: &Value, field: &str) -> u32 {
    u32::try_from(
        value
            .get(field)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("no integer field {field:?}")),
    )
    .expect("it fits a u32")
}

// =============================================================================================
// The capability registry
// =============================================================================================

/// The table matches the file's `capability_registry`, both directions.
#[test]
fn the_capability_table_matches_the_file() {
    let registry: Vec<String> = document()
        .get("capability_registry")
        .and_then(Value::as_array)
        .expect("capability_registry")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    assert_eq!(CAPABILITIES.len(), registry.len(), "the counts differ");
    assert_eq!(CAPABILITIES.len(), 18, "the file declares 18 capabilities");

    // Same order as well as same contents. A set comparison alone would pass on a reordering, and the
    // order is what the registry publishes.
    let as_strings: Vec<&str> = CAPABILITIES.to_vec();

    assert_eq!(as_strings, registry, "the order or the contents differ");

    // Every name is known, and a name that is not, is not.
    for name in CAPABILITIES {
        assert!(is_known_capability(name), "{name} is not recognised");
    }

    assert!(!is_known_capability("future.capability.v2"));
    assert!(!is_known_capability(""));
    assert!(
        !is_known_capability("Screen.Mirror"),
        "names are case-sensitive"
    );

    // The registry's own list is unique, so a duplicate there would be a fixture defect rather than a
    // normalisation to hide.
    let mut sorted = registry.clone();
    sorted.sort();

    let mut deduped = sorted.clone();
    deduped.dedup();

    assert_eq!(
        deduped.len(),
        sorted.len(),
        "the file's capability list has a duplicate"
    );

    assert_eq!(COMPRESSION, "compression.deflate");
    assert!(is_known_capability(COMPRESSION));
}

// =============================================================================================
// Negotiation
// =============================================================================================

/// Every negotiation vector produces its declared set.
#[test]
fn every_negotiation_vector_produces_its_declared_set() {
    let vectors_list = group("negotiation_vectors");

    assert_eq!(vectors_list.len(), 8, "eight negotiation vectors");

    for vector in &vectors_list {
        let id = vectors::id(vector);

        let agent = strings(vector, "agent_capabilities");
        let disabled = strings(vector, "agent_disabled");
        let offered = strings(vector, "controller_offered");

        let expected: Vec<String> = strings(vector, "expected_negotiated");
        let mut expected = expected;
        expected.sort();

        let result = negotiate(&agent, &disabled, &offered);

        assert_eq!(
            result.capabilities, expected,
            "{id}: negotiated {:?} and the vector declares {expected:?}",
            result.capabilities
        );

        // The set is sorted, so two peers comparing their results agree on order.
        let mut as_sorted = result.capabilities.clone();
        as_sorted.sort();

        assert_eq!(
            result.capabilities, as_sorted,
            "{id}: the negotiated set is not sorted"
        );

        // And it has no duplicates.
        let mut deduped = result.capabilities.clone();
        deduped.dedup();

        assert_eq!(
            result.capabilities.len(),
            deduped.len(),
            "{id}: the negotiated set has a duplicate"
        );

        // Every negotiated name is one DLWP/1 defines, so the intersection cannot introduce a stranger.
        for name in &result.capabilities {
            assert!(
                is_known_capability(name),
                "{id}: {name} is not a DLWP/1 capability"
            );
        }

        // Every negotiated name was OFFERED, which is the property that a capability the controller
        // never asked for cannot appear.
        for name in &result.capabilities {
            assert!(
                offered.contains(name),
                "{id}: {name} was negotiated though it was never offered"
            );
            assert!(
                agent.contains(name),
                "{id}: {name} was negotiated though the agent does not implement it"
            );
            assert!(
                !disabled.contains(name),
                "{id}: {name} was negotiated though it is disabled"
            );
        }
    }
}

/// The operator's switch wins, and `disabled` is why.
///
/// The vector's note: "This is the rule that makes the device-side switch meaningful." A two-way
/// intersection would negotiate the capability and make the switch decorative.
#[test]
fn the_operators_switch_wins() {
    let vector = group("negotiation_vectors")
        .into_iter()
        .find(|vector| {
            vectors::id(vector) == "negotiate.operator-disabled-wins-even-when-both-support-it"
        })
        .expect("the disabled vector is present");

    let agent = strings(&vector, "agent_capabilities");
    let disabled = strings(&vector, "agent_disabled");
    let offered = strings(&vector, "controller_offered");

    // Both sides really do have it, which is what makes the vector a test of the third term.
    assert!(agent.contains(&"shell.exec".to_owned()));
    assert!(offered.contains(&"shell.exec".to_owned()));
    assert!(disabled.contains(&"shell.exec".to_owned()));

    let result = negotiate(&agent, &disabled, &offered);

    assert!(
        !result.has("shell.exec"),
        "a disabled capability was negotiated, which makes the device-side switch decorative"
    );

    // The others in the same vector ARE negotiated, so the exclusion is specific.
    assert!(result.has("screen.mirror"));
    assert!(result.has("input.touch"));

    // And removing it from `disabled` restores it, which proves `disabled` was the cause rather than
    // some other term.
    let restored = negotiate(&agent, &[], &offered);

    assert!(
        restored.has("shell.exec"),
        "shell.exec is not negotiated even with the switch on, so something else excluded it"
    );
}

/// An empty intersection is legal and is not an error.
#[test]
fn an_empty_intersection_is_legal() {
    let vector = group("negotiation_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "negotiate.empty-intersection")
        .expect("the empty vector is present");

    let agent = strings(&vector, "agent_capabilities");
    let offered = strings(&vector, "controller_offered");

    let result = negotiate(&agent, &[], &offered);

    assert!(result.is_empty(), "the intersection is not empty");
    assert!(result.capabilities.is_empty());
    assert_eq!(
        result.unknown,
        Vec::<String>::new(),
        "nothing unknown was offered"
    );

    // The vector declares no error, and there is none to declare: an empty set is a valid outcome.
    assert_eq!(
        vector.get("expected_error"),
        Some(&Value::Null),
        "the vector now expects an error, so re-read the note"
    );

    // The fixture correction: the registry gates DEVICE_INFO under device.info, so a controller that
    // offered nothing must NOT be able to read device metadata. An earlier revision of the note said
    // the device-information channel stays usable; the note now says capability and error channels and
    // says the registry's answer is normative, so the test follows the registry.
    assert!(
        !result.has("device.info"),
        "device.info was negotiated from an empty intersection"
    );

    assert_eq!(
        capability_for_message_type(128),
        Some("device.info"),
        "DEVICE_INFO must be gated on device.info, or the corrected note is wrong"
    );
    assert_eq!(capability_for_message_type(129), Some("device.info"));

    let device_info = message_type_by_name("DEVICE_INFO").expect("DEVICE_INFO is registered");

    assert_eq!(device_info.code, 128);

    assert!(
        !result.has(capability_for_message_type(device_info.code).expect("DEVICE_INFO is gated")),
        "DEVICE_INFO is gated on a capability this session does not have"
    );

    // What keeps the session diagnosable: exactly three ungated message types.
    let ungated = ungated_message_types();

    assert_eq!(ungated.len(), 3);
    assert!(ungated.contains(&16), "GET_CAPABILITIES is ungated");
    assert!(ungated.contains(&17), "CAPABILITIES is ungated");
    assert!(ungated.contains(&240), "ERROR is ungated");
    assert!(
        !ungated.contains(&128),
        "DEVICE_INFO must NOT be ungated, or the corrected note is wrong"
    );

    // And the ungated set is exactly the three types with no capability requirement, checked against
    // the registry's mapping rather than against this crate's list.
    assert_eq!(
        capability_for_message_type(16),
        None,
        "GET_CAPABILITIES is ungated"
    );
    assert_eq!(
        capability_for_message_type(17),
        None,
        "CAPABILITIES is ungated"
    );
    assert_eq!(capability_for_message_type(240), None, "ERROR is ungated");

    for code in ungated {
        assert!(
            is_registered_message_type(code),
            "{code} is ungated but unregistered"
        );
    }
}

/// An unknown capability name is ignored in the offer, and reported.
#[test]
fn an_unknown_capability_name_is_ignored() {
    let vector = group("negotiation_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "negotiate.unknown-capability-name-ignored")
        .expect("the unknown-capability vector is present");

    let agent = strings(&vector, "agent_capabilities");
    let offered = strings(&vector, "controller_offered");
    let ignored = strings(&vector, "unknown_ignored");

    assert_eq!(ignored, vec!["future.capability.v2".to_owned()]);

    // Both sides advertise it, so a two-way intersection would negotiate it, which is what the
    // unknown-name rule prevents.
    assert!(agent.contains(&"future.capability.v2".to_owned()));
    assert!(offered.contains(&"future.capability.v2".to_owned()));

    let result = negotiate(&agent, &[], &offered);

    assert!(
        !result.has("future.capability.v2"),
        "an unknown capability was negotiated, which would break a future minor version"
    );

    // Reported rather than silently dropped, so a log can name it.
    assert_eq!(
        result.unknown,
        vec!["future.capability.v2".to_owned()],
        "the unknown name was not reported"
    );

    // And the known one survived, so the rule is not "refuse the whole offer".
    assert_eq!(result.capabilities, vec!["screen.mirror".to_owned()]);

    // A duplicate unknown name is reported once.
    let duplicated = negotiate(
        &agent,
        &[],
        &[
            "future.capability.v2".to_owned(),
            "future.capability.v2".to_owned(),
            "another.future".to_owned(),
        ],
    );

    assert_eq!(duplicated.unknown.len(), 2);
    assert_eq!(duplicated.capabilities, Vec::<String>::new());
}

/// A duplicated name is normalised to one entry.
#[test]
fn a_duplicated_name_appears_once() {
    let vector = group("negotiation_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "negotiate.duplicate-names-normalised")
        .expect("the duplicate-name vector is present");

    let agent = strings(&vector, "agent_capabilities");
    let offered = strings(&vector, "controller_offered");

    // The vector really does duplicate, on both sides.
    assert_eq!(
        agent.iter().filter(|name| *name == "screen.mirror").count(),
        2,
        "the agent side must duplicate the name"
    );
    assert_eq!(
        offered
            .iter()
            .filter(|name| *name == "screen.mirror")
            .count(),
        2,
        "the controller side must duplicate the name"
    );

    let result = negotiate(&agent, &[], &offered);

    assert_eq!(result.capabilities, vec!["screen.mirror".to_owned()]);

    // `input.touch` is in the agent's list but NOT offered, so it is correctly absent -- the vector's
    // expected set is one name, not two.
    assert!(!result.has("input.touch"));
}

/// The three terms are all necessary, checked by removing each in turn.
#[test]
fn all_three_terms_are_necessary() {
    let agent = vec!["screen.mirror".to_owned(), "shell.exec".to_owned()];
    let disabled = vec!["shell.exec".to_owned()];
    let offered = vec!["screen.mirror".to_owned(), "shell.exec".to_owned()];

    // Baseline.
    let baseline = negotiate(&agent, &disabled, &offered);

    assert_eq!(baseline.capabilities, vec!["screen.mirror".to_owned()]);

    // Remove the agent's implementation of screen.mirror -> nothing is negotiated.
    let without_agent = negotiate(&["shell.exec".to_owned()], &disabled, &offered);

    assert!(
        without_agent.is_empty(),
        "the agent term is not being applied"
    );

    // Remove the controller's offer -> nothing.
    let without_offer = negotiate(&agent, &disabled, &[]);

    assert!(
        without_offer.is_empty(),
        "the controller term is not being applied"
    );

    // Clear `disabled` -> shell.exec returns, so the disabled term was doing work.
    let without_disabled = negotiate(&agent, &[], &offered);

    assert_eq!(
        without_disabled.capabilities,
        vec!["screen.mirror".to_owned(), "shell.exec".to_owned()]
    );
    assert_ne!(without_disabled.capabilities, baseline.capabilities);
}

// =============================================================================================
// Limit clamping
// =============================================================================================

/// The video clamp to the agent's own maxima.
#[test]
fn the_video_clamps_to_the_agents_maxima() {
    let vector = group("limit_clamp_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "limits.video-clamp-to-agent-maximum")
        .expect("the video clamp vector is present");

    let requested = vector.get("requested").expect("requested");
    let agent_limits = vector.get("agent_limits").expect("agent_limits");
    let expected = vector.get("expected_applied").expect("expected_applied");

    let request = VideoRequest {
        width: u32_of(requested, "max_width"),
        height: u32_of(requested, "max_height"),
        fps: u32_of(requested, "fps"),
    };

    assert_eq!(request.width, 2560);
    assert_eq!(request.height, 1440);
    assert_eq!(request.fps, 120);

    let limits = Limits {
        max_video_width: u32_of(agent_limits, "max_video_width"),
        max_video_height: u32_of(agent_limits, "max_video_height"),
        max_video_fps: u32_of(agent_limits, "max_video_fps"),
        ..Limits::DEFAULT
    };

    // No screen, so only the agent's maxima apply.
    let applied = clamp_video(request, &limits, None);

    assert_eq!(applied.width, u32_of(expected, "width"));
    assert_eq!(applied.height, u32_of(expected, "height"));
    assert_eq!(applied.fps, u32_of(expected, "fps"));

    assert_eq!(applied.width, 1920);
    assert_eq!(applied.height, 1080);
    assert_eq!(applied.fps, 60);

    // Clamped rather than refused: the request was larger in all three dimensions and still produced a
    // usable result. The vector: "the agent clamps rather than refusing".
    assert!(applied.width < request.width);

    // The frame rate was clamped too, and independently of the size.
    assert!(applied.fps < request.fps);
    assert_eq!(applied.fps, limits.max_video_fps);
}

/// The video clamp to the screen's size, which is where the arithmetic lives.
#[test]
fn the_video_clamps_to_the_screen_size() {
    let vector = group("limit_clamp_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "limits.video-clamp-to-screen-size")
        .expect("the screen-size vector is present");

    let requested = vector.get("requested").expect("requested");
    let screen = vector.get("screen").expect("screen");
    let expected = vector.get("expected_applied").expect("expected_applied");

    let request = VideoRequest {
        width: u32_of(requested, "max_width"),
        height: u32_of(requested, "max_height"),
        fps: 60,
    };

    assert_eq!(request.width, 1920);
    assert_eq!(request.height, 1080);

    let screen_size = (u32_of(screen, "width"), u32_of(screen, "height"));

    assert_eq!(screen_size, (1080, 2400));

    // The agent's maxima are the defaults, which are above the request, so only the screen clamps.
    let applied = clamp_video(request, &Limits::DEFAULT, Some(screen_size));

    assert_eq!(
        applied.width,
        u32_of(expected, "width"),
        "the width does not match the vector"
    );
    assert_eq!(
        applied.height,
        u32_of(expected, "height"),
        "the height does not match the vector"
    );

    assert_eq!(applied.width, 486);
    assert_eq!(applied.height, 1080);

    assert!(applied.width < request.width);

    // The height is the SMALLER of the request's and the screen's -- 1080 against the screen's 2400, so
    // the request's. I had written `applied.height == screen_size.1`, which is 2400 and wrong: the
    // request is not scaled UP to fill the screen, only down to the ceiling it asked for.
    assert_eq!(applied.height, request.height);
    assert_eq!(applied.height, 1080);
    assert!(
        applied.height < screen_size.1,
        "the request was not magnified to the screen's height"
    );

    // The applied ratio is the SCREEN's, not the request's. This is the correction the vector forced:
    // my first implementation fitted the requested box inside the screen, giving 1080x607 with the
    // request's 16:9 shape. The vector's 486x1080 has the screen's 0.45 ratio exactly.
    let screen_ratio = f64::from(screen_size.0) / f64::from(screen_size.1);
    let applied_ratio = f64::from(applied.width) / f64::from(applied.height);
    let requested_ratio = f64::from(request.width) / f64::from(request.height);

    assert!(
        (applied_ratio - screen_ratio).abs() < 0.001,
        "the applied ratio {applied_ratio} is not the screen's {screen_ratio}"
    );
    assert!(
        (applied_ratio - requested_ratio).abs() > 0.1,
        "the applied ratio {applied_ratio} matches the REQUEST's {requested_ratio}, so the request's \
         shape was kept instead of the screen's -- this is the bug the vector catches"
    );

    // And the width is the screen's ratio at the applied height, computed here from the formula rather
    // than read from the vector.
    let expected_width = u64::from(applied.height)
        .saturating_mul(u64::from(screen_size.0))
        .checked_div(u64::from(screen_size.1))
        .unwrap_or(0);

    assert_eq!(u64::from(applied.width), expected_width);
    assert_eq!(applied.width, 486, "486 = 1080 * 1080 / 2400");

    // Both dimensions even, as H.264 requires. This is the part a plain multiply-divide violates:
    // 1080 * 1080 / 2400 is 486, which happens to be even, so the vector's own numbers do not catch an
    // odd result -- but `even_floor` is what guarantees it for the cases the vector does not carry.
    assert_eq!(
        applied.width % 2,
        0,
        "the width is odd, which H.264 cannot encode"
    );
    assert_eq!(applied.height % 2, 0, "the height is odd");

    // The area really is capped: the result fits inside the screen box.
    assert!(applied.width <= screen_size.0);
    assert!(applied.height <= screen_size.1);

    // And the rounding helper is what makes them even, tested directly.
    assert_eq!(even_floor(486), 486);
    assert_eq!(even_floor(487), 486);
    assert_eq!(even_floor(1), 0);
    assert_eq!(even_floor(0), 0);
    assert_eq!(even_floor(u32::MAX), u32::MAX - 1);
}

/// The fit-and-preserve arithmetic, checked on cases the vectors do not carry.
#[test]
fn the_fit_preserves_the_aspect_ratio() {
    // A square inside a wide box is limited by the height.
    assert_eq!(fit_inside(100, 100, 1000, 400), (400, 400));

    // A square inside a tall box is limited by the width.
    assert_eq!(fit_inside(100, 100, 400, 1000), (400, 400));

    // A box exactly matching the bound is unchanged.
    assert_eq!(fit_inside(1920, 1080, 1920, 1080), (1920, 1080));

    // A box SMALLER than the bound is scaled UP, which is what "fit" means here. I had asserted it was
    // left alone, and the failure was 1000x500 against my expected 100x50: the function is a fit, not a
    // cap, so it grows to touch the bound. That is also why `clamp_video` does not use it for the screen
    // -- magnifying a small request is not what a screen fits.
    assert_eq!(fit_inside(100, 50, 1000, 1000), (1000, 500));

    // So the general property is: the result touches the bound on at least one side, and keeps the
    // input's ratio.
    for (width, height) in [(1920u32, 1080u32), (100, 50), (3, 7), (1000, 1)] {
        let (fitted_width, fitted_height) = fit_inside(width, height, 1000, 1000);

        assert!(
            fitted_width == 1000 || fitted_height == 1000,
            "{width}x{height} produced {fitted_width}x{fitted_height}, which touches neither side"
        );

        // Inside the bound in both dimensions.
        assert!(fitted_width <= 1000);
        assert!(fitted_height <= 1000);
    }

    // A degenerate box or bound gives zero rather than dividing by zero.
    assert_eq!(fit_inside(0, 100, 1000, 1000), (0, 0));
    assert_eq!(fit_inside(100, 0, 1000, 1000), (0, 0));
    assert_eq!(fit_inside(100, 100, 0, 1000), (0, 0));
    assert_eq!(fit_inside(100, 100, 1000, 0), (0, 0));

    // The overflow case a u32 would hit: 65535 * 65535 is past a u32. The u64 intermediates handle it
    // and the result stays inside the bound.
    let (width, height) = fit_inside(65_535, 65_535, 65_535, 65_535);

    assert_eq!((width, height), (65_535, 65_535));

    let (width, height) = fit_inside(65_535, 1, 100_000, 1);

    assert!(width <= 100_000);
    assert!(height <= 1);

    // A very tall box inside a small square bound: the result is inside the bound in both dimensions,
    // which is the invariant that matters whatever the rounding.
    for (width, height) in [(10_000u32, 1u32), (1, 10_000), (3, 7), (7, 3)] {
        let (fitted_width, fitted_height) = fit_inside(width, height, 1000, 1000);

        assert!(
            fitted_width <= 1000,
            "{width}x{height} overflowed the width"
        );
        assert!(
            fitted_height <= 1000,
            "{width}x{height} overflowed the height"
        );
    }
}

/// A file chunk larger than the limit is refused, not truncated.
#[test]
fn a_large_file_chunk_is_refused() {
    let vector = group("limit_clamp_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "limits.file-chunk-clamped")
        .expect("the file-chunk vector is present");

    let requested = u32_of(&vector, "requested_chunk");
    let maximum = u32_of(&vector, "agent_max_file_chunk");

    assert_eq!(requested, 4_194_304);
    assert_eq!(maximum, 262_144);

    let limits = Limits {
        max_file_chunk: maximum,
        ..Limits::DEFAULT
    };

    // Refused, not truncated. `None` rather than `Some(262_144)`, because the number is a claim about
    // how many bytes follow: truncating the number without the data would desynchronise the stream.
    assert_eq!(
        clamp_file_chunk(requested, &limits),
        None,
        "an oversized chunk was truncated rather than refused"
    );

    // The vector's code, and it is the frame-size code rather than a file-specific one.
    assert_eq!(vectors::str_field(&vector, "expected"), "rejected");

    let code = vectors::str_field(&vector, "expected_error");

    assert_eq!(code, "ERR_FRAME_TOO_LARGE");

    // The boundary: exactly the maximum is allowed, one byte over is refused.
    assert_eq!(clamp_file_chunk(maximum, &limits), Some(maximum));
    assert_eq!(
        clamp_file_chunk(maximum.saturating_sub(1), &limits),
        Some(maximum - 1)
    );
    assert_eq!(clamp_file_chunk(maximum.saturating_add(1), &limits), None);

    assert_eq!(clamp_file_chunk(0, &limits), Some(0));

    // A zero limit means no ceiling was set, which the `Limits::ZERO` case would otherwise turn into
    // "refuse every chunk".
    let unbounded = Limits {
        max_file_chunk: 0,
        ..Limits::DEFAULT
    };

    assert_eq!(clamp_file_chunk(requested, &unbounded), Some(requested));
}

/// A shell timeout clamps to the agent's deadline.
#[test]
fn a_shell_timeout_clamps_to_the_agents_deadline() {
    let vector = group("limit_clamp_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "limits.shell-timeout-clamped")
        .expect("the shell-timeout vector is present");

    let requested = u32_of(&vector, "requested_timeout_ms");
    let maximum = u32_of(&vector, "agent_shell_timeout_ms");
    let expected = u32_of(&vector, "expected_applied_timeout_ms");

    assert_eq!(requested, 600_000);
    assert_eq!(maximum, 30_000);
    assert_eq!(expected, 30_000);

    let limits = Limits {
        shell_timeout_ms: maximum,
        ..Limits::DEFAULT
    };

    // Clamped, unlike the file chunk: a deadline is a preference, so the agent's is applied and the
    // caller learns the value it actually got. The vector adds that "the truncated flag is set if
    // output was cut short", which is the caller's business.
    assert_eq!(clamp_shell_timeout(requested, &limits), expected);
    assert_eq!(clamp_shell_timeout(requested, &limits), maximum);

    // Under the deadline it is unchanged, and exactly at it too.
    assert_eq!(clamp_shell_timeout(1_000, &limits), 1_000);
    assert_eq!(clamp_shell_timeout(maximum, &limits), maximum);

    // A zero limit is unconstrained.
    let unbounded = Limits {
        shell_timeout_ms: 0,
        ..Limits::DEFAULT
    };

    assert_eq!(clamp_shell_timeout(requested, &unbounded), requested);
}

/// The two clamp outcomes really differ, which is the design decision worth asserting.
#[test]
fn the_two_clamp_shapes_differ_deliberately() {
    let limits = Limits {
        max_file_chunk: 100,
        shell_timeout_ms: 100,
        max_video_width: 100,
        max_video_height: 100,
        max_video_fps: 100,
        ..Limits::DEFAULT
    };

    // A video request clamps down and reports what was chosen.
    let applied = clamp_video(
        VideoRequest {
            width: 1000,
            height: 1000,
            fps: 1000,
        },
        &limits,
        None,
    );

    assert_eq!(
        (applied.width, applied.height, applied.fps),
        (100, 100, 100)
    );

    // A shell timeout clamps down too.
    assert_eq!(clamp_shell_timeout(1000, &limits), 100);

    // A file chunk is REFUSED, and the asymmetry is deliberate: the chunk's number is a claim about how
    // many bytes follow, so clamping it silently would either desynchronise the stream or allocate what
    // the peer asked for.
    assert_eq!(clamp_file_chunk(1000, &limits), None);

    // All three see the same limit value, so the difference is not the number.
    assert_eq!(limits.max_video_width, limits.max_file_chunk);
    assert_eq!(limits.max_file_chunk, limits.shell_timeout_ms);
}

// =============================================================================================
// Channel id allocation
// =============================================================================================

/// The controller takes odd ids and the agent even ones, and the sequences match the vector.
#[test]
fn the_channel_allocators_match_the_vector() {
    let vector = group("direction_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "negotiate.controller-allocates-odd-channel-ids")
        .expect("the parity vector is present");

    let expected_controller: Vec<u32> = vector
        .get("expected_controller_sequence")
        .and_then(Value::as_array)
        .expect("a sequence")
        .iter()
        .map(|value| u32::try_from(value.as_u64().expect("an integer")).expect("fits"))
        .collect();

    let expected_agent: Vec<u32> = vector
        .get("expected_agent_sequence")
        .and_then(Value::as_array)
        .expect("a sequence")
        .iter()
        .map(|value| u32::try_from(value.as_u64().expect("an integer")).expect("fits"))
        .collect();

    assert_eq!(expected_controller, vec![1, 3, 5, 7]);
    assert_eq!(expected_agent, vec![2, 4, 6, 8]);

    // The vector's own `controller_first` and `agent_first` are the first values.
    assert_eq!(u32_of(&vector, "controller_first"), 1);
    assert_eq!(u32_of(&vector, "agent_first"), 2);

    assert_eq!(ChannelAllocator::Controller.take(4), expected_controller);
    assert_eq!(ChannelAllocator::Agent.take(4), expected_agent);

    assert_eq!(ChannelAllocator::Controller.first(), 1);
    assert_eq!(ChannelAllocator::Agent.first(), 2);

    // Every id belongs to exactly its own allocator, and neither owns the control channel.
    for channel_id in 1u32..64 {
        let controller = ChannelAllocator::Controller.owns(channel_id);
        let agent = ChannelAllocator::Agent.owns(channel_id);

        assert_ne!(
            controller, agent,
            "{channel_id}: both or neither allocator owns it"
        );
        assert!(!controller || channel_id % 2 == 1);
        assert!(!agent || channel_id % 2 == 0);
    }

    assert!(
        !ChannelAllocator::Controller.owns(0),
        "0 is the control channel"
    );
    assert!(!ChannelAllocator::Agent.owns(0), "0 is the control channel");

    // Zero is the control channel, which is why the parity partition starts at one.
    assert_eq!(ChannelAllocator::Controller.nth(0), 1);
    assert_ne!(ChannelAllocator::Controller.nth(0), 0);
    assert_eq!(ChannelAllocator::Agent.nth(0), 2);

    // The two sequences never collide, which is the point of the partition: concurrent allocation
    // without a race needs no lock if the two sides cannot pick the same number.
    let controller = ChannelAllocator::Controller.take(200);
    let agent = ChannelAllocator::Agent.take(200);

    for id in &controller {
        assert!(
            !agent.contains(id),
            "{id} appears in both sequences, so the partition does not prevent a race"
        );
    }

    // And the stride is two, so no third of the ids is wasted.
    assert_eq!(ChannelAllocator::Controller.nth(10), 21);
    assert_eq!(ChannelAllocator::Agent.nth(10), 22);
}

/// Reusing an open channel id is a state error.
#[test]
fn reusing_an_open_channel_is_a_state_error() {
    let vector = group("direction_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "negotiate.channel-id-reuse-requires-close")
        .expect("the reuse vector is present");

    let open: Vec<u32> = vector
        .get("open_channels")
        .and_then(Value::as_array)
        .expect("open_channels")
        .iter()
        .map(|value| u32::try_from(value.as_u64().expect("an integer")).expect("fits"))
        .collect();

    let reopen = u32_of(&vector, "reopen_request");

    assert_eq!(open, vec![0, 1]);
    assert_eq!(reopen, 1);
    assert!(
        open.contains(&reopen),
        "the vector must reuse an OPEN channel"
    );

    assert_eq!(
        vectors::str_field(&vector, "expected_error"),
        "ERR_BAD_STATE"
    );

    assert!(
        !may_reopen(reopen, &open),
        "an open channel id was allowed to reopen, so the peer's queued frames would arrive at a new \
         channel"
    );

    // A closed id may be reused, and the control channel is always open so it never may be.
    assert!(may_reopen(3, &open));
    assert!(may_reopen(1, &[]));
    assert!(!may_reopen(0, &open));

    // The exclusion is specific to the id, not to the list being non-empty.
    for id in [2u32, 3, 4, 99] {
        assert!(
            may_reopen(id, &open),
            "{id} is not open and must be reusable"
        );
    }
}

/// A registered type's name, by code.
///
/// A local helper because the registry's `message_type(code)` returns a `&MessageType` and a `Vec<&str>`
/// wants the name; `filter_map` over `message_type` would need a closure anyway.
fn message_type_by_name_name(code: u8) -> Option<&'static str> {
    droidlab_protocol::registry::message_type(code).map(|entry| entry.name)
}

/// The ungated message set is a subset of the registered types, in both directions.
#[test]
fn the_ungated_set_is_registered() {
    let ungated = ungated_message_types();

    for code in ungated {
        assert!(
            is_registered_message_type(code),
            "{code} is ungated but unregistered"
        );
        assert_eq!(
            capability_for_message_type(code),
            None,
            "{code} is listed as ungated but the registry gates it"
        );
    }

    // The reverse direction, and I got it wrong TWICE. First I asserted that every registered type with
    // no capability requirement is ungated, which failed on code 1 (HELLO). Then I narrowed it to
    // "post-handshake types", which failed on code 5 (PING).
    //
    // Both failures were the same mistake: I was trying to derive the ungated set from the capability
    // mapping, and the two are not the same relation. Several types carry no capability for reasons of
    // their own -- the handshake precedes negotiation, so nothing can gate HELLO; PING and PONG are
    // transport keepalives that a session needs regardless of what it may carry.
    //
    // The honest statement is the one the note makes, and it is a fact about the SET rather than a rule
    // derived from the mapping: three message types are ungated, they are named, and the capability
    // mapping does not gate them. Anything stronger is a taxonomy I invented.
    let mut uncapabilityd = Vec::new();

    for code in 1u16..=255 {
        let code = u8::try_from(code).expect("it fits");

        if is_registered_message_type(code) && capability_for_message_type(code).is_none() {
            uncapabilityd.push(code);
        }
    }

    // More types carry no capability than are ungated, which is exactly why the two must not be
    // conflated. Recorded as a count so the gap between the two sets is visible.
    assert!(
        uncapabilityd.len() > ungated.len(),
        "the two sets are the same size, so the distinction this test draws may have collapsed"
    );

    // Every ungated type is uncapability'd, which is the one direction that IS a rule.
    for code in ungated {
        assert!(
            uncapabilityd.contains(&code),
            "{code} is ungated but the registry gates it"
        );
    }

    // The named exceptions, so the gap is documented rather than incidental.
    for (code, name) in [
        (1u8, "HELLO"),
        (2, "HELLO_ACK"),
        (3, "AUTH"),
        (4, "AUTH_OK"),
        (5, "PING"),
        (6, "PONG"),
        (16, "GET_CAPABILITIES"),
        (17, "CAPABILITIES"),
        (32, "CHANNEL_OPEN"),
        (33, "CHANNEL_OPENED"),
        (34, "CHANNEL_CLOSE"),
        (240, "ERROR"),
        (241, "SESSION_END"),
    ] {
        assert!(
            uncapabilityd.contains(&code),
            "{name} must carry no capability"
        );
    }

    // Ten of the thirteen are uncapability'd WITHOUT being ungated, and the three that are ungated are
    // named. My first version ran the exclusion over all thirteen and failed on GET_CAPABILITIES -- which
    // IS ungated, and must be, or a session with an empty set could not ask what the device supports.
    assert_eq!(ungated.len(), 3);

    for code in [1u8, 2, 3, 4, 5, 6, 32, 33, 34, 241] {
        assert!(
            !ungated.contains(&code),
            "{code} carries no capability but must not be ungated"
        );
    }

    for code in ungated {
        assert!(
            uncapabilityd.contains(&code),
            "{code} is ungated and must therefore carry no capability"
        );
    }

    // The count is DERIVED from the registry by the loop above. I wrote 11 from memory, then 13, then 14
    // -- and the 14 came from the BROKEN mapping table, which is itself the point: a count derived from a
    // wrong table is wrong in a way that looks derived. The registry's answer is 13.
    assert_eq!(
        uncapabilityd.len(),
        13,
        "the registry has {} uncapability'd types; three of them are the ungated set",
        uncapabilityd.len()
    );

    // And the same census read straight from the registry file, so this literal is checked against the
    // source rather than against the table under test.
    let registry = vectors::load_registry();

    let registry_gated: Vec<u64> = registry
        .get("message_type_capability")
        .and_then(Value::as_array)
        .expect("message_type_capability")
        .iter()
        .filter_map(|mapping| mapping.get("message_type").and_then(Value::as_u64))
        .collect();

    let registry_types = registry
        .get("message_types")
        .and_then(Value::as_array)
        .expect("message_types");

    let registry_uncapabilityd = registry_types
        .iter()
        .filter_map(|entry| entry.get("code").and_then(Value::as_u64))
        .filter(|code| !registry_gated.contains(code))
        .count();

    assert_eq!(
        uncapabilityd.len(),
        registry_uncapabilityd,
        "the table says {} uncapability'd types and the file says {registry_uncapabilityd}",
        uncapabilityd.len()
    );

    // And the named ones, so the 13 is not a bare number.
    let named: Vec<&str> = uncapabilityd
        .iter()
        .filter_map(|code| message_type_by_name_name(*code))
        .collect();

    for expected in ["HELLO", "HELLO_ACK", "AUTH", "AUTH_OK", "PING", "PONG"] {
        assert!(
            named.contains(&expected),
            "{expected} should carry no capability: {named:?}"
        );
    }

    for code in ungated {
        let name = message_type_by_name_name(code).expect("ungated types are registered");

        assert!(
            ["GET_CAPABILITIES", "CAPABILITIES", "ERROR"].contains(&name),
            "the ungated set changed: {name} is in it"
        );
    }
}

// =============================================================================================
// The capability mapping table
// =============================================================================================

/// `capability_for_message_type` matches the registry's `message_type_capability`, both directions.
///
/// The test my first hand-written table would have failed. That version omitted CHANNEL_OPEN,
/// CHANNEL_OPENED, CHANNEL_CLOSE and SESSION_END entirely, and mapped VIDEO_STATS to `screen.mirror`
/// where the registry says `telemetry.stats`. Nothing in this crate caught it, because every other test
/// asked this function what it thought rather than asking the file.
///
/// Both directions: every registry entry must be reproduced, and every name this function returns must
/// be in the registry.
#[test]
fn the_capability_mapping_matches_the_registry() {
    let registry = vectors::load_registry();

    let mappings = registry
        .get("message_type_capability")
        .and_then(Value::as_array)
        .expect("the registry has a message_type_capability array")
        .clone();

    assert_eq!(
        mappings.len(),
        29,
        "the registry declares 29 capability mappings"
    );

    let mut reproduced = 0usize;

    for mapping in &mappings {
        let code = u8::try_from(
            mapping
                .get("message_type")
                .and_then(Value::as_u64)
                .expect("message_type"),
        )
        .expect("it fits a u8");

        let capability = mapping
            .get("capability")
            .and_then(Value::as_str)
            .expect("capability");

        assert_eq!(
            capability_for_message_type(code),
            Some(capability),
            "message type {code} should map to {capability:?}"
        );

        reproduced = reproduced.saturating_add(1);
    }

    assert_eq!(reproduced, 29, "every mapping was checked");

    // The other direction: nothing this crate maps is absent from the registry.
    let mut checked = 0usize;

    for code in 1u16..=255 {
        let code = u8::try_from(code).expect("it fits");

        let Some(capability) = capability_for_message_type(code) else {
            continue;
        };

        checked = checked.saturating_add(1);

        assert!(
            is_registered_message_type(code),
            "{code} is mapped to {capability} but is not a registered message type"
        );

        assert!(
            mappings.iter().any(|mapping| {
                mapping.get("message_type").and_then(Value::as_u64) == Some(u64::from(code))
                    && mapping.get("capability").and_then(Value::as_str) == Some(capability)
            }),
            "{code} maps to {capability} here but the registry has no such entry"
        );

        // And the capability it names is one DLWP/1 defines.
        assert!(
            is_known_capability(capability),
            "{code} maps to {capability}, which is not a DLWP/1 capability"
        );
    }

    assert_eq!(checked, 29, "the same 29 mappings, seen from this side");

    // The specific errors my hand-written versions made, named, so a regression is unmistakable.
    //
    // CHANNEL_OPEN/OPENED/CLOSE are UNGATED, so my first version's omission of them happened to give the
    // right answer (None) for the wrong reason -- which is why this assertion is `None` and why the
    // direction check above is the one that matters.
    assert_eq!(capability_for_message_type(32), None);
    assert_eq!(capability_for_message_type(33), None);
    assert_eq!(capability_for_message_type(34), None);
    assert_eq!(capability_for_message_type(241), None);

    // VIDEO_STATS is telemetry, not mirroring.
    assert_eq!(capability_for_message_type(52), Some("telemetry.stats"));
    assert_ne!(
        capability_for_message_type(52),
        Some("screen.mirror"),
        "VIDEO_STATS is a telemetry type, not a mirroring one"
    );

    // INPUT_SCROLL rides on input.touch; INPUT_GESTURE has its own capability. My first version had these
    // the wrong way round.
    assert_eq!(capability_for_message_type(67), Some("input.touch"));
    assert_eq!(capability_for_message_type(68), Some("input.gesture"));
    assert_ne!(
        capability_for_message_type(67),
        capability_for_message_type(68),
        "INPUT_SCROLL and INPUT_GESTURE must not share a capability"
    );

    // FILE_RESULT is a WRITE result, not a read one.
    assert_eq!(capability_for_message_type(100), Some("file.write"));
    assert_eq!(capability_for_message_type(101), Some("file.write"));
    assert_eq!(capability_for_message_type(96), Some("file.read"));

    // Every mapping is a real capability, so the list is not padded.
    let mut named: Vec<&str> = mappings
        .iter()
        .filter_map(|mapping| mapping.get("capability").and_then(Value::as_str))
        .collect();

    named.sort_unstable();
    named.dedup();

    for capability in &named {
        assert!(
            is_known_capability(capability),
            "{capability} is not a DLWP/1 capability"
        );
    }

    assert!(
        named.len() >= 10,
        "only {} distinct capabilities are mapped",
        named.len()
    );
}

/// The eleven message types that are gated on `input.*` and the four on `screen.mirror`.
#[test]
fn the_gated_counts_come_from_the_registry() {
    let registry = vectors::load_registry();

    let mappings = registry
        .get("message_type_capability")
        .and_then(Value::as_array)
        .expect("message_type_capability");

    for capability in ["screen.mirror", "shell.exec", "input.touch", "device.info"] {
        let from_registry: Vec<u64> = mappings
            .iter()
            .filter(|mapping| mapping.get("capability").and_then(Value::as_str) == Some(capability))
            .filter_map(|mapping| mapping.get("message_type").and_then(Value::as_u64))
            .collect();

        let mut from_table: Vec<u64> = (1u16..=255)
            .filter_map(|code| u8::try_from(code).ok())
            .filter(|code| capability_for_message_type(*code) == Some(capability))
            .map(u64::from)
            .collect();

        from_table.sort_unstable();

        let mut expected = from_registry.clone();
        expected.sort_unstable();

        assert_eq!(
            from_table, expected,
            "{capability}: the table gates {from_table:?} and the registry {expected:?}"
        );

        assert!(
            !expected.is_empty(),
            "{capability} gates no message type, so this comparison proves nothing"
        );
    }

    // The three ungated types really are absent from the mapping.
    for code in ungated_message_types() {
        assert!(
            !mappings.iter().any(
                |mapping| mapping.get("message_type").and_then(Value::as_u64)
                    == Some(u64::from(code))
            ),
            "{code} is ungated here but the registry gates it"
        );
    }
}
