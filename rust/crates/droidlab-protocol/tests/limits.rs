//! Conformance tests for [`Limits`] against the registry's `default_limits`.
//!
//! The registry is normative and `Limits::DEFAULT` is a mirror, so this is the test that keeps the
//! mirror honest. It reads every field by name rather than comparing a serialised blob, so a renamed
//! or added limit fails with the field's name in the message.

use droidlab_protocol::Limits;

use serde_json::Value;
use std::path::PathBuf;

/// Loads `protocol/registry/dlwp-1.json`.
fn registry() -> Value {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // crates/droidlab-protocol -> crates -> rust -> <repo root>
    let root = manifest
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("crate manifest directory has no grandparent: {manifest:?}"));

    let path = root.join("protocol").join("registry").join("dlwp-1.json");

    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// The registry's `default_limits` object.
fn default_limits() -> Value {
    let document = registry();

    document
        .get("default_limits")
        .cloned()
        .unwrap_or_else(|| panic!("dlwp-1.json has no `default_limits` object"))
}

/// A named limit from the registry, as `u64`.
fn registry_limit(name: &str) -> u64 {
    default_limits()
        .get(name)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("default_limits has no unsigned `{name}`"))
}

/// Every field of `Limits::DEFAULT` matches the registry's `default_limits`.
///
/// The check that makes the mirror safe. A limit that exists in the registry and not here is a
/// limit the two peers would silently use different values for.
///
/// The field-by-field comparison is in `every_registry_limit_is_mirrored`, which drives a table so a
/// new field cannot be forgotten.
#[test]
fn the_registry_declares_limits_this_crate_mirrors() {
    let object = default_limits();
    let object = object.as_object().expect("default_limits is an object");

    assert!(
        !object.is_empty(),
        "the registry declares no limits, so the mirror cannot be checked"
    );
}

/// The field-by-field comparison, asserted through a table so a new field cannot be forgotten.
#[test]
fn every_registry_limit_is_mirrored() {
    let limits = Limits::DEFAULT;
    let registry = default_limits();
    let object = registry.as_object().expect("default_limits is an object");

    // Every registry key, mapped to the field it should equal.
    let expected: [(&str, u64); 9] = [
        ("max_frame_bytes", limits.max_frame_bytes),
        ("max_channels", u64::from(limits.max_channels)),
        ("max_video_width", u64::from(limits.max_video_width)),
        ("max_video_height", u64::from(limits.max_video_height)),
        ("max_video_fps", u64::from(limits.max_video_fps)),
        ("max_video_bitrate", u64::from(limits.max_video_bitrate)),
        ("max_file_chunk", u64::from(limits.max_file_chunk)),
        ("shell_timeout_ms", u64::from(limits.shell_timeout_ms)),
        ("max_gesture_steps", u64::from(limits.max_gesture_steps)),
    ];

    // The registry must not have gained a limit this struct does not carry.
    assert_eq!(
        object.len(),
        expected.len(),
        "the registry declares {} limits and this struct carries {}; registry keys are {:?}",
        object.len(),
        expected.len(),
        {
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            keys
        }
    );

    for (name, actual) in expected {
        assert_eq!(
            registry_limit(name),
            actual,
            "default_limits.{name} is {} but Limits::DEFAULT has {actual}",
            registry_limit(name)
        );
    }
}

/// The registry limit values are the ones this crate was written against.
///
/// Listed individually as well as by iteration, because a wholesale change to the registry that this
/// struct also picked up would pass the comparison above while silently changing the protocol.
#[test]
fn the_known_limit_values_are_unchanged() {
    let limits = Limits::DEFAULT;

    assert_eq!(limits.max_frame_bytes, 16_777_216, "16 MiB");
    assert_eq!(limits.max_channels, 8);
    assert_eq!(limits.max_video_width, 1920);
    assert_eq!(limits.max_video_height, 1080);
    assert_eq!(limits.max_video_fps, 60);
    assert_eq!(limits.max_video_bitrate, 16_000_000);
    assert_eq!(limits.max_file_chunk, 262_144, "256 KiB");
    assert_eq!(limits.shell_timeout_ms, 30_000);
    assert_eq!(limits.max_gesture_steps, 256);

    // And the registry agrees, so a change to one without the other fails.
    assert_eq!(registry_limit("max_frame_bytes"), limits.max_frame_bytes);
    assert_eq!(
        registry_limit("max_channels"),
        u64::from(limits.max_channels)
    );
    assert_eq!(
        registry_limit("max_file_chunk"),
        u64::from(limits.max_file_chunk)
    );
}

/// A frame at the limit is permitted and one byte over is not.
///
/// The boundary is inclusive: `max_frame_bytes` is the largest size that **is** allowed, not the
/// first size that is not. An off-by-one here is the difference between a peer sending a frame at
/// exactly its ceiling and having it refused.
#[test]
fn the_frame_size_limit_is_inclusive() {
    let limits = Limits::DEFAULT;

    assert!(
        limits.permits_frame_of(0),
        "an empty frame is within any limit"
    );
    assert!(limits.permits_frame_of(24), "a bare header is fine");
    assert!(
        limits.permits_frame_of(limits.max_frame_bytes),
        "a frame exactly at the limit is permitted"
    );
    assert!(
        !limits.permits_frame_of(limits.max_frame_bytes.saturating_add(1)),
        "one byte over is refused"
    );
    assert!(
        !limits.permits_frame_of(u64::MAX),
        "and an absurd size is refused without arithmetic wrapping"
    );

    // The `usize` accessor agrees with the `u64` one.
    assert_eq!(
        limits.max_frame_bytes_usize() as u64,
        limits.max_frame_bytes,
        "the usize view matches the u64 field"
    );
    assert!(
        limits.max_frame_bytes_usize() >= 24,
        "a limit below a header would refuse everything"
    );
}

/// `max_channels` counts the control channel, so 8 permits 7 data channels.
///
/// The off-by-one that the field's own documentation warns about. Asserted because the session state
/// machine and the channel allocator both ask, and they must answer the same way.
#[test]
fn max_channels_counts_the_control_channel() {
    let limits = Limits::DEFAULT;

    assert_eq!(limits.max_channels, 8);
    assert_eq!(
        limits.data_channels(),
        7,
        "the control channel is one of the eight"
    );

    // With 7 channels open -- the control channel plus six -- an eighth is still permitted.
    assert!(
        limits.permits_open_channel(7),
        "7 open is below the limit of 8"
    );
    // With 8 open, the limit is reached.
    assert!(!limits.permits_open_channel(8), "8 open reaches the limit");
    assert!(!limits.permits_open_channel(9), "and 9 is beyond it");

    // Zero is open-channel-free, which is the state before the control channel is established.
    assert!(limits.permits_open_channel(0));

    // A misconfigured zero does not wrap.
    let broken = Limits {
        max_channels: 0,
        ..Limits::DEFAULT
    };

    assert_eq!(
        broken.data_channels(),
        0,
        "a zero max_channels yields zero data channels"
    );
    assert!(
        !broken.permits_open_channel(0),
        "and permits no channel at all, including the control channel"
    );
}

/// `intersect` takes the smaller value of every field.
///
/// Negotiation combines an agent's offer with a controller's request by taking the minimum, because
/// a limit either side cannot meet is not a limit both can honour. A `max` here would be the bug
/// that produces a frame one side sends and the other refuses.
#[test]
fn intersect_takes_the_smaller_of_every_field() {
    let base = Limits::DEFAULT;

    let tighter = Limits {
        max_frame_bytes: 1024,
        max_channels: 2,
        max_video_width: 640,
        max_video_height: 480,
        max_video_fps: 30,
        max_video_bitrate: 1_000_000,
        max_file_chunk: 4096,
        shell_timeout_ms: 1000,
        max_gesture_steps: 16,
    };

    let combined = base.intersect(tighter);

    assert_eq!(
        combined, tighter,
        "intersecting with a tighter set gives the tighter set"
    );

    // And it is symmetric, so which side is the offer does not matter.
    assert_eq!(tighter.intersect(base), tighter);

    // Intersecting with the defaults is the identity.
    assert_eq!(base.intersect(base), base);

    // A zero set annihilates, which is what makes `ZERO` a safe starting point: a session that has
    // not negotiated refuses everything rather than silently using the defaults.
    assert_eq!(base.intersect(Limits::ZERO), Limits::ZERO);
    assert_eq!(Limits::ZERO.intersect(base), Limits::ZERO);

    // The zero limits permit exactly one thing: a frame of zero bytes. `permits_frame_of` is
    // `<=`, so a limit of 0 accepts a 0-byte frame -- which is the empty body of a PING and is
    // genuinely within any limit. What the zero set refuses is everything with content, and every
    // channel. My first version of this test asserted the opposite and was wrong: I had written
    // "the zero limits permit no frame" without checking what a zero-length frame is.
    assert!(
        Limits::ZERO.permits_frame_of(0),
        "a zero-byte frame is within any limit"
    );
    assert!(!Limits::ZERO.permits_frame_of(1), "but nothing larger is");
    assert!(
        !Limits::ZERO.permits_open_channel(0),
        "and no channel is permitted at all"
    );

    // A session that has not negotiated cannot carry a real frame, which is the property `ZERO`
    // exists for -- stated in terms of the header rather than of zero.
    assert!(!Limits::ZERO.permits_frame_of(24), "not even a bare header");
}

/// `contains` is true only when every field is at least as permissive.
#[test]
fn contains_compares_every_field() {
    let base = Limits::DEFAULT;

    assert!(base.contains(base), "a set contains itself");
    assert!(base.contains(Limits::ZERO), "and contains the zero set");
    assert!(
        !Limits::ZERO.contains(base),
        "the zero set contains nothing permissive"
    );

    // `contains` means "no more permissive than", so a set with one field LOWER is contained by the
    // base and does NOT contain the base. My first version had this backwards: it built sets with a
    // single field set to 1, called them "stricter" (they are), and then asserted the base does not
    // contain them -- but a lower ceiling IS contained by a higher one. The assertion was inverted,
    // not the implementation.
    for stricter in [
        Limits {
            max_frame_bytes: 1,
            ..base
        },
        Limits {
            max_channels: 1,
            ..base
        },
        Limits {
            max_video_width: 1,
            ..base
        },
        Limits {
            max_video_height: 1,
            ..base
        },
        Limits {
            max_video_fps: 1,
            ..base
        },
        Limits {
            max_video_bitrate: 1,
            ..base
        },
        Limits {
            max_file_chunk: 1,
            ..base
        },
        Limits {
            shell_timeout_ms: 1,
            ..base
        },
        Limits {
            max_gesture_steps: 1,
            ..base
        },
    ] {
        assert!(
            base.contains(stricter),
            "a set with one lower field is contained by the base: {stricter:?}"
        );
        assert!(
            !stricter.contains(base),
            "but it does not contain the base, because that one field is lower"
        );
        assert_eq!(
            stricter.intersect(base),
            stricter,
            "and intersecting with the base leaves it unchanged"
        );
        assert_eq!(base.intersect(stricter), stricter, "in either order");
    }

    // A set with one field HIGHER is not contained by the base, and contains it.
    let roomier = Limits {
        max_frame_bytes: base.max_frame_bytes.saturating_add(1),
        ..base
    };

    assert!(
        !base.contains(roomier),
        "a higher frame limit is not contained"
    );
    assert!(
        roomier.contains(base),
        "but the roomier set contains the base"
    );
}

/// `Default` is the registry defaults, not the zero set.
///
/// A `Default` that returned zero limits would be a trap: `Limits::default()` reads like a usable
/// session, and zero limits refuse every frame.
#[test]
fn default_is_the_registry_defaults() {
    assert_eq!(Limits::default(), Limits::DEFAULT);
    assert_ne!(Limits::default(), Limits::ZERO);
    assert!(Limits::default().permits_frame_of(24));
    assert!(!Limits::ZERO.permits_frame_of(24));
}
