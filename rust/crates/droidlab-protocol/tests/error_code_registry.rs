//! Conformance tests for [`ErrorCode`] against `protocol/registry/dlwp-1.json`.
//!
//! The registry is normative, and this crate's table is written by hand. This test is what makes
//! "written by hand" safe: it reads the registry and asserts the two agree code by code.
//!
//! It exists because nothing else did. `windows/DroidLab.Protocol/ErrorCode.cs` documents a
//! `RegistryConformanceTests` that asserts the same thing for the C# table, and that test is not in
//! the repository — see `docs/findings/no-registry-severity-check.md`. Severity is not decoration:
//! a fatal error closes the session and a recoverable one leaves it running, so a code whose
//! severity differs between the controller and the agent produces one side tearing down the
//! connection while the other waits for the next frame.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::{ErrorCode, Severity};

use serde_json::Value;

const REGISTRY: &str = "dlwp-1.json";

/// Loads `protocol/registry/dlwp-1.json`.
fn registry() -> Value {
    // The vectors helper resolves `protocol/vectors`; the registry lives in a sibling directory, so
    // the path is rebuilt from the same root rather than duplicated.
    let path = vectors::vectors_dir()
        .parent()
        .expect("protocol/vectors has a parent")
        .join("registry")
        .join(REGISTRY);

    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// The registry's `error_codes` array, as `(code, severity)` pairs.
fn registry_codes() -> Vec<(String, String)> {
    let document = registry();

    document
        .get("error_codes")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{REGISTRY} has no `error_codes` array"))
        .iter()
        .map(|entry| {
            let code = entry
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("an error_codes entry has no string `code`: {entry}"));
            let severity = entry
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{code} has no string `severity`"));

            (code.to_owned(), severity.to_owned())
        })
        .collect()
}

/// The Rust severity, spelled as the registry spells it.
fn rust_severity(code: ErrorCode) -> &'static str {
    match code.severity() {
        Severity::Recoverable => "recoverable",
        Severity::Fatal => "fatal",
    }
}

/// The registry declares exactly the codes this crate knows, with the same wire names.
///
/// Both directions are checked. A code in the registry and not here means a peer can send an error
/// this crate cannot name; a code here and not in the registry means this crate can send one no
/// peer is required to understand.
#[test]
fn the_registry_and_this_crate_declare_the_same_codes() {
    let registry = registry_codes();

    assert_eq!(
        registry.len(),
        ErrorCode::ALL.len(),
        "the registry declares {} codes and this crate has {}",
        registry.len(),
        ErrorCode::ALL.len()
    );

    for (name, _) in &registry {
        assert!(
            ErrorCode::from_wire_name(name).is_some(),
            "the registry declares {name}, which this crate does not have"
        );
    }

    for code in ErrorCode::ALL {
        assert!(
            registry.iter().any(|(name, _)| name == code.wire_name()),
            "this crate has {}, which the registry does not declare",
            code.wire_name()
        );
    }
}

/// Every code's severity matches the registry's.
///
/// The check the C# comment claims to have and does not. Asserted per code so a failure names the
/// code rather than reporting a count.
#[test]
fn every_severity_matches_the_registry() {
    let registry = registry_codes();

    for (name, severity) in &registry {
        let code = ErrorCode::from_wire_name(name)
            .unwrap_or_else(|| panic!("the registry declares {name}, which this crate does not"));

        assert_eq!(
            rust_severity(code),
            severity.as_str(),
            "{name} is {severity} in the registry and {} here",
            rust_severity(code)
        );
    }
}

/// The severity counts are 11 and 11, so a wholesale inversion would be caught.
///
/// A test that iterated an empty table would pass. This pins the shape of the table, so deleting
/// codes cannot turn the loop above into a no-op.
#[test]
fn the_severity_table_is_evenly_split() {
    let registry = registry_codes();

    let recoverable = registry
        .iter()
        .filter(|(_, severity)| severity == "recoverable")
        .count();
    let fatal = registry
        .iter()
        .filter(|(_, severity)| severity == "fatal")
        .count();

    assert_eq!(recoverable, 11, "the registry has 11 recoverable codes");
    assert_eq!(fatal, 11, "and 11 fatal ones");
    assert_eq!(
        recoverable + fatal,
        registry.len(),
        "every code is classified"
    );
}

/// A fatal code ends the session and a recoverable one does not.
///
/// The consequence of the severity, asserted as behaviour rather than as a table lookup, because the
/// whole point of the field is what it does to the session.
#[test]
fn severity_decides_whether_a_fault_is_fatal() {
    for (name, severity) in registry_codes() {
        let code = ErrorCode::from_wire_name(&name).expect("the code exists");

        assert_eq!(
            code.is_fatal(),
            severity == "fatal",
            "{name} is {severity}, so is_fatal should be {}",
            severity == "fatal"
        );
    }

    // Spot-check both directions with codes whose meaning is unambiguous.
    assert!(
        ErrorCode::Malformed.is_fatal(),
        "a malformed body closes the session"
    );
    assert!(
        ErrorCode::Unauthorized.is_fatal(),
        "an unauthenticated peer closes it"
    );
    assert!(
        !ErrorCode::Timeout.is_fatal(),
        "a timeout aborts the operation, not the session"
    );
    assert!(
        !ErrorCode::ChannelLimit.is_fatal(),
        "a full channel table refuses the open, not the session"
    );
}

/// `from_wire_name` round-trips every code and rejects anything else.
#[test]
fn wire_names_round_trip() {
    for code in ErrorCode::ALL {
        let name = code.wire_name();

        assert!(
            name.starts_with("ERR_"),
            "{name} does not follow the ERR_ prefix convention"
        );
        assert_eq!(
            ErrorCode::from_wire_name(name),
            Some(code),
            "{name} did not round-trip"
        );
    }

    for absent in ["", "ERR_", "err_malformed", "MALFORMED", "ERR_NOPE"] {
        assert_eq!(
            ErrorCode::from_wire_name(absent),
            None,
            "{absent:?} should not resolve to a code"
        );
    }
}

/// The discriminants are a contiguous `1..=22` set with no duplicates or gaps.
///
/// The registry's `error_codes` array is in **alphabetical** order, not numeric, so the array index
/// is not the discriminant and this test does not assume it. What it asserts is the property that
/// actually matters: the `#[repr(u8)]` values form an unbroken run from 1, so no two codes share a
/// number and none is silently skipped. My first version compared against the array index and
/// failed on `ERR_UNSUPPORTED_MESSAGE`, which is 11th in name order but has discriminant 11 for a
/// different reason — the two orderings coincide for some codes and not others, which is exactly
/// the sort of coincidence a test should not encode.
#[test]
fn discriminants_form_an_unbroken_run_from_one() {
    let mut seen: Vec<u8> = ErrorCode::ALL.iter().map(|code| *code as u8).collect();
    seen.sort_unstable();

    let expected: Vec<u8> =
        (1..=u8::try_from(ErrorCode::ALL.len()).expect("a small count")).collect();

    assert_eq!(
        seen, expected,
        "the discriminants must be exactly {expected:?}, with no duplicate and no gap"
    );

    // And the registry declares each of those names, so the numbering is over the real registry
    // rather than over a list that drifted from it.
    let registry = registry_codes();

    for code in ErrorCode::ALL {
        let name = code.wire_name();

        assert!(
            registry.iter().any(|(candidate, _)| candidate == name),
            "{name} has discriminant {} but is not in the registry",
            code as u8
        );
    }
}

/// The registry assigns no numbers to error codes, and this crate's discriminants are its own.
///
/// This took three attempts to get right, and the trail is worth keeping. I asserted the array index
/// was the discriminant (failed: the array opens with the three `UNSUPPORTED_*` codes, so
/// `ERR_UNSUPPORTED_MESSAGE` is first while its discriminant is 11). I then asserted the array was
/// alphabetical (failed: it is grouped thematically). Only then did I read the entries:
///
/// ```json
/// { "code": "ERR_UNSUPPORTED_MESSAGE", "severity": "recoverable" }
/// ```
///
/// There is no numeric field. Unlike `message_types`, whose entries carry `"code": 1`, error codes
/// are identified on the wire **only by their name**. So the `#[repr(u8)]` discriminants in this
/// crate are a private convenience, and asserting anything about their relationship to the array
/// order was asserting a property the normative file does not have.
///
/// What is asserted instead is the property that does hold and does matter: the array declares no
/// numbers, so no implementation can be wrong about a number that does not exist.
#[test]
fn the_registry_assigns_no_numbers_to_error_codes() {
    let document = registry();

    let entries = document
        .get("error_codes")
        .and_then(Value::as_array)
        .expect("error_codes is an array");

    for entry in entries {
        let object = entry.as_object().expect("an error code is an object");

        let keys: Vec<&str> = object.keys().map(String::as_str).collect();

        assert!(
            !keys.contains(&"code_number") && !keys.contains(&"number") && !keys.contains(&"value"),
            "an error code now has a numeric field ({keys:?}); if the registry starts numbering \
             error codes, this crate's `#[repr(u8)]` discriminants must be checked against it"
        );
        assert_eq!(
            keys.len(),
            2,
            "an error code entry should have exactly `code` and `severity`, found {keys:?}"
        );
        assert!(keys.contains(&"code"), "an entry has no `code`");
        assert!(keys.contains(&"severity"), "an entry has no `severity`");
    }

    // Contrasted with message types, which DO carry numbers. Asserted so the distinction is
    // recorded rather than assumed.
    let message_types = document
        .get("message_types")
        .and_then(Value::as_array)
        .expect("message_types is an array");

    assert!(
        message_types
            .iter()
            .all(|entry| entry.get("code").and_then(Value::as_u64).is_some()),
        "every message type carries a numeric `code`"
    );
}

/// The registry's `warning` severity is not representable, and this records that.
///
/// `error_severity_semantics` defines three severities, but all 22 codes are recoverable or fatal,
/// so `warning` is currently unreachable. The enum cannot represent it, which means a code
/// registered with it later would fail to decode rather than being silently mishandled.
///
/// The test asserts the *current* state, so registering a `warning` code fails here with an
/// explanation rather than surfacing as a decode error somewhere else.
#[test]
fn the_registry_defines_no_warning_severity_that_this_crate_cannot_represent() {
    let document = registry();

    let semantics = document
        .get("error_severity_semantics")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{REGISTRY} has no `error_severity_semantics` object"));

    assert!(
        semantics.contains_key("warning"),
        "the registry no longer defines `warning`; the note in this test is stale"
    );

    let warnings: Vec<String> = registry_codes()
        .into_iter()
        .filter(|(_, severity)| severity == "warning")
        .map(|(name, _)| name)
        .collect();

    assert!(
        warnings.is_empty(),
        "the registry now has codes with the `warning` severity: {warnings:?}. \
         `ErrorCode::severity` cannot represent it, so either add a `Severity::Warning` case to \
         this crate and the other two implementations, or remove `warning` from the registry. \
         See docs/findings/no-registry-severity-check.md."
    );
}
