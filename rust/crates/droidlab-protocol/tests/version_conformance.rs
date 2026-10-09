//! Conformance tests for version negotiation, against `version-negotiation.json` (11 vectors).
//!
//! The file's `rule` is `highest_common_version_or_fail`, and the three ways an implementation gets it
//! wrong are each carried by a vector:
//!
//!   * taking the FIRST common version rather than the highest (`both-newer-and-older`);
//!   * downgrading silently in one direction or the other (`agent-does-not-downgrade-silently`,
//!     `controller-does-not-downgrade-silently`);
//!   * comparing versions as strings, which no vector exercises because every version in the file has a
//!     single-digit minor, so this test constructs `1.10` against `1.9` itself.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::version::{
    check_header_against_body, classify_change, is_a_valid_answer, negotiate_versions, ChangeKind,
    Negotiation, Version,
};

use serde_json::Value;

const VERSION_FILE: &str = "version-negotiation.json";

fn document() -> Value {
    vectors::load(VERSION_FILE)
}

fn version_vectors() -> Vec<Value> {
    vectors::vectors(VERSION_FILE)
}

/// A JSON array of version strings, parsed numerically.
fn versions(vector: &Value, field: &str) -> Vec<Version> {
    vector
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| {
                    Version::parse(text).unwrap_or_else(|error| panic!("{text:?}: {error}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The two version lists from a vector, for the vectors that have them.
fn both_lists(vector: &Value) -> Option<(Vec<Version>, Vec<Version>)> {
    if vector.get("controller_supported").is_none() || vector.get("agent_supported").is_none() {
        return None;
    }

    Some((
        versions(vector, "controller_supported"),
        versions(vector, "agent_supported"),
    ))
}

// =============================================================================================
// The vectors
// =============================================================================================

/// Every version vector produces its declared outcome.
#[test]
fn every_version_vector_negotiates_as_declared() {
    let vectors_list = version_vectors();

    assert_eq!(vectors_list.len(), 11, "eleven version vectors");

    let mut negotiated = 0usize;
    let mut refused = 0usize;

    for vector in &vectors_list {
        let id = vectors::id(vector);

        let Some((controller, agent)) = both_lists(vector) else {
            continue;
        };

        let result = negotiate_versions(&controller, &agent);

        let expected = vector.get("expected_negotiated").and_then(Value::as_str);
        let expected_error = vector
            .get("expected_error")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty());

        match expected {
            Some(text) => {
                let want = Version::parse(text).expect("the vector's version parses");

                assert_eq!(
                    result.version(),
                    Some(want),
                    "{id}: negotiated {:?} and the vector declares {text}",
                    result.version().map(Version::to_wire_string)
                );
                assert!(result.is_agreed());
                assert_eq!(
                    expected_error, None,
                    "{id}: the vector declares both a version and an error"
                );

                negotiated = negotiated.saturating_add(1);
            }
            None => {
                assert_eq!(
                    result,
                    Negotiation::NoCommonVersion,
                    "{id}: negotiated {:?} and the vector declares no common version",
                    result
                );
                assert_eq!(
                    expected_error,
                    Some("ERR_VERSION_MISMATCH"),
                    "{id}: a failure must be ERR_VERSION_MISMATCH"
                );

                let severity = vectors::str_field(vector, "expected_severity");

                assert_eq!(severity, "fatal", "{id}: a version mismatch is fatal");

                refused = refused.saturating_add(1);
            }
        }
    }

    // Four agree, three are refused, and the remaining four are not two-list vectors at all: two are
    // about the header field, and two are about change classification. Those four are covered by
    // `the_header_field_carries_the_major_only` and `additive_changes_do_not_bump_the_version`.
    assert_eq!(negotiated, 4, "four vectors agree on a version");
    assert_eq!(refused, 3, "three vectors have no common version");
    assert_eq!(negotiated + refused, 7);
    assert_eq!(
        negotiated + refused + 4,
        11,
        "the other four vectors are the header-field and change-classification cases"
    );

    // Named, so the census above cannot drift without naming what moved.
    let two_list: Vec<String> = vectors_list
        .iter()
        .filter(|vector| both_lists(vector).is_some())
        .map(|vector| vectors::id(vector).to_owned())
        .collect();

    assert_eq!(two_list.len(), 7, "seven vectors carry two version lists");
    assert!(!two_list.contains(&"version.major-only-in-version-field".to_owned()));
    assert!(!two_list.contains(&"version.header-major-too-new".to_owned()));
    assert!(!two_list.contains(&"version.additive-change-is-not-a-major-bump".to_owned()));
    assert!(!two_list.contains(&"version.breaking-change-requires-major-bump".to_owned()));
}

/// The answer is the HIGHEST common version, not the first.
///
/// `version.both-newer-and-older`: the controller's first preference is 2.0 and the agreed version is
/// 1.1. An implementation that walked the controller's list and took the first entry the agent also has
/// would give 2.0 — no, it would give 1.1 here, because 2.0 is not in the agent's list. The vector that
/// actually distinguishes them is a case where both lists are MOST-PREFERRED-FIRST but ordered
/// differently, so the first match is not the highest.
#[test]
fn the_answer_is_the_highest_common_version() {
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.both-newer-and-older")
        .expect("the ordering vector is present");

    let (controller, agent) = both_lists(&vector).expect("two lists");

    assert_eq!(
        controller,
        vec![Version::new(2, 0), Version::new(1, 1), Version::new(1, 0)]
    );
    assert_eq!(agent, vec![Version::new(1, 1), Version::new(1, 0)]);

    let result = negotiate_versions(&controller, &agent);

    assert_eq!(result.version(), Some(Version::new(1, 1)));
    assert_ne!(
        result.version(),
        Some(Version::new(2, 0)),
        "the controller's first preference was agreed, but the agent does not support it"
    );

    // The distinguishing case, constructed because the file has none: both lists contain 1.0 and 1.1,
    // and the CONTROLLER lists the lower one first. A first-match scan gives 1.0; the correct answer is
    // 1.1.
    let reversed_controller = vec![Version::new(1, 0), Version::new(1, 1)];
    let reversed_agent = vec![Version::new(1, 1), Version::new(1, 0)];

    let result = negotiate_versions(&reversed_controller, &reversed_agent);

    assert_eq!(
        result.version(),
        Some(Version::new(1, 1)),
        "a first-match scan was used instead of a maximum"
    );

    // And the answer does not depend on either list's order, checked over all four orderings.
    let ascending = vec![Version::new(1, 0), Version::new(1, 1)];
    let descending = vec![Version::new(1, 1), Version::new(1, 0)];

    for controller in [&ascending, &descending] {
        for agent in [&ascending, &descending] {
            assert_eq!(
                negotiate_versions(controller, agent).version(),
                Some(Version::new(1, 1)),
                "the answer depends on the input order"
            );
        }
    }
}

/// Versions compare numerically, so `1.10` is newer than `1.9`.
///
/// The classic version bug, and NO VECTOR IN THE FILE EXERCISES IT: every version in
/// `version-negotiation.json` has a single-digit minor, so a string comparison would pass the whole
/// file. This test constructs the case.
#[test]
fn versions_compare_numerically_not_lexically() {
    let one_nine = Version::parse("1.9").expect("1.9 parses");
    let one_ten = Version::parse("1.10").expect("1.10 parses");
    let one_two = Version::parse("1.2").expect("1.2 parses");

    assert!(
        one_ten > one_nine,
        "1.10 must be newer than 1.9, not older: lexically \"1.10\" < \"1.9\""
    );
    assert!(one_nine > one_two, "1.9 must be newer than 1.2");

    // And through a negotiation, which is where it would matter.
    let controller = vec![one_nine, one_two];
    let agent = vec![one_ten, one_nine, one_two];

    assert_eq!(
        negotiate_versions(&controller, &agent).version(),
        Some(one_nine),
        "the answer is the highest common version, 1.9"
    );

    // With both on the controller's side, 1.10 wins.
    let controller = vec![one_ten, one_nine];

    assert_eq!(
        negotiate_versions(&controller, &agent).version(),
        Some(one_ten),
        "1.10 is the highest common version"
    );

    // The major dominates the minor, so 2.0 beats 1.99.
    assert!(Version::parse("2.0").expect("parses") > Version::parse("1.99").expect("parses"));

    // Zero is a valid minor, and 1.0 is a version rather than "no version".
    assert!(Version::parse("1.0").is_ok());
    assert!(Version::new(1, 0) > Version::new(0, 99));

    // Parsing is strict, so two implementations cannot disagree about a malformed string.
    for text in [
        "", "1", "1.", ".0", "1.2.3", "1.2.", "-1.0", "1.-1", "a.b", " 1.0", "1.0 ",
    ] {
        assert!(
            Version::parse(text).is_err(),
            "{text:?} was accepted as a version"
        );
    }

    // Round trip.
    for text in ["1.0", "1.1", "2.0", "1.10", "255.255"] {
        let parsed = Version::parse(text).expect("parses");

        assert_eq!(
            parsed.to_wire_string(),
            text,
            "round trip failed for {text}"
        );
    }
}

/// Neither side downgrades silently.
#[test]
fn neither_side_downgrades_silently() {
    // The agent's side: the controller offers only 9.9, which the agent does not know.
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.agent-does-not-downgrade-silently")
        .expect("the agent-downgrade vector is present");

    let (controller, agent) = both_lists(&vector).expect("two lists");

    assert_eq!(controller, vec![Version::new(9, 9)]);
    assert_eq!(agent, vec![Version::new(1, 0)]);

    assert_eq!(
        negotiate_versions(&controller, &agent),
        Negotiation::NoCommonVersion,
        "the agent assumed the controller meant 1.0"
    );

    // The controller's side: the agent answers with a version the controller never offered.
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.controller-does-not-downgrade-silently")
        .expect("the controller-downgrade vector is present");

    let (controller, agent) = both_lists(&vector).expect("two lists");

    assert_eq!(controller, vec![Version::new(1, 1)]);
    assert_eq!(agent, vec![Version::new(1, 0)]);

    // Negotiation correctly finds no common version, so a correct agent would refuse.
    assert_eq!(
        negotiate_versions(&controller, &agent),
        Negotiation::NoCommonVersion
    );

    // And the vector's `agent_answered` is 1.0, which the controller never offered, so the controller
    // must abort.
    let answered = Version::parse(vectors::str_field(&vector, "agent_answered")).expect("parses");

    assert_eq!(answered, Version::new(1, 0));
    assert!(
        !is_a_valid_answer(&controller, answered),
        "the controller accepted an answer it never offered"
    );

    // Every offered version IS a valid answer, so the check is not a refusal of everything.
    for version in &controller {
        assert!(is_a_valid_answer(&controller, *version));
    }

    // And an empty offer accepts nothing, which is the degenerate case.
    assert!(!is_a_valid_answer(&[], answered));
}

/// An exact match agrees, and so does a subset either way.
#[test]
fn matching_lists_agree() {
    for id in [
        "version.exact-match",
        "version.controller-newer-known",
        "version.agent-newer-known",
    ] {
        let vector = version_vectors()
            .into_iter()
            .find(|vector| vectors::id(vector) == id)
            .unwrap_or_else(|| panic!("{id} is present"));

        let (controller, agent) = both_lists(&vector).expect("two lists");

        let result = negotiate_versions(&controller, &agent);

        assert_eq!(
            result.version(),
            Some(Version::new(1, 0)),
            "{id}: the agreed version is not 1.0"
        );

        // The answer is always one BOTH sides listed, which is the invariant.
        let agreed = result.version().expect("agreed");

        assert!(
            controller.contains(&agreed),
            "{id}: the answer was not offered"
        );
        assert!(agent.contains(&agreed), "{id}: the answer is not supported");
    }

    // No overlap at all.
    assert_eq!(
        negotiate_versions(&[Version::new(2, 0)], &[Version::new(1, 0)]),
        Negotiation::NoCommonVersion
    );

    // An empty side agrees to nothing, in either direction.
    assert_eq!(
        negotiate_versions(&[], &[Version::new(1, 0)]),
        Negotiation::NoCommonVersion
    );
    assert_eq!(
        negotiate_versions(&[Version::new(1, 0)], &[]),
        Negotiation::NoCommonVersion
    );
    assert_eq!(negotiate_versions(&[], &[]), Negotiation::NoCommonVersion);
}

// =============================================================================================
// The header field and the body string
// =============================================================================================

/// The header carries the major only, and the body's string carries the rest.
#[test]
fn the_header_field_carries_the_major_only() {
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.major-only-in-version-field")
        .expect("the header-field vector is present");

    let header_field =
        u8::try_from(vectors::u64_field(&vector, "header_version_field")).expect("it fits a u8");
    let body_string = vectors::str_field(&vector, "hello_proto_string");

    assert_eq!(header_field, 1);
    assert_eq!(body_string, "1.1");

    let body = Version::parse(body_string).expect("the body version parses");

    // A 1.1 body against a major-1 header is CONSISTENT: the field carries 1, and 1.1's major is 1.
    // This is the property that lets a minor be added without changing the frame layout.
    assert_eq!(body.header_version_field(), 1);
    assert_eq!(check_header_against_body(header_field, body), None);

    // And the version vector's other case: a header major of 2 is refused.
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.header-major-too-new")
        .expect("the too-new-header vector is present");

    let header_field =
        u8::try_from(vectors::u64_field(&vector, "header_version_field")).expect("it fits a u8");

    assert_eq!(header_field, 2);
    assert_eq!(
        vectors::str_field(&vector, "expected_error"),
        "ERR_VERSION_MISMATCH"
    );

    // A 1.0 body against a major-2 header is a mismatch.
    let mismatch = check_header_against_body(header_field, Version::V1_0);

    assert_eq!(
        mismatch,
        Some(droidlab_protocol::version::HeaderBodyMismatch {
            header: 2,
            body_major: 1
        }),
        "a major-2 header against a 1.0 body was not reported as a mismatch"
    );

    // The frame header's own version check agrees: a Version field of 2 is refused by the classifier.
    assert_eq!(Version::new(2, 0).header_version_field(), 2);
    assert_eq!(Version::V1_0.header_version_field(), 1);

    // Every 1.x has a header field of 1, which is the whole point.
    for minor in [0u32, 1, 2, 10, 99] {
        assert_eq!(Version::new(1, minor).header_version_field(), 1);
    }

    // A major past 255 saturates rather than wrapping, so a receiver sees a version it will refuse
    // rather than one that merely looks old.
    assert_eq!(Version::new(256, 0).header_version_field(), 255);
    assert_eq!(Version::new(65_536, 0).header_version_field(), 255);
    assert_ne!(
        Version::new(256, 0).header_version_field(),
        0,
        "a major of 256 wrapped to 0, which reads as a pre-1.0 version"
    );
}

/// Minor versions are compatible; different majors are not.
#[test]
fn the_major_is_what_decides_compatibility() {
    assert!(Version::new(1, 0).is_compatible_with(Version::new(1, 9)));
    assert!(Version::new(1, 9).is_compatible_with(Version::new(1, 0)));
    assert!(Version::new(1, 0).is_compatible_with(Version::V1_0));

    assert!(!Version::new(1, 0).is_compatible_with(Version::new(2, 0)));
    assert!(!Version::new(2, 0).is_compatible_with(Version::new(1, 0)));

    // Compatibility is reflexive and symmetric over the 1.x line, which is what makes the relation
    // usable at all.
    for minor in 0u32..20 {
        let version = Version::new(1, minor);

        assert!(version.is_compatible_with(version));

        for other_minor in 0u32..20 {
            let other = Version::new(1, other_minor);

            assert_eq!(
                version.is_compatible_with(other),
                other.is_compatible_with(version),
                "compatibility is not symmetric for 1.{minor} and 1.{other_minor}"
            );
        }
    }
}

// =============================================================================================
// Change classification
// =============================================================================================

/// An additive change does not bump the version; a breaking one does.
#[test]
fn additive_changes_do_not_bump_the_version() {
    // The additive vector's own change kind is a COMPOUND name, which is why the classifier looks for
    // the leading verb rather than requiring an exact match.
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.additive-change-is-not-a-major-bump")
        .expect("the additive vector is present");

    let kind = vectors::str_field(&vector, "change_kind");

    assert_eq!(kind, "add_capability_and_message_type");

    let classified = classify_change(kind).expect("the compound name is classified");

    assert_eq!(classified, ChangeKind::AddCapability);
    assert!(classified.is_additive());
    assert!(!classified.requires_version_bump());

    // The vector's declared answer.
    assert_eq!(
        vectors::nested(&vector, "expected_version_bump").as_bool(),
        Some(false),
        "the vector now expects a version bump for an additive change"
    );

    // The breaking vector.
    let vector = version_vectors()
        .into_iter()
        .find(|vector| vectors::id(vector) == "version.breaking-change-requires-major-bump")
        .expect("the breaking vector is present");

    let kind = vectors::str_field(&vector, "change_kind");

    assert_eq!(kind, "change_default_of_video_codec");

    let classified = classify_change(kind).expect("the change default is classified");

    assert_eq!(classified, ChangeKind::ChangeDefault);
    assert!(!classified.is_additive());
    assert!(classified.requires_version_bump());

    assert_eq!(
        vectors::nested(&vector, "expected_version_bump").as_bool(),
        Some(true),
        "the vector now expects no version bump for a breaking change"
    );

    // Every additive kind requires no bump and every breaking one does, in both directions, so the two
    // predicates are not accidentally the same.
    for kind in [
        ChangeKind::AddMessageType,
        ChangeKind::AddCapability,
        ChangeKind::AddOptionalKey,
    ] {
        assert!(kind.is_additive());
        assert!(!kind.requires_version_bump());
    }

    for kind in [
        ChangeKind::ChangeFieldMeaning,
        ChangeKind::RemoveField,
        ChangeKind::ChangeDefault,
    ] {
        assert!(!kind.is_additive());
        assert!(kind.requires_version_bump());
    }

    // An unclassifiable name is refused rather than assumed additive, because assuming additive is the
    // direction that breaks peers.
    for text in [
        "",
        "frobnicate_the_wire",
        "Add_Capability",
        "add capability",
    ] {
        assert_eq!(
            classify_change(text),
            None,
            "{text:?} was classified, so an unknown change could be treated as safe"
        );
    }

    // The verbs, individually.
    assert_eq!(
        classify_change("add_message_type"),
        Some(ChangeKind::AddMessageType)
    );
    assert_eq!(
        classify_change("add_capability"),
        Some(ChangeKind::AddCapability)
    );
    assert_eq!(
        classify_change("add_optional_key"),
        Some(ChangeKind::AddOptionalKey)
    );
    assert_eq!(
        classify_change("remove_field"),
        Some(ChangeKind::RemoveField)
    );
    assert_eq!(
        classify_change("change_field_meaning"),
        Some(ChangeKind::ChangeFieldMeaning)
    );
    assert_eq!(
        classify_change("change_meaning_of_action"),
        Some(ChangeKind::ChangeFieldMeaning)
    );
}

// =============================================================================================
// The CI rules
// =============================================================================================

/// The file's CI rules are assertions about the repository that this test can check.
#[test]
fn the_ci_rules_are_present_and_parseable() {
    let rules = document()
        .get("ci_rules")
        .and_then(Value::as_array)
        .expect("ci_rules")
        .clone();

    assert_eq!(rules.len(), 3, "three CI rules");

    let ids: Vec<String> = rules
        .iter()
        .map(|rule| vectors::id(rule).to_owned())
        .collect();

    assert!(ids.contains(&"ci.rfc-change-requires-vector-change".to_owned()));
    assert!(ids.contains(&"ci.new-error-code-requires-registry-entry".to_owned()));
    assert!(ids.contains(&"ci.new-capability-requires-registry-entry".to_owned()));

    // Every rule declares what it watches.
    for rule in &rules {
        let watch = rule
            .get("watch")
            .and_then(Value::as_array)
            .expect("a watch list");

        assert!(
            !watch.is_empty(),
            "{}: an empty watch list",
            vectors::id(rule)
        );

        for path in watch {
            let path = path.as_str().expect("a path");

            assert!(
                path.starts_with("protocol/") || path.starts_with("docs/"),
                "{}: the watched path {path} is outside the protocol",
                vectors::id(rule)
            );
        }
    }

    // The rule's targets are real repository paths, so the rule is not aspirational. Checked by
    // existence, because a rule watching a path that does not exist can never fire.
    //
    // The root is two levels up from `protocol/vectors`, not three. My first version walked three and
    // reported that `docs/rfc/RFC-0001-wire-protocol.md` -- a file that is plainly in the repository --
    // did not exist, which is a test bug that looks exactly like a repository bug.
    let root = vectors::vectors_dir()
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the repository root")
        .to_path_buf();

    // The root really is the repository, checked by a path that must be there.
    assert!(
        root.join("protocol").join("vectors").is_dir(),
        "the computed root {} is not the repository root",
        root.display()
    );
    assert!(
        root.join("docs").join("rfc").is_dir(),
        "the computed root {} has no docs/rfc",
        root.display()
    );

    for rule in &rules {
        for field in ["watch", "require_touch", "require_registry"] {
            let Some(list) = rule.get(field).and_then(Value::as_array) else {
                continue;
            };

            for path in list {
                let path = path.as_str().expect("a path");

                // A fragment is not part of a path; and a glob is checked by its prefix.
                let without_fragment = path.split('#').next().unwrap_or(path);

                if without_fragment.contains('*') {
                    let prefix = without_fragment.split('*').next().unwrap_or("");

                    if prefix.is_empty() {
                        continue;
                    }

                    assert!(
                        root.join(prefix).exists(),
                        "{}: the watched prefix {prefix} does not exist",
                        vectors::id(rule)
                    );
                } else {
                    assert!(
                        root.join(without_fragment).exists(),
                        "{}: the watched path {without_fragment} does not exist",
                        vectors::id(rule)
                    );
                }
            }
        }
    }
}
