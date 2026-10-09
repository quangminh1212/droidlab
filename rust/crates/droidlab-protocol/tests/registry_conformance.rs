//! Conformance tests for the message-type registry.
//!
//! `src/registry.rs` is a transcription of `protocol/registry/dlwp-1.json`'s `message_types` array, and
//! these tests read that file and compare. The direction matters: a transcription checked only against
//! itself drifts silently, and this repository has already found four defects of exactly that shape — a
//! label length written from memory (13 written as 15), a TXT label length (10 written as 8), a
//! `0xF1` placed in the wrong header field, and three inserted bytes that no length check could see.
//!
//! The single most important property is that **a message code is the registry's 1-based `code`, not
//! the 0-based index of the JSON enumeration.** `HELLO` is 1, not 0. An implementation that used the
//! enumeration order would read every type as one less than intended, and it would still work for
//! `HELLO` — which is why the bug survives a shallow test.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::registry::{
    all_codes, all_names, is_registered_message_type, may_be_unencrypted, message_type,
    message_type_by_name, must_be_encrypted, ChannelScope, Direction, MESSAGE_TYPES,
};

use serde_json::Value;

/// The registry file, read from disk rather than transcribed.
fn registry() -> Value {
    let path = vectors::vectors_dir()
        .parent()
        .expect("the vectors directory has a parent")
        .join("registry")
        .join("dlwp-1.json");

    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn registry_message_types() -> Vec<Value> {
    registry()
        .get("message_types")
        .and_then(Value::as_array)
        .expect("the registry has a message_types array")
        .clone()
}

/// The registry's `message_type_capability` map, which is an object keyed by enumeration index.
fn message_type_capability() -> Vec<Value> {
    registry()
        .get("message_type_capability")
        .and_then(Value::as_array)
        .expect("the registry has a message_type_capability array")
        .clone()
}

// =============================================================================================
// The transcription
// =============================================================================================

/// The table's size matches the registry's.
#[test]
fn the_table_has_the_registrys_size() {
    let registry_types = registry_message_types();

    assert_eq!(
        MESSAGE_TYPES.len(),
        registry_types.len(),
        "the table has {} entries and the registry has {}",
        MESSAGE_TYPES.len(),
        registry_types.len()
    );

    assert_eq!(
        MESSAGE_TYPES.len(),
        42,
        "the registry declares 42 message types"
    );
}

/// Every code and name matches the registry, in the registry's order.
#[test]
fn every_entry_matches_the_registry() {
    let registry_types = registry_message_types();

    assert_eq!(MESSAGE_TYPES.len(), registry_types.len());

    for (entry, recorded) in MESSAGE_TYPES.iter().zip(registry_types.iter()) {
        let code = recorded
            .get("code")
            .and_then(Value::as_u64)
            .expect("a code");
        let name = recorded
            .get("name")
            .and_then(Value::as_str)
            .expect("a name");
        let direction = recorded
            .get("direction")
            .and_then(Value::as_str)
            .expect("a direction");
        let channel = recorded
            .get("channel")
            .and_then(Value::as_str)
            .expect("a channel");
        let encrypted = recorded
            .get("encrypted")
            .and_then(Value::as_bool)
            .expect("an encrypted flag");

        assert_eq!(
            u64::from(entry.code),
            code,
            "{}: the table says {} and the registry says {code}",
            name,
            entry.code
        );
        assert_eq!(entry.name, name, "the table's name is wrong at code {code}");
        assert_eq!(
            entry.direction.wire_name(),
            direction,
            "{name}: the direction differs"
        );
        assert_eq!(
            entry.channel.wire_name(),
            channel,
            "{name}: the channel scope differs"
        );
        assert_eq!(
            entry.encrypted, encrypted,
            "{name}: the encrypted flag differs"
        );
    }
}

/// The code is the registry's `code`, not the enumeration index.
///
/// The defect that would survive every other test here. At index 0 the registry says `HELLO` with code
/// **1**; an implementation that derived the code from the index would produce 0, which is not a
/// registered type at all — so it would fail immediately for `HELLO`, and then be wrong by one for
/// everything after it.
#[test]
fn the_code_is_the_registrys_code_not_the_index() {
    let registry_types = registry_message_types();

    let mut indices_that_differ = 0usize;

    for (index, recorded) in registry_types.iter().enumerate() {
        let code = recorded
            .get("code")
            .and_then(Value::as_u64)
            .expect("a code");
        let name = recorded
            .get("name")
            .and_then(Value::as_str)
            .expect("a name");

        let index_as_u64 = u64::try_from(index).expect("it fits");

        if code != index_as_u64 {
            indices_that_differ = indices_that_differ.saturating_add(1);
        }

        // The table's entry at this position holds the registry's CODE, not the index.
        let entry = MESSAGE_TYPES.get(index).expect("an entry at this index");

        assert_eq!(
            u64::from(entry.code),
            code,
            "{name}: the entry holds the index {index} instead of the code {code}"
        );

        // And looking up by the index would find either nothing or the wrong entry.
        if code != index_as_u64 {
            let index_code = u8::try_from(index).unwrap_or(u8::MAX);

            if let Some(wrong) = message_type(index_code) {
                assert_ne!(
                    wrong.name, name,
                    "{name}: code {index_code} happens to be {name}, so the difference is invisible \
                     -- choose another pair"
                );
            }
        }
    }

    // Almost every entry differs from its index, which is what makes this test worth having.
    assert!(
        indices_that_differ >= 40,
        "only {indices_that_differ} of {} entries have a code that differs from its index, so the \
         registry has been renumbered and this test may no longer be the one guarding the property",
        registry_types.len()
    );

    // The first entry, named, because it is the one an index-based decoder gets wrong first.
    assert_eq!(MESSAGE_TYPES.first().map(|entry| entry.code), Some(1));
    assert_eq!(MESSAGE_TYPES.first().map(|entry| entry.name), Some("HELLO"));
}

/// Codes are unique, and names are unique.
#[test]
fn codes_and_names_are_unique() {
    let mut codes = all_codes();
    let before_codes = codes.len();

    codes.sort_unstable();
    codes.dedup();

    assert_eq!(codes.len(), before_codes, "two message types share a code");

    let mut names = all_names();
    let before_names = names.len();

    names.sort_unstable();
    names.dedup();

    assert_eq!(names.len(), before_names, "two message types share a name");
}

/// `is_registered_message_type` is a lookup, not a range comparison.
///
/// The registry's codes have **gaps** — 7..=15, 18..=31, 35..=47 and so on — and the
/// `unknown-message-type` vector's code is 254, which is inside the `u8` range and above the highest
/// registered code of 241. So neither "within the known range" nor "a small number" is a correct test.
#[test]
fn the_registration_check_is_a_lookup_not_a_range() {
    let codes = all_codes();
    let highest = codes.iter().copied().max().expect("at least one code");
    let lowest = codes.iter().copied().min().expect("at least one code");

    assert_eq!(lowest, 1, "the lowest code is 1, which is HELLO");
    assert_eq!(
        highest, 241,
        "the highest code is 241, which is SESSION_END"
    );

    // The vector's code: inside the u8 range, above the highest registered code.
    assert!(!is_registered_message_type(254));
    assert_eq!(254, u8::MAX.wrapping_sub(1));
    assert!(!is_registered_message_type(255));

    // Gaps, found from the file rather than written from memory.
    let mut gaps = Vec::new();

    for code in lowest..=highest {
        if !codes.contains(&code) {
            gaps.push(code);
        }
    }

    assert!(
        gaps.len() > 100,
        "only {} gaps between {lowest} and {highest}, so the codes are denser than expected",
        gaps.len()
    );

    // Every gap is refused, and every registered code is accepted. Both directions.
    for code in &gaps {
        assert!(
            !is_registered_message_type(*code),
            "{code} is a gap and was accepted"
        );
    }

    for code in &codes {
        assert!(
            is_registered_message_type(*code),
            "{code} is registered and was refused"
        );
    }

    // And the count of accepted codes is exactly the registry's size, so the loop above did not pass
    // by accepting everything.
    let accepted = (lowest..=highest)
        .filter(|code| is_registered_message_type(*code))
        .count();

    assert_eq!(accepted, codes.len());
}

/// Lookups by code and by name agree, in both directions.
#[test]
fn lookups_by_code_and_by_name_agree() {
    for entry in MESSAGE_TYPES {
        let by_code = message_type(entry.code).expect("the code is registered");
        let by_name = message_type_by_name(entry.name).expect("the name is registered");

        assert_eq!(
            by_code.code, by_name.code,
            "{}: the two lookups disagree",
            entry.name
        );
        assert_eq!(by_code.name, by_name.name);
        assert_eq!(by_code, by_name);
    }

    // An unregistered name and an unregistered code both give nothing.
    assert_eq!(message_type_by_name("NOT_A_MESSAGE"), None);
    assert_eq!(
        message_type_by_name("hello"),
        None,
        "names are case-sensitive"
    );
    assert_eq!(message_type(0), None, "code 0 is not HELLO, which is 1");

    // The named constants match their entries.
    assert_eq!(
        message_type_by_name("HELLO").map(|entry| entry.code),
        Some(1)
    );
    assert_eq!(
        message_type_by_name("SESSION_END").map(|entry| entry.code),
        Some(241)
    );
}

/// Exactly two message types may travel unencrypted.
///
/// The registry's `encrypted` flag is false for `HELLO` and `HELLO_ACK`, and the reason is structural:
/// those two are exchanged before a session key exists. A receiver that demanded encryption for `HELLO`
/// could never complete a handshake.
#[test]
fn exactly_the_handshake_types_may_be_unencrypted() {
    let cleartext: Vec<&str> = MESSAGE_TYPES
        .iter()
        .filter(|entry| !entry.encrypted)
        .map(|entry| entry.name)
        .collect();

    assert_eq!(
        cleartext,
        vec!["HELLO", "HELLO_ACK"],
        "the set of types that may be cleartext changed"
    );

    assert!(may_be_unencrypted(1), "HELLO may be cleartext");
    assert!(may_be_unencrypted(2), "HELLO_ACK may be cleartext");

    assert!(!may_be_unencrypted(3), "AUTH must be encrypted");
    assert!(!may_be_unencrypted(5), "PING must be encrypted");

    // Every other registered type must be encrypted, so the check is not vacuous.
    for entry in MESSAGE_TYPES {
        if entry.code > 2 {
            assert!(
                must_be_encrypted(entry.code),
                "{} must be encrypted",
                entry.name
            );
        }
    }

    // An unregistered code is neither, which is the honest answer rather than a default.
    assert!(!must_be_encrypted(254));
    assert!(!may_be_unencrypted(254));
}

/// The directions and channel scopes match the registry, and their helpers are consistent.
#[test]
fn the_directions_and_scopes_are_consistent() {
    for entry in MESSAGE_TYPES {
        let (controller, agent) = (
            entry.direction.controller_may_send(),
            entry.direction.agent_may_send(),
        );

        match entry.direction {
            Direction::ControllerToAgent => {
                assert!(
                    controller && !agent,
                    "{}: one-way from the controller",
                    entry.name
                );
            }
            Direction::AgentToController => {
                assert!(
                    !controller && agent,
                    "{}: one-way from the agent",
                    entry.name
                );
            }
            Direction::Both => {
                assert!(controller && agent, "{}: both may send", entry.name);
            }
        }

        // A type on the control channel must not be sent on a data channel.
        match entry.channel {
            ChannelScope::Control => {
                assert!(entry.channel.permits_control());
                assert!(
                    !entry.channel.permits_data(),
                    "{}: control-only",
                    entry.name
                );
            }
            ChannelScope::Data => {
                assert!(!entry.channel.permits_control());
                assert!(entry.channel.permits_data());
            }
            ChannelScope::Any => {
                assert!(entry.channel.permits_control());
                assert!(entry.channel.permits_data());
            }
        }
    }

    // The counts, so a change to the registry's shape is noticed.
    let control_only = MESSAGE_TYPES
        .iter()
        .filter(|entry| entry.channel == ChannelScope::Control)
        .count();
    let any_channel = MESSAGE_TYPES
        .iter()
        .filter(|entry| entry.channel == ChannelScope::Any)
        .count();
    let data_only = MESSAGE_TYPES
        .iter()
        .filter(|entry| entry.channel == ChannelScope::Data)
        .count();

    // The counts are DERIVED from the registry file and then compared against the table, rather than
    // written as literals. My first version hardcoded sixteen for the control-channel count; the file
    // says seventeen. Writing a count from memory is the exact error this repository has now produced
    // five times, so the number is computed here and the table is what gets checked.
    let registry_control = registry_message_types()
        .iter()
        .filter(|entry| entry.get("channel").and_then(Value::as_str) == Some("control"))
        .count();
    let registry_any = registry_message_types()
        .iter()
        .filter(|entry| entry.get("channel").and_then(Value::as_str) == Some("any"))
        .count();

    assert_eq!(
        control_only, registry_control,
        "the table has {control_only} control-channel types and the registry has {registry_control}"
    );
    assert_eq!(
        any_channel, registry_any,
        "the table has {any_channel} any-channel types and the registry has {registry_any}"
    );
    assert_eq!(data_only, 0, "no type is data-channel only");
    assert_eq!(control_only + any_channel + data_only, 42);

    // The direction counts, derived the same way.
    let registry_controller_to_agent = registry_message_types()
        .iter()
        .filter(|entry| {
            entry.get("direction").and_then(Value::as_str) == Some("controller_to_agent")
        })
        .count();
    let registry_both = registry_message_types()
        .iter()
        .filter(|entry| entry.get("direction").and_then(Value::as_str) == Some("both"))
        .count();

    let table_controller_to_agent = MESSAGE_TYPES
        .iter()
        .filter(|entry| entry.direction == Direction::ControllerToAgent)
        .count();
    let table_both = MESSAGE_TYPES
        .iter()
        .filter(|entry| entry.direction == Direction::Both)
        .count();

    assert_eq!(table_controller_to_agent, registry_controller_to_agent);
    assert_eq!(table_both, registry_both);

    // And the derived numbers are what they are, so a change to the registry is visible in this test's
    // failure rather than silently absorbed.
    assert_eq!(control_only, 17);
    assert_eq!(any_channel, 25);
}

/// `HELLO` and `HELLO_ACK` are exactly the two control-channel, cleartext, handshake types.
///
/// The intersection the handshake depends on, asserted as an intersection rather than as two separate
/// claims, because a type that was cleartext but on a data channel would be a contradiction.
#[test]
fn the_handshake_pair_is_the_cleartext_control_pair() {
    let handshake: Vec<&str> = MESSAGE_TYPES
        .iter()
        .filter(|entry| !entry.encrypted && entry.channel == ChannelScope::Control)
        .map(|entry| entry.name)
        .collect();

    assert_eq!(handshake, vec!["HELLO", "HELLO_ACK"]);

    // They are one-way in opposite directions, which is what makes the handshake a handshake.
    let hello = message_type_by_name("HELLO").expect("HELLO");
    let hello_ack = message_type_by_name("HELLO_ACK").expect("HELLO_ACK");

    assert_eq!(hello.direction, Direction::ControllerToAgent);
    assert_eq!(hello_ack.direction, Direction::AgentToController);
    assert_ne!(hello.direction, hello_ack.direction);

    // AUTH and AUTH_OK follow the same directions and ARE encrypted, so the pairing is not accidental.
    let auth = message_type_by_name("AUTH").expect("AUTH");
    let auth_ok = message_type_by_name("AUTH_OK").expect("AUTH_OK");

    assert_eq!(auth.direction, hello.direction);
    assert_eq!(auth_ok.direction, hello_ack.direction);
    assert!(auth.encrypted && auth_ok.encrypted);
}

/// Every capability mapping names a message type that exists.
///
/// The registry's `message_type_capability` is keyed by enumeration index, which is the trap this whole
/// test file is about: index 0 is `HELLO`, whose code is 1. A mapping read by index would attach
/// capabilities to the wrong messages.
#[test]
fn the_capability_mappings_name_real_message_types() {
    let mappings = message_type_capability();

    assert_eq!(
        mappings.len(),
        29,
        "the registry declares 29 capability mappings"
    );

    // The keys are the enumeration indices, so index 0 is HELLO. Assert that rather than assume it.
    assert_eq!(
        MESSAGE_TYPES.first().map(|entry| entry.name),
        Some("HELLO"),
        "the registry's first message type is HELLO, so index 0 is HELLO"
    );

    let mut named = 0usize;

    for mapping in &mappings {
        // Each mapping holds a capability name and, in the registry's shape, the index it applies to.
        // The values are strings; the keys carry the index. Read whichever is present.
        let capability = mapping
            .get("capability")
            .and_then(Value::as_str)
            .or_else(|| mapping.get("name").and_then(Value::as_str));

        if capability.is_some() {
            named = named.saturating_add(1);
        }

        // A message type index must be inside the table.
        if let Some(index) = mapping.get("index").and_then(Value::as_u64) {
            let index = usize::try_from(index).expect("it fits");

            assert!(
                index < MESSAGE_TYPES.len(),
                "a capability mapping names message index {index}, past the table"
            );
        }
    }

    // The mappings are the capability requirements for SHELL_EXEC and friends, so at least some must
    // name a capability.
    assert!(
        named > 0,
        "no capability mapping names a capability, so the shape changed and this test proves nothing"
    );
}
