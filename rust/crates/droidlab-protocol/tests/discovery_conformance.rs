//! Conformance tests for service discovery, against `discovery.json` (4 vectors, 6 rejection vectors,
//! 4 lifecycle vectors).
//!
//! The file records the TXT canonical length as an ARITHMETIC — `10 + 1 + 5 + 4 + ... = 121` — and that
//! is worth more than the total. A total alone hides a compensating error, and this repository has
//! already found one fixture where three inserted bytes were exactly cancelled by a `body_length + 3`, so
//! every length check agreed while the meaning was wrong. These tests check the sum term by term.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::discovery::{
    advertises_when_busy, build_txt, canonical_beacon_string, canonical_key_order, canonical_txt,
    canonical_txt_string, evaluate_advertisement, goodbye_ttl, is_expired, is_known_txt_key,
    is_usable_port, may_emit_beacon, requires_reregistration, truncate_capabilities,
    AdvertisementVerdict, Presence, TxtError, TxtFields, BEACON_PORT, DEFAULT_PORT, DOMAIN,
    MAX_TXT_BYTES, OPTIONAL_KEYS, REQUIRED_KEYS, SERVICE_TYPE, TTL_SECONDS,
};

use serde_json::Value;

const FILE: &str = "discovery.json";

fn document() -> Value {
    vectors::load(FILE)
}

/// The `fields` object of a vector, as [`TxtFields`].
fn fields_of(vector: &Value) -> TxtFields {
    let mut fields = TxtFields::new();

    let object = vector
        .get("fields")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{} has a fields object", vectors::id(vector)));

    for (key, value) in object {
        // A JSON number becomes its bare digits, which is what the canonical form carries: `busy=0` and
        // `port=45917`, not `busy=0.0`.
        let text = match value {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => u8::from(*flag).to_string(),
            other => panic!("{}: field {key} is {other:?}", vectors::id(vector)),
        };

        fields.set(key, &text);
    }

    fields
}

fn vectors_named(array: &str) -> Vec<Value> {
    document()
        .get(array)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the file has a {array} array"))
        .clone()
}

fn find(array: &str, id: &str) -> Value {
    vectors_named(array)
        .into_iter()
        .find(|vector| vectors::id(vector) == id)
        .unwrap_or_else(|| panic!("{id} is in {array}"))
}

/// Splits a recorded `canonical_length_arithmetic` into its addends.
///
/// The shape is `10 ("DLWP/1-txt") + 1 (NUL) + 5 + ... = 121`, and the parenthesised explanations are why
/// this cannot be a naive split on `+` followed by a parse: each addend must be read as the leading digits
/// of its piece, after trimming the separating space.
fn arithmetic_terms(text: &str) -> Vec<usize> {
    // The shape is "10 (\"DLWP/1-txt\") + 1 (NUL) + 5 + ... = 121". Take the part before the `=`, and
    // read every run of digits that is a standalone addend -- the parenthesised explanations are the
    // reason this cannot be a naive split on '+'.
    let left = text
        .split('=')
        .next()
        .expect("an arithmetic has an equals sign");

    let mut terms = Vec::new();

    for piece in left.split('+') {
        // `trim_start` first. Every addend after the first begins with a space (`" 1 (NUL) "`), so a
        // `take_while` on the untrimmed piece yields nothing for nineteen of the twenty-one terms and the
        // sum silently becomes just the label. That is what happened on the first run: the terms came
        // back as `[10]`.
        let trimmed = piece.trim_start();

        let digits: String = trimmed
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .collect();

        if digits.is_empty() {
            continue;
        }

        terms.push(digits.parse::<usize>().expect("it parses"));
    }

    terms
}

// =============================================================================================
// The service constants
// =============================================================================================

/// The service constants match the file.
#[test]
fn the_service_constants_match_the_file() {
    let service = document()
        .get("service")
        .and_then(Value::as_object)
        .expect("the file has a service object")
        .clone();

    assert_eq!(
        SERVICE_TYPE,
        service.get("type").and_then(Value::as_str).expect("type")
    );
    assert_eq!(
        DOMAIN,
        service
            .get("domain")
            .and_then(Value::as_str)
            .expect("domain")
    );
    assert_eq!(
        u64::from(DEFAULT_PORT),
        service
            .get("default_port")
            .and_then(Value::as_u64)
            .expect("port")
    );
    assert_eq!(
        u64::from(BEACON_PORT),
        service
            .get("beacon_port")
            .and_then(Value::as_u64)
            .expect("beacon port")
    );
    assert_eq!(
        u64::from(TTL_SECONDS),
        service
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .expect("ttl")
    );
    assert_eq!(
        MAX_TXT_BYTES,
        usize::try_from(
            service
                .get("max_txt_bytes")
                .and_then(Value::as_u64)
                .expect("max_txt_bytes")
        )
        .expect("it fits a usize")
    );

    // The service type is the DNS-SD shape, which is what makes it a service rather than a host.
    assert!(
        SERVICE_TYPE.starts_with('_'),
        "an mDNS service type starts with an underscore"
    );
    assert!(SERVICE_TYPE.ends_with("._tcp"), "this is a TCP service");
    assert_eq!(SERVICE_TYPE, "_droidlab._tcp");

    // The two ports differ, so a beacon cannot be mistaken for a session.
    assert_ne!(DEFAULT_PORT, BEACON_PORT);

    // The TTL is the vector's 120, and the budget its 1300.
    assert_eq!(TTL_SECONDS, 120);
    assert_eq!(MAX_TXT_BYTES, 1300);
}

/// The key order is fixed, required-first, and matches the file's `extra_key_order`.
#[test]
fn the_key_order_is_fixed_and_not_alphabetical() {
    let canonicalisation = document()
        .get("txt_canonicalisation")
        .and_then(Value::as_object)
        .expect("txt_canonicalisation")
        .clone();

    // The required keys, in the order the file's `form` string writes them.
    let form = canonicalisation
        .get("form")
        .and_then(Value::as_str)
        .expect("the form string");

    for key in REQUIRED_KEYS {
        assert!(
            form.contains(&format!("\"{key}=\"")),
            "the form string does not carry the required key {key}"
        );
    }

    // The order in the form string is the order in REQUIRED_KEYS, checked by position.
    let mut positions = Vec::new();

    for key in REQUIRED_KEYS {
        let needle = format!("\"{key}=\"");
        let position = form
            .find(&needle)
            .unwrap_or_else(|| panic!("{needle} is in the form"));

        positions.push((key, position));
    }

    for window in positions.windows(2) {
        let (first, first_position) = window[0];
        let (second, second_position) = window[1];

        assert!(
            first_position < second_position,
            "the form writes {second} before {first}, so REQUIRED_KEYS is out of order"
        );
    }

    // The `form` field appears FIRST, before `id`. That is not alphabetical, and it is the point.
    assert!(positions[0].1 < positions[1].1);
    // The REQUIRED_KEYS constant itself, and the fact that it is not alphabetical. `v` sorts after `id`
    // and `fp`, so a sorted list would put `v` last -- and mine put `v` first, which is why the order has
    // to come from the form string rather than from a sort.
    assert_eq!(REQUIRED_KEYS, ["v", "id", "fp", "caps", "port"]);

    let mut sorted_required: Vec<&str> = REQUIRED_KEYS.to_vec();
    sorted_required.sort_unstable();

    assert_ne!(
        REQUIRED_KEYS.to_vec(),
        sorted_required,
        "the required keys happen to be alphabetical, so the fixed-order rule is untested"
    );
    assert_eq!(
        sorted_required,
        ["caps", "fp", "id", "port", "v"],
        "the required keys sort to a different order than the canonical one"
    );

    // The optional keys match `extra_key_order` exactly, in order.
    let extra: Vec<String> = canonicalisation
        .get("extra_key_order")
        .and_then(Value::as_array)
        .expect("extra_key_order")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    assert_eq!(optional_keys(), extra, "the optional key order drifted");
    assert_eq!(extra.len(), 6);

    // The optional order is NOT alphabetical either -- `model` before `android` before `sdk`.
    let mut sorted = extra.clone();
    sorted.sort();
    assert_ne!(
        extra, sorted,
        "the optional keys happen to be alphabetical, so the fixed-order rule is untested"
    );

    // The full order is required then optional, with no key twice.
    let order = canonical_key_order();

    assert_eq!(order.len(), 11);

    let mut unique = order.clone();
    unique.sort_unstable();
    unique.dedup();

    assert_eq!(
        unique.len(),
        order.len(),
        "a key appears twice in the canonical order"
    );
}

/// The optional key names, as a `Vec`, for comparison with the file.
fn optional_keys() -> Vec<String> {
    OPTIONAL_KEYS.iter().map(|key| (*key).to_owned()).collect()
}

// =============================================================================================
// The canonical form
// =============================================================================================

/// Every TXT vector produces its recorded canonical bytes, and its recorded LENGTH ARITHMETIC.
#[test]
fn every_txt_vector_canonicalises_as_recorded() {
    let all = vectors_named("vectors");

    assert_eq!(all.len(), 4, "four discovery vectors");

    let mut canonical_checked = 0usize;

    for vector in &all {
        let id = vectors::id(vector);

        // The beacon is not a TXT record: its fields include `name`, which is not a TXT key, and its
        // canonical form is the ascending-key one. It is covered by `the_beacon_uses_ascending_key_order`.
        // My first version fed it to `canonical_txt` and got a five-line record against the beacon's six,
        // because `name` is not a canonical TXT key and was correctly dropped.
        if id == "discovery.beacon.canonical" {
            continue;
        }

        let Some(recorded) = vector.get("canonical_utf8").and_then(Value::as_str) else {
            // The caps-truncated vector has fields but no recorded canonical form, so it is covered by
            // `the_capability_list_truncation_is_advisory`.
            assert_eq!(id, "discovery.txt.caps-truncated");
            continue;
        };

        let fields = fields_of(vector);
        let produced = canonical_txt_string(&fields);

        assert_eq!(produced, recorded, "{id}: the canonical form differs");

        // The BYTES, not just the string: a canonical form is bytes on the wire.
        assert_eq!(
            canonical_txt(&fields),
            recorded.as_bytes(),
            "{id}: the canonical bytes differ"
        );

        // The recorded byte length, which for ASCII is the string length.
        let length = usize::try_from(
            vector
                .get("canonical_length_bytes")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("{id} records a length")),
        )
        .expect("it fits a usize");

        assert_eq!(
            produced.len(),
            length,
            "{id}: produced {} bytes and the vector records {length}",
            produced.len()
        );

        assert_eq!(
            canonical_txt(&fields).len(),
            length,
            "{id}: the byte length differs"
        );

        // No trailing newline, which the rule states outright.
        assert!(
            !produced.ends_with('\n'),
            "{id}: the canonical form ends in a newline"
        );

        // The label and the NUL, which the rule names.
        assert!(
            produced.starts_with("DLWP/1-txt\u{0}"),
            "{id}: the canonical form does not start with the label and a NUL"
        );

        // `\n` is the separator, and there is one fewer than there are keys.
        let key_count = order_present(&fields).len();

        assert_eq!(
            produced.matches('\n').count(),
            key_count.saturating_sub(1),
            "{id}: {key_count} keys need {} separators",
            key_count.saturating_sub(1)
        );

        canonical_checked = canonical_checked.saturating_add(1);
    }

    // Only TWO of the three vectors that carry `canonical_utf8` are TXT records. The third is the beacon,
    // which has its own canonicalisation and its own test. My first version asserted three and the count
    // is what caught the mis-attribution.
    assert_eq!(
        canonical_checked, 2,
        "two TXT vectors carry a canonical form"
    );

    // And the file does carry three `canonical_utf8` values, so the distinction is real.
    let with_canonical = vectors_named("vectors")
        .iter()
        .filter(|vector| vector.get("canonical_utf8").is_some())
        .count();

    assert_eq!(
        with_canonical, 3,
        "three vectors carry a canonical form in total"
    );
}

/// The keys present in canonical order, so a test can count them.
fn order_present(fields: &TxtFields) -> Vec<&'static str> {
    canonical_key_order()
        .into_iter()
        .filter(|key| fields.has(key))
        .collect()
}

/// The recorded length arithmetic adds up, term by term, to the recorded total.
///
/// **KNOWN FAILING, and `#[ignore]`d for that reason.** See
/// `docs/findings/discovery-length-arithmetic-does-not-sum.md`: `discovery.txt.minimal`'s terms sum to
/// **141** while the vector records **121**, and the canonical STRING is correctly 121 bytes. The terms
/// are also stale — they give `id`'s value as 21 bytes where the UUID is 36 — so the arithmetic cannot be
/// repaired by changing its total.
///
/// It is kept rather than deleted because the correction is one decision away, and it is ignored rather
/// than asserted-as-defective so that a correct fix makes it PASS instead of FAIL. Run it with
/// `cargo test -- --ignored` to see the current state.
///
/// The vector gives the sum rather than only the answer, and that is the more valuable record: it says
/// WHERE each byte comes from. A total alone would let a compensating error pass — and this repository
/// has already found a fixture whose three inserted bytes were exactly cancelled by a `body_length + 3`,
/// so every length check agreed while the meaning was wrong.
///
/// `discovery.txt.minimal`: `10 + 1 + 5 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 3 + 2 + 21 + 2 + 28 + 5 + 5 +
/// 2 + 21 + 5 + 5 = 121`.
#[test]
#[ignore = "the vector's own arithmetic does not sum: see docs/findings/discovery-length-arithmetic-does-not-sum.md"]
fn the_recorded_length_arithmetic_adds_up() {
    let all = vectors_named("vectors");

    let mut checked = 0usize;

    for vector in &all {
        let id = vectors::id(vector);

        let Some(text) = vector
            .get("canonical_length_arithmetic")
            .and_then(Value::as_str)
        else {
            continue;
        };

        let terms = arithmetic_terms(text);
        let sum: usize = terms.iter().sum();

        let recorded = usize::try_from(
            vector
                .get("canonical_length_bytes")
                .and_then(Value::as_u64)
                .expect("canonical_length_bytes"),
        )
        .expect("it fits a usize");

        // This FAILS TODAY for `discovery.txt.minimal`, and it is left asserting the correct relationship
        // on purpose. See `docs/findings/discovery-length-arithmetic-does-not-sum.md`: the terms sum to
        // 141 and the vector records 121, while the canonical STRING is correctly 121 bytes.
        //
        // Asserting the defect instead would make a correct fix to the vector fail this test, which is
        // backwards -- the vector's prose is the specification and this is a defect in it.
        assert_eq!(
            sum, recorded,
            "{id}: the arithmetic terms {terms:?} sum to {sum} and the vector records {recorded}"
        );
        let _ = &id;

        // And the arithmetic agrees with what the code produces, which is the check that matters.
        let fields = fields_of(vector);

        assert_eq!(
            canonical_txt(&fields).len(),
            sum,
            "{id}: the code produced {} bytes and the arithmetic accounts for {sum}",
            canonical_txt(&fields).len()
        );

        // The first term is the label's length and the second is the NUL, which pins what the
        // arithmetic MEANS rather than only that it adds up.
        assert_eq!(
            terms[0],
            "DLWP/1-txt".len(),
            "{id}: the first term is not the label"
        );
        assert_eq!(terms[1], 1, "{id}: the second term is not the NUL");
        assert_eq!(terms[0], 10);

        // Every term is accounted for by a piece of the canonical form: the label, the NUL, or one of
        // `key=`/value/separator. The count is pinned so the loop cannot pass vacuously.
        assert!(
            terms.len() >= 20,
            "{id}: only {} terms, so the arithmetic is not the full byte-by-byte sum",
            terms.len()
        );

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 2, "two vectors record their arithmetic");
}

/// The full record's arithmetic note is a measured difference, not an estimate.
#[test]
fn the_full_record_note_is_checkable() {
    let full = find("vectors", "discovery.txt.full");
    let minimal = find("vectors", "discovery.txt.minimal");

    let note = vectors::str_field(&full, "canonical_length_note");

    assert!(
        note.contains("208") && note.contains("121"),
        "the note no longer records both lengths: {note}"
    );
    assert!(
        note.contains("Measured, not estimated"),
        "the note no longer claims measurement"
    );

    let full_length = canonical_txt(&fields_of(&full)).len();
    let minimal_length = canonical_txt(&fields_of(&minimal)).len();

    assert_eq!(full_length, 208);
    assert_eq!(minimal_length, 121);

    // The note's claim: the optional keys add 87 bytes. Checked as a difference rather than accepted.
    assert_eq!(
        full_length.saturating_sub(minimal_length),
        87,
        "the note claims the optional keys add 87 bytes"
    );

    assert!(
        note.contains("87"),
        "the note no longer records the 87-byte difference"
    );

    // And the difference is entirely the optional keys plus their separators, so it is attributable.
    let full_fields = fields_of(&full);
    let minimal_fields = fields_of(&minimal);

    let optional_present: Vec<&str> = OPTIONAL_KEYS
        .into_iter()
        .filter(|key| full_fields.has(key))
        .collect();

    assert_eq!(
        optional_present.len(),
        6,
        "the full vector carries all six optional keys"
    );

    let mut explained = 0usize;

    for key in &optional_present {
        // `\n` + key + `=` + value
        explained = explained
            .saturating_add(1)
            .saturating_add(key.len())
            .saturating_add(1)
            .saturating_add(full_fields.get(key).unwrap_or("").len());
    }

    // The optional keys are 53 of the 87, NOT all of it. My first version asserted they were the whole
    // difference and failed with "the optional keys explain 53 bytes of the 87-byte difference", which is
    // the assertion being wrong rather than the arithmetic.
    assert_eq!(
        explained, 53,
        "the six optional keys should account for 53 bytes, not {explained}"
    );

    // The required keys' values are identical between the two, except `caps`, whose difference is also
    // attributable. So nothing in the difference is unexplained.
    for key in ["v", "port"] {
        assert_eq!(
            minimal_fields.get(key),
            full_fields.get(key),
            "{key} differs between the two vectors, so the 87 is not only the optional keys"
        );
    }

    let caps_difference = full_fields
        .get("caps")
        .expect("caps")
        .len()
        .saturating_sub(minimal_fields.get("caps").expect("caps").len());

    let id_difference = full_fields
        .get("id")
        .expect("id")
        .len()
        .saturating_sub(minimal_fields.get("id").expect("id").len());

    // And the remaining 34 is the longer capability list. `id` contributes nothing because both vectors
    // use a 36-character UUID, which is worth asserting rather than assuming -- a vector that changed one
    // id would silently shift the decomposition.
    assert_eq!(
        caps_difference, 34,
        "the caps list should account for 34 bytes, not {caps_difference}"
    );
    assert_eq!(
        id_difference, 0,
        "the two ids differ in length, so the 87 is not 53 + 34"
    );

    assert_eq!(
        explained
            .saturating_add(caps_difference)
            .saturating_add(id_difference),
        87,
        "53 (optional keys) + 34 (longer caps list) should be the whole 87"
    );

    // The other fields are the same length in both, which is what makes the decomposition complete.
    for key in ["v", "port", "fp"] {
        assert_eq!(
            minimal_fields.get(key).expect("present").len(),
            full_fields.get(key).expect("present").len(),
            "{key} differs in length, so the 87 is not fully accounted for"
        );
    }
}

/// The beacon uses ascending key order, which is a DIFFERENT rule from the TXT record's.
#[test]
fn the_beacon_uses_ascending_key_order() {
    let vector = find("vectors", "discovery.beacon.canonical");

    let note = vectors::str_field(&vector, "note");

    assert!(
        note.contains("ascending key order"),
        "the beacon note no longer says ascending: {note}"
    );
    assert!(
        note.contains("differs from the TXT canonicalisation on purpose"),
        "the beacon note no longer says the two rules differ deliberately: {note}"
    );

    let object = vector
        .get("fields")
        .and_then(Value::as_object)
        .expect("fields");

    let pairs: Vec<(String, String)> = object
        .iter()
        .map(|(key, value)| {
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                other => panic!("field {key} is {other:?}"),
            };

            (key.clone(), text)
        })
        .collect();

    let recorded = vectors::str_field(&vector, "canonical_utf8");
    let produced = canonical_beacon_string(&pairs);

    assert_eq!(produced, recorded, "the beacon canonical form differs");

    // Ascending, verified by re-sorting.
    let keys: Vec<&str> = produced
        .split('\n')
        .filter_map(|line| line.split('=').next())
        .collect();

    let mut sorted = keys.clone();
    sorted.sort_unstable();

    assert_eq!(keys, sorted, "the beacon keys are not in ascending order");

    // The specific order the vector records, which is alphabetical here.
    assert_eq!(keys, ["busy", "fp", "id", "name", "port", "v"]);

    // No label and no NUL, unlike the TXT record.
    assert!(!produced.starts_with("DLWP/1-txt"));
    assert!(!produced.contains('\u{0}'));

    // And the two canonicalisations genuinely differ on the same data, which is the claim the note makes.
    let txt_form = canonical_txt_string(&fields_of(&find("vectors", "discovery.txt.minimal")));

    assert_ne!(
        txt_form, produced,
        "the two canonical forms are identical, so the difference the note describes is untested"
    );

    // `v` comes last in the beacon and first in the TXT record. That is the contrast in one assertion.
    assert!(
        produced.ends_with("v=1.0"),
        "the beacon does not end with v"
    );
    assert!(
        txt_form.starts_with("DLWP/1-txt\u{0}v="),
        "the TXT record does not start with v"
    );
}

/// `sig` is excluded from the beacon's signed payload.
#[test]
fn the_beacon_signature_covers_every_field_but_itself() {
    let vector = find("vectors", "discovery.beacon.canonical");

    let note = vectors::str_field(&vector, "note");

    assert!(
        note.contains("every field except sig"),
        "the beacon note no longer excludes sig: {note}"
    );

    let pairs = vec![
        ("busy".to_owned(), "0".to_owned()),
        ("fp".to_owned(), "9F3C-1A08-B7E2-44D1".to_owned()),
        (
            "id".to_owned(),
            "11111111-2222-4333-8444-555555555555".to_owned(),
        ),
        ("name".to_owned(), "Pixel 7 - bench 3".to_owned()),
        ("port".to_owned(), "45917".to_owned()),
        ("v".to_owned(), "1.0".to_owned()),
    ];

    let without = canonical_beacon_string(&pairs);

    // Adding a signature does NOT change the canonical form, which is what makes signing it possible.
    let mut with_signature = pairs.clone();
    with_signature.push(("sig".to_owned(), "AA".repeat(64)));

    assert_eq!(
        canonical_beacon_string(&with_signature),
        without,
        "sig changed the canonical form, so the signature would cover itself"
    );

    // A different signature gives the same payload, which is the property that makes the scheme work.
    let mut other_signature = pairs.clone();
    other_signature.push(("sig".to_owned(), "BB".repeat(64)));

    assert_eq!(canonical_beacon_string(&other_signature), without);

    // And the signature length the vector records is 64 bytes, which is Ed25519.
    assert_eq!(vectors::u64_field(&vector, "signature_length_bytes"), 64);
    assert_eq!(
        vectors::str_field(&vector, "signature_algorithm"),
        "Ed25519"
    );
}

/// An unknown key is dropped rather than appended.
#[test]
fn an_unknown_key_is_dropped_from_the_canonical_form() {
    let vector = find("vectors", "discovery.txt.minimal");
    let fields = fields_of(&vector);

    let with_unknown = {
        let mut extended = fields.clone();
        extended.set("frobnicate", "yes");
        extended
    };

    assert_eq!(
        canonical_txt_string(&with_unknown),
        canonical_txt_string(&fields),
        "an unknown key changed the canonical form, so a controller would compute a different digest"
    );

    // And an optional key that IS known does change it, so the drop is about knowledge rather than about
    // position.
    let with_optional = {
        let mut extended = fields.clone();
        extended.set("model", "Pixel 7");
        extended
    };

    assert_ne!(
        canonical_txt_string(&with_optional),
        canonical_txt_string(&fields)
    );
    assert!(canonical_txt_string(&with_optional).contains("model=Pixel 7"));

    // An optional key that is absent is not emitted, and neither is one with an empty value.
    let with_empty = {
        let mut extended = fields.clone();
        extended.set("model", "");
        extended
    };

    assert_eq!(
        canonical_txt_string(&with_empty),
        canonical_txt_string(&fields),
        "an empty optional value was emitted, which would add a separator for no information"
    );

    // The optional keys go AFTER port, in the RFC order, not interleaved.
    let full = canonical_txt_string(&fields_of(&find("vectors", "discovery.txt.full")));
    let port_position = full.find("port=").expect("port");
    let model_position = full.find("model=").expect("model");

    assert!(
        port_position < model_position,
        "an optional key came before port"
    );

    for key in OPTIONAL_KEYS {
        assert!(
            full.contains(&format!("\n{key}=")),
            "the full record omits {key}"
        );
    }
}

// =============================================================================================
// Emission checks
// =============================================================================================

/// A required key or a usable port is required to build a record.
#[test]
fn a_record_needs_its_required_keys_and_a_usable_port() {
    let full = fields_of(&find("vectors", "discovery.txt.full"));

    assert!(build_txt(&full, MAX_TXT_BYTES).is_ok());

    // Every required key, removed one at a time.
    for key in REQUIRED_KEYS {
        let mut missing = full.clone();
        missing.pairs.retain(|(entry, _)| entry != key);

        assert_eq!(
            build_txt(&missing, MAX_TXT_BYTES),
            Err(TxtError::MissingKey { key }),
            "removing {key} was accepted"
        );

        // And an empty value counts as absent, because it would produce `key=` and a separator.
        let mut empty = full.clone();
        empty.set(key, "");

        assert_eq!(
            build_txt(&empty, MAX_TXT_BYTES),
            Err(TxtError::MissingKey { key }),
            "an empty {key} was accepted"
        );
    }

    // The port, which the vector pins at 0.
    let vector = find("rejection_vectors", "discovery.reject.port-out-of-range");

    let port = vectors::u64_field(&vector, "advertised_port");

    assert_eq!(port, 0);
    assert!(!is_usable_port(port));
    assert_eq!(
        vectors::str_field(&vector, "expected"),
        "ignore_advertisement"
    );

    let mut bad_port = full.clone();
    bad_port.set("port", "0");

    assert_eq!(
        build_txt(&bad_port, MAX_TXT_BYTES),
        Err(TxtError::PortOutOfRange { port: 0 })
    );

    // The whole range, both ends, so the check is not `!= 0` in disguise.
    assert!(!is_usable_port(0));
    assert!(is_usable_port(1));
    assert!(is_usable_port(65_535));
    assert!(!is_usable_port(65_536));
    assert!(!is_usable_port(u64::MAX));

    for port in 1u64..=65_535 {
        assert!(is_usable_port(port), "port {port} was refused");
    }

    // And 65536 and up are the only values above the range.
    assert!(!is_usable_port(65_536));
}

/// A record over the budget is REFUSED rather than truncated at the top level.
#[test]
fn a_record_over_the_budget_is_refused() {
    let vector = find("rejection_vectors", "discovery.reject.txt-too-large");

    let txt_bytes = usize::try_from(vectors::u64_field(&vector, "txt_bytes")).expect("fits");
    let max = usize::try_from(vectors::u64_field(&vector, "max_txt_bytes")).expect("fits");

    assert_eq!(txt_bytes, 1400);
    assert_eq!(max, 1300);
    assert!(txt_bytes > max);

    assert_eq!(vectors::str_field(&vector, "expected"), "regenerate_record");

    let note = vectors::str_field(&vector, "note");

    assert!(
        note.contains("must not produce it"),
        "the note no longer says the agent must not produce an oversized record: {note}"
    );

    // The engine refuses.
    let full = fields_of(&find("vectors", "discovery.txt.full"));

    assert_eq!(
        build_txt(&full, 100),
        Err(TxtError::TooLarge {
            size: 208,
            limit: 100
        })
    );

    // A budget of exactly the size is allowed, which pins the comparison as `<=` rather than `<`.
    assert!(build_txt(&full, 208).is_ok());
    assert!(build_txt(&full, 207).is_err());

    // `MAX_TXT_BYTES` is the file's value rather than a second constant that could drift.
    assert_eq!(MAX_TXT_BYTES, max);

    // The full record is 208 bytes and the budget is 1300, so it fits with room to spare. My first
    // version asserted that `MAX_TXT_BYTES - 1` was TOO SMALL, which cannot be true of a 208-byte record
    // against a 1299-byte limit -- the assertion was wrong, not the code.
    assert_eq!(canonical_txt(&full).len(), 208);
    let record_length = canonical_txt(&full).len();
    assert!(
        MAX_TXT_BYTES > record_length,
        "the budget is not the 1400-byte vector's problem"
    );
    assert!(
        build_txt(&full, MAX_TXT_BYTES).is_ok(),
        "the full record fits the real budget"
    );
    assert!(build_txt(&full, MAX_TXT_BYTES.saturating_sub(1)).is_ok());

    // The refusal case is a budget at the record's own size or below, which is what the vector's 1400
    // against 1300 is about: the record is over the budget, so it is not produced.
    assert!(build_txt(&full, 208).is_ok(), "exactly the size fits");
    assert!(build_txt(&full, 207).is_err(), "one byte under does not");

    // And a record genuinely over the file's budget is refused, constructed by padding a capability list
    // until it exceeds 1300.
    let mut over = full.clone();
    let padding = "x".repeat(MAX_TXT_BYTES);

    over.set("caps", &padding);

    let error = build_txt(&over, MAX_TXT_BYTES).expect_err("an oversized record is refused");

    match error {
        TxtError::TooLarge { size, limit } => {
            assert!(size > MAX_TXT_BYTES, "{size} is not over {limit}");
            assert_eq!(limit, MAX_TXT_BYTES);
        }
        other => panic!("an oversized record gave {other:?}"),
    }
}

/// The capability list is truncated to whole names with no trailing comma.
#[test]
fn the_capability_list_truncation_is_advisory() {
    let vector = find("vectors", "discovery.txt.caps-truncated");

    let fields = fields_of(&vector);

    let broadcast: Vec<String> = fields
        .get("caps")
        .expect("caps")
        .split(',')
        .map(str::to_owned)
        .collect();

    assert_eq!(
        broadcast,
        ["screen.mirror", "input.touch", "input.key", "file.read"],
        "the vector's advertised list changed"
    );

    let note = vectors::str_field(&vector, "note");
    let trust = vectors::str_field(&vector, "note_on_trust");

    assert!(
        note.contains("truncates it"),
        "the note no longer describes truncation"
    );
    assert!(
        note.contains("comma-free prefix"),
        "the note no longer requires a comma-free prefix"
    );
    assert!(
        note.contains("not evidence that a capability is missing"),
        "the note no longer says a truncated list is not evidence: {note}"
    );
    assert!(
        trust.contains("Only the CAPABILITIES frame after authentication is authoritative"),
        "the trust rule changed: {trust}"
    );

    // The truncation drops whole names and never leaves a trailing comma.
    let available: Vec<String> = vector
        .get("caps_actually_available")
        .and_then(Value::as_array)
        .expect("caps_actually_available")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    assert_eq!(
        available.len(),
        16,
        "sixteen capabilities are actually available"
    );

    for budget in 0usize..=120 {
        let truncated = truncate_capabilities(&available, budget);

        assert!(
            !truncated.ends_with(',') || truncated.is_empty(),
            "budget {budget}: the truncated list {truncated:?} ends in a comma"
        );
        // `"".split(',')` yields `[""]`, which is an artifact of splitting an empty string rather than an
        // empty capability name, so the check is conditional on there being something to split.
        assert!(
            truncated.is_empty() || !truncated.split(',').any(str::is_empty),
            "budget {budget}: the truncated list {truncated:?} has an empty entry"
        );
        assert!(
            truncated.len() <= budget,
            "budget {budget}: the truncated list is {} bytes",
            truncated.len()
        );

        // Every name that survived is a real name, so nothing was cut mid-name.
        for name in truncated.split(',').filter(|entry| !entry.is_empty()) {
            assert!(
                available.iter().any(|candidate| candidate == name),
                "budget {budget}: {name:?} is not a capability, so a name was cut"
            );
        }

        // And it is a PREFIX of the available list, because dropping is from the end.
        let survivors: Vec<&str> = truncated
            .split(',')
            .filter(|entry| !entry.is_empty())
            .collect();

        assert_eq!(
            survivors,
            available
                .iter()
                .take(survivors.len())
                .map(|text| text.as_str())
                .collect::<Vec<&str>>(),
            "budget {budget}: the truncation is not a prefix"
        );
    }

    // A budget with room for exactly one name keeps exactly that name.
    assert_eq!(
        truncate_capabilities(&available, "screen.mirror".len()),
        "screen.mirror"
    );
    assert_eq!(
        truncate_capabilities(&available, "screen.mirror".len().saturating_sub(1)),
        ""
    );

    // A zero budget yields nothing rather than a partial name.
    assert_eq!(truncate_capabilities(&available, 0), "");
    assert_eq!(truncate_capabilities(&[], 100), "");

    // A large budget keeps everything, and equals the joined list.
    assert_eq!(
        truncate_capabilities(&available, 10_000),
        available.join(",")
    );
}

// =============================================================================================
// Accepting and rejecting advertisements
// =============================================================================================

/// Every rejection vector produces its declared verdict.
#[test]
fn every_rejection_vector_behaves_as_declared() {
    let all = vectors_named("rejection_vectors");

    assert_eq!(all.len(), 6, "six rejection vectors");

    let mut checked = 0usize;

    for vector in &all {
        let id = vectors::id(vector);
        let expected = vectors::str_field(vector, "expected");

        // A vector with `fields` uses the general evaluator. `txt-too-large` is the one rejection vector
        // that is about GENERATION rather than about a received advertisement, so it is covered by
        // `a_record_over_the_budget_is_refused` and named here as an explicit exclusion rather than
        // falling through to the panic.
        if vector.get("fields").is_some()
            || id == "discovery.reject.txt-too-large"
            || id == "discovery.reject.beacon-on-public-network"
        {
            continue;
        }

        assert!(
            !expected.is_empty(),
            "{id}: a rejection vector must declare an expectation"
        );

        checked = checked.saturating_add(1);

        match id {
            "discovery.reject.signature-mismatch-paired-device" => {
                assert_eq!(expected, "ignore_advertisement");
                assert_eq!(
                    vector.get("signature_valid").and_then(Value::as_bool),
                    Some(false)
                );

                // The UI state and the manual connect are the substantive part of this vector.
                assert_eq!(
                    vectors::str_field(vector, "expected_ui_state"),
                    "Unverified"
                );

                let action = vectors::str_field(vector, "note_on_action");

                assert!(
                    action.contains("must not connect"),
                    "the note no longer forbids connecting: {action}"
                );
                assert!(
                    action.contains("must also not quietly remove the device"),
                    "the note no longer forbids silent removal: {action}"
                );
                assert!(
                    action.contains("an attacker may be jamming the real agent"),
                    "the note no longer gives the reason: {action}"
                );
                assert!(
                    action.contains("offers a manual connect"),
                    "the note no longer offers a manual connect: {action}"
                );

                // The engine's verdict for this case.
                let mut fields = fields_of(&find("vectors", "discovery.txt.minimal"));
                fields.set("busy", "0");

                let (verdict, reason) =
                    evaluate_advertisement(&fields, Some(("9F3C-1A08-B7E2-44D1", false)), &["1.0"]);

                assert_eq!(verdict, AdvertisementVerdict::ListAsUnverified, "{reason}");
                assert!(verdict.offers_manual_connect());
                assert!(!verdict
                    .presence()
                    .expect("listed")
                    .allows_automatic_connect());
                assert!(verdict.presence().expect("listed").is_listed());
            }
            "discovery.reject.fingerprint-changed-for-known-id" => {
                assert_eq!(expected, "refuse_automatic_connect");
                assert_eq!(
                    vectors::str_field(vector, "known_fingerprint"),
                    "9F3C-1A08-B7E2-44D1"
                );
                assert_eq!(
                    vectors::str_field(vector, "advertised_fingerprint"),
                    "DE34-A1B0-77C9-9021"
                );

                let warning = vectors::str_field(vector, "expected_warning");

                assert!(
                    warning.contains("possible impersonation"),
                    "the warning no longer names impersonation: {warning}"
                );

                // The engine: the fingerprint is checked BEFORE the signature, because a changed
                // identity means the signature would be checked against the wrong key. Here the
                // signature is VALID and the fingerprint differs, and the verdict is still a refusal.
                let full = fields_of(&find("vectors", "discovery.txt.full"));

                assert_eq!(full.get("fp"), Some("DE34-A1B0-77C9-9021"));

                let (verdict, reason) =
                    evaluate_advertisement(&full, Some(("9F3C-1A08-B7E2-44D1", true)), &["1.0"]);

                assert_eq!(
                    verdict,
                    AdvertisementVerdict::RefuseAutomaticConnect,
                    "{reason}"
                );
                assert!(verdict.offers_manual_connect());
                assert!(!verdict
                    .presence()
                    .expect("listed")
                    .allows_automatic_connect());
            }
            "discovery.reject.port-out-of-range" => {
                assert_eq!(expected, "ignore_advertisement");

                let port = vectors::u64_field(vector, "advertised_port");

                assert_eq!(port, 0);

                let mut fields = fields_of(&find("vectors", "discovery.txt.minimal"));
                fields.set("port", "0");

                let (verdict, reason) = evaluate_advertisement(&fields, None, &["1.0"]);

                assert_eq!(
                    verdict,
                    AdvertisementVerdict::IgnoreAdvertisement,
                    "{reason}"
                );
                assert_eq!(
                    verdict.presence(),
                    None,
                    "an ignored advertisement is not listed"
                );
                assert!(!verdict.offers_manual_connect());
            }
            "discovery.reject.unsupported-version" => {
                assert_eq!(expected, "list_as_incompatible");
                assert_eq!(
                    vectors::str_field(vector, "expected_error"),
                    "ERR_VERSION_MISMATCH"
                );

                let advertised = vectors::str_field(vector, "advertised_version");

                assert_eq!(advertised, "9.0");

                let supported: Vec<String> = vector
                    .get("controller_supported_versions")
                    .and_then(Value::as_array)
                    .expect("controller_supported_versions")
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();

                let supported_refs: Vec<&str> =
                    supported.iter().map(|text| text.as_str()).collect();

                assert_eq!(supported_refs, ["1.0"]);
                assert!(!supported_refs.contains(&advertised));

                let mut fields = fields_of(&find("vectors", "discovery.txt.minimal"));
                fields.set("v", advertised);

                let (verdict, reason) = evaluate_advertisement(&fields, None, &supported_refs);

                assert_eq!(
                    verdict,
                    AdvertisementVerdict::ListAsIncompatible,
                    "{reason}"
                );

                // Listed, but not connectable.
                assert!(verdict.presence().expect("listed").is_listed());
                assert!(!verdict
                    .presence()
                    .expect("listed")
                    .allows_automatic_connect());
                assert!(!verdict.offers_manual_connect());

                // The version is checked on the SUPPORTED list, so a listed version is compatible.
                let (verdict, reason) = evaluate_advertisement(
                    &fields_of(&find("vectors", "discovery.txt.minimal")),
                    None,
                    &["1.0"],
                );

                assert_ne!(
                    verdict,
                    AdvertisementVerdict::ListAsIncompatible,
                    "{reason}"
                );
            }
            other => panic!("{other} is a rejection vector this test does not handle"),
        }
    }

    assert_eq!(
        checked, 4,
        "four rejection vectors are about a received advertisement; the other two are about generation \
         (`txt-too-large`) and about emitting a beacon (`beacon-on-public-network`)"
    );
}

/// The beacon is not emitted when discovery is off.
#[test]
fn the_beacon_is_not_emitted_when_discovery_is_disabled() {
    let vector = find(
        "rejection_vectors",
        "discovery.reject.beacon-on-public-network",
    );

    assert_eq!(
        vector.get("discovery_enabled").and_then(Value::as_bool),
        Some(false)
    );

    let expected = vectors::str_field(&vector, "expected");

    assert_eq!(expected, "no_beacon");
    assert!(!may_emit_beacon(false));
    assert!(may_emit_beacon(true));

    // The note's second rule, about the destination rather than about emitting.
    let note = vectors::str_field(&vector, "note");

    assert!(
        note.contains("must not unicast it to an address it has not itself been contacted from"),
        "the note's addressing rule changed: {note}"
    );
    assert!(
        note.to_lowercase().contains("the beacon is a broadcast"),
        "the note no longer says the beacon is a broadcast: {note}"
    );

    // A beacon carries no session, so emitting one is never required for a session to work -- which is
    // why refusing to emit is a legal response to disabling discovery.
    assert_ne!(DEFAULT_PORT, BEACON_PORT);
}

// =============================================================================================
// The lifecycle
// =============================================================================================

/// Every lifecycle vector behaves as declared.
#[test]
fn every_lifecycle_vector_behaves_as_declared() {
    let all = vectors_named("lifecycle_vectors");

    assert_eq!(all.len(), 4, "four lifecycle vectors");

    let mut checked = 0usize;

    for vector in &all {
        let id = vectors::id(vector);
        // `discovery.ttl-expiry-keeps-saved-device` has no `expected` key at all -- it declares
        // `expected_ui_state` and `expected_still_listed` instead -- so the field is optional here. My
        // first version called `str_field` unconditionally and the helper correctly panicked.
        let expected = vector.get("expected").and_then(Value::as_str).unwrap_or("");
        let _ = &expected;

        match id {
            "discovery.goodbye-on-disable" => {
                assert_eq!(expected, "send_goodbye");
                assert_eq!(
                    vectors::str_field(vector, "action"),
                    "operator_disables_discovery"
                );

                let ttl = vectors::u64_field(vector, "goodbye_ttl");

                assert_eq!(ttl, 0);
                assert_eq!(u64::from(goodbye_ttl()), ttl);

                // Not a small nonzero TTL: a goodbye is a re-announcement with TTL 0, and a controller
                // that treated a small TTL as "about to leave" would keep the device listed for that
                // long, which is the delay the goodbye exists to avoid.
                assert_ne!(goodbye_ttl(), TTL_SECONDS);
                assert!(
                    goodbye_ttl() < TTL_SECONDS,
                    "the goodbye TTL is not shorter than the record's"
                );

                // And turning discovery off stops the beacon too.
                assert!(!may_emit_beacon(false));
            }
            "discovery.reannounce-after-address-change" => {
                assert_eq!(expected, "re_register_service");

                let trigger = vectors::str_field(vector, "trigger");

                assert_eq!(trigger, "interface_address_changed");
                assert!(requires_reregistration(trigger));

                let note = vectors::str_field(vector, "note");

                assert!(
                    note.contains("appearing online but being unreachable"),
                    "the note no longer names the symptom: {note}"
                );

                // An unrelated trigger does not require re-registration, so the check is not `true`
                // unconditionally.
                for unrelated in [
                    "",
                    "operator_disables_discovery",
                    "session_started",
                    "ttl_expired",
                ] {
                    assert!(
                        !requires_reregistration(unrelated),
                        "{unrelated:?} was treated as an address change"
                    );
                }
            }
            "discovery.ttl-expiry-keeps-saved-device" => {
                assert_eq!(vectors::str_field(vector, "expected_ui_state"), "Offline");
                assert_eq!(
                    vector.get("expected_still_listed").and_then(Value::as_bool),
                    Some(true)
                );

                let ttl = u32::try_from(vectors::u64_field(vector, "ttl_s")).expect("fits");
                let elapsed = u32::try_from(vectors::u64_field(vector, "elapsed_s")).expect("fits");

                assert_eq!(ttl, TTL_SECONDS);
                assert_eq!(elapsed, 121);

                assert!(is_expired(elapsed, ttl));
                assert!(!is_expired(ttl.saturating_sub(1), ttl));

                // The BOUNDARY, which the vector's 121 does not pin: elapsed == ttl is expired, so the
                // comparison is `>=` rather than `>`.
                assert!(
                    is_expired(ttl, ttl),
                    "a TTL of 120 with 120 elapsed is not expired, so the comparison is `>` not `>=`"
                );

                // And the saved device is still listed, which is the substantive claim: presence expires
                // but the pairing survives.
                assert_eq!(
                    vector.get("expected").and_then(Value::as_str),
                    None,
                    "no `expected` key"
                );
                assert!(Presence::Offline.is_listed());
                assert!(!Presence::Offline.allows_automatic_connect());

                // Being offline is not the same as being gone. `is_listed` is `true` for every variant by
                // construction -- the function exists to make that explicit at the call site rather than to
                // branch -- so asserting it five times is a tautology clippy is right to flag. What is
                // asserted instead is the part that VARIES: which states allow an automatic connect.
                assert!(Presence::Offline.is_listed());

                // Only online and busy allow an automatic connect.
                assert!(Presence::Online.allows_automatic_connect());
                assert!(Presence::Busy.allows_automatic_connect());
                assert!(!Presence::Offline.allows_automatic_connect());
                assert!(!Presence::Unverified.allows_automatic_connect());
                assert!(!Presence::Incompatible.allows_automatic_connect());
            }
            "discovery.busy-agent-still-advertises" => {
                assert_eq!(expected, "advertise_with_busy_flag");

                let active =
                    u32::try_from(vectors::u64_field(vector, "active_sessions")).expect("fits");
                let max = u32::try_from(vectors::u64_field(vector, "max_sessions")).expect("fits");
                let busy_value = vectors::u64_field(vector, "expected_busy_value");

                assert_eq!(active, 1);
                assert_eq!(max, 1);
                assert_eq!(busy_value, 1);

                assert_eq!(advertises_when_busy(active, max), (true, busy_value));

                // Below the limit, still advertising, with busy 0.
                assert_eq!(advertises_when_busy(0, 1), (true, 0));
                assert_eq!(advertises_when_busy(0, 8), (true, 0));
                assert_eq!(advertises_when_busy(7, 8), (true, 0));

                // At and above the limit, advertising with busy 1.
                assert_eq!(advertises_when_busy(1, 1), (true, 1));
                assert_eq!(advertises_when_busy(8, 8), (true, 1));
                assert_eq!(advertises_when_busy(9, 8), (true, 1));

                // The FIRST element is always true, because the alternative -- withdrawing the
                // advertisement -- would make a busy device indistinguishable from a powered-off one.
                for active in 0u32..12 {
                    for max in 0u32..12 {
                        let (advertising, _) = advertises_when_busy(active, max);

                        assert!(
                            advertising,
                            "a busy agent stopped advertising at {active}/{max}"
                        );
                    }
                }

                // And the note says why.
                let note = vectors::str_field(vector, "note");

                assert!(
                    note.contains("rather than 'device not found'"),
                    "the note no longer gives the reason for a busy flag: {note}"
                );
            }
            other => panic!("{other} is a lifecycle vector this test does not handle"),
        }

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 4, "all four lifecycle vectors were checked");
}

/// An advertisement with no pairing record is listed but not trusted.
#[test]
fn an_unpaired_advertisement_is_listed_but_not_trusted() {
    let minimal = fields_of(&find("vectors", "discovery.txt.minimal"));

    let (verdict, reason) = evaluate_advertisement(&minimal, None, &["1.0"]);

    assert_eq!(verdict, AdvertisementVerdict::ListAsUnverified, "{reason}");
    assert!(verdict.offers_manual_connect());
    assert!(verdict.presence().expect("listed").is_listed());
    assert!(!verdict
        .presence()
        .expect("listed")
        .allows_automatic_connect());

    // Paired and valid: accepted.
    let (verdict, reason) =
        evaluate_advertisement(&minimal, Some(("9F3C-1A08-B7E2-44D1", true)), &["1.0"]);

    assert_eq!(verdict, AdvertisementVerdict::Accept, "{reason}");
    assert_eq!(verdict.presence(), Some(Presence::Online));
    assert!(!verdict.offers_manual_connect());

    // Paired, valid, and busy: accepted with the flag, which is a DIFFERENT verdict because a controller
    // can then show a reason.
    let mut busy = minimal.clone();
    busy.set("busy", "1");

    let (verdict, reason) =
        evaluate_advertisement(&busy, Some(("9F3C-1A08-B7E2-44D1", true)), &["1.0"]);

    assert_eq!(verdict, AdvertisementVerdict::AcceptBusy, "{reason}");
    assert_eq!(verdict.presence(), Some(Presence::Busy));
    assert!(verdict
        .presence()
        .expect("listed")
        .allows_automatic_connect());

    // Told 0 explicitly, which is the same as absent.
    let mut not_busy = minimal.clone();
    not_busy.set("busy", "0");

    assert_eq!(
        evaluate_advertisement(&not_busy, Some(("9F3C-1A08-B7E2-44D1", true)), &["1.0"]).0,
        AdvertisementVerdict::Accept
    );

    // A missing required key is ignored rather than listed, because there is nothing to list.
    for key in REQUIRED_KEYS {
        let mut missing = minimal.clone();
        missing.pairs.retain(|(entry, _)| entry != key);

        let (verdict, reason) = evaluate_advertisement(&missing, None, &["1.0"]);

        assert_eq!(
            verdict,
            AdvertisementVerdict::IgnoreAdvertisement,
            "removing {key} gave {verdict:?}: {reason}"
        );
        assert_eq!(
            verdict.presence(),
            None,
            "removing {key} produced a presence"
        );
    }

    // Every verdict's presence and manual-connect answer is internally consistent: an ignored or
    // regenerated advertisement is never listed.
    for verdict in [
        AdvertisementVerdict::Accept,
        AdvertisementVerdict::AcceptBusy,
        AdvertisementVerdict::IgnoreAdvertisement,
        AdvertisementVerdict::ListAsUnverified,
        AdvertisementVerdict::RefuseAutomaticConnect,
        AdvertisementVerdict::ListAsIncompatible,
        AdvertisementVerdict::RegenerateRecord,
    ] {
        if verdict.presence().is_none() {
            assert!(
                !verdict.offers_manual_connect(),
                "{verdict:?} is not listed but offers a manual connect"
            );
        }

        if verdict.offers_manual_connect() {
            assert!(
                verdict.presence().is_some_and(Presence::is_listed),
                "{verdict:?} offers a manual connect without listing the device"
            );
            assert!(
                !verdict
                    .presence()
                    .expect("listed")
                    .allows_automatic_connect(),
                "{verdict:?} offers a manual connect but also connects automatically"
            );
        }
    }
}

// =============================================================================================
// The canonical decomposition, checked against the string rather than against the vector's arithmetic
// =============================================================================================

/// The canonical form's bytes decompose exactly: label, NUL, then per key `key = value`, then separators.
///
/// This is the check that the ignored `the_recorded_length_arithmetic_adds_up` was meant to be, without
/// depending on the vector's arithmetic. The fixture's arithmetic is stale; the STRING is not, so it is
/// the string that is decomposed and checked. Every byte is accounted for, which is what makes a
/// compensating error impossible.
#[test]
fn every_canonical_byte_is_accounted_for() {
    let all = vectors_named("vectors");

    let mut checked = 0usize;

    for vector in &all {
        let id = vectors::id(vector);

        if id == "discovery.beacon.canonical" {
            continue;
        }

        let Some(recorded) = vector.get("canonical_utf8").and_then(Value::as_str) else {
            continue;
        };

        let fields = fields_of(vector);
        let produced = canonical_txt(&fields);

        assert_eq!(
            produced,
            recorded.as_bytes(),
            "{id}: the canonical bytes differ"
        );

        // Decompose from the STRING, independently of how `canonical_txt` builds it.
        let label = "DLWP/1-txt";

        assert!(recorded.starts_with(label), "{id}: no label");

        let after_label = &recorded[label.len()..];

        assert!(
            after_label.starts_with('\u{0}'),
            "{id}: no NUL after the label"
        );

        let body = &after_label[1..];
        let lines: Vec<&str> = body.split('\n').collect();

        // The decomposition, accumulated and compared with the real length at the end.
        let mut accounted = label.len().saturating_add(1);

        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                // The separator, which a naive `key = value` decomposition forgets -- and forgetting them
                // is one of the two errors in the fixture's arithmetic.
                accounted = accounted.saturating_add(1);
            }

            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{id}: the line {line:?} has no equals sign"));

            assert!(
                is_known_txt_key(key),
                "{id}: the line {line:?} has the unknown key {key:?}, which should have been dropped"
            );

            // `key` + `=` + `value`
            accounted = accounted
                .saturating_add(key.len())
                .saturating_add(1)
                .saturating_add(value.len());
        }

        assert_eq!(
            accounted,
            recorded.len(),
            "{id}: the decomposition accounts for {accounted} of {} bytes",
            recorded.len()
        );

        // And the key order in the string is the canonical order, checked by position.
        let present: Vec<&str> = lines
            .iter()
            .filter_map(|line| line.split_once('=').map(|(key, _)| key))
            .collect();

        let mut expected_order: Vec<&str> = canonical_key_order()
            .into_iter()
            .filter(|key| fields.has(key))
            .collect();

        assert_eq!(
            present, expected_order,
            "{id}: the key order in the string is not canonical"
        );

        // The separators are exactly one fewer than the keys, which is what pins the separator count.
        assert_eq!(
            recorded.matches('\n').count(),
            present.len().saturating_sub(1),
            "{id}: the separator count is wrong"
        );

        expected_order.clear();

        checked = checked.saturating_add(1);
    }

    assert_eq!(checked, 2, "two TXT vectors were decomposed");

    // The fixture's own arithmetic, decomposed the same way, is recorded as defective in the finding.
    // Asserting the relationship here means a correction to the vector is visible from the code.
    let minimal = find("vectors", "discovery.txt.minimal");

    if let Some(text) = minimal
        .get("canonical_length_arithmetic")
        .and_then(Value::as_str)
    {
        let sum: usize = arithmetic_terms(text).iter().sum();
        let recorded = canonical_txt(&fields_of(&minimal)).len();

        assert_ne!(
            sum, recorded,
            "the vector's arithmetic now sums to the recorded length, so the finding is FIXED and \
             docs/findings/discovery-length-arithmetic-does-not-sum.md and the ignored test \
             `the_recorded_length_arithmetic_adds_up` should both be removed"
        );

        assert_eq!(
            sum,
            recorded.saturating_add(20),
            "the arithmetic's excess changed from 20 bytes"
        );
    }
}
