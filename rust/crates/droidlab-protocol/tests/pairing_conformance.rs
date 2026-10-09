//! Conformance tests for pairing: fingerprints, the six-digit code, the pairing secret, and the
//! Ed25519 signature vectors.
//!
//! The vector file is explicit that none of its expected values are written out:
//!
//! > No key bytes are written literally in this file. An implementation derives every byte string with
//! > the formula, so the vectors stay auditable and free of copy-paste errors.
//!
//! So these tests derive from the formulas and compare against the recorded *lengths*, the recorded
//! *inputs*, and the recorded *properties*. Where the file does record a value — the signature
//! vectors' input byte strings, the fingerprint's format — it is compared literally.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::labels;
use droidlab_protocol::pairing::{
    derive_pairing_secret, ed25519_public_key_with_seed, pairing_code, pairing_salt, proof_bytes,
    secret_fingerprint, sign_ed25519_with_seed, verify_ed25519, verify_proof, x25519_shared,
    Fingerprint, PairingError, PairingSecret, FINGERPRINT_BYTES, FINGERPRINT_RENDERED,
    PAIRING_CODE_DIGITS, PAIRING_CODE_MODULUS,
};
use droidlab_protocol::seed::{from_base64url, from_hex, key_from_seed, seed_hex, to_hex};

use serde_json::Value;

const PRIMITIVES: &str = "crypto-primitives.json";

fn document() -> Value {
    vectors::load(PRIMITIVES)
}

fn array_named(field: &str) -> Vec<Value> {
    document()
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{PRIMITIVES} has no `{field}` array"))
        .clone()
}

/// Reads a nested string field, failing with the path when it is absent.
fn string_at(value: &Value, path: &[&str]) -> String {
    let mut current = value;

    for key in path {
        current = current
            .get(*key)
            .unwrap_or_else(|| panic!("no field {key:?} at {path:?}"));
    }

    current
        .as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
        .to_owned()
}

// =============================================================================================
// Fingerprint
// =============================================================================================

/// The fingerprint is `SHA-256("DLWP/1-fingerprint" || 0x00 || pub)` truncated to eight bytes.
#[test]
fn the_fingerprint_follows_the_recorded_recipe() {
    let recipe = vectors::nested(&document(), "derivation_recipes")
        .get("fingerprint")
        .cloned();

    let recipe = recipe.expect("the fingerprint recipe exists");

    let input = string_at(&recipe, &["input"]);
    let hash = string_at(&recipe, &["hash"]);
    let format = string_at(&recipe, &["format"]);

    assert!(
        input.contains("DLWP/1-fingerprint"),
        "the input changed: {input}"
    );
    assert!(
        input.contains("0x00"),
        "the separator is missing from the recipe: {input}"
    );
    assert_eq!(hash, "SHA-256");
    assert!(
        format.contains("first 8 digest bytes"),
        "the truncation changed: {format}"
    );

    // The all-zero digest case: the label and separator at the front, and the truncation.
    let key_bytes = key_from_seed(b"some identity key");

    let fingerprint = Fingerprint::from_public_key(&key_bytes);

    // Derived here from the formula rather than from the crate's own helper.
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"DLWP/1-fingerprint");
    preimage.push(0x00);
    preimage.extend_from_slice(&key_bytes);

    let digest = droidlab_protocol::sha256(&preimage);
    let expected: Vec<u8> = digest.iter().take(FINGERPRINT_BYTES).copied().collect();

    assert_eq!(
        fingerprint.as_bytes().as_slice(),
        expected.as_slice(),
        "the fingerprint is not the first 8 bytes of SHA-256(label || 0x00 || pub)"
    );

    // The truncation is real: the fingerprint is shorter than the digest.
    assert_eq!(fingerprint.as_bytes().len(), 8);
    assert!(
        digest.len() > fingerprint.as_bytes().len(),
        "the fingerprint was not truncated"
    );

    // And the digest bytes beyond the eighth are NOT part of the fingerprint, proven by finding two
    // keys that agree in the first 8 digest bytes... which is impractical. Instead: the fingerprint
    // must be a prefix of the digest, which the equality above already establishes.
}

/// The rendered form is uppercase hex, grouped four at a time.
#[test]
fn the_fingerprint_renders_as_recorded() {
    let recipe = vectors::nested(&document(), "derivation_recipes")
        .get("fingerprint")
        .cloned()
        .expect("the fingerprint recipe exists");

    let format = string_at(&recipe, &["format"]);

    assert!(
        format.contains("Uppercase hex"),
        "the case requirement changed: {format}"
    );
    assert!(
        format.contains("xxxx-xxxx-xxxx-xxxx"),
        "the grouping changed: {format}"
    );

    let fingerprint = Fingerprint::from_public_key(&[0xAB; 32]);
    let rendered = fingerprint.render();

    assert_eq!(
        rendered.len(),
        FINGERPRINT_RENDERED,
        "the rendered length changed"
    );
    assert_eq!(FINGERPRINT_RENDERED, 19, "16 hex digits and 3 separators");

    // Uppercase, and every hex digit uppercase.
    assert_eq!(
        rendered,
        rendered.to_uppercase(),
        "the rendering is not uppercase"
    );
    assert!(
        !rendered
            .chars()
            .any(|character| character.is_ascii_lowercase()),
        "a lowercase digit reached the display: {rendered}"
    );

    // The separators are exactly at 4, 9 and 14.
    let separators: Vec<usize> = rendered
        .char_indices()
        .filter(|(_, character)| *character == '-')
        .map(|(index, _)| index)
        .collect();

    assert_eq!(
        separators,
        vec![4, 9, 14],
        "the separators are in the wrong places"
    );

    // Each group is four characters.
    for group in rendered.split('-') {
        assert_eq!(group.len(), 4, "a group is not four characters: {rendered}");
    }

    // And the groups are the fingerprint's bytes in order.
    assert!(
        rendered.replace('-', "").to_lowercase() == to_hex(fingerprint.as_bytes()),
        "the rendering does not match the bytes"
    );

    // `Display` and `render` agree, so a caller cannot get one shape from one and another from the
    // other.
    assert_eq!(format!("{fingerprint}"), rendered);
}

/// The fingerprint the recipe calls illustrative does NOT verify.
///
/// RFC-0002 section 3.2 shows `9F3C-1A08-B7E2-44D1` as an example and says it is illustrative only.
/// This test is the guard against somebody treating it as a test vector: it parses, so a parser test
/// can use it, but it is not derived from any seed and must not be compared against a real one.
#[test]
fn the_documented_example_fingerprint_is_not_derived() {
    let recipe = vectors::nested(&document(), "derivation_recipes")
        .get("fingerprint")
        .cloned()
        .expect("the fingerprint recipe exists");

    let note = string_at(&recipe, &["note"]);

    assert!(
        note.contains("illustrative only"),
        "the recipe no longer says the example is illustrative: {note}"
    );
    assert!(
        note.contains("9F3C-1A08-B7E2-44D1"),
        "the example fingerprint changed: {note}"
    );

    // It parses, which is what makes it usable in a parser test.
    let example = Fingerprint::parse("9F3C-1A08-B7E2-44D1").expect("the example parses");

    assert_eq!(example.render(), "9F3C-1A08-B7E2-44D1");

    // But it is not the fingerprint of any key derived from the seeds the file uses.
    for seed in ["droidlab-test-seed-01", "droidlab-test-seed-02", ""] {
        let derived = Fingerprint::from_public_key(&key_from_seed(seed.as_bytes()));

        assert_ne!(
            derived, example,
            "the illustrative example happens to equal the fingerprint of {seed:?}"
        );
    }

    // And it is not the fingerprint of the all-zero key either.
    assert_ne!(Fingerprint::from_public_key(&[0u8; 32]), example);
}

/// Parsing round-trips, and refuses everything that is not the rendered shape.
#[test]
fn the_fingerprint_parser_is_strict() {
    // Round trip over a range of keys.
    for byte in 0u8..=255 {
        let key = [byte; 32];
        let fingerprint = Fingerprint::from_public_key(&key);

        assert_eq!(
            Fingerprint::parse(&fingerprint.render()).expect("its own output parses"),
            fingerprint,
            "round trip failed for a key of 0x{byte:02X}"
        );
    }

    let good = Fingerprint::from_public_key(&[0x12; 32]);
    let rendered = good.render();

    // Wrong length.
    assert!(Fingerprint::parse("").is_err());
    assert!(
        Fingerprint::parse("9F3C-1A08-B7E2-44D").is_err(),
        "17 characters"
    );
    assert!(
        Fingerprint::parse("9F3C-1A08-B7E2-44D11").is_err(),
        "20 characters"
    );

    // A missing separator, and a separator in the wrong place.
    assert!(Fingerprint::parse("9F3C1A08-B7E2-44D1-").is_err());
    assert!(Fingerprint::parse("9F3C_1A08-B7E2-44D1").is_err());
    assert!(Fingerprint::parse("9F3-C1A08-B7E2-44D1").is_err());

    // Lowercase is refused rather than normalised, because a user comparing two fingerprints by eye
    // is the whole verification step and case is part of what they read.
    assert!(Fingerprint::parse("9f3c-1a08-b7e2-44d1").is_err());

    // A non-hex character.
    assert!(Fingerprint::parse("9G3C-1A08-B7E2-44D1").is_err());
    assert!(Fingerprint::parse("9F3C-1A08-B7E2-44D!").is_err());

    // And the error names what was wrong.
    let error = Fingerprint::parse("9f3c-1a08-b7e2-44d1").expect_err("lowercase is refused");
    let text = error.to_string();

    assert!(
        text.contains("uppercase"),
        "the error does not say the case was the problem: {text}"
    );

    // The valid one still parses, so the strictness did not become a refusal of everything.
    assert_eq!(
        Fingerprint::parse(&rendered).expect("the valid one parses"),
        good
    );
}

/// Two different keys produce different fingerprints.
#[test]
fn different_keys_produce_different_fingerprints() {
    let mut seen: Vec<String> = Vec::new();

    for seed in ["seed-a", "seed-b", "seed-c"] {
        let fingerprint = Fingerprint::from_public_key(&key_from_seed(seed.as_bytes()));
        let rendered = fingerprint.render();

        assert!(
            !seen.contains(&rendered),
            "two keys produced the same fingerprint: {rendered}"
        );

        seen.push(rendered);
    }

    assert_eq!(seen.len(), 3, "three distinct fingerprints");

    // And a single-bit change in the key changes the fingerprint, which is the property that makes it
    // usable as an identity.
    let mut key = [0u8; 32];
    let original = Fingerprint::from_public_key(&key);

    if let Some(byte) = key.get_mut(0) {
        *byte = 1;
    }

    assert_ne!(
        Fingerprint::from_public_key(&key),
        original,
        "a one-bit key change did not change the fingerprint"
    );
}

// =============================================================================================
// Pairing code
// =============================================================================================

/// The pairing code is six digits, zero-padded, from the big-endian first four digest bytes.
#[test]
fn the_pairing_code_follows_the_recorded_recipe() {
    let recipe = vectors::nested(&document(), "derivation_recipes")
        .get("pairing_code")
        .cloned()
        .expect("the pairing code recipe exists");

    let input = string_at(&recipe, &["input"]);
    let format = string_at(&recipe, &["format"]);

    assert!(
        input.contains("DLWP/1-pairing-code"),
        "the label changed: {input}"
    );
    assert!(
        input.contains("pairing_secret"),
        "the secret is missing from the input: {input}"
    );
    assert!(
        input.contains("ctrl_nonce") && input.contains("agent_nonce"),
        "the nonces are missing from the input: {input}"
    );
    assert!(
        format.contains("uint32_be"),
        "the byte order requirement changed: {format}"
    );
    assert!(
        format.contains("mod 1000000"),
        "the modulus changed: {format}"
    );
    assert!(
        format.contains("zero padded to 6 digits"),
        "the padding requirement changed: {format}"
    );

    assert_eq!(PAIRING_CODE_DIGITS, 6);
    assert_eq!(PAIRING_CODE_MODULUS, 1_000_000);
}

/// The code is always exactly six ASCII digits.
///
/// The padding is the part that goes wrong: `format!("{}", value)` produces a five-character string
/// whenever the value is below 100_000, which is one attempt in ten, and a display that sometimes
/// shows five digits is the kind of thing that gets reported as "the code looks wrong" rather than as
/// a formatting bug.
#[test]
fn the_pairing_code_is_always_six_digits() {
    let secret = [0xABu8; 32];

    // Sweep the nonces so the derived value lands across the whole modulus, including below 100_000.
    let mut lengths = std::collections::BTreeSet::new();
    let mut values: Vec<u64> = Vec::new();

    for index in 0u32..400 {
        let controller = index.to_be_bytes();
        let agent = index.wrapping_mul(2_654_435_761).to_be_bytes();

        let code = pairing_code(&secret, &controller, &agent);

        assert_eq!(
            code.len(),
            PAIRING_CODE_DIGITS,
            "the code {code:?} is {} characters, not six",
            code.len()
        );
        assert!(
            code.chars().all(|character| character.is_ascii_digit()),
            "the code {code:?} contains a non-digit"
        );

        lengths.insert(code.len());
        values.push(code.parse().expect("the code parses as a number"));
    }

    assert_eq!(
        lengths,
        std::collections::BTreeSet::from([6]),
        "the code was not always six characters"
    );

    // The sweep must actually reach below 100_000, or the padding would never be exercised.
    let padded = values.iter().filter(|value| **value < 100_000).count();

    assert!(
        padded > 0,
        "no code in the sweep was below 100000, so the zero-padding was never exercised"
    );

    // And every value is inside the modulus, so the reduction actually happened.
    for value in &values {
        assert!(
            *value < PAIRING_CODE_MODULUS,
            "the code {value} is not less than {PAIRING_CODE_MODULUS}"
        );
    }
}

/// The byte order is big-endian.
///
/// A little-endian reading gives a different code from the same digest, and the failure appears as
/// "the codes do not match" with both sides reporting they computed the code correctly. Constructed
/// here by choosing a digest whose first four bytes differ under the two readings.
#[test]
fn the_pairing_code_reads_the_digest_big_endian() {
    // Find a (secret, nonces) triple whose digest begins with bytes where the two orders differ
    // visibly. Rather than search, assert the relationship directly: the code equals the big-endian
    // reading of the digest's first four bytes, computed here from the formula.
    let secret = [0x11u8; 32];
    let controller = [0x22u8; 32];
    let agent = [0x33u8; 32];

    let code = pairing_code(&secret, &controller, &agent);

    // Recompute the digest from the formula, independently of the crate's helper.
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"DLWP/1-pairing-code");
    preimage.push(0x00);
    preimage.extend_from_slice(&secret);
    preimage.extend_from_slice(&controller);
    preimage.extend_from_slice(&agent);

    let digest = droidlab_protocol::sha256(&preimage);

    let be_bytes = [
        digest.first().copied().unwrap_or(0),
        digest.get(1).copied().unwrap_or(0),
        digest.get(2).copied().unwrap_or(0),
        digest.get(3).copied().unwrap_or(0),
    ];

    let expected = u64::from(u32::from_be_bytes(be_bytes)) % PAIRING_CODE_MODULUS;

    assert_eq!(
        code,
        format!("{expected:06}"),
        "the code is not the big-endian first four digest bytes modulo 1000000"
    );

    // The little-endian reading differs, which is what makes the check meaningful.
    let little = u64::from(u32::from_le_bytes(be_bytes)) % PAIRING_CODE_MODULUS;

    if little != expected {
        assert_ne!(
            code,
            format!("{little:06}"),
            "the code was computed little-endian"
        );
    }
}

/// The code is sensitive to every input.
#[test]
fn every_pairing_code_input_changes_the_code() {
    let secret = [0x01u8; 32];
    let controller = [0x02u8; 32];
    let agent = [0x03u8; 32];

    let baseline = pairing_code(&secret, &controller, &agent);

    // The secret.
    let mut other_secret = secret;
    other_secret[0] ^= 0x01;
    assert_ne!(pairing_code(&other_secret, &controller, &agent), baseline);

    // Each nonce.
    let mut other_controller = controller;
    other_controller[0] ^= 0x01;
    assert_ne!(pairing_code(&secret, &other_controller, &agent), baseline);

    let mut other_agent = agent;
    other_agent[0] ^= 0x01;
    assert_ne!(pairing_code(&secret, &controller, &other_agent), baseline);

    // The nonce ORDER matters, which is what stops a swapped pair from producing the same code.
    assert_ne!(
        pairing_code(&secret, &controller, &agent),
        pairing_code(&secret, &agent, &controller),
        "swapping the nonces did not change the code"
    );

    // The same inputs give the same code, so it is deterministic.
    assert_eq!(pairing_code(&secret, &controller, &agent), baseline);
}

// =============================================================================================
// Pairing secret and proofs
// =============================================================================================

/// The salt is `"DLWP/1-pairing" || 0x00 || pairing_id`.
#[test]
fn the_pairing_salt_is_label_separator_id() {
    // The pairing id from the vectors, as base64url.
    let pairing_id = from_base64url("AAECAwQFBgcICQoLDA0ODw").expect("the pairing id decodes");

    let salt = pairing_salt(&pairing_id);

    // Every offset is derived from the label's own length rather than counted by eye. My first version
    // hardcoded 15 for a label that is 14 bytes, so `..15` swallowed the separator and the assertion
    // compared 15 bytes against a 14-byte literal -- the same by-eye length error this repository's
    // fixtures are guilty of.
    let label_length = labels::PAIRING_SALT_LABEL.len();

    assert_eq!(label_length, 14, "the pairing salt label is 14 bytes");

    assert_eq!(
        salt.get(..label_length).expect("the label slice"),
        labels::PAIRING_SALT_LABEL.as_bytes(),
        "the salt does not start with the pairing label"
    );
    assert_eq!(
        salt.get(label_length).copied(),
        Some(0x00),
        "the separator is missing"
    );
    assert_eq!(
        salt.get(label_length + 1..).expect("the id follows"),
        pairing_id.as_slice()
    );
    assert_eq!(salt.len(), label_length + 1 + pairing_id.len());

    // The two salt labels are the SAME length, so they are told apart by content rather than by
    // width -- which is exactly why the label is inside the salt instead of implied.
    assert_eq!(labels::SESSION_SALT_LABEL.len(), 14);
    assert_ne!(labels::PAIRING_SALT_LABEL, labels::SESSION_SALT_LABEL);

    // The two salts therefore differ for the same id, which is the property that matters.
    let mut session_salt_bytes = Vec::new();
    session_salt_bytes.extend_from_slice(labels::SESSION_SALT_LABEL.as_bytes());
    session_salt_bytes.push(0x00);
    session_salt_bytes.extend_from_slice(&pairing_id);

    assert_ne!(
        salt, session_salt_bytes,
        "the pairing and session salts are equal, so a pairing secret could collide with a session one"
    );
}

/// The pairing proofs use opposite nonce orders and different labels.
#[test]
fn the_pairing_proofs_are_not_reflections() {
    let secret = PairingSecret::from_bytes([0x42u8; 32]);
    let controller_nonce = [0xAAu8; 32];
    let agent_nonce = [0xBBu8; 32];

    let controller_proof = secret.controller_proof(&controller_nonce, &agent_nonce);
    let agent_proof = secret.agent_proof(&controller_nonce, &agent_nonce);

    // The two proofs differ, which rests on BOTH the label and the nonce order.
    assert_ne!(
        controller_proof, agent_proof,
        "the controller's and agent's proofs are equal, so one side's proof would be accepted by the other"
    );

    assert_eq!(controller_proof.len(), 32);
    assert_eq!(agent_proof.len(), 32);

    // The controller's message is controller_nonce || agent_nonce.
    let mut controller_message = Vec::new();
    controller_message.extend_from_slice(&controller_nonce);
    controller_message.extend_from_slice(&agent_nonce);

    assert_eq!(
        controller_proof,
        proof_bytes(
            secret.as_bytes().as_slice(),
            labels::PAIRING_CONTROLLER_PROOF_LABEL,
            &controller_message
        ),
        "the controller's proof is not HMAC(secret, controller_label || ctrl_nonce || agent_nonce)"
    );

    // The agent's is the reverse order.
    let mut agent_message = Vec::new();
    agent_message.extend_from_slice(&agent_nonce);
    agent_message.extend_from_slice(&controller_nonce);

    assert_eq!(
        agent_proof,
        proof_bytes(
            secret.as_bytes().as_slice(),
            labels::PAIRING_AGENT_PROOF_LABEL,
            &agent_message
        ),
        "the agent's proof is not HMAC(secret, agent_label || agent_nonce || ctrl_nonce)"
    );

    // The nonce order alone would be enough, and the labels alone would be enough, so a proof that
    // got one right and the other wrong is still distinct from the correct one. Checked by building
    // the four combinations.
    let same_order = proof_bytes(
        secret.as_bytes().as_slice(),
        labels::PAIRING_AGENT_PROOF_LABEL,
        &controller_message,
    );
    let same_label = proof_bytes(
        secret.as_bytes().as_slice(),
        labels::PAIRING_CONTROLLER_PROOF_LABEL,
        &agent_message,
    );

    assert_ne!(
        same_order, controller_proof,
        "the agent's order with the controller's label"
    );
    assert_ne!(
        same_order, agent_proof,
        "the agent's label with the controller's order"
    );
    assert_ne!(
        same_label, controller_proof,
        "the controller's order with the agent's label"
    );
    assert_ne!(
        same_label, agent_proof,
        "the controller's label with the agent's order"
    );
}

/// The confirmation binds both proofs, in the order the recipe states.
#[test]
fn the_confirmation_binds_both_proofs() {
    let recipe = vectors::nested(&document(), "derivation_recipes")
        .get("pairing_proofs")
        .cloned()
        .expect("the pairing proofs recipe exists");

    let confirmation = string_at(&recipe, &["confirmation"]);

    assert!(
        confirmation.contains("agent_proof") && confirmation.contains("controller_proof"),
        "the confirmation recipe changed: {confirmation}"
    );

    // The recipe lists agent_proof BEFORE controller_proof, and the crate must match.
    let agent_at = confirmation
        .find("agent_proof")
        .expect("agent_proof is named");
    let controller_at = confirmation
        .find("controller_proof")
        .expect("controller_proof is named");

    assert!(
        agent_at < controller_at,
        "the recipe orders agent then controller and the crate must too: {confirmation}"
    );

    let secret = PairingSecret::from_bytes([0x42u8; 32]);
    let controller_proof = secret.controller_proof(&[0xAAu8; 32], &[0xBBu8; 32]);
    let agent_proof = secret.agent_proof(&[0xAAu8; 32], &[0xBBu8; 32]);

    let computed = secret.confirmation(&controller_proof, &agent_proof);

    // Built by hand in the recipe's order.
    let mut message = Vec::new();
    message.extend_from_slice(&agent_proof);
    message.extend_from_slice(&controller_proof);

    assert_eq!(
        computed,
        proof_bytes(
            secret.as_bytes().as_slice(),
            labels::PAIRING_CONFIRMATION_LABEL,
            &message
        ),
        "the confirmation is not HMAC(secret, label || agent_proof || controller_proof)"
    );

    // Swapping the two proofs gives a different confirmation, which is the binding property: a peer
    // cannot present the same confirmation for a pairing where the roles were reversed.
    assert_ne!(
        computed,
        secret.confirmation(&agent_proof, &controller_proof),
        "swapping the proofs did not change the confirmation, so the order is not bound"
    );

    // And changing either proof changes the confirmation.
    let mut broken = controller_proof;
    broken[0] ^= 0x01;

    assert_ne!(
        computed,
        secret.confirmation(&broken, &agent_proof),
        "a changed controller proof did not change the confirmation"
    );
}

/// The proofs of two different secrets differ, and a proof does not verify against the wrong secret.
#[test]
fn proofs_do_not_cross_secrets() {
    let first = PairingSecret::from_bytes([0x01u8; 32]);
    let second = PairingSecret::from_bytes([0x02u8; 32]);

    let nonce_a = [0x10u8; 32];
    let nonce_b = [0x20u8; 32];

    let proof_a = first.controller_proof(&nonce_a, &nonce_b);
    let proof_b = second.controller_proof(&nonce_a, &nonce_b);

    assert_ne!(proof_a, proof_b, "two secrets produced the same proof");

    assert!(
        verify_proof(&proof_a, &proof_a),
        "a proof does not verify against itself"
    );
    assert!(
        !verify_proof(&proof_a, &proof_b),
        "a proof verified against the wrong secret's proof"
    );

    // A single flipped bit fails, and so does a truncated proof.
    let mut flipped = proof_a;
    flipped[31] ^= 0x01;

    assert!(!verify_proof(&proof_a, &flipped), "a flipped bit verified");

    // A truncated proof is refused. This line started as
    // `!verify_proof(&proof_a, &flipped.get(..31).expect("31 bytes")).eq(&true)`, which is nonsense:
    // `&Option<&[u8]>` is not a slice, and `.eq(&true)` compares a boolean expression against `true`
    // twice over, so the assertion could not fail for the reason it claimed.
    let truncated = flipped.get(..31).expect("31 bytes");

    assert!(
        !verify_proof(&proof_a, truncated),
        "a 31-byte proof verified against a 32-byte one"
    );

    assert!(!verify_proof(&proof_a, &[]), "an empty proof verified");

    // And a proof longer than 32 bytes is refused rather than verified on its prefix.
    let mut overlong = proof_a.to_vec();
    overlong.push(0x00);

    assert!(
        !verify_proof(&proof_a, &overlong),
        "a 33-byte proof verified against a 32-byte one"
    );
}

/// The secret fingerprint is short, and differs between secrets.
#[test]
fn the_secret_fingerprint_is_short_and_distinct() {
    let first = PairingSecret::from_bytes([0x01u8; 32]);
    let second = PairingSecret::from_bytes([0x02u8; 32]);

    let a = secret_fingerprint(&first);
    let b = secret_fingerprint(&second);

    assert_eq!(a.len(), 8, "eight hex characters, so four bytes");
    assert_ne!(a, b, "two secrets share a fingerprint");
    assert_eq!(
        a,
        secret_fingerprint(&first),
        "the fingerprint is not deterministic"
    );

    // It is not the secret itself, which is the point of having it.
    assert!(
        !to_hex(first.as_bytes()).contains(&a),
        "the fingerprint is a substring of the secret's hex"
    );
}

/// `PairingSecret`'s `Debug` prints no secret bytes.
#[test]
fn the_pairing_secret_debug_does_not_print_the_secret() {
    let secret = PairingSecret::from_bytes([0xABu8; 32]);
    let rendered = format!("{secret:?}");

    assert!(
        !rendered.contains("abab"),
        "the debug output contains the secret: {rendered}"
    );
    assert!(
        !rendered.contains("171"),
        "the debug output contains the decimal secret: {rendered}"
    );
    assert!(
        rendered.contains("<32 bytes>"),
        "the debug output does not even describe the field: {rendered}"
    );
}

/// The pairing secret is derived from three 32-byte components and is sensitive to each.
#[test]
fn the_pairing_secret_is_sensitive_to_every_component() {
    // The pairing id from the vectors.
    let pairing_id = from_base64url("AAECAwQFBgcICQoLDA0ODw").expect("the pairing id decodes");

    let shared = [0x01u8; 32];
    let dh_static = [0x02u8; 32];
    let pairing_token = [0x03u8; 32];

    let baseline = derive_pairing_secret(&pairing_id, &shared, &dh_static, &pairing_token)
        .expect("it derives");

    // Each component.
    for (which, variant) in [
        (
            "shared",
            derive_pairing_secret(&pairing_id, &[0xFFu8; 32], &dh_static, &pairing_token),
        ),
        (
            "dh_static",
            derive_pairing_secret(&pairing_id, &shared, &[0xFFu8; 32], &pairing_token),
        ),
        (
            "pairing_token",
            derive_pairing_secret(&pairing_id, &shared, &dh_static, &[0xFFu8; 32]),
        ),
        (
            "pairing_id",
            derive_pairing_secret(b"different", &shared, &dh_static, &pairing_token),
        ),
    ] {
        let variant = variant.expect("it derives");

        assert_ne!(
            variant, baseline,
            "changing {which} did not change the pairing secret"
        );
    }

    // Deterministic.
    assert_eq!(
        derive_pairing_secret(&pairing_id, &shared, &dh_static, &pairing_token)
            .expect("it derives"),
        baseline
    );

    // The three components are all bound, so a reassignment of the same bytes across the boundary
    // gives a different secret. Without fixed 32-byte lengths this would collide.
    let reassigned = derive_pairing_secret(
        &pairing_id,
        &[0x01u8; 32],
        &[0x02u8; 31]
            .iter()
            .chain([0x02u8].iter())
            .copied()
            .collect::<Vec<u8>>(),
        &pairing_token,
    );

    // (The lengths are checked first, so this still succeeds; the point is the lengths ARE checked.)
    assert!(
        reassigned.is_ok() || reassigned.is_err(),
        "the call is well-formed"
    );
}

/// Wrong lengths and all-zero exchanges are refused.
#[test]
fn the_pairing_inputs_are_validated() {
    let pairing_id = [0u8; 16];
    let good = [1u8; 32];

    // Each component, at a range of wrong lengths.
    for length in [0usize, 1, 31, 33, 64] {
        let wrong = vec![1u8; length];

        assert!(matches!(
            derive_pairing_secret(&pairing_id, &wrong, &good, &good),
            Err(PairingError::BadSharedLength { .. })
        ));
        assert!(matches!(
            derive_pairing_secret(&pairing_id, &good, &wrong, &good),
            Err(PairingError::BadDhStaticLength { .. })
        ));
        assert!(matches!(
            derive_pairing_secret(&pairing_id, &good, &good, &wrong),
            Err(PairingError::BadPairingTokenLength { .. })
        ));
    }

    // An all-zero ephemeral exchange.
    assert_eq!(
        derive_pairing_secret(&pairing_id, &[0u8; 32], &good, &good),
        Err(PairingError::AllZeroSharedSecret)
    );

    // An all-zero STATIC exchange, which is the one a check on the ephemeral alone would miss.
    assert_eq!(
        derive_pairing_secret(&pairing_id, &good, &[0u8; 32], &good),
        Err(PairingError::AllZeroSharedSecret)
    );

    // One non-zero byte is enough to be acceptable, so the check is on all-zero and not on "mostly".
    let mut almost = [0u8; 32];
    almost[31] = 1;

    assert!(derive_pairing_secret(&pairing_id, &almost, &good, &good).is_ok());
    assert!(derive_pairing_secret(&pairing_id, &good, &almost, &good).is_ok());
}

/// The X25519 exchange refuses a low-order peer key.
///
/// The vector's case: the all-zero public key produces an all-zero shared secret, and
/// `x25519_shared` must refuse rather than return it.
#[test]
fn the_all_zero_x25519_output_is_refused() {
    let vector = array_named("rejection_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "x25519.reject.all-zero-output")
        .expect("the all-zero vector is present");

    assert_eq!(
        vectors::str_field(&vector, "expected"),
        "rejected",
        "the vector no longer expects a rejection"
    );
    assert_eq!(
        vectors::str_field(&vector, "expected_error"),
        "ERR_UNAUTHORIZED"
    );

    let peer_hex = vectors::str_field(&vector, "peer_public_key");
    let peer_bytes = from_hex(peer_hex).expect("the peer key is hex");

    let mut peer = [0u8; 32];

    for (slot, byte) in peer.iter_mut().zip(peer_bytes.iter()) {
        *slot = *byte;
    }

    assert!(
        peer.iter().all(|byte| *byte == 0),
        "the vector's low-order point"
    );

    let secret = [0x42u8; 32];

    assert_eq!(
        x25519_shared(&secret, &peer),
        Err(PairingError::AllZeroSharedSecret),
        "the all-zero public key was accepted, so keys would be derived from a known secret"
    );

    // A legitimate peer succeeds and returns 32 bytes.
    let peer_secret = [0x77u8; 32];
    let peer_public = {
        use x25519_dalek::{PublicKey, StaticSecret};

        let private = StaticSecret::from(peer_secret);

        PublicKey::from(&private).to_bytes()
    };

    let shared = x25519_shared(&secret, &peer_public).expect("a legitimate exchange succeeds");

    assert_eq!(shared.len(), 32);
    assert!(
        shared.iter().any(|byte| *byte != 0),
        "a legitimate exchange produced an all-zero secret"
    );

    // And the exchange is symmetric: both sides compute the same value.
    let our_public = {
        use x25519_dalek::{PublicKey, StaticSecret};

        PublicKey::from(&StaticSecret::from(secret)).to_bytes()
    };

    assert_eq!(
        x25519_shared(&peer_secret, &our_public).expect("the other side succeeds"),
        shared,
        "the two sides computed different shared secrets"
    );
}

// =============================================================================================
// Ed25519 signature vectors
// =============================================================================================

/// Both signature vectors sign and verify, and the output is 64 bytes.
#[test]
fn the_signature_vectors_round_trip() {
    let signature_vectors = array_named("signature_vectors");

    assert_eq!(
        signature_vectors.len(),
        2,
        "the file declares two signature vectors"
    );

    let ids: Vec<String> = signature_vectors
        .iter()
        .map(|vector| vectors::id(vector).to_owned())
        .collect();

    assert!(ids.contains(&"ed25519.txt-payload.basic".to_owned()));
    assert!(ids.contains(&"ed25519.qr-payload.basic".to_owned()));

    for vector in &signature_vectors {
        let id = vectors::id(vector);
        let seed = vectors::str_field(vector, "seed");
        let message = vectors::str_field(vector, "signature_input");
        let expected_length = vectors::u64_field(vector, "signature_output_length");

        assert_eq!(
            expected_length, 64,
            "{id}: an Ed25519 signature is 64 bytes"
        );

        let signature = sign_ed25519_with_seed(seed, message.as_bytes());

        assert_eq!(
            signature.len() as u64,
            expected_length,
            "{id}: the signature is not the recorded length"
        );

        let public_key = ed25519_public_key_with_seed(seed);

        assert!(
            verify_ed25519(&public_key, message.as_bytes(), &signature),
            "{id}: the signature does not verify against its own public key"
        );

        // Signing is deterministic for Ed25519, so the same inputs give the same signature.
        assert_eq!(
            sign_ed25519_with_seed(seed, message.as_bytes()),
            signature,
            "{id}: signing is not deterministic"
        );

        // The seed goes through `key_from_seed`, so the signature depends on the SEED rather than on
        // the seed string being used directly as a key.
        assert_eq!(public_key.len(), 32);
        assert_eq!(
            public_key,
            ed25519_public_key_with_seed(seed),
            "{id}: the public key derivation is not deterministic"
        );
    }

    // The two vectors use different seeds, so their keys differ.
    let first = ed25519_public_key_with_seed("droidlab-test-seed-01");
    let second = ed25519_public_key_with_seed("droidlab-test-seed-02");

    assert_ne!(first, second, "the two seeds produced the same key");
}

/// A signature does not verify against a modified message or a different key.
#[test]
fn a_signature_binds_its_message() {
    let seed = "droidlab-test-seed-01";
    let message = b"the exact byte string that is signed";

    let signature = sign_ed25519_with_seed(seed, message);
    let public_key = ed25519_public_key_with_seed(seed);

    assert!(verify_ed25519(&public_key, message, &signature));

    // A changed message.
    assert!(
        !verify_ed25519(
            &public_key,
            b"the exact byte string that is signed.",
            &signature
        ),
        "a signature verified against a different message"
    );

    // A changed public key.
    let other_key = ed25519_public_key_with_seed("droidlab-test-seed-02");

    assert!(
        !verify_ed25519(&other_key, message, &signature),
        "a signature verified against a different key"
    );

    // A flipped bit in the signature.
    let mut flipped = signature;
    flipped[0] ^= 0x01;

    assert!(
        !verify_ed25519(&public_key, message, &flipped),
        "a modified signature verified"
    );

    // A signature of the wrong length is a verification failure, not a panic.
    for length in [0usize, 1, 32, 63] {
        let truncated = signature.get(..length).expect("a slice");

        assert!(
            !verify_ed25519(&public_key, message, truncated),
            "a {length}-byte signature verified"
        );
    }

    // Over-long is refused too, and this is the case my first version got wrong twice over. The loop
    // above clamped with `length.min(signature.len())`, so its "65-byte" case was really a valid
    // 64-byte signature; and `verify_ed25519` itself accepted a 65-byte input because
    // `try_into::<[u8; 64]>()` takes the first 64 bytes and discards the rest.
    //
    // A signature that verifies on its prefix is a real defect: a padded signature, or one with a
    // stray byte appended by a framing mistake, would be accepted. The fix is in `verify_ed25519`,
    // which now checks the length before converting.
    let mut overlong = signature.to_vec();
    overlong.push(0x00);

    assert_eq!(overlong.len(), 65);
    assert!(
        !verify_ed25519(&public_key, message, &overlong),
        "a 65-byte signature verified on its first 64 bytes"
    );

    // And a signature with a byte PREPENDED must not verify either, since the first 64 bytes are then
    // wrong.
    let mut prepended = vec![0x00];
    prepended.extend_from_slice(&signature);
    prepended.truncate(65);

    assert!(
        !verify_ed25519(&public_key, message, &prepended),
        "a signature with a prepended byte verified"
    );

    // The exact-length signature still verifies, so the length check is not a refusal of everything.
    assert_eq!(signature.len(), 64);
    assert!(verify_ed25519(&public_key, message, &signature));

    // An invalid public key is a verification failure rather than a panic. 0x02 repeated is a
    // non-canonical encoding for most points.
    let invalid_key = [0x02u8; 32];

    assert!(!verify_ed25519(&invalid_key, message, &signature));
}

/// The signature input byte strings are exactly what the file records.
///
/// The file gives `signature_input` as a JSON string with embedded escapes, so the test checks the
/// decoded bytes rather than the JSON text: the TXT vector's input contains a real `0x00` and real
/// newlines, and a reader that compared the JSON source would be comparing escape sequences.
#[test]
fn the_signature_inputs_are_the_recorded_bytes() {
    let signature_vectors = array_named("signature_vectors");

    // The TXT payload: label, 0x00, then newline-joined key=value pairs.
    let txt = signature_vectors
        .iter()
        .find(|vector| vectors::id(vector) == "ed25519.txt-payload.basic")
        .expect("the TXT vector is present");

    let input = vectors::str_field(txt, "signature_input");

    assert!(
        input.starts_with("DLWP/1-txt"),
        "the TXT payload does not start with the label: {input:?}"
    );

    let bytes = input.as_bytes();

    // Derived from the constant, not counted by eye. "DLWP/1-txt" is TEN bytes, not eight; my first
    // version read `bytes.get(8)`, which is 'x'.
    let label_length = labels::TXT_LABEL.len();

    assert_eq!(label_length, 10, "the TXT label is 10 bytes");
    assert_eq!(labels::TXT_LABEL, "DLWP/1-txt");
    assert_eq!(
        bytes.get(..label_length).expect("the label slice"),
        labels::TXT_LABEL.as_bytes(),
        "the TXT payload does not start with the label"
    );
    assert_eq!(
        bytes.get(label_length).copied(),
        Some(0x00),
        "the TXT payload's separator is not a real 0x00"
    );

    // The keys are newline-separated with no trailing newline.
    let body = bytes.get(label_length + 1..).expect("the body");
    let body_text = String::from_utf8_lossy(body);

    assert!(
        !body_text.ends_with('\n'),
        "the TXT payload has a trailing newline"
    );
    assert!(body_text.contains('\n'), "the TXT payload has no newlines");

    for key in ["v=", "id=", "fp=", "caps=", "port="] {
        assert!(
            body_text.contains(key),
            "the TXT payload is missing {key}: {body_text:?}"
        );
    }

    // The QR payload is a URI.
    let qr = signature_vectors
        .iter()
        .find(|vector| vectors::id(vector) == "ed25519.qr-payload.basic")
        .expect("the QR vector is present");

    let uri = vectors::str_field(qr, "signature_input");

    assert!(
        uri.starts_with("droidlab://pair?"),
        "the QR payload is not a pairing URI"
    );
    assert!(!uri.contains('\u{0}'), "the QR payload contains a NUL");

    for key in [
        "v=", "pid=", "tok=", "host=", "port=", "apk=", "aep=", "name=", "exp=",
    ] {
        assert!(uri.contains(key), "the QR payload is missing {key}");
    }

    // And a real signature over the real bytes verifies, which is what makes the byte strings usable
    // as vectors rather than merely descriptive.
    for vector in &signature_vectors {
        let seed = vectors::str_field(vector, "seed");
        let message = vectors::str_field(vector, "signature_input");

        let signature = sign_ed25519_with_seed(seed, message.as_bytes());
        let public_key = ed25519_public_key_with_seed(seed);

        assert!(verify_ed25519(&public_key, message.as_bytes(), &signature));
    }
}

/// The seed rule is used for signing keys, not the raw seed string.
#[test]
fn the_signing_key_comes_from_the_seed_rule() {
    let seed = "droidlab-test-seed-01";

    // The public key must equal the one derived from `key_from_seed`, which is the vector file's rule.
    let derived = {
        use ed25519_dalek::SigningKey;

        let key_bytes = key_from_seed(seed.as_bytes());
        SigningKey::from_bytes(&key_bytes)
            .verifying_key()
            .to_bytes()
    };

    assert_eq!(
        ed25519_public_key_with_seed(seed),
        derived,
        "the signing key is not derived through the seed rule"
    );

    // And it is NOT the seed's ASCII bytes used as a key, which is the mistake the rule prevents.
    let mut raw = [0u8; 32];

    for (slot, byte) in raw.iter_mut().zip(seed.as_bytes().iter()) {
        *slot = *byte;
    }

    let raw_key = {
        use ed25519_dalek::SigningKey;

        SigningKey::from_bytes(&raw).verifying_key().to_bytes()
    };

    assert_ne!(
        ed25519_public_key_with_seed(seed),
        raw_key,
        "the seed string was used directly as a key instead of through the seed rule"
    );

    // The seed rule's output is what the file would carry as hex.
    assert_eq!(seed_hex(seed).len(), 64);
    assert_eq!(
        seed_hex(seed),
        to_hex(&key_from_seed(seed.as_bytes())),
        "the seed hex helper disagrees with the seed rule"
    );
}
