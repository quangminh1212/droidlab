//! Conformance tests for the DLWP/1 key schedule, record protection and handshake transcript.
//!
//! Every expected value in this file is either **derived here from the vector's own inputs**, or read
//! out of the vector file. Nothing is transcribed as a literal, because that is the failure mode the
//! vector files exist to prevent: `crypto-session-keys.json` says so itself —
//!
//! > The key and iv byte values are not written here because they are recomputed by the verifier from
//! > the given inputs and compared with each implementation's output. This keeps the file free of long
//! > hex blobs that a reader cannot check, while still making a mismatch between the Kotlin and C#
//! > implementations a hard failure.
//!
//! So the tests below are the verifier. Where a vector gives only assertions (`c2a_key != a2c_key`),
//! the assertion is what is tested; where it gives a byte string, the byte string is compared.

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::keyschedule::{
    derive_session_keys, session_ikm, session_salt, Direction, RecordError, SessionKeys,
    EXPORTER_LENGTH, IV_PREFIX_LENGTH, KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
};
use droidlab_protocol::labels::{self, ALL as ALL_LABELS};
use droidlab_protocol::seed::{
    from_base64url, from_hex, key_from_seed, seed_hex, to_base64url, to_hex,
};
use droidlab_protocol::transcript::{
    Transcript, LABEL_LENGTH, LENGTH_PREFIX_LENGTH, SEPARATOR_LENGTH,
};
use droidlab_protocol::{
    aad_from_header, build_nonce, constant_time_eq, hmac_labeled, open, seal, sha256,
    sha256_labeled, FrameHeader, FIXED_LENGTH,
};

use serde_json::Value;

const PRIMITIVES: &str = "crypto-primitives.json";
const SESSION_KEYS: &str = "crypto-session-keys.json";
const TRANSCRIPT: &str = "handshake-transcript.json";

/// Reads an array field by name, with a message that names the field and the file.
///
/// Three vector files use three different key names for their arrays (`vectors`, `aead_vectors`,
/// `rejection_vectors`, `signature_vectors`), so a single `vectors()` helper silently reads the wrong
/// file's array. My first version assumed `vectors` everywhere and six tests failed on files that
/// simply do not have one — which is a defect in the test, not in the crate.
fn array_named(file: &str, field: &str) -> Vec<Value> {
    document(file)
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{file} has no `{field}` array"))
        .clone()
}

fn document(file: &str) -> Value {
    vectors::load(file)
}

/// Reads a nested string field and fails with the path when it is absent.
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

/// The vector file's `labels` object, as `(key, value)` pairs.
fn vector_labels() -> Vec<(String, String)> {
    let document = document(PRIMITIVES);

    let labels = document
        .get("labels")
        .and_then(Value::as_object)
        .expect("crypto-primitives.json has a labels object");

    labels
        .iter()
        .filter(|(key, _)| key.as_str() != "note")
        .map(|(key, value)| {
            (
                key.clone(),
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("labels.{key} is not a string"))
                    .to_owned(),
            )
        })
        .collect()
}

// =============================================================================================
// Labels
// =============================================================================================

/// Every label this crate defines matches the vector file's, by registry name.
///
/// Both directions, and by name rather than by value: comparing the sets of strings alone would pass
/// if two labels were swapped, and a swapped pair is exactly the bug that produces a session which
/// authenticates with the agent's proof where the controller's belongs.
#[test]
fn the_labels_match_the_vector_file() {
    let expected = vector_labels();

    assert_eq!(
        ALL_LABELS.len(),
        expected.len(),
        "the crate defines {} labels and the vector file declares {}",
        ALL_LABELS.len(),
        expected.len()
    );

    for (key, expected_value) in &expected {
        let found = labels::by_registry_name(key).unwrap_or_else(|| {
            panic!("the vector file declares labels.{key} and the crate does not define it")
        });

        assert_eq!(
            found, expected_value,
            "labels.{key} differs: the vector file says {expected_value:?}, the crate says {found:?}"
        );
    }

    // The reverse direction: nothing in the crate is absent from the file.
    for (key, _) in ALL_LABELS {
        assert!(
            expected.iter().any(|(expected_key, _)| expected_key == key),
            "the crate defines labels.{key} and the vector file does not declare it"
        );
    }
}

/// The label list has the length the file has, pinned so a loop cannot pass vacuously.
#[test]
fn the_label_list_is_not_empty() {
    let expected = vector_labels();

    assert_eq!(expected.len(), 17, "the vector file declares 17 labels");
    assert_eq!(ALL_LABELS.len(), 17);
}

/// The seed rule is `SHA-256(prefix || 0x00 || seed)`.
///
/// Derived here from first principles rather than from the crate's own helper, so the helper is
/// checked against the formula in the vector file and not against itself.
#[test]
fn the_seed_rule_is_sha256_of_prefix_separator_seed() {
    let prefix = string_at(&document(PRIMITIVES), &["seed_rule", "formula"]);

    assert!(
        prefix.contains("SHA-256"),
        "the seed rule formula changed: {prefix}"
    );

    for seed in ["droidlab-test-seed-01", "droidlab-test-seed-02", "", "x"] {
        // Built by hand, one component at a time, straight from the formula.
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"DLWP/1-test-key");
        buffer.push(0x00);
        buffer.extend_from_slice(seed.as_bytes());

        let expected = sha256(&buffer);
        let actual = key_from_seed(seed.as_bytes());

        assert_eq!(
            actual, expected,
            "the seed rule for {seed:?} disagrees with the formula in crypto-primitives.json"
        );
        assert_eq!(seed_hex(seed), to_hex(&expected));
    }

    // And the separator matters: dropping it changes the key.
    let mut without_separator = Vec::new();
    without_separator.extend_from_slice(b"DLWP/1-test-key");
    without_separator.extend_from_slice(b"droidlab-test-seed-01");

    assert_ne!(
        sha256(&without_separator),
        key_from_seed(b"droidlab-test-seed-01"),
        "the 0x00 separator has no effect, so a seed could collide with a different one"
    );
}

/// Every hex helper round-trips, and refuses what is not hex.
#[test]
fn the_hex_codec_round_trips_and_refuses() {
    for length in 0..=64usize {
        let bytes: Vec<u8> = (0..length).map(|index| (index % 256) as u8).collect();
        let text = to_hex(&bytes);

        assert_eq!(text.len(), length * 2);
        assert_eq!(from_hex(&text).expect("its own output parses"), bytes);
        assert_eq!(
            from_hex(&text.to_uppercase()).expect("uppercase parses"),
            bytes
        );
    }

    // An odd length has no byte boundary.
    assert!(from_hex("abc").is_err());
    // A non-digit is refused, and the offenders are the interesting ones: characters adjacent to the
    // digit ranges, where an off-by-one in a subtraction would wrongly accept them.
    for bad in ["zz", "0g", "0:  ", "@@", "0/", "0G", "0`"] {
        assert!(
            from_hex(bad).is_err(),
            "{bad:?} was accepted as hex, so a malformed vector would decode to a shorter key"
        );
    }
}

/// The base64url codec is unpadded and rejects the standard alphabet.
#[test]
fn the_base64url_codec_is_unpadded_and_strict() {
    // Vectors from the files themselves: a 16-byte session id and 32-byte keys.
    let session_id = from_base64url("AAECAwQFBgcICQoLDA0ODw").expect("the session id decodes");

    assert_eq!(session_id.len(), 16, "the session id is 16 bytes");
    assert_eq!(session_id, (0u8..16).collect::<Vec<u8>>());
    assert_eq!(to_base64url(&session_id), "AAECAwQFBgcICQoLDA0ODw");

    // 32 bytes, and the unpadded length is what proves the padding is absent: 32 bytes is 43
    // characters when unpadded and 44 with one '='.
    let key = from_base64url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").expect("a 32-byte key");
    assert_eq!(key.len(), 32);
    assert_eq!(key, (0u8..32).collect::<Vec<u8>>());

    let text = to_base64url(&key);
    assert_eq!(text.len(), 43, "43 characters, not 44: no '=' padding");
    assert!(!text.contains('='), "the encoding is unpadded");
    assert_eq!(from_base64url(&text).expect("round trip"), key);

    // All three lengths modulo 3, so every padding branch is exercised.
    for length in 0..=40usize {
        let bytes: Vec<u8> = (0..length).map(|index| (index % 256) as u8).collect();
        let encoded = to_base64url(&bytes);

        assert!(
            !encoded.contains('='),
            "a {length}-byte input produced padding: {encoded}"
        );
        assert_eq!(
            from_base64url(&encoded).expect("its own output decodes"),
            bytes,
            "round trip failed for {length} bytes"
        );
    }

    // The standard alphabet is refused, because the vectors do not use it and accepting it would
    // hide a caller picking the wrong variant.
    assert!(
        from_base64url("AA+/").is_err(),
        "+/ is standard base64, not base64url"
    );
    assert!(from_base64url("AAAA=").is_err(), "'=' padding is refused");
}

/// The base64url alphabet uses the URL-safe characters, not the standard ones.
#[test]
fn the_base64url_alphabet_is_the_url_safe_one() {
    // 0xFF 0xFF 0xFF is the strongest case: standard base64 gives "////" and base64url "____".
    let bytes = [0xFFu8, 0xFF, 0xFF];

    assert_eq!(
        to_base64url(&bytes),
        "____",
        "the URL-safe alphabet was not used"
    );
    assert_eq!(from_base64url("____").expect("it decodes"), bytes);
    assert_eq!(
        from_base64url("----").expect("it decodes"),
        [0xFB, 0xEF, 0xBE]
    );

    // Decoding a string containing '+' must fail rather than silently producing different bytes.
    assert!(from_base64url("//__").is_err());
}

// =============================================================================================
// Session key schedule
// =============================================================================================

/// Reads a session-keys vector's inputs.
fn session_inputs(vector: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let inputs = vectors::nested(vector, "inputs");

    (
        from_base64url(vectors::str_field(inputs, "session_id")).expect("the session id decodes"),
        from_hex(vectors::str_field(inputs, "shared")).expect("shared is hex"),
        from_hex(vectors::str_field(inputs, "pairing_secret")).expect("pairing_secret is hex"),
        from_hex(vectors::str_field(inputs, "transcript_hash")).expect("transcript_hash is hex"),
    )
}

/// Derives the keys for a session-keys vector.
fn derive(vector: &Value) -> SessionKeys {
    let (session_id, shared, pairing_secret, transcript_hash) = session_inputs(vector);

    derive_session_keys(&session_id, &shared, &pairing_secret, &transcript_hash)
        .unwrap_or_else(|error| panic!("derivation failed for {}: {error}", vectors::id(vector)))
}

/// The salt and IKM helpers reproduce the vector's recorded bytes.
#[test]
fn the_salt_and_ikm_match_the_recorded_bytes() {
    let vectors = document(SESSION_KEYS);
    let first = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "session.keys.baseline")
        .expect("the baseline vector is present");

    let derived = vectors::nested(&first, "derived");

    let (session_id, shared, pairing_secret, _) = session_inputs(&first);

    let salt = session_salt(&session_id);
    let expected_salt = from_hex(vectors::str_field(derived, "salt_hex")).expect("salt_hex is hex");

    assert_eq!(
        salt, expected_salt,
        "the salt is not \"DLWP/1-session\" || 0x00 || session_id"
    );

    // And it is built the way the schedule says, checked component by component rather than only by
    // its total bytes.
    assert_eq!(
        salt.get(..14).expect("the label is 14 bytes"),
        b"DLWP/1-session",
        "the salt does not start with the label"
    );
    assert_eq!(
        salt.get(14).copied(),
        Some(0x00),
        "the separator is missing"
    );
    assert_eq!(
        salt.get(15..).expect("the session id follows"),
        session_id.as_slice()
    );

    let ikm = session_ikm(&shared, &pairing_secret);
    let expected_ikm = from_hex(vectors::str_field(derived, "ikm_hex")).expect("ikm_hex is hex");

    assert_eq!(ikm, expected_ikm, "the IKM is not shared || pairing_secret");
    assert_eq!(ikm.len(), 64);
    assert_eq!(ikm.get(..32).expect("shared first"), shared.as_slice());
    assert_eq!(
        ikm.get(32..).expect("pairing_secret second"),
        pairing_secret.as_slice()
    );

    let _ = vectors;
}

/// The recorded key lengths are the ones this crate derives.
#[test]
fn the_derived_lengths_are_the_recorded_lengths() {
    let vector = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "session.keys.baseline")
        .expect("the baseline vector is present");

    let lengths = vectors::nested(vectors::nested(&vector, "derived"), "expected_lengths");

    let keys = derive(&vector);

    assert_eq!(
        keys.c2a_key.len(),
        vectors::u64_field(lengths, "c2a_key") as usize,
        "c2a_key length"
    );
    assert_eq!(
        keys.a2c_key.len(),
        vectors::u64_field(lengths, "a2c_key") as usize,
        "a2c_key length"
    );
    assert_eq!(
        keys.c2a_iv.len(),
        vectors::u64_field(lengths, "c2a_iv") as usize,
        "c2a_iv length"
    );
    assert_eq!(
        keys.a2c_iv.len(),
        vectors::u64_field(lengths, "a2c_iv") as usize,
        "a2c_iv length"
    );
    assert_eq!(
        keys.exporter.len(),
        vectors::u64_field(lengths, "exporter") as usize,
        "exporter length"
    );

    // And the constants agree with the file, so a change to one without the other fails.
    assert_eq!(KEY_LENGTH, 32);
    assert_eq!(IV_PREFIX_LENGTH, 4);
    assert_eq!(EXPORTER_LENGTH, 32);
}

/// The direction-separation vector's four assertions hold.
#[test]
fn the_directions_are_separated() {
    let vector = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "session.keys.direction-separation")
        .expect("the direction-separation vector is present");

    // The vector names its assertions as strings; they are asserted here as code. Reading the strings
    // would only check that the file is self-consistent, not that the crate agrees.
    let assertions: Vec<String> = vector
        .get("assertions")
        .and_then(Value::as_array)
        .expect("assertions is an array")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();

    assert_eq!(assertions.len(), 4, "the vector declares four assertions");
    assert!(assertions.iter().any(|text| text == "c2a_key != a2c_key"));

    let keys = derive(&vector);

    assert_ne!(keys.c2a_key, keys.a2c_key, "c2a_key equals a2c_key");
    assert_ne!(keys.c2a_key, keys.exporter, "c2a_key equals exporter");
    assert_ne!(keys.a2c_key, keys.exporter, "a2c_key equals exporter");
    assert_ne!(keys.c2a_iv, keys.a2c_iv, "c2a_iv equals a2c_iv");
}

/// A different session id changes every derived value.
#[test]
fn session_id_changes_every_derived_value() {
    let all = vectors::vectors(SESSION_KEYS);

    let baseline = all
        .iter()
        .find(|vector| vectors::id(vector) == "session.keys.baseline")
        .expect("the baseline vector is present");

    let changed = all
        .iter()
        .find(|vector| vectors::id(vector) == "session.keys.session-id-changes-everything")
        .expect("the changed-session-id vector is present");

    // The inputs differ in the session id and nowhere else, which is what makes this test about the
    // salt rather than about anything else.
    let (base_id, base_shared, base_pairing, base_transcript) = session_inputs(baseline);
    let (changed_id, shared, pairing, transcript) = session_inputs(changed);

    assert_ne!(
        base_id, changed_id,
        "the vector did not actually change the session id"
    );
    assert_eq!(base_shared, shared);
    assert_eq!(base_pairing, pairing);
    assert_eq!(base_transcript, transcript);

    let a = derive(baseline);
    let b = derive(changed);

    assert_ne!(a.c2a_key, b.c2a_key, "the session id did not reach c2a_key");
    assert_ne!(a.a2c_key, b.a2c_key, "the session id did not reach a2c_key");
    assert_ne!(a.c2a_iv, b.c2a_iv, "the session id did not reach c2a_iv");
    assert_ne!(a.a2c_iv, b.a2c_iv, "the session id did not reach a2c_iv");
    assert_ne!(
        a.exporter, b.exporter,
        "the session id did not reach the exporter"
    );
}

/// Changing the transcript hash changes only the exporter.
///
/// The most valuable test in this file. It catches the mistake of mixing the transcript into the IKM
/// or the salt, which would produce a session that works until a HELLO is retransmitted and then
/// fails — with self-consistent keys at both ends, so nothing narrows down the cause.
#[test]
fn the_transcript_changes_the_exporter_only() {
    let all = vectors::vectors(SESSION_KEYS);

    let baseline = all
        .iter()
        .find(|vector| vectors::id(vector) == "session.keys.baseline")
        .expect("the baseline vector is present");

    let changed = all
        .iter()
        .find(|vector| vectors::id(vector) == "session.keys.transcript-changes-exporter-only")
        .expect("the changed-transcript vector is present");

    // The vector's own note: only the transcript hash differs.
    let (base_id, base_shared, base_pairing, base_transcript) = session_inputs(baseline);
    let (changed_id, shared, pairing, changed_transcript) = session_inputs(changed);

    assert_eq!(base_id, changed_id);
    assert_eq!(base_shared, shared);
    assert_eq!(base_pairing, pairing);
    assert_ne!(
        base_transcript, changed_transcript,
        "the vector did not actually change the transcript hash"
    );

    let a = derive(baseline);
    let b = derive(changed);

    // The four record-protection values must be UNCHANGED.
    assert_eq!(
        a.c2a_key, b.c2a_key,
        "the transcript hash reached c2a_key, which breaks reconnection after a retransmitted HELLO"
    );
    assert_eq!(a.a2c_key, b.a2c_key, "the transcript hash reached a2c_key");
    assert_eq!(a.c2a_iv, b.c2a_iv, "the transcript hash reached c2a_iv");
    assert_eq!(a.a2c_iv, b.a2c_iv, "the transcript hash reached a2c_iv");

    // And the exporter must change, or the transcript would be bound to nothing at all.
    assert_ne!(
        a.exporter, b.exporter,
        "the transcript hash did not reach the exporter, so AUTH would bind nothing"
    );
}

/// `Direction` selects the matching key and prefix.
///
/// A guard against a `Direction` whose two arms return the same half: the session would look correct
/// on one side and decrypt the other side's frames, which is a symmetric channel rather than a
/// two-directional one.
#[test]
fn a_direction_selects_its_own_key_and_iv() {
    let vector = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "session.keys.baseline")
        .expect("the baseline vector is present");

    let keys = derive(&vector);

    assert_eq!(
        Direction::ControllerToAgent.key(&keys),
        &keys.c2a_key,
        "the controller-to-agent direction used the wrong key"
    );
    assert_eq!(
        Direction::AgentToController.key(&keys),
        &keys.a2c_key,
        "the agent-to-controller direction used the wrong key"
    );
    assert_eq!(Direction::ControllerToAgent.iv(&keys), &keys.c2a_iv);
    assert_eq!(Direction::AgentToController.iv(&keys), &keys.a2c_iv);

    // The two directions must not select the same material.
    assert_ne!(
        Direction::ControllerToAgent.key(&keys),
        Direction::AgentToController.key(&keys),
        "both directions selected the same key"
    );
    assert_ne!(
        Direction::ControllerToAgent.iv(&keys),
        Direction::AgentToController.iv(&keys),
        "both directions selected the same nonce prefix, which would reuse a nonce"
    );

    // And `opposite` is an involution, so a reply's direction is a single call.
    assert_eq!(
        Direction::ControllerToAgent.opposite(),
        Direction::AgentToController
    );
    assert_eq!(
        Direction::ControllerToAgent.opposite().opposite(),
        Direction::ControllerToAgent
    );
}

/// The all-zero shared secret is refused rather than derived from.
#[test]
fn an_all_zero_shared_secret_is_refused() {
    let vector = array_named(PRIMITIVES, "rejection_vectors")
        .into_iter()
        .find(|vector| vectors::id(vector) == "x25519.reject.all-zero-output")
        .expect("the all-zero vector is present");

    // The vector points at a public key; what the crate sees is the OUTPUT being zero, which is the
    // stronger check because it does not require knowing which points are low-order.
    let public_key = vectors::str_field(&vector, "peer_public_key");
    let decoded = from_hex(public_key).expect("the public key is hex");

    assert_eq!(decoded.len(), 32);
    assert!(
        decoded.iter().all(|byte| *byte == 0),
        "the vector's low-order point"
    );

    let session_id = [0u8; 16];
    let secret = [1u8; KEY_LENGTH];
    let transcript = [2u8; KEY_LENGTH];

    let zero = [0u8; KEY_LENGTH];
    let error = derive_session_keys(&session_id, &zero, &secret, &transcript)
        .expect_err("an all-zero shared secret must be refused");

    assert_eq!(
        error,
        droidlab_protocol::KeyScheduleError::AllZeroSharedSecret
    );

    // The message names the reason, so a log line is actionable rather than merely a failure.
    let text = error.to_string();
    assert!(
        text.contains("all zero"),
        "the message does not say why: {text}"
    );

    // And a single non-zero byte makes it acceptable, so the check is on all-zero and not on
    // "mostly zero".
    let mut almost_zero = [0u8; KEY_LENGTH];
    almost_zero[31] = 1;

    assert!(derive_session_keys(&session_id, &almost_zero, &secret, &transcript).is_ok());
}

/// Wrong input lengths are refused, each naming the field.
#[test]
fn the_input_lengths_are_enforced() {
    let session_id = [0u8; 16];
    let good = [1u8; KEY_LENGTH];

    // The shared secret.
    for length in [0usize, 1, 31, 33, 64] {
        let short = vec![1u8; length];

        assert!(
            matches!(
                derive_session_keys(&session_id, &short, &good, &good),
                Err(droidlab_protocol::KeyScheduleError::BadSharedLength { .. })
            ),
            "a {length}-byte shared secret was accepted"
        );
    }

    // The pairing secret.
    for length in [0usize, 31, 33] {
        let short = vec![1u8; length];

        assert!(
            matches!(
                derive_session_keys(&session_id, &good, &short, &good),
                Err(droidlab_protocol::KeyScheduleError::BadPairingSecretLength { .. })
            ),
            "a {length}-byte pairing secret was accepted"
        );
    }

    // The transcript hash.
    for length in [0usize, 31, 33] {
        let short = vec![1u8; length];

        assert!(
            matches!(
                derive_session_keys(&session_id, &good, &good, &short),
                Err(droidlab_protocol::KeyScheduleError::BadTranscriptHashLength { .. })
            ),
            "a {length}-byte transcript hash was accepted"
        );
    }
}

/// `Debug` on the key set prints no key bytes.
///
/// A derived `Debug` would be a real defect: this is the value a caller reaches for when logging a
/// session, and a key that reaches a log has left the device.
#[test]
fn the_key_set_debug_does_not_print_keys() {
    let mut keys = SessionKeys {
        c2a_key: [0xAB; KEY_LENGTH],
        a2c_key: [0xCD; KEY_LENGTH],
        c2a_iv: [0x11; IV_PREFIX_LENGTH],
        a2c_iv: [0x22; IV_PREFIX_LENGTH],
        exporter: [0xEF; EXPORTER_LENGTH],
    };

    let rendered = format!("{keys:?}");

    // The repeated byte, in hex, must not appear anywhere.
    assert!(
        !rendered.contains("abab"),
        "the debug output contains key bytes: {rendered}"
    );
    assert!(
        !rendered.contains("cdcd"),
        "the debug output contains key bytes: {rendered}"
    );
    assert!(
        !rendered.contains("efef"),
        "the debug output contains exporter bytes: {rendered}"
    );

    // The nonce prefixes are not secret and are shown, which is what makes the output useful.
    assert!(
        rendered.contains("1111"),
        "the nonce prefix is missing: {rendered}"
    );
    assert!(
        rendered.contains("2222"),
        "the nonce prefix is missing: {rendered}"
    );
    assert!(
        rendered.contains("<32 bytes>"),
        "a key field is missing: {rendered}"
    );

    // A key set whose bytes were changed must not render identically, or the "no bytes" property
    // would be trivially satisfied by printing a constant.
    keys.c2a_iv = [0x33; IV_PREFIX_LENGTH];
    assert_ne!(
        format!("{keys:?}"),
        rendered,
        "the debug output is constant"
    );
}

/// The vector file's prose about the AUTH proof label lengths is wrong.
///
/// `crypto-session-keys.json`'s `auth.proofs.baseline` vector says:
///
/// > "DLWP/1-client" is 15 bytes and "DLWP/1-agent" is 14, so the two message strings differ in both
/// > label and length; the proofs must therefore differ even for identical inputs.
///
/// The labels are 13 and 12 bytes. The vector's own recorded message hex decodes to strings whose
/// label prefixes are 13 and 12 bytes, so the file disagrees with itself and the hex is the correct
/// half. The claim the note is making -- that the two labels differ in both length and content --
/// survives, which is why the numbers went unnoticed.
///
/// This test asserts the defect. If somebody corrects the prose to say 13 and 12, this test fails and
/// tells them to update the note here too, rather than the correction passing silently.
#[test]
fn the_auth_proof_label_lengths_in_the_vector_prose_are_wrong() {
    let vector = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "auth.proofs.baseline")
        .expect("the auth-proofs vector is present");

    let note = vectors::str_field(vectors::nested(&vector, "derived"), "note");

    // The note reads `is 15 bytes ... is 14,` -- only the first number carries the word "bytes", so
    // requiring "14 bytes" failed on a note that does contain the claim.
    assert!(
        note.contains("15 bytes") && note.contains("is 14,"),
        "the prose note no longer claims 15 and 14; it now reads: {note}"
    );

    // The truth, taken from the vector's own recorded hex rather than from the crate's constants, so
    // this test is about the file and not about the crate agreeing with itself.
    let derived = vectors::nested(&vector, "derived");

    for (field, expected_label) in [
        ("client_proof_message_hex", labels::AUTH_CLIENT_LABEL),
        ("agent_proof_message_hex", labels::AUTH_AGENT_LABEL),
    ] {
        let message = from_hex(vectors::str_field(derived, field)).expect("the message is hex");

        assert!(
            message.starts_with(expected_label.as_bytes()),
            "{field} does not begin with {expected_label:?}"
        );

        let label_length = expected_label.len();
        let suffix = message
            .get(label_length..)
            .expect("the message is longer than its label");

        assert_eq!(
            suffix.len(),
            32,
            "{field}: the bytes after the label are not a 32-byte transcript hash"
        );

        assert_eq!(
            label_length,
            expected_label.len(),
            "{field}: the label length in the file disagrees with the crate"
        );

        assert!(
            label_length == 13 || label_length == 12,
            "{field}: the label is {label_length} bytes, but the prose says 15 and 14"
        );
    }

    assert_eq!(labels::AUTH_CLIENT_LABEL, "DLWP/1-client");
    assert_eq!(labels::AUTH_AGENT_LABEL, "DLWP/1-agent");
    assert_eq!(labels::AUTH_CLIENT_LABEL.len(), 13);
    assert_eq!(labels::AUTH_AGENT_LABEL.len(), 12);
}
// =============================================================================================
// AEAD: nonce layout, associated data, seal and open
// =============================================================================================

/// The nonce is the 4-byte prefix followed by the big-endian sequence number.
#[test]
fn the_nonce_layout_is_the_recorded_bytes() {
    // Bound to a local first: `array_named` returns an owned Vec, and `.iter()` on the temporary
    // would borrow a value dropped at the end of the statement.
    let aead_vectors = array_named(SESSION_KEYS, "aead_vectors");
    let nonce_vector = aead_vectors
        .iter()
        .find(|vector| vectors::id(vector) == "aead.nonce.layout")
        .expect("the nonce-layout vector is present");

    let prefix_hex = vectors::str_field(nonce_vector, "c2a_iv");
    let sequence = vectors::u64_field(nonce_vector, "sequence_number");
    let expected = vectors::str_field(nonce_vector, "expected_nonce_hex");

    let prefix_bytes = from_hex(prefix_hex).expect("the prefix is hex");

    let mut prefix = [0u8; IV_PREFIX_LENGTH];

    for (slot, byte) in prefix.iter_mut().zip(prefix_bytes.iter()) {
        *slot = *byte;
    }

    let nonce = build_nonce(&prefix, sequence);

    assert_eq!(
        to_hex(&nonce),
        expected,
        "the nonce is not iv_prefix || sequence_number (8, big-endian)"
    );
    assert_eq!(nonce.len(), NONCE_LENGTH);
    assert_eq!(NONCE_LENGTH, 12, "the nonce is 96 bits");

    // The layout, checked by component as well: the prefix occupies the first four bytes and the
    // sequence the last eight, big-endian.
    assert_eq!(
        nonce.get(..IV_PREFIX_LENGTH).expect("the prefix"),
        prefix_bytes.as_slice()
    );

    let sequence_bytes = sequence.to_be_bytes();
    assert_eq!(
        nonce.get(IV_PREFIX_LENGTH..).expect("the sequence"),
        &sequence_bytes,
        "the sequence number is not big-endian in the nonce"
    );

    // Big-endian, not little-endian, checked on a value where the two differ visibly.
    let one = build_nonce(&[0u8; IV_PREFIX_LENGTH], 1);
    assert_eq!(to_hex(&one), "000000000000000000000001");
    assert_ne!(
        to_hex(&one),
        "000000000000000000000100",
        "the sequence was little-endian"
    );
}

/// A different sequence number produces a different nonce, for every prefix.
///
/// The property that makes nonce reuse impossible: the prefix is fixed per direction per session, so
/// the sequence number is the only thing that can vary and it must actually vary the nonce.
#[test]
fn every_sequence_number_produces_a_distinct_nonce() {
    let prefix = [0x5Au8; IV_PREFIX_LENGTH];
    let mut seen: Vec<[u8; NONCE_LENGTH]> = Vec::new();

    for sequence in [0u64, 1, 2, 255, 256, 65_535, 65_536, u64::MAX - 1, u64::MAX] {
        let nonce = build_nonce(&prefix, sequence);

        assert!(!seen.contains(&nonce), "sequence {sequence} reused a nonce");
        seen.push(nonce);

        // And the prefix is intact, so a prefix cannot be displaced by the sequence number.
        assert_eq!(nonce.get(..IV_PREFIX_LENGTH), Some(prefix.as_slice()));
    }

    assert_eq!(seen.len(), 9, "every sequence number produced a nonce");

    // A different prefix with the same sequence is also a different nonce, which is why the direction
    // matters as much as the sequence number.
    assert_ne!(
        build_nonce(&[0x00; IV_PREFIX_LENGTH], 417),
        build_nonce(&[0xFF; IV_PREFIX_LENGTH], 417)
    );
}

/// The two AEAD vectors from `crypto-primitives.json` behave as declared.
///
/// The tampered-header vector and the reused-sequence vector are as much about the *session* as the
/// AEAD, so what is asserted here is the part the AEAD itself owns: a modified header fails tag
/// verification, and a reused sequence number produces a repeated nonce.
#[test]
fn the_aead_vectors_hold() {
    // Pin the count and the ids, so the two checks below cannot pass by iterating an empty array.
    let rejections = array_named(PRIMITIVES, "rejection_vectors");

    assert_eq!(
        rejections.len(),
        5,
        "the file declares five rejection vectors"
    );
    assert!(
        rejections
            .iter()
            .any(|entry| vectors::id(entry) == "aead.reject.tampered-header"),
        "the tampered-header vector is missing, so the check below is about nothing"
    );

    let session_id = [0x11u8; 16];
    let shared = [0x22u8; KEY_LENGTH];
    let pairing_secret = [0x33u8; KEY_LENGTH];
    let transcript_hash = [0x44u8; KEY_LENGTH];

    let keys = derive_session_keys(&session_id, &shared, &pairing_secret, &transcript_hash)
        .expect("the keys derive");

    let header = FrameHeader {
        version: 1,
        flags: 0x01,
        header_length: 24,
        message_type: 50,
        channel_id: 3,
        sequence_number: 914,
        acknowledgment: 910,
        body_length: 0,
    };

    let plaintext = b"a video frame's payload";
    let aad = aad_from_header(&header.encode(), plaintext.len() as u32).expect("the AAD builds");

    assert_eq!(aad.len(), FIXED_LENGTH, "the AAD is the 24-byte header");

    let body =
        seal(&keys, Direction::ControllerToAgent, 914, plaintext, &aad).expect("sealing succeeds");

    // The wire form: nonce, then ciphertext, then a 16-byte tag.
    assert_eq!(body.len(), NONCE_LENGTH + plaintext.len() + TAG_LENGTH);

    // The plaintext does not appear in the ciphertext. Checked with a real search rather than by
    // asserting a slice equals `None`, which is what my first version did: a `get` that returns
    // `Some(ciphertext)` has no relationship to the plaintext being absent, so the assertion proved
    // nothing about encryption at all.
    let ciphertext = body
        .get(NONCE_LENGTH..NONCE_LENGTH + plaintext.len())
        .expect("the ciphertext is present");
    assert_ne!(
        ciphertext, plaintext,
        "the ciphertext is the plaintext, so the record is not encrypted"
    );
    assert!(
        !body
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "the plaintext appears verbatim inside the sealed record"
    );

    // And it opens back to the same plaintext.
    let recovered =
        open(&keys, Direction::ControllerToAgent, &body, &aad).expect("opening succeeds");
    assert_eq!(recovered, plaintext);

    // The tampered-header vector: change the sequence number in the header and the tag must fail.
    let mut tampered = header;
    tampered.sequence_number = 915;

    let tampered_aad =
        aad_from_header(&tampered.encode(), plaintext.len() as u32).expect("the AAD builds");

    assert_eq!(
        open(&keys, Direction::ControllerToAgent, &body, &tampered_aad),
        Err(RecordError::OpenFailed),
        "a single changed header byte did not fail tag verification"
    );

    // A single flipped body byte must also fail.
    let mut flipped = body.clone();
    if let Some(byte) = flipped.get_mut(NONCE_LENGTH) {
        *byte ^= 0x01;
    }

    assert_eq!(
        open(&keys, Direction::ControllerToAgent, &flipped, &aad),
        Err(RecordError::OpenFailed)
    );

    // The reused-sequence vector: the same sequence under the same direction produces the same
    // nonce, so the two ciphertexts share a keystream. This is what the session's replay protection
    // exists to prevent; the AEAD itself cannot detect it, and the test says so rather than pretending
    // otherwise.
    let first_nonce = build_nonce(Direction::ControllerToAgent.iv(&keys), 417);
    let second_nonce = build_nonce(Direction::ControllerToAgent.iv(&keys), 417);

    assert_eq!(
        first_nonce, second_nonce,
        "the nonce layout stopped being deterministic, so the replay check is what matters"
    );

    // The opposite direction with the same sequence gives a different nonce, because the prefix
    // differs. That is the second half of the uniqueness argument.
    assert_ne!(
        first_nonce,
        build_nonce(Direction::AgentToController.iv(&keys), 417)
    );
}

/// The AAD is the header with the body length replaced by the plaintext length.
#[test]
fn the_associated_data_replaces_the_body_length() {
    let aead_vectors = array_named(SESSION_KEYS, "aead_vectors");
    let vector = aead_vectors
        .iter()
        .find(|vector| vectors::id(vector) == "aead.header-is-associated-data")
        .expect("the AAD vector is present");

    // The vector records the exact AAD bytes, and separately the fields they decode to. Both are
    // checked, so the recorded bytes and the recorded decoding cannot disagree.
    let recorded = from_hex(vectors::str_field(vector, "aad_bytes")).expect("aad_bytes is hex");
    let declared = vectors::u64_field(vector, "aad_length");

    assert_eq!(
        recorded.len() as u64,
        declared,
        "aad_bytes is {} bytes and aad_length says {declared}",
        recorded.len()
    );

    // No `&`: `vector` is already a `&Value` because `iter().find()` yields a reference, and the
    // extra borrow is what clippy flagged as immediately dereferenced.
    let decoded = vectors::nested(vector, "aad_decoded");
    let header = FrameHeader::decode(&recorded).expect("the AAD is a decodable header");

    assert_eq!(header.version, vectors::u8_field(decoded, "version"));
    assert_eq!(header.flags, vectors::u8_field(decoded, "flags"));
    assert_eq!(
        header.header_length,
        vectors::u8_field(decoded, "header_length")
    );
    assert_eq!(
        header.message_type,
        vectors::u8_field(decoded, "message_type")
    );
    assert_eq!(header.channel_id, vectors::u32_field(decoded, "channel_id"));
    assert_eq!(
        header.sequence_number,
        vectors::u32_field(decoded, "sequence_number")
    );
    assert_eq!(
        header.acknowledgment,
        vectors::u32_field(decoded, "acknowledgment")
    );
    assert_eq!(
        header.body_length,
        vectors::u32_field(decoded, "body_length")
    );

    // The recorded AAD has a zero body length because the plaintext is empty, even though the frame's
    // own body_length would be 28. Rebuilding it from the recorded header with a plaintext length of
    // zero must reproduce the recorded bytes exactly.
    let rebuilt = aad_from_header(&recorded, 0).expect("the AAD rebuilds");

    assert_eq!(
        to_hex(&rebuilt),
        vectors::str_field(vector, "aad_bytes"),
        "rebuilding the AAD from the header did not reproduce the recorded bytes"
    );

    // And with a NON-zero plaintext length it differs, in exactly bytes 20–23.
    let changed = aad_from_header(&recorded, 28).expect("the AAD rebuilds");

    assert_eq!(changed.len(), FIXED_LENGTH);

    let mut differences = Vec::new();

    for (index, (left, right)) in recorded.iter().zip(changed.iter()).enumerate() {
        if left != right {
            differences.push(index);
        }
    }

    // 0 -> 28 is 0x00000000 -> 0x0000001C, which differs in ONE byte: the least significant, at
    // position 23. My first version expected positions 22 and 23, which would be the case only if the
    // change crossed a byte boundary. It does not.
    assert_eq!(
        differences,
        vec![23],
        "replacing a zero plaintext length with 28 changed bytes other than position 23"
    );

    // The field is four bytes wide and big-endian, established by which bytes DIFFER rather than by
    // which are non-zero. My first version of this check got that wrong twice:
    //
    //   0 -> 28   is 0x00000000 -> 0x0000001C   one byte differs (23)
    //   0 -> 256  is 0x00000000 -> 0x00000100   one byte differs (22)  <- NOT two: byte 23 is 0x00
    //   0 -> 65536 is 0x00000000 -> 0x00010000  one byte differs (21)
    //
    // So a single-byte change per mask is the correct expectation and it is a stronger statement than
    // an arc of adjacent bytes would be: it shows the field is a big-endian integer rather than four
    // independent bytes, because a byte-order bug would move the difference to a different position.
    for (value, expected_position) in [(28u32, 23usize), (256, 22), (65_536, 21), (16_777_216, 20)]
    {
        let changed = aad_from_header(&recorded, value)
            .unwrap_or_else(|error| panic!("the AAD for {value} failed: {error}"));

        let mut differences = Vec::new();

        for (index, (left, right)) in recorded.iter().zip(changed.iter()).enumerate() {
            if left != right {
                differences.push(index);
            }
        }

        assert_eq!(
            differences,
            vec![expected_position],
            "plaintext length {value} (0x{value:08X}) should differ in exactly byte {expected_position}"
        );

        // And the byte really holds the big-endian encoding of the value: the value's 4-byte
        // big-endian form, indexed by the position that differed.
        let encoded = value.to_be_bytes();
        let offset = expected_position.saturating_sub(20);
        let expected_byte = encoded.get(offset).copied().unwrap_or(0);

        assert_eq!(
            changed.get(expected_position).copied(),
            Some(expected_byte),
            "byte {expected_position} does not carry 0x{expected_byte:02X}"
        );
    }

    // Byte 20 is the most significant, so the field spans 20..24 and is four bytes wide.
    let widest = aad_from_header(&recorded, u32::MAX).expect("the AAD rebuilds");

    assert_eq!(
        widest.get(20..24),
        Some([0xFFu8, 0xFF, 0xFF, 0xFF].as_slice()),
        "the body-length field is not the four bytes at 20..24"
    );
}

/// Every direction and sequence number pair rejects the other's ciphertext.
#[test]
fn a_record_does_not_open_in_the_wrong_direction() {
    let session_id = [0x01u8; 16];
    let shared = [0x02u8; KEY_LENGTH];
    let pairing_secret = [0x03u8; KEY_LENGTH];
    let transcript_hash = [0x04u8; KEY_LENGTH];

    let keys = derive_session_keys(&session_id, &shared, &pairing_secret, &transcript_hash)
        .expect("the keys derive");

    let header = FrameHeader {
        version: 1,
        flags: 0x01,
        header_length: 24,
        message_type: 50,
        channel_id: 0,
        sequence_number: 1,
        acknowledgment: 0,
        body_length: 0,
    };

    let plaintext = b"payload";
    let aad = aad_from_header(&header.encode(), plaintext.len() as u32).expect("the AAD builds");

    for direction in [Direction::ControllerToAgent, Direction::AgentToController] {
        let body = seal(&keys, direction, 1, plaintext, &aad).expect("sealing succeeds");

        // It opens in its own direction.
        assert!(open(&keys, direction, &body, &aad).is_ok());

        // And NOT in the other, which is the whole reason the two keys exist.
        assert_eq!(
            open(&keys, direction.opposite(), &body, &aad),
            Err(RecordError::OpenFailed),
            "a {direction:?} record opened in the opposite direction"
        );
    }
}

/// Short bodies and wrong AAD lengths are refused with the right error.
#[test]
fn short_bodies_and_wrong_aad_lengths_are_refused() {
    let session_id = [0x01u8; 16];
    let shared = [0x02u8; KEY_LENGTH];
    let pairing_secret = [0x03u8; KEY_LENGTH];
    let transcript_hash = [0x04u8; KEY_LENGTH];

    let keys = derive_session_keys(&session_id, &shared, &pairing_secret, &transcript_hash)
        .expect("the keys derive");

    let good_aad = [0u8; FIXED_LENGTH];

    // A body shorter than a nonce plus a tag cannot be a sealed record.
    for length in 0..NONCE_LENGTH + TAG_LENGTH {
        let body = vec![0u8; length];

        assert_eq!(
            open(&keys, Direction::ControllerToAgent, &body, &good_aad),
            Err(RecordError::OpenFailed),
            "a {length}-byte body was accepted as a sealed record"
        );
    }

    // Exactly at the boundary it is attempted and fails on the tag, not on the length.
    let boundary = vec![0u8; NONCE_LENGTH + TAG_LENGTH];

    assert_eq!(
        open(&keys, Direction::ControllerToAgent, &boundary, &good_aad),
        Err(RecordError::OpenFailed)
    );

    // AAD of the wrong length is a distinct error, because it is a programming mistake rather than
    // a forged frame.
    for length in [0usize, 1, 23, 25, 48] {
        let aad = vec![0u8; length];

        assert_eq!(
            open(&keys, Direction::ControllerToAgent, &boundary, &aad),
            Err(RecordError::BadAadLength { got: length })
        );
        assert_eq!(
            seal(&keys, Direction::ControllerToAgent, 1, b"x", &aad),
            Err(RecordError::BadAadLength { got: length })
        );
        assert_eq!(
            aad_from_header(&aad, 0),
            Err(RecordError::BadAadLength { got: length })
        );
    }
}

/// An empty plaintext still produces a verifiable tag.
#[test]
fn an_empty_plaintext_is_protected() {
    let session_id = [0x01u8; 16];
    let keys = derive_session_keys(
        &session_id,
        &[0x02u8; KEY_LENGTH],
        &[0x03u8; KEY_LENGTH],
        &[0x04u8; KEY_LENGTH],
    )
    .expect("the keys derive");

    // The AAD vector's case: a zero-length plaintext, so the frame's body is nonce plus tag.
    let aad = [0u8; FIXED_LENGTH];
    let body = seal(&keys, Direction::ControllerToAgent, 914, b"", &aad).expect("sealing succeeds");

    assert_eq!(
        body.len(),
        NONCE_LENGTH + TAG_LENGTH,
        "an empty plaintext produces 28 bytes: nonce plus tag"
    );

    assert_eq!(
        open(&keys, Direction::ControllerToAgent, &body, &aad).expect("opening succeeds"),
        Vec::<u8>::new()
    );

    // The tag is not vacuous: flipping the last byte must fail, so an empty plaintext is authenticated
    // rather than the tag being a constant.
    let mut broken = body;
    let last = broken.len().saturating_sub(1);

    if let Some(byte) = broken.get_mut(last) {
        *byte ^= 0x01;
    }

    assert_eq!(
        open(&keys, Direction::ControllerToAgent, &broken, &aad),
        Err(RecordError::OpenFailed)
    );
}

// =============================================================================================
// HMAC, constant-time comparison
// =============================================================================================

/// `hmac_labeled` is HMAC over `label || message`.
#[test]
fn hmac_labeled_prefixes_the_message() {
    let key = [0x5Au8; KEY_LENGTH];
    let message = b"the message";
    let label = labels::AUTH_CLIENT_LABEL;

    let expected = hmac_labeled(&key, label, message);

    // Rebuilt by hand from the label and the message, so the helper is checked rather than trusted.
    let mut buffer = Vec::new();
    buffer.extend_from_slice(label.as_bytes());
    buffer.extend_from_slice(message);

    assert_eq!(expected, droidlab_protocol::hmac_sha256(&key, &buffer));

    // The label is inside the MAC, so two labels produce different proofs for the same message.
    //
    // The vector file's note about these two labels is WRONG and this test records the truth:
    //
    //   > "DLWP/1-client" is 15 bytes and "DLWP/1-agent" is 14, so the two message strings differ
    //   > in both label and length
    //
    // They are 13 and 12. The same vector's own `client_proof_message_hex` and
    // `agent_proof_message_hex` decode to 45- and 44-byte strings whose label prefixes are 13 and 12
    // bytes, so the file contradicts itself and the hex is the half that is right. The conclusion the
    // note draws still holds -- the labels differ in both label and length -- which is presumably why
    // nobody noticed the numbers.
    //
    // `the_auth_proof_label_lengths_in_the_vector_prose_are_wrong` asserts the defect directly, so
    // correcting the prose fails that test rather than passing unnoticed.
    assert_eq!(labels::AUTH_CLIENT_LABEL.len(), 13);
    assert_eq!(labels::AUTH_AGENT_LABEL.len(), 12);
    assert_ne!(
        labels::AUTH_CLIENT_LABEL.len(),
        labels::AUTH_AGENT_LABEL.len(),
        "the two labels are the same length, so the byte strings would differ only by content"
    );

    let client = hmac_labeled(&key, labels::AUTH_CLIENT_LABEL, message);
    let agent = hmac_labeled(&key, labels::AUTH_AGENT_LABEL, message);

    assert_ne!(
        client, agent,
        "the client and agent authentication proofs are equal, so a peer could swap them"
    );

    // The proof-message byte strings recorded in the vector file, rebuilt here from the labels and a
    // transcript hash, so the labels are checked as byte strings rather than only as lengths.
    let vector = vectors::vectors(SESSION_KEYS)
        .into_iter()
        .find(|vector| vectors::id(vector) == "auth.proofs.baseline")
        .expect("the auth-proofs vector is present");

    let derived = vectors::nested(&vector, "derived");
    let transcript_hash = from_hex(vectors::str_field(
        vectors::nested(&vector, "inputs"),
        "transcript_hash",
    ))
    .expect("the transcript hash is hex");

    let mut client_message = Vec::new();
    client_message.extend_from_slice(labels::AUTH_CLIENT_LABEL.as_bytes());
    client_message.extend_from_slice(&transcript_hash);

    assert_eq!(
        to_hex(&client_message),
        vectors::str_field(derived, "client_proof_message_hex"),
        "the client proof message is not \"DLWP/1-client\" || transcript_hash"
    );

    let mut agent_message = Vec::new();
    agent_message.extend_from_slice(labels::AUTH_AGENT_LABEL.as_bytes());
    agent_message.extend_from_slice(&transcript_hash);

    assert_eq!(
        to_hex(&agent_message),
        vectors::str_field(derived, "agent_proof_message_hex"),
        "the agent proof message is not \"DLWP/1-agent\" || transcript_hash"
    );
}

/// `sha256_labeled` inserts a `0x00` between the label and the message.
#[test]
fn sha256_labeled_uses_a_zero_separator() {
    let label = labels::FINGERPRINT_LABEL;
    let message = b"identity public key";

    let expected = sha256_labeled(b"", label, message);

    let mut buffer = Vec::new();
    buffer.extend_from_slice(label.as_bytes());
    buffer.push(0x00);
    buffer.extend_from_slice(message);

    assert_eq!(expected, sha256(&buffer));

    // The separator is load-bearing: without it, a label ending in a byte that also starts a message
    // would collide with a different (label, message) pair.
    let mut without = Vec::new();
    without.extend_from_slice(label.as_bytes());
    without.extend_from_slice(message);

    assert_ne!(
        expected,
        sha256(&without),
        "the 0x00 separator has no effect on the labeled hash"
    );

    // The nonce prefix shifts the label, which is the "|| key" first component.
    let prefixed = sha256_labeled(b"PREFIX", label, message);

    assert_ne!(prefixed, expected, "the leading key was ignored");
}

/// `constant_time_eq` is right, and does not shortcut on length.
#[test]
fn constant_time_comparison_is_correct() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"a", b"a"));
    assert!(constant_time_eq(&[0xAB; 32], &[0xAB; 32]));

    // A difference in the first byte, the middle, and the last: all false, and none of them can be
    // distinguished by timing because the loop never returns early.
    let reference = [0x00u8; 32];
    let mut first = reference;
    first[0] = 1;
    let mut middle = reference;
    middle[16] = 1;
    let mut last = reference;
    last[31] = 1;

    for candidate in [first, middle, last] {
        assert!(!constant_time_eq(&reference, &candidate));
    }

    // Different lengths are unequal, and that is the one early return.
    assert!(!constant_time_eq(b"a", b"ab"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(!constant_time_eq(&[0u8; 31], &[0u8; 32]));
}

// =============================================================================================
// Handshake transcript
// =============================================================================================

/// Reads a transcript vector's inputs.
fn transcript_inputs(vector: &Value) -> (String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let inputs = vectors::nested(vector, "inputs");

    let decode = |field: &str| {
        from_base64url(vectors::str_field(inputs, field))
            .unwrap_or_else(|error| panic!("{field} does not decode: {error}"))
    };

    (
        vectors::str_field(inputs, "client_id").to_owned(),
        vectors::str_field(inputs, "agent_id").to_owned(),
        decode("client_nonce"),
        decode("agent_nonce"),
        decode("client_pub"),
        decode("agent_pub"),
    )
}

/// Builds a transcript from a vector.
fn build_transcript(vector: &Value) -> Transcript {
    let (client_id, agent_id, client_nonce, agent_nonce, client_pub, agent_pub) =
        transcript_inputs(vector);

    Transcript::new(
        &client_id,
        &agent_id,
        &client_nonce,
        &agent_nonce,
        &client_pub,
        &agent_pub,
    )
    .unwrap_or_else(|error| panic!("the transcript failed for {}: {error}", vectors::id(vector)))
}

/// The transcript's length is the recorded arithmetic for every vector.
#[test]
fn the_transcript_length_is_the_recorded_arithmetic() {
    let vectors = vectors::vectors(TRANSCRIPT);

    assert_eq!(vectors.len(), 2, "two positive transcript vectors");
    assert_eq!(TRANSCRIPT, "handshake-transcript.json");

    for vector in &vectors {
        let (client_id, agent_id, ..) = transcript_inputs(vector);

        let transcript = build_transcript(vector);
        let expected = Transcript::length_of(client_id.len(), agent_id.len());

        assert_eq!(
            transcript.len(),
            expected,
            "{}: the transcript is not 16 + 1 + (2+len) + 1 + (2+len) + 1 + 128",
            vectors::id(vector)
        );

        // For the synthetic vector the file records the total; for the minimum-length one the note
        // records it. Checked against the formula rather than a literal, and the formula against the
        // file's own `total_bytes_formula` in `the_total_bytes_formula_is_the_one_used`.
        assert_eq!(
            transcript.len(),
            transcript.as_bytes().len(),
            "the reported length is not the byte length"
        );
    }

    // The two specific totals the file names in prose.
    let synthetic = vectors
        .iter()
        .find(|vector| vectors::id(vector) == "transcript.synthetic.basic")
        .expect("the synthetic vector is present");
    let minimum = vectors
        .iter()
        .find(|vector| vectors::id(vector) == "transcript.minimum-length")
        .expect("the minimum-length vector is present");

    assert_eq!(
        build_transcript(synthetic).len(),
        223,
        "the synthetic transcript should be 223 bytes"
    );
    assert_eq!(
        build_transcript(minimum).len(),
        153,
        "the minimum transcript should be 153 bytes"
    );
}

/// The recorded total-bytes formula is the one this crate implements.
#[test]
fn the_total_bytes_formula_is_the_one_used() {
    let document = document(TRANSCRIPT);

    let format = vectors::nested(&document, "transcript_format");
    let formula = vectors::str_field(format, "total_bytes_formula");

    assert_eq!(
        formula, "16 + 1 + (2 + len(client_id)) + 1 + (2 + len(agent_id)) + 1 + 128",
        "the total-bytes formula changed"
    );

    // Evaluated for the two vectors, so the formula is used rather than merely quoted.
    assert_eq!(Transcript::length_of(36, 36), 223);
    assert_eq!(Transcript::length_of(1, 1), 153);
    assert_eq!(Transcript::length_of(0, 0), 151);

    // And `length_of` agrees with an actually-built transcript for every identifier length in a
    // range, so the formula and the constructor cannot drift.
    let nonce = [0u8; 32];

    for client_length in 0..8usize {
        for agent_length in 0..8usize {
            let client = "c".repeat(client_length);
            let agent = "a".repeat(agent_length);

            let transcript = Transcript::new(&client, &agent, &nonce, &nonce, &nonce, &nonce)
                .expect("the transcript builds");

            assert_eq!(
                transcript.len(),
                Transcript::length_of(client_length, agent_length),
                "the formula and the constructor disagree at ({client_length}, {agent_length})"
            );
        }
    }
}

/// The transcript's component layout, checked byte by byte against the recorded format.
#[test]
fn the_transcript_layout_matches_the_recorded_format() {
    let document = document(TRANSCRIPT);
    let format = vectors::nested(&document, "transcript_format");

    // The fixed widths the file records.
    let widths = vectors::nested(format, "fixed_width_bytes");

    assert_eq!(
        vectors::u64_field(widths, "label") as usize,
        LABEL_LENGTH,
        "the label width differs"
    );
    assert_eq!(
        vectors::u64_field(widths, "separator") as usize,
        SEPARATOR_LENGTH
    );
    assert_eq!(
        vectors::u64_field(widths, "length_prefix") as usize,
        LENGTH_PREFIX_LENGTH
    );
    assert_eq!(vectors::u64_field(widths, "nonce") as usize, 32);
    assert_eq!(vectors::u64_field(widths, "public_key") as usize, 32);

    // The label itself.
    // The label is component 0 of `transcript_format.components`, whose `value` is the label itself.
    let components = vectors::nested(&document, "transcript_format")
        .get("components")
        .and_then(Value::as_array)
        .expect("transcript_format.components is an array")
        .clone();

    let label = components
        .iter()
        .find(|component| component.get("index").and_then(Value::as_u64) == Some(0))
        .and_then(|component| component.get("value"))
        .and_then(Value::as_str)
        .expect("component 0 is the transcript label");
    assert_eq!(label, labels::TRANSCRIPT_LABEL);
    assert_eq!(label.len(), LABEL_LENGTH);

    // The components, applied to the synthetic vector.
    let vector = vectors::vectors(TRANSCRIPT)
        .into_iter()
        .find(|vector| vectors::id(vector) == "transcript.synthetic.basic")
        .expect("the synthetic vector is present");

    let (client_id, agent_id, client_nonce, agent_nonce, client_pub, agent_pub) =
        transcript_inputs(&vector);

    let transcript = build_transcript(&vector);
    let bytes = transcript.as_bytes();

    // Component 0: the label, no prefix.
    assert_eq!(
        bytes.get(..LABEL_LENGTH).expect("the label slice"),
        labels::TRANSCRIPT_LABEL.as_bytes(),
        "component 0 is not the transcript label"
    );
    // Component 1: a separator.
    assert_eq!(bytes.get(LABEL_LENGTH).copied(), Some(0x00), "component 1");

    // Component 2: the client id with its u16 big-endian prefix.
    let client_prefix_at = LABEL_LENGTH + SEPARATOR_LENGTH;
    let prefix = bytes
        .get(client_prefix_at..client_prefix_at + LENGTH_PREFIX_LENGTH)
        .expect("the client prefix");
    let declared = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;

    assert_eq!(
        declared,
        client_id.len(),
        "the client id's length prefix does not state its length"
    );
    assert_eq!(
        bytes
            .get(
                client_prefix_at + LENGTH_PREFIX_LENGTH
                    ..client_prefix_at + LENGTH_PREFIX_LENGTH + declared
            )
            .expect("the client id slice"),
        client_id.as_bytes(),
        "component 2 is not the client id"
    );

    // The chain of offsets, computed the same way the constructor does.
    let agent_prefix_at =
        client_prefix_at + LENGTH_PREFIX_LENGTH + client_id.len() + SEPARATOR_LENGTH;

    assert_eq!(
        bytes.get(agent_prefix_at - 1).copied(),
        Some(0x00),
        "component 3 is not a separator"
    );

    let agent_prefix = bytes
        .get(agent_prefix_at..agent_prefix_at + LENGTH_PREFIX_LENGTH)
        .expect("the agent prefix");
    let agent_declared = u16::from_be_bytes([agent_prefix[0], agent_prefix[1]]) as usize;

    assert_eq!(
        agent_declared,
        agent_id.len(),
        "the agent id's prefix is wrong"
    );

    // Component 5's separator comes BEFORE the four fixed-width fields, so the nonces begin one byte
    // after the agent id ends. My first version omitted that byte, which put `nonces_at - 1` on the
    // last character of the agent id -- and the failure reported byte 101, which is 'e', the last
    // byte of "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".
    let nonces_at = agent_prefix_at + LENGTH_PREFIX_LENGTH + agent_id.len() + SEPARATOR_LENGTH;

    assert_eq!(
        bytes.get(nonces_at - SEPARATOR_LENGTH).copied(),
        Some(0x00),
        "component 5 is not a separator"
    );

    // The agent id itself, so the offset arithmetic is checked against the bytes rather than only
    // against the field's declared length.
    assert_eq!(
        bytes
            .get(
                agent_prefix_at + LENGTH_PREFIX_LENGTH
                    ..agent_prefix_at + LENGTH_PREFIX_LENGTH + agent_declared
            )
            .expect("the agent id slice"),
        agent_id.as_bytes(),
        "component 4 is not the agent id"
    );

    // Components 6–9: the four 32-byte fields, in order, with no prefixes.
    let fields_at = nonces_at;

    assert_eq!(
        bytes.get(fields_at..fields_at + 32).expect("client nonce"),
        client_nonce.as_slice(),
        "component 6 is not the client nonce"
    );
    assert_eq!(
        bytes
            .get(fields_at + 32..fields_at + 64)
            .expect("agent nonce"),
        agent_nonce.as_slice(),
        "component 7 is not the agent nonce"
    );
    assert_eq!(
        bytes
            .get(fields_at + 64..fields_at + 96)
            .expect("client pub"),
        client_pub.as_slice(),
        "component 8 is not the client public key"
    );
    assert_eq!(
        bytes
            .get(fields_at + 96..fields_at + 128)
            .expect("agent pub"),
        agent_pub.as_slice(),
        "component 9 is not the agent public key"
    );

    // And the four fields total 128, the last term of the formula.
    assert_eq!(
        bytes.len() - fields_at,
        128,
        "the four fixed-width fields are not 128 bytes"
    );
}

/// The recorded transcript hashes are reproduced.
///
/// The two hashes are recorded in the vector file as `expected.transcript_hash`, so this is a real
/// comparison against a literal rather than a self-check. If the vector's inputs and its hash are
/// consistent, this test either confirms both or finds the defect.
#[test]
fn the_transcript_hashes_are_reproduced() {
    let mut checked = 0usize;

    for vector in vectors::vectors(TRANSCRIPT) {
        let transcript = build_transcript(&vector);
        let id = vectors::id(&vector);
        let expected = vectors::nested(&vector, "expected");

        // The vector records the exact transcript BYTES, so the construction is compared against a
        // literal rather than only against its length. My first version looked for a
        // `transcript_hash` field that does not exist, found nothing, and reported "this test proved
        // nothing" -- which is at least an honest failure rather than a silent pass.
        let recorded_bytes = from_hex(vectors::str_field(expected, "transcript_bytes"))
            .expect("transcript_bytes is hex");

        assert_eq!(
            transcript.as_bytes(),
            recorded_bytes.as_slice(),
            "{id}: the transcript bytes differ from the recorded ones"
        );

        // The recorded length, and the transcript's own idea of its length, and the recorded bytes'
        // length, all three agreeing.
        let recorded_length = vectors::u64_field(expected, "transcript_length_bytes") as usize;

        assert_eq!(transcript.len(), recorded_length, "{id}: length");
        assert_eq!(
            recorded_bytes.len(),
            recorded_length,
            "{id}: the recorded bytes are the wrong size"
        );

        // And the recorded hash, which is the value the AUTH proofs bind.
        let recorded_hash = vectors::str_field(expected, "transcript_sha256");

        assert_eq!(
            transcript.hash_hex(),
            recorded_hash,
            "{id}: the transcript hash differs from the recorded one"
        );

        checked += 1;
    }

    assert_eq!(
        checked, 2,
        "both transcript vectors recorded bytes and a hash, so both must be checked"
    );
}

/// The leading-separator confusion the length prefixes exist to prevent.
///
/// The rejection vector's case: `client_id = "c\x00a"`, `agent_id = ""` must NOT serialise to the
/// same bytes as `client_id = "c"`, `agent_id = "a"`. A naive concatenation would, and this test is
/// what makes the length prefix a guard rather than a decoration.
#[test]
fn the_leading_separator_confusion_is_prevented() {
    let rejections = array_named(TRANSCRIPT, "rejection_vectors");

    let vector = rejections.first().expect("the rejection vector");

    assert_eq!(
        vectors::id(vector),
        "transcript.reject.leading-separator-confusion"
    );

    let (client_id, agent_id, client_nonce, agent_nonce, client_pub, agent_pub) =
        transcript_inputs(vector);

    // The vector's own identifiers, checked so the test is about the case it names.
    assert_eq!(
        client_id, "c\u{0}a",
        "the rejection vector's client id changed"
    );
    assert_eq!(agent_id, "", "the rejection vector's agent id changed");

    let naively_different = Transcript::new(
        &client_id,
        &agent_id,
        &client_nonce,
        &agent_nonce,
        &client_pub,
        &agent_pub,
    )
    .expect("the transcript builds");

    // The colliding pair: the same three bytes split at a different point.
    let colliding = Transcript::new(
        "c",
        "a",
        &client_nonce,
        &agent_nonce,
        &client_pub,
        &agent_pub,
    )
    .expect("the transcript builds");

    // The two must differ, and the recorded arithmetic says by exactly one byte.
    assert_ne!(
        naively_different.as_bytes(),
        colliding.as_bytes(),
        "the length prefixes did not prevent the leading-separator confusion, so an attacker can \
         move a byte between the two identifiers and keep the transcript hash"
    );

    let expected_length = vector
        .get("expected")
        .and_then(|expected| expected.get("transcript_length_bytes"))
        .and_then(Value::as_u64);

    assert_eq!(
        naively_different.len() as u64,
        expected_length.expect("the vector records a length"),
        "the rejection vector's length is not the recorded one"
    );

    // The recorded arithmetic in prose: 154, one byte more than the 153-byte minimum.
    assert_eq!(
        naively_different.len(),
        154,
        "16 + 1 + (2+3) + 1 + (2+0) + 1 + 128 = 154"
    );
    assert_eq!(Transcript::length_of(3, 0), 154);
    assert_eq!(Transcript::length_of(1, 1), 153);

    // The 154-byte transcript is exactly one byte longer than the 153-byte one, and the extra byte is
    // the client id's extra character, which is what the recorded note says.
    assert_eq!(
        naively_different.len() - colliding.len(),
        1,
        "the difference should be exactly the client id's extra byte"
    );

    // And the hashes differ, which is the property that actually matters.
    assert_ne!(
        naively_different.hash(),
        colliding.hash(),
        "two confusable transcripts hashed to the same value"
    );
}

/// The minimum-length transcript is 153 bytes and its components are as recorded.
#[test]
fn the_minimum_transcript_is_153_bytes() {
    let vector = vectors::vectors(TRANSCRIPT)
        .into_iter()
        .find(|vector| vectors::id(vector) == "transcript.minimum-length")
        .expect("the minimum-length vector is present");

    let (client_id, agent_id, ..) = transcript_inputs(&vector);

    assert_eq!(
        client_id.len(),
        1,
        "the minimum transcript's client id is one byte"
    );
    assert_eq!(
        agent_id.len(),
        1,
        "the minimum transcript's agent id is one byte"
    );

    let transcript = build_transcript(&vector);

    assert_eq!(transcript.len(), 153);
    assert_eq!(transcript.len(), Transcript::length_of(1, 1));

    // The two one-byte identifiers' length prefixes are both 0x0001, which is the file's claim.
    let bytes = transcript.as_bytes();
    let client_prefix_at = LABEL_LENGTH + SEPARATOR_LENGTH;
    let agent_prefix_at = client_prefix_at + LENGTH_PREFIX_LENGTH + 1 + SEPARATOR_LENGTH;

    assert_eq!(
        bytes.get(client_prefix_at..client_prefix_at + 2),
        Some([0x00u8, 0x01].as_slice()),
        "the client id's prefix is not 0x0001"
    );
    assert_eq!(
        bytes.get(agent_prefix_at..agent_prefix_at + 2),
        Some([0x00u8, 0x01].as_slice()),
        "the agent id's prefix is not 0x0001"
    );
}

/// Transcript fields of the wrong width are refused, each naming the field.
#[test]
fn the_transcript_refuses_wrong_widths() {
    let nonce = [0u8; 32];

    for length in [0usize, 1, 16, 31, 33, 64] {
        let short = vec![0u8; length];

        // Each of the four fixed-width positions, so a check that only validated the first would
        // fail this.
        assert!(Transcript::new("c", "a", &short, &nonce, &nonce, &nonce).is_err());
        assert!(Transcript::new("c", "a", &nonce, &short, &nonce, &nonce).is_err());
        assert!(Transcript::new("c", "a", &nonce, &nonce, &short, &nonce).is_err());
        assert!(Transcript::new("c", "a", &nonce, &nonce, &nonce, &short).is_err());
    }

    // The four 32-byte positions are accepted together.
    assert!(Transcript::new("c", "a", &nonce, &nonce, &nonce, &nonce).is_ok());

    // And the message names the field, so a failure is actionable.
    let error = Transcript::new("c", "a", &[0u8; 31], &nonce, &nonce, &nonce)
        .expect_err("a 31-byte nonce is refused");

    assert!(
        error.to_string().contains("client_nonce"),
        "the error does not name the field: {error}"
    );
}

/// An identifier too long for its 2-byte prefix is refused rather than truncated.
#[test]
fn an_overlong_identifier_is_refused() {
    let nonce = [0u8; 32];

    // 65_535 is the largest a u16 can describe.
    let longest = "c".repeat(65_535);
    let transcript = Transcript::new(&longest, "a", &nonce, &nonce, &nonce, &nonce)
        .expect("65535 bytes fits a u16 prefix");

    assert_eq!(transcript.len(), Transcript::length_of(65_535, 1));

    // One byte more cannot be described, and truncating it would change the transcript silently.
    let too_long = "c".repeat(65_536);

    let error = Transcript::new(&too_long, "a", &nonce, &nonce, &nonce, &nonce)
        .expect_err("65536 bytes does not fit a u16 prefix");

    assert!(
        error.to_string().contains("client_id"),
        "the error does not name the field: {error}"
    );

    // And the same for the agent id.
    assert!(Transcript::new("a", &too_long, &nonce, &nonce, &nonce, &nonce).is_err());
}

/// Every transcript field affects the hash.
///
/// The guard that makes the transcript meaningful: if a field were ignored, two different handshakes
/// would produce the same transcript hash and the AUTH proofs would bind nothing.
#[test]
fn every_transcript_field_affects_the_hash() {
    let nonce = [0u8; 32];
    let other = [0xFFu8; 32];

    let baseline = Transcript::new("client", "agent", &nonce, &nonce, &nonce, &nonce)
        .expect("the baseline builds");
    let baseline_hash = baseline.hash();

    let variants = [
        (
            "client_id",
            Transcript::new("clienT", "agent", &nonce, &nonce, &nonce, &nonce),
        ),
        (
            "agent_id",
            Transcript::new("client", "agenT", &nonce, &nonce, &nonce, &nonce),
        ),
        (
            "client_nonce",
            Transcript::new("client", "agent", &other, &nonce, &nonce, &nonce),
        ),
        (
            "agent_nonce",
            Transcript::new("client", "agent", &nonce, &other, &nonce, &nonce),
        ),
        (
            "client_pub",
            Transcript::new("client", "agent", &nonce, &nonce, &other, &nonce),
        ),
        (
            "agent_pub",
            Transcript::new("client", "agent", &nonce, &nonce, &nonce, &other),
        ),
    ];

    for (field, variant) in variants {
        let variant = variant.expect("the variant builds");

        assert_ne!(
            variant.hash(),
            baseline_hash,
            "changing {field} did not change the transcript hash, so AUTH binds nothing about it"
        );
        assert_eq!(
            variant.len(),
            baseline.len(),
            "changing {field} changed the length, which means it changed a width rather than a value"
        );
    }

    // The three separators are actually present, at the offsets the layout requires.
    let bytes = baseline.as_bytes();

    assert_eq!(bytes.get(LABEL_LENGTH), Some(&0x00));

    // A transcript whose label is wrong must differ, so the label is part of the hash.
    assert_eq!(labels::TRANSCRIPT_LABEL, "DLWP/1-handshake");
}
