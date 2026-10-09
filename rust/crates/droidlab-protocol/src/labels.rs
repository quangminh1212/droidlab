//! The DLWP/1 labels: exact ASCII strings used as HKDF info or HMAC message prefixes.
//!
//! RFC-0002 section 4.1. Every one is case-sensitive and every one is a **domain separator** — a
//! constant placed in front of a message so that a hash or MAC computed for one purpose cannot be
//! replayed in another. A one-character difference yields a different key, and the failure appears at
//! the first record rather than at the point of the mistake.
//!
//! These are `pub const &str` rather than a module of `str`s for one reason worth stating: the tests
//! compare them against `protocol/vectors/crypto-primitives.json`'s `labels` object by name. A typo
//! introduced here fails a test that reads the file, instead of being a constant that a hand-written
//! test also misspells.

/// Prefix of the handshake transcript, `"DLWP/1-handshake"`.
pub const TRANSCRIPT_LABEL: &str = "DLWP/1-handshake";

/// Info for the session record keys, `"DLWP/1-session"`.
///
/// Note the asymmetry with the other labels: this one is used as the *salt* prefix rather than as
/// HKDF info. RFC-0002 section 5.1 derives `salt = "DLWP/1-session" || 0x00 || session_id`, which is
/// what makes a replayed handshake produce different keys.
pub const SESSION_SALT_LABEL: &str = "DLWP/1-session";

/// Salt prefix for the pairing secret, `"DLWP/1-pairing"`.
pub const PAIRING_SALT_LABEL: &str = "DLWP/1-pairing";

/// HKDF info for the pairing secret, `"DLWP/1-pairing-secret"`.
pub const PAIRING_SECRET_INFO: &str = "DLWP/1-pairing-secret";

/// HMAC prefix for the agent's pairing proof, `"DLWP/1-pairing-agent"`.
pub const PAIRING_AGENT_PROOF_LABEL: &str = "DLWP/1-pairing-agent";

/// HMAC prefix for the controller's pairing proof, `"DLWP/1-pairing-controller"`.
pub const PAIRING_CONTROLLER_PROOF_LABEL: &str = "DLWP/1-pairing-controller";

/// HMAC prefix for the pairing confirmation, `"DLWP/1-pairing-confirm"`.
pub const PAIRING_CONFIRMATION_LABEL: &str = "DLWP/1-pairing-confirm";

/// SHA-256 prefix for the six-digit pairing code, `"DLWP/1-pairing-code"`.
pub const PAIRING_CODE_LABEL: &str = "DLWP/1-pairing-code";

/// SHA-256 prefix for the human-readable device fingerprint, `"DLWP/1-fingerprint"`.
pub const FINGERPRINT_LABEL: &str = "DLWP/1-fingerprint";

/// Prefix for the canonicalised mDNS TXT record, `"DLWP/1-txt"`.
pub const TXT_LABEL: &str = "DLWP/1-txt";

/// HKDF info prefix for the exporter secret, `"DLWP/1-exporter"`.
pub const EXPORTER_LABEL: &str = "DLWP/1-exporter";

/// HKDF info for the controller-to-agent record key, `"DLWP/1-c2a-key"`.
pub const C2A_KEY_INFO: &str = "DLWP/1-c2a-key";

/// HKDF info for the agent-to-controller record key, `"DLWP/1-a2c-key"`.
pub const A2C_KEY_INFO: &str = "DLWP/1-a2c-key";

/// HKDF info for the controller-to-agent nonce prefix, `"DLWP/1-c2a-iv"`.
pub const C2A_IV_INFO: &str = "DLWP/1-c2a-iv";

/// HKDF info for the agent-to-controller nonce prefix, `"DLWP/1-a2c-iv"`.
pub const A2C_IV_INFO: &str = "DLWP/1-a2c-iv";

/// HMAC prefix for the client's authentication proof, `"DLWP/1-client"`.
pub const AUTH_CLIENT_LABEL: &str = "DLWP/1-client";

/// HMAC prefix for the agent's authentication proof, `"DLWP/1-agent"`.
pub const AUTH_AGENT_LABEL: &str = "DLWP/1-agent";

/// Every label, paired with the registry's own key for it.
///
/// The pairing is the point: `the_labels_match_the_vector_file` walks this array and looks each name
/// up in `crypto-primitives.json`, so a label that is misspelled *or* attached to the wrong name
/// fails. A list of labels alone would only catch the first.
pub const ALL: [(&str, &str); 17] = [
    ("transcript_label", TRANSCRIPT_LABEL),
    ("session_salt_label", SESSION_SALT_LABEL),
    ("pairing_salt_label", PAIRING_SALT_LABEL),
    ("pairing_secret_info", PAIRING_SECRET_INFO),
    ("pairing_agent_proof_label", PAIRING_AGENT_PROOF_LABEL),
    (
        "pairing_controller_proof_label",
        PAIRING_CONTROLLER_PROOF_LABEL,
    ),
    ("pairing_confirmation_label", PAIRING_CONFIRMATION_LABEL),
    ("pairing_code_label", PAIRING_CODE_LABEL),
    ("fingerprint_label", FINGERPRINT_LABEL),
    ("txt_label", TXT_LABEL),
    ("exporter_label", EXPORTER_LABEL),
    ("c2a_key_info", C2A_KEY_INFO),
    ("a2c_key_info", A2C_KEY_INFO),
    ("c2a_iv_info", C2A_IV_INFO),
    ("a2c_iv_info", A2C_IV_INFO),
    ("auth_client_label", AUTH_CLIENT_LABEL),
    ("auth_agent_label", AUTH_AGENT_LABEL),
];

/// Looks a label up by its registry name.
#[must_use]
pub fn by_registry_name(name: &str) -> Option<&'static str> {
    ALL.iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}
