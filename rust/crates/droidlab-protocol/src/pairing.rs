//! Pairing: fingerprints, the six-digit code, the pairing secret, and the proofs that bind a device
//! to a controller.
//!
//! RFC-0002 sections 3 and 4. The flow this module implements the primitives for:
//!
//! 1. The controller scans a QR code carrying the agent's `pairing_id`, `pairing_token`, ephemeral
//!    public key and identity public key.
//! 2. Both sides derive the same `pairing_secret` from a fresh X25519 exchange plus a static X25519
//!    exchange, which is what gives the pairing both forward secrecy and device binding.
//! 3. Both sides derive the same six-digit `pairing_code` and the human compares them. This is the
//!    only step a person performs, and it is what turns an unauthenticated channel into a paired one.
//! 4. Both sides prove possession of the secret, and the confirmation binds both proofs together.
//!
//! The parts worth naming, because each is a place where a plausible implementation is wrong:
//!
//! * **The fingerprint is over the identity public key, not the session key.** A fingerprint that
//!   changed per session could not be compared against a stored one, which is its entire purpose.
//! * **The pairing code is `decimal(uint32_be(digest[0..4]) mod 1_000_000)`, zero-padded.** The byte
//!   order is specified because a little-endian reading gives a different code from the same digest,
//!   and the padding is specified because `7` and `000007` are different strings.
//! * **The controller's and agent's proofs use each other's nonces in opposite order.** The
//!   controller's message is `controller_label || ctrl_nonce || agent_nonce` and the agent's is
//!   `agent_label || agent_nonce || ctrl_nonce`. Both the label and the nonce order differ, so a
//!   reflected proof cannot be mistaken for the other's.
//! * **The confirmation binds both proofs**, in a fixed order, so a peer cannot claim a pairing the
//!   other side did not complete.

use crate::keyschedule::{constant_time_eq, hmac_sha256, sha256, sha256_labeled};
use crate::labels::{
    FINGERPRINT_LABEL, PAIRING_AGENT_PROOF_LABEL, PAIRING_CODE_LABEL, PAIRING_CONFIRMATION_LABEL,
    PAIRING_CONTROLLER_PROOF_LABEL, PAIRING_SALT_LABEL, PAIRING_SECRET_INFO,
};

use hkdf::Hkdf;
use sha2::Sha256;

/// A fingerprint's byte length, before hex grouping.
pub const FINGERPRINT_BYTES: usize = 8;
/// A fingerprint's rendered length: 16 hex digits plus 3 separators.
pub const FINGERPRINT_RENDERED: usize = 19;
/// A pairing code's digit count.
pub const PAIRING_CODE_DIGITS: usize = 6;
/// The modulus the pairing code is reduced by: ten to the power of the digit count.
pub const PAIRING_CODE_MODULUS: u64 = 1_000_000;
/// A pairing secret's length.
pub const PAIRING_SECRET_LENGTH: usize = 32;
/// A proof's length, which is an HMAC-SHA256 output.
pub const PROOF_LENGTH: usize = 32;

/// A device fingerprint: eight bytes, rendered as `xxxx-xxxx-xxxx-xxxx`.
///
/// Compared by a person, so the rendering is part of the type rather than left to a caller. The usual
/// mistake is to render the first eight bytes in a different grouping or the wrong case, and then two
/// correct implementations disagree in a way a human reads as "different device".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    bytes: [u8; FINGERPRINT_BYTES],
}

impl Fingerprint {
    /// Derives a fingerprint from an identity public key.
    ///
    /// `SHA-256("DLWP/1-fingerprint" || 0x00 || identity_pub)`, truncated to eight bytes. The
    /// truncation is deliberate and is not a security decision: the fingerprint is compared by eye,
    /// and 64 bits is far more than enough to distinguish the handful of devices a person pairs with.
    /// Using the whole digest would make the string too long to read aloud.
    #[must_use]
    pub fn from_public_key(identity_pub: &[u8]) -> Self {
        let digest = sha256_labeled(b"", FINGERPRINT_LABEL, identity_pub);

        let mut bytes = [0u8; FINGERPRINT_BYTES];
        let mut index = 0usize;

        while index < FINGERPRINT_BYTES {
            if let (Some(slot), Some(byte)) = (bytes.get_mut(index), digest.get(index)) {
                *slot = *byte;
            }

            index = index.saturating_add(1);
        }

        Self { bytes }
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.bytes
    }

    /// The rendered form, `xxxx-xxxx-xxxx-xxxx`, uppercase.
    #[must_use]
    pub fn render(&self) -> String {
        let hex = crate::seed::to_hex(&self.bytes).to_uppercase();

        // Grouped four at a time, three separators. Built by walking the pairs of hex digits rather
        // than by slicing, so a short buffer cannot produce a partial string.
        let mut out = String::with_capacity(FINGERPRINT_RENDERED);
        let mut index = 0usize;

        while index < hex.len() {
            if index > 0 && index % 4 == 0 {
                out.push('-');
            }

            if let Some(character) = hex.chars().nth(index) {
                out.push(character);
            }

            index = index.saturating_add(1);
        }

        out
    }

    /// Parses a rendered fingerprint back to bytes.
    ///
    /// # Errors
    ///
    /// [`FingerprintError`] when the string is not exactly the rendered shape. A lenient parser that
    /// accepted a missing separator or a lowercase letter would let a user compare two fingerprints
    /// that differ and be told they match.
    pub fn parse(text: &str) -> Result<Self, FingerprintError> {
        if text.len() != FINGERPRINT_RENDERED {
            return Err(FingerprintError::WrongLength {
                got: text.len(),
                want: FINGERPRINT_RENDERED,
            });
        }

        let mut digits = String::with_capacity(16);

        for (index, character) in text.chars().enumerate() {
            // Separators at 4, 9 and 14 -- the group boundaries.
            if index == 4 || index == 9 || index == 14 {
                if character != '-' {
                    return Err(FingerprintError::BadSeparator {
                        index,
                        got: character,
                    });
                }

                continue;
            }

            if !character.is_ascii_hexdigit() {
                return Err(FingerprintError::NotHexDigit {
                    index,
                    got: character,
                });
            }

            if character.is_ascii_lowercase() {
                return Err(FingerprintError::NotUppercase {
                    index,
                    got: character,
                });
            }

            digits.push(character);
        }

        let decoded = crate::seed::from_hex(&digits)
            .map_err(|_| FingerprintError::NotHexDigit { index: 0, got: '?' })?;

        let mut bytes = [0u8; FINGERPRINT_BYTES];

        for (slot, byte) in bytes.iter_mut().zip(decoded.iter()) {
            *slot = *byte;
        }

        Ok(Self { bytes })
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Why a fingerprint could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// The string was not the rendered length.
    WrongLength {
        /// The length found.
        got: usize,
        /// The length required.
        want: usize,
    },
    /// A separator was missing or in the wrong place.
    BadSeparator {
        /// Where.
        index: usize,
        /// What was found.
        got: char,
    },
    /// A character was not a hex digit.
    NotHexDigit {
        /// Where.
        index: usize,
        /// What was found.
        got: char,
    },
    /// A hex digit was lowercase.
    NotUppercase {
        /// Where.
        index: usize,
        /// What was found.
        got: char,
    },
}

impl core::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { got, want } => {
                write!(f, "a fingerprint is {want} characters, not {got}")
            }
            Self::BadSeparator { index, got } => {
                write!(
                    f,
                    "a separator is required at position {index}, found {got:?}"
                )
            }
            Self::NotHexDigit { index, got } => {
                write!(f, "{got:?} at position {index} is not a hex digit")
            }
            Self::NotUppercase { index, got } => {
                write!(f, "{got:?} at position {index} must be uppercase")
            }
        }
    }
}

impl core::error::Error for FingerprintError {}

/// Derives the six-digit pairing code both sides display.
///
/// `SHA-256("DLWP/1-pairing-code" || 0x00 || pairing_secret || ctrl_nonce || agent_nonce)`, then
/// `decimal(uint32_be(digest[0..4]) mod 1_000_000)`, zero-padded.
///
/// The nonces are included so that the code is specific to this pairing attempt: a code observed once
/// cannot be replayed in a later pairing, because a fresh attempt has fresh nonces.
#[must_use]
pub fn pairing_code(pairing_secret: &[u8], controller_nonce: &[u8], agent_nonce: &[u8]) -> String {
    let mut message = Vec::with_capacity(
        pairing_secret
            .len()
            .saturating_add(controller_nonce.len())
            .saturating_add(agent_nonce.len()),
    );

    message.extend_from_slice(pairing_secret);
    message.extend_from_slice(controller_nonce);
    message.extend_from_slice(agent_nonce);

    let digest = sha256_labeled(b"", PAIRING_CODE_LABEL, &message);

    // Big-endian, as the recipe specifies. A little-endian reading produces a different code from the
    // same digest, which is the kind of divergence that shows up as "the codes do not match" with
    // both implementations reporting they computed the code correctly.
    let first_four = [
        digest.first().copied().unwrap_or(0),
        digest.get(1).copied().unwrap_or(0),
        digest.get(2).copied().unwrap_or(0),
        digest.get(3).copied().unwrap_or(0),
    ];

    let value = u64::from(u32::from_be_bytes(first_four)) % PAIRING_CODE_MODULUS;

    // Zero-padded to six digits, so "7" becomes "000007". Truncation would produce a five-character
    // string about 10% of the time and a display that flickers between widths.
    format!("{value:06}")
}

/// The pairing secret and the three proofs derived from it.
///
/// `Debug` is hand-written to print nothing but the fingerprint-free shape, for the same reason
/// `SessionKeys`' is: this holds the pairing secret, and the pairing secret is the whole security
/// value of the pairing.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingSecret {
    secret: [u8; PAIRING_SECRET_LENGTH],
}

impl core::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingSecret")
            .field("secret", &"<32 bytes>")
            .finish()
    }
}

impl PairingSecret {
    /// Wraps an existing secret.
    #[must_use]
    pub const fn from_bytes(secret: [u8; PAIRING_SECRET_LENGTH]) -> Self {
        Self { secret }
    }

    /// The raw secret, for the key schedule.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PAIRING_SECRET_LENGTH] {
        &self.secret
    }

    /// The controller's proof: `HMAC(secret, "DLWP/1-pairing-controller" || ctrl_nonce || agent_nonce)`.
    #[must_use]
    pub fn controller_proof(
        &self,
        controller_nonce: &[u8],
        agent_nonce: &[u8],
    ) -> [u8; PROOF_LENGTH] {
        let mut message =
            Vec::with_capacity(controller_nonce.len().saturating_add(agent_nonce.len()));

        message.extend_from_slice(controller_nonce);
        message.extend_from_slice(agent_nonce);

        crate::keyschedule::hmac_labeled(&self.secret, PAIRING_CONTROLLER_PROOF_LABEL, &message)
    }

    /// The agent's proof: `HMAC(secret, "DLWP/1-pairing-agent" || agent_nonce || ctrl_nonce)`.
    ///
    /// Note the nonce order: the agent's own nonce comes **first**, the reverse of the controller's.
    /// With the two labels also differing, a reflected message is not a valid proof for either side.
    #[must_use]
    pub fn agent_proof(&self, controller_nonce: &[u8], agent_nonce: &[u8]) -> [u8; PROOF_LENGTH] {
        let mut message =
            Vec::with_capacity(controller_nonce.len().saturating_add(agent_nonce.len()));

        message.extend_from_slice(agent_nonce);
        message.extend_from_slice(controller_nonce);

        crate::keyschedule::hmac_labeled(&self.secret, PAIRING_AGENT_PROOF_LABEL, &message)
    }

    /// The confirmation: `HMAC(secret, "DLWP/1-pairing-confirm" || agent_proof || controller_proof)`.
    ///
    /// Both proofs, in a fixed order. Binding both is what stops a peer from claiming a completed
    /// pairing when the other side only got as far as sending one proof.
    #[must_use]
    pub fn confirmation(&self, controller_proof: &[u8], agent_proof: &[u8]) -> [u8; PROOF_LENGTH] {
        let mut message =
            Vec::with_capacity(agent_proof.len().saturating_add(controller_proof.len()));

        // Agent first, then controller, as the recipe states. The order is load-bearing: the
        // confirmation is a mutual value and both sides must build the same one.
        message.extend_from_slice(agent_proof);
        message.extend_from_slice(controller_proof);

        crate::keyschedule::hmac_labeled(&self.secret, PAIRING_CONFIRMATION_LABEL, &message)
    }

    /// The authentication proofs for the session's AUTH and AUTH_OK frames.
    #[must_use]
    pub fn auth_proofs(&self, transcript_hash: &[u8]) -> AuthProofs {
        AuthProofs {
            client: crate::keyschedule::hmac_labeled(
                &self.secret,
                crate::labels::AUTH_CLIENT_LABEL,
                transcript_hash,
            ),
            agent: crate::keyschedule::hmac_labeled(
                &self.secret,
                crate::labels::AUTH_AGENT_LABEL,
                transcript_hash,
            ),
        }
    }
}

/// The two authentication proofs, exchanged in AUTH and AUTH_OK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthProofs {
    /// The controller's proof.
    pub client: [u8; PROOF_LENGTH],
    /// The agent's proof.
    pub agent: [u8; PROOF_LENGTH],
}

/// Why the pairing secret could not be derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// `shared` was not 32 bytes.
    BadSharedLength {
        /// The length found.
        got: usize,
    },
    /// `dh_static` was not 32 bytes.
    BadDhStaticLength {
        /// The length found.
        got: usize,
    },
    /// `pairing_token` was not 32 bytes.
    BadPairingTokenLength {
        /// The length found.
        got: usize,
    },
    /// The combined input was not 96 bytes.
    ///
    /// The three components are concatenated with no separator, which is safe only because each is
    /// exactly 32 bytes. Without the check, `shared = X`, `dh_static = Y‖Z`, `pairing_token = W` would
    /// produce the same input as a different split of the same buffer.
    BadInputLength {
        /// The length found.
        got: usize,
    },
    /// The X25519 exchanges produced an all-zero secret, which a low-order point produces.
    AllZeroSharedSecret,
    /// HKDF-Expand failed.
    ExpandFailed,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSharedLength { got } => write!(f, "the shared secret is {got} bytes, not 32"),
            Self::BadDhStaticLength { got } => {
                write!(f, "the static DH result is {got} bytes, not 32")
            }
            Self::BadPairingTokenLength { got } => {
                write!(f, "the pairing token is {got} bytes, not 32")
            }
            Self::BadInputLength { got } => {
                write!(f, "the pairing input is {got} bytes, not 96")
            }
            Self::AllZeroSharedSecret => write!(
                f,
                "an X25519 exchange produced an all-zero secret; the pairing must be refused"
            ),
            Self::ExpandFailed => write!(f, "HKDF-Expand failed"),
        }
    }
}

impl core::error::Error for PairingError {}

/// Builds the HKDF salt for the pairing secret: `"DLWP/1-pairing" || 0x00 || pairing_id`.
#[must_use]
pub fn pairing_salt(pairing_id: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(
        PAIRING_SALT_LABEL
            .len()
            .saturating_add(1)
            .saturating_add(pairing_id.len()),
    );

    salt.extend_from_slice(PAIRING_SALT_LABEL.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(pairing_id);

    salt
}

/// Derives the pairing secret.
///
/// `HKDF-Extract(salt = "DLWP/1-pairing" || 0x00 || pairing_id, ikm = shared || dh_static ||
/// pairing_token)`, then `HKDF-Expand(prk, "DLWP/1-pairing-secret", 32)`.
///
/// # Errors
///
/// [`PairingError::AllZeroSharedSecret`] when any of the two X25519 results is all zero, and a
/// `Bad*Length` variant for a component of the wrong size.
pub fn derive_pairing_secret(
    pairing_id: &[u8],
    shared: &[u8],
    dh_static: &[u8],
    pairing_token: &[u8],
) -> Result<PairingSecret, PairingError> {
    if shared.len() != 32 {
        return Err(PairingError::BadSharedLength { got: shared.len() });
    }

    if dh_static.len() != 32 {
        return Err(PairingError::BadDhStaticLength {
            got: dh_static.len(),
        });
    }

    if pairing_token.len() != 32 {
        return Err(PairingError::BadPairingTokenLength {
            got: pairing_token.len(),
        });
    }

    // Both exchange results are checked: an ephemeral exchange that landed on a low-order point is
    // just as fatal as the static one, and checking only the first would leave the other open.
    for (which, value) in [("shared", shared), ("dh_static", dh_static)] {
        if value.iter().all(|byte| *byte == 0) {
            let _ = which;
            return Err(PairingError::AllZeroSharedSecret);
        }
    }

    let mut ikm = Vec::with_capacity(96);

    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(dh_static);
    ikm.extend_from_slice(pairing_token);

    if ikm.len() != 96 {
        return Err(PairingError::BadInputLength { got: ikm.len() });
    }

    let salt = pairing_salt(pairing_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut secret = [0u8; PAIRING_SECRET_LENGTH];

    hkdf.expand(PAIRING_SECRET_INFO.as_bytes(), &mut secret)
        .map_err(|_| PairingError::ExpandFailed)?;

    Ok(PairingSecret { secret })
}

/// An X25519 exchange result, with the contributory check applied.
///
/// # Errors
///
/// [`PairingError::AllZeroSharedSecret`] when the exchange produced all zeros.
pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], PairingError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*secret);
    let peer = PublicKey::from(*peer_public);

    let shared = secret.diffie_hellman(&peer);
    let bytes = shared.to_bytes();

    if bytes.iter().all(|byte| *byte == 0) {
        return Err(PairingError::AllZeroSharedSecret);
    }

    Ok(bytes)
}

/// Verifies a proof in constant time.
///
/// Exists so that a caller cannot use `==` on two proofs by accident: `==` on byte arrays short-
/// circuits, and a comparison time that depends on how many leading bytes matched is an oracle for
/// recovering a valid proof byte by byte.
#[must_use]
pub fn verify_proof(expected: &[u8], received: &[u8]) -> bool {
    constant_time_eq(expected, received)
}

/// The pairing secret's own hash, used as a short comparison value in logs.
///
/// Not a security value and the doc says so: it exists so that a trace can say "these two runs used
/// the same secret" without putting the secret in the log.
#[must_use]
pub fn secret_fingerprint(secret: &PairingSecret) -> String {
    let digest = sha256(&secret.secret);

    crate::seed::to_hex(digest.get(..4).unwrap_or(&[]))
}

/// Verifies an Ed25519 signature.
///
/// Used for the discovery advertisement's `sig` field (RFC-0003 section 2.1) and for the QR pairing
/// URI. Both sign an exact byte string recorded in `crypto-primitives.json`'s `signature_vectors`.
#[must_use]
pub fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        // An invalid public key is a verification failure, not an error: the caller's question is
        // "does this signature verify", and it does not.
        return false;
    };

    // The length is checked BEFORE converting. `signature.try_into::<[u8; 64]>()` succeeds on a
    // 65-byte slice by taking the first 64, so a longer signature -- a padded one, or one with an
    // appended byte from a framing mistake -- would verify on its prefix. My first version did exactly
    // that, and a test asserting that a 65-byte signature is refused is what found it.
    if signature.len() != 64 {
        return false;
    }

    let bytes: [u8; 64] = match signature.try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };

    key.verify(message, &Signature::from_bytes(&bytes)).is_ok()
}

/// Signs a message with an Ed25519 key derived from a seed.
///
/// The seed goes through [`crate::seed::key_from_seed`] so the vector files carry readable seeds
/// rather than key bytes. Test and tooling helper; the agent's real key comes from the platform
/// keystore.
#[must_use]
pub fn sign_ed25519_with_seed(seed: &str, message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};

    let key_bytes = crate::seed::key_from_seed(seed.as_bytes());
    let signing_key = SigningKey::from_bytes(&key_bytes);

    signing_key.sign(message).to_bytes()
}

/// The verifying key derived from a seed, for tests that sign and then verify.
#[must_use]
pub fn ed25519_public_key_with_seed(seed: &str) -> [u8; 32] {
    use ed25519_dalek::SigningKey;

    let key_bytes = crate::seed::key_from_seed(seed.as_bytes());
    let signing_key = SigningKey::from_bytes(&key_bytes);

    signing_key.verifying_key().to_bytes()
}

/// Computes an HMAC that the tests can compare against a vector.
#[must_use]
pub fn proof_bytes(key: &[u8], label: &str, message: &[u8]) -> [u8; 32] {
    crate::keyschedule::hmac_labeled(key, label, message)
}

/// Computes `HMAC-SHA256(key, message)` for the vectors.
#[must_use]
pub fn raw_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac_sha256(key, message)
}
