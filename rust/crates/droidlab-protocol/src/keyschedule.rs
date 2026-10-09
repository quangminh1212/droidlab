//! The session key schedule, and the record protection built on it.
//!
//! RFC-0002 section 5. Three things are derived from one shared secret and one `pairing_secret`:
//!
//! ```text
//! salt = "DLWP/1-session" || 0x00 || session_id
//! prk  = HKDF-Extract(salt, shared || pairing_secret)
//! ```
//!
//! and from `prk`, five outputs, each with its own info string:
//!
//! | Output | Info | Length |
//! | ------ | ---- | ------ |
//! | `c2a_key` | `"DLWP/1-c2a-key"` | 32 |
//! | `a2c_key` | `"DLWP/1-a2c-key"` | 32 |
//! | `c2a_iv` | `"DLWP/1-c2a-iv"` | 4 |
//! | `a2c_iv` | `"DLWP/1-a2c-iv"` | 4 |
//! | `exporter` | `"DLWP/1-exporter" ‖ transcript_hash` | 32 |
//!
//! Two properties are load-bearing and are what the vectors test:
//!
//! * **Direction separation.** `c2a_key` and `a2c_key` differ *only* in their info string, and that
//!   difference is what stops a frame one side sends from being a valid frame either side receives.
//! * **The transcript hashes only the exporter.** A separate vector asserts that changing
//!   `transcript_hash` leaves the four record-protection values untouched, which is what lets a
//!   retransmitted HELLO be handled without the record keys changing.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::labels::{
    A2C_IV_INFO, A2C_KEY_INFO, C2A_IV_INFO, C2A_KEY_INFO, EXPORTER_LABEL, SESSION_SALT_LABEL,
};

/// The key length, in bytes. AES-256.
pub const KEY_LENGTH: usize = 32;
/// The nonce prefix length, in bytes: the first half of a 96-bit nonce.
pub const IV_PREFIX_LENGTH: usize = 4;
/// The sequence-number half of the nonce, in bytes.
pub const SEQUENCE_LENGTH: usize = 8;
/// The GCM tag length, in bytes.
pub const TAG_LENGTH: usize = 16;
/// The full nonce length: 4-byte prefix plus 8-byte sequence.
pub const NONCE_LENGTH: usize = IV_PREFIX_LENGTH + SEQUENCE_LENGTH;
/// The exporter output length.
pub const EXPORTER_LENGTH: usize = 32;

/// The five outputs of the session key schedule.
///
/// Named fields rather than a tuple, and `Debug` is deliberately **not** derived: this value holds
/// two AES keys, and a `{:?}` that printed them would put session keys into a log. `Debug` is
/// implemented by hand below to print lengths and no bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// The controller-to-agent record key.
    pub c2a_key: [u8; KEY_LENGTH],
    /// The agent-to-controller record key.
    pub a2c_key: [u8; KEY_LENGTH],
    /// The controller-to-agent nonce prefix.
    pub c2a_iv: [u8; IV_PREFIX_LENGTH],
    /// The agent-to-controller nonce prefix.
    pub a2c_iv: [u8; IV_PREFIX_LENGTH],
    /// The exporter secret, bound to the handshake transcript.
    pub exporter: [u8; EXPORTER_LENGTH],
}

impl core::fmt::Debug for SessionKeys {
    /// Prints lengths, never key bytes.
    ///
    /// A derived `Debug` here would be a real defect rather than a style point: `SessionKeys` is the
    /// natural thing to reach for when logging a session's state, and a key that reaches a log is a
    /// key that has left the device.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("c2a_key", &"<32 bytes>")
            .field("a2c_key", &"<32 bytes>")
            .field("c2a_iv", &crate::seed::to_hex(&self.c2a_iv))
            .field("a2c_iv", &crate::seed::to_hex(&self.a2c_iv))
            .field("exporter", &"<32 bytes>")
            .finish()
    }
}

/// Why the key schedule could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheduleError {
    /// The `shared` secret was not 32 bytes.
    BadSharedLength {
        /// The length found.
        got: usize,
    },
    /// The `pairing_secret` was not 32 bytes.
    BadPairingSecretLength {
        /// The length found.
        got: usize,
    },
    /// The `transcript_hash` was not 32 bytes.
    BadTranscriptHashLength {
        /// The length found.
        got: usize,
    },
    /// HKDF-Expand failed, which for these lengths means an internal length error.
    ExpandFailed,
    /// The `shared` secret was X25519's all-zero output.
    ///
    /// RFC-0002 section 7 requires this be refused rather than derived from: an all-zero shared
    /// secret is what a low-order point produces, and it is the same value for every session, so
    /// deriving keys from it gives an attacker known keys rather than secret ones.
    AllZeroSharedSecret,
}

impl core::fmt::Display for KeyScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSharedLength { got } => {
                write!(f, "the shared secret is {got} bytes, not {KEY_LENGTH}")
            }
            Self::BadPairingSecretLength { got } => {
                write!(f, "the pairing secret is {got} bytes, not {KEY_LENGTH}")
            }
            Self::BadTranscriptHashLength { got } => {
                write!(f, "the transcript hash is {got} bytes, not {KEY_LENGTH}")
            }
            Self::ExpandFailed => write!(f, "HKDF-Expand failed"),
            Self::AllZeroSharedSecret => write!(
                f,
                "the X25519 shared secret is all zero, which a low-order point produces; the \
                 connection must be refused rather than keys derived from it"
            ),
        }
    }
}

impl core::error::Error for KeyScheduleError {}

/// Builds the HKDF salt: `"DLWP/1-session" || 0x00 || session_id`.
///
/// The session id is inside the salt, which is what makes a replayed handshake produce different
/// keys. Asserted by `session_id_changes_every_derived_value`.
#[must_use]
pub fn session_salt(session_id: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(
        SESSION_SALT_LABEL
            .len()
            .saturating_add(1)
            .saturating_add(session_id.len()),
    );

    salt.extend_from_slice(SESSION_SALT_LABEL.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(session_id);

    salt
}

/// Builds the HKDF input keying material: `shared || pairing_secret`.
///
/// Concatenated with no separator and no length prefix, which is safe **only because both are exactly
/// 32 bytes**. That is why [`derive_session_keys`] checks both lengths rather than accepting slices:
/// with variable lengths, `shared = X` and `pairing_secret = Y‖Z` would produce the same IKM as
/// `shared = X‖Y` and `pairing_secret = Z`.
#[must_use]
pub fn session_ikm(shared: &[u8], pairing_secret: &[u8]) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(shared.len().saturating_add(pairing_secret.len()));

    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(pairing_secret);

    ikm
}

/// The HKDF info for the exporter: `"DLWP/1-exporter" || transcript_hash`.
///
/// The transcript is appended to the *info* rather than to the IKM or the salt. That choice is what
/// the vector `session.keys.transcript-changes-exporter-only` pins: because the info string is the
/// only place the transcript appears, a retransmitted HELLO changes the exporter and leaves the
/// record keys alone. An implementation that mixed the transcript into the IKM would still derive
/// self-consistent keys and would break reconnection.
#[must_use]
pub fn exporter_info(transcript_hash: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(EXPORTER_LABEL.len().saturating_add(transcript_hash.len()));

    info.extend_from_slice(EXPORTER_LABEL.as_bytes());
    info.extend_from_slice(transcript_hash);

    info
}

/// Derives the five session values.
///
/// # Errors
///
/// * [`KeyScheduleError::AllZeroSharedSecret`] when `shared` is 32 zero bytes.
/// * A `Bad*Length` variant for any input of the wrong size.
/// * [`KeyScheduleError::ExpandFailed`] if HKDF-Expand fails.
pub fn derive_session_keys(
    session_id: &[u8],
    shared: &[u8],
    pairing_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<SessionKeys, KeyScheduleError> {
    if shared.len() != KEY_LENGTH {
        return Err(KeyScheduleError::BadSharedLength { got: shared.len() });
    }

    if pairing_secret.len() != KEY_LENGTH {
        return Err(KeyScheduleError::BadPairingSecretLength {
            got: pairing_secret.len(),
        });
    }

    if transcript_hash.len() != KEY_LENGTH {
        return Err(KeyScheduleError::BadTranscriptHashLength {
            got: transcript_hash.len(),
        });
    }

    // The contributory check, on the OUTPUT rather than on the peer's public key. Checking the input
    // would mean knowing which points are low-order, and RFC 7748 leaves that as an implementation
    // choice; checking the output catches every case including ones a table would miss.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(KeyScheduleError::AllZeroSharedSecret);
    }

    let salt = session_salt(session_id);
    let ikm = session_ikm(shared, pairing_secret);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut c2a_key = [0u8; KEY_LENGTH];
    let mut a2c_key = [0u8; KEY_LENGTH];
    let mut c2a_iv = [0u8; IV_PREFIX_LENGTH];
    let mut a2c_iv = [0u8; IV_PREFIX_LENGTH];
    let mut exporter = [0u8; EXPORTER_LENGTH];

    hkdf.expand(C2A_KEY_INFO.as_bytes(), &mut c2a_key)
        .map_err(|_| KeyScheduleError::ExpandFailed)?;
    hkdf.expand(A2C_KEY_INFO.as_bytes(), &mut a2c_key)
        .map_err(|_| KeyScheduleError::ExpandFailed)?;
    hkdf.expand(C2A_IV_INFO.as_bytes(), &mut c2a_iv)
        .map_err(|_| KeyScheduleError::ExpandFailed)?;
    hkdf.expand(A2C_IV_INFO.as_bytes(), &mut a2c_iv)
        .map_err(|_| KeyScheduleError::ExpandFailed)?;
    hkdf.expand(&exporter_info(transcript_hash), &mut exporter)
        .map_err(|_| KeyScheduleError::ExpandFailed)?;

    Ok(SessionKeys {
        c2a_key,
        a2c_key,
        c2a_iv,
        a2c_iv,
        exporter,
    })
}

/// Which direction a record is travelling in.
///
/// A direction is not a nicety: it selects both the key and the nonce prefix, and it is the only
/// thing separating the two halves of a symmetric channel. The `key()` and `iv()` methods take
/// `SessionKeys`, so a caller cannot accidentally use the same key both ways without writing it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Controller to agent.
    ControllerToAgent,
    /// Agent to controller.
    AgentToController,
}

impl Direction {
    /// This direction's record key.
    #[must_use]
    pub const fn key(self, keys: &SessionKeys) -> &[u8; KEY_LENGTH] {
        match self {
            Self::ControllerToAgent => &keys.c2a_key,
            Self::AgentToController => &keys.a2c_key,
        }
    }

    /// This direction's nonce prefix.
    #[must_use]
    pub const fn iv(self, keys: &SessionKeys) -> &[u8; IV_PREFIX_LENGTH] {
        match self {
            Self::ControllerToAgent => &keys.c2a_iv,
            Self::AgentToController => &keys.a2c_iv,
        }
    }

    /// The opposite direction, which is the one a reply travels in.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::ControllerToAgent => Self::AgentToController,
            Self::AgentToController => Self::ControllerToAgent,
        }
    }
}

/// Builds the 12-byte nonce: `iv_prefix(4) || sequence_number(8, big-endian)`.
///
/// The layout is what guarantees nonce uniqueness per direction: the prefix is fixed per direction
/// per session, and the sequence number never repeats within a session, so the same (key, nonce)
/// pair cannot occur twice. Getting this wrong is a **catastrophic** AEAD failure rather than a
/// correctness one — a repeated nonce under the same key lets an attacker recover plaintext — which
/// is why the layout has its own vector and its own test rather than being implied.
#[must_use]
pub fn build_nonce(iv_prefix: &[u8; IV_PREFIX_LENGTH], sequence_number: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];

    for (slot, byte) in nonce.iter_mut().zip(iv_prefix.iter()) {
        *slot = *byte;
    }

    let sequence = sequence_number.to_be_bytes();

    for (slot, byte) in nonce.iter_mut().skip(IV_PREFIX_LENGTH).zip(sequence.iter()) {
        *slot = *byte;
    }

    nonce
}

/// Why a record could not be protected or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The associated data was not the 24-byte header.
    BadAadLength {
        /// The length found.
        got: usize,
    },
    /// Encryption failed.
    SealFailed,
    /// Decryption or tag verification failed.
    ///
    /// Deliberately one variant for every cause: a tag that does not verify, a header that was
    /// tampered with, and a truncated ciphertext are indistinguishable to the receiver, and giving
    /// them different errors would tell an attacker which part of a forged frame was wrong.
    OpenFailed,
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadAadLength { got } => {
                write!(f, "the associated data is {got} bytes, not 24")
            }
            Self::SealFailed => write!(f, "AEAD encryption failed"),
            Self::OpenFailed => write!(
                f,
                "AEAD tag verification failed: the frame was modified, truncated, or meant for a \
                 different key or direction"
            ),
        }
    }
}

impl core::error::Error for RecordError {}

/// Encrypts a plaintext body, returning `nonce || ciphertext || tag`.
///
/// # Errors
///
/// [`RecordError::BadAadLength`] when the associated data is not 24 bytes, and
/// [`RecordError::SealFailed`] on an AEAD failure.
pub fn seal(
    keys: &SessionKeys,
    direction: Direction,
    sequence_number: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RecordError> {
    if aad.len() != crate::FIXED_LENGTH {
        return Err(RecordError::BadAadLength { got: aad.len() });
    }

    let cipher =
        Aes256Gcm::new_from_slice(direction.key(keys)).map_err(|_| RecordError::SealFailed)?;

    let nonce_bytes = build_nonce(direction.iv(keys), sequence_number);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| RecordError::SealFailed)?;

    // `nonce || ciphertext || tag` is exactly what `aes-gcm` returns: it appends the 16-byte tag to
    // the ciphertext, so prefixing the nonce gives the wire form.
    let mut out = Vec::with_capacity(NONCE_LENGTH.saturating_add(ciphertext.len()));

    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Opens an encrypted body: `nonce || ciphertext || tag` back to plaintext.
///
/// The nonce is taken from the body rather than rebuilt from the frame's sequence number. That is
/// deliberate: rebuilding it would mean a frame whose nonce does not match its sequence number would
/// still decrypt, and the binding between the two is part of what the tag protects. Taking it from
/// the body means the sender's own nonce is the one verified.
///
/// # Errors
///
/// [`RecordError::BadAadLength`] for associated data that is not 24 bytes, and
/// [`RecordError::OpenFailed`] for anything that fails tag verification or is too short to hold a
/// nonce and tag.
pub fn open(
    keys: &SessionKeys,
    direction: Direction,
    body: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RecordError> {
    if aad.len() != crate::FIXED_LENGTH {
        return Err(RecordError::BadAadLength { got: aad.len() });
    }

    if body.len() < NONCE_LENGTH.saturating_add(TAG_LENGTH) {
        return Err(RecordError::OpenFailed);
    }

    let nonce_bytes = body.get(..NONCE_LENGTH).ok_or(RecordError::OpenFailed)?;
    let ciphertext = body.get(NONCE_LENGTH..).ok_or(RecordError::OpenFailed)?;

    let cipher =
        Aes256Gcm::new_from_slice(direction.key(keys)).map_err(|_| RecordError::OpenFailed)?;

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| RecordError::OpenFailed)
}

/// Builds the associated data: the 24-byte header with `body_length` replaced by the plaintext length.
///
/// The substitution is what makes the AAD the same string on both sides. The sender's frame header
/// carries the *ciphertext* length, which the receiver can only know after reading the frame; the
/// plaintext length is known before encryption. Authenticating the ciphertext length instead would
/// mean the receiver had to decrypt to compute the AAD, which is not possible.
///
/// # Errors
///
/// [`RecordError::BadAadLength`] when the header is not 24 bytes.
pub fn aad_from_header(header: &[u8], plaintext_len: u32) -> Result<Vec<u8>, RecordError> {
    if header.len() != crate::FIXED_LENGTH {
        return Err(RecordError::BadAadLength { got: header.len() });
    }

    let mut aad = header.to_vec();

    // Bytes 20–23 are the big-endian body length. Written with `to_be_bytes` rather than shifted by
    // hand, and through a slice rather than by index, because this crate denies indexing on the
    // library target.
    let length = plaintext_len.to_be_bytes();

    if let Some(range) = aad.get_mut(20..crate::FIXED_LENGTH) {
        for (slot, byte) in range.iter_mut().zip(length.iter()) {
            *slot = *byte;
        }
    }

    Ok(aad)
}

/// Computes HMAC-SHA256.
///
/// # Panics
///
/// Does not panic: `new_from_slice` accepts a key of any length for HMAC. Written as a `match` rather
/// than `expect` because this crate denies `expect` on the library target, and the fallback is
/// unreachable.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return [0u8; 32];
    };

    mac.update(message);

    mac.finalize().into_bytes().into()
}

/// Computes `HMAC-SHA256(key, label || message)`, the shape every proof in RFC-0002 uses.
#[must_use]
pub fn hmac_labeled(key: &[u8], label: &str, message: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(label.len().saturating_add(message.len()));

    buffer.extend_from_slice(label.as_bytes());
    buffer.extend_from_slice(message);

    hmac_sha256(key, &buffer)
}

/// Computes SHA-256.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;

    let mut hasher = Sha256::new();
    hasher.update(data);

    hasher.finalize().into()
}

/// Computes `SHA-256(label || 0x00 || message)`.
///
/// The `0x00` separator is present in the fingerprint, the pairing code and the seed rule, and absent
/// in the transcript label's use — the transcript puts its label first and then a separator, so the
/// two shapes are genuinely different and are not unified here.
#[must_use]
pub fn sha256_labeled(key: &[u8], label: &str, message: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(
        key.len()
            .saturating_add(label.len())
            .saturating_add(1)
            .saturating_add(message.len()),
    );

    buffer.extend_from_slice(key);
    buffer.extend_from_slice(label.as_bytes());
    buffer.push(0x00);
    buffer.extend_from_slice(message);

    sha256(&buffer)
}

/// Compares two byte strings in constant time.
///
/// No early return on the first differing byte, and the loop runs over the longer input, XORing with
/// a value that is zero when the shorter input has run out. `aes-gcm` and `hmac` already compare tags
/// this way; this exists for the proofs and the pairing code, where a comparison time that depends on
/// how many leading bytes match is an oracle.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    // Length is not secret, so an early length check is fine and avoids the index arithmetic.
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;

    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }

    difference == 0
}
