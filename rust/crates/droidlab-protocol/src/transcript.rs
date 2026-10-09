//! The handshake transcript, and the hash bound into the authentication proofs.
//!
//! RFC-0001 section 5.4 and RFC-0002 section 5.1. The transcript is the byte string:
//!
//! ```text
//! "DLWP/1-handshake" ‖ 0x00 ‖ u16len(client_id) ‖ 0x00 ‖ u16len(agent_id) ‖ 0x00
//!                     ‖ client_nonce(32) ‖ agent_nonce(32) ‖ client_pub(32) ‖ agent_pub(32)
//! ```
//!
//! hashed with SHA-256. Its size is `16 + 1 + (2 + len(client_id)) + 1 + (2 + len(agent_id)) + 1 + 128`.
//!
//! The reason the two identifiers are **length-prefixed** and the four fixed-width fields are not is
//! the whole point of the construction, and it is pinned by `transcript.reject.leading-separator-confusion`:
//! a naive concatenation without prefixes would serialise `client_id = "c"`, `agent_id = "a"` and
//! `client_id = "c\x00a"`, `agent_id = ""` to the same bytes. Both describe a one-character split of
//! the same buffer, so a transcript built without prefixes would let an attacker move a byte between
//! the two identifiers and keep the hash — and the hash is what the AUTH proofs bind.
//!
//! The four 32-byte fields need no prefix because their width is fixed by the algorithm. A
//! length-prefixed variable-width field is indistinguishable from its contents; a fixed-width one is
//! not.

use crate::labels::TRANSCRIPT_LABEL;

/// The transcript label's byte length, as the vector file records it.
pub const LABEL_LENGTH: usize = 16;
/// A separator's byte length.
pub const SEPARATOR_LENGTH: usize = 1;
/// A length prefix's byte length.
pub const LENGTH_PREFIX_LENGTH: usize = 2;
/// A nonce's byte length.
pub const NONCE_LENGTH: usize = 32;
/// A public key's byte length.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The four fixed-width fields, totalled: two nonces and two public keys.
pub const FIXED_WIDTH_TOTAL: usize =
    NONCE_LENGTH + NONCE_LENGTH + PUBLIC_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The transcript bytes, before hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Builds a transcript from the six handshake fields.
    ///
    /// # Errors
    ///
    /// A `Bad*Length` variant when a fixed-width field is not 32 bytes, and
    /// [`TranscriptError::IdentifierTooLong`] when an identifier exceeds what a `u16` prefix can
    /// describe. Both are refused rather than truncated: a truncated identifier changes the transcript
    /// silently, and the transcript is what the proofs bind.
    pub fn new(
        client_id: &str,
        agent_id: &str,
        client_nonce: &[u8],
        agent_nonce: &[u8],
        client_pub: &[u8],
        agent_pub: &[u8],
    ) -> Result<Self, TranscriptError> {
        check_width("client_nonce", client_nonce.len())?;
        check_width("agent_nonce", agent_nonce.len())?;
        check_width("client_pub", client_pub.len())?;
        check_width("agent_pub", agent_pub.len())?;

        let client_bytes = client_id.as_bytes();
        let agent_bytes = agent_id.as_bytes();

        let client_length =
            u16::try_from(client_bytes.len()).map_err(|_| TranscriptError::IdentifierTooLong {
                which: "client_id",
                got: client_bytes.len(),
            })?;
        let agent_length =
            u16::try_from(agent_bytes.len()).map_err(|_| TranscriptError::IdentifierTooLong {
                which: "agent_id",
                got: agent_bytes.len(),
            })?;

        let mut bytes = Vec::with_capacity(Self::length_of(client_bytes.len(), agent_bytes.len()));

        // Component 0: the label, an ASCII literal with no length prefix.
        bytes.extend_from_slice(TRANSCRIPT_LABEL.as_bytes());
        // Component 1: the first separator.
        bytes.push(0x00);

        // Component 2: the client id, u16 big-endian length then UTF-8 bytes. The prefix is what
        // keeps the identifier from being confusable with the separator.
        bytes.extend_from_slice(&client_length.to_be_bytes());
        bytes.extend_from_slice(client_bytes);

        // Component 3: the second separator.
        bytes.push(0x00);

        // Component 4: the agent id.
        bytes.extend_from_slice(&agent_length.to_be_bytes());
        bytes.extend_from_slice(agent_bytes);

        // Component 5: the third separator.
        bytes.push(0x00);

        // Components 6–9: the four fixed-width fields, no prefixes.
        bytes.extend_from_slice(client_nonce);
        bytes.extend_from_slice(agent_nonce);
        bytes.extend_from_slice(client_pub);
        bytes.extend_from_slice(agent_pub);

        Ok(Self { bytes })
    }

    /// The transcript's size for two identifier lengths.
    ///
    /// The formula from the vector file, in one place: `16 + 1 + (2 + len) + 1 + (2 + len) + 1 + 128`.
    #[must_use]
    pub const fn length_of(client_id_len: usize, agent_id_len: usize) -> usize {
        LABEL_LENGTH
            .saturating_add(SEPARATOR_LENGTH)
            .saturating_add(LENGTH_PREFIX_LENGTH)
            .saturating_add(client_id_len)
            .saturating_add(SEPARATOR_LENGTH)
            .saturating_add(LENGTH_PREFIX_LENGTH)
            .saturating_add(agent_id_len)
            .saturating_add(SEPARATOR_LENGTH)
            .saturating_add(FIXED_WIDTH_TOTAL)
    }

    /// The transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The transcript's length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the transcript is empty, which it never is.
    ///
    /// Present because clippy warns when `len` exists without `is_empty`, and returning `false`
    /// rather than omitting the method is the honest answer: the minimum transcript is 153 bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// The SHA-256 hash of the transcript.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        crate::keyschedule::sha256(&self.bytes)
    }

    /// The hash as lowercase hex.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        crate::seed::to_hex(&self.hash())
    }

    /// An owned copy of the transcript bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Checks that a fixed-width field is 32 bytes.
fn check_width(which: &'static str, got: usize) -> Result<(), TranscriptError> {
    if got == NONCE_LENGTH {
        Ok(())
    } else {
        Err(TranscriptError::BadFieldLength { which, got })
    }
}

/// Why a transcript could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptError {
    /// A fixed-width field was not 32 bytes.
    BadFieldLength {
        /// Which field.
        which: &'static str,
        /// The length found.
        got: usize,
    },
    /// An identifier was too long for its `u16` length prefix.
    IdentifierTooLong {
        /// Which identifier.
        which: &'static str,
        /// Its length.
        got: usize,
    },
}

impl core::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFieldLength { which, got } => {
                write!(f, "{which} is {got} bytes, not {NONCE_LENGTH}")
            }
            Self::IdentifierTooLong { which, got } => write!(
                f,
                "{which} is {got} bytes, which a 2-byte length prefix cannot describe"
            ),
        }
    }
}

impl core::error::Error for TranscriptError {}
