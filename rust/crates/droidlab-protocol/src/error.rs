//! The frame-level error model (RFC-0001 §6).
//!
//! Decoding returns these as values rather than panicking. A malformed frame is an **expected**
//! event on a network — an attacker, a version mismatch, or a buggy peer — and the protocol
//! requires a specific error code and severity for each class. Exceptions would push that mapping
//! into catch blocks and lose the distinction between "the peer is on a different version" and
//! "the peer is broken".

use core::fmt;

/// Why a frame could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than 24 bytes were available for a frame header.
    TruncatedHeader {
        /// How many bytes a header needs.
        need: usize,
        /// How many were available.
        got: usize,
    },
    /// The first four bytes were not the ASCII magic `DLWP`.
    BadMagic {
        /// The four bytes that were found.
        got: [u8; 4],
    },
    /// `header_length` was not 24.
    UnsupportedHeaderLength {
        /// The declared length.
        got: u8,
    },
    /// The version is not one this codec speaks.
    VersionMismatch {
        /// The version the peer declared.
        offered: u8,
        /// The version this codec implements.
        supported: u8,
    },
    /// The frame is larger than the negotiated maximum.
    FrameTooLarge {
        /// The declared total size.
        declared: u64,
        /// The negotiated maximum.
        limit: u64,
    },
    /// A message type that is not in the registry.
    UnknownMessageType {
        /// The type code found.
        message_type: u8,
    },
    /// The body was not well-formed cbOR, or violated a DLWP/1 encoding rule.
    Malformed {
        /// A static description of the specific violation.
        reason: &'static str,
    },
    /// The `ENCRYPTED` flag was set on a frame that must be cleartext, or unset on one that must
    /// not.
    EncryptionMismatch {
        /// The message type involved.
        message_type: u8,
        /// Whether the frame was encrypted.
        encrypted: bool,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { need, got } => {
                write!(f, "need {need} bytes for a frame header, got {got}")
            }
            Self::BadMagic { got } => write!(
                f,
                "expected magic 'DLWP', got 0x{:02x}{:02x}{:02x}{:02x}",
                got[0], got[1], got[2], got[3]
            ),
            Self::UnsupportedHeaderLength { got } => {
                write!(f, "expected header_length 24, got {got}")
            }
            Self::VersionMismatch { offered, supported } => {
                write!(
                    f,
                    "peer offered version {offered}, this codec speaks {supported}"
                )
            }
            Self::FrameTooLarge { declared, limit } => {
                write!(f, "frame declares {declared} bytes, limit is {limit}")
            }
            Self::UnknownMessageType { message_type } => {
                write!(f, "message type {message_type} is not in the registry")
            }
            Self::Malformed { reason } => write!(f, "malformed body: {reason}"),
            Self::EncryptionMismatch {
                message_type,
                encrypted,
            } => write!(
                f,
                "message type {message_type} must not be sent with encrypted={encrypted}"
            ),
        }
    }
}

impl core::error::Error for FrameError {}
