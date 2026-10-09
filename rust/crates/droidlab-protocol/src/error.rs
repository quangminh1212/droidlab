//! The frame-level error model (RFC-0001 §6).
//!
//! Decoding returns these as values rather than panicking. A malformed frame is an **expected**
//! event on a network — an attacker, a version mismatch, or a buggy peer — and the protocol
//! requires a specific error code and severity for each class. Exceptions would push that mapping
//! into catch blocks and lose the distinction between "the peer is on a different version" and
//! "the peer is broken".

use core::fmt;

/// A DLWP/1 error code from the RFC-0001 §6 registry.
///
/// The wire names and severities come from `protocol/registry/dlwp-1.json`, which is normative.
/// The Kotlin `ErrorCode` enum is generated from that file and the C# one is written by hand
/// against it; this is the third, and it is written by hand here rather than generated to keep the
/// crate free of build-time code generation. The conformance suite checks every name and severity
/// against the registry, so "written by hand" does not mean "unchecked".
///
/// **Severity is the part that matters.** A recoverable fault leaves the session alone and the
/// controller can retry; a fatal one closes it. Collapsing the two would tell a controller to
/// retry a framing error, which is why severity is carried on the code rather than looked up at
/// the point of use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCode {
    /// The header's `header_length` is not one this version supports.
    UnsupportedHeader = 1,
    /// The frame is larger than the negotiated limit.
    FrameTooLarge = 2,
    /// The body is not well-formed, or violates an encoding rule.
    Malformed = 3,
    /// The peer's protocol version is not one this session can use.
    VersionMismatch = 4,
    /// The handshake transcript does not match what was expected.
    HandshakeMismatch = 5,
    /// The peer is not authenticated.
    Unauthorized = 6,
    /// The device requires pairing before this session can proceed.
    PairingRequired = 7,
    /// The pairing was revoked by the operator.
    PairingRevoked = 8,
    /// A sequence number was seen twice.
    ReplayDetected = 9,
    /// A message arrived in a state that does not accept it.
    UnexpectedMessage = 10,
    /// The message type is not in the registry.
    UnsupportedMessage = 11,
    /// The message is known but a capability it needs was not negotiated.
    UnsupportedFeature = 12,
    /// The request is not legal in the current session state.
    BadState = 13,
    /// The channel id is not open.
    ChannelUnknown = 14,
    /// The channel limit for this session has been reached.
    ChannelLimit = 15,
    /// The operator has not granted this operation.
    PermissionDenied = 16,
    /// The operation is refused by policy.
    NotAllowed = 17,
    /// The operation did not finish in time.
    Timeout = 18,
    /// The agent is at its session limit.
    Busy = 19,
    /// A resource limit was reached.
    ResourceExhausted = 20,
    /// An underlying input or output operation failed.
    Io = 21,
    /// An internal error.
    Internal = 22,
}

/// How badly a fault damages the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The frame was refused and the session continues.
    Recoverable,
    /// The session must be closed.
    Fatal,
}

impl ErrorCode {
    /// Every code, in registry order, for cross-checking against `dlwp-1.json`.
    pub const ALL: [Self; 22] = [
        Self::UnsupportedHeader,
        Self::FrameTooLarge,
        Self::Malformed,
        Self::VersionMismatch,
        Self::HandshakeMismatch,
        Self::Unauthorized,
        Self::PairingRequired,
        Self::PairingRevoked,
        Self::ReplayDetected,
        Self::UnexpectedMessage,
        Self::UnsupportedMessage,
        Self::UnsupportedFeature,
        Self::BadState,
        Self::ChannelUnknown,
        Self::ChannelLimit,
        Self::PermissionDenied,
        Self::NotAllowed,
        Self::Timeout,
        Self::Busy,
        Self::ResourceExhausted,
        Self::Io,
        Self::Internal,
    ];

    /// The code with a given wire name, for reading a registry.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.wire_name() == name)
    }

    /// The wire name, as it appears in the registry and on a log line.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UnsupportedHeader => "ERR_UNSUPPORTED_HEADER",
            Self::FrameTooLarge => "ERR_FRAME_TOO_LARGE",
            Self::Malformed => "ERR_MALFORMED",
            Self::VersionMismatch => "ERR_VERSION_MISMATCH",
            Self::HandshakeMismatch => "ERR_HANDSHAKE_MISMATCH",
            Self::Unauthorized => "ERR_UNAUTHORIZED",
            Self::PairingRequired => "ERR_PAIRING_REQUIRED",
            Self::PairingRevoked => "ERR_PAIRING_REVOKED",
            Self::ReplayDetected => "ERR_REPLAY_DETECTED",
            Self::UnexpectedMessage => "ERR_UNEXPECTED_MESSAGE",
            Self::UnsupportedMessage => "ERR_UNSUPPORTED_MESSAGE",
            Self::UnsupportedFeature => "ERR_UNSUPPORTED_FEATURE",
            Self::BadState => "ERR_BAD_STATE",
            Self::ChannelUnknown => "ERR_CHANNEL_UNKNOWN",
            Self::ChannelLimit => "ERR_CHANNEL_LIMIT",
            Self::PermissionDenied => "ERR_PERMISSION_DENIED",
            Self::NotAllowed => "ERR_NOT_ALLOWED",
            Self::Timeout => "ERR_TIMEOUT",
            Self::Busy => "ERR_BUSY",
            Self::ResourceExhausted => "ERR_RESOURCE_EXHAUSTED",
            Self::Io => "ERR_IO",
            Self::Internal => "ERR_INTERNAL",
        }
    }

    /// Whether a fault with this code leaves the session usable.
    ///
    /// The RECOVERABLE set is listed rather than the fatal one, so that a code added to the
    /// registry without a decision here is treated as **fatal**. A new error nobody has classified
    /// is not one a controller should retry into, and defaulting the other way would make an
    /// unclassified fault silently retryable.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::UnsupportedMessage
            | Self::UnsupportedFeature
            | Self::BadState
            | Self::ChannelUnknown
            | Self::ChannelLimit
            | Self::PermissionDenied
            | Self::NotAllowed
            | Self::Timeout
            | Self::Busy
            | Self::ResourceExhausted
            | Self::Io => Severity::Recoverable,
            _ => Severity::Fatal,
        }
    }

    /// Whether a fault with this code closes the session.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self.severity(), Severity::Fatal)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

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

impl FrameError {
    /// The DLWP/1 error code this failure must be reported as.
    ///
    /// Stated once here rather than at each call site, so a caller cannot invent a code, and so the
    /// mapping can be read in one place. The severity follows from [`ErrorCode::severity`].
    ///
    /// Note what is **fatal** and what is not. A bad magic is fatal — the peer is not speaking
    /// DLWP/1 at all, so there is nothing to recover. A bad `header_length` is fatal too, because
    /// the framing is not one this version can resynchronise on. An unknown message type and an
    /// unnegotiated feature are recoverable, because the framing is sound and only the payload is
    /// unusable.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::TruncatedHeader { .. }
            | Self::BadMagic { .. }
            | Self::Malformed { .. }
            | Self::EncryptionMismatch { .. } => ErrorCode::Malformed,
            Self::UnsupportedHeaderLength { .. } => ErrorCode::UnsupportedHeader,
            Self::VersionMismatch { .. } => ErrorCode::VersionMismatch,
            Self::FrameTooLarge { .. } => ErrorCode::FrameTooLarge,
            Self::UnknownMessageType { .. } => ErrorCode::UnsupportedMessage,
        }
    }
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
