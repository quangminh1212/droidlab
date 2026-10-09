//! Message-body validation against the DLWP/1 schema, and the semantic checks a frame's bytes alone
//! cannot carry.
//!
//! The classifier in [`crate::classify`] answers questions about a frame's **bytes**. A large part of
//! `malformed.json` asks questions the bytes do not answer:
//!
//! | Vector | Needs |
//! | ------ | ----- |
//! | `unknown-capability-command` | the negotiated capability set |
//! | `channel-not-opened` | the set of open channels |
//! | `channel-limit` | `max_channels` and the current count |
//! | `missing-required-key` | the message's schema |
//! | `wrong-value-type` | the message's schema |
//! | `unknown-extra-key-ignored` | the message's schema, to know the key is extra |
//! | `first-frame-not-hello` | the session state |
//! | `second-auth-rejected` | the session state |
//!
//! So this module carries a small, explicit **body schema** table: for each message type, which keys
//! are required and which value types they hold. It is not a general schema engine and it is not meant
//! to be one — it is the subset the vectors exercise, written out so that a reader can check it against
//! RFC-0001 section 6 by eye.
//!
//! The forward-compatibility rule is the subtle one and it is why validation is keyed rather than
//! positional: an unknown key must be **ignored**, not rejected. That is the single case where a
//! "malformed-looking" body is accepted, and a validator that refused unknown keys would break every
//! future minor version.

use crate::cbor::{self, CborError, Value};
use crate::error::ErrorCode;
use crate::limits::Limits;

/// The value type a schema entry requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// A cbOR unsigned integer.
    Unsigned,
    /// A cbOR text string.
    Text,
    /// A cbOR byte string.
    Bytes,
    /// A cbOR array.
    Array,
    /// A cbOR map.
    Map,
    /// A cbOR boolean, which DLWP/1 encodes as an integer 0 or 1.
    Boolean,
    /// Either an unsigned integer or a text string.
    ///
    /// For fields like `text`, which RFC-0001 allows as either a string or a codepoint array.
    UnsignedOrText,
}

impl FieldType {
    /// Whether a decoded value satisfies this type.
    #[must_use]
    pub fn accepts(self, value: &Value) -> bool {
        match self {
            Self::Unsigned => matches!(value, Value::Unsigned(_)),
            Self::Text => matches!(value, Value::Text(_)),
            Self::Bytes => matches!(value, Value::ByteString(_)),
            Self::Array => matches!(value, Value::Array(_)),
            Self::Map => matches!(value, Value::Map(_)),
            Self::Boolean => matches!(value, Value::Unsigned(0 | 1)),
            Self::UnsignedOrText => matches!(value, Value::Unsigned(_) | Value::Text(_)),
        }
    }
}

/// One field of a message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    /// The cbOR text key.
    pub key: &'static str,
    /// The required type.
    pub field_type: FieldType,
    /// Whether the field must be present.
    pub required: bool,
}

impl FieldSpec {
    /// A required field.
    #[must_use]
    pub const fn required(key: &'static str, field_type: FieldType) -> Self {
        Self {
            key,
            field_type,
            required: true,
        }
    }

    /// An optional field.
    #[must_use]
    pub const fn optional(key: &'static str, field_type: FieldType) -> Self {
        Self {
            key,
            field_type,
            required: false,
        }
    }
}

/// A message body's schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodySchema {
    /// The message type this schema describes.
    pub message_type: u8,
    /// Its fields. Unknown keys are not listed and must be ignored.
    pub fields: &'static [FieldSpec],
}

/// Why a body failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// The body was not a cbOR map.
    NotAMap {
        /// The cbOR defect.
        error: CborError,
    },
    /// A required key was absent.
    MissingKey {
        /// The key.
        key: &'static str,
    },
    /// A key was present with the wrong type.
    WrongType {
        /// The key.
        key: &'static str,
        /// What was required.
        expected: FieldType,
    },
    /// The message type has no schema in this table.
    UnknownMessageType {
        /// The type.
        message_type: u8,
    },
}

impl ValidationError {
    /// The error code this failure produces.
    ///
    /// Always `ERR_MALFORMED`, and the vectors say why: a body that fails validation is fatal because
    /// "the peer cannot be trusted to resynchronise". Silently coercing a coordinate is how a mis-tap
    /// bug is born.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        ErrorCode::Malformed
    }
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAMap { error } => write!(f, "the body is not a cbOR map: {}", error.message),
            Self::MissingKey { key } => write!(f, "the required key {key:?} is absent"),
            Self::WrongType { key, expected } => {
                write!(
                    f,
                    "the key {key:?} has the wrong type, expected {expected:?}"
                )
            }
            Self::UnknownMessageType { message_type } => {
                write!(f, "message type {message_type} has no schema in this table")
            }
        }
    }
}

impl core::error::Error for ValidationError {}

/// The body schemas this crate knows, taken from RFC-0001 section 6.
///
/// Deliberately partial and deliberately explicit. The vectors exercise a handful of message types, and
/// writing out only those keeps each entry checkable against the RFC by eye. A general schema engine
/// would be more code and less verifiable.
pub const SCHEMAS: &[BodySchema] = &[
    // HELLO: RFC-0001 6.1. client_id and client_nonce are required.
    BodySchema {
        message_type: 0x01,
        fields: &[
            FieldSpec::required("client_id", FieldType::Text),
            FieldSpec::required("client_nonce", FieldType::Bytes),
            FieldSpec::required("client_pub", FieldType::Bytes),
            FieldSpec::optional("version", FieldType::Text),
        ],
    },
    // HELLO_ACK: RFC-0001 6.1.
    BodySchema {
        message_type: 0x02,
        fields: &[
            FieldSpec::required("agent_id", FieldType::Text),
            FieldSpec::required("agent_nonce", FieldType::Bytes),
            FieldSpec::required("agent_pub", FieldType::Bytes),
        ],
    },
    // AUTH: the transcript hash.
    BodySchema {
        message_type: 0x03,
        fields: &[FieldSpec::required("transcript_hash", FieldType::Bytes)],
    },
    // AUTH_OK.
    BodySchema {
        message_type: 0x04,
        fields: &[FieldSpec::required("transcript_hash", FieldType::Bytes)],
    },
    // INPUT_TOUCH: RFC-0001 6.5. `action` and `pointers` are required, and a pointer needs id, x, y.
    BodySchema {
        message_type: 0x40,
        fields: &[
            FieldSpec::required("action", FieldType::Text),
            FieldSpec::required("pointers", FieldType::Array),
        ],
    },
    // SHELL_EXEC: an argv, not a command string.
    BodySchema {
        message_type: 0x50,
        fields: &[
            FieldSpec::required("exe", FieldType::Text),
            FieldSpec::required("argv", FieldType::Array),
        ],
    },
    // VIDEO_FRAME.
    BodySchema {
        message_type: 0x32,
        fields: &[
            FieldSpec::required("flags", FieldType::Unsigned),
            FieldSpec::optional("pts", FieldType::Unsigned),
        ],
    },
    // CHANNEL_OPEN.
    BodySchema {
        message_type: 0x20,
        fields: &[
            FieldSpec::required("channel_id", FieldType::Unsigned),
            FieldSpec::required("kind", FieldType::Text),
        ],
    },
];

/// Finds the schema for a message type.
#[must_use]
pub fn schema_for(message_type: u8) -> Option<&'static BodySchema> {
    SCHEMAS
        .iter()
        .find(|schema| schema.message_type == message_type)
}

/// Validates a decoded body against a message type's schema.
///
/// # Errors
///
/// [`ValidationError::UnknownMessageType`] when there is no schema, or a `MissingKey` / `WrongType`
/// variant. Unknown keys are **not** an error.
pub fn validate_body(message_type: u8, body: &[(Value, Value)]) -> Result<(), ValidationError> {
    let schema =
        schema_for(message_type).ok_or(ValidationError::UnknownMessageType { message_type })?;

    for field in schema.fields {
        // Look the key up by its text form. A body whose keys are not text cannot match, and a
        // missing text key is a missing field.
        let found = body.iter().find_map(|(key, value)| match key {
            Value::Text(text) if text == field.key => Some(value),
            _ => None,
        });

        match found {
            Some(value) => {
                if !field.field_type.accepts(value) {
                    return Err(ValidationError::WrongType {
                        key: field.key,
                        expected: field.field_type,
                    });
                }
            }
            None => {
                if field.required {
                    return Err(ValidationError::MissingKey { key: field.key });
                }
            }
        }
    }

    // Unknown keys are ignored by design. This is the forward-compatibility rule and the reason a
    // loop over the schema's own fields is the correct shape: a validator that iterated the BODY
    // would reject the extra key.
    Ok(())
}

/// Validates a raw body, decoding it first.
///
/// # Errors
///
/// [`ValidationError::NotAMap`] when the bytes are not a cbOR map.
pub fn validate_raw_body(message_type: u8, body: &[u8]) -> Result<(), ValidationError> {
    let map = cbor::parse_map(body).map_err(|error| ValidationError::NotAMap { error })?;

    validate_body(message_type, &map)
}

/// Whether a message type requires a capability, and the capability's name.
///
/// The registry's `message_type_capability` maps message types to capabilities. This is the subset the
/// vectors exercise, plus the ones a session needs.
#[must_use]
pub const fn capability_for_message_type(message_type: u8) -> Option<&'static str> {
    match message_type {
        0x30..=0x33 => Some("screen.mirror"),
        0x34 => Some("telemetry.stats"),
        0x40 | 0x43 => Some("input.touch"),
        0x41 => Some("input.key"),
        0x42 => Some("input.text"),
        0x44 => Some("input.gesture"),
        0x50..=0x52 => Some("shell.exec"),
        0x60..=0x63 => Some("file.read"),
        0x64 | 0x65 => Some("file.write"),
        0x70 | 0x72 => Some("clipboard.read"),
        0x71 => Some("clipboard.write"),
        0x80 | 0x81 => Some("device.info"),
        0x82 | 0x83 => Some("log.stream"),
        0x90 => Some("app.install"),
        0x91 | 0x92 => Some("app.launch"),
        _ => None,
    }
}

/// Checks whether a message type is allowed by a negotiated capability set.
///
/// A message type with no capability requirement is always allowed, which is what makes the handshake
/// and the error channel work before any capability is negotiated.
#[must_use]
pub fn is_capability_allowed(message_type: u8, negotiated: &[String]) -> bool {
    match capability_for_message_type(message_type) {
        None => true,
        Some(required) => negotiated.iter().any(|name| name == required),
    }
}

/// What a session-level check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticCheck {
    /// The error code, or `None` when the message is allowed.
    pub code: Option<ErrorCode>,
    /// A short explanation.
    pub reason: &'static str,
}

impl SemanticCheck {
    /// The message is allowed.
    #[must_use]
    pub const fn allowed(reason: &'static str) -> Self {
        Self { code: None, reason }
    }

    /// The message is refused with a code.
    #[must_use]
    pub const fn refused(code: ErrorCode, reason: &'static str) -> Self {
        Self {
            code: Some(code),
            reason,
        }
    }
}

/// Checks a message type against the negotiated capability set.
#[must_use]
pub fn check_capability(message_type: u8, negotiated: &[String]) -> SemanticCheck {
    if is_capability_allowed(message_type, negotiated) {
        SemanticCheck::allowed("the message's capability was negotiated")
    } else {
        SemanticCheck::refused(
            ErrorCode::UnsupportedFeature,
            "the message type needs a capability this session did not negotiate",
        )
    }
}

/// Checks whether a message names a channel that was opened.
///
/// Channel 0 is **always** open — the control channel — which is why the `channel-not-opened` vector
/// insists its frame "must name a non-zero channel". Checking every channel against the open set
/// would refuse the control channel.
#[must_use]
pub fn check_channel(channel_id: u32, open_channels: &[u32]) -> SemanticCheck {
    if channel_id == 0 {
        return SemanticCheck::allowed("channel 0 is the control channel and is always open");
    }

    if open_channels.contains(&channel_id) {
        SemanticCheck::allowed("the channel is open")
    } else {
        SemanticCheck::refused(
            ErrorCode::ChannelUnknown,
            "the message names a channel that was never opened",
        )
    }
}

/// Checks whether one more channel may be opened.
///
/// `max_channels` counts the control channel, so a limit of 8 permits the control channel plus 7 data
/// channels. Expressed through [`Limits::permits_open_channel`], which is the single place that
/// subtraction lives.
#[must_use]
pub fn check_channel_limit(open_count: usize, limits: &Limits) -> SemanticCheck {
    let open = u32::try_from(open_count).unwrap_or(u32::MAX);

    if limits.permits_open_channel(open) {
        SemanticCheck::allowed("the channel count is below the limit")
    } else {
        SemanticCheck::refused(
            ErrorCode::ChannelLimit,
            "opening another channel would exceed max_channels",
        )
    }
}
