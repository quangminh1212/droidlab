//! The DLWP/1 message type registry.
//!
//! The table is transcribed from `protocol/registry/dlwp-1.json`'s `message_types` array, and the tests
//! read that file and compare against it. That direction matters: a transcription checked only against
//! itself drifts silently, and this repository has already found four defects of exactly that shape (a
//! label length written from memory, a header length written from memory, and a `0xF1` placed in the
//! wrong field of a fixture). So this table is a transcription and the test is the authority.
//!
//! The critical property, and the one that has caused a defect in another implementation: **the code is
//! the registry's 1-based `code`, not the 0-based index of the JSON object's keys.** `HELLO` is code 1,
//! not 0. A decoder that used the enumeration order would read every message type as one less than the
//! sender intended, and it would work for `HELLO` alone — which is exactly why the bug survives a
//! shallow test.

/// How a message type may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The Windows controller sends it.
    ControllerToAgent,
    /// The Android agent sends it.
    AgentToController,
    /// Either side sends it.
    Both,
}

impl Direction {
    /// The registry's name for this direction.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ControllerToAgent => "controller_to_agent",
            Self::AgentToController => "agent_to_controller",
            Self::Both => "both",
        }
    }

    /// Whether a controller may send a message of this direction.
    #[must_use]
    pub const fn controller_may_send(self) -> bool {
        matches!(self, Self::ControllerToAgent | Self::Both)
    }

    /// Whether an agent may send a message of this direction.
    #[must_use]
    pub const fn agent_may_send(self) -> bool {
        matches!(self, Self::AgentToController | Self::Both)
    }
}

/// Which channel a message type may travel on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelScope {
    /// The control channel only.
    Control,
    /// A data channel only. (No type uses this.)
    Data,
    /// Either.
    Any,
}

impl ChannelScope {
    /// The registry's name for this scope.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::Any => "any",
        }
    }

    /// Whether a message of this scope may travel on the control channel.
    #[must_use]
    pub const fn permits_control(self) -> bool {
        matches!(self, Self::Control | Self::Any)
    }

    /// Whether a message of this scope may travel on a data channel.
    #[must_use]
    pub const fn permits_data(self) -> bool {
        matches!(self, Self::Data | Self::Any)
    }
}

/// One registered message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageType {
    /// The wire code. 1-based, and never the enumeration index.
    pub code: u8,
    /// The registry's name.
    pub name: &'static str,
    /// Who may send it.
    pub direction: Direction,
    /// Where it may travel.
    pub channel: ChannelScope,
    /// Whether the registry marks it as necessarily encrypted.
    pub encrypted: bool,
}

/// Every registered message type, in the registry's own order.
pub const MESSAGE_TYPES: &[MessageType] = &[
    MessageType {
        code: 1,
        name: "HELLO",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: false,
    },
    MessageType {
        code: 2,
        name: "HELLO_ACK",
        direction: Direction::AgentToController,
        channel: ChannelScope::Control,
        encrypted: false,
    },
    MessageType {
        code: 3,
        name: "AUTH",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 4,
        name: "AUTH_OK",
        direction: Direction::AgentToController,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 5,
        name: "PING",
        direction: Direction::Both,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 6,
        name: "PONG",
        direction: Direction::Both,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 16,
        name: "GET_CAPABILITIES",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 17,
        name: "CAPABILITIES",
        direction: Direction::AgentToController,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 32,
        name: "CHANNEL_OPEN",
        direction: Direction::Both,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 33,
        name: "CHANNEL_OPENED",
        direction: Direction::Both,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 34,
        name: "CHANNEL_CLOSE",
        direction: Direction::Both,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 48,
        name: "VIDEO_START",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 49,
        name: "VIDEO_CONFIG",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 50,
        name: "VIDEO_FRAME",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 51,
        name: "VIDEO_STOP",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 52,
        name: "VIDEO_STATS",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 64,
        name: "INPUT_TOUCH",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 65,
        name: "INPUT_KEY",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 66,
        name: "INPUT_TEXT",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 67,
        name: "INPUT_SCROLL",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 68,
        name: "INPUT_GESTURE",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 80,
        name: "SHELL_EXEC",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 81,
        name: "SHELL_STDOUT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 82,
        name: "SHELL_EXIT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 96,
        name: "FILE_LIST",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 97,
        name: "FILE_LIST_RESULT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 98,
        name: "FILE_PULL",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 99,
        name: "FILE_CHUNK",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 100,
        name: "FILE_PUSH",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 101,
        name: "FILE_RESULT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 112,
        name: "CLIPBOARD_GET",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 113,
        name: "CLIPBOARD_SET",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 114,
        name: "CLIPBOARD_DATA",
        direction: Direction::AgentToController,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 128,
        name: "DEVICE_INFO",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 129,
        name: "DEVICE_INFO_RESULT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 130,
        name: "LOG_SUBSCRIBE",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 131,
        name: "LOG_ENTRY",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 144,
        name: "APP_INSTALL",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 145,
        name: "APP_LAUNCH",
        direction: Direction::ControllerToAgent,
        channel: ChannelScope::Control,
        encrypted: true,
    },
    MessageType {
        code: 146,
        name: "APP_RESULT",
        direction: Direction::AgentToController,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 240,
        name: "ERROR",
        direction: Direction::Both,
        channel: ChannelScope::Any,
        encrypted: true,
    },
    MessageType {
        code: 241,
        name: "SESSION_END",
        direction: Direction::Both,
        channel: ChannelScope::Control,
        encrypted: true,
    },
];

/// Looks up a message type by its code.
#[must_use]
pub fn message_type(code: u8) -> Option<&'static MessageType> {
    MESSAGE_TYPES.iter().find(|entry| entry.code == code)
}

/// Looks up a message type by its registry name.
#[must_use]
pub fn message_type_by_name(name: &str) -> Option<&'static MessageType> {
    MESSAGE_TYPES.iter().find(|entry| entry.name == name)
}

/// Whether a code is a registered message type.
///
/// The check the `unknown-message-type` vector is about. Note the vector's code is **254**, which is
/// deliberately above the highest registered code (241) but inside the `u8` range -- so a receiver
/// cannot use "is it within the range of known codes" as the test. The table has gaps (7..15, 18..31,
/// and so on) and the check must be a lookup, not a range comparison.
#[must_use]
pub fn is_registered_message_type(code: u8) -> bool {
    message_type(code).is_some()
}

/// Whether a message type's name is registered.
#[must_use]
pub fn is_registered_name(name: &str) -> bool {
    message_type_by_name(name).is_some()
}

/// Every registered name, for cross-checking against the registry file.
#[must_use]
pub fn all_names() -> Vec<&'static str> {
    MESSAGE_TYPES.iter().map(|entry| entry.name).collect()
}

/// Every registered code, for cross-checking against the registry file.
#[must_use]
pub fn all_codes() -> Vec<u8> {
    MESSAGE_TYPES.iter().map(|entry| entry.code).collect()
}

/// The `HELLO` code, named rather than written as a literal at each call site.
pub const HELLO: u8 = 1;
/// The `HELLO_ACK` code.
pub const HELLO_ACK: u8 = 2;
/// The `AUTH` code.
pub const AUTH: u8 = 3;
/// The `AUTH_OK` code.
pub const AUTH_OK: u8 = 4;
/// The `GET_CAPABILITIES` code.
pub const GET_CAPABILITIES_CODE: u8 = 16;
/// The `CAPABILITIES` code.
pub const CAPABILITIES_CODE: u8 = 17;
/// The `ERROR` code.
pub const ERROR: u8 = 240;
/// The `SESSION_END` code.
pub const SESSION_END: u8 = 241;

/// Whether a message type must be encrypted when sent.
///
/// The registry's `encrypted` flag is false for exactly two types, because those two are exchanged
/// before a session key exists. A receiver that demanded encryption for `HELLO` could never complete a
/// handshake.
#[must_use]
pub fn must_be_encrypted(code: u8) -> bool {
    message_type(code).is_some_and(|entry| entry.encrypted)
}

/// Whether a message type may travel unencrypted.
#[must_use]
pub fn may_be_unencrypted(code: u8) -> bool {
    message_type(code).is_some_and(|entry| !entry.encrypted)
}

/// Whether a message type requires a capability, and the capability's name.
///
/// Transcribed from the registry's `message_type_capability`, which is keyed by the message type's
/// **code** (not by an enumeration index, and not by name). The tests read that file and compare, in
/// both directions.
///
/// That test exists because my first two hand-written versions of this table were both wrong, in three
/// places, and nothing else in this crate could see it:
///
///   * it omitted CHANNEL_OPEN, CHANNEL_OPENED and CHANNEL_CLOSE entirely;
///   * it omitted SESSION_END;
///   * it mapped VIDEO_STATS to `screen.mirror` (the registry says `telemetry.stats`);
///   * it gated 68 (INPUT_GESTURE) on `input.touch` and missed 67 (INPUT_SCROLL), when the registry
///     does the opposite: `input.gesture` is its own capability and INPUT_SCROLL rides on `input.touch`;
///   * it mapped 101 (FILE_RESULT) to `file.read` where the registry says `file.write`.
///
/// Every one of those was invisible to a test that asked this function what it thought. The lesson is
/// the one this repository keeps relearning: a transcription must be checked against its source, not
/// against itself.
///
/// Thirteen of the forty-two types carry no capability, for two distinct reasons:
///
///   * The handshake types (HELLO, HELLO_ACK, AUTH, AUTH_OK) precede negotiation, so nothing can gate
///     them -- HELLO is what establishes what could be gated.
///   * The transport and diagnostics types (PING, PONG, GET_CAPABILITIES, CAPABILITIES, CHANNEL_OPEN,
///     CHANNEL_OPENED, CHANNEL_CLOSE, ERROR, SESSION_END) are what a session of any capability set
///     needs in order to exist, to open a channel, and to be diagnosed.
#[must_use]
pub const fn capability_for_message_type(message_type: u8) -> Option<&'static str> {
    match message_type {
        48..=51 => Some("screen.mirror"),
        52 => Some("telemetry.stats"),
        64 | 67 => Some("input.touch"),
        65 => Some("input.key"),
        66 => Some("input.text"),
        68 => Some("input.gesture"),
        80..=82 => Some("shell.exec"),
        96..=99 => Some("file.read"),
        100 | 101 => Some("file.write"),
        112 | 114 => Some("clipboard.read"),
        113 => Some("clipboard.write"),
        128 | 129 => Some("device.info"),
        130 | 131 => Some("log.stream"),
        144 => Some("app.install"),
        145 | 146 => Some("app.launch"),
        _ => None,
    }
}
