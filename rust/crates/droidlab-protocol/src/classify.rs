//! Frame classification: what a receiver must do with a frame, and why.
//!
//! `malformed.json` is the largest vector file and the one with the most history. Its own
//! `vectors_note` records that an earlier revision inserted three bytes between the header and the
//! body of every frame and added three to `body_length` to match — so every frame agreed with its own
//! declared length and no length check could detect it. The effect was substantive: the body a
//! receiver decoded began with three bytes of noise rather than the byte each note named, so cases
//! named for a leading `0xFF` or `0xBF` did not exercise that byte at all, and the accepted cases
//! carried a body that was not cbOR. Nothing caught it because every check asked "does this frame
//! agree with itself", and it did.
//!
//! That history is why this module's job is stated as a **verdict** rather than a boolean. The
//! verifier's real question is not "is this frame valid" but "what must the receiver do about it",
//! and the answer is one of five things:
//!
//! | `expected` | Meaning |
//! | ---------- | ------- |
//! | `accepted` | Process it normally. |
//! | `close_connection` | Close with **no** error frame — the peer is not speaking DLWP/1 at all. |
//! | `error_frame_then_close` | Send an ERROR frame, then close. |
//! | `error_session_continues` | Send an ERROR frame and keep the session. |
//! | `wait_then_error_on_close` | Wait: the frame is incomplete, not invalid. |
//!
//! The `close_connection` case is the subtle one. A bad magic means the bytes are not DLWP/1, so
//! sending an ERROR frame would be sending a DLWP/1 frame to something that may not be a DLWP/1 peer
//! — and the note says so: "Nothing may be parsed before the magic is checked."

use crate::cbor;
use crate::error::{ErrorCode, Severity};
use crate::frame_header::FrameHeader;
use crate::limits::Limits;
use crate::PROTOCOL_VERSION;

/// What a receiver must do with a frame it has looked at.
///
/// Ordered from least to most disruptive, and the ordering is meaningful: [`Ord`] is derived so that
/// a caller can ask "is this at least as bad as" without a match. That is a convenience, not the
/// specification — the specification is the vector file's `expected` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Process the frame normally.
    Accepted,
    /// The frame is a prefix of a valid frame. Read more bytes and decide again.
    ///
    /// Distinct from every rejection because the answer is "not yet", not "no". A socket returns a
    /// prefix of a frame routinely, and treating that as malformed is how a partial read becomes a
    /// closed connection.
    Incomplete,
    /// Send an ERROR frame with a recoverable code, and keep the session.
    ErrorSessionContinues,
    /// Send an ERROR frame, then close.
    ErrorFrameThenClose,
    /// Close with no error frame.
    ///
    /// Only for frames that are not DLWP/1 at all: the magic is wrong, so there is no peer to send a
    /// DLWP/1 error to.
    CloseConnection,
}

impl Verdict {
    /// The vector file's name for this verdict, which is what the tests compare against.
    #[must_use]
    pub const fn vector_name(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Incomplete => "incomplete",
            Self::ErrorSessionContinues => "error_session_continues",
            Self::ErrorFrameThenClose => "error_frame_then_close",
            Self::CloseConnection => "close_connection",
        }
    }

    /// Whether the session survives this verdict.
    #[must_use]
    pub const fn session_survives(self) -> bool {
        matches!(self, Self::Accepted | Self::ErrorSessionContinues)
    }

    /// Whether an ERROR frame is sent.
    ///
    /// False for [`Verdict::CloseConnection`], which is the whole reason the variant exists: a bad
    /// magic means the peer may not understand a DLWP/1 error frame, so sending one is pointless and
    /// possibly harmful.
    #[must_use]
    pub const fn sends_error_frame(self) -> bool {
        matches!(
            self,
            Self::ErrorSessionContinues | Self::ErrorFrameThenClose
        )
    }

    /// Whether the connection closes.
    #[must_use]
    pub const fn closes_connection(self) -> bool {
        matches!(self, Self::ErrorFrameThenClose | Self::CloseConnection)
    }
}

/// A classified frame: the verdict, the code to report, and the reason.
///
/// All three are present for every outcome, including the accepted one, because the `reason` is what
/// a log line needs and the `code` is what an ERROR frame carries. `None` for a code on an accepted
/// frame is the honest representation of "no error to report".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    /// What to do.
    pub verdict: Verdict,
    /// The error code to report, if any.
    pub code: Option<ErrorCode>,
    /// The severity, if there is a code.
    pub severity: Option<Severity>,
    /// A short explanation, for a log line.
    pub reason: &'static str,
}

impl Classification {
    /// An accepted frame.
    #[must_use]
    pub const fn accepted(reason: &'static str) -> Self {
        Self {
            verdict: Verdict::Accepted,
            code: None,
            severity: None,
            reason,
        }
    }

    /// A frame that is a prefix of a valid frame.
    #[must_use]
    pub const fn incomplete(reason: &'static str) -> Self {
        Self {
            verdict: Verdict::Incomplete,
            code: None,
            severity: None,
            reason,
        }
    }

    /// A rejection with a code.
    #[must_use]
    pub const fn rejected(verdict: Verdict, code: ErrorCode, reason: &'static str) -> Self {
        Self {
            verdict,
            code: Some(code),
            severity: Some(code.severity()),
            reason,
        }
    }
}

/// Classifies a frame from its raw bytes.
///
/// The order of the checks is normative, and each step is where a plausible implementation goes
/// wrong:
///
/// 1. **Length.** Fewer than 24 bytes is [`Verdict::Incomplete`], not a rejection.
/// 2. **Magic, before anything else.** The vector's note is explicit: "Nothing may be parsed before
///    the magic is checked." A wrong magic is [`Verdict::CloseConnection`].
/// 3. **Version.** Before the header length, because a different version may define a different header
///    layout and reading `header_length` from it would be reading a field that may not exist.
/// 4. **Header length.** Must be exactly 24; there are no extensions in version 1.
/// 5. **Frame size against the limits**, which needs a `Limits` because the ceiling is negotiated.
/// 6. **Total length.** Fewer bytes than declared is [`Verdict::Incomplete`] — "wait", not "error".
/// 7. **Body well-formedness, on cleartext bodies only.** An encrypted body is
///    `nonce || ciphertext || tag`, so its bytes are not cbOR and checking them would reject every
///    encrypted frame. This is the check the `body-not-cbor` vector is about.
#[must_use]
pub fn classify(frame: &[u8], limits: &Limits) -> Classification {
    // 1. The fixed header must be present.
    if frame.len() < crate::FIXED_LENGTH {
        return Classification::incomplete("fewer than 24 bytes: the header is not all here yet");
    }

    // 2. The magic, before anything is parsed.
    if frame.get(..4) != Some(crate::MAGIC.as_slice()) {
        return Classification::rejected(
            Verdict::CloseConnection,
            ErrorCode::Malformed,
            "the first four bytes are not the DLWP magic, so this is not a DLWP/1 stream",
        );
    }

    // 3. The version.
    let version = frame.get(4).copied().unwrap_or(0);

    if version != PROTOCOL_VERSION {
        return Classification::rejected(
            Verdict::ErrorFrameThenClose,
            ErrorCode::VersionMismatch,
            "the frame's version is not one this receiver implements",
        );
    }

    // 4. The header length. Version 1 defines no extensions.
    let header_length = frame.get(6).copied().unwrap_or(0);

    if header_length != 24 {
        // A zero or short header_length is malformed rather than unsupported: it would make the
        // header shorter than its own fixed prefix. That is what the header-length-zero vector pins,
        // and it is why the two cases carry different codes.
        let code = if header_length < 24 {
            ErrorCode::Malformed
        } else {
            ErrorCode::UnsupportedHeader
        };

        return Classification::rejected(
            Verdict::ErrorFrameThenClose,
            code,
            "version 1 has no header extensions, so header_length must be 24",
        );
    }

    // The header is now safe to decode: the fixed prefix is present and the layout is the version-1
    // one. `decode` repeats the magic and length checks, which is deliberate -- it is the single
    // place those bytes are interpreted, so this function does not have a second copy of the rule.
    let header = match FrameHeader::decode(frame) {
        Ok(header) => header,
        Err(error) => {
            return Classification::rejected(
                Verdict::ErrorFrameThenClose,
                error.code(),
                "the header did not decode",
            )
        }
    };

    // 5. The frame size, against the negotiated ceiling.
    if !limits.permits_frame_of(header.total_length()) {
        return Classification::rejected(
            Verdict::ErrorFrameThenClose,
            ErrorCode::FrameTooLarge,
            "the declared frame is larger than the negotiated limit",
        );
    }

    // 6. The whole frame, not just its prefix.
    let total = match usize::try_from(header.total_length()) {
        Ok(value) => value,
        Err(_) => {
            return Classification::rejected(
                Verdict::ErrorFrameThenClose,
                ErrorCode::FrameTooLarge,
                "the declared frame cannot fit in this address space",
            )
        }
    };

    if frame.len() < total {
        return Classification::incomplete(
            "fewer bytes than body_length declares: the frame is partial",
        );
    }

    let body = frame.get(crate::FIXED_LENGTH..total).unwrap_or(&[]);

    // 7. A cleartext body must be a definite-length cbOR map.
    //
    // Only cleartext: an encrypted body is nonce || ciphertext || tag, whose bytes are not cbOR by
    // construction. Checking it would reject every encrypted frame, which is the mistake that makes
    // this step worth a comment.
    let encrypted = header.has_flag(crate::FrameFlag::Encrypted);

    if !encrypted {
        if let Err(error) = cbor::parse_map(body) {
            return Classification::rejected(
                Verdict::ErrorFrameThenClose,
                ErrorCode::Malformed,
                error.message,
            );
        }
    }

    // 8. A registered message type.
    //
    // The `unknown-message-type` vector. Checked LAST, and deliberately so: the vector's expected
    // verdict is `error_session_continues` with `ERR_UNSUPPORTED_MESSAGE`, which is recoverable,
    // whereas every earlier check is fatal. A receiver must therefore already know the frame is
    // well-formed before it can report that it does not understand the message -- otherwise an
    // unknown type in a malformed frame would be reported as unsupported rather than as malformed,
    // and the peer would keep sending a frame this receiver cannot parse.
    //
    // `is_registered_message_type` is in the registry module; the classifier asks it rather than
    // duplicating the list.
    if !crate::registry::is_registered_message_type(header.message_type) {
        return Classification::rejected(
            Verdict::ErrorSessionContinues,
            ErrorCode::UnsupportedMessage,
            "the frame is well-formed and its message type is not one this receiver knows",
        );
    }

    Classification::accepted(if encrypted {
        "an encrypted frame within the limits"
    } else {
        "a cleartext frame whose body is a cbOR map within the limits"
    })
}

/// Classifies a frame and names the message type it claims.
///
/// Separate from [`classify`] because a message type is a **session-level** concept: whether a given
/// type is expected now depends on the state machine, which is not something a single frame carries.
/// This returns the type for a caller that has the state to judge it.
#[must_use]
pub fn classify_with_message_type(frame: &[u8], limits: &Limits) -> (Classification, Option<u8>) {
    let classification = classify(frame, limits);

    let message_type = if classification.verdict == Verdict::Accepted {
        frame.get(7).copied()
    } else {
        None
    };

    (classification, message_type)
}

/// Whether a frame type is unencrypted by definition.
///
/// Only `HELLO` and `HELLO_ACK`, because they are the frames exchanged before a session key exists.
/// Every other type must set the `ENCRYPTED` flag.
#[must_use]
pub const fn may_be_cleartext(message_type: u8) -> bool {
    matches!(message_type, 0x01 | 0x02)
}

/// The reasons an ERROR frame is sent, from the registry's `session_end_reasons` where relevant.
///
/// Kept here rather than in the classifier because a session end is a state-machine outcome.
#[must_use]
pub const fn closes_session(code: ErrorCode) -> bool {
    code.is_fatal()
}

/// What a handshake has seen so far, which is the state a frame's **position** depends on.
///
/// The `first-frame-not-hello` vector is why this exists, and it is the most important lesson in
/// `malformed.json`. Its frame is a **well-formed PING**: [`classify`] accepts it, correctly, because
/// nothing in the frame's own bytes is wrong. What is wrong is that it is *first*. No single frame
/// carries that, so a classifier alone cannot produce the vector's verdict of
/// `error_frame_then_close` / `ERR_UNEXPECTED_MESSAGE`.
///
/// The vector says so itself: "HELLO must be the first frame of a session. A PING first is a protocol
/// violation, not a warning." So the verdict is a function of the frame AND the state, and this enum
/// is the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// No frame has been seen; the next frame must be `HELLO`.
    AwaitingHello,
    /// `HELLO` has been received; the next must be `HELLO_ACK`.
    AwaitingHelloAck,
    /// `HELLO_ACK` has been received; the next must be `AUTH`.
    AwaitingAuth,
    /// `AUTH` has been received; the next must be `AUTH_OK`.
    AwaitingAuthOk,
    /// The handshake is complete. `AUTH` is no longer in turn.
    Established,
}

impl HandshakeState {
    /// The one message type that is legal in this state, and the one that follows it.
    ///
    /// Returns `(expected, next)`. In [`HandshakeState::Established`] nothing advances.
    #[must_use]
    pub const fn expected(self) -> (u8, Self) {
        match self {
            Self::AwaitingHello => (0x01, Self::AwaitingHelloAck),
            Self::AwaitingHelloAck => (0x02, Self::AwaitingAuth),
            Self::AwaitingAuth => (0x03, Self::AwaitingAuthOk),
            Self::AwaitingAuthOk => (0x04, Self::Established),
            Self::Established => (0x00, Self::Established),
        }
    }

    /// Whether this state's set of legal message types is empty.
    ///
    /// False in [`HandshakeState::Established`], where the handshake imposes no ordering and the
    /// session's own rules govern instead. A caller must not treat `Established` as "nothing is
    /// legal" -- that would refuse every frame after the handshake.
    #[must_use]
    pub const fn imposes_ordering(self) -> bool {
        !matches!(self, Self::Established)
    }
}

/// Classifies a frame **and** judges whether it is in turn.
///
/// The two-part verdict the vectors actually ask for. [`classify`] answers "are these bytes a valid
/// frame"; this answers "and may it be sent now". `first-frame-not-hello` needs both, and it is the
/// vector a classifier alone gets wrong.
///
/// The order matters: a frame that is not well-formed is refused for being malformed rather than for
/// being out of turn, because the out-of-turn code would be a claim about a message that has not been
/// read.
#[must_use]
pub fn classify_in_state(frame: &[u8], limits: &Limits, state: HandshakeState) -> Classification {
    let classification = classify(frame, limits);

    if classification.verdict != Verdict::Accepted {
        return classification;
    }

    // Only the handshake imposes an order.
    if !state.imposes_ordering() {
        return classification;
    }

    let Some(message_type) = frame.get(7).copied() else {
        return classification;
    };

    let (expected, _) = state.expected();

    if message_type == expected {
        return classification;
    }

    Classification::rejected(
        Verdict::ErrorFrameThenClose,
        ErrorCode::UnexpectedMessage,
        "the frame is well-formed but arrived out of turn",
    )
}

/// Whether a message type re-arrives after the state that consumes it.
///
/// The `second-auth-rejected` vector. Its note: "A peer that repeats AUTH has broken the state machine,
/// and continuing would mean guessing which of the two proofs was authoritative."
///
/// Distinct from the out-of-turn check, because a repeat is not a reorder: the sequence is
/// `HELLO, HELLO_ACK, AUTH, AUTH_OK, AUTH`, and the final `AUTH` is *earlier* in the handshake than the
/// state the session reached. So the test is "has this state already been passed", not "is this the
/// expected state now".
#[must_use]
pub const fn is_repeat_of_a_passed_state(message_type: u8, reached: HandshakeState) -> bool {
    match reached {
        // AUTH (3) arriving once AUTH_OK (4) has been exchanged is a repeat.
        HandshakeState::Established => message_type == 0x03,
        _ => false,
    }
}
