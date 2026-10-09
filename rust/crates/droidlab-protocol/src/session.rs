//! The session state machine, sequence numbering and replay detection.
//!
//! `session-basic.json` is an ordered transcript of nineteen steps, and it is the vector that ties every
//! other module together: capability negotiation, frame classification, the reorder window, the
//! recoverable-versus-fatal distinction, and the abnormal termination path all meet here. Four things in
//! it are worth naming before the code, because each is a rule an implementation commonly gets wrong.
//!
//! **The two directions number independently.** The assertion says it outright: "Sequence numbers are
//! session-global and increase by one per frame sent by that side. The two directions number
//! independently, which is why both sides legitimately use sequence number 1 for their first frame." So
//! `HELLO` from the controller is 1 and `HELLO_ACK` from the agent is also 1, and neither is a duplicate
//! of the other.
//!
//! **An ERROR frame does not carry a new sequence number of its own in the counter that matters.** In the
//! transcript the agent answers the rejected `SHELL_EXEC` (controller sequence 10) with `ERROR` at its own
//! sequence 8, and answers the replayed `INPUT_TOUCH` with `ERROR` at 9 and then `SESSION_END` at 10. The
//! agent's counter continues from where the agent left off; the `request_seq` in the body names the
//! controller's frame. Conflating the two would desynchronise the streams.
//!
//! **A recoverable fault leaves the session alone.** `ERR_UNSUPPORTED_FEATURE` is recoverable, and the
//! expectations are explicit: "session survives", "video stream continues", "controller surfaces the error
//! without tearing down the session". A fatal fault closes.
//!
//! **A duplicate is a replay, and a replay is FATAL.** Step 17 re-sends controller sequence 8, which was
//! already accepted, and the vector marks it `deliberate_replay` with the reason: "This is the adversarial
//! case the monotonic rule exists for". The answer is `ERR_REPLAY_DETECTED` with "severity is fatal",
//! followed by `SESSION_END`.

use crate::error::{ErrorCode, Severity};

/// The states a session passes through.
///
/// From the vector's `state_machine` assertion:
///
/// ```text
/// idle -> discovering -> connecting -> handshaking -> authenticating -> established -> streaming -> closing -> closed
/// any_state_on_fatal_error -> closing
/// ```
///
/// The linear list and the second rule together mean this is not a simple counter: a fatal error at any
/// state jumps to `Closing`, so the type needs a transition function rather than an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionState {
    /// Nothing has begun.
    Idle,
    /// Looking for a device.
    Discovering,
    /// A transport is being opened.
    Connecting,
    /// `HELLO` and `HELLO_ACK` are being exchanged.
    Handshaking,
    /// `AUTH` and `AUTH_OK` are being exchanged.
    Authenticating,
    /// Both handshake proofs are done; the session is usable.
    Established,
    /// A media or channel stream is active.
    Streaming,
    /// Shutting down.
    Closing,
    /// Finished.
    Closed,
}

impl SessionState {
    /// The wire name, which is what the vectors write.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Discovering => "discovering",
            Self::Connecting => "connecting",
            Self::Handshaking => "handshaking",
            Self::Authenticating => "authenticating",
            Self::Established => "established",
            Self::Streaming => "streaming",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }

    /// Reads a wire name.
    #[must_use]
    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|state| state.wire_name() == name)
    }

    /// Every state, in the order the vector's transition list uses.
    pub const ALL: [Self; 9] = [
        Self::Idle,
        Self::Discovering,
        Self::Connecting,
        Self::Handshaking,
        Self::Authenticating,
        Self::Established,
        Self::Streaming,
        Self::Closing,
        Self::Closed,
    ];

    /// The positional order this state occupies on the linear path, or `None` for the two terminal states.
    ///
    /// `Closing` and `Closed` are off the path, which is why they are not numbered: a session can reach
    /// `Closing` from anywhere.
    const fn path_index(self) -> Option<u8> {
        match self {
            Self::Idle => Some(0),
            Self::Discovering => Some(1),
            Self::Connecting => Some(2),
            Self::Handshaking => Some(3),
            Self::Authenticating => Some(4),
            Self::Established => Some(5),
            Self::Streaming => Some(6),
            Self::Closing | Self::Closed => None,
        }
    }

    /// Whether the session can carry application traffic.
    ///
    /// `Established` and `Streaming` both can: `Established` is the state after `AUTH_OK` and before any
    /// channel work, and the transcript sends `DEVICE_INFO` in it.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Established | Self::Streaming)
    }

    /// Whether the session has finished, one way or another.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Whether a normal forward transition from here is legal.
    ///
    /// The rule is `next.path_index() == self.path_index() + 1` on the linear path, plus the two off-path
    /// moves: to `Closing`, and from `Closing` to `Closed`.
    ///
    /// Going BACKWARDS is refused, which is what makes the state machine a machine rather than a counter:
    /// a transition from `Established` back to `Handshaking` would mean re-running a handshake over an
    /// authenticated session.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        if next == self {
            // A self-transition is a no-op, not an advance. `Connecting -> Connecting` is allowed because a
            // reconnect attempt is a real thing, but it changes nothing, so allowing it costs nothing.
            return true;
        }

        // From anywhere to `Closing`, and from `Closing` to `Closed`.
        if next == Self::Closing {
            return !self.is_terminal();
        }

        if self == Self::Closing {
            return next == Self::Closed;
        }

        match (self.path_index(), next.path_index()) {
            (Some(from), Some(to)) => to == from.saturating_add(1),
            // A terminal state cannot advance.
            _ => false,
        }
    }
}

impl core::fmt::Display for SessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// Why a transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    /// The state the session was in.
    pub from: SessionState,
    /// The state it was asked to move to.
    pub to: SessionState,
}

impl core::fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot move from {} to {}", self.from, self.to)
    }
}

impl core::error::Error for IllegalTransition {}

/// One side's sending counter.
///
/// Both sides have one, and they are independent. The counter starts at zero and the first frame sent is
/// **1**, which the transcript confirms: `HELLO` carries `sequence_number: 1` and `HELLO_ACK` carries 1 as
/// well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SequenceCounter {
    next: u32,
}

impl SequenceCounter {
    /// A fresh counter. The first frame it yields is 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// The sequence number the next frame will carry.
    #[must_use]
    pub const fn peek(self) -> u32 {
        self.next
    }

    /// Takes the next sequence number and advances.
    ///
    /// The counter **advances by one**, which is the vector's rule: "increase by one per frame sent by
    /// that side". This is a different rule from the *receiver's* monotonicity check, which only requires
    /// that the number move forward.
    pub fn take(&mut self) -> u32 {
        let taken = self.next;

        // Saturating rather than wrapping: a wrap to 0 would re-issue a number that had already been used,
        // which the peer would then refuse as a replay. Ending the session at exhaustion is the safe
        // direction, and 2^32 frames is unreachable at any plausible rate.
        self.next = self.next.saturating_add(1);

        taken
    }

    /// How many frames have been sent.
    #[must_use]
    pub const fn sent(self) -> u32 {
        self.next.saturating_sub(1)
    }
}

/// What a received sequence number means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceVerdict {
    /// The next number in order.
    InOrder,
    /// Ahead of the highest seen, with a gap.
    Ahead {
        /// The highest number previously seen.
        expected: u32,
    },
    /// Already accepted. **Fatal**: this is a replay.
    Duplicate {
        /// The number that was repeated.
        sequence: u32,
    },
}

impl SequenceVerdict {
    /// Whether the session survives this verdict.
    ///
    /// Only a duplicate does not. The transcript's step 17 is a re-send of controller sequence 8, and the
    /// answer is `ERR_REPLAY_DETECTED` with "severity is fatal" followed by `SESSION_END`.
    ///
    /// Note which way round this is: the adversarial case is the one that is already SEEN, not the one
    /// that arrives too LATE. An out-of-order frame is a network artifact and a duplicate is an attack, and
    /// the vector's own rule reflects that.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::Duplicate { .. })
    }

    /// The error code for a verdict that is not fatal, if any.
    #[must_use]
    pub const fn code(self) -> Option<ErrorCode> {
        match self {
            Self::InOrder | Self::Ahead { .. } => None,
            Self::Duplicate { .. } => Some(ErrorCode::ReplayDetected),
        }
    }
}

/// A per-direction receiver: the highest sequence number accepted, plus a seen-set and a reorder window.
///
/// The seen-set is why this is not just a "highest" number. The vector's `nonce.reject.reused-sequence`
/// case is the same number twice, and `nonce.accept.inside-window` is a number BELOW the highest that is
/// nevertheless new. Those two cases are indistinguishable from the highest number alone:
///
///   * 417 then 417 — the second is a replay;
///   * highest 1000, received 969, window 32 — accepted, because it is inside the window and was never
///     seen.
///
/// So [`SequenceTracker`] keeps the window's worth of seen numbers and treats anything older than the
/// window as a replay, whether or not it was in the seen-set.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    highest: u32,
    seen: Vec<u32>,
    window: u32,
    started: bool,
}

impl SequenceTracker {
    /// The window the vectors use.
    pub const DEFAULT_WINDOW: u32 = 32;

    /// A fresh tracker. The first frame it receives is `InOrder` whatever the number, because there is no
    /// highest yet.
    #[must_use]
    pub fn new(window: u32) -> Self {
        Self {
            highest: 0,
            seen: Vec::new(),
            window,
            started: false,
        }
    }

    /// The default-window tracker.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Self::DEFAULT_WINDOW)
    }

    /// The highest sequence number accepted, or `None` before anything has been.
    #[must_use]
    pub const fn highest(&self) -> Option<u32> {
        if self.started {
            Some(self.highest)
        } else {
            None
        }
    }

    /// The window.
    #[must_use]
    pub const fn window(&self) -> u32 {
        self.window
    }

    /// Whether a number has been accepted.
    #[must_use]
    pub fn has_seen(&self, sequence: u32) -> bool {
        self.seen.contains(&sequence)
    }

    /// Classifies an incoming number WITHOUT recording it.
    ///
    /// Split from [`Self::accept`] so a caller can decide and then act, which matters because a duplicate
    /// ends the session and a caller may want to log before it does.
    ///
    /// The order of the checks is the whole rule, and it is the same ordering the nonce window needs:
    ///
    ///   1. **Nothing seen yet** — in order, whatever the number.
    ///   2. **Already seen** — a duplicate, and FATAL, before any window arithmetic. Checking the window
    ///      first would classify an exact replay of a recent frame as "inside the window" and ACCEPT it.
    ///   3. **At or below `highest - window`** — outside the window, so a replay that the seen-set may have
    ///      already evicted. Fatal.
    ///   4. **Above the highest** — a gap, but not fatal.
    ///   5. **Otherwise** — inside the window and unseen, so accepted as a reorder.
    #[must_use]
    pub fn classify(&self, sequence: u32) -> SequenceVerdict {
        if !self.started {
            return SequenceVerdict::InOrder;
        }

        // A duplicate before the window. `nonce.reject.reused-sequence` is this case.
        if self.has_seen(sequence) {
            return SequenceVerdict::Duplicate { sequence };
        }

        // Outside the window entirely. The boundary is INCLUSIVE of `highest - window`, so a window of 32
        // against a highest of 1000 refuses 968 and below and accepts 969 and above.
        let lowest = self.highest.saturating_sub(self.window);

        if sequence < lowest {
            return SequenceVerdict::Duplicate { sequence };
        }

        // The NEXT number is in order; only a jump past it is a gap. My first version returned `Ahead` for
        // anything above the highest, so a perfectly sequential 8-then-9 was reported as a gap of 9 --
        // which the deliberate-replay test caught immediately.
        let next = self.highest.saturating_add(1);

        if sequence == next {
            return SequenceVerdict::InOrder;
        }

        if sequence > next {
            return SequenceVerdict::Ahead { expected: next };
        }

        // Inside the window and not seen.
        SequenceVerdict::InOrder
    }

    /// Classifies and records.
    ///
    /// A duplicate does NOT update the tracker, so a replay cannot move the window and thereby make a
    /// later genuine frame look stale.
    pub fn accept(&mut self, sequence: u32) -> SequenceVerdict {
        let verdict = self.classify(sequence);

        if verdict.is_fatal() {
            return verdict;
        }

        if !self.started || sequence > self.highest {
            self.highest = sequence;
        }

        self.started = true;
        self.seen.push(sequence);
        self.trim();

        verdict
    }

    /// Drops seen numbers below the window, so the set cannot grow without bound.
    fn trim(&mut self) {
        let lowest = self.highest.saturating_sub(self.window);

        self.seen.retain(|sequence| *sequence >= lowest);
    }
}

/// Whether an error code's severity means the session survives.
///
/// `ERR_UNSUPPORTED_FEATURE` is the transcript's recoverable case and the expectations are explicit:
/// "session survives", "video stream continues", "controller surfaces the error without tearing down the
/// session". `ERR_REPLAY_DETECTED` is fatal and is followed by `SESSION_END`.
#[must_use]
pub fn session_survives(code: ErrorCode) -> bool {
    matches!(code.severity(), Severity::Recoverable)
}

/// What the agent must do about an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResponse {
    /// Send an ERROR frame and carry on.
    SendErrorAndContinue,
    /// Send an ERROR frame, then `SESSION_END`, then close.
    SendErrorThenSessionEnd,
}

impl FaultResponse {
    /// The response for an error code.
    #[must_use]
    pub fn for_code(code: ErrorCode) -> Self {
        if session_survives(code) {
            Self::SendErrorAndContinue
        } else {
            Self::SendErrorThenSessionEnd
        }
    }

    /// Whether the session continues.
    #[must_use]
    pub const fn continues(self) -> bool {
        matches!(self, Self::SendErrorAndContinue)
    }

    /// Whether a `SESSION_END` follows.
    #[must_use]
    pub const fn ends_the_session(self) -> bool {
        matches!(self, Self::SendErrorThenSessionEnd)
    }
}

/// The `reason` a `SESSION_END` carries.
///
/// The transcript's step 19 uses `protocol_error` for a fatal replay, which is the pair of values the
/// registry's `session_end_reasons` distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEndReason {
    /// The operator or a peer asked to stop.
    Normal,
    /// A protocol violation ended the session.
    ProtocolError,
    /// The session timed out.
    Timeout,
    /// The agent is shutting down.
    ShuttingDown,
}

impl SessionEndReason {
    /// The wire name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ProtocolError => "protocol_error",
            Self::Timeout => "timeout",
            Self::ShuttingDown => "shutting_down",
        }
    }

    /// Every reason, for a completeness check against the registry.
    pub const ALL: [Self; 4] = [
        Self::Normal,
        Self::ProtocolError,
        Self::Timeout,
        Self::ShuttingDown,
    ];
}

/// The reason a fatal error implies.
///
/// A replay is a protocol violation rather than a timeout or a shutdown, which is what the transcript's
/// step 19 records.
#[must_use]
pub const fn end_reason_for(code: ErrorCode) -> SessionEndReason {
    match code {
        ErrorCode::Timeout => SessionEndReason::Timeout,
        _ => SessionEndReason::ProtocolError,
    }
}

/// A channel identifier, with the parity rule.
///
/// The controller allocates odd ids and the agent even ones, and id 0 is the control channel, which
/// belongs to neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelId(pub u32);

impl ChannelId {
    /// The control channel.
    pub const CONTROL: Self = Self(0);

    /// Whether this is the control channel.
    #[must_use]
    pub const fn is_control(self) -> bool {
        self.0 == 0
    }

    /// Whether the controller owns this id, which is every odd id except the control channel's 0.
    #[must_use]
    pub const fn is_controller_owned(self) -> bool {
        !self.is_control() && self.0 % 2 == 1
    }

    /// Whether the agent owns this id.
    #[must_use]
    pub const fn is_agent_owned(self) -> bool {
        !self.is_control() && self.0 % 2 == 0
    }

    /// Whether this id may be opened by the given side.
    #[must_use]
    pub const fn may_be_opened_by(self, side: Side) -> bool {
        match side {
            Side::Controller => self.is_controller_owned(),
            Side::Agent => self.is_agent_owned(),
        }
    }
}

/// Which side of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The Windows application.
    Controller,
    /// The Android application.
    Agent,
}

impl Side {
    /// The other side.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Controller => Self::Agent,
            Self::Agent => Self::Controller,
        }
    }
}
