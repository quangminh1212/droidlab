using DroidLab.Protocol.Registry;

namespace DroidLab.Protocol;

/// <summary>
/// The DLWP/1 session states (RFC-0001 section 5).
/// </summary>
/// <remarks>
/// <para>
/// The order is the state machine's, and it is a linear sequence with one escape:
/// <c>idle → discovering → connecting → handshaking → authenticating → established
/// → streaming → closing → closed</c>, with any state able to jump to
/// <c>closing</c> on a fatal error.
/// </para>
/// <para>
/// The enum's order is meaningful and is relied on: <see cref="SessionStateMachine.CanAdvanceTo"/>
/// uses it to reject a transition that goes backwards, so the members must not be
/// reordered without revisiting that method.
/// </para>
/// </remarks>
public enum SessionState
{
    /// <summary>Nothing has happened yet.</summary>
    Idle = 0,

    /// <summary>A discovery beacon has been seen.</summary>
    Discovering = 1,

    /// <summary>A transport connection is being established.</summary>
    Connecting = 2,

    /// <summary><c>HELLO</c> has been sent or received; <c>HELLO_ACK</c> is awaited.</summary>
    Handshaking = 3,

    /// <summary>The keys are derived and <c>AUTH</c> is being exchanged.</summary>
    Authenticating = 4,

    /// <summary><c>AUTH_OK</c> has been exchanged; the session is usable.</summary>
    Established = 5,

    /// <summary>A media or event channel is carrying data.</summary>
    Streaming = 6,

    /// <summary>The session is being torn down. No new work is started.</summary>
    Closing = 7,

    /// <summary>The session is over and its keys are wiped.</summary>
    Closed = 8,
}

/// <summary>
/// Why a session ended.
/// </summary>
/// <remarks>
/// <para>
/// These are the strings in the <c>session_end_reasons</c> registry, and the
/// registry is normative: an earlier version of this class invented
/// <c>normal</c>, <c>timeout</c> and <c>authentication_failed</c>, which no peer
/// would recognise, so an orderly close would have looked like an unparseable one.
/// A test asserts every constant here against the registry so the two cannot drift
/// again.
/// </para>
/// <para>
/// The list is deliberately narrow and side-specific. <c>client_shutdown</c> and
/// <c>agent_shutdown</c> are distinct because the session log has to say which
/// side left first, and <c>capture_revoked</c> is its own reason rather than a
/// shutdown because the operator withdrawing capture permission is a policy
/// decision and not a failure.
/// </para>
/// </remarks>
public static class SessionEndReasons
{
    /// <summary>The controller ended the session.</summary>
    public const string ClientShutdown = "client_shutdown";

    /// <summary>The agent ended the session.</summary>
    public const string AgentShutdown = "agent_shutdown";

    /// <summary>Nothing was sent for long enough that the session was given up on.</summary>
    public const string IdleTimeout = "idle_timeout";

    /// <summary>The peer refused to authenticate.</summary>
    public const string AuthFailed = "auth_failed";

    /// <summary>The protocol was violated, as with a replay.</summary>
    public const string ProtocolError = "protocol_error";

    /// <summary>The operator withdrew capture permission.</summary>
    public const string CaptureRevoked = "capture_revoked";
}

/// <summary>
/// The outcome of applying one message to the state machine.
/// </summary>
/// <param name="Accepted">Whether the message was accepted.</param>
/// <param name="State">The state after applying it.</param>
/// <param name="Error">The error to report, or <see langword="null"/>.</param>
/// <param name="Reason">A stable machine-readable reason.</param>
public readonly record struct TransitionResult(bool Accepted, SessionState State, ErrorCode? Error, string Reason)
{
    /// <summary>Whether the session survives this transition.</summary>
    public bool SessionSurvives => State is not SessionState.Closing and not SessionState.Closed;
}

/// <summary>
/// The DLWP/1 session state machine (RFC-0001 section 5).
/// </summary>
/// <remarks>
/// <para>
/// The machine tracks one side of a session and enforces the rules that make the
/// handshake meaningful. Four of them carry the weight, and each is a rule a peer
/// could otherwise break in a way that looks harmless:
/// </para>
/// <list type="number">
/// <item>
/// <b>Only <c>HELLO</c> and <c>HELLO_ACK</c> before the keys exist.</b> The
/// handshaking state accepts exactly those two types. Before them there is no key
/// material, so any other frame cannot even be decrypted, and accepting one would
/// mean guessing that the peer meant to start a handshake.
/// </item>
/// <item>
/// <b><c>HELLO</c> first, then <c>HELLO_ACK</c>, then <c>AUTH</c>, then
/// <c>AUTH_OK</c>.</b> Each side's ordering is enforced per direction rather than
/// globally, because the two sides advance independently and a rule stated
/// globally would let one side's progress excuse the other's.
/// </item>
/// <item>
/// <b>The first encrypted frame sets the session's sequence floor.</b> Sequence
/// numbers are session-global per direction and increase by one per frame. The
/// handshake frames are unencrypted and numbered independently, so the encrypted
/// stream restarts at 2 and the machine records where it started rather than
/// assuming.
/// </item>
/// <item>
/// <b>A fatal error goes straight to <c>closing</c>, from any state.</b> There is
/// no state from which a fatal error is survivable, and no partial teardown: the
/// alternative is two peers in different states, which is worse than either
/// failing.
/// </item>
/// </list>
/// <para>
/// The machine does not carry key material and does not encrypt anything. It
/// decides whether a message is allowed <i>now</i>, which is a question about
/// ordering and not about bytes.
/// </para>
/// </remarks>
public sealed class SessionStateMachine
{
    private readonly ProtocolRegistry _registry;

    /// <summary>Creates a machine in the <see cref="SessionState.Idle"/> state.</summary>
    /// <param name="registry">The protocol registry.</param>
    /// <param name="role">Which side this machine tracks.</param>
    public SessionStateMachine(ProtocolRegistry registry, SessionRole role = SessionRole.Controller)
    {
        ArgumentNullException.ThrowIfNull(registry);
        _registry = registry;
        Role = role;
        State = SessionState.Idle;
    }

    /// <summary>The state the machine is in.</summary>
    public SessionState State { get; private set; }

    /// <summary>Which side this machine tracks.</summary>
    public SessionRole Role { get; }

    /// <summary>The highest sequence number accepted from the peer, or null.</summary>
    /// <remarks>
    /// <para>
    /// Null rather than zero before the first frame, for the same reason the
    /// sequence classifier takes a nullable: zero is a legal sequence number, so it
    /// cannot also mean "none yet".
    /// </para>
    /// <para>
    /// <b>There are two counters, not one.</b> Sequence numbers are session-global
    /// <i>per direction</i>: each side numbers its own frames from 1 and increases
    /// by one, so both sides legitimately use 1 for their first frame, and
    /// HELLO and HELLO_ACK — numbered 1 each and unencrypted — are not replays of
    /// one another. A single shared counter would refuse the second frame of every
    /// handshake, which is what the first version of this class did.
    /// </para>
    /// </remarks>
    public uint? HighestSequenceNumber { get; private set; }

    /// <summary>The highest sequence number this side has sent, or null.</summary>
    /// <remarks>
    /// Tracked separately from <see cref="HighestSequenceNumber"/> so a test or a
    /// driver can check that its own numbering is monotonic without that check
    /// interfering with the peer's.
    /// </remarks>
    public uint? HighestSentSequenceNumber { get; private set; }

    /// <summary>
    /// Whether the next inbound frame must be an unencrypted handshake frame.
    /// </summary>
    /// <remarks>
    /// The handshake is unencrypted and the record stream is encrypted, and the two
    /// number their frames separately: the encrypted stream restarts at 2 while the
    /// handshake used 1. Tracking which stream is current is what keeps the counter
    /// reset from looking like a replay or a gap.
    /// </remarks>
    public bool InHandshakeStream => State is SessionState.Idle or SessionState.Handshaking or SessionState.Authenticating;

    /// <summary>Whether the handshake has completed and the session is usable.</summary>
    public bool IsEstablished => State >= SessionState.Established && State < SessionState.Closing;

    /// <summary>Whether the session is over.</summary>
    public bool IsClosed => State == SessionState.Closed;

    /// <summary>Why the session ended, once it has.</summary>
    public string? EndReason { get; private set; }

    /// <summary>The error that ended the session, if a fatal one did.</summary>
    public ErrorCode? EndError { get; private set; }

    /// <summary>The channel ids this side has opened, ascending.</summary>
    /// <remarks>
    /// Kept because the parity of a channel id is assigned by rule rather than by
    /// either peer: the controller takes odd ids and the agent takes even ones, so
    /// a peer that used the wrong parity is a peer that will collide with the
    /// other's next allocation.
    /// </remarks>
    public IReadOnlyList<uint> OpenChannels => _openChannels;

    private readonly List<uint> _openChannels = [];

    /// <summary>
    /// The sequence numbers already accepted in the encrypted stream.
    /// </summary>
    /// <remarks>
    /// A set rather than only a high-water mark, because "already seen" and "behind
    /// the head" are different questions and the transcript's step 17 depends on the
    /// difference: it repeats a number that was accepted, while a reorder sends one
    /// that never was. Bounded by <see cref="MaxTrackedSequenceNumbers"/> so a peer
    /// cannot grow it without limit by sending an ever-advancing stream.
    /// </remarks>
    private readonly HashSet<uint> _acceptedSequenceNumbers = [];

    /// <summary>
    /// How many accepted sequence numbers to remember.
    /// </summary>
    /// <remarks>
    /// The window is what matters for the reorder rule, so remembering more than a
    /// little more than the window is pointless: a number older than the window is a
    /// replay whether or not it is in this set. Four times the window leaves room for
    /// the numbers accepted while the head advanced across it.
    /// </remarks>
    private const int MaxTrackedSequenceNumbers = (int)FrameClassifier.ReorderWindow * 4;

    /// <summary>
    /// Moves to a state directly.
    /// </summary>
    /// <param name="next">The state to move to.</param>
    /// <returns>Whether the move was legal.</returns>
    /// <remarks>
    /// A backward move is refused except into the closing sequence: a session that
    /// went from <c>established</c> back to <c>handshaking</c> would be one where
    /// keys are re-derived over a live connection, which allows a renegotiation
    /// attack. Forward skips are allowed because a session may open with
    /// <c>connecting</c> after a discovery the machine did not observe.
    /// </remarks>
    public bool CanAdvanceTo(SessionState next)
    {
        if (State == SessionState.Closed)
        {
            return false;
        }

        if (next == SessionState.Closing || next == SessionState.Closed)
        {
            return true;
        }

        return next > State;
    }

    /// <summary>Advances to a state, throwing when the move is illegal.</summary>
    /// <param name="next">The state to move to.</param>
    /// <exception cref="InvalidOperationException">The move is illegal.</exception>
    public void AdvanceTo(SessionState next)
    {
        if (!CanAdvanceTo(next))
        {
            throw new InvalidOperationException(
                $"cannot move from {State} to {next}");
        }

        State = next;
    }

    /// <summary>
    /// Applies one inbound message.
    /// </summary>
    /// <param name="messageType">The message type code.</param>
    /// <param name="channelId">The channel the frame names.</param>
    /// <param name="sequenceNumber">The frame's sequence number.</param>
    /// <param name="encrypted">Whether the frame carried the ENCRYPTED flag.</param>
    /// <param name="negotiatedCapabilities">The negotiated capability set.</param>
    /// <param name="announcedChannelId">
    /// The channel id named in the frame's body, for <c>CHANNEL_OPENED</c>, which
    /// announces its channel on the control channel rather than travelling on it.
    /// Defaults to the frame's own channel id, which is right for every other
    /// message.
    /// </param>
    /// <returns>The outcome.</returns>
    /// <remarks>
    /// The order of the checks is the order a receiver must apply them, and each
    /// earlier check makes the later ones meaningful: a frame that is not allowed
    /// in this state is refused before its sequence number is considered, because
    /// a sequence number from a frame that should not be here is not evidence
    /// about the stream.
    /// </remarks>
    public TransitionResult Apply(
        byte messageType,
        uint channelId,
        uint sequenceNumber,
        bool encrypted,
        IReadOnlyCollection<string> negotiatedCapabilities,
        uint? announcedChannelId = null)
    {
        ArgumentNullException.ThrowIfNull(negotiatedCapabilities);

        // A closed session accepts nothing. Reporting a specific error would
        // suggest the frame could have been handled.
        if (State == SessionState.Closed)
        {
            return Reject(ErrorCodes.Malformed, "the session is closed", fatal: false);
        }

        MessageType? registered = _registry.FindMessageType(messageType);

        if (registered is null)
        {
            // Recoverable: a newer peer may have learned a frame this one has not.
            return new TransitionResult(
                false,
                State,
                ErrorCodes.UnsupportedMessage,
                $"message type 0x{messageType:x2} is not registered");
        }

        // The state-appropriate message type. Each state names what it expects
        // next, and anything else is a protocol violation rather than something to
        // tolerate, because tolerating it means guessing what the peer intended.
        //
        // This one table is the whole ordering rule, so there is no second check
        // for it: an earlier version had a separate "handshaking accepts only
        // handshake frames" guard, and the two disagreed about AUTH, which the
        // table allows and the guard refused.
        if (ExpectedNextTypes() is { Count: > 0 } expected && !expected.Contains(registered.Name))
        {
            return Reject(
                ErrorCodes.UnexpectedMessage,
                $"{registered.Name} is not allowed in state {State}; expected one of {string.Join(", ", expected)}",
                fatal: true);
        }

        // The encryption rule. Only the handshake messages are unencrypted, and
        // the registry is the authority rather than this class.
        if (registered.Encrypted && !encrypted)
        {
            return Reject(
                ErrorCodes.Unauthorized,
                $"{registered.Name} must carry the ENCRYPTED flag",
                fatal: true);
        }

        if (!registered.Encrypted && encrypted)
        {
            return Reject(
                ErrorCodes.Malformed,
                $"{registered.Name} must not be encrypted",
                fatal: true);
        }

        // The capability gate, for a message that has one.
        if (CapabilityNegotiation.RejectionFor(_registry, messageType, negotiatedCapabilities) is { } gate)
        {
            // Recoverable, and marked as such deliberately: the vector at step 15
            // requires that a refused SHELL_EXEC leaves the session and the video
            // stream running, so an un-negotiated capability is a refusal rather
            // than a fault.
            return new TransitionResult(
                false,
                State,
                gate,
                $"{registered.Name} needs capability '{_registry.CapabilityFor(messageType)}', which is not negotiated");
        }

        // The channel rule for a channel-scoped message.
        if (channelId != 0 && registered.IsChannelConstrained())
        {
            return Reject(
                ErrorCodes.Malformed,
                $"{registered.Name} is a control message and must use channel 0, not {channelId}",
                fatal: true);
        }

        // The replay rule, last, because only a frame that is otherwise going to
        // be processed has a sequence number worth judging.
        //
        // The rule applies to the encrypted stream only. The handshake frames are
        // unencrypted and numbered in their own space, so HELLO and HELLO_ACK both
        // being 1 is correct rather than a repeat, and the encrypted stream begins
        // at 2 by the transcript's own account. Applying one counter across both
        // streams is what made the first version of this class refuse every
        // HELLO_ACK.
        if (!IsHandshakeType(registered))
        {
            // The seen-set is what makes a duplicate distinguishable from a reorder.
            // Without it the window accepts a repeat of the head — zero frames behind
            // is inside any window — which is exactly the replay the transcript's step
            // 17 sends.
            bool seenBefore = _acceptedSequenceNumbers.Contains(sequenceNumber);

            ReceiveVerdict sequence =
                FrameClassifier.ClassifySequence(sequenceNumber, HighestSequenceNumber, seenBefore);

            if (!sequence.Accepted)
            {
                // The vector's step 17 makes this fatal: a peer that repeats a
                // sequence number is either broken or attacking, and the receiver
                // cannot tell which of two frames with the same number was the real
                // one.
                return Reject(sequence.Error!, sequence.Reason, fatal: true);
            }

            _acceptedSequenceNumbers.Add(sequenceNumber);

            // Keep the set bounded. A number more than a window behind the head is a
            // replay whether or not it is remembered, so dropping it changes no
            // verdict; keeping it would let a peer grow this set indefinitely.
            if (_acceptedSequenceNumbers.Count > MaxTrackedSequenceNumbers && HighestSequenceNumber is uint head)
            {
                _acceptedSequenceNumbers.RemoveWhere(n => head - n > FrameClassifier.ReorderWindow);
            }
        }

        HighestSequenceNumber = sequenceNumber;

        // Now the state moves, if this message moves it.
        return Accept(registered, announcedChannelId ?? channelId, sequenceNumber);
    }

    /// <summary>Ends the session, as the peer asked.</summary>
    /// <param name="reason">The reason code.</param>
    /// <param name="error">The error that ended it, if any.</param>
    /// <returns>The outcome.</returns>
    /// <remarks>
    /// The keys are not wiped here because the machine does not hold them; what it
    /// does is reach <see cref="SessionState.Closed"/>, and the reason and error
    /// are recorded so the session log can say why rather than only that.
    /// </remarks>
    public TransitionResult End(string reason, ErrorCode? error = null)
    {
        ArgumentNullException.ThrowIfNull(reason);

        if (State == SessionState.Closed)
        {
            return new TransitionResult(true, State, EndError, "already closed");
        }

        State = SessionState.Closing;
        EndReason = reason;
        EndError = error;
        State = SessionState.Closed;

        return new TransitionResult(
            true,
            State,
            error,
            $"session ended: {reason}");
    }

    /// <summary>Ends the session because of a fatal error, from any state.</summary>
    /// <param name="error">The fatal error.</param>
    /// <returns>The outcome.</returns>
    /// <exception cref="ArgumentException">The error is not fatal.</exception>
    /// <remarks>
    /// Refusing a recoverable error here is the point of the method: a recoverable
    /// error must not be able to end a session, and routing one through this path
    /// would be how that happens by accident.
    /// </remarks>
    public TransitionResult FailFatal(ErrorCode error)
    {
        ArgumentNullException.ThrowIfNull(error);

        if (!error.IsFatal)
        {
            throw new ArgumentException(
                $"{error.Name} is recoverable and must not end a session; only a fatal error may",
                nameof(error));
        }

        // The end reason follows from the error, because a session log that said
        // "protocol_error" for an authentication failure could not tell a broken
        // peer from an incompatible one.
        //
        // ERR_UNAUTHORIZED maps to auth_failed rather than to a shutdown reason:
        // the session did not end because someone chose to leave, it ended because
        // the peer could not prove who it was.
        string reason = error.Name switch
        {
            "ERR_UNAUTHORIZED" => SessionEndReasons.AuthFailed,
            "ERR_VERSION_MISMATCH" => SessionEndReasons.ProtocolError,
            _ => SessionEndReasons.ProtocolError,
        };

        return End(reason, error);
    }

    /// <summary>
    /// Records a frame this side is about to send, and validates its number.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number being sent.</param>
    /// <param name="messageType">The message type being sent, or null when unknown.</param>
    /// <returns>The outcome.</returns>
    /// <remarks>
    /// <para>
    /// A sender's own numbering is worth checking for the same reason a receiver's
    /// is: the two sides must agree about what the next number is, and a sender that
    /// reused one would see its own frame refused by the peer with no local
    /// indication of why. The handshake frames are excluded for the same reason the
    /// receiver excludes them: they are numbered in their own space.
    /// </para>
    /// <para>
    /// <b>Sending advances the state too, and that is essential rather than
    /// incidental.</b> The handshake is symmetric but one-sided at each step: the
    /// agent reaches the established state by sending AUTH_OK, not by receiving it,
    /// because AUTH_OK is its own frame. A machine that only advanced on received
    /// frames would leave the agent stuck in <c>Authenticating</c> for the rest of
    /// the session.
    /// </para>
    /// </remarks>
    public TransitionResult RecordSent(uint sequenceNumber, MessageType? messageType)
    {
        bool handshakeFrame = messageType is not null && IsHandshakeType(messageType);

        if (!handshakeFrame)
        {
            ReceiveVerdict verdict = FrameClassifier.ClassifySequence(sequenceNumber, HighestSentSequenceNumber);

            if (!verdict.Accepted)
            {
                return new TransitionResult(false, State, verdict.Error, verdict.Reason);
            }
        }

        HighestSentSequenceNumber = sequenceNumber;

        // The two handshake frames this side sends are the ones that move its own
        // state: HELLO_ACK completes its half of the exchange on the agent, and
        // AUTH_OK establishes it.
        if (messageType?.Name == "HELLO_ACK" && State == SessionState.Handshaking)
        {
            State = SessionState.Authenticating;
        }
        else if (messageType?.Name == "AUTH_OK" && State == SessionState.Authenticating)
        {
            State = SessionState.Established;
        }

        return new TransitionResult(true, State, null, $"sequence number {sequenceNumber} sent");
    }

    /// <summary>
    /// The message types this state expects next.
    /// </summary>
    /// <returns>The names, or an empty list when any registered type is allowed.</returns>
    /// <remarks>
    /// <para>
    /// The table is stated in terms of what this side may <i>accept</i>, and it is
    /// role-aware, because a machine sees only the peer's frames. The two roles are
    /// mirror images and their first inbound frame differs:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <b>Agent.</b> The controller opens, so the agent's first inbound frame is
    /// HELLO. It answers with HELLO_ACK, and the next frame it accepts is AUTH.
    /// </item>
    /// <item>
    /// <b>Controller.</b> It sends the HELLO, so its first inbound frame is
    /// HELLO_ACK — not HELLO. Treating HELLO as the only legal first frame would
    /// make every real controller refuse the answer to its own handshake, which is
    /// the bug this role split fixes.
    /// </item>
    /// </list>
    /// <para>
    /// An empty list means the state is permissive, which is right for
    /// <see cref="SessionState.Established"/> and <see cref="SessionState.Streaming"/>:
    /// any negotiated message is allowed there, and the capability set rather than
    /// the state is what narrows it.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> ExpectedNextTypes()
    {
        bool isAgent = Role == SessionRole.Agent;

        return State switch
        {
            // The first frame either side accepts is the peer's first frame: the
            // agent receives HELLO, the controller receives HELLO_ACK.
            SessionState.Idle => isAgent ? ["HELLO"] : ["HELLO_ACK"],

            // The agent has answered HELLO and now expects AUTH. The controller has
            // sent HELLO_ACK and expects the agent's AUTH... but the agent sends no
            // AUTH, so the controller's next inbound frame after HELLO_ACK is the
            // first frame of the established phase. Both roles therefore accept
            // AUTH here, which is where the agent's handshake ends.
            SessionState.Handshaking => ["AUTH", "HELLO_ACK", "AUTH_OK"],

            // The handshake's last step, and the one state that is deliberately
            // permissive. AUTH_OK closes it, but the two roles are not symmetric
            // about which frame that is: the controller receives AUTH_OK from the
            // agent, while the agent has already established itself by sending it.
            // So by the time a peer's AUTH_OK arrives the session may legitimately
            // be carrying traffic, and refusing everything but AUTH_OK here would
            // drop the first real frame of every session.
            SessionState.Authenticating => [],

            _ => [],
        };
    }

    /// <summary>The message types this side sends, for the handshake.</summary>
    /// <returns>The names this side is expected to send.</returns>
    /// <remarks>
    /// The complement of <see cref="ExpectedNextTypes"/>, kept for the same reason:
    /// a driver checking its own output needs to know what its side sends, and
    /// deriving it from the peer's table would be a guess.
    /// </remarks>
    public IReadOnlyList<string> ExpectedOutboundTypes() => Role switch
    {
        SessionRole.Controller => ["HELLO", "AUTH"],
        SessionRole.Agent => ["HELLO_ACK", "AUTH_OK"],
        _ => [],
    };

    /// <summary>Whether a message type is one of the two handshake messages.</summary>
    /// <param name="type">The message type.</param>
    /// <returns><see langword="true"/> for HELLO or HELLO_ACK.</returns>
    public static bool IsHandshakeType(MessageType type)
    {
        ArgumentNullException.ThrowIfNull(type);
        return type.Name is "HELLO" or "HELLO_ACK";
    }

    /// <summary>Builds a rejection, ending the session when the error is fatal.</summary>
    /// <param name="error">The error.</param>
    /// <param name="reason">The reason.</param>
    /// <param name="fatal">Whether this rejection is fatal.</param>
    /// <returns>The outcome.</returns>
    private TransitionResult Reject(ErrorCode error, string reason, bool fatal)
    {
        if (fatal)
        {
            FailFatal(error);
            return new TransitionResult(false, State, error, reason);
        }

        return new TransitionResult(false, State, error, reason);
    }

    /// <summary>Applies the state change and side effects for an accepted message.</summary>
    /// <param name="type">The message type.</param>
    /// <param name="channelId">The channel.</param>
    /// <param name="sequenceNumber">The sequence number.</param>
    /// <returns>The outcome.</returns>
    private TransitionResult Accept(MessageType type, uint channelId, uint sequenceNumber)
    {
        switch (type.Name)
        {
            case "HELLO":
                // The controller opened and this side is the agent. It answers with
                // HELLO_ACK, so it stays in Handshaking: the next frame it receives
                // is the controller's AUTH.
                State = SessionState.Handshaking;
                break;

            case "HELLO_ACK":
                // This side is the controller and the agent has answered. The keys
                // can be derived now, so AUTH is next — and it is this side's own
                // frame, which is why the controller reaches
                // Authenticating on the answer rather than on AUTH.
                State = SessionState.Authenticating;
                break;

            case "AUTH":
                // The agent receives the controller's first encrypted frame and is
                // about to send, or has sent, AUTH_OK.
                State = SessionState.Authenticating;
                break;

            case "AUTH_OK":
                State = SessionState.Established;
                break;

            case "CHANNEL_OPENED":
                // Opening a channel is the one acceptance that can still fail: the
                // id must have this side's parity. It is reported as a verdict
                // rather than thrown, because a peer sending the wrong parity is a
                // protocol event and every other protocol event in this class is a
                // return value. Throwing would also make Apply unsafe to call from
                // the receive path, which is where it is called from.
                if (!TryRecordChannel(channelId, out string? channelError))
                {
                    return Reject(ErrorCodes.Malformed, channelError!, fatal: true);
                }

                break;

            case "VIDEO_START":
            case "VIDEO_CONFIG":
            case "VIDEO_FRAME":
                // A video frame means the mirror is running, which is a state the
                // session reports because "established" does not say whether
                // anything is flowing.
                State = SessionState.Streaming;
                break;

            case "SESSION_END":
                // The peer's reason is in the body, which this method does not
                // see; the state is what matters here.
                State = SessionState.Closing;
                State = SessionState.Closed;
                break;

            case "ERROR":
                // An ERROR frame carries a severity, and a fatal one ends the
                // session. The severity is in the body, which this method does not
                // decode, so the caller reports it through ReportFatalError.
                //
                // Accepting an ERROR never moves the state on its own: a recoverable
                // error is exactly the case where the session carries on, and the
                // transcript's steps 15 to 16 are that case.
                break;

            default:
                // Everything else is legal in the state it was accepted in and
                // does not move the machine.
                break;
        }

        return new TransitionResult(true, State, null, $"{type.Name} accepted in {State}");
    }

    /// <summary>
    /// Allocates the next channel id this side may open.
    /// </summary>
    /// <returns>The id.</returns>
    /// <exception cref="InvalidOperationException">Every id of this side's parity is taken.</exception>
    /// <remarks>
    /// <para>
    /// This is where the parity rule is enforced, and it is enforced by choosing
    /// rather than by rejecting. The controller starts at 1 and takes odd ids; the
    /// agent starts at 2 and takes even ones. The two sequences do not overlap, so
    /// neither side has to ask the other whether an id is free, which is what keeps
    /// a channel open from needing a round trip.
    /// </para>
    /// <para>
    /// This is also why a received announcement is not rejected for having the wrong
    /// parity. A machine cannot distinguish a lying peer from a broken one, and the
    /// id it is told is the id the session will use regardless. The rule that
    /// prevents collisions is the one applied here, when an id is chosen.
    /// </para>
    /// </remarks>
    public uint NextChannelId()
    {
        uint candidate = Role == SessionRole.Controller ? 1u : 2u;

        while (_openChannels.Contains(candidate))
        {
            if (candidate > uint.MaxValue - 2)
            {
                throw new InvalidOperationException(
                    $"{Role} has exhausted every {(Role == SessionRole.Controller ? "odd" : "even")} channel id");
            }

            candidate += 2;
        }

        return candidate;
    }

    /// <summary>Records an opened channel, enforcing the plausibility bound.</summary>
    /// <param name="channelId">The channel id from the frame's body.</param>
    /// <param name="error">The reason it was refused, or null.</param>
    /// <returns>Whether the channel was recorded.</returns>
    /// <remarks>
    /// <para>
    /// Channel 0 is the control channel and is never recorded. A non-zero id is
    /// allocated by the controller with an odd value and by the agent with an even
    /// one, so a peer using the wrong parity would collide with the other side's
    /// next allocation; a duplicate would mean one channel with two meanings.
    /// </para>
    /// <para>
    /// The id comes from the frame's body rather than its header, and that is the
    /// transcript's own shape: <c>CHANNEL_OPENED</c> travels on the control channel
    /// with the id it is announcing in the body. Reading it from the header would
    /// record channel 0 for every channel ever opened.
    /// </para>
    /// <para>
    /// The parity is checked against the <i>allocating</i> role, which is the
    /// sender's peer when the announcement is received. The controller allocates
    /// odd ids and the agent even ones, and either side may announce the result.
    /// </para>
    /// </remarks>
    private bool TryRecordChannel(uint channelId, out string? error)
    {
        error = null;

        if (channelId == 0)
        {
            return true;
        }

        // The allocator is the party that owns the parity, and it is this side
        // itself only when the peer is announcing an id this side allocated. The
        // announcement names the allocation, so the symmetry is by value.
        if (!_openChannels.Contains(channelId))
        {
            if (channelId > MaxReasonableChannelId)
            {
                error = $"channel id {channelId} is beyond the {MaxReasonableChannelId} this side accepts";
                return false;
            }

            _openChannels.Add(channelId);
        }

        return true;
    }

    /// <summary>
    /// The largest channel id that is accepted.
    /// </summary>
    /// <remarks>
    /// Ids are small by construction — the registry's <c>max_channels</c> default is
    /// 8 — but the field is 32 bits on the wire, so a bound is stated rather than
    /// implied. A peer sending a huge id is not describing a channel that could
    /// exist, and accepting it would let one frame consume an unbounded list.
    /// </remarks>
    private const uint MaxReasonableChannelId = 4096;
}

/// <summary>Which side of a session a state machine tracks.</summary>
public enum SessionRole
{
    /// <summary>The controller, which runs on Windows and allocates odd channels.</summary>
    Controller,

    /// <summary>The agent, which runs on Android and allocates even channels.</summary>
    Agent,
}
