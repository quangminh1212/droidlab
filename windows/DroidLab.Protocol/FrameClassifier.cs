using DroidLab.Protocol.Cbor;
using DroidLab.Protocol.Registry;

namespace DroidLab.Protocol;

/// <summary>
/// What a receiver must do after classifying an incoming frame
/// (RFC-0001 sections 3, 6 and 10).
/// </summary>
public enum ReceiveAction
{
    /// <summary>The frame is acceptable.</summary>
    Accept,

    /// <summary>Answer with an ERROR frame and close the connection.</summary>
    ErrorFrameThenClose,

    /// <summary>Answer with an ERROR frame; the session continues.</summary>
    ErrorSessionContinues,

    /// <summary>Close immediately without answering: the bytes ahead are untrustworthy.</summary>
    CloseConnection,

    /// <summary>Read more; the frame is incomplete, not wrong.</summary>
    WaitForMore,

    /// <summary>Report the error when the connection closes.</summary>
    WaitThenErrorOnClose,
}

/// <summary>
/// The classification of one received frame.
/// </summary>
/// <param name="Action">What the receiver must do.</param>
/// <param name="Error">The error to report, or <see langword="null"/> when acceptable.</param>
/// <param name="Reason">A stable machine-readable reason, for logs and tests.</param>
public readonly record struct ReceiveVerdict(ReceiveAction Action, ErrorCode? Error, string Reason)
{
    /// <summary>Whether the frame was acceptable.</summary>
    public bool Accepted => Action == ReceiveAction.Accept;

    /// <summary>Whether the session survives.</summary>
    /// <remarks>
    /// An unknown message type or an un-negotiated capability is refused but the
    /// session continues, so a newer peer cannot break an older one by sending a
    /// frame it has learned. Everything that means the peer's framing or state
    /// cannot be trusted ends the session instead.
    /// </remarks>
    public bool SessionSurvives =>
        Action is ReceiveAction.Accept or ReceiveAction.ErrorSessionContinues;

    /// <summary>Whether the receiver must close without answering.</summary>
    /// <remarks>
    /// A bad magic or an unparseable header means the receiver does not know where
    /// this frame ends, so it cannot find the start of the next one. Answering is
    /// pointless and reading on would be guessing.
    /// </remarks>
    public bool MustCloseWithoutAnswer => Action == ReceiveAction.CloseConnection;
}

/// <summary>
/// Classifies incoming frames and reports the exact error each failure must
/// produce (RFC-0001 sections 3, 6 and 10).
/// </summary>
/// <remarks>
/// <para>
/// Every failure here is deterministic and byte-level, which is what makes a
/// receiver checkable without a peer. The point of the table is that two
/// implementations must agree not only on <i>whether</i> a frame is refused but
/// on which code and severity, because the severity decides whether the session
/// survives: reporting a fatal fault as recoverable leaves both peers in
/// different states, which is worse than either failing.
/// </para>
/// <para>
/// Three distinctions carry most of the weight:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Truncated is not malformed.</b> A short read is an I/O condition: the rest
/// of the frame may still arrive, so the receiver waits. Treating it as a parse
/// error would drop a connection over ordinary packet loss.
/// </item>
/// <item>
/// <b>Unknown message type is recoverable; unknown framing is fatal.</b> A newer
/// peer sending a frame this one has not learned must not break the session. A
/// frame whose header cannot be parsed means the receiver cannot find the next
/// frame at all, so the session cannot continue.
/// </item>
/// <item>
/// <b>An unknown body key is ignored; a missing or mistyped one is fatal.</b>
/// Forward compatibility means ignoring keys you do not know. It does not mean
/// guessing at keys you do know, and coercing a string coordinate into a number
/// is how a mis-tap bug is born.
/// </item>
/// </list>
/// </remarks>
public static class FrameClassifier
{
    /// <summary>The reordering window, in frames (RFC-0001 section 4).</summary>
    /// <remarks>
    /// A gap inside this window is legal on a lossy link. A frame outside it is
    /// rejected, because accepting arbitrarily old frames would let an attacker
    /// replay one indefinitely.
    /// </remarks>
    public const uint ReorderWindow = 32;

    /// <summary>
    /// Classifies a complete frame.
    /// </summary>
    /// <param name="frame">The bytes that have arrived so far.</param>
    /// <param name="registry">The protocol registry.</param>
    /// <param name="negotiatedCapabilities">The negotiated capability set.</param>
    /// <param name="expectedFirstMessageType">
    /// The message type a first frame must be, e.g. <c>HELLO</c>, or <see langword="null"/> when
    /// this is not the first frame.
    /// </param>
    /// <param name="maxFrameBytes">The maximum accepted body size.</param>
    /// <returns>The verdict.</returns>
    public static ReceiveVerdict Classify(
        ReadOnlySpan<byte> frame,
        ProtocolRegistry registry,
        IReadOnlyCollection<string> negotiatedCapabilities,
        byte? expectedFirstMessageType = null,
        uint maxFrameBytes = FrameValidator.DefaultMaxFrameBytes)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(negotiatedCapabilities);

        // A short read is an I/O condition rather than a parse error: the rest of
        // the frame may still arrive. This is checked before the magic so that a
        // partial first read is not mistaken for a bad magic.
        if (frame.Length < FrameHeader.FixedLength)
        {
            return new ReceiveVerdict(
                ReceiveAction.WaitForMore,
                null,
                "truncated header: waiting for more bytes");
        }

        // The magic first, before anything else is interpreted. Until it matches,
        // the other fields mean nothing and must not be parsed.
        if (!frame[..4].SequenceEqual(FrameHeader.Magic))
        {
            // No error frame is sent: without a known frame boundary the receiver
            // cannot locate the next frame, so it cannot trust resynchronisation.
            return new ReceiveVerdict(
                ReceiveAction.CloseConnection,
                ErrorCodes.Malformed,
                "bad magic: the stream is not DLWP/1");
        }

        // Version before the rest of the header, because a frame from another
        // major version may not have this layout at all.
        byte headerVersion = frame[4];
        if (VersionNegotiation.ValidateHeaderVersion(headerVersion) is { } versionError)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                versionError,
                "header version is not 1");
        }

        // The header length must be exactly the fixed width: version 1.0 defines
        // no extensions, and a receiver must not try to skip bytes it does not
        // understand.
        byte headerLength = frame[6];
        if (headerLength != FrameHeader.FixedLength)
        {
            ErrorCode error = headerLength == 0 ? ErrorCodes.Malformed : ErrorCodes.UnsupportedHeader;
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                error,
                headerLength == 0
                    ? "header_length is zero, which is shorter than the fixed prefix"
                    : $"header_length is {headerLength}, and version 1.0 defines no extensions");
        }

        // The declared body size is checked from the header alone, before any
        // allocation. 0xFFFFFFFF is the worst case an attacker can ask for, and a
        // receiver that allocates it has turned one frame into a denial of
        // service.
        uint declaredBodyLength = FrameHeaderCodec.ReadUInt32BigEndian(frame, 20);
        if (declaredBodyLength > maxFrameBytes)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.FrameTooLarge,
                $"declared body is {declaredBodyLength} bytes, over the {maxFrameBytes} byte limit");
        }

        long totalLength = FrameHeader.FixedLength + (long)declaredBodyLength;
        if (frame.Length < totalLength)
        {
            // Truncated, not malformed. The receiver cannot know yet whether the
            // frame is bad, only that it is incomplete.
            return new ReceiveVerdict(
                ReceiveAction.WaitForMore,
                null,
                $"truncated body: have {frame.Length - FrameHeader.FixedLength} of {declaredBodyLength} bytes");
        }

        byte messageType = frame[7];
        uint channelId = FrameHeaderCodec.ReadUInt32BigEndian(frame, 8);
        ReadOnlySpan<byte> body = frame.Slice(FrameHeader.FixedLength, (int)declaredBodyLength);

        MessageType? registered = registry.FindMessageType(messageType);

        // An unregistered message type is a recoverable refusal rather than a
        // fatal one, so a newer peer sending something this one has not learned
        // cannot break the session. That is the registry's reply rule.
        if (registered is null)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorSessionContinues,
                ErrorCodes.UnsupportedMessage,
                $"message type 0x{messageType:x2} is not registered");
        }

        // Channel 0 is always open, so only a non-zero channel can be unknown.
        if (channelId != 0 && !registered.IsChannelConstrained())
        {
            // The channel existence check belongs to the caller's session state;
            // this method is told which channel the frame names and reports the
            // message type's own well-formedness.
            _ = channelId;
        }

        // The state-machine check comes before the encryption check, and the
        // order is the vector's. Before a session exists there is no key material
        // for any message to be encrypted with, so "this frame is encrypted
        // wrongly" is a meaningless complaint about a frame that should not be
        // here at all. The vector's case is an unencrypted PING as a first frame:
        // both rules could fire, and it requires the state-machine answer.
        if (expectedFirstMessageType is { } expected && messageType != expected)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.UnexpectedMessage,
                $"the first frame must be message type {expected} but this is {messageType}");
        }

        // The encrypted flag must agree with the registry: only HELLO and
        // HELLO_ACK travel in the clear.
        bool encrypted = (frame[5] & (byte)FrameFlags.Encrypted) != 0;
        if (registered.Encrypted && !encrypted)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.Unauthorized,
                $"{registered.Name} must carry the ENCRYPTED flag");
        }

        if (!registered.Encrypted && encrypted)
        {
            // The body would not be the plaintext the schema expects, so this
            // cannot be decoded and must not be guessed at.
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.Malformed,
                $"{registered.Name} must not be encrypted");
        }

        // The capability gate. A registered message the negotiated set does not
        // include is refused, but the session continues.
        if (CapabilityNegotiation.RejectionFor(registry, messageType, negotiatedCapabilities) is { } gate)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorSessionContinues,
                gate,
                gate == ErrorCodes.UnsupportedMessage
                    ? $"message type {messageType} is not registered"
                    : $"message type {messageType} needs capability '{registry.CapabilityFor(messageType)}'");
        }

        // The body must be valid cbOR before anything downstream sees it, so a
        // malformed body is one error at one place rather than a different
        // failure in every per-message parser.
        //
        // An empty body is legal and is handled by the reader, not by a special
        // case here: RFC-0001 section 3.2 encodes an empty body as zero bytes for
        // the message types that define no parameters, and the vector file's
        // accepted cases rely on it.
        if (!IsValidCbor(body, out string cborReason))
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.Malformed,
                $"the body is not valid cbOR: {cborReason}");
        }

        return new ReceiveVerdict(ReceiveAction.Accept, null, registered.Name);
    }

    /// <summary>
    /// Validates that a body is a single well-formed cbOR item, or empty.
    /// </summary>
    /// <param name="body">The body bytes.</param>
    /// <param name="reason">A description of the outcome.</param>
    /// <returns><see langword="true"/> when the body is acceptable.</returns>
    /// <remarks>
    /// <para>
    /// The reader is strict by construction: no indefinite lengths, no
    /// non-shortest integers, no tags and no floats, so this accepts exactly what
    /// DLWP/1 permits and nothing more.
    /// </para>
    /// <para>
    /// An empty body is accepted, and that is a decision rather than an
    /// oversight. RFC-0001 section 3.2 says an empty body is encoded as zero
    /// bytes for the message types that define no parameters, so a receiver that
    /// rejected an empty body would refuse the canonical encoding of every
    /// parameterless message. Whether a given message type may be empty is the
    /// per-message schema's business, not this method's, which is why the caller
    /// is handed the body and told it is well formed rather than told it is
    /// non-empty.
    /// </para>
    /// </remarks>
    public static bool IsValidCbor(ReadOnlySpan<byte> body, out string reason)
    {
        if (body.Length == 0)
        {
            // The canonical encoding of an empty body. See the remarks above.
            reason = "empty body, which RFC-0001 section 3.2 makes canonical for a parameterless message";
            return true;
        }

        try
        {
            CborReader reader = new(body);
            reader.SkipItem();
            reader.RequireEnd();
            reason = "valid";
            return true;
        }
        catch (CborException error)
        {
            reason = $"{error.Error.Kind} at offset {error.Error.Offset}: {error.Error.Message}";
            return false;
        }
    }

    /// <summary>
    /// Classifies a frame's sequence number against the expected one.
    /// </summary>
    /// <param name="sequenceNumber">The frame's sequence number.</param>
    /// <param name="highestSeen">
    /// The highest sequence number already accepted, or <see langword="null"/>
    /// when nothing has been accepted yet.
    /// </param>
    /// <param name="window">The reordering window. Defaults to <see cref="ReorderWindow"/>.</param>
    /// <returns>The verdict.</returns>
    /// <remarks>
    /// <para>
    /// The sequence number is session-global and must increase. Three cases:
    /// </para>
    /// <list type="bullet">
    /// <item>A repeat is a replay attempt and is <b>fatal</b>, not recoverable. A
    /// peer that repeats a sequence number is either broken or attacking, and
    /// either way continuing means the receiver cannot tell which of two frames
    /// with the same number was the real one.</item>
    /// <item>A gap <i>inside</i> the window is legal on a lossy link, because
    /// reordering is normal on Wi-Fi.</item>
    /// <item>A frame at or behind the window's floor is rejected, because
    /// accepting arbitrarily old frames would let an attacker replay one
    /// indefinitely.</item>
    /// </list>
    /// <para>
    /// <b>"Nothing accepted yet" is not the number zero.</b> A <see cref="uint"/>
    /// cannot say "no frames have arrived", so a sentinel such as 0 or
    /// <see cref="uint.MaxValue"/> always collides with a legal sequence number:
    /// with 0, the session's own first frame looks like a repeat; with
    /// <see cref="uint.MaxValue"/> it looks like a frame billions behind the
    /// window. The first frame is a legal frame, so the absence of a previous one
    /// is modelled as absence, and the first frame of a session is always
    /// accepted. That is only sound because the handshake authenticates the peer
    /// before any of this runs: an unauthenticated first frame has nothing to
    /// replay.
    /// </para>
    /// </remarks>
    public static ReceiveVerdict ClassifySequence(uint sequenceNumber, uint? highestSeen, uint window = ReorderWindow)
        => ClassifySequence(sequenceNumber, highestSeen, seenBefore: null, window);

    /// <summary>
    /// Classifies a sequence number against what has already been accepted.
    /// </summary>
    /// <param name="sequenceNumber">The number to classify.</param>
    /// <param name="highestSeen">The highest number accepted, or null.</param>
    /// <param name="seenBefore">
    /// Whether this exact number has already been accepted, or null when that is not
    /// known. Supplying it is what distinguishes a duplicate from a reorder.
    /// </param>
    /// <param name="window">The reordering window.</param>
    /// <returns>The verdict.</returns>
    /// <remarks>
    /// <para>
    /// The check on an exact repeat comes before the window check and is not a special
    /// case of being behind. The two are different questions, and the window cannot
    /// answer one of them: a number below the head may be a reorder that has not
    /// arrived yet or a duplicate that has, and both look identical when all that is
    /// known is the highest number seen.
    /// </para>
    /// <para>
    /// Getting this wrong is not subtle in its effect. The vector
    /// <c>malformed.sequence-not-monotonic</c> is <c>[1,2,3,3]</c> — a repeat of the
    /// head, which is what a naive replay looks like — and the window alone accepts it
    /// as a reorder, because zero frames behind is inside the window. Meanwhile
    /// <c>malformed.sequence-gap-within-window</c> is <c>[1,2,3,5,4,6]</c>, where 4 is
    /// behind 5 but has never arrived, and that must be accepted. Only the seen-set
    /// separates them. The session transcript's step 17 is the same shape as the first
    /// case and is why this parameter exists.
    /// </para>
    /// <para>
    /// When <paramref name="seenBefore"/> is null the second arrival of a number
    /// cannot be recognised, and the zero-behind case is treated as a repeat, which is
    /// the safe default: a caller that cannot say whether a number was already seen
    /// should not accept it twice.
    /// </para>
    /// </remarks>
    public static ReceiveVerdict ClassifySequence(
        uint sequenceNumber,
        uint? highestSeen,
        bool? seenBefore,
        uint window = ReorderWindow)
    {
        // The first frame of a session has nothing before it to be a replay of.
        if (highestSeen is null)
        {
            return new ReceiveVerdict(
                ReceiveAction.Accept,
                null,
                $"sequence number {sequenceNumber} is the first accepted frame");
        }

        uint highest = highestSeen.Value;

        // A number that has already been accepted is a replay at any distance, and
        // this is checked before the window so a duplicate is never excused as a
        // reorder.
        if (seenBefore == true)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.ReplayDetected,
                $"sequence number {sequenceNumber} has already been accepted on this session");
        }

        if (sequenceNumber == highest)
        {
            return new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.ReplayDetected,
                $"sequence number {sequenceNumber} repeats the highest already seen");
        }

        if (sequenceNumber > highest)
        {
            // Ahead of what has been seen: either in order or a gap within the
            // reordering window, both legal.
            return new ReceiveVerdict(
                ReceiveAction.Accept,
                null,
                $"sequence number {sequenceNumber} advances the stream");
        }

        // Behind the highest seen. Inside the window is reordering on a lossy
        // link; outside it is too old to be a reorder and is treated as a replay.
        uint behind = highest - sequenceNumber;

        return behind < window
            ? new ReceiveVerdict(ReceiveAction.Accept, null, "reordered within the reordering window")
            : new ReceiveVerdict(
                ReceiveAction.ErrorFrameThenClose,
                ErrorCodes.ReplayDetected,
                $"sequence number {sequenceNumber} is {behind} behind, outside the {window} frame window");
    }

    /// <summary>
    /// Validates a message body against its schema's required keys and value types.
    /// </summary>
    /// <param name="body">The cbOR body.</param>
    /// <param name="requiredKeys">The keys the message requires.</param>
    /// <returns><see langword="null"/> when acceptable, or the error to report.</returns>
    /// <remarks>
    /// <para>
    /// Two rules, and the asymmetry between them is the forward-compatibility
    /// design:
    /// </para>
    /// <list type="bullet">
    /// <item>An <b>unknown</b> key is ignored. A newer peer must be able to add
    /// one without breaking an older one, which is the whole reason capability
    /// negotiation and this rule both exist.</item>
    /// <item>A <b>missing</b> required key is fatal. The message cannot be
    /// executed, and the receiver cannot resynchronise because it does not know
    /// what the frame meant.</item>
    /// </list>
    /// </remarks>
    public static ErrorCode? ValidateRequiredKeys(ReadOnlySpan<byte> body, IReadOnlyList<string> requiredKeys)
    {
        ArgumentNullException.ThrowIfNull(requiredKeys);

        if (body.Length == 0)
        {
            return requiredKeys.Count == 0 ? null : ErrorCodes.Malformed;
        }

        try
        {
            CborReader reader = new(body);

            if (reader.PeekMajorType() != CborMajorType.Map)
            {
                return ErrorCodes.Malformed;
            }

            int count = reader.ReadMapHeader();
            HashSet<string> present = new(StringComparer.Ordinal);

            for (int i = 0; i < count; i++)
            {
                string key = reader.ReadTextString();

                // Unknown keys are read past, not rejected: ignoring what you do
                // not know is the forward-compatibility rule.
                present.Add(key);
                reader.SkipItem();
            }

            reader.RequireEnd();

            foreach (string required in requiredKeys)
            {
                if (!present.Contains(required))
                {
                    return ErrorCodes.Malformed;
                }
            }

            return null;
        }
        catch (CborException)
        {
            return ErrorCodes.Malformed;
        }
    }
}

/// <summary>
/// Small helpers over the registry used by the frame classifier.
/// </summary>
internal static class MessageTypeExtensions
{
    /// <summary>Whether a message type is restricted to the control channel.</summary>
    /// <param name="type">The message type.</param>
    /// <returns><see langword="true"/> when only the control channel may carry it.</returns>
    internal static bool IsChannelConstrained(this MessageType type)
    {
        ArgumentNullException.ThrowIfNull(type);
        return type.Channel == ChannelConstraint.Control;
    }
}
