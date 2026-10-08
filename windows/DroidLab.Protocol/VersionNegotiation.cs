namespace DroidLab.Protocol;

/// <summary>
/// A DLWP/1 protocol version, major and minor (RFC-0001 section 5).
/// </summary>
/// <param name="Major">The major number. This is the value in the frame header's Version field.</param>
/// <param name="Minor">The minor number. Minor versions travel in the <c>HELLO</c> body, not the header.</param>
/// <remarks>
/// <para>
/// Only the major number can appear in the 24-byte frame header, which is the
/// whole point of splitting them: a minor release adds message types, capability
/// names and optional body keys, none of which changes the frame layout, so the
/// header can keep carrying a single byte that stays at 1 for every 1.x. This is
/// what lets a 1.0 peer and a 1.1 peer share a wire format at all.
/// </para>
/// <para>
/// The type is ordered by major first and then minor, so "highest common
/// version" is a plain comparison rather than a custom sort.
/// </para>
/// </remarks>
public readonly record struct ProtocolVersion(byte Major, byte Minor) : IComparable<ProtocolVersion>
{
    /// <summary>The version this codec implements.</summary>
    public static readonly ProtocolVersion Current = new(1, 0);

    /// <summary>The major version carried in the frame header.</summary>
    public static readonly byte HeaderMajorVersion = 1;

    /// <summary>Compares by major first, then minor.</summary>
    /// <param name="other">The version to compare with.</param>
    /// <returns>A negative value, zero, or a positive value.</returns>
    public int CompareTo(ProtocolVersion other) =>
        Major != other.Major ? Major.CompareTo(other.Major) : Minor.CompareTo(other.Minor);

    /// <summary>Whether this version is greater than another.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> is greater.</returns>
    public static bool operator >(ProtocolVersion left, ProtocolVersion right) => left.CompareTo(right) > 0;

    /// <summary>Whether this version is less than another.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> is less.</returns>
    public static bool operator <(ProtocolVersion left, ProtocolVersion right) => left.CompareTo(right) < 0;

    /// <summary>Whether this version is greater than or equal to another.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> is at least <paramref name="right"/>.</returns>
    public static bool operator >=(ProtocolVersion left, ProtocolVersion right) => left.CompareTo(right) >= 0;

    /// <summary>Whether this version is less than or equal to another.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> is at most <paramref name="right"/>.</returns>
    public static bool operator <=(ProtocolVersion left, ProtocolVersion right) => left.CompareTo(right) <= 0;

    /// <summary>Formats the version as <c>major.minor</c>.</summary>
    /// <returns>The string form, e.g. <c>1.0</c>.</returns>
    public override string ToString() => $"{Major}.{Minor}";

    /// <summary>
    /// Parses a <c>major.minor</c> string.
    /// </summary>
    /// <param name="text">The text, e.g. <c>1.0</c>.</param>
    /// <param name="version">The parsed version.</param>
    /// <returns><see langword="true"/> when the text was a valid version.</returns>
    /// <remarks>
    /// Rejects anything that is not exactly two dotted components of digits. A
    /// permissive parser here would accept <c>1.0.3</c> or <c>1</c> and guess at
    /// what the peer meant, which is the guessing the negotiation rule exists to
    /// forbid.
    /// </remarks>
    public static bool TryParse(string? text, out ProtocolVersion version)
    {
        version = default;

        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        int dot = text.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0 || dot == text.Length - 1)
        {
            return false;
        }

        ReadOnlySpan<char> majorText = text.AsSpan(0, dot);
        ReadOnlySpan<char> minorText = text.AsSpan(dot + 1);

        // Exactly one dot: a third component means the peer sent something this
        // format does not define.
        if (minorText.Contains('.'))
        {
            return false;
        }

        // byte.TryParse accepts surrounding whitespace, so " 1.0" and "1.0 "
        // would parse. A version string with a space in it is not this format,
        // and silently trimming means accepting a value no other implementation
        // would produce — which is precisely the drift the negotiation rule
        // exists to prevent.
        if (majorText.Contains(' ') || minorText.Contains(' '))
        {
            return false;
        }

        if (!byte.TryParse(majorText, out byte major) || !byte.TryParse(minorText, out byte minor))
        {
            return false;
        }

        version = new ProtocolVersion(major, minor);
        return true;
    }

    /// <summary>
    /// Parses a <c>major.minor</c> string.
    /// </summary>
    /// <param name="text">The text, e.g. <c>1.0</c>.</param>
    /// <returns>The parsed version.</returns>
    /// <exception cref="FormatException">The text is not a valid version.</exception>
    public static ProtocolVersion Parse(string text) =>
        TryParse(text, out ProtocolVersion version)
            ? version
            : throw new FormatException($"'{text}' is not a major.minor version");
}

/// <summary>
/// The outcome of a version negotiation.
/// </summary>
/// <param name="Version">The agreed version, or <see langword="null"/> when none could be agreed.</param>
/// <param name="Error">The error to report, or <see langword="null"/> on success.</param>
public readonly record struct VersionNegotiationResult(ProtocolVersion? Version, ErrorCode? Error)
{
    /// <summary>Whether a version was agreed.</summary>
    public bool Succeeded => Version is not null;
}

/// <summary>
/// Negotiates the protocol version (RFC-0001 sections 5 and 10).
/// </summary>
/// <remarks>
/// <para>
/// The rule is <b>highest common version, or fail</b>. There is deliberately no
/// fallback and no guessing:
/// </para>
/// <list type="bullet">
/// <item>
/// A peer must not silently use an older version than the one agreed. A silent
/// downgrade turns a version bug into corrupt behaviour that looks like a
/// decoding bug, and the failure surfaces far from its cause.
/// </item>
/// <item>
/// A peer must not assume an unknown version meant the one it supports. "9.9" is
/// not "1.0", and treating it as such is how two implementations end up
/// disagreeing about the wire while both believe they agreed.
/// </item>
/// <item>
/// If the agent answers with a version the controller never offered, the
/// controller aborts. The agent has broken the rule, and continuing with an
/// unrequested version would mean the controller's own version list is
/// meaningless.
/// </item>
/// </list>
/// <para>
/// No overlap is <c>ERR_VERSION_MISMATCH</c> with fatal severity: send the error
/// and close, without attempting to parse the rest of the frame, because the
/// frame was encoded by a version whose layout this implementation does not know.
/// </para>
/// </remarks>
public static class VersionNegotiation
{
    /// <summary>
    /// Picks the highest version both sides support.
    /// </summary>
    /// <param name="controllerSupported">The versions the controller supports, most preferred first.</param>
    /// <param name="agentSupported">The versions the agent supports, most preferred first.</param>
    /// <returns>The highest common version, or <see langword="null"/> when there is none.</returns>
    /// <remarks>
    /// The order of the input lists does not matter and is not trusted. The
    /// answer is the highest version present in both, so a controller that lists
    /// 2.0 first still agrees 1.1 when the agent only knows 1.1 and 1.0. Treating
    /// the first entry as the controller's demand would make the answer depend
    /// on how a peer happened to sort its own list.
    /// </remarks>
    public static ProtocolVersion? HighestCommonVersion(
        IEnumerable<ProtocolVersion> controllerSupported,
        IEnumerable<ProtocolVersion> agentSupported)
    {
        ArgumentNullException.ThrowIfNull(controllerSupported);
        ArgumentNullException.ThrowIfNull(agentSupported);

        HashSet<ProtocolVersion> agent = [.. agentSupported];

        ProtocolVersion? best = null;
        foreach (ProtocolVersion candidate in controllerSupported)
        {
            if (!agent.Contains(candidate))
            {
                continue;
            }

            if (best is null || candidate > best.Value)
            {
                best = candidate;
            }
        }

        return best;
    }

    /// <summary>
    /// Negotiates a version, reporting the error to send when none can be agreed.
    /// </summary>
    /// <param name="controllerSupported">The versions the controller supports.</param>
    /// <param name="agentSupported">The versions the agent supports.</param>
    /// <returns>The agreed version, or the error to report.</returns>
    public static VersionNegotiationResult Negotiate(
        IEnumerable<ProtocolVersion> controllerSupported,
        IEnumerable<ProtocolVersion> agentSupported)
    {
        ProtocolVersion? agreed = HighestCommonVersion(controllerSupported, agentSupported);

        // No overlap is fatal, and deliberately not recoverable: a retry cannot
        // help, because both peers have already stated the full set of versions
        // they understand.
        return agreed is null
            ? new VersionNegotiationResult(null, ErrorCodes.VersionMismatch)
            : new VersionNegotiationResult(agreed, null);
    }

    /// <summary>
    /// Validates the version in the frame header.
    /// </summary>
    /// <param name="headerVersion">The Version field from the 24-byte header.</param>
    /// <returns><see langword="null"/> when acceptable, or the error to report.</returns>
    /// <remarks>
    /// The header carries the major number only. A receiver checks this byte
    /// before it parses anything else, because a frame from a different major
    /// version may not have the layout being parsed at all: the remaining fields
    /// could be a different width or mean something else entirely. Anything newer
    /// than this implementation's major is a mismatch, not something to attempt.
    /// </remarks>
    public static ErrorCode? ValidateHeaderVersion(byte headerVersion)
    {
        if (headerVersion != ProtocolVersion.HeaderMajorVersion)
        {
            return ErrorCodes.VersionMismatch;
        }

        return null;
    }

    /// <summary>
    /// Validates that the agent answered with a version the controller offered.
    /// </summary>
    /// <param name="controllerSupported">The versions the controller offered.</param>
    /// <param name="agentAnswered">The version the agent answered with.</param>
    /// <returns><see langword="null"/> when the answer is acceptable, or the error to report.</returns>
    /// <remarks>
    /// This is the controller checking the agent, not the other way round. An
    /// agent that answers with something the controller never offered has
    /// violated the rule, and accepting it would make the controller's own
    /// version list decorative.
    /// </remarks>
    public static ErrorCode? ValidateAgentAnswer(
        IEnumerable<ProtocolVersion> controllerSupported,
        ProtocolVersion agentAnswered)
    {
        ArgumentNullException.ThrowIfNull(controllerSupported);

        foreach (ProtocolVersion offered in controllerSupported)
        {
            if (offered == agentAnswered)
            {
                return null;
            }
        }

        return ErrorCodes.VersionMismatch;
    }

    /// <summary>
    /// Whether a change to the protocol requires a major version bump.
    /// </summary>
    /// <param name="changeKind">The kind of change, as named in the vectors.</param>
    /// <returns><see langword="true"/> when a major bump is required.</returns>
    /// <remarks>
    /// An additive change does not bump the version: a new message type, a new
    /// capability name or a new optional body key is ignored by an old peer,
    /// which is exactly what the unknown-name rules in negotiation are for. A
    /// change that alters the meaning of an existing field, removes one, or
    /// changes a default in a way that breaks an old peer does require a bump,
    /// because an old peer cannot detect it and will simply misbehave.
    /// </remarks>
    public static bool RequiresMajorBump(string changeKind) => changeKind switch
    {
        "add_capability_and_message_type" => false,
        "add_optional_body_key" => false,
        "add_message_type" => false,
        "change_default_of_video_codec" => true,
        "change_field_meaning" => true,
        "remove_field" => true,
        _ => throw new ArgumentOutOfRangeException(
            nameof(changeKind),
            changeKind,
            "this change kind is not classified; an unclassified change must not be assumed additive"),
    };
}
