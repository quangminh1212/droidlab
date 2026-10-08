using System.Collections.Frozen;

namespace DroidLab.Protocol;

/// <summary>
/// The DLWP/1 error-code registry (RFC-0001 section 6.2).
/// </summary>
/// <remarks>
/// <para>
/// The registry is declared normative by RFC-0001 section 11, and its
/// machine-readable encoding is <c>protocol/registry/dlwp-1.json</c>. The table
/// below is a mirror of that file, and
/// <c>RegistryConformanceTests</c> asserts the two agree: a code or severity
/// that exists here but not in the registry, or the reverse, fails the build.
/// </para>
/// <para>
/// Severities are not advice. Section 6.1 requires a fatal error to be followed
/// by <c>SESSION_END</c>, so a codec that reports <c>ERR_MALFORMED</c> as
/// recoverable and keeps the session alive is non-conformant, not merely
/// lenient.
/// </para>
/// </remarks>
public static class ErrorCodes
{
    /// <summary>Unknown or disabled message type.</summary>
    public static readonly ErrorCode UnsupportedMessage = new("ERR_UNSUPPORTED_MESSAGE", ErrorSeverity.Recoverable);

    /// <summary>Known type, capability not negotiated.</summary>
    public static readonly ErrorCode UnsupportedFeature = new("ERR_UNSUPPORTED_FEATURE", ErrorSeverity.Recoverable);

    /// <summary>Header length other than 24.</summary>
    public static readonly ErrorCode UnsupportedHeader = new("ERR_UNSUPPORTED_HEADER", ErrorSeverity.Fatal);

    /// <summary>Declared body exceeds the negotiated maximum.</summary>
    public static readonly ErrorCode FrameTooLarge = new("ERR_FRAME_TOO_LARGE", ErrorSeverity.Fatal);

    /// <summary>Body is not valid cbOR or violates the schema.</summary>
    public static readonly ErrorCode Malformed = new("ERR_MALFORMED", ErrorSeverity.Fatal);

    /// <summary>No protocol version in common.</summary>
    public static readonly ErrorCode VersionMismatch = new("ERR_VERSION_MISMATCH", ErrorSeverity.Fatal);

    /// <summary>Transcript hash disagreement.</summary>
    public static readonly ErrorCode HandshakeMismatch = new("ERR_HANDSHAKE_MISMATCH", ErrorSeverity.Fatal);

    /// <summary>Missing, wrong or expired proof.</summary>
    public static readonly ErrorCode Unauthorized = new("ERR_UNAUTHORIZED", ErrorSeverity.Fatal);

    /// <summary>Unknown pairing id; the controller must pair first.</summary>
    public static readonly ErrorCode PairingRequired = new("ERR_PAIRING_REQUIRED", ErrorSeverity.Fatal);

    /// <summary>The pairing was revoked on the device.</summary>
    public static readonly ErrorCode PairingRevoked = new("ERR_PAIRING_REVOKED", ErrorSeverity.Fatal);

    /// <summary>Reused sequence number or nonce.</summary>
    public static readonly ErrorCode ReplayDetected = new("ERR_REPLAY_DETECTED", ErrorSeverity.Fatal);

    /// <summary>Message is legal but out of order.</summary>
    public static readonly ErrorCode BadState = new("ERR_BAD_STATE", ErrorSeverity.Recoverable);

    /// <summary>Message may not appear at this point.</summary>
    public static readonly ErrorCode UnexpectedMessage = new("ERR_UNEXPECTED_MESSAGE", ErrorSeverity.Fatal);

    /// <summary>Operation on an unopened channel.</summary>
    public static readonly ErrorCode ChannelUnknown = new("ERR_CHANNEL_UNKNOWN", ErrorSeverity.Recoverable);

    /// <summary>Too many open channels.</summary>
    public static readonly ErrorCode ChannelLimit = new("ERR_CHANNEL_LIMIT", ErrorSeverity.Recoverable);

    /// <summary>Operator has not granted the required permission.</summary>
    public static readonly ErrorCode PermissionDenied = new("ERR_PERMISSION_DENIED", ErrorSeverity.Recoverable);

    /// <summary>Shell allow-list rejected the command.</summary>
    public static readonly ErrorCode NotAllowed = new("ERR_NOT_ALLOWED", ErrorSeverity.Recoverable);

    /// <summary>Operation exceeded its deadline.</summary>
    public static readonly ErrorCode Timeout = new("ERR_TIMEOUT", ErrorSeverity.Recoverable);

    /// <summary>Resource in use, e.g. an active capture.</summary>
    public static readonly ErrorCode Busy = new("ERR_BUSY", ErrorSeverity.Recoverable);

    /// <summary>Out of memory, file descriptors or disk.</summary>
    public static readonly ErrorCode ResourceExhausted = new("ERR_RESOURCE_EXHAUSTED", ErrorSeverity.Recoverable);

    /// <summary>Platform I/O failure.</summary>
    public static readonly ErrorCode Io = new("ERR_IO", ErrorSeverity.Recoverable);

    /// <summary>Unclassified defect.</summary>
    public static readonly ErrorCode Internal = new("ERR_INTERNAL", ErrorSeverity.Fatal);

    /// <summary>Every registered error code.</summary>
    /// <remarks>
    /// This is a plain field, not a property, and it is declared before
    /// <see cref="ByName"/>. Static initialisers run in declaration order, so a
    /// property here would let <see cref="ByName"/> read a null backing field
    /// depending on which member was touched first.
    /// </remarks>
    public static readonly IReadOnlyList<ErrorCode> All =
    [
        UnsupportedMessage,
        UnsupportedFeature,
        UnsupportedHeader,
        FrameTooLarge,
        Malformed,
        VersionMismatch,
        HandshakeMismatch,
        Unauthorized,
        PairingRequired,
        PairingRevoked,
        ReplayDetected,
        BadState,
        UnexpectedMessage,
        ChannelUnknown,
        ChannelLimit,
        PermissionDenied,
        NotAllowed,
        Timeout,
        Busy,
        ResourceExhausted,
        Io,
        Internal,
    ];

    private static readonly FrozenDictionary<string, ErrorCode> ByName =
        All.ToFrozenDictionary(code => code.Name, StringComparer.Ordinal);

    /// <summary>Looks up a code by its symbolic name.</summary>
    /// <param name="name">The symbolic name, e.g. <c>ERR_MALFORMED</c>.</param>
    /// <returns>The code, or <see langword="null"/> when the name is not registered.</returns>
    public static ErrorCode? Find(string name) =>
        ByName.TryGetValue(name, out ErrorCode? code) ? code : null;
}

/// <summary>
/// A DLWP/1 error code with the severity RFC-0001 section 6.2 assigns to it.
/// </summary>
/// <param name="Name">The symbolic name, e.g. <c>ERR_MALFORMED</c>.</param>
/// <param name="Severity">The registered severity.</param>
public sealed record ErrorCode(string Name, ErrorSeverity Severity)
{
    /// <summary>Whether reporting this error requires closing the connection.</summary>
    public bool IsFatal => Severity == ErrorSeverity.Fatal;

    /// <summary>Returns the symbolic name, which is what appears on the wire.</summary>
    /// <returns>The symbolic name.</returns>
    public override string ToString() => Name;
}
