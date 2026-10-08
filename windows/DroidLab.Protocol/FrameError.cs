namespace DroidLab.Protocol;

/// <summary>
/// The class of a frame-level defect, before it is mapped to a protocol error code.
/// </summary>
/// <remarks>
/// These are decoding concerns, not wire error codes. The mapping from a class
/// to an <see cref="ErrorCode"/> and a severity is a specification decision, so
/// it lives in <see cref="FrameValidator"/> where it can be tested against the
/// registry rather than scattered across decoders.
/// </remarks>
public enum FrameErrorKind
{
    /// <summary>The buffer ended before a complete header was available.</summary>
    TruncatedHeader,

    /// <summary>The first four bytes were not ASCII "DLWP".</summary>
    BadMagic,

    /// <summary>The declared header length is not the DLWP/1 fixed length of 24.</summary>
    UnsupportedHeaderLength,

    /// <summary>The protocol version in the header is not implemented by this codec.</summary>
    UnsupportedVersion,

    /// <summary>The declared body length exceeds the negotiated maximum.</summary>
    FrameTooLarge,

    /// <summary>The buffer ended before a complete body was available.</summary>
    TruncatedBody,

    /// <summary>The body is not valid cbOR or violates the schema for its message type.</summary>
    MalformedBody,
}

/// <summary>
/// A frame-level defect, carrying the protocol error code and severity the peer
/// must be told about.
/// </summary>
/// <remarks>
/// The severity is normative: RFC-0001 section 6.2 assigns one to each error
/// code, and section 6.1 says a fatal error must be followed by
/// <c>SESSION_END</c> and closed. Carrying the severity with the error keeps
/// that mapping in one place and makes it impossible to report a fatal
/// condition while leaving the session running.
/// </remarks>
/// <param name="Kind">The decoding defect class.</param>
/// <param name="Message">A human-readable description for the log. Never sent to the peer verbatim.</param>
/// <param name="Code">The wire error code, or <see langword="null"/> when the defect is not reportable.</param>
/// <param name="Severity">The severity of <paramref name="Code"/>, or <see langword="null"/> when there is no code.</param>
/// <param name="ClosesConnection">Whether the connection must be closed after reporting.</param>
public sealed record FrameError(
    FrameErrorKind Kind,
    string Message,
    ErrorCode? Code = null,
    ErrorSeverity? Severity = null,
    bool ClosesConnection = false)
{
    /// <summary>Whether this defect can be reported to the peer at all.</summary>
    /// <remarks>
    /// A bad magic or a truncated header cannot be reported inside the failed
    /// session, because the peer is not speaking DLWP/1 or the framing is
    /// already lost. Those cases close the connection silently and the reason is
    /// recorded locally.
    /// </remarks>
    public bool IsReportable => Code is not null;
}

/// <summary>
/// The severity classes of RFC-0001 section 6.1.
/// </summary>
public enum ErrorSeverity
{
    /// <summary>Informational; the session continues.</summary>
    Warning,

    /// <summary>Aborts only the affected operation or channel; the session continues.</summary>
    Recoverable,

    /// <summary>Must be followed by <c>SESSION_END</c>, and the sender must close the connection.</summary>
    Fatal,
}
