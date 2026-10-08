namespace DroidLab.Protocol.Cbor;

/// <summary>
/// Wraps a <see cref="CborError"/> so it can be thrown.
/// </summary>
/// <remarks>
/// Reading a body is a local, bounded parse of bytes that are already in memory,
/// so an exception is the right shape: unlike a frame arriving off a socket,
/// there is no partial-result state a caller could act on. The
/// <see cref="Error"/> property carries the DLWP/1 error code, so the session
/// layer translates it straight into an <c>ERROR</c> frame without re-deriving
/// which error the RFC mandates.
/// </remarks>
public sealed class CborException : Exception
{
    /// <summary>Creates an exception from a decoding error.</summary>
    /// <param name="error">The decoding error.</param>
    public CborException(CborError error)
        : base(error.Message)
    {
        Error = error;
    }

    /// <summary>Creates an exception from a decoding error and an inner cause.</summary>
    /// <param name="error">The decoding error.</param>
    /// <param name="innerException">The underlying cause.</param>
    public CborException(CborError error, Exception innerException)
        : base(error.Message, innerException)
    {
        Error = error;
    }

    /// <summary>Creates an exception with a default message.</summary>
    public CborException()
        : base("cbOR decoding failed")
    {
        Error = new CborError(CborErrorKind.SchemaViolation, "cbOR decoding failed", 0);
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">The message.</param>
    public CborException(string message)
        : base(message)
    {
        Error = new CborError(CborErrorKind.SchemaViolation, message, 0);
    }

    /// <summary>Creates an exception with a message and an inner cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public CborException(string message, Exception innerException)
        : base(message, innerException)
    {
        Error = new CborError(CborErrorKind.SchemaViolation, message, 0);
    }

    /// <summary>The structured decoding error, including the DLWP/1 error code.</summary>
    public CborError Error { get; }
}
