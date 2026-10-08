namespace DroidLab.Protocol;

/// <summary>
/// Enforces the frame-level rules of RFC-0001 that a decoder cannot decide on
/// its own, and maps each violation to the error code and severity the peer must
/// be told about.
/// </summary>
/// <remarks>
/// <para>
/// The order of checks is normative and matters. Magic comes first, because
/// nothing else in the buffer means anything until it matches. Version comes
/// next, because the rest of the rules are version-specific. The declared body
/// length is checked before the body is read, so a hostile sender cannot make
/// the receiver allocate 4 GiB by claiming it (RFC-0001 section 2).
/// </para>
/// </remarks>
public static class FrameValidator
{
    /// <summary>The default maximum body size, from the RFC-0001 section 7.3 limits table.</summary>
    public const uint DefaultMaxFrameBytes = 16_777_216;

    /// <summary>
    /// Validates a decoded header against the rules that do not depend on session state.
    /// </summary>
    /// <param name="header">The decoded header.</param>
    /// <param name="maxFrameBytes">The negotiated maximum body size, or <see cref="DefaultMaxFrameBytes"/>.</param>
    /// <returns><see langword="null"/> when the header is valid; the violation otherwise.</returns>
    /// <remarks>
    /// This checks structure only. Whether the message type is known, whether it
    /// is enabled by a negotiated capability, and whether it is legal in the
    /// current state are separate questions with separate error codes.
    /// </remarks>
    public static FrameError? Validate(FrameHeader header, uint maxFrameBytes = DefaultMaxFrameBytes)
    {
        if (header.Version != FrameHeader.ProtocolVersion)
        {
            // No best-effort parse: RFC-0001 section 10 says a receiver that does
            // not implement the version must not try to read the frame anyway.
            return new FrameError(
                FrameErrorKind.UnsupportedVersion,
                $"protocol version {header.Version} is not implemented; this codec implements " +
                $"{FrameHeader.ProtocolVersion}",
                ErrorCodes.VersionMismatch,
                ErrorCodes.VersionMismatch.Severity,
                ClosesConnection: true);
        }

        if (header.HeaderLength != FrameHeader.FixedLength)
        {
            // Version 1.0 defines no header extensions, so any other value is
            // rejected rather than skipped.
            return new FrameError(
                FrameErrorKind.UnsupportedHeaderLength,
                $"header_length must be {FrameHeader.FixedLength} in DLWP/1, got {header.HeaderLength}",
                ErrorCodes.UnsupportedHeader,
                ErrorCodes.UnsupportedHeader.Severity,
                ClosesConnection: true);
        }

        if (header.BodyLength > maxFrameBytes)
        {
            return new FrameError(
                FrameErrorKind.FrameTooLarge,
                $"declared body_length {header.BodyLength} exceeds the maximum of {maxFrameBytes}",
                ErrorCodes.FrameTooLarge,
                ErrorCodes.FrameTooLarge.Severity,
                ClosesConnection: true);
        }

        return null;
    }

    /// <summary>
    /// Validates a whole frame buffer: header, declared length and body presence.
    /// </summary>
    /// <param name="frame">The bytes of one frame.</param>
    /// <param name="header">The decoded header on success.</param>
    /// <param name="body">The body bytes on success.</param>
    /// <param name="error">The violation on failure.</param>
    /// <param name="maxFrameBytes">The negotiated maximum body size.</param>
    /// <returns><see langword="true"/> when the frame is structurally valid.</returns>
    /// <remarks>
    /// A frame whose declared length does not match the bytes present is
    /// rejected rather than tolerated. Accepting a short frame would let a
    /// truncated stream desynchronise the framing silently, and accepting a long
    /// one would splice the next frame's bytes into the body.
    /// </remarks>
    public static bool TryValidateFrame(
        ReadOnlySpan<byte> frame,
        out FrameHeader header,
        out ReadOnlySpan<byte> body,
        out FrameError? error,
        uint maxFrameBytes = DefaultMaxFrameBytes)
    {
        body = default;

        if (!FrameHeaderCodec.TryDecode(frame, out header, out error))
        {
            // A bad magic is not reportable: the peer is not speaking DLWP/1, so
            // there is no session to send an ERROR frame inside.
            if (error?.Kind == FrameErrorKind.BadMagic)
            {
                error = error with
                {
                    Code = ErrorCodes.Malformed,
                    Severity = ErrorCodes.Malformed.Severity,
                    ClosesConnection = true,
                };
            }

            return false;
        }

        error = Validate(header, maxFrameBytes);
        if (error is not null)
        {
            return false;
        }

        if (frame.Length < header.TotalLength)
        {
            error = new FrameError(
                FrameErrorKind.TruncatedBody,
                $"header declares {header.TotalLength} bytes but only {frame.Length} are present",
                ErrorCodes.Malformed,
                ErrorCodes.Malformed.Severity,
                ClosesConnection: true);
            return false;
        }

        if (frame.Length > header.TotalLength)
        {
            error = new FrameError(
                FrameErrorKind.MalformedBody,
                $"frame is {frame.Length} bytes but the header declares {header.TotalLength}",
                ErrorCodes.Malformed,
                ErrorCodes.Malformed.Severity,
                ClosesConnection: true);
            return false;
        }

        body = frame[header.HeaderLength..];
        return true;
    }
}
