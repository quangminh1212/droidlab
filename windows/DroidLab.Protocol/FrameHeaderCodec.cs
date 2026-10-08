namespace DroidLab.Protocol;

/// <summary>
/// Reads and writes the fixed 24-byte DLWP/1 frame header.
/// </summary>
/// <remarks>
/// <para>
/// Two deliberate design choices, both driven by the conformance vectors:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Decoding never throws for a malformed input.</b> A malformed frame is an
/// expected event on a network — an attacker, a version mismatch, or a buggy
/// peer — and the protocol requires a specific error code and severity for each
/// class. Exceptions would push that mapping into catch blocks and lose the
/// distinction between "the peer is on a different version" and "the peer is
/// broken". <see cref="TryDecode"/> returns the exact
/// <see cref="FrameError"/> the RFC mandates.
/// </item>
/// <item>
/// <b>Decoding does not enforce protocol policy.</b> Whether
/// <c>header_length</c> must be 24, whether a message type is known, and whether
/// a frame is too large are all questions about a specific protocol version and
/// a negotiated limit, so they are answered by <see cref="FrameValidator"/>
/// against the registry. This type only turns bytes into fields.
/// </item>
/// </list>
/// </remarks>
public static class FrameHeaderCodec
{
    /// <summary>
    /// Attempts to read a frame header from the start of a buffer.
    /// </summary>
    /// <param name="buffer">The bytes to read. Only the first 24 are inspected.</param>
    /// <param name="header">The decoded header on success; default on failure.</param>
    /// <param name="error">The reason for failure, or <see langword="null"/> on success.</param>
    /// <returns><see langword="true"/> when a header was read.</returns>
    /// <remarks>
    /// A buffer shorter than 24 bytes fails with <see cref="FrameErrorKind.TruncatedHeader"/>
    /// and produces no header. The magic is checked first, because nothing else
    /// in the buffer can be trusted until it matches.
    /// </remarks>
    public static bool TryDecode(ReadOnlySpan<byte> buffer, out FrameHeader header, out FrameError? error)
    {
        header = default;
        error = null;

        if (buffer.Length < FrameHeader.FixedLength)
        {
            error = new FrameError(
                FrameErrorKind.TruncatedHeader,
                $"need {FrameHeader.FixedLength} bytes for a frame header, got {buffer.Length}");
            return false;
        }

        // The magic is checked before any other field. Reading a version or a
        // channel id out of bytes that are not a DLWP/1 frame is how a stun
        // protocol or a stray HTTP request gets parsed into nonsense.
        for (int i = 0; i < FrameHeader.Magic.Length; i++)
        {
            if (buffer[i] != FrameHeader.Magic[i])
            {
                error = new FrameError(
                    FrameErrorKind.BadMagic,
                    $"expected magic 'DLWP', got 0x{buffer[0]:x2}{buffer[1]:x2}{buffer[2]:x2}{buffer[3]:x2}");
                return false;
            }
        }

        header = new FrameHeader
        {
            Version = buffer[4],
            Flags = buffer[5],
            HeaderLength = buffer[6],
            MessageType = buffer[7],
            ChannelId = ReadUInt32BigEndian(buffer, 8),
            SequenceNumber = ReadUInt32BigEndian(buffer, 12),
            Acknowledgment = ReadUInt32BigEndian(buffer, 16),
            BodyLength = ReadUInt32BigEndian(buffer, 20),
        };

        return true;
    }

    /// <summary>
    /// Writes a frame header into the start of a buffer.
    /// </summary>
    /// <param name="header">The header to write.</param>
    /// <param name="destination">A buffer of at least 24 bytes.</param>
    /// <exception cref="ArgumentException">The destination is shorter than 24 bytes.</exception>
    /// <remarks>
    /// The reserved flag bits are masked off rather than trusted, so a caller
    /// cannot accidentally emit them and make a conformant peer reject the
    /// frame. Every field is written big-endian.
    /// </remarks>
    public static void Encode(FrameHeader header, Span<byte> destination)
    {
        if (destination.Length < FrameHeader.FixedLength)
        {
            throw new ArgumentException(
                $"a frame header needs {FrameHeader.FixedLength} bytes, got {destination.Length}",
                nameof(destination));
        }

        FrameHeader.Magic.CopyTo(destination);
        destination[4] = header.Version;
        destination[5] = (byte)(header.Flags & FrameFlagsMask.Defined);
        destination[6] = header.HeaderLength;
        destination[7] = header.MessageType;
        WriteUInt32BigEndian(destination, 8, header.ChannelId);
        WriteUInt32BigEndian(destination, 12, header.SequenceNumber);
        WriteUInt32BigEndian(destination, 16, header.Acknowledgment);
        WriteUInt32BigEndian(destination, 20, header.BodyLength);
    }

    /// <summary>
    /// Writes a frame header into a new 24-byte array.
    /// </summary>
    /// <param name="header">The header to write.</param>
    /// <returns>A 24-byte array holding the encoded header.</returns>
    public static byte[] Encode(FrameHeader header)
    {
        byte[] buffer = new byte[FrameHeader.FixedLength];
        Encode(header, buffer);
        return buffer;
    }

    internal static uint ReadUInt32BigEndian(ReadOnlySpan<byte> buffer, int offset) =>
        ((uint)buffer[offset] << 24)
        | ((uint)buffer[offset + 1] << 16)
        | ((uint)buffer[offset + 2] << 8)
        | buffer[offset + 3];

    internal static void WriteUInt32BigEndian(Span<byte> buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }
}
