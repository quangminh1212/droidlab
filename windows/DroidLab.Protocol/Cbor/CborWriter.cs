using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace DroidLab.Protocol.Cbor;

/// <summary>
/// Writes DLWP/1 body values in the canonical cbOR form the vectors pin.
/// </summary>
/// <remarks>
/// <para>
/// The writer emits the shortest form of every argument and always uses a
/// definite length, matching the "integer_encoding" and "map_encoding" rules in
/// <c>protocol/vectors/framing-basic.json</c>. That is what makes an encoded
/// body unique, and a unique encoding is what lets two independent
/// implementations — the Kotlin agent and this C# controller — be compared byte
/// for byte.
/// </para>
/// <para>
/// Map keys are written in the order the caller supplies them. RFC-0001 lists
/// keys per message in a fixed order and the vectors depend on it, so the
/// ordering is a caller responsibility and each message body type owns its own
/// key order.
/// </para>
/// </remarks>
public struct CborWriter : IDisposable
{
    private ArrayBufferWriter<byte> _buffer;

    /// <summary>Creates a writer with a default initial capacity.</summary>
    public CborWriter()
    {
        _buffer = new ArrayBufferWriter<byte>(64);
    }

    /// <summary>Creates a writer with a hint for the expected size.</summary>
    /// <param name="initialCapacity">The initial capacity in bytes.</param>
    public CborWriter(int initialCapacity)
    {
        _buffer = new ArrayBufferWriter<byte>(initialCapacity);
    }

    /// <summary>The number of bytes written so far.</summary>
    public readonly int Length => _buffer.WrittenCount;

    /// <summary>The bytes written so far.</summary>
    /// <returns>A copy of the written bytes.</returns>
    public readonly byte[] ToArray() => _buffer.WrittenSpan.ToArray();

    /// <summary>The bytes written so far, as a span.</summary>
    public readonly ReadOnlySpan<byte> WrittenSpan => _buffer.WrittenSpan;

    /// <summary>Writes the head byte and argument for an item.</summary>
    /// <param name="major">The major type.</param>
    /// <param name="argument">The argument, which must be non-negative.</param>
    private void WriteHead(CborMajorType major, ulong argument)
    {
        byte prefix = (byte)((byte)major << 5);
        Span<byte> destination = _buffer.GetSpan(9);

        if (argument < 24)
        {
            destination[0] = (byte)(prefix | (byte)argument);
            _buffer.Advance(1);
            return;
        }

        if (argument <= byte.MaxValue)
        {
            destination[0] = (byte)(prefix | 24);
            destination[1] = (byte)argument;
            _buffer.Advance(2);
            return;
        }

        if (argument <= ushort.MaxValue)
        {
            destination[0] = (byte)(prefix | 25);
            BinaryPrimitives.WriteUInt16BigEndian(destination[1..], (ushort)argument);
            _buffer.Advance(3);
            return;
        }

        if (argument <= uint.MaxValue)
        {
            destination[0] = (byte)(prefix | 26);
            BinaryPrimitives.WriteUInt32BigEndian(destination[1..], (uint)argument);
            _buffer.Advance(5);
            return;
        }

        destination[0] = (byte)(prefix | 27);
        BinaryPrimitives.WriteUInt64BigEndian(destination[1..], argument);
        _buffer.Advance(9);
    }

    /// <summary>Writes an unsigned integer.</summary>
    /// <param name="value">The value.</param>
    public void WriteUnsignedInteger(ulong value) => WriteHead(CborMajorType.UnsignedInteger, value);

    /// <summary>Writes an unsigned integer from a smaller type.</summary>
    /// <param name="value">The value.</param>
    public void WriteUnsignedInteger(uint value) => WriteUnsignedInteger((ulong)value);

    /// <summary>Writes an unsigned integer from a smaller type.</summary>
    /// <param name="value">The value.</param>
    public void WriteUnsignedInteger(int value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        WriteUnsignedInteger((ulong)value);
    }

    /// <summary>Writes a byte string.</summary>
    /// <param name="value">The bytes.</param>
    public void WriteByteString(ReadOnlySpan<byte> value)
    {
        WriteHead(CborMajorType.ByteString, (ulong)value.Length);
        value.CopyTo(_buffer.GetSpan(value.Length));
        _buffer.Advance(value.Length);
    }

    /// <summary>Writes a UTF-8 text string.</summary>
    /// <param name="value">The string. <see langword="null"/> is written as an empty string.</param>
    /// <exception cref="ArgumentException">The string contains an unpaired surrogate.</exception>
    /// <remarks>
    /// An unpaired surrogate has no valid UTF-8 encoding, so writing one would
    /// produce a body the peer must reject. It is a caller bug and is reported
    /// as such rather than silently replaced.
    /// </remarks>
    public void WriteTextString(string? value)
    {
        value ??= string.Empty;

        // The strict encoder throws on an unpaired surrogate, so the byte count
        // is computed once and the encode is attempted on exactly that span.
        int byteCount;
        try
        {
            byteCount = StrictUtf8.GetByteCount(value);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException(
                "the string contains an unpaired surrogate and has no valid UTF-8 encoding",
                nameof(value),
                ex);
        }

        WriteHead(CborMajorType.TextString, (ulong)byteCount);
        StrictUtf8.GetBytes(value, _buffer.GetSpan(byteCount));
        _buffer.Advance(byteCount);
    }

    /// <summary>Writes a definite-length array header.</summary>
    /// <param name="count">The number of elements that follow.</param>
    public void WriteArrayHeader(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        WriteHead(CborMajorType.Array, (ulong)count);
    }

    /// <summary>Writes a definite-length map header.</summary>
    /// <param name="count">The number of key/value pairs that follow.</param>
    public void WriteMapHeader(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        WriteHead(CborMajorType.Map, (ulong)count);
    }

    /// <summary>Writes an empty map, the encoding for a message with no parameters.</summary>
    public void WriteEmptyMap() => WriteMapHeader(0);

    /// <summary>Releases the buffer.</summary>
    public void Dispose() => _buffer = null!;
}

/// <summary>
/// A strict UTF-8 codec that throws on invalid input, rather than substituting U+FFFD.
/// </summary>
internal static class StrictUtf8
{
    private static readonly System.Text.UTF8Encoding Strict = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static string GetString(ReadOnlySpan<byte> bytes) => Strict.GetString(bytes);

    internal static byte[] GetBytes(string value) => Strict.GetBytes(value);

    internal static int GetByteCount(string value) => Strict.GetByteCount(value);

    internal static void GetBytes(string value, Span<byte> destination)
    {
#pragma warning disable CA1305 // the strict encoder is culture-independent
        Strict.GetBytes(value.AsSpan(), destination);
#pragma warning restore CA1305
    }
}
