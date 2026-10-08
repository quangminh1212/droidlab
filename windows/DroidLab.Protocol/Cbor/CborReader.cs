using System.Buffers.Binary;
using System.Text;

namespace DroidLab.Protocol.Cbor;

/// <summary>
/// The cbOR major types (RFC 8949 section 3.1).
/// </summary>
/// <remarks>
/// DLWP/1 uses major types 0 through 5 only. Tags (6) and simple/float values
/// (7) are rejected outright, because the protocol defines no floating-point
/// fields and no tags — see "no_tags" and "no_floats" in the framing vectors.
/// </remarks>
public enum CborMajorType : byte
{
    /// <summary>Unsigned integer.</summary>
    UnsignedInteger = 0,

    /// <summary>Negative integer.</summary>
    NegativeInteger = 1,

    /// <summary>Byte string.</summary>
    ByteString = 2,

    /// <summary>UTF-8 text string.</summary>
    TextString = 3,

    /// <summary>Array.</summary>
    Array = 4,

    /// <summary>Map.</summary>
    Map = 5,

    /// <summary>Tag. Not used by DLWP/1; rejected.</summary>
    Tag = 6,

    /// <summary>Simple value or float. Not used by DLWP/1; rejected.</summary>
    SimpleOrFloat = 7,
}

/// <summary>
/// The reason a cbOR item was rejected, with the error code the peer must be told about.
/// </summary>
public enum CborErrorKind
{
    /// <summary>The input ended before the item was complete.</summary>
    Truncated,

    /// <summary>An indefinite-length item was used, which DLWP/1 forbids.</summary>
    IndefiniteLength,

    /// <summary>An integer was encoded in more bytes than its value requires.</summary>
    NonShortestInteger,

    /// <summary>A tag appeared, which DLWP/1 forbids.</summary>
    TagNotAllowed,

    /// <summary>A floating-point value appeared, which DLWP/1 forbids.</summary>
    FloatNotAllowed,

    /// <summary>A byte or text string was not valid UTF-8.</summary>
    InvalidUtf8,

    /// <summary>A string or collection declared more elements than are present.</summary>
    LengthMismatch,

    /// <summary>Seconds, halves and other unspecified simple values.</summary>
    UnsupportedSimpleValue,

    /// <summary>The map key ordering or type did not match the message schema.</summary>
    SchemaViolation,

    /// <summary>A required key was absent.</summary>
    MissingRequiredKey,

    /// <summary>A key's value had the wrong cbOR type.</summary>
    WrongValueType,

    /// <summary>A fixed-width field had the wrong width.</summary>
    WrongWidth,
}

/// <summary>
/// A cbOR decoding failure carrying the DLWP/1 error code RFC-0001 section 3.2 requires.
/// </summary>
/// <param name="Kind">The decoding defect class.</param>
/// <param name="Message">A human-readable description for the log.</param>
/// <param name="Offset">The byte offset within the body where the defect was found.</param>
public sealed record CborError(CborErrorKind Kind, string Message, int Offset)
{
    /// <summary>
    /// The DLWP/1 error code for this defect.
    /// </summary>
    /// <remarks>
    /// Every cbOR defect in a body is <c>ERR_MALFORMED</c>, which RFC-0001
    /// section 6.2 registers as fatal. Returning the code rather than letting
    /// callers invent one keeps that mapping in a single place.
    /// </remarks>
    public ErrorCode Code => ErrorCodes.Malformed;
}

/// <summary>
/// Reads DLWP/1 body values, with the strictness the protocol requires.
/// </summary>
/// <remarks>
/// <para>
/// This is a deliberately small cbOR reader: it implements only what DLWP/1
/// uses, and it rejects everything else rather than skipping over it. That
/// matters because cbOR is a wide format and a permissive reader accepts many
/// distinct byte sequences for the same logical message. Rejecting those is what
/// makes the vectors' bytes unique, which is what makes the two codecs provably
/// equivalent (ADR-0003, ADR-0007).
/// </para>
/// <para>
/// The rules enforced here come from the "encoding rules" block of
/// <c>protocol/vectors/framing-basic.json</c>: definite lengths only, shortest
/// form integers, valid UTF-8, no tags and no floats.
/// </para>
/// </remarks>
public ref struct CborReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _offset;

    /// <summary>Creates a reader over a body buffer.</summary>
    /// <param name="buffer">The body bytes.</param>
    public CborReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _offset = 0;
    }

    /// <summary>Whether every byte has been consumed.</summary>
    public readonly bool IsAtEnd => _offset >= _buffer.Length;

    /// <summary>The current read offset, for diagnostics.</summary>
    public readonly int Offset => _offset;

    /// <summary>Throws when the buffer is not fully consumed.</summary>
    /// <exception cref="CborException">Trailing bytes follow the top-level item.</exception>
    /// <remarks>
    /// Trailing bytes are an error, not padding. A body with slack would let two
    /// different byte sequences decode to the same message, which breaks the
    /// uniqueness the vectors depend on.
    /// </remarks>
    public readonly void RequireEnd()
    {
        if (!IsAtEnd)
        {
            throw new CborException(new CborError(
                CborErrorKind.SchemaViolation,
                $"{_buffer.Length - _offset} trailing byte(s) after the top-level item",
                _offset));
        }
    }

    /// <summary>Reads the initial byte and decodes the argument.</summary>
    /// <param name="major">The major type of the item.</param>
    /// <param name="argument">The decoded argument, or -1 for an indefinite length.</param>
    private void ReadHead(out CborMajorType major, out long argument)
    {
        if (IsAtEnd)
        {
            throw new CborException(new CborError(
                CborErrorKind.Truncated, "expected an item but the body ended", _offset));
        }

        int start = _offset;
        byte initial = _buffer[_offset];
        _offset += 1;

        major = (CborMajorType)(initial >> 5);
        int additional = initial & 0x1F;

        switch (additional)
        {
            case <= 23:
                argument = additional;
                return;

            case 24:
                argument = ReadByte(start, "1-byte argument");
                // Shortest-form rule: a value below 24 must use the inline form.
                if (argument < 24)
                {
                    throw NonShortest(start, argument, 1);
                }

                return;

            case 25:
                argument = ReadUInt16(start, "2-byte argument");
                if (argument <= byte.MaxValue)
                {
                    throw NonShortest(start, argument, 2);
                }

                return;

            case 26:
                argument = ReadUInt32(start, "4-byte argument");
                if (argument <= ushort.MaxValue)
                {
                    throw NonShortest(start, argument, 4);
                }

                return;

            case 27:
                {
                    ulong wide = ReadUInt64(start, "8-byte argument");
                    if (wide <= uint.MaxValue)
                    {
                        throw NonShortest(start, (long)wide, 8);
                    }

                    if (wide > long.MaxValue)
                    {
                        // DLWP/1 defines no integers above 2^63-1, so the top bit
                        // being set means the value cannot be represented at all.
                        throw new CborException(new CborError(
                            CborErrorKind.SchemaViolation,
                            $"integer {wide} exceeds the DLWP/1 range",
                            start));
                    }

                    argument = (long)wide;
                    return;
                }

            case 31:
                // Indefinite length. The vectors require ERR_MALFORMED because
                // there is no indefinite form of any DLWP/1 body.
                throw new CborException(new CborError(
                    CborErrorKind.IndefiniteLength,
                    "indefinite-length items are not permitted in DLWP/1",
                    start));

            default:
                throw new CborException(new CborError(
                    CborErrorKind.UnsupportedSimpleValue,
                    $"reserved additional information value {additional}",
                    start));
        }
    }

    private CborException NonShortest(int offset, long value, int width) =>
        new(new CborError(
            CborErrorKind.NonShortestInteger,
            $"integer {value} was encoded in {width} byte(s) but fits the shortest form",
            offset));

    private byte ReadByte(int start, string what)
    {
        Require(1, start, what);
        return _buffer[_offset++];
    }

    private ushort ReadUInt16(int start, string what)
    {
        Require(2, start, what);
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(_buffer[_offset..]);
        _offset += 2;
        return value;
    }

    private uint ReadUInt32(int start, string what)
    {
        Require(4, start, what);
        uint value = BinaryPrimitives.ReadUInt32BigEndian(_buffer[_offset..]);
        _offset += 4;
        return value;
    }

    private ulong ReadUInt64(int start, string what)
    {
        Require(8, start, what);
        ulong value = BinaryPrimitives.ReadUInt64BigEndian(_buffer[_offset..]);
        _offset += 8;
        return value;
    }

    private readonly void Require(int count, int start, string what)
    {
        if (_buffer.Length - _offset < count)
        {
            throw new CborException(new CborError(
                CborErrorKind.Truncated,
                $"expected {count} byte(s) for the {what}, only {_buffer.Length - _offset} remain",
                start));
        }
    }

    /// <summary>Peeks at the major type of the next item without consuming it.</summary>
    /// <returns>The major type, or <see langword="null"/> at end of input.</returns>
    public readonly CborMajorType? PeekMajorType()
    {
        if (IsAtEnd)
        {
            return null;
        }

        return (CborMajorType)(_buffer[_offset] >> 5);
    }

    /// <summary>Reads an unsigned integer, rejecting negative values.</summary>
    /// <returns>The value.</returns>
    /// <exception cref="CborException">The next item is not a non-negative integer.</exception>
    public ulong ReadUnsignedInteger()
    {
        ReadHead(out CborMajorType major, out long argument);
        if (major != CborMajorType.UnsignedInteger)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongValueType,
                $"expected an unsigned integer, found major type {major}",
                _offset));
        }

        return (ulong)argument;
    }

    /// <summary>Reads a byte string.</summary>
    /// <returns>The bytes.</returns>
    /// <exception cref="CborException">The next item is not a byte string.</exception>
    public ReadOnlySpan<byte> ReadByteString()
    {
        ReadHead(out CborMajorType major, out long length);
        if (major != CborMajorType.ByteString)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongValueType,
                $"expected a byte string, found major type {major}",
                _offset));
        }

        if (length > _buffer.Length - _offset)
        {
            throw new CborException(new CborError(
                CborErrorKind.LengthMismatch,
                $"byte string declares {length} bytes but only {_buffer.Length - _offset} remain",
                _offset));
        }

        ReadOnlySpan<byte> result = _buffer.Slice(_offset, (int)length);
        _offset += (int)length;
        return result;
    }

    /// <summary>Reads a byte string and requires an exact width.</summary>
    /// <param name="expectedLength">The required length in bytes.</param>
    /// <returns>The bytes.</returns>
    /// <exception cref="CborException">The width differs from <paramref name="expectedLength"/>.</exception>
    /// <remarks>
    /// Used for the fixed-width fields of RFC-0002 — nonces, public keys and
    /// digests — where a wrong length is a protocol error rather than a
    /// differently-sized value.
    /// </remarks>
    public ReadOnlySpan<byte> ReadFixedByteString(int expectedLength)
    {
        int start = _offset;
        ReadOnlySpan<byte> value = ReadByteString();
        if (value.Length != expectedLength)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongWidth,
                $"expected a {expectedLength}-byte string, got {value.Length}",
                start));
        }

        return value;
    }

    /// <summary>Reads a UTF-8 text string.</summary>
    /// <returns>The decoded string.</returns>
    /// <exception cref="CborException">The next item is not a text string, or its bytes are not valid UTF-8.</exception>
    public string ReadTextString()
    {
        int start = _offset;
        ReadHead(out CborMajorType major, out long length);
        if (major != CborMajorType.TextString)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongValueType,
                $"expected a text string, found major type {major}",
                start));
        }

        if (length > _buffer.Length - _offset)
        {
            throw new CborException(new CborError(
                CborErrorKind.LengthMismatch,
                $"text string declares {length} bytes but only {_buffer.Length - _offset} remain",
                start));
        }

        ReadOnlySpan<byte> bytes = _buffer.Slice(_offset, (int)length);
        _offset += (int)length;

        // A strict UTF-8 decode. The default Encoding.UTF8 replaces invalid
        // sequences with U+FFFD, which would silently accept corrupted input, so
        // a throwing decoder is used instead.
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new CborException(new CborError(
                CborErrorKind.InvalidUtf8,
                $"text string is not valid UTF-8: {ex.Message}",
                start));
        }
    }

    /// <summary>Reads an array header.</summary>
    /// <returns>The number of elements.</returns>
    /// <exception cref="CborException">The next item is not an array.</exception>
    public int ReadArrayHeader()
    {
        ReadHead(out CborMajorType major, out long length);
        if (major != CborMajorType.Array)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongValueType,
                $"expected an array, found major type {major}",
                _offset));
        }

        if (length > int.MaxValue)
        {
            throw new CborException(new CborError(
                CborErrorKind.LengthMismatch, $"array declares {length} elements", _offset));
        }

        return (int)length;
    }

    /// <summary>Reads a map header.</summary>
    /// <returns>The number of key/value pairs.</returns>
    /// <exception cref="CborException">The next item is not a map.</exception>
    public int ReadMapHeader()
    {
        ReadHead(out CborMajorType major, out long length);
        if (major != CborMajorType.Map)
        {
            throw new CborException(new CborError(
                CborErrorKind.WrongValueType,
                $"expected a map, found major type {major}",
                _offset));
        }

        if (length > int.MaxValue)
        {
            throw new CborException(new CborError(
                CborErrorKind.LengthMismatch, $"map declares {length} pairs", _offset));
        }

        return (int)length;
    }

    /// <summary>Skips one complete item, including nested collections.</summary>
    /// <remarks>
    /// Used for the RFC-0001 section 3.2 rule that unknown keys are ignored
    /// rather than rejected. Skipping is bounded by the buffer length and
    /// rejects indefinite lengths and tags, so a hostile body cannot make this
    /// loop forever.
    /// </remarks>
    /// <exception cref="CborException">The item is truncated or uses a forbidden encoding.</exception>
    public void SkipItem()
    {
        SkipItem(depth: 0);
    }

    private void SkipItem(int depth)
    {
        // A bound on nesting. The protocol's deepest real body is a few levels,
        // so this only ever trips on a hostile input designed to exhaust the stack.
        const int MaxDepth = 32;
        if (depth > MaxDepth)
        {
            throw new CborException(new CborError(
                CborErrorKind.SchemaViolation,
                $"cbOR nesting exceeded {MaxDepth} levels",
                _offset));
        }

        int start = _offset;
        ReadHead(out CborMajorType major, out long argument);

        switch (major)
        {
            case CborMajorType.UnsignedInteger:
            case CborMajorType.NegativeInteger:
                return;

            case CborMajorType.ByteString:
            case CborMajorType.TextString:
                if (argument > _buffer.Length - _offset)
                {
                    throw new CborException(new CborError(
                        CborErrorKind.LengthMismatch,
                        $"string declares {argument} bytes but only {_buffer.Length - _offset} remain",
                        start));
                }

                _offset += (int)argument;
                return;

            case CborMajorType.Array:
                for (long i = 0; i < argument; i++)
                {
                    SkipItem(depth + 1);
                }

                return;

            case CborMajorType.Map:
                for (long i = 0; i < argument * 2; i++)
                {
                    SkipItem(depth + 1);
                }

                return;

            case CborMajorType.Tag:
                throw new CborException(new CborError(
                    CborErrorKind.TagNotAllowed,
                    $"cbOR tag {argument} is not permitted in DLWP/1; tag 2 and tag 3 (bignum) in particular must be rejected",
                    start));

            case CborMajorType.SimpleOrFloat:
                throw new CborException(new CborError(
                    CborErrorKind.FloatNotAllowed,
                    $"cbOR simple/float value (additional {argument}) is not permitted in DLWP/1",
                    start));

            default:
                throw new CborException(new CborError(
                    CborErrorKind.SchemaViolation, $"unsupported major type {major}", start));
        }
    }
}
