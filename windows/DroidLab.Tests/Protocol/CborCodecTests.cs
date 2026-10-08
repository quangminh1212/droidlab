using DroidLab.Protocol;
using DroidLab.Protocol.Cbor;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for the DLWP/1 cbOR reader and writer.
/// </summary>
/// <remarks>
/// These are hand-written cases rather than file-driven ones, because cbOR is a
/// general encoding and the protocol-specific bodies are covered by the schema
/// tests. Each case is a rule from the "encoding rules" block of
/// <c>protocol/vectors/framing-basic.json</c>.
/// </remarks>
/// <remarks>
/// <see cref="CborReader"/> is deliberately a <c>ref struct</c>, so it cannot be
/// captured by a lambda. Every failure case here therefore calls the reader
/// through a local helper that returns the caught exception, instead of using
/// <c>Assert.Throws</c> with a closure.
/// </remarks>
public sealed class CborCodecTests
{
    /// <summary>Runs an action that must fail with a <see cref="CborException"/> and returns it.</summary>
    private static CborError CaptureError(Action action)
    {
        CborException ex = Assert.Throws<CborException>(action);
        return ex.Error;
    }

    // ---- Integer encoding -------------------------------------------------

    /// <summary>Shortest-form integers decode correctly across every width boundary.</summary>
    [Theory]
    [InlineData("00", 0UL)]
    [InlineData("17", 23UL)]
    [InlineData("1818", 24UL)]
    [InlineData("18ff", 255UL)]
    [InlineData("190100", 256UL)]
    [InlineData("19ffff", 65535UL)]
    [InlineData("1a00010000", 65536UL)]
    [InlineData("1affffffff", 4294967295UL)]
    [InlineData("1b0000000100000000", 4294967296UL)]
    [InlineData("1b7fffffffffffffff", 9223372036854775807UL)]
    public void ShortestFormIntegersDecode(string hex, ulong expected)
    {
        CborReader reader = new(Convert.FromHexString(hex));

        Assert.Equal(expected, reader.ReadUnsignedInteger());
        Assert.True(reader.IsAtEnd);
    }

    /// <summary>Writing an integer uses the shortest form, matching the reader's requirement.</summary>
    [Theory]
    [InlineData(0UL, "00")]
    [InlineData(23UL, "17")]
    [InlineData(24UL, "1818")]
    [InlineData(255UL, "18ff")]
    [InlineData(256UL, "190100")]
    [InlineData(65535UL, "19ffff")]
    [InlineData(65536UL, "1a00010000")]
    [InlineData(4294967295UL, "1affffffff")]
    [InlineData(4294967296UL, "1b0000000100000000")]
    public void IntegersEncodeInShortestForm(ulong value, string expectedHex)
    {
        CborWriter writer = new();
        writer.WriteUnsignedInteger(value);

        Assert.Equal(expectedHex, Convert.ToHexString(writer.ToArray()).ToLowerInvariant());
    }

    /// <summary>
    /// A non-shortest integer must be rejected: two encodings of one value would
    /// break the byte uniqueness the vectors rely on.
    /// </summary>
    [Theory]
    [InlineData("1800")]               // 0 encoded in one byte
    [InlineData("1817")]               // 23 encoded in one byte
    [InlineData("190018")]             // 24 encoded in two bytes
    [InlineData("1a00000100")]         // 256 encoded in four bytes
    [InlineData("1b0000000000000001")] // 1 encoded in eight bytes
    public void NonShortestIntegersAreRejected(string hex)
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString(hex));
            reader.ReadUnsignedInteger();
        });

        Assert.Equal(CborErrorKind.NonShortestInteger, error.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
    }

    /// <summary>A negative integer is not valid where an unsigned one is expected.</summary>
    [Fact]
    public void NegativeIntegerIsRejectedForUnsignedField()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0x20]); // major 1, value -1
            reader.ReadUnsignedInteger();
        });

        Assert.Equal(CborErrorKind.WrongValueType, error.Kind);
    }

    /// <summary>
    /// An integer wider than the DLWP/1 range is rejected rather than truncated.
    /// </summary>
    [Fact]
    public void IntegerAboveTheProtocolRangeIsRejected()
    {
        // 2^63, encoded canonically in eight bytes.
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString("1b8000000000000000"));
            reader.ReadUnsignedInteger();
        });

        Assert.Equal(CborErrorKind.SchemaViolation, error.Kind);
        Assert.Contains("range", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Definite length --------------------------------------------------

    /// <summary>An indefinite-length map is rejected, per the "map_encoding" rule.</summary>
    [Fact]
    public void IndefiniteLengthMapIsRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0xBF, 0xFF]); // major 5, additional 31
            reader.ReadMapHeader();
        });

        Assert.Equal(CborErrorKind.IndefiniteLength, error.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
    }

    /// <summary>An indefinite-length byte string is rejected.</summary>
    [Fact]
    public void IndefiniteLengthByteStringIsRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0x5F, 0xFF]);
            reader.ReadByteString();
        });

        Assert.Equal(CborErrorKind.IndefiniteLength, error.Kind);
    }

    /// <summary>An indefinite-length array is rejected.</summary>
    [Fact]
    public void IndefiniteLengthArrayIsRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0x9F, 0xFF]);
            reader.ReadArrayHeader();
        });

        Assert.Equal(CborErrorKind.IndefiniteLength, error.Kind);
    }

    /// <summary>An empty definite-length array is 0x80.</summary>
    [Fact]
    public void EmptyArrayIsEncodedAs0x80()
    {
        CborReader reader = new([0x80]);
        Assert.Equal(0, reader.ReadArrayHeader());

        CborWriter writer = new();
        writer.WriteArrayHeader(0);
        Assert.Equal("80", Convert.ToHexString(writer.ToArray()).ToLowerInvariant());
    }

    // ---- Tags and floats --------------------------------------------------

    /// <summary>Tags are rejected: the protocol uses none.</summary>
    [Theory]
    [InlineData("c2")] // tag 2, positive bignum
    [InlineData("c3")] // tag 3, negative bignum
    [InlineData("c0")] // tag 0, date/time string
    public void TagsAreRejected(string hex)
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString(hex));
            reader.SkipItem();
        });

        Assert.Equal(CborErrorKind.TagNotAllowed, error.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
    }

    /// <summary>Tag 2 specifically must be rejected, since it is the bignum loophole.</summary>
    [Fact]
    public void TagTwoBignumIsRejected()
    {
        // tag 2 wrapping a 9-byte positive bignum
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString("c249010000000000000000"));
            reader.SkipItem();
        });

        Assert.Equal(CborErrorKind.TagNotAllowed, error.Kind);
        Assert.Contains("bignum", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Half, single and double precision floats are all rejected.</summary>
    [Theory]
    [InlineData("f93c00")]             // half precision 1.0
    [InlineData("fa3f800000")]         // single precision 1.0
    [InlineData("fb3ff0000000000000")] // double precision 1.0
    public void FloatsAreRejected(string hex)
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString(hex));
            reader.SkipItem();
        });

        Assert.Equal(CborErrorKind.FloatNotAllowed, error.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
    }

    // ---- Strings ----------------------------------------------------------

    /// <summary>Definite-length text decodes, including multi-byte UTF-8.</summary>
    [Theory]
    [InlineData("60", "")]
    [InlineData("6161", "a")]
    [InlineData("6444524f49", "DROI")]
    [InlineData("6b44726f69644c6162207631", "DroidLab v1")]
    [InlineData("63e29883", "\u2603")] // 3-byte UTF-8 snowman
    public void TextStringsDecode(string hex, string expected)
    {
        CborReader reader = new(Convert.FromHexString(hex));

        Assert.Equal(expected, reader.ReadTextString());
        Assert.True(reader.IsAtEnd);
    }

    /// <summary>Invalid UTF-8 is rejected, not replaced with U+FFFD.</summary>
    [Fact]
    public void InvalidUtf8IsRejected()
    {
        CborError error = CaptureError(() =>
        {
            // 0x62 declares two bytes; 0xFF 0xFE is not valid UTF-8.
            CborReader reader = new([0x62, 0xFF, 0xFE]);
            reader.ReadTextString();
        });

        Assert.Equal(CborErrorKind.InvalidUtf8, error.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
    }

    /// <summary>A lone surrogate is rejected, since it has no UTF-8 encoding.</summary>
    [Fact]
    public void LoneSurrogateTextIsRejected()
    {
        CborWriter writer = new();

        Assert.Throws<ArgumentException>(() => writer.WriteTextString("\uD800"));
    }

    /// <summary>A byte string decodes to its exact bytes.</summary>
    [Fact]
    public void ByteStringsDecode()
    {
        CborReader reader = new(Convert.FromHexString("4401020304"));

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, reader.ReadByteString().ToArray());
    }

    /// <summary>A wrong fixed width is rejected.</summary>
    [Fact]
    public void WrongFixedWidthIsRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString("4401020304")); // 4 bytes
            reader.ReadFixedByteString(32);
        });

        Assert.Equal(CborErrorKind.WrongWidth, error.Kind);
    }

    /// <summary>A declared string length longer than the buffer is rejected.</summary>
    /// <remarks>
    /// 0x78 is major type 3 (text string) with additional information 24, so it
    /// is followed by a one-byte length. 0xFF declares 255 bytes and none follow.
    /// </remarks>
    [Fact]
    public void OversizedStringLengthIsRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0x78, 0xFF]);
            reader.ReadTextString();
        });

        Assert.Equal(CborErrorKind.LengthMismatch, error.Kind);
    }

    /// <summary>
    /// A byte string where a text string is expected is a type error, not a length error.
    /// </summary>
    /// <remarks>
    /// This case originally asserted the wrong failure kind, which is how the
    /// distinction between "wrong type" and "wrong length" got pinned down.
    /// </remarks>
    [Fact]
    public void ByteStringWhereTextIsExpectedIsATypeError()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new([0x58, 0xFF]); // major 2, one-byte length, none present
            reader.ReadTextString();
        });

        Assert.Equal(CborErrorKind.WrongValueType, error.Kind);
    }

    /// <summary>A text string round-trips through the writer and reader.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("screen.mirror")]
    [InlineData("ERR_MALFORMED")]
    [InlineData("\u2603 snowman")]
    public void TextStringsRoundTrip(string value)
    {
        CborWriter writer = new();
        writer.WriteTextString(value);
        byte[] encoded = writer.ToArray();

        CborReader reader = new(encoded);
        Assert.Equal(value, reader.ReadTextString());
        Assert.True(reader.IsAtEnd);
    }

    // ---- Structure --------------------------------------------------------

    /// <summary>A map header reports its pair count.</summary>
    [Fact]
    public void MapHeaderReportsPairCount()
    {
        CborReader reader = new([0xA4]); // map with 4 pairs

        Assert.Equal(4, reader.ReadMapHeader());
    }

    /// <summary>An empty map is 0xA0, which is how a no-parameter body is written.</summary>
    [Fact]
    public void EmptyMapIsEncodedAs0xA0()
    {
        CborReader reader = new([0xA0]);
        Assert.Equal(0, reader.ReadMapHeader());

        CborWriter writer = new();
        writer.WriteEmptyMap();
        Assert.Equal("a0", Convert.ToHexString(writer.ToArray()).ToLowerInvariant());
    }

    /// <summary>Trailing bytes after the top-level item are rejected.</summary>
    [Fact]
    public void TrailingBytesAreRejected()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(Convert.FromHexString("00ff"));
            reader.ReadUnsignedInteger();
            reader.RequireEnd();
        });

        Assert.Equal(CborErrorKind.SchemaViolation, error.Kind);
        Assert.Contains("trailing", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>An empty body is reported as at end immediately.</summary>
    [Fact]
    public void EmptyBodyIsAtEnd()
    {
        CborReader reader = new(ReadOnlySpan<byte>.Empty);

        Assert.True(reader.IsAtEnd);
        reader.RequireEnd();
    }

    /// <summary>Reading past the end is a truncation error.</summary>
    [Fact]
    public void ReadingPastTheEndIsTruncated()
    {
        CborError error = CaptureError(() =>
        {
            CborReader reader = new(ReadOnlySpan<byte>.Empty);
            reader.ReadUnsignedInteger();
        });

        Assert.Equal(CborErrorKind.Truncated, error.Kind);
    }

    /// <summary>Peeking reports the next major type without consuming it.</summary>
    [Fact]
    public void PeekReportsMajorTypeWithoutConsuming()
    {
        CborReader reader = new([0xA0]);

        Assert.Equal(CborMajorType.Map, reader.PeekMajorType());
        Assert.Equal(0, reader.Offset);
    }

    /// <summary>Peeking at the end of input reports nothing.</summary>
    [Fact]
    public void PeekAtEndReturnsNull()
    {
        CborReader reader = new(ReadOnlySpan<byte>.Empty);

        Assert.Null(reader.PeekMajorType());
    }

    // ---- Skip -------------------------------------------------------------

    /// <summary>Skipping an item advances past it, for the unknown-key rule.</summary>
    [Fact]
    public void SkipAdvancesPastAScalar()
    {
        CborReader reader = new(Convert.FromHexString("0018ff"));

        reader.SkipItem();
        Assert.Equal(1, reader.Offset);
        Assert.Equal(255UL, reader.ReadUnsignedInteger());
        Assert.True(reader.IsAtEnd);
    }

    /// <summary>Skipping a nested map consumes the whole subtree.</summary>
    /// <remarks>
    /// The bytes are <c>{"a": [1, {"b": 2}]}</c> followed by the integer 7:
    /// <c>a1</c> map(1), <c>61 61</c> text "a", <c>82</c> array(2), <c>01</c> 1,
    /// <c>a1</c> map(1), <c>61 62</c> text "b", <c>02</c> 2, then <c>07</c>.
    /// </remarks>
    [Fact]
    public void SkipConsumesNestedStructures()
    {
        CborReader reader = new(Convert.FromHexString("a161618201a1616202 07".Replace(" ", string.Empty)));

        reader.SkipItem();
        Assert.Equal(7UL, reader.ReadUnsignedInteger());
        Assert.True(reader.IsAtEnd);
    }

    /// <summary>Deep nesting is bounded so a hostile body cannot exhaust the stack.</summary>
    [Fact]
    public void DeeplyNestedItemsAreRejected()
    {
        CborError error = CaptureError(() =>
        {
            // 40 nested single-element arrays, then a scalar.
            byte[] bytes = new byte[41];
            for (int i = 0; i < 40; i++)
            {
                bytes[i] = 0x81; // array of 1
            }

            bytes[40] = 0x00;

            CborReader reader = new(bytes);
            reader.SkipItem();
        });

        Assert.Equal(CborErrorKind.SchemaViolation, error.Kind);
        Assert.Contains("nesting", error.Message, StringComparison.OrdinalIgnoreCase);
    }
}
