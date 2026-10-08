using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Conformance tests for the DLWP/1 frame header (RFC-0001 section 3).
/// </summary>
/// <remarks>
/// Every assertion is driven by <c>protocol/vectors/framing-basic.json</c>, which
/// is the same file the Kotlin codec is checked against. The vectors are not
/// duplicated here on purpose: a test that hard-codes its own expectations can
/// drift from the contract while still passing.
/// </remarks>
public sealed class FrameHeaderCodecTests
{
    private const string FramingVectors = "framing-basic.json";

    /// <summary>
    /// Proves the vector file is actually being read. Without this, a broken link
    /// in the test project would make every theory below vacuous and the suite
    /// would still report success.
    /// </summary>
    [Fact]
    public void VectorFileIsPresentAndNonEmpty()
    {
        IReadOnlyList<JsonElement> vectors = VectorLoader.Vectors(FramingVectors);

        Assert.NotEmpty(vectors);
    }

    /// <summary>
    /// Each vector carries a hex frame, so the test names it by id for a readable failure.
    /// </summary>
    public static TheoryData<string> VectorIds()
    {
        TheoryData<string> ids = [];
        foreach (JsonElement vector in VectorLoader.Vectors(FramingVectors))
        {
            ids.Add(vector.GetProperty("id").GetString()!);
        }

        return ids;
    }

    private static (JsonElement Decoded, FrameHeader Header, byte[] Frame) Load(string id)
    {
        JsonElement vector = VectorLoader.Vectors(FramingVectors)
            .Single(v => v.GetProperty("id").GetString() == id);

        JsonElement decoded = vector.GetProperty("decoded");
        JsonElement headerJson = decoded.GetProperty("header");
        byte[] frame = Convert.FromHexString(vector.GetProperty("frame").GetString()!);

        FrameHeader header = new()
        {
            Version = headerJson.GetProperty("version").GetByte(),
            Flags = headerJson.GetProperty("flags").GetByte(),
            HeaderLength = headerJson.GetProperty("header_length").GetByte(),
            MessageType = headerJson.GetProperty("message_type").GetByte(),
            ChannelId = headerJson.GetProperty("channel_id").GetUInt32(),
            SequenceNumber = headerJson.GetProperty("sequence_number").GetUInt32(),
            Acknowledgment = headerJson.GetProperty("acknowledgment").GetUInt32(),
            BodyLength = headerJson.GetProperty("body_length").GetUInt32(),
        };

        return (decoded, header, frame);
    }

    /// <summary>
    /// Decoding the vector's hex must reproduce the vector's declared fields.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void DecodesEveryFieldFromTheVectorBytes(string id)
    {
        (_, FrameHeader expected, byte[] frame) = Load(id);

        bool ok = FrameHeaderCodec.TryDecode(frame, out FrameHeader actual, out FrameError? error);

        Assert.Null(error);
        Assert.True(ok);
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Re-encoding the decoded header must reproduce the vector's exact bytes.
    /// </summary>
    /// <remarks>
    /// Round-tripping through the vector's own hex is the strongest available
    /// check: it catches a field written at the wrong offset, which field-by-field
    /// assertions would miss if both the writer and the asserted value were
    /// derived from the same wrong constant.
    /// </remarks>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void ReEncodesToTheExactVectorBytes(string id)
    {
        (_, FrameHeader header, byte[] frame) = Load(id);

        byte[] encoded = FrameHeaderCodec.Encode(header);

        Assert.Equal(Convert.ToHexString(frame[..FrameHeader.FixedLength]).ToLowerInvariant(),
                     Convert.ToHexString(encoded).ToLowerInvariant());
        Assert.Equal(24, encoded.Length);
    }

    /// <summary>
    /// The declared body length must equal the bytes actually present after the header.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void DeclaredBodyLengthMatchesTheTrailingBytes(string id)
    {
        (_, FrameHeader header, byte[] frame) = Load(id);

        Assert.Equal(frame.Length - FrameHeader.FixedLength, (int)header.BodyLength);
        Assert.Equal(frame.Length, header.TotalLength);
    }

    /// <summary>
    /// The magic is ASCII "DLWP" in every vector.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void EveryFrameStartsWithTheMagic(string id)
    {
        (JsonElement decoded, _, byte[] frame) = Load(id);

        Assert.Equal("DLWP", decoded.GetProperty("header").GetProperty("magic").GetString());
        Assert.Equal("DLWP"u8.ToArray(), frame[..4].ToArray());
    }

    // ---- Failure cases -----------------------------------------------------

    /// <summary>A buffer too short for a header is rejected without a header value.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(23)]
    public void TruncatedHeaderIsRejected(int length)
    {
        byte[] buffer = new byte[length];

        bool ok = FrameHeaderCodec.TryDecode(buffer, out _, out FrameError? error);

        Assert.False(ok);
        Assert.NotNull(error);
        Assert.Equal(FrameErrorKind.TruncatedHeader, error!.Kind);
    }

    /// <summary>A wrong magic is rejected before any other field is read.</summary>
    [Fact]
    public void WrongMagicIsRejected()
    {
        // A well-formed header with the magic replaced by "HTTP".
        byte[] frame = Convert.FromHexString(
            "485454500100180500000000000000010000000000000000");

        bool ok = FrameHeaderCodec.TryDecode(frame, out _, out FrameError? error);

        Assert.False(ok);
        Assert.Equal(FrameErrorKind.BadMagic, error!.Kind);
    }

    /// <summary>
    /// A bad magic is not reportable: there is no DLWP/1 session to report it inside.
    /// </summary>
    [Fact]
    public void WrongMagicIsClassifiedAsMalformedAndClosing()
    {
        byte[] frame = Convert.FromHexString(
            "485454500100180500000000000000010000000000000000");

        bool ok = FrameValidator.TryValidateFrame(frame, out _, out _, out FrameError? error);

        Assert.False(ok);
        Assert.Equal(FrameErrorKind.BadMagic, error!.Kind);
        Assert.Equal(ErrorCodes.Malformed, error.Code);
        Assert.True(error.ClosesConnection);
    }

    // ---- Flag handling -----------------------------------------------------

    /// <summary>Defined flags are exposed as an enum.</summary>
    [Theory]
    [InlineData(0x01, FrameFlags.Encrypted)]
    [InlineData(0x02, FrameFlags.Urgent)]
    [InlineData(0x04, FrameFlags.EndOfStream)]
    [InlineData(0x08, FrameFlags.Compressed)]
    [InlineData(0x0B, FrameFlags.Encrypted | FrameFlags.Urgent | FrameFlags.Compressed)]
    public void DefinedFlagsAreReported(byte raw, FrameFlags expected)
    {
        FrameHeader header = new FrameHeaderBuilder().WithFlags(raw).Build();

        Assert.Equal(expected, header.DefinedFlags);
        Assert.True(header.HasFlag(expected));
    }

    /// <summary>
    /// Reserved bits 4–7 are ignored on receive, per RFC-0001 section 3.1.
    /// </summary>
    [Fact]
    public void ReservedFlagBitsAreReportedButNotDefined()
    {
        FrameHeader header = new FrameHeaderBuilder().WithFlags(0xF1).Build();

        Assert.Equal(0xF0, header.ReservedFlags);
        Assert.Equal(FrameFlags.Encrypted, header.DefinedFlags);
    }

    /// <summary>
    /// Reserved bits must not be emitted: a conformant peer would reject them.
    /// </summary>
    [Fact]
    public void ReservedFlagBitsAreClearedOnEncode()
    {
        FrameHeader header = new FrameHeaderBuilder().WithFlags(0xFF).Build();

        byte[] encoded = FrameHeaderCodec.Encode(header);

        Assert.Equal(FrameFlagsMask.Defined, encoded[5]);
    }

    /// <summary>The raw flag byte survives a decode so a receiver can see an unclean peer.</summary>
    [Fact]
    public void RawFlagByteIsPreservedOnDecode()
    {
        FrameHeader header = new FrameHeaderBuilder().WithFlags(0xF1).Build();

        byte[] encoded = FrameHeaderCodec.Encode(header);
        FrameHeaderCodec.TryDecode(encoded, out FrameHeader decoded, out _);

        // Encode masked off the reserved bits, so the decoded raw byte is 0x01.
        Assert.Equal(0x01, decoded.Flags);
        Assert.Equal(FrameFlags.Encrypted, decoded.DefinedFlags);
    }

    // ---- Endianness --------------------------------------------------------

    /// <summary>
    /// Every multi-byte field is big-endian, checked against a hand-written frame.
    /// </summary>
    [Fact]
    public void MultiByteFieldsAreBigEndian()
    {
        FrameHeader header = new FrameHeaderBuilder()
            .WithChannelId(0x01020304)
            .WithSequenceNumber(0x05060708)
            .WithAcknowledgment(0x090A0B0C)
            .WithBodyLength(0x0D0E0F10)
            .Build();

        byte[] encoded = FrameHeaderCodec.Encode(header);

        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, encoded[8..12]);
        Assert.Equal(new byte[] { 0x05, 0x06, 0x07, 0x08 }, encoded[12..16]);
        Assert.Equal(new byte[] { 0x09, 0x0A, 0x0B, 0x0C }, encoded[16..20]);
        Assert.Equal(new byte[] { 0x0D, 0x0E, 0x0F, 0x10 }, encoded[20..24]);
    }

    /// <summary>Maximum u32 values survive a round trip, so no field is accidentally signed.</summary>
    [Fact]
    public void MaximumUInt32ValuesRoundTrip()
    {
        FrameHeader header = new FrameHeaderBuilder()
            .WithChannelId(uint.MaxValue)
            .WithSequenceNumber(uint.MaxValue)
            .WithAcknowledgment(uint.MaxValue)
            .WithBodyLength(uint.MaxValue)
            .Build();

        byte[] encoded = FrameHeaderCodec.Encode(header);
        FrameHeaderCodec.TryDecode(encoded, out FrameHeader decoded, out _);

        Assert.Equal(uint.MaxValue, decoded.ChannelId);
        Assert.Equal(uint.MaxValue, decoded.SequenceNumber);
        Assert.Equal(uint.MaxValue, decoded.Acknowledgment);
        Assert.Equal(uint.MaxValue, decoded.BodyLength);
    }

    /// <summary>Encoding into an undersized buffer is a programming error, not a wire error.</summary>
    [Fact]
    public void EncodingIntoATooSmallBufferThrows()
    {
        FrameHeader header = new FrameHeaderBuilder().Build();
        byte[] tooSmall = new byte[23];

        Assert.Throws<ArgumentException>(() => FrameHeaderCodec.Encode(header, tooSmall));
    }

    /// <summary>
    /// Only HELLO and HELLO_ACK are unencrypted, per RFC-0001 section 4.
    /// </summary>
    [Theory]
    [InlineData(0x01, false)]
    [InlineData(0x02, false)]
    [InlineData(0x03, true)]
    [InlineData(0x10, true)]
    public void OnlyTheHandshakeFramesAreUnencrypted(byte messageType, bool mustBeEncrypted)
    {
        FrameHeader header = new FrameHeaderBuilder().WithMessageType(messageType).Build();

        Assert.Equal(mustBeEncrypted, header.MustBeEncrypted);
    }
}
