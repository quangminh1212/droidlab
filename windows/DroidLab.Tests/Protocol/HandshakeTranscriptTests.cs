using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Conformance tests for the DLWP/1 handshake transcript (RFC-0002 section 5.1).
/// </summary>
/// <remarks>
/// The transcript is the most failure-prone part of the protocol, because a
/// mis-sized component produces a transcript that is self-consistent and agrees
/// with no peer. These tests therefore check three independent things: the
/// serialised bytes, the declared arithmetic, and the resulting digest. A codec
/// that gets all three right by accident is not plausible.
/// </remarks>
public sealed class HandshakeTranscriptTests
{
    private const string TranscriptVectors = "handshake-transcript.json";

    /// <summary>The label must be 16 bytes; the vectors once recorded 18.</summary>
    [Fact]
    public void LabelIsSixteenBytes()
    {
        Assert.Equal(16, HandshakeTranscript.LabelLength);
        Assert.Equal(16, System.Text.Encoding.ASCII.GetByteCount(HandshakeTranscript.Label));
        Assert.Equal("DLWP/1-handshake", HandshakeTranscript.Label);
    }

    /// <summary>The vector file is present, so the theories below are not vacuous.</summary>
    [Fact]
    public void VectorFileIsPresentAndNonEmpty()
    {
        Assert.NotEmpty(VectorLoader.Vectors(TranscriptVectors));
        Assert.NotEmpty(VectorLoader.Vectors(TranscriptVectors, "rejection_vectors"));
    }

    /// <summary>Ids of the accepted transcript vectors.</summary>
    public static TheoryData<string> VectorIds()
    {
        TheoryData<string> ids = [];
        foreach (JsonElement vector in VectorLoader.Vectors(TranscriptVectors))
        {
            ids.Add(vector.GetProperty("id").GetString()!);
        }

        return ids;
    }

    private static (JsonElement Inputs, JsonElement Expected) Load(string id)
    {
        JsonElement vector = VectorLoader.Vectors(TranscriptVectors)
            .Single(v => v.GetProperty("id").GetString() == id);

        return (vector.GetProperty("inputs"), vector.GetProperty("expected"));
    }

    private static HandshakeTranscript.Inputs Inputs(JsonElement inputs) => new(
        ClientId: inputs.GetProperty("client_id").GetString()!,
        AgentId: inputs.GetProperty("agent_id").GetString()!,
        ClientNonce: VectorBinary.FromBase64Url(inputs.GetProperty("client_nonce").GetString()!),
        AgentNonce: VectorBinary.FromBase64Url(inputs.GetProperty("agent_nonce").GetString()!),
        ClientPublicKey: VectorBinary.FromBase64Url(inputs.GetProperty("client_pub").GetString()!),
        AgentPublicKey: VectorBinary.FromBase64Url(inputs.GetProperty("agent_pub").GetString()!));

    /// <summary>The serialised transcript must equal the vector's recorded bytes.</summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void BuildsTheExactTranscriptBytes(string id)
    {
        (JsonElement inputsJson, JsonElement expected) = Load(id);

        byte[] actual = HandshakeTranscript.Build(Inputs(inputsJson));
        byte[] wanted = Convert.FromHexString(expected.GetProperty("transcript_bytes").GetString()!);

        Assert.Equal(Convert.ToHexString(wanted).ToLowerInvariant(),
                     Convert.ToHexString(actual).ToLowerInvariant());
    }

    /// <summary>The transcript length must match the vector's declared length.</summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void MatchesTheDeclaredLength(string id)
    {
        (JsonElement inputsJson, JsonElement expected) = Load(id);

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson);
        byte[] actual = HandshakeTranscript.Build(inputs);

        Assert.Equal(expected.GetProperty("transcript_length_bytes").GetInt32(), actual.Length);
        Assert.Equal(expected.GetProperty("transcript_length_bytes").GetInt32(),
                     HandshakeTranscript.LengthFor(inputs.ClientId, inputs.AgentId));
    }

    /// <summary>
    /// The hash must equal the vector's recorded digest.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void HashesToTheRecordedDigest(string id)
    {
        (JsonElement inputsJson, JsonElement expected) = Load(id);

        byte[] digest = HandshakeTranscript.Hash(Inputs(inputsJson));

        Assert.Equal(expected.GetProperty("transcript_sha256").GetString(),
                     Convert.ToHexString(digest).ToLowerInvariant());
    }

    /// <summary>
    /// Hashing the built bytes must agree with hashing from inputs.
    /// </summary>
    /// <remarks>
    /// The receiver hashes the bytes it built, not a re-encoding of the parsed
    /// fields. If those two paths ever diverged, a peer that serialised
    /// differently would still be accepted.
    /// </remarks>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void HashingBuiltBytesAgreesWithHashingInputs(string id)
    {
        (JsonElement inputsJson, JsonElement expected) = Load(id);

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson);
        byte[] built = HandshakeTranscript.Build(inputs);
        byte[] fromBytes = HandshakeTranscript.HashTranscript(built);

        Assert.Equal(expected.GetProperty("transcript_sha256").GetString(),
                     Convert.ToHexString(fromBytes).ToLowerInvariant());
        Assert.Equal(HandshakeTranscript.Hash(inputs), fromBytes);
    }

    /// <summary>The recorded identifier length prefixes must match the inputs.</summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void RecordsTheCorrectLengthPrefixes(string id)
    {
        (JsonElement inputsJson, JsonElement expected) = Load(id);

        string clientId = inputsJson.GetProperty("client_id").GetString()!;
        string agentId = inputsJson.GetProperty("agent_id").GetString()!;

        int clientBytes = System.Text.Encoding.UTF8.GetByteCount(clientId);
        int agentBytes = System.Text.Encoding.UTF8.GetByteCount(agentId);

        Assert.Equal(expected.GetProperty("client_id_length_prefix").GetString(),
                     clientBytes.ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(expected.GetProperty("agent_id_length_prefix").GetString(),
                     agentBytes.ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// The label occupies the first 16 bytes and is followed by a separator.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void TranscriptOpensWithTheLabelAndSeparator(string id)
    {
        (JsonElement inputsJson, _) = Load(id);

        byte[] transcript = HandshakeTranscript.Build(Inputs(inputsJson));

        Assert.Equal("DLWP/1-handshake"u8.ToArray(), transcript[..16].ToArray());
        Assert.Equal(0x00, transcript[16]);
    }

    /// <summary>
    /// The four fixed-width fields occupy the last 128 bytes in a fixed order.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorIds))]
    public void TranscriptEndsWithTheFourFixedWidthFields(string id)
    {
        (JsonElement inputsJson, _) = Load(id);

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson);
        byte[] transcript = HandshakeTranscript.Build(inputs);
        byte[] tail = transcript[^128..];

        Assert.Equal(inputs.ClientNonce, tail[..32]);
        Assert.Equal(inputs.AgentNonce, tail[32..64]);
        Assert.Equal(inputs.ClientPublicKey, tail[64..96]);
        Assert.Equal(inputs.AgentPublicKey, tail[96..128]);
    }

    /// <summary>
    /// The label length check: a wrong label length shifts every later field.
    /// </summary>
    /// <remarks>
    /// This is the regression guard for the bug the vectors originally carried.
    /// If the label were treated as 18 bytes, the separator would be read from
    /// the wrong offset and the length would be wrong by two.
    /// </remarks>
    [Fact]
    public void WrongLabelLengthWouldChangeTheTranscriptLength()
    {
        (JsonElement inputsJson, JsonElement expected) = Load("transcript.synthetic.basic");

        int actual = HandshakeTranscript.Build(Inputs(inputsJson)).Length;
        int declared = expected.GetProperty("transcript_length_bytes").GetInt32();

        Assert.Equal(223, declared);
        Assert.Equal(declared, actual);

        // If the label were mis-sized as 18 the total would be 225, which is what
        // the original vectors asserted for a different reason.
        Assert.NotEqual(225, actual);
    }

    // ---- Minimum length ---------------------------------------------------

    /// <summary>
    /// The shortest legal transcript is 153 bytes, not 121.
    /// </summary>
    /// <remarks>
    /// Both identifiers are one byte, so each contributes a 2-byte prefix plus
    /// one byte of payload: 16 + 1 + 3 + 1 + 3 + 1 + 128 = 153. An
    /// implementation that gets this wrong has mis-sized a separator or a prefix.
    /// </remarks>
    [Fact]
    public void MinimumLengthIsOneHundredFiftyThree()
    {
        (JsonElement inputsJson, JsonElement expected) = Load("transcript.minimum-length");

        int length = HandshakeTranscript.Build(Inputs(inputsJson)).Length;

        Assert.Equal(153, length);
        Assert.Equal(expected.GetProperty("transcript_length_bytes").GetInt32(), length);
    }

    // ---- Rejection vectors ------------------------------------------------

    /// <summary>
    /// Length prefixing must keep two different identifier splits byte-distinct.
    /// </summary>
    /// <remarks>
    /// Without the length prefixes, <c>client_id="c\x00a", agent_id=""</c> would
    /// serialise identically to <c>client_id="c", agent_id="a"</c>, letting an
    /// attacker steer two different handshakes onto one transcript. This test
    /// pins that the two differ.
    /// </remarks>
    [Fact]
    public void LengthPrefixingKeepsAmbiguousIdentifierSplitsDistinct()
    {
        JsonElement minimum = VectorLoader.Load(TranscriptVectors)
            .RootElement.GetProperty("vectors")
            .EnumerateArray()
            .Single(v => v.GetProperty("id").GetString() == "transcript.minimum-length");

        JsonElement rejection = VectorLoader.Vectors(TranscriptVectors, "rejection_vectors")
            .Single(v => v.GetProperty("id").GetString() == "transcript.reject.leading-separator-confusion");

        byte[] minimumBytes = HandshakeTranscript.Build(Inputs(minimum.GetProperty("inputs")));
        byte[] rejectionBytes = HandshakeTranscript.Build(Inputs(rejection.GetProperty("inputs")));

        Assert.NotEqual(
            Convert.ToHexString(minimumBytes),
            Convert.ToHexString(rejectionBytes));

        Assert.Equal(
            rejection.GetProperty("expected").GetProperty("transcript_length_bytes").GetInt32(),
            rejectionBytes.Length);
    }

    /// <summary>
    /// The two identically-shaped splits must not collide once length prefixes apply.
    /// </summary>
    /// <remarks>
    /// The vector's point is narrower than "concatenation is unsafe in general":
    /// it is that a plain <c>client_id + agent_id</c> join maps two different
    /// pairs onto one byte string, whereas the length-prefixed form keeps them
    /// apart. The test asserts both halves, because asserting only the prefixed
    /// half would not show that the prefix is what does the work.
    /// </remarks>
    [Fact]
    public void LengthPrefixingIsWhatSeparatesAmbiguousIdentifierSplits()
    {
        // Split one: client_id "c", agent_id "a".
        const string SplitOneClient = "c";
        const string SplitOneAgent = "a";

        // Split two: the same total payload, divided differently.
        const string SplitTwoClient = "ca";
        const string SplitTwoAgent = "";

        // A naive join of the two identifier strings cannot tell them apart.
        Assert.Equal(SplitOneClient + SplitOneAgent, SplitTwoClient + SplitTwoAgent);

        // The length-prefixed join can, because the prefix records where the
        // identifier ends instead of relying on the payload's own bytes.
        HandshakeTranscript.Inputs template = Inputs(VectorLoader.Vectors(TranscriptVectors)
            .Single(v => v.GetProperty("id").GetString() == "transcript.minimum-length")
            .GetProperty("inputs"));

        byte[] fromSplitOne = HandshakeTranscript.Build(
            template with { ClientId = SplitOneClient, AgentId = SplitOneAgent });
        byte[] fromSplitTwo = HandshakeTranscript.Build(
            template with { ClientId = SplitTwoClient, AgentId = SplitTwoAgent });

        Assert.NotEqual(Convert.ToHexString(fromSplitOne), Convert.ToHexString(fromSplitTwo));

        // Both splits happen to be the same total size, because "c"+"a" and
        // "ca"+"" carry two payload bytes between them either way. That is
        // exactly why the differing *prefix values*, and not the length, are
        // what disambiguate them.
        Assert.Equal(153, fromSplitOne.Length);
        Assert.Equal(153, fromSplitTwo.Length);

        Assert.Equal(0x00, fromSplitOne[17]);
        Assert.Equal(0x01, fromSplitOne[18]); // client_id is 1 byte
        Assert.Equal(0x00, fromSplitTwo[17]);
        Assert.Equal(0x02, fromSplitTwo[18]); // client_id is 2 bytes
    }

    // ---- Input validation -------------------------------------------------

    /// <summary>A short nonce is rejected rather than padded.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void ShortNonceIsRejected(int width)
    {
        (JsonElement inputsJson, _) = Load("transcript.synthetic.basic");

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson) with
        {
            ClientNonce = new byte[width],
        };

        Assert.Throws<ArgumentException>(() => HandshakeTranscript.Build(inputs));
    }

    /// <summary>A short public key is rejected rather than padded.</summary>
    [Fact]
    public void ShortPublicKeyIsRejected()
    {
        (JsonElement inputsJson, _) = Load("transcript.synthetic.basic");

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson) with
        {
            AgentPublicKey = new byte[16],
        };

        Assert.Throws<ArgumentException>(() => HandshakeTranscript.Build(inputs));
    }

    /// <summary>An identifier longer than a 2-byte prefix is rejected.</summary>
    [Fact]
    public void OverlongIdentifierIsRejected()
    {
        (JsonElement inputsJson, _) = Load("transcript.synthetic.basic");

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson) with
        {
            ClientId = new string('x', 65_536),
        };

        Assert.Throws<ArgumentException>(() => HandshakeTranscript.Build(inputs));
    }

    /// <summary>
    /// A non-ASCII identifier is measured in bytes, not characters.
    /// </summary>
    /// <remarks>
    /// A three-byte UTF-8 character makes the length prefix and the total length
    /// differ from the character count. Counting characters here would produce a
    /// transcript two bytes short per character.
    /// </remarks>
    [Fact]
    public void NonAsciiIdentifierIsMeasuredInBytes()
    {
        (JsonElement inputsJson, _) = Load("transcript.synthetic.basic");

        HandshakeTranscript.Inputs inputs = Inputs(inputsJson) with
        {
            ClientId = "\u2603", // 3 bytes in UTF-8, 1 char
            AgentId = "a",
        };

        byte[] transcript = HandshakeTranscript.Build(inputs);

        // 16 + 1 + 2 + 3 + 1 + 2 + 1 + 1 + 128 = 155
        Assert.Equal(155, transcript.Length);
        Assert.Equal(155, HandshakeTranscript.LengthFor(inputs.ClientId, inputs.AgentId));

        // The prefix must record 3, the byte count, not 1.
        Assert.Equal(0x00, transcript[17]);
        Assert.Equal(0x03, transcript[18]);
    }
}
