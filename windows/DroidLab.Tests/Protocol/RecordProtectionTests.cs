using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Crypto;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for DLWP/1 record protection (RFC-0002 section 5.2).
/// </summary>
/// <remarks>
/// These tests are adversarial by design. The AEAD is the only thing standing
/// between an attacker on the LAN and the session, so the cases here are the
/// ones an attacker would actually try: flipping a header byte, swapping a frame
/// between directions, replaying a frame at a different sequence number, and
/// truncating or extending the body.
/// </remarks>
public sealed class RecordProtectionTests
{
    private const string KeyVectors = "crypto-session-keys.json";

    private static readonly byte[] C2aKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] A2cKey = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] C2aIv = [0xA1, 0xB2, 0xC3, 0xD4];
    private static readonly byte[] A2cIv = [0xE5, 0xF6, 0x07, 0x18];

    private static FrameHeader Header(uint sequence = 1, uint bodyLength = 0, byte messageType = 0x30)
    {
        FrameHeaderBuilder builder = new FrameHeaderBuilder()
            .WithFlags((byte)FrameFlags.Encrypted)
            .WithMessageType(messageType)
            .WithSequenceNumber(sequence)
            .WithBodyLength(bodyLength);
        return builder.Build();
    }

    // ---- Nonce layout ----------------------------------------------------

    /// <summary>The nonce layout vector: prefix then big-endian sequence number.</summary>
    /// <remarks>
    /// The vector gives <c>a1b2c3d4</c> with sequence 418 and expects
    /// <c>a1b2c3d400000000000001a2</c>. Note that 418 is not a round number,
    /// which is what makes the big-endian encoding of the sequence visible.
    /// </remarks>
    [Fact]
    public void NonceLayoutMatchesTheVector()
    {
        JsonElement vector = VectorLoader.Vectors(KeyVectors, "aead_vectors")
            .Single(v => v.GetProperty("id").GetString() == "aead.nonce.layout");

        byte[] ivPrefix = Convert.FromHexString(vector.GetProperty("c2a_iv").GetString()!);
        ulong sequence = vector.GetProperty("sequence_number").GetUInt64();

        byte[] nonce = RecordProtection.BuildNonce(ivPrefix, sequence);

        Assert.Equal(vector.GetProperty("expected_nonce_hex").GetString(),
                     Convert.ToHexString(nonce).ToLowerInvariant());
        Assert.Equal(12, nonce.Length);
    }

    /// <summary>The sequence number occupies the last 8 bytes, big-endian.</summary>
    [Theory]
    [InlineData(0UL, "0000000000000000")]
    [InlineData(1UL, "0000000000000001")]
    [InlineData(255UL, "00000000000000ff")]
    [InlineData(256UL, "0000000000000100")]
    [InlineData(0x0102030405060708UL, "0102030405060708")]
    [InlineData(ulong.MaxValue, "ffffffffffffffff")]
    public void SequenceNumberIsEightByteBigEndian(ulong sequence, string expectedTail)
    {
        byte[] nonce = RecordProtection.BuildNonce(C2aIv, sequence);

        Assert.Equal(expectedTail, Convert.ToHexString(nonce[4..]).ToLowerInvariant());
    }

    /// <summary>The nonce must be unique for every sequence number, which is what prevents reuse.</summary>
    [Fact]
    public void EverySequenceNumberGivesADistinctNonce()
    {
        HashSet<string> seen = [];

        for (ulong sequence = 1; sequence <= 4096; sequence++)
        {
            Assert.True(
                seen.Add(Convert.ToHexString(RecordProtection.BuildNonce(C2aIv, sequence))),
                $"nonce for sequence {sequence} repeated");
        }
    }

    /// <summary>A wrong-width prefix is rejected.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    public void WrongPrefixWidthIsRejected(int width)
    {
        Assert.Throws<ArgumentException>(() => RecordProtection.BuildNonce(new byte[width], 1));
    }

    // ---- Associated data --------------------------------------------------

    /// <summary>
    /// The header is associated data with body_length replaced by the plaintext length.
    /// </summary>
    /// <remarks>
    /// The vector's <c>aad_bytes</c> is a 24-byte header whose bytes 20-23 are
    /// <c>00000000</c>: the plaintext length for a zero-length body. The frame's
    /// own body_length would have been the ciphertext length, 28. Getting this
    /// wrong makes every frame fail to authenticate, because the two sides would
    /// be hashing different strings.
    /// </remarks>
    [Fact]
    public void AssociatedDataUsesPlaintextLengthForTheBodyLengthField()
    {
        JsonElement vector = VectorLoader.Vectors(KeyVectors, "aead_vectors")
            .Single(v => v.GetProperty("id").GetString() == "aead.header-is-associated-data");

        byte[] expected = Convert.FromHexString(vector.GetProperty("aad_bytes").GetString()!);
        Assert.Equal(vector.GetProperty("aad_length").GetInt32(), expected.Length);

        // Reconstruct the header the vector describes and check our encoder
        // agrees byte for byte.
        FrameHeader header = FrameHeaderCodec.TryDecode(expected, out FrameHeader decoded, out _)
            ? decoded
            : throw new InvalidOperationException("the vector's aad_bytes is not a valid header");

        Assert.Equal((byte)0xF0, header.MessageType); // ERROR
        Assert.Equal(3u, header.ChannelId);
        Assert.Equal(914u, header.SequenceNumber);
        Assert.Equal(910u, header.Acknowledgment);

        // Its body_length field is the plaintext length, 0.
        Assert.Equal(0u, header.BodyLength);

        byte[] rebuilt = RecordProtection.BuildAssociatedData(header, plaintextLength: 0);
        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(rebuilt));
    }

    /// <summary>The associated data is exactly 24 bytes, the header width.</summary>
    [Fact]
    public void AssociatedDataIsTwentyFourBytes()
    {
        byte[] aad = RecordProtection.BuildAssociatedData(Header(), plaintextLength: 17);

        Assert.Equal(24, aad.Length);
        Assert.Equal(24, FrameHeader.FixedLength);
    }

    /// <summary>The body length field of the associated data is the plaintext length.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(4096)]
    public void AssociatedDataBodyLengthIsThePlaintextLength(int plaintextLength)
    {
        byte[] aad = RecordProtection.BuildAssociatedData(Header(), plaintextLength);

        Assert.Equal((uint)plaintextLength, FrameHeaderCodec.ReadUInt32BigEndian(aad, 20));
    }

    /// <summary>Every other header field is authenticated unchanged.</summary>
    [Fact]
    public void AssociatedDataCoversTheWholeHeader()
    {
        FrameHeader header = new FrameHeaderBuilder()
            .WithFlags((byte)FrameFlags.Encrypted)
            .WithMessageType(0x40)
            .WithChannelId(7)
            .WithSequenceNumber(99)
            .WithAcknowledgment(42)
            .WithBodyLength(1234)
            .Build();

        byte[] aad = RecordProtection.BuildAssociatedData(header, plaintextLength: 5);

        Assert.Equal("DLWP"u8.ToArray(), aad[..4].ToArray());
        Assert.Equal(1, aad[4]);
        Assert.Equal((byte)FrameFlags.Encrypted, aad[5]);
        Assert.Equal(24, aad[6]);
        Assert.Equal(0x40, aad[7]);
        Assert.Equal(7u, FrameHeaderCodec.ReadUInt32BigEndian(aad, 8));
        Assert.Equal(99u, FrameHeaderCodec.ReadUInt32BigEndian(aad, 12));
        Assert.Equal(42u, FrameHeaderCodec.ReadUInt32BigEndian(aad, 16));
        Assert.Equal(5u, FrameHeaderCodec.ReadUInt32BigEndian(aad, 20));
    }

    // ---- Seal and open round trip ----------------------------------------

    /// <summary>A sealed body opens back to the original plaintext.</summary>
    [Theory]
    [InlineData(1, "")]
    [InlineData(1, "a0")]
    [InlineData(1, "a1616182")]
    [InlineData(418, "a465636f64656d4552525f4d414c464f524d4544")]
    [InlineData(0xFFFFFF, "a0")]
    public void SealThenOpenRecoversThePlaintext(uint sequence, string plaintextHex)
    {
        byte[] plaintext = Convert.FromHexString(plaintextHex);
        FrameHeader header = Header(sequence, (uint)plaintext.Length);

        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        Assert.Equal(RecordProtection.Overhead + plaintext.Length, sealedBody.Length);

        bool ok = RecordProtection.TryOpen(C2aKey, header, sealedBody, out byte[] opened, out FrameError? error);

        Assert.True(ok);
        Assert.Null(error);
        Assert.Equal(plaintext, opened);
    }

    /// <summary>The sealed body is nonce || ciphertext || tag, with the nonce first.</summary>
    [Fact]
    public void SealedBodyCarriesTheNonceInline()
    {
        byte[] plaintext = [0x01, 0x02, 0x03];
        FrameHeader header = Header(sequence: 7, bodyLength: 3);

        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        byte[] expectedNonce = RecordProtection.BuildNonce(C2aIv, 7);
        Assert.Equal(expectedNonce, sealedBody[..12]);
        Assert.Equal(12 + 3 + 16, sealedBody.Length);
    }

    /// <summary>The same plaintext and sequence number produce identical ciphertext.</summary>
    /// <remarks>
    /// Deterministic encryption is safe here precisely because the nonce is
    /// derived rather than random: the same nonce is never reused under a given
    /// key for different plaintext, since the sequence number never repeats.
    /// </remarks>
    [Fact]
    public void SealingIsDeterministic()
    {
        byte[] plaintext = [0xAA, 0xBB];
        FrameHeader header = Header(sequence: 3, bodyLength: 2);

        Assert.Equal(
            RecordProtection.Seal(C2aKey, C2aIv, header, plaintext),
            RecordProtection.Seal(C2aKey, C2aIv, header, plaintext));
    }

    /// <summary>Different sequence numbers produce different ciphertext for the same plaintext.</summary>
    [Fact]
    public void DifferentSequenceNumbersGiveDifferentCiphertext()
    {
        byte[] plaintext = [0xAA, 0xBB];

        byte[] first = RecordProtection.Seal(C2aKey, C2aIv, Header(1, 2), plaintext);
        byte[] second = RecordProtection.Seal(C2aKey, C2aIv, Header(2, 2), plaintext);

        Assert.NotEqual(first, second);
    }

    /// <summary>An empty plaintext still produces a full nonce and tag.</summary>
    [Fact]
    public void EmptyPlaintextStillHasANonceAndTag()
    {
        FrameHeader header = Header(sequence: 1, bodyLength: 0);

        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, []);

        Assert.Equal(RecordProtection.Overhead, sealedBody.Length);

        Assert.True(RecordProtection.TryOpen(C2aKey, header, sealedBody, out byte[] opened, out _));
        Assert.Empty(opened);
    }

    // ---- Adversarial cases ------------------------------------------------

    /// <summary>Opening with the wrong direction key fails and reports why.</summary>
    /// <remarks>
    /// This is the reflection attack: a frame sealed controller-to-agent must not
    /// open under the agent-to-controller key. The error must be present and must
    /// urge closing the connection, because a reflected frame means either an
    /// attacker or a catastrophic implementation bug, and continuing the session
    /// is wrong in both cases.
    /// </remarks>
    [Fact]
    public void WrongDirectionKeyFailsToOpen()
    {
        byte[] plaintext = [0x01, 0x02];
        FrameHeader header = Header(sequence: 1, bodyLength: 2);

        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        bool ok = RecordProtection.TryOpen(A2cKey, header, sealedBody, out byte[] opened, out FrameError? error);

        Assert.False(ok);
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.Unauthorized, error!.Code);
        Assert.Empty(opened);
    }

    /// <summary>Opening with the wrong direction key reports an authorization failure.</summary>
    [Fact]
    public void WrongDirectionKeyReportsUnauthorized()
    {
        byte[] plaintext = [0x01, 0x02];
        FrameHeader header = Header(sequence: 1, bodyLength: 2);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        RecordProtection.TryOpen(A2cKey, header, sealedBody, out _, out FrameError? error);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.Unauthorized, error!.Code);
        Assert.True(error.ClosesConnection);
    }

    /// <summary>Altering any header field breaks authentication.</summary>
    /// <remarks>
    /// The header is associated data, so a tampered channel, message type,
    /// sequence number or acknowledgment must fail the tag check rather than be
    /// acted on. This is what stops an attacker turning a benign frame into a
    /// destructive one by editing its type.
    /// </remarks>
    [Fact]
    public void TamperedHeaderFieldBreaksAuthentication()
    {
        byte[] plaintext = [0x01, 0x02, 0x03];
        FrameHeader original = Header(sequence: 5, bodyLength: 3);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, original, plaintext);

        // A frame that claims a different message type, channel or sequence.
        FrameHeader[] forgeries =
        [
            original with { MessageType = 0x41 },
            original with { ChannelId = 9 },
            original with { SequenceNumber = 6 },
            original with { Acknowledgment = 77 },
            original with { Flags = (byte)(FrameFlags.Encrypted | FrameFlags.Urgent) },
        ];

        foreach (FrameHeader forgery in forgeries)
        {
            bool ok = RecordProtection.TryOpen(C2aKey, forgery, sealedBody, out byte[] opened, out FrameError? error);

            Assert.False(ok);
            Assert.NotNull(error);
            Assert.Equal(ErrorCodes.Unauthorized, error!.Code);
            Assert.Empty(opened);
        }
    }

    /// <summary>Flipping one bit of the ciphertext breaks authentication.</summary>
    [Theory]
    [InlineData(12)]  // first ciphertext byte
    [InlineData(13)]  // a middle ciphertext byte
    [InlineData(14)]  // last ciphertext byte
    [InlineData(15)]  // first tag byte
    [InlineData(30)]  // last tag byte
    [InlineData(0)]   // nonce byte
    public void FlippingAnyByteBreaksAuthentication(int index)
    {
        byte[] plaintext = [0x01, 0x02, 0x03];
        FrameHeader header = Header(sequence: 1, bodyLength: 3);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        sealedBody[index] ^= 0x01;

        bool ok = RecordProtection.TryOpen(C2aKey, header, sealedBody, out _, out FrameError? error);

        Assert.False(ok);
        Assert.NotNull(error);
    }

    /// <summary>Truncating the body is rejected before any decryption is attempted.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(11)]
    [InlineData(27)] // one byte short of nonce+tag
    public void TruncatedBodyIsRejected(int length)
    {
        byte[] sealedBody = new byte[length];
        FrameHeader header = Header(sequence: 1, bodyLength: 0);

        bool ok = RecordProtection.TryOpen(C2aKey, header, sealedBody, out _, out FrameError? error);

        Assert.False(ok);
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.Malformed, error!.Code);
    }

    /// <summary>A frame sealed for one sequence number does not open at another.</summary>
    /// <remarks>
    /// This is the replay case: an attacker who captures a frame cannot present
    /// it as frame 900 instead of frame 5, because the nonce is the sequence
    /// number and the header carries it too.
    /// </remarks>
    [Fact]
    public void FrameDoesNotOpenAtADifferentSequenceNumber()
    {
        byte[] plaintext = [0x01, 0x02];
        FrameHeader header = Header(sequence: 5, bodyLength: 2);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, plaintext);

        Assert.False(RecordProtection.TryOpen(C2aKey, Header(900, 2), sealedBody, out _, out _));
        Assert.False(RecordProtection.TryOpen(C2aKey, Header(4, 2), sealedBody, out _, out _));
        Assert.False(RecordProtection.TryOpen(C2aKey, Header(6, 2), sealedBody, out _, out _));
    }

    /// <summary>A wrong-width key is rejected rather than silently accepted.</summary>
    [Fact]
    public void WrongWidthKeyIsRejectedOnOpen()
    {
        FrameHeader header = Header(sequence: 1, bodyLength: 0);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, []);

        Assert.False(RecordProtection.TryOpen(new byte[16], header, sealedBody, out _, out FrameError? error));
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.Internal, error!.Code);
    }

    /// <summary>A wrong-width key is rejected on seal.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void WrongWidthKeyIsRejectedOnSeal(int width)
    {
        Assert.Throws<ArgumentException>(
            () => RecordProtection.Seal(new byte[width], C2aIv, Header(), []));
    }

    // ---- Nonce prefix checks ---------------------------------------------

    /// <summary>The prefix check accepts a matching prefix.</summary>
    [Fact]
    public void NoncePrefixCheckAcceptsAMatch()
    {
        FrameHeader header = Header(sequence: 1, bodyLength: 0);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, []);

        Assert.True(RecordProtection.VerifyNoncePrefix(C2aIv, sealedBody));
    }

    /// <summary>The prefix check rejects the other direction's prefix.</summary>
    /// <remarks>
    /// This is the cheap pre-check for a reflected frame, reported separately
    /// from a tag failure so the two are distinguishable in a log.
    /// </remarks>
    [Fact]
    public void NoncePrefixCheckRejectsTheOtherDirection()
    {
        FrameHeader header = Header(sequence: 1, bodyLength: 0);
        byte[] sealedBody = RecordProtection.Seal(C2aKey, C2aIv, header, []);

        Assert.False(RecordProtection.VerifyNoncePrefix(A2cIv, sealedBody));
    }

    /// <summary>The prefix check rejects a short body and a wrong-width prefix.</summary>
    [Fact]
    public void NoncePrefixCheckRejectsDegenerateInput()
    {
        Assert.False(RecordProtection.VerifyNoncePrefix(C2aIv, new byte[3]));
        Assert.False(RecordProtection.VerifyNoncePrefix(new byte[3], new byte[12]));
    }

    // ---- Integration with the frame header --------------------------------

    /// <summary>
    /// A sealed body's length is the plaintext length plus the fixed overhead.
    /// </summary>
    /// <remarks>
    /// RFC-0001's frame schema states the encrypted body length as
    /// <c>12 + plaintext_length + 16</c>. This test pins that the constant in the
    /// codec agrees with the constant in the schema.
    /// </remarks>
    [Theory]
    [InlineData(0, 28)]
    [InlineData(1, 29)]
    [InlineData(100, 128)]
    [InlineData(16777216, 16777244)]
    public void SealedLengthMatchesTheSchemaFormula(int plaintextLength, int expectedSealedLength)
    {
        Assert.Equal(expectedSealedLength, 12 + plaintextLength + 16);
        Assert.Equal(expectedSealedLength, RecordProtection.Overhead + plaintextLength);
    }
}
