using System.Text;
using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Registry;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for malformed-frame classification (RFC-0001 sections 3, 6 and 10).
/// </summary>
/// <remarks>
/// Every case in the vector file is a deterministic, byte-level input, so both
/// implementations can be checked without a peer. A receiver that parses one of
/// these successfully, or that reports a different code or severity, is
/// non-conformant — which is why the assertions check the action, the code and
/// the recoverability, not just "the frame was refused".
/// </remarks>
public sealed class FrameClassifierTests
{
    private const string VectorFile = "malformed.json";

    /// <summary>The message type a first frame of a session must be.</summary>
    /// <remarks>
    /// Read from the registry rather than hardcoded, so a registry change that
    /// moved the handshake would fail here instead of silently making these tests
    /// assert yesterday's layout.
    /// </remarks>
    private static byte HelloMessageType =>
        Registry.FindMessageType("HELLO")!.Code;

    private static readonly Lazy<ProtocolRegistry> RegistryValue = new(() =>
    {
        using JsonDocument document = VectorLoader.LoadRegistry();
        return ProtocolRegistry.FromJson(document.RootElement);
    });

    private static ProtocolRegistry Registry => RegistryValue.Value;

    private static IEnumerable<JsonElement> Vectors() => VectorLoader.Vectors(VectorFile);

    private static IEnumerable<JsonElement> SequenceVectors() =>
        VectorLoader.Vectors(VectorFile, "sequence_vectors");

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static IEnumerable<JsonElement> RawFrameVectors() =>
        Vectors().Where(v => v.TryGetProperty("frame", out _));

    // ---- The raw-frame vectors --------------------------------------------

    /// <summary>Every raw-frame vector produces its declared error and severity.</summary>
    /// <remarks>
    /// The action is mapped from the vector's <c>expected</c> string, so a vector
    /// asking for <c>close_connection</c> and one asking for
    /// <c>error_frame_then_close</c> are distinguished. That difference matters:
    /// without a known frame boundary the receiver cannot answer without guessing
    /// where to put the next frame.
    /// </remarks>
    [Fact]
    public void EveryRawFrameVectorMatchesItsDeclaredOutcome()
    {
        int checked_ = 0;

        foreach (JsonElement vector in RawFrameVectors())
        {
            string id = vector.GetProperty("id").GetString()!;
            byte[] frame = Hex(vector.GetProperty("frame").GetString()!);

            // A vector that declares first_frame_message_type states that its
            // frame is arriving as the first frame of a session, and names the
            // type that frame carries. The expectation handed to the classifier
            // is the opposite: the type a first frame is required to BE, which is
            // HELLO. Passing the declared value straight through would ask the
            // classifier to expect the very violation the case describes, and the
            // rule would never fire.
            byte? expectedFirstType = null;
            if (vector.TryGetProperty("first_frame_message_type", out JsonElement first))
            {
                // The frame really does carry the type the vector names; without
                // this the case could pass for the wrong reason.
                Assert.Equal(first.GetByte(), frame[7]);
                expectedFirstType = HelloMessageType;
            }

            ReceiveVerdict verdict = FrameClassifier.Classify(
                frame,
                Registry,
                negotiatedCapabilities: [],
                expectedFirstMessageType: expectedFirstType);

            string expected = vector.GetProperty("expected").GetString()!;

            // The id is included so a failure names the vector rather than only
            // the assertion, which matters when 15 cases share one loop.
            string because = $"vector {id}";

            switch (expected)
            {
                case "close_connection":
                    Assert.Equal(ReceiveAction.CloseConnection, verdict.Action);
                    Assert.True(
                        string.Equals(vector.GetProperty("expected_error").GetString(), verdict.Error!.Name, StringComparison.Ordinal),
                        $"{because}: expected {vector.GetProperty("expected_error").GetString()} but got {verdict.Error!.Name}");
                    Assert.True(verdict.MustCloseWithoutAnswer, because);
                    break;

                case "error_frame_then_close":
                    Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
                    Assert.True(
                        string.Equals(vector.GetProperty("expected_error").GetString(), verdict.Error!.Name, StringComparison.Ordinal),
                        $"{because}: expected {vector.GetProperty("expected_error").GetString()} but got {verdict.Error!.Name} ({verdict.Reason})");
                    Assert.False(verdict.SessionSurvives, because);
                    break;

                case "error_session_continues":
                    Assert.Equal(ReceiveAction.ErrorSessionContinues, verdict.Action);
                    Assert.True(
                        string.Equals(vector.GetProperty("expected_error").GetString(), verdict.Error!.Name, StringComparison.Ordinal),
                        $"{because}: expected {vector.GetProperty("expected_error").GetString()} but got {verdict.Error!.Name}");
                    Assert.True(verdict.SessionSurvives, because);
                    break;

                case "accepted":
                    Assert.Equal(ReceiveAction.Accept, verdict.Action);
                    Assert.Null(verdict.Error);
                    Assert.True(verdict.SessionSurvives, because);
                    break;

                case "wait_then_error_on_close":
                    // A short read is an I/O condition, not a parse error.
                    Assert.Equal(ReceiveAction.WaitForMore, verdict.Action);
                    Assert.Null(verdict.Error);
                    break;

                default:
                    Assert.Fail($"{id}: unhandled expected action '{expected}'");
                    break;
            }

            // The declared severity must match the error's own severity, so a
            // vector cannot claim recoverable for a code the registry marks fatal.
            if (vector.TryGetProperty("expected_severity", out JsonElement severity)
                && severity.ValueKind == JsonValueKind.String
                && verdict.Error is { } error)
            {
                string want = severity.GetString()!;
                bool fatal = error.IsFatal;
                Assert.Equal(want == "fatal", fatal);
            }

            checked_++;
        }

        // A floor rather than an exact count: the point is that the loop cannot
        // pass by iterating over nothing if the vector file is emptied or its
        // shape changes.
        Assert.True(checked_ >= 14, $"expected at least 14 raw-frame vectors, checked {checked_}");
    }

    // ---- Bad magic ---------------------------------------------------------

    /// <summary>A bad magic closes the connection without answering.</summary>
    /// <remarks>
    /// The vector's key point: nothing may be parsed before the magic is checked.
    /// Without a known frame boundary the receiver cannot find the next frame, so
    /// it cannot answer meaningfully either.
    /// </remarks>
    [Fact]
    public void BadMagicClosesWithoutAnswering()
    {
        byte[] frame = Hex("444c58500100180500000000000000010000000000000003000000");

        // The vector's magic is "DLXP", one byte off.
        Assert.Equal("DLXP"u8.ToArray(), frame[..4].ToArray());

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.CloseConnection, verdict.Action);
        Assert.Equal(ErrorCodes.Malformed, verdict.Error);
        Assert.True(verdict.MustCloseWithoutAnswer);
    }

    /// <summary>Every wrong magic is caught, not only a near miss.</summary>
    [Theory]
    [InlineData("444c5850")] // DLXP, one byte off
    [InlineData("44575750")] // DWWP
    [InlineData("00000000")] // nothing
    [InlineData("646c7770")] // lowercase
    [InlineData("444c5750")] // the right magic, used as a control below
    public void AnyWrongMagicIsCaught(string magicHex)
    {
        byte[] frame = new byte[24];
        Hex(magicHex).CopyTo(frame, 0);
        frame[4] = 1;
        frame[5] = 1;
        frame[6] = 24;

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        if (magicHex == "444c5750")
        {
            // The control: with the real magic this frame gets past the magic
            // check, so the test is really about the magic and not about an
            // unrelated rejection.
            Assert.NotEqual(ReceiveAction.CloseConnection, verdict.Action);
        }
        else
        {
            Assert.Equal(ReceiveAction.CloseConnection, verdict.Action);
        }
    }

    // ---- Version -----------------------------------------------------------

    /// <summary>An unimplemented version is fatal and is not best-effort parsed.</summary>
    /// <remarks>
    /// A frame from another major version may not have this layout at all, so the
    /// receiver must not attempt a best-effort parse: the remaining fields could
    /// be a different width or mean something else.
    /// </remarks>
    [Fact]
    public void UnsupportedVersionIsFatal()
    {
        byte[] frame = Hex("444c57500200180500000000000000010000000000000003000000");

        Assert.Equal(2, frame[4]);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
        Assert.Equal(ErrorCodes.VersionMismatch, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);
    }

    // ---- Header length -----------------------------------------------------

    /// <summary>
    /// A header length other than 24 is rejected, and zero is malformed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two different errors for the same field, and the distinction is the
    /// vector's: a length of 25 asks for an extension version 1.0 does not define
    /// (<c>ERR_UNSUPPORTED_HEADER</c>), while a length of zero is shorter than the
    /// fixed prefix and cannot describe a header at all (<c>ERR_MALFORMED</c>).
    /// </para>
    /// <para>
    /// The case that matters is zero, and it is worth saying why the field is
    /// written rather than trusted: this vector's frame once carried 0x18 (24) at
    /// offset 6, the only value version 1.0 accepts, so it was byte-for-byte a
    /// frame that is fine and it tested nothing.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(25, "ERR_UNSUPPORTED_HEADER")]
    [InlineData(0, "ERR_MALFORMED")]
    [InlineData(23, "ERR_UNSUPPORTED_HEADER")]
    [InlineData(32, "ERR_UNSUPPORTED_HEADER")]
    [InlineData(255, "ERR_UNSUPPORTED_HEADER")]
    public void WrongHeaderLengthIsRejected(byte headerLength, string expectedError)
    {
        byte[] frame = new byte[24];
        "DLWP"u8.CopyTo(frame);
        frame[4] = 1;                 // version
        frame[5] = 1;                 // flags
        frame[6] = headerLength;

        // The field really holds what the case names. Without this the theory
        // would pass a frame whose length is 24 while claiming to test 0.
        Assert.Equal(headerLength, frame[6]);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
        Assert.Equal(expectedError, verdict.Error!.Name);
    }

    /// <summary>The vector's own zero-length frame is rejected as malformed.</summary>
    /// <remarks>
    /// Driven from the vector file rather than a constructed frame, so the bytes
    /// the file actually holds are the ones under test.
    /// </remarks>
    [Fact]
    public void TheZeroHeaderLengthVectorIsMalformed()
    {
        JsonElement vector = Vectors().Single(v => v.GetProperty("id").GetString() == "malformed.header-length-zero");
        byte[] frame = Hex(vector.GetProperty("frame").GetString()!);

        Assert.Equal(0, frame[6]);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
        Assert.Equal(vector.GetProperty("expected_error").GetString(), verdict.Error!.Name);
    }

    // ---- Frame size --------------------------------------------------------

    /// <summary>
    /// An oversized declared body is rejected from the header alone.
    /// </summary>
    /// <remarks>
    /// The frame is <b>24 bytes and nothing more</b>: there is no body to read
    /// and none to allocate. That is what makes this case prove the ordering, and
    /// it is why the vector was corrected to be header-only. 0xFFFFFFFF is the
    /// worst case an attacker can request, and a receiver that allocates before
    /// checking has turned one 24-byte frame into a four-gigabyte allocation.
    /// </remarks>
    [Fact]
    public void OversizedDeclaredBodyIsRejectedFromTheHeaderAlone()
    {
        byte[] frame = Hex("444c575001011832000000000000000100000000ffffffff");

        Assert.Equal(24, frame.Length);
        Assert.Equal(uint.MaxValue, FrameHeaderCodec.ReadUInt32BigEndian(frame, 20));

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
        Assert.Equal(ErrorCodes.FrameTooLarge, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);
    }

    /// <summary>An oversized body is rejected even when every other byte is valid.</summary>
    [Theory]
    [InlineData(16_777_217u)]
    [InlineData(uint.MaxValue)]
    public void BodiesOverTheLimitAreRejected(uint declaredLength)
    {
        byte[] frame = new byte[24];
        "DLWP"u8.CopyTo(frame);
        frame[4] = 1;
        frame[5] = 1;
        frame[6] = 24;
        frame[7] = 0x30;
        frame[20] = (byte)(declaredLength >> 24);
        frame[21] = (byte)(declaredLength >> 16);
        frame[22] = (byte)(declaredLength >> 8);
        frame[23] = (byte)declaredLength;

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ErrorCodes.FrameTooLarge, verdict.Error);
    }

    /// <summary>A body exactly at the limit is not rejected for size.</summary>
    [Fact]
    public void BodyAtTheLimitIsNotRejectedForSize()
    {
        byte[] frame = new byte[24];
        "DLWP"u8.CopyTo(frame);
        frame[4] = 1;
        frame[5] = 1;
        frame[6] = 24;
        frame[7] = 0x30;
        frame[20] = 0x01;
        frame[21] = 0x00;
        frame[22] = 0x00;
        frame[23] = 0x00;

        // 16_777_216 bytes declared but none supplied: the receiver waits rather
        // than reporting a size error.
        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.NotEqual(ErrorCodes.FrameTooLarge, verdict.Error);
        Assert.Equal(ReceiveAction.WaitForMore, verdict.Action);
    }

    // ---- Truncation --------------------------------------------------------

    /// <summary>A truncated frame waits rather than failing.</summary>
    /// <remarks>
    /// The vector's point is that a short read is an I/O condition: the rest of
    /// the frame may still arrive. Reporting a parse error here would drop a
    /// connection over ordinary packet loss, and the eventual error when the
    /// connection closes is <c>ERR_IO</c>, which is recoverable.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(23)]
    public void TruncatedHeaderWaitsForMore(int length)
    {
        ReceiveVerdict verdict = FrameClassifier.Classify(new byte[length], Registry, []);

        Assert.Equal(ReceiveAction.WaitForMore, verdict.Action);
        Assert.Null(verdict.Error);
    }

    /// <summary>A complete header with a partial body waits for more.</summary>
    /// <remarks>
    /// The vector declares 81 bytes of body and supplies 40: enough to know the
    /// frame is incomplete, not enough to know it is wrong.
    /// </remarks>
    [Fact]
    public void PartialBodyWaitsForMore()
    {
        byte[] frame = new byte[24 + 40];
        "DLWP"u8.CopyTo(frame);
        frame[4] = 1;
        frame[5] = 1;
        frame[6] = 24;
        frame[7] = 0x30;
        frame[23] = 81; // declared body length

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.WaitForMore, verdict.Action);
        Assert.Null(verdict.Error);

        // The vector says the eventual error is ERR_IO, which is recoverable:
        // a lost connection is not a broken peer.
        Assert.Equal("ERR_IO", ErrorCodes.Io.Name);
        Assert.False(ErrorCodes.Io.IsFatal);
    }

    // ---- Body well-formedness ---------------------------------------------

    /// <summary>A body that is not valid cbOR fails the frame.</summary>
    /// <remarks>
    /// The receiver must fail here rather than pass the bytes through, so a
    /// malformed body is one error in one place instead of a different failure in
    /// every per-message parser.
    /// </remarks>
    [Theory]
    [InlineData("ff", "not a valid initial byte")]
    [InlineData("bf616161626201ff", "indefinite-length map")]
    [InlineData("a161781805", "non-shortest integer")]
    [InlineData("a16178f97e00", "float encoding")]
    [InlineData("a16178c2410a", "tag")]
    [InlineData("a161ff", "invalid UTF-8")]
    public void MalformedBodyFailsTheFrame(string bodyHex, string description)
    {
        byte[] body = Hex(bodyHex);

        Assert.False(FrameClassifier.IsValidCbor(body, out string reason), description);
        Assert.NotEqual("valid", reason);

        // And the same through the full classifier, using an ungated message type
        // so the body check is what decides.
        byte[] frame = BuildFrame(body);
        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, negotiatedCapabilities: []);

        Assert.Equal(ErrorCodes.Malformed, verdict.Error);
    }

    /// <summary>A well-formed body passes.</summary>
    [Theory]
    [InlineData("a0")]
    [InlineData("a1616101")]
    [InlineData("a161618201a1616202")]
    [InlineData("80")]
    [InlineData("40")]
    public void WellFormedBodyPasses(string bodyHex)
    {
        Assert.True(FrameClassifier.IsValidCbor(Hex(bodyHex), out string reason), reason);
    }

    /// <summary>An empty body is the canonical encoding of a parameterless message.</summary>
    /// <remarks>
    /// RFC-0001 section 3.2: an empty body is encoded as zero bytes for the
    /// message types that define no parameters. Rejecting it would refuse the
    /// canonical encoding of every such message, and the vector file's accepted
    /// cases are exactly this — a HELLO or a PING with no bytes after the header.
    /// Whether a particular message type may be empty belongs to its schema, so
    /// this reports empty as acceptable and names the rule.
    /// </remarks>
    [Fact]
    public void EmptyBodyIsAcceptedAsCanonical()
    {
        Assert.True(FrameClassifier.IsValidCbor([], out string reason));
        Assert.Contains("3.2", reason, StringComparison.Ordinal);
    }

    /// <summary>Reserved flag bits are ignored, not rejected.</summary>
    /// <remarks>
    /// The bits can be assigned later without a version bump precisely because a
    /// receiver that does not know them ignores them. Rejecting them would make
    /// every future use of the field a breaking change. The vector sets all four
    /// reserved bits plus ENCRYPTED, which PING requires.
    /// </remarks>
    [Fact]
    public void ReservedFlagBitsAreIgnored()
    {
        byte[] frame = Hex("444c575001f1180500000000000000010000000000000000");

        Assert.Equal(1, frame[4]);
        Assert.Equal(0xF1, frame[5]);
        Assert.NotEqual(0, frame[5] & 0xF0);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.Accept, verdict.Action);
        Assert.Null(verdict.Error);
    }

    // ---- Message type and gating ------------------------------------------

    /// <summary>An unregistered message type is recoverable and the session survives.</summary>
    /// <remarks>
    /// So a newer peer cannot break an older one by sending a frame it has
    /// learned. This is the registry's reply rule, and it is why
    /// <c>ERR_UNSUPPORTED_MESSAGE</c> is not fatal.
    /// </remarks>
    [Fact]
    public void UnknownMessageTypeIsRecoverable()
    {
        byte[] frame = Hex("444c5750010018fe00000000000000050000000000000003000000");

        Assert.Equal(0xFE, frame[7]);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.ErrorSessionContinues, verdict.Action);
        Assert.Equal(ErrorCodes.UnsupportedMessage, verdict.Error);
        Assert.False(verdict.Error!.IsFatal);
        Assert.True(verdict.SessionSurvives);
    }

    /// <summary>A registered message outside the negotiated set is refused recoverably.</summary>
    [Fact]
    public void UngatedMessageIsRefusedRecoverably()
    {
        byte[] frame = BuildFrame(body: [0xA0], messageType: 80, encrypted: true);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, ["screen.mirror", "input.touch"]);

        Assert.Equal(ReceiveAction.ErrorSessionContinues, verdict.Action);
        Assert.Equal(ErrorCodes.UnsupportedFeature, verdict.Error);
        Assert.False(verdict.Error!.IsFatal);

        // With the capability negotiated it is accepted, which shows the gate is
        // the capability and not the message type.
        Assert.Equal(
            ReceiveAction.Accept,
            FrameClassifier.Classify(frame, Registry, ["shell.exec"]).Action);
    }

    /// <summary>
    /// A first frame that is not HELLO is fatal, and that is decided before the
    /// encryption rule.
    /// </summary>
    /// <remarks>
    /// The vector's frame is an <b>unencrypted</b> PING, so two rules could
    /// apply: PING must be encrypted, and the first frame must be HELLO. The
    /// vector requires <c>ERR_UNEXPECTED_MESSAGE</c>, which means the
    /// state-machine check runs first. That order is right: before a session
    /// exists there is no key material for any message to be encrypted with, so
    /// complaining that the frame is encrypted wrongly is meaningless compared to
    /// saying the frame should not be here.
    /// </remarks>
    [Fact]
    public void FirstFrameMustBeHello()
    {
        byte[] frame = Hex("444c57500100180500000000000000010000000000000003000000");

        // The frame really is an unencrypted PING: the ordering is under test,
        // not an artefact of the bytes.
        Assert.Equal(0x05, frame[7]);
        Assert.Equal(0, frame[5] & (byte)FrameFlags.Encrypted);

        ReceiveVerdict verdict = FrameClassifier.Classify(
            frame, Registry, [], expectedFirstMessageType: 0x01);

        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
        Assert.Equal(ErrorCodes.UnexpectedMessage, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);

        // Without the first-frame expectation the same bytes fail the encryption
        // rule instead, which shows the two checks are distinct.
        Assert.Equal(ErrorCodes.Unauthorized, FrameClassifier.Classify(frame, Registry, []).Error);
    }

    /// <summary>
    /// An unencrypted-looking HELLO is accepted, since HELLO is not encrypted.
    /// </summary>
    [Fact]
    public void HelloIsAcceptedWithoutTheEncryptedFlag()
    {
        byte[] frame = BuildFrame(body: [0xA0], messageType: 0x01, encrypted: false);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ReceiveAction.Accept, verdict.Action);
        Assert.Null(verdict.Error);
    }

    /// <summary>HELLO carrying the ENCRYPTED flag is rejected.</summary>
    /// <remarks>
    /// Its body would not be the plaintext the schema expects, so it cannot be
    /// decoded. Guessing at it would mean trying to decrypt with a key that does
    /// not exist yet.
    /// </remarks>
    [Fact]
    public void EncryptedHelloIsRejected()
    {
        byte[] frame = BuildFrame(body: [0xA0], messageType: 0x01, encrypted: true);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ErrorCodes.Malformed, verdict.Error);
        Assert.Equal(ReceiveAction.ErrorFrameThenClose, verdict.Action);
    }

    /// <summary>A message that must be encrypted is rejected without the flag.</summary>
    [Theory]
    [InlineData(0x03)] // AUTH
    [InlineData(0x10)] // GET_CAPABILITIES
    [InlineData(0x40)] // INPUT_TOUCH
    [InlineData(0xF0)] // ERROR
    public void UnencryptedWhereEncryptedIsRequiredIsRejected(byte messageType)
    {
        byte[] frame = BuildFrame(body: [0xA0], messageType: messageType, encrypted: false);

        ReceiveVerdict verdict = FrameClassifier.Classify(frame, Registry, []);

        Assert.Equal(ErrorCodes.Unauthorized, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);
    }

    // ---- Body schema -------------------------------------------------------

    /// <summary>A missing required key is fatal.</summary>
    /// <remarks>
    /// The message cannot be executed, and the receiver cannot resynchronise
    /// because it does not know what the frame meant. Continuing would leave both
    /// peers in different states, which is worse than either failing.
    /// </remarks>
    [Fact]
    public void MissingRequiredKeyIsFatal()
    {
        // {"action": "down"} with no "pointers" key.
        byte[] body = Hex("a166616374696f6e64646f776e");

        Assert.Equal(ErrorCodes.Malformed, FrameClassifier.ValidateRequiredKeys(body, ["action", "pointers"]));
        Assert.True(ErrorCodes.Malformed.IsFatal);

        Assert.Null(FrameClassifier.ValidateRequiredKeys(body, ["action"]));
    }

    /// <summary>
    /// An unknown extra key is ignored, which is the one accepted "malformed-looking" case.
    /// </summary>
    /// <remarks>
    /// This is the forward-compatibility rule, and it is the reason a newer peer
    /// can add a field without breaking an older one. Rejecting unknown keys would
    /// make every additive change a breaking change, which is why the same frame
    /// shape is malformed when a <i>required</i> key is missing and fine when an
    /// extra one is present.
    /// </remarks>
    [Fact]
    public void UnknownExtraKeysAreIgnored()
    {
        // {"action":"down", "pointers":[1], "unknown_message_level_key":12345}
        // A map of three pairs: the two required keys and one the receiver has
        // never heard of.
        byte[] body = Hex(
            "a366616374696f6e64646f776e68706f696e7465727381017819756e6b6e6f776e5f6d6573736167655f6c6576656c5f6b6579193039");

        Assert.Equal(3, body[0] - 0xa0);
        Assert.Null(FrameClassifier.ValidateRequiredKeys(body, ["action", "pointers"]));

        // The same body missing a required key is malformed, so the acceptance
        // really is about the unknown key and not about the frame shape.
        Assert.Equal(
            ErrorCodes.Malformed,
            FrameClassifier.ValidateRequiredKeys(body, ["action", "pointers", "absent_key"]));
    }

    /// <summary>An empty required-key list accepts an empty map.</summary>
    [Fact]
    public void EmptyRequiredKeysAcceptsAnEmptyMap()
    {
        Assert.Null(FrameClassifier.ValidateRequiredKeys(Hex("a0"), []));
        Assert.Null(FrameClassifier.ValidateRequiredKeys([], []));
    }

    /// <summary>A non-map body is malformed rather than ignored.</summary>
    [Theory]
    [InlineData("80")]  // array
    [InlineData("40")]  // byte string
    [InlineData("01")]  // integer
    public void NonMapBodyIsMalformed(string bodyHex)
    {
        Assert.Equal(ErrorCodes.Malformed, FrameClassifier.ValidateRequiredKeys(Hex(bodyHex), ["action"]));
    }

    /// <summary>A truncated body is malformed when validating keys.</summary>
    [Fact]
    public void TruncatedBodyIsMalformedForKeyValidation()
    {
        // A map header promising two pairs with nothing after it.
        Assert.Equal(ErrorCodes.Malformed, FrameClassifier.ValidateRequiredKeys(Hex("a2"), ["action"]));
    }

    // ---- Sequence numbers --------------------------------------------------

    /// <summary>Every sequence vector produces its declared outcome.</summary>
    [Fact]
    public void EverySequenceVectorMatchesItsDeclaredOutcome()
    {
        int checked_ = 0;

        foreach (JsonElement vector in SequenceVectors())
        {
            string id = vector.GetProperty("id").GetString()!;
            uint[] sequence = [.. vector.GetProperty("sequence").EnumerateArray().Select(e => e.GetUInt32())];

            // Replay the stream: an accepted frame advances the highest seen.
            // Nothing has been accepted before the first frame, which is why the
            // starting value is null rather than 0.
            uint? highest = null;
            ReceiveVerdict last = new(ReceiveAction.Accept, null, "start");

            bool stopped = false;
            foreach (uint number in sequence)
            {
                last = FrameClassifier.ClassifySequence(number, highest);

                if (last.Accepted)
                {
                    highest = highest is null ? number : Math.Max(highest.Value, number);
                }
                else
                {
                    // A fatal rejection ends the session, so the rest of the
                    // stream is never processed.
                    stopped = true;
                    break;
                }
            }

            if (vector.TryGetProperty("expected_error", out JsonElement expectedError))
            {
                Assert.True(stopped, $"{id}: expected a rejection but the whole stream was accepted");
                Assert.Equal(expectedError.GetString(), last.Error!.Name);

                if (vector.TryGetProperty("expected_severity", out JsonElement severity))
                {
                    Assert.Equal(severity.GetString() == "fatal", last.Error!.IsFatal);
                }
            }
            else
            {
                Assert.False(stopped, $"{id}: expected the whole stream to be accepted but it was rejected");
                Assert.True(last.Accepted);
            }

            checked_++;
        }

        Assert.True(checked_ >= 3, $"expected at least 3 sequence vectors, checked {checked_}");
    }

    /// <summary>A repeated sequence number is a fatal replay.</summary>
    /// <remarks>
    /// Fatal rather than recoverable: a peer that repeats a number is either
    /// broken or attacking, and in both cases the receiver cannot tell which of
    /// two frames with the same number was the real one.
    /// </remarks>
    [Fact]
    public void RepeatedSequenceNumberIsFatalReplay()
    {
        ReceiveVerdict verdict = FrameClassifier.ClassifySequence(3, 3);

        Assert.Equal(ErrorCodes.ReplayDetected, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);
        Assert.False(verdict.SessionSurvives);
    }

    /// <summary>A gap inside the window is legal reordering.</summary>
    /// <remarks>
    /// The vector's case is 1, 2, 3, 5, 4, 6: the 5 jumps ahead and the 4
    /// arrives late. That is normal on a lossy Wi-Fi link, so it must not be
    /// reported as a replay.
    /// </remarks>
    [Theory]
    [InlineData(5u, 3u)]   // ahead by two
    [InlineData(4u, 5u)]   // one behind the highest
    [InlineData(1u, 32u)]  // at the edge of the window
    public void ReorderingInsideTheWindowIsAccepted(uint sequence, uint highest)
    {
        ReceiveVerdict verdict = FrameClassifier.ClassifySequence(sequence, highest);

        Assert.True(verdict.Accepted, verdict.Reason);
        Assert.Null(verdict.Error);
    }

    /// <summary>A frame outside the window is treated as a replay and is fatal.</summary>
    /// <remarks>
    /// Accepting arbitrarily old frames would let an attacker replay one
    /// indefinitely, which is why the window exists at all rather than accepting
    /// everything out of order.
    /// </remarks>
    [Theory]
    [InlineData(3u, 40u)]   // far behind the highest
    [InlineData(1u, 100u)]
    [InlineData(0u, 32u)]   // exactly at the window boundary
    public void FramesOutsideTheWindowAreFatalReplays(uint sequence, uint highest)
    {
        ReceiveVerdict verdict = FrameClassifier.ClassifySequence(sequence, highest);

        Assert.Equal(ErrorCodes.ReplayDetected, verdict.Error);
        Assert.True(verdict.Error!.IsFatal);
    }

    /// <summary>The window boundary is exactly where the constant says.</summary>
    /// <remarks>
    /// Pinned in both directions so an off-by-one in the comparison shows up as a
    /// failure rather than as a slightly different tolerance between two
    /// implementations.
    /// </remarks>
    [Fact]
    public void TheWindowBoundaryIsExact()
    {
        uint window = FrameClassifier.ReorderWindow;

        Assert.True(FrameClassifier.ClassifySequence(100 - window + 1, 100).Accepted);
        Assert.False(FrameClassifier.ClassifySequence(100 - window, 100).Accepted);
    }

    /// <summary>The first frame of a session may be numbered zero.</summary>
    /// <remarks>
    /// <para>
    /// This states a contract the caller has to hold up: <c>highestSeen</c> is the
    /// highest sequence number <i>accepted</i>, and before anything has been
    /// accepted there is no such number. A caller that initialises it to 0 makes
    /// the session's own first frame look like a repeat of a frame it never saw.
    /// </para>
    /// <para>
    /// So the window is opened below the range, and the test pins both halves:
    /// with the window open, sequence 0 is accepted, and once 0 has been accepted
    /// a second 0 is a replay. The second half matters as much as the first,
    /// because it is what stops the fix from being "accept 0 always".
    /// </para>
    /// </remarks>
    [Fact]
    public void FirstFrameMayBeSequenceZero()
    {
        // Nothing has been accepted, so there is no highest number: modelled as
        // absence, not as 0 and not as uint.MaxValue, both of which collide with
        // a legal sequence number.
        Assert.True(FrameClassifier.ClassifySequence(0, null).Accepted);
        Assert.True(FrameClassifier.ClassifySequence(7, null).Accepted);

        // Having accepted 0, another 0 is a replay like any other repeat.
        Assert.Equal(ErrorCodes.ReplayDetected, FrameClassifier.ClassifySequence(0, 0).Error);
        Assert.True(FrameClassifier.ClassifySequence(1, 0).Accepted);
    }

    // ---- The severity contract --------------------------------------------

    /// <summary>The codes the vectors name exist and carry the right severity.</summary>
    /// <remarks>
    /// A receiver that reports a fatal fault as recoverable leaves both peers in
    /// different states, which is worse than either failing, so the severity of
    /// each code is asserted rather than assumed.
    /// </remarks>
    [Theory]
    [InlineData("ERR_MALFORMED", true)]
    [InlineData("ERR_VERSION_MISMATCH", true)]
    [InlineData("ERR_UNSUPPORTED_HEADER", true)]
    [InlineData("ERR_FRAME_TOO_LARGE", true)]
    [InlineData("ERR_UNEXPECTED_MESSAGE", true)]
    [InlineData("ERR_REPLAY_DETECTED", true)]
    [InlineData("ERR_UNSUPPORTED_MESSAGE", false)]
    [InlineData("ERR_UNSUPPORTED_FEATURE", false)]
    [InlineData("ERR_CHANNEL_UNKNOWN", false)]
    [InlineData("ERR_CHANNEL_LIMIT", false)]
    [InlineData("ERR_IO", false)]
    public void ErrorSeveritiesAreAsTheVectorsRequire(string name, bool fatal)
    {
        ErrorCode? code = ErrorCodes.Find(name);

        Assert.NotNull(code);
        Assert.Equal(fatal, code!.IsFatal);
    }

    /// <summary>Only HELLO and HELLO_ACK are unencrypted.</summary>
    /// <remarks>
    /// The single most security-relevant fact in the registry: every other
    /// message type must be inside the AEAD.
    /// </remarks>
    [Fact]
    public void OnlyHandshakeMessagesAreUnencrypted()
    {
        string[] inTheClear = [.. Registry.MessageTypes.Where(m => !m.Encrypted).Select(m => m.Name).Order()];

        Assert.Equal(["HELLO", "HELLO_ACK"], inTheClear);
    }

    // ---- Helpers -----------------------------------------------------------

    /// <summary>Builds a syntactically valid frame around a body.</summary>
    /// <remarks>
    /// The default message type is PING, which is ungated and encrypted, so a
    /// body test exercises the body check rather than tripping the capability
    /// gate or the encryption rule first.
    /// </remarks>
    private static byte[] BuildFrame(byte[] body, byte messageType = 0x05, bool encrypted = true)
    {
        byte[] frame = new byte[24 + body.Length];
        "DLWP"u8.CopyTo(frame);
        frame[4] = 1;
        frame[5] = encrypted ? (byte)FrameFlags.Encrypted : (byte)0;
        frame[6] = 24;
        frame[7] = messageType;
        frame[20] = (byte)(body.Length >> 24);
        frame[21] = (byte)(body.Length >> 16);
        frame[22] = (byte)(body.Length >> 8);
        frame[23] = (byte)body.Length;
        body.CopyTo(frame, 24);
        return frame;
    }
}
