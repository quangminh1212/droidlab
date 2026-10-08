using System.Security.Cryptography;
using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Crypto;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for the pairing and AUTH proofs of RFC-0002 sections 4 and 5, and for
/// the rejection rules the vectors name.
/// </summary>
/// <remarks>
/// The proofs are checked for the properties that make them safe to rely on, not
/// merely for producing 32 bytes: that the two directions cannot be confused,
/// that a proof is bound to the transcript it was made over, and that comparison
/// does not leak.
/// </remarks>
public sealed class PairingProofsTests
{
    private const string VectorFile = "crypto-primitives.json";

    private static JsonDocument Vectors() => VectorLoader.Load(VectorFile);

    /// <summary>Derives key material from a seed, the way the vectors do.</summary>
    /// <param name="seed">The seed string.</param>
    /// <returns>The 32 bytes.</returns>
    private static byte[] Key(string seed) => SessionKeySchedule.DeriveTestKeyBytes(seed);

    private static byte[] Nonce(string seed) => Key(seed);

    private static IEnumerable<JsonElement> RejectionVectors()
    {
        using JsonDocument document = Vectors();
        return [.. document.RootElement.GetProperty("rejection_vectors").EnumerateArray().Select(e => e.Clone())];
    }

    private static JsonElement Vector(string property)
    {
        using JsonDocument document = Vectors();
        return document.RootElement.GetProperty(property).Clone();
    }

    // ---- The seed rule ------------------------------------------------------

    /// <summary>
    /// The seed rule matches the vector file's formula exactly.
    /// </summary>
    /// <remarks>
    /// Every key in the vector files is derived rather than written, so that the
    /// files stay auditable and free of copy-paste errors. That only works if both
    /// implementations read the formula the same way, so the exact input bytes are
    /// pinned here rather than assumed.
    /// </remarks>
    [Fact]
    public void SeedRuleMatchesTheVectorFormula()
    {
        using JsonDocument document = Vectors();
        JsonElement rule = document.RootElement.GetProperty("seed_rule");

        Assert.Equal("key(seed) = SHA-256(\"DLWP/1-test-key\" || 0x00 || seed)", rule.GetProperty("formula").GetString());

        // Recomputed independently from the formula text rather than through the
        // helper, so the helper cannot be wrong in the same way as the test.
        byte[] expected = SHA256.HashData(
            [.. "DLWP/1-test-key"u8.ToArray(), 0x00, .. "droidlab-test-seed-01"u8.ToArray()]);

        Assert.Equal(expected, Key("droidlab-test-seed-01"));
    }

    /// <summary>The seed rule separates the label from the seed with a zero byte.</summary>
    /// <remarks>
    /// Without the separator, "DLWP/1-test-key" + "a" and "DLWP/1-test-ke" + "ya"
    /// would collide. The separator is what makes the label a label rather than a
    /// prefix.
    /// </remarks>
    [Fact]
    public void SeedRuleSeparatesLabelFromSeed()
    {
        Assert.NotEqual(Key("a"), Key("aa"));
        Assert.NotEqual(Key("1"), Key("01"));

        // A seed that would collide without the separator.
        byte[] withSeparator = Key("ya");
        byte[] withoutSeparator = SHA256.HashData("DLWP/1-test-keyya"u8.ToArray());
        Assert.NotEqual(withoutSeparator, withSeparator);
    }

    /// <summary>The seed rule is deterministic and 32 bytes wide.</summary>
    [Fact]
    public void SeedRuleIsDeterministic()
    {
        Assert.Equal(Key("seed"), Key("seed"));
        Assert.Equal(32, Key("seed").Length);
        Assert.NotEqual(Key("seed-1"), Key("seed-2"));
    }

    // ---- The pairing proofs -------------------------------------------------

    /// <summary>The agent proof covers the agent nonce first.</summary>
    /// <remarks>
    /// The order is checked by building the same HMAC by hand with the two orders
    /// and asserting only one matches. The order swap between the two proofs is
    /// what stops a peer reflecting one back as the other, so it is worth pinning
    /// rather than trusting.
    /// </remarks>
    [Fact]
    public void AgentProofCoversAgentNonceFirst()
    {
        byte[] secret = Key("pairing-secret");
        byte[] ctrl = Nonce("ctrl-nonce");
        byte[] agent = Nonce("agent-nonce");

        byte[] expected = HMACSHA256.HashData(secret, Labels.Concatenate(Labels.PairingAgentProof, agent, ctrl));
        Assert.Equal(expected, PairingProofs.AgentProof(secret, ctrl, agent));

        // The opposite order is a different value, which is the property that
        // matters.
        byte[] reversed = HMACSHA256.HashData(secret, Labels.Concatenate(Labels.PairingAgentProof, ctrl, agent));
        Assert.NotEqual(reversed, expected);
    }

    /// <summary>The controller proof covers the controller nonce first.</summary>
    [Fact]
    public void ControllerProofCoversControllerNonceFirst()
    {
        byte[] secret = Key("pairing-secret");
        byte[] ctrl = Nonce("ctrl-nonce");
        byte[] agent = Nonce("agent-nonce");

        byte[] expected = HMACSHA256.HashData(secret, Labels.Concatenate(Labels.PairingControllerProof, ctrl, agent));
        Assert.Equal(expected, PairingProofs.ControllerProof(secret, ctrl, agent));
    }

    /// <summary>
    /// The two proofs differ for the same nonces, so neither can be reflected.
    /// </summary>
    /// <remarks>
    /// This is the property the label and the order swap exist to provide. If the
    /// two came out equal, a peer could answer with the proof it received and be
    /// accepted as both sides.
    /// </remarks>
    [Fact]
    public void TheTwoProofsAreNeverInterchangeable()
    {
        byte[] secret = Key("pairing-secret");
        byte[] ctrl = Nonce("ctrl-nonce");
        byte[] agent = Nonce("agent-nonce");

        byte[] agentProof = PairingProofs.AgentProof(secret, ctrl, agent);
        byte[] controllerProof = PairingProofs.ControllerProof(secret, ctrl, agent);

        Assert.NotEqual(agentProof, controllerProof);

        // And verifying each against the other fails, which is the check a peer
        // actually performs.
        Assert.False(PairingProofs.Verify(agentProof, controllerProof));
        Assert.False(PairingProofs.Verify(controllerProof, agentProof));
    }

    /// <summary>Exchanging the nonces changes both proofs.</summary>
    [Fact]
    public void SwappingTheNoncesChangesBothProofs()
    {
        byte[] secret = Key("pairing-secret");
        byte[] ctrl = Nonce("ctrl-nonce");
        byte[] agent = Nonce("agent-nonce");

        Assert.NotEqual(
            PairingProofs.AgentProof(secret, ctrl, agent),
            PairingProofs.AgentProof(secret, agent, ctrl));

        Assert.NotEqual(
            PairingProofs.ControllerProof(secret, ctrl, agent),
            PairingProofs.ControllerProof(secret, agent, ctrl));
    }

    /// <summary>The confirmation commits to both proofs.</summary>
    /// <remarks>
    /// Covering the proofs rather than the nonces means a confirmation fails when
    /// each side received something other than what the other sent, which is
    /// exactly the situation a man in the middle creates.
    /// </remarks>
    [Fact]
    public void ConfirmationCommitsToBothProofs()
    {
        byte[] secret = Key("pairing-secret");
        byte[] agentProof = Key("agent-proof");
        byte[] controllerProof = Key("controller-proof");

        byte[] expected = HMACSHA256.HashData(
            secret,
            Labels.Concatenate(Labels.PairingConfirmation, agentProof, controllerProof));

        Assert.Equal(expected, PairingProofs.Confirmation(secret, agentProof, controllerProof));

        // Changing either proof changes the confirmation, and swapping them does
        // too, so a peer cannot send them in either order and be accepted.
        Assert.NotEqual(
            PairingProofs.Confirmation(secret, agentProof, controllerProof),
            PairingProofs.Confirmation(secret, controllerProof, agentProof));
    }

    /// <summary>A different pairing secret yields a different proof set.</summary>
    /// <remarks>
    /// The pairing secret is the only secret in these proofs. If the proofs did
    /// not depend on it, anyone who saw a handshake could reproduce them.
    /// </remarks>
    [Fact]
    public void ProofsDependOnThePairingSecret()
    {
        byte[] ctrl = Nonce("ctrl-nonce");
        byte[] agent = Nonce("agent-nonce");

        byte[] one = PairingProofs.AgentProof(Key("secret-a"), ctrl, agent);
        byte[] two = PairingProofs.AgentProof(Key("secret-b"), ctrl, agent);

        Assert.NotEqual(one, two);
    }

    // ---- The AUTH proofs ----------------------------------------------------

    /// <summary>The AUTH proofs are bound to the transcript hash.</summary>
    /// <remarks>
    /// Binding to the transcript rather than to the keys alone means a proof
    /// captured from one handshake does not authenticate another, even between the
    /// same two peers with the same keys.
    /// </remarks>
    [Fact]
    public void AuthProofsAreBoundToTheTranscript()
    {
        byte[] secret = Key("pairing-secret");
        byte[] transcriptA = Key("transcript-a");
        byte[] transcriptB = Key("transcript-b");

        byte[] clientA = PairingProofs.AuthClientProof(secret, transcriptA);
        byte[] clientB = PairingProofs.AuthClientProof(secret, transcriptB);

        Assert.NotEqual(clientA, clientB);
        Assert.False(PairingProofs.Verify(clientA, clientB));
    }

    /// <summary>The client and agent AUTH proofs are different labels.</summary>
    [Fact]
    public void TheTwoAuthProofsDiffer()
    {
        byte[] secret = Key("pairing-secret");
        byte[] transcript = Key("transcript");

        byte[] client = PairingProofs.AuthClientProof(secret, transcript);
        byte[] agent = PairingProofs.AuthAgentProof(secret, transcript);

        Assert.NotEqual(client, agent);
        Assert.False(PairingProofs.Verify(client, agent));
    }

    /// <summary>The AUTH proofs match the recipes in the vector file.</summary>
    /// <remarks>
    /// The recipes are read out of the file and compared against the constants, so
    /// a label edited in one place but not the other fails here rather than as an
    /// authentication failure at run time.
    /// </remarks>
    [Fact]
    public void AuthProofRecipesMatchTheVectorFile()
    {
        JsonElement recipes = Vector("derivation_recipes").GetProperty("auth_proofs");

        Assert.Equal(
            "HMAC-SHA256(pairing_secret, \"DLWP/1-client\" || transcript_hash)",
            recipes.GetProperty("client").GetString());

        Assert.Equal(
            "HMAC-SHA256(pairing_secret, \"DLWP/1-agent\" || transcript_hash)",
            recipes.GetProperty("agent").GetString());

        // And the labels really are those strings, so the two cannot drift.
        Assert.Equal("DLWP/1-client", Labels.AuthClient);
        Assert.Equal("DLWP/1-agent", Labels.AuthAgent);
        Assert.Equal("DLWP/1-pairing-controller", Labels.PairingControllerProof);
        Assert.Equal("DLWP/1-pairing-agent", Labels.PairingAgentProof);
        Assert.Equal("DLWP/1-pairing-confirm", Labels.PairingConfirmation);
    }

    /// <summary>The pairing proof recipes match the vector file.</summary>
    [Fact]
    public void PairingProofRecipesMatchTheVectorFile()
    {
        JsonElement recipes = Vector("derivation_recipes").GetProperty("pairing_proofs");

        Assert.Equal(
            "HMAC-SHA256(pairing_secret, \"DLWP/1-pairing-controller\" || ctrl_nonce || agent_nonce)",
            recipes.GetProperty("controller").GetString());

        Assert.Equal(
            "HMAC-SHA256(pairing_secret, \"DLWP/1-pairing-agent\" || agent_nonce || ctrl_nonce)",
            recipes.GetProperty("agent").GetString());

        Assert.Equal(
            "HMAC-SHA256(pairing_secret, \"DLWP/1-pairing-confirm\" || agent_proof || controller_proof)",
            recipes.GetProperty("confirmation").GetString());
    }

    // ---- Comparison ---------------------------------------------------------

    /// <summary>Verification rejects a proof of the wrong length.</summary>
    /// <remarks>
    /// A variable-length comparison that returned early on a length mismatch would
    /// let a forger learn the expected length, and one that compared only the
    /// common prefix would accept a truncated proof.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void VerificationRejectsTheWrongLength(int length)
    {
        byte[] secret = Key("pairing-secret");
        byte[] transcript = Key("transcript");
        byte[] proof = PairingProofs.AuthClientProof(secret, transcript);

        Assert.False(PairingProofs.Verify(proof, new byte[length]));
        Assert.False(PairingProofs.Verify(new byte[length], proof));
    }

    /// <summary>Verification rejects every single-bit change.</summary>
    /// <remarks>
    /// Every position and every bit, because a comparison that skipped a byte or
    /// compared only some bits would still pass a spot check.
    /// </remarks>
    [Fact]
    public void VerificationRejectsAnySingleBitChange()
    {
        byte[] secret = Key("pairing-secret");
        byte[] transcript = Key("transcript");
        byte[] proof = PairingProofs.AuthClientProof(secret, transcript);

        for (int index = 0; index < proof.Length; index++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                byte[] tampered = (byte[])proof.Clone();
                tampered[index] ^= (byte)(1 << bit);

                Assert.False(
                    PairingProofs.Verify(proof, tampered),
                    $"a change to byte {index} bit {bit} was accepted");
            }
        }
    }

    /// <summary>Verification accepts an exact copy.</summary>
    [Fact]
    public void VerificationAcceptsAnExactMatch()
    {
        byte[] secret = Key("pairing-secret");
        byte[] transcript = Key("transcript");
        byte[] proof = PairingProofs.AuthClientProof(secret, transcript);

        Assert.True(PairingProofs.Verify(proof, (byte[])proof.Clone()));
    }

    // ---- X25519 and the all-zero rejection ----------------------------------

    /// <summary>A delegate that fits the span-typed agreement signature.</summary>
    /// <param name="privateKey">The local private key.</param>
    /// <param name="peerPublicKey">The peer's public key.</param>
    /// <returns>The shared secret.</returns>
    /// <remarks>
    /// A named delegate rather than <c>Func&lt;,&gt;</c>: a
    /// <see cref="ReadOnlySpan{T}"/> is a ref struct and cannot be a type argument,
    /// so the callback has to be declared with spans in its own signature.
    /// </remarks>
    private delegate byte[] Derive(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey);

    /// <summary>A stub implementation, so the policy can be tested without a curve.</summary>
    /// <remarks>
    /// The primitive is supplied by the host (RFC-0002 section 7 forbids
    /// implementing it here), so the rejection policy is tested through this stub.
    /// That is the right seam: the policy is this project's and the curve is not.
    /// </remarks>
    private sealed class StubCurve(Derive derive) : IX25519
    {
        public byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey) =>
            derive(privateKey, peerPublicKey);

        /// <summary>A curve that returns the value it is told to.</summary>
        public static StubCurve Returning(byte[] value) => new((_, _) => (byte[])value.Clone());

        /// <summary>A curve that returns all zeros, the low-order point result.</summary>
        public static StubCurve ReturningZero() => new((_, _) => new byte[32]);
    }

    /// <summary>Rejecting the all-zero result is required, and it is done.</summary>
    /// <remarks>
    /// This is <c>x25519.reject.all-zero-output</c>, and the vector names
    /// <c>ERR_UNAUTHORIZED</c> rather than a malformed frame: the peer's key is
    /// well formed and the bytes are fine, what fails is that the exchange proves
    /// nothing. An implementation that derived keys from the zero value would have
    /// a session it believes is authenticated and an attacker who can read it.
    /// </remarks>
    [Fact]
    public void AllZeroX25519OutputIsRejected()
    {
        byte[] privateKey = Key("identity-sk");
        byte[] lowOrderPoint = new byte[32];

        CryptographicException error = Assert.Throws<CryptographicException>(
            () => PairingProofs.X25519(StubCurve.ReturningZero(), privateKey, lowOrderPoint));

        Assert.Contains("all-zero", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("low-order", error.Message, StringComparison.OrdinalIgnoreCase);

        // The error code the vector names, and it is fatal.
        Assert.Equal("ERR_UNAUTHORIZED", ErrorCodes.Unauthorized.Name);
        Assert.True(ErrorCodes.Unauthorized.IsFatal);
    }

    /// <summary>The all-zero vector's own key really is all zero.</summary>
    /// <remarks>
    /// Driven from the file, so the bytes the vector holds are the ones tested.
    /// </remarks>
    [Fact]
    public void TheAllZeroRejectionVectorIsAllZero()
    {
        JsonElement vector = RejectionVectors()
            .Single(v => v.GetProperty("id").GetString() == "x25519.reject.all-zero-output");

        byte[] peerKey = Convert.FromHexString(vector.GetProperty("peer_public_key").GetString()!);

        Assert.Equal(32, peerKey.Length);
        Assert.True(PairingProofs.IsAllZero(peerKey));
        Assert.Equal("rejected", vector.GetProperty("expected").GetString());
        Assert.Equal("ERR_UNAUTHORIZED", vector.GetProperty("expected_error").GetString());

        Assert.Throws<CryptographicException>(
            () => PairingProofs.X25519(StubCurve.ReturningZero(), Key("sk"), peerKey));
    }

    /// <summary>A non-zero result is accepted and returned unchanged.</summary>
    /// <remarks>
    /// The counterpart, so the test above cannot pass by rejecting everything.
    /// </remarks>
    [Fact]
    public void NonZeroX25519OutputIsAccepted()
    {
        byte[] value = Key("some-shared-secret");

        // A single non-zero byte is enough to be a real result.
        byte[] almostZero = new byte[32];
        almostZero[31] = 1;

        Assert.Equal(value, PairingProofs.X25519(StubCurve.Returning(value), Key("sk"), Key("pk")));
        Assert.Equal(almostZero, PairingProofs.X25519(StubCurve.Returning(almostZero), Key("sk"), Key("pk")));
    }

    /// <summary>The all-zero check is not fooled by a zero in one position.</summary>
    [Fact]
    public void IsAllZeroChecksEveryByte()
    {
        Assert.True(PairingProofs.IsAllZero(new byte[32]));
        Assert.True(PairingProofs.IsAllZero([]));

        for (int index = 0; index < 32; index++)
        {
            byte[] value = new byte[32];
            value[index] = 1;
            Assert.False(PairingProofs.IsAllZero(value), $"a set byte at {index} was seen as zero");
        }
    }

    /// <summary>A wrong-width result from the implementation is refused.</summary>
    /// <remarks>
    /// A curve that returned 16 or 64 bytes would otherwise be fed into HKDF and
    /// produce keys, silently, from a value that is not a shared secret.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(64)]
    public void WrongWidthSharedSecretIsRefused(int length)
    {
        byte[] value = new byte[length];
        value.AsSpan().Fill(1);

        Assert.Throws<CryptographicException>(
            () => PairingProofs.X25519(StubCurve.Returning(value), Key("sk"), Key("pk")));
    }

    /// <summary>Wrong-width inputs are refused before the curve is called.</summary>
    [Theory]
    [InlineData(31, 32)]
    [InlineData(32, 31)]
    [InlineData(0, 0)]
    [InlineData(33, 33)]
    public void WrongWidthKeyMaterialIsRefused(int privateLength, int publicLength)
    {
        byte[] privateKey = new byte[privateLength];
        byte[] publicKey = new byte[publicLength];

        Assert.Throws<ArgumentException>(
            () => PairingProofs.X25519(StubCurve.ReturningZero(), privateKey, publicKey));
    }

    /// <summary>A null implementation is refused.</summary>
    [Fact]
    public void NullCurveIsRefused() =>
        Assert.Throws<ArgumentNullException>(() => PairingProofs.X25519(null!, Key("sk"), Key("pk")));

    /// <summary>Wrong-width transcript hashes are refused.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    public void WrongWidthTranscriptIsRefused(int length)
    {
        byte[] secret = Key("pairing-secret");

        Assert.Throws<ArgumentException>(() => PairingProofs.AuthClientProof(secret, new byte[length]));
        Assert.Throws<ArgumentException>(() => PairingProofs.AuthAgentProof(secret, new byte[length]));
    }

    // ---- The nonce and window rejection vectors -----------------------------

    /// <summary>Every rejection vector produces its declared outcome.</summary>
    /// <remarks>
    /// The four that are not the all-zero case are replay and tampering rules, and
    /// they are exercised through the code that owns them rather than restated, so
    /// the vector and the implementation cannot drift.
    /// </remarks>
    [Fact]
    public void EveryRejectionVectorMatchesItsDeclaredOutcome()
    {
        int checked_ = 0;

        foreach (JsonElement vector in RejectionVectors())
        {
            string id = vector.GetProperty("id").GetString()!;
            string expected = vector.GetProperty("expected").GetString()!;

            switch (id)
            {
                case "x25519.reject.all-zero-output":
                    Assert.Equal("rejected", expected);
                    Assert.Throws<CryptographicException>(
                        () => PairingProofs.X25519(StubCurve.ReturningZero(), Key("sk"), new byte[32]));
                    break;

                case "nonce.reject.reused-sequence":
                {
                    uint first = vector.GetProperty("first_sequence_number").GetUInt32();
                    uint second = vector.GetProperty("second_sequence_number").GetUInt32();

                    Assert.Equal(first, second);

                    // Accepted once, then a repeat is a replay.
                    Assert.True(FrameClassifier.ClassifySequence(first, null).Accepted);
                    ReceiveVerdict repeat = FrameClassifier.ClassifySequence(second, first);

                    Assert.Equal(vector.GetProperty("expected_error").GetString(), repeat.Error!.Name);
                    Assert.True(repeat.Error!.IsFatal);
                    break;
                }

                case "nonce.reject.out-of-window":
                {
                    uint highest = vector.GetProperty("highest_accepted").GetUInt32();
                    uint received = vector.GetProperty("received").GetUInt32();
                    uint window = vector.GetProperty("window").GetUInt32();

                    Assert.Equal(FrameClassifier.ReorderWindow, window);
                    Assert.Equal(33u, highest - received);

                    ReceiveVerdict verdict = FrameClassifier.ClassifySequence(received, highest, window);

                    Assert.False(verdict.Accepted);
                    Assert.Equal(vector.GetProperty("expected_error").GetString(), verdict.Error!.Name);
                    break;
                }

                case "nonce.accept.inside-window":
                {
                    uint highest = vector.GetProperty("highest_accepted").GetUInt32();
                    uint received = vector.GetProperty("received").GetUInt32();
                    uint window = vector.GetProperty("window").GetUInt32();

                    Assert.Equal(31u, highest - received);
                    Assert.True(FrameClassifier.ClassifySequence(received, highest, window).Accepted);
                    break;
                }

                case "aead.reject.tampered-header":
                    // The header is the associated data, so a changed header byte
                    // must fail the tag. Covered in the record protection tests,
                    // which own the AEAD; asserted here for the code the vector
                    // names.
                    Assert.Equal("sequence_number", vector.GetProperty("mutated_field").GetString());
                    Assert.Equal("ERR_MALFORMED", vector.GetProperty("expected_error").GetString());
                    break;

                default:
                    Assert.Fail($"{id}: unhandled rejection vector");
                    break;
            }

            checked_++;
        }

        Assert.Equal(5, checked_);
    }

    /// <summary>The window values in the vectors are a pair around the boundary.</summary>
    /// <remarks>
    /// 31 behind is inside and 33 behind is outside, so the two vectors pin the
    /// window from both sides. That is worth asserting together: a change that
    /// accepted both, or rejected both, would otherwise pass one of them.
    /// </remarks>
    [Fact]
    public void TheTwoWindowVectorsBracketTheBoundary()
    {
        Assert.True(FrameClassifier.ClassifySequence(969, 1000, 32).Accepted);
        Assert.False(FrameClassifier.ClassifySequence(967, 1000, 32).Accepted);

        // And the boundary itself: 32 behind is outside, since the window is 32
        // frames and a frame exactly 32 behind has fallen out of it.
        Assert.False(FrameClassifier.ClassifySequence(968, 1000, 32).Accepted);
        Assert.True(FrameClassifier.ClassifySequence(969, 1000, 32).Accepted);
    }

    // ---- Hex helpers --------------------------------------------------------

    /// <summary>Hex round-trips, and is lowercase as the vector files are.</summary>
    [Fact]
    public void HexRoundTrips()
    {
        byte[] value = Key("some-value");
        string hex = PairingProofs.ToHex(value);

        Assert.Equal(hex, hex.ToLowerInvariant());
        Assert.Equal(value, PairingProofs.FromHex(hex));
    }

    /// <summary>Parsing a null or invalid hex string is refused.</summary>
    [Fact]
    public void InvalidHexIsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => PairingProofs.FromHex(null!));
        Assert.Throws<FormatException>(() => PairingProofs.FromHex("not hex"));
    }
}
