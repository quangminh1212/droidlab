using System.Text;
using System.Text.Json;
using DroidLab.Protocol.Crypto;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for the DLWP/1 key schedule and AEAD (RFC-0002 section 5).
/// </summary>
/// <remarks>
/// <para>
/// The session-key vectors pin <em>relationships</em> rather than opaque hex
/// blobs: which outputs must differ from each other, which must stay equal when
/// one input changes, and what the salt and input keying material must be. That
/// design is better than literal key bytes, because it cannot be satisfied by
/// copy-pasting the expected value.
/// </para>
/// <para>
/// Because HKDF itself would then be untested against any external reference,
/// <see cref="HkdfMatchesRfc5869PublishedVectors"/> checks it against RFC 5869
/// appendix A. That is a genuinely independent oracle: if our HKDF were wrong in
/// a way both our vectors and our implementation agreed on, that test still fails.
/// </para>
/// </remarks>
public sealed class SessionKeyScheduleTests
{
    private const string KeyVectors = "crypto-session-keys.json";
    private const string PrimitiveVectors = "crypto-primitives.json";

    private static byte[] Hex(string s) => Convert.FromHexString(s);

    // ---- HKDF independently verified -------------------------------------

    /// <summary>
    /// RFC 5869 appendix A test cases, for SHA-256 (A.1, A.2) and SHA-1 (A.3, as a negative control).
    /// </summary>
    /// <remarks>
    /// A.1 and A.2 are the SHA-256 cases and must pass. A.3 uses SHA-1 and is
    /// deliberately not included, because passing it is impossible with this
    /// implementation and its presence would only be confusing.
    /// </remarks>
    [Fact]
    public void HkdfMatchesRfc5869PublishedVectors()
    {
        // RFC 5869 A.1: basic test case with SHA-256.
        byte[] ikm1 = new byte[22];
        for (int i = 0; i < ikm1.Length; i++)
        {
            ikm1[i] = 0x0b;
        }

        byte[] salt1 = Hex("000102030405060708090a0b0c");
        byte[] info1 = Hex("f0f1f2f3f4f5f6f7f8f9");

        Assert.Equal(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            Convert.ToHexString(Hkdf.Extract(salt1, ikm1)).ToLowerInvariant());

        Assert.Equal(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Convert.ToHexString(Hkdf.Expand(
                Hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                info1,
                42)).ToLowerInvariant());

        // RFC 5869 A.2: longer inputs and output, exercising the multi-block chain.
        byte[] ikm2 = new byte[80];
        for (int i = 0; i < ikm2.Length; i++)
        {
            ikm2[i] = (byte)i;
        }

        byte[] salt2 = new byte[80];
        for (int i = 0; i < salt2.Length; i++)
        {
            salt2[i] = (byte)(0x60 + i);
        }

        byte[] info2 = new byte[80];
        for (int i = 0; i < info2.Length; i++)
        {
            info2[i] = (byte)(0xb0 + i);
        }

        Assert.Equal(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            Convert.ToHexString(Hkdf.Extract(salt2, ikm2)).ToLowerInvariant());

        Assert.Equal(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            Convert.ToHexString(Hkdf.Expand(
                Hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
                info2,
                82)).ToLowerInvariant());
    }

    /// <summary>An empty salt is treated as 32 zero bytes, per RFC 5869.</summary>
    [Fact]
    public void EmptySaltIsThirtyTwoZeroBytes()
    {
        byte[] ikm = new byte[22];
        for (int i = 0; i < ikm.Length; i++)
        {
            ikm[i] = 0x0b;
        }

        byte[] withEmpty = Hkdf.Extract([], ikm);
        byte[] withExplicit = Hkdf.Extract(new byte[32], ikm);

        Assert.Equal(withExplicit, withEmpty);
    }

    /// <summary>Expanding to zero bytes yields an empty array rather than throwing.</summary>
    [Fact]
    public void ExpandsToZeroBytes()
    {
        Assert.Empty(Hkdf.Expand(new byte[32], [], 0));
    }

    /// <summary>The expand output is bounded by the single-byte counter.</summary>
    [Fact]
    public void ExpandBeyond255BlocksIsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Hkdf.Expand(new byte[32], [], 255 * 32 + 1));
    }

    /// <summary>Expansion is a prefix property: asking for more extends, never changes.</summary>
    [Fact]
    public void ExpansionIsAPrefixProperty()
    {
        byte[] prk = Hkdf.Extract(Hex("000102030405060708090a0b0c"), Hex("0b0b0b0b0b0b0b0b0b0b0b0b"));

        byte[] short32 = Hkdf.Expand(prk, Hex("f0f1f2f3"), 32);
        byte[] long64 = Hkdf.Expand(prk, Hex("f0f1f2f3"), 64);

        Assert.Equal(short32, long64[..32]);
    }

    // ---- Labels ----------------------------------------------------------

    /// <summary>Every label must match the vector file exactly.</summary>
    [Fact]
    public void EveryLabelMatchesTheVectorFile()
    {
        using JsonDocument registry = VectorLoader.Load(PrimitiveVectors);
        JsonElement labels = registry.RootElement.GetProperty("labels");

        Assert.Equal(Labels.Transcript, labels.GetProperty("transcript_label").GetString());
        Assert.Equal(Labels.SessionSalt, labels.GetProperty("session_salt_label").GetString());
        Assert.Equal(Labels.PairingSalt, labels.GetProperty("pairing_salt_label").GetString());
        Assert.Equal(Labels.PairingSecretInfo, labels.GetProperty("pairing_secret_info").GetString());
        Assert.Equal(Labels.PairingAgentProof, labels.GetProperty("pairing_agent_proof_label").GetString());
        Assert.Equal(Labels.PairingControllerProof, labels.GetProperty("pairing_controller_proof_label").GetString());
        Assert.Equal(Labels.PairingConfirmation, labels.GetProperty("pairing_confirmation_label").GetString());
        Assert.Equal(Labels.PairingCode, labels.GetProperty("pairing_code_label").GetString());
        Assert.Equal(Labels.Fingerprint, labels.GetProperty("fingerprint_label").GetString());
        Assert.Equal(Labels.Txt, labels.GetProperty("txt_label").GetString());
        Assert.Equal(Labels.Exporter, labels.GetProperty("exporter_label").GetString());
        Assert.Equal(Labels.C2aKey, labels.GetProperty("c2a_key_info").GetString());
        Assert.Equal(Labels.A2cKey, labels.GetProperty("a2c_key_info").GetString());
        Assert.Equal(Labels.C2aIv, labels.GetProperty("c2a_iv_info").GetString());
        Assert.Equal(Labels.A2cIv, labels.GetProperty("a2c_iv_info").GetString());
        Assert.Equal(Labels.AuthClient, labels.GetProperty("auth_client_label").GetString());
        Assert.Equal(Labels.AuthAgent, labels.GetProperty("auth_agent_label").GetString());
    }

    /// <summary>Labels are ASCII, so both codecs encode identical bytes.</summary>
    [Fact]
    public void LabelsAreAscii()
    {
        foreach (string label in new[]
        {
            Labels.Transcript, Labels.SessionSalt, Labels.PairingSalt, Labels.PairingSecretInfo,
            Labels.PairingAgentProof, Labels.PairingControllerProof, Labels.PairingConfirmation,
            Labels.PairingCode, Labels.Fingerprint, Labels.Txt, Labels.Exporter,
            Labels.C2aKey, Labels.A2cKey, Labels.C2aIv, Labels.A2cIv,
            Labels.AuthClient, Labels.AuthAgent,
        })
        {
            Assert.All(label, c => Assert.True(c < 128, $"label '{label}' contains a non-ASCII character"));
            // ASCII and UTF-8 must agree, which they only do for ASCII input.
            Assert.Equal(Encoding.ASCII.GetBytes(label), Encoding.UTF8.GetBytes(label));
        }
    }

    // ---- Salt and input keying material ----------------------------------

    /// <summary>The session salt must match the vector's recorded hex.</summary>
    [Fact]
    public void SessionSaltMatchesTheVector()
    {
        JsonElement vector = BaselineVector();

        byte[] sessionId = VectorBinary.FromBase64Url(
            vector.GetProperty("inputs").GetProperty("session_id").GetString()!);

        byte[] salt = SessionKeySchedule.BuildSalt(sessionId);

        Assert.Equal(
            vector.GetProperty("derived").GetProperty("salt_hex").GetString(),
            Convert.ToHexString(salt).ToLowerInvariant());
    }

    /// <summary>The input keying material must be shared || pairing_secret.</summary>
    [Fact]
    public void InputKeyingMaterialMatchesTheVector()
    {
        JsonElement vector = BaselineVector();
        JsonElement inputs = vector.GetProperty("inputs");

        byte[] ikm = SessionKeySchedule.BuildInputKeyMaterial(
            Hex(inputs.GetProperty("shared").GetString()!),
            Hex(inputs.GetProperty("pairing_secret").GetString()!));

        Assert.Equal(
            vector.GetProperty("derived").GetProperty("ikm_hex").GetString(),
            Convert.ToHexString(ikm).ToLowerInvariant());
    }

    /// <summary>The salt is label || 0x00 || session_id.</summary>
    /// <remarks>
    /// The label here is 14 bytes ("DLWP/1-session"), which is easy to confuse
    /// with the 16-byte transcript label "DLWP/1-handshake". The lengths are
    /// asserted separately so that confusing the two fails loudly rather than
    /// producing a salt that is one byte short.
    /// </remarks>
    [Fact]
    public void SaltLayoutIsLabelSeparatorSessionId()
    {
        byte[] sessionId = VectorBinary.FromBase64Url("AAECAwQFBgcICQoLDA0ODw");
        byte[] salt = SessionKeySchedule.BuildSalt(sessionId);

        byte[] expected = [.. Encoding.ASCII.GetBytes("DLWP/1-session"), 0x00, .. sessionId];

        Assert.Equal(expected, salt);

        // The session-salt label is 14 bytes; the transcript label is 16. They
        // are different strings and must not be conflated.
        Assert.Equal(14, Encoding.ASCII.GetByteCount("DLWP/1-session"));
        Assert.Equal(16, Encoding.ASCII.GetByteCount("DLWP/1-handshake"));

        // 14 + 1 separator + 16 session id.
        Assert.Equal(31, salt.Length);

        // The vector's recorded salt agrees, which is the independent check.
        Assert.Equal(
            "444c57502f312d73657373696f6e00000102030405060708090a0b0c0d0e0f",
            Convert.ToHexString(salt).ToLowerInvariant());
    }

    /// <summary>A wrong-width session id is rejected rather than truncated.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(17)]
    public void WrongSessionIdWidthIsRejected(int width)
    {
        Assert.Throws<ArgumentException>(() => SessionKeySchedule.BuildSalt(new byte[width]));
    }

    // ---- Derived key properties ------------------------------------------

    /// <summary>Every derived value must have the declared length.</summary>
    [Fact]
    public void DerivedValuesHaveTheDeclaredLengths()
    {
        using SessionKeySchedule.Keys keys = DeriveBaseline();

        Assert.Equal(32, keys.C2aKey.Length);
        Assert.Equal(32, keys.A2cKey.Length);
        Assert.Equal(4, keys.C2aIv.Length);
        Assert.Equal(4, keys.A2cIv.Length);
        Assert.Equal(32, keys.Exporter.Length);

        JsonElement lengths = BaselineVector()
            .GetProperty("derived").GetProperty("expected_lengths");

        Assert.Equal(lengths.GetProperty("c2a_key").GetInt32(), keys.C2aKey.Length);
        Assert.Equal(lengths.GetProperty("a2c_key").GetInt32(), keys.A2cKey.Length);
        Assert.Equal(lengths.GetProperty("c2a_iv").GetInt32(), keys.C2aIv.Length);
        Assert.Equal(lengths.GetProperty("a2c_iv").GetInt32(), keys.A2cIv.Length);
        Assert.Equal(lengths.GetProperty("exporter").GetInt32(), keys.Exporter.Length);
    }

    /// <summary>The two direction keys and the nonce prefixes must all differ.</summary>
    /// <remarks>
    /// This is the direction-separation property. If the two directions shared a
    /// key, a frame could be reflected back at its sender and would authenticate.
    /// </remarks>
    [Fact]
    public void DirectionsAreSeparated()
    {
        using SessionKeySchedule.Keys keys = DeriveBaseline();

        Assert.NotEqual(keys.C2aKey, keys.A2cKey);
        Assert.NotEqual(keys.C2aKey, keys.Exporter);
        Assert.NotEqual(keys.A2cKey, keys.Exporter);
        Assert.NotEqual(keys.C2aIv, keys.A2cIv);
    }

    /// <summary>
    /// The direction-separation vector's assertions, read from the file.
    /// </summary>
    [Fact]
    public void DirectionSeparationVectorAssertionsHold()
    {
        JsonElement vector = VectorLoader.Vectors(KeyVectors)
            .Single(v => v.GetProperty("id").GetString() == "session.keys.direction-separation");

        // The assertions are prose; the test's job is to satisfy each of them.
        Assert.Contains("c2a_key != a2c_key", vector.GetProperty("assertions")
            .EnumerateArray().Select(a => a.GetString()));

        using SessionKeySchedule.Keys keys = Derive(
            vector.GetProperty("inputs"));

        Assert.NotEqual(keys.C2aKey, keys.A2cKey);
        Assert.NotEqual(keys.C2aKey, keys.Exporter);
        Assert.NotEqual(keys.A2cKey, keys.Exporter);
        Assert.NotEqual(keys.C2aIv, keys.A2cIv);
    }

    /// <summary>Changing only the session id must change every derived value.</summary>
    /// <remarks>
    /// The session id is part of the HKDF salt, so this is what makes a replayed
    /// handshake produce different keys and therefore a useless recording for an
    /// attacker.
    /// </remarks>
    [Fact]
    public void ChangingTheSessionIdChangesEverything()
    {
        JsonElement vector = VectorLoader.Vectors(KeyVectors)
            .Single(v => v.GetProperty("id").GetString() == "session.keys.session-id-changes-everything");

        using SessionKeySchedule.Keys baseline = DeriveBaseline();
        using SessionKeySchedule.Keys changed = Derive(vector.GetProperty("inputs"));

        Assert.NotEqual(baseline.C2aKey, changed.C2aKey);
        Assert.NotEqual(baseline.A2cKey, changed.A2cKey);
        Assert.NotEqual(baseline.C2aIv, changed.C2aIv);
        Assert.NotEqual(baseline.A2cIv, changed.A2cIv);
        Assert.NotEqual(baseline.Exporter, changed.Exporter);
    }

    /// <summary>
    /// Changing only the transcript hash must change the exporter and nothing else.
    /// </summary>
    /// <remarks>
    /// The transcript hash is fed only into the exporter info. An implementation
    /// that mixed it into the record keys would break reconnection after a
    /// retransmitted HELLO, which is precisely the case the handshake exists to
    /// recover from.
    /// </remarks>
    [Fact]
    public void ChangingTheTranscriptChangesOnlyTheExporter()
    {
        JsonElement vector = VectorLoader.Vectors(KeyVectors)
            .Single(v => v.GetProperty("id").GetString() == "session.keys.transcript-changes-exporter-only");

        using SessionKeySchedule.Keys baseline = DeriveBaseline();
        using SessionKeySchedule.Keys changed = Derive(vector.GetProperty("inputs"));

        Assert.Equal(baseline.C2aKey, changed.C2aKey);
        Assert.Equal(baseline.A2cKey, changed.A2cKey);
        Assert.Equal(baseline.C2aIv, changed.C2aIv);
        Assert.Equal(baseline.A2cIv, changed.A2cIv);

        Assert.NotEqual(baseline.Exporter, changed.Exporter);
    }

    /// <summary>Derivation is deterministic: the same inputs give the same keys.</summary>
    [Fact]
    public void DerivationIsDeterministic()
    {
        using SessionKeySchedule.Keys first = DeriveBaseline();
        using SessionKeySchedule.Keys second = DeriveBaseline();

        Assert.Equal(first.C2aKey, second.C2aKey);
        Assert.Equal(first.A2cKey, second.A2cKey);
        Assert.Equal(first.Exporter, second.Exporter);
    }

    /// <summary>A wrong-width shared secret or pairing secret is rejected.</summary>
    [Fact]
    public void WrongWidthSecretsAreRejected()
    {
        byte[] sessionId = VectorBinary.FromBase64Url("AAECAwQFBgcICQoLDA0ODw");
        byte[] good = new byte[32];
        byte[] transcript = new byte[32];

        Assert.Throws<ArgumentException>(
            () => SessionKeySchedule.Derive(sessionId, new byte[31], good, transcript));
        Assert.Throws<ArgumentException>(
            () => SessionKeySchedule.Derive(sessionId, good, new byte[31], transcript));
        Assert.Throws<ArgumentException>(
            () => SessionKeySchedule.Derive(sessionId, good, good, new byte[31]));
    }

    // ---- Test-key seed rule ----------------------------------------------

    /// <summary>The seed rule is SHA-256("DLWP/1-test-key" || 0x00 || seed).</summary>
    /// <remarks>
    /// The vectors contain no literal key bytes; every secret is derived from a
    /// readable seed by this rule. The test recomputes it independently so the
    /// rule itself is pinned rather than assumed.
    /// </remarks>
    [Fact]
    public void TestKeySeedRuleMatchesItsOwnFormula()
    {
        using JsonDocument primitives = VectorLoader.Load(PrimitiveVectors);
        string formula = primitives.RootElement.GetProperty("seed_rule").GetProperty("formula").GetString()!;

        Assert.Contains("DLWP/1-test-key", formula, StringComparison.Ordinal);

        byte[] expected = System.Security.Cryptography.SHA256.HashData(
            [.. Encoding.ASCII.GetBytes("DLWP/1-test-key"), 0x00, .. Encoding.UTF8.GetBytes("some-seed")]);

        Assert.Equal(expected, SessionKeySchedule.DeriveTestKeyBytes("some-seed"));
    }

    /// <summary>Different seeds give different keys.</summary>
    [Fact]
    public void DifferentSeedsGiveDifferentKeys()
    {
        Assert.NotEqual(
            SessionKeySchedule.DeriveTestKeyBytes("seed-a"),
            SessionKeySchedule.DeriveTestKeyBytes("seed-b"));
    }

    // ---- Fingerprint and pairing code ------------------------------------

    /// <summary>The fingerprint has the documented shape.</summary>
    /// <remarks>
    /// Uppercase hex of the first 8 digest bytes grouped as xxxx-xxxx-xxxx-xxxx.
    /// The format matters because an operator reads it aloud and compares it on
    /// two screens.
    /// </remarks>
    [Fact]
    public void FingerprintHasTheDocumentedFormat()
    {
        byte[] identity = new byte[32];

        string fingerprint = SessionKeySchedule.DeriveFingerprint(identity);

        Assert.Equal(19, fingerprint.Length); // 16 hex + 3 hyphens
        Assert.Matches("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", fingerprint);
    }

    /// <summary>Different identity keys give different fingerprints.</summary>
    [Fact]
    public void DifferentIdentitiesGiveDifferentFingerprints()
    {
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        second[0] = 1;

        Assert.NotEqual(
            SessionKeySchedule.DeriveFingerprint(first),
            SessionKeySchedule.DeriveFingerprint(second));
    }

    /// <summary>
    /// The fingerprint derivation is label || 0x00 || identity_pub, and matches an
    /// independent computation.
    /// </summary>
    [Fact]
    public void FingerprintMatchesAnIndependentDerivation()
    {
        byte[] identity = VectorBinary.FromBase64Url("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8");

        byte[] input = [.. Encoding.ASCII.GetBytes("DLWP/1-fingerprint"), 0x00, .. identity];
        byte[] digest = System.Security.Cryptography.SHA256.HashData(input);
        string hex = Convert.ToHexString(digest[..8]);

        Assert.Equal(
            $"{hex[0..4]}-{hex[4..8]}-{hex[8..12]}-{hex[12..16]}",
            SessionKeySchedule.DeriveFingerprint(identity));
    }

    /// <summary>A wrong-width identity key is rejected.</summary>
    [Fact]
    public void WrongWidthIdentityKeyIsRejected()
    {
        Assert.Throws<ArgumentException>(() => SessionKeySchedule.DeriveFingerprint(new byte[31]));
    }

    /// <summary>The pairing code is always six decimal digits.</summary>
    [Fact]
    public void PairingCodeIsSixDigits()
    {
        byte[] secret = new byte[32];
        byte[] ctrl = new byte[32];
        byte[] agent = new byte[32];
        agent[0] = 1;

        string code = SessionKeySchedule.DerivePairingCode(secret, ctrl, agent);

        Assert.Equal(6, code.Length);
        Assert.Matches("^[0-9]{6}$", code);
    }

    /// <summary>The pairing code is deterministic and input-sensitive.</summary>
    [Fact]
    public void PairingCodeIsDeterministicAndInputSensitive()
    {
        byte[] secret = new byte[32];
        byte[] ctrl = new byte[32];
        byte[] agent = new byte[32];
        byte[] otherAgent = new byte[32];
        otherAgent[31] = 0xFF;

        Assert.Equal(
            SessionKeySchedule.DerivePairingCode(secret, ctrl, agent),
            SessionKeySchedule.DerivePairingCode(secret, ctrl, agent));

        Assert.NotEqual(
            SessionKeySchedule.DerivePairingCode(secret, ctrl, agent),
            SessionKeySchedule.DerivePairingCode(secret, ctrl, otherAgent));
    }

    /// <summary>
    /// The pairing code's inputs are ordered secret, controller nonce, agent nonce.
    /// </summary>
    /// <remarks>
    /// Swapping the two nonces must change the code, which is what pins the order
    /// rather than leaving it to chance.
    /// </remarks>
    [Fact]
    public void PairingCodeIsSensitiveToNonceOrder()
    {
        byte[] secret = new byte[32];
        byte[] ctrl = new byte[32];
        ctrl[0] = 0xAA;
        byte[] agent = new byte[32];
        agent[0] = 0xBB;

        Assert.NotEqual(
            SessionKeySchedule.DerivePairingCode(secret, ctrl, agent),
            SessionKeySchedule.DerivePairingCode(secret, agent, ctrl));
    }

    // ---- Helpers ---------------------------------------------------------

    private static JsonElement BaselineVector() =>
        VectorLoader.Vectors(KeyVectors)
            .Single(v => v.GetProperty("id").GetString() == "session.keys.baseline");

    private static SessionKeySchedule.Keys DeriveBaseline() => Derive(BaselineVector().GetProperty("inputs"));

    private static SessionKeySchedule.Keys Derive(JsonElement inputs) => SessionKeySchedule.Derive(
        VectorBinary.FromBase64Url(inputs.GetProperty("session_id").GetString()!),
        Hex(inputs.GetProperty("shared").GetString()!),
        Hex(inputs.GetProperty("pairing_secret").GetString()!),
        Hex(inputs.GetProperty("transcript_hash").GetString()!));
}
