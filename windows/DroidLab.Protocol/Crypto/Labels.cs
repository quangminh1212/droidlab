using System.Text;

namespace DroidLab.Protocol.Crypto;

/// <summary>
/// The exact ASCII label strings used by RFC-0002, from the <c>labels</c> block of
/// <c>protocol/vectors/crypto-primitives.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// These are case-sensitive and every one of them is load-bearing. A single
/// character's difference yields a different key, and the failure appears at the
/// first record as an authentication failure rather than as anything pointing at
/// the label. Because of that they are constants in one place, never inline
/// literals at a call site, and <c>CryptoLabelTests</c> asserts each against the
/// vector file so a typo cannot survive.
/// </para>
/// <para>
/// The <c>0x00</c> separator that accompanies most of these labels is applied by
/// <see cref="Separator"/> and the helpers below, not folded into the constants,
/// so that a label and its separator cannot drift apart.
/// </para>
/// </remarks>
public static class Labels
{
    /// <summary>The single zero byte that separates a label from the data that follows it.</summary>
    public const byte SeparatorByte = 0x00;

    /// <summary>The handshake transcript label. Also 16 bytes, the transcript prefix.</summary>
    public const string Transcript = "DLWP/1-handshake";

    /// <summary>The HKDF salt label for the session key schedule.</summary>
    public const string SessionSalt = "DLWP/1-session";

    /// <summary>The HKDF salt label for the pairing secret.</summary>
    public const string PairingSalt = "DLWP/1-pairing";

    /// <summary>The HKDF info label for the pairing secret.</summary>
    public const string PairingSecretInfo = "DLWP/1-pairing-secret";

    /// <summary>The HMAC prefix for the agent's pairing proof.</summary>
    public const string PairingAgentProof = "DLWP/1-pairing-agent";

    /// <summary>The HMAC prefix for the controller's pairing proof.</summary>
    public const string PairingControllerProof = "DLWP/1-pairing-controller";

    /// <summary>The HMAC prefix for the pairing confirmation.</summary>
    public const string PairingConfirmation = "DLWP/1-pairing-confirm";

    /// <summary>The hash prefix for the 6-digit pairing code.</summary>
    public const string PairingCode = "DLWP/1-pairing-code";

    /// <summary>The hash prefix for the identity fingerprint.</summary>
    public const string Fingerprint = "DLWP/1-fingerprint";

    /// <summary>The prefix for discovery TXT record signing.</summary>
    public const string Txt = "DLWP/1-txt";

    /// <summary>The HKDF info label for the TLS-style exporter.</summary>
    public const string Exporter = "DLWP/1-exporter";

    /// <summary>The HKDF info label for the controller-to-agent record key.</summary>
    public const string C2aKey = "DLWP/1-c2a-key";

    /// <summary>The HKDF info label for the agent-to-controller record key.</summary>
    public const string A2cKey = "DLWP/1-a2c-key";

    /// <summary>The HKDF info label for the controller-to-agent nonce prefix.</summary>
    public const string C2aIv = "DLWP/1-c2a-iv";

    /// <summary>The HKDF info label for the agent-to-controller nonce prefix.</summary>
    public const string A2cIv = "DLWP/1-a2c-iv";

    /// <summary>The HKDF info label for the test-key seed rule.</summary>
    public const string TestKeySeed = "DLWP/1-test-key";

    /// <summary>The HMAC prefix for the client's AUTH proof.</summary>
    public const string AuthClient = "DLWP/1-client";

    /// <summary>The HMAC prefix for the agent's AUTH proof.</summary>
    public const string AuthAgent = "DLWP/1-agent";

    /// <summary>The separator as a single-byte array.</summary>
    public static ReadOnlySpan<byte> Separator => [SeparatorByte];

    /// <summary>Encodes a label as ASCII bytes.</summary>
    /// <param name="label">The label.</param>
    /// <returns>The label's bytes.</returns>
    /// <remarks>
    /// ASCII rather than UTF-8, so a label containing a non-ASCII character fails
    /// loudly here instead of producing different bytes in the two codecs.
    /// </remarks>
    public static byte[] Bytes(string label) => Encoding.ASCII.GetBytes(label);

    /// <summary>
    /// Builds <c>label || 0x00 || suffix</c>, the shape most labels use.
    /// </summary>
    /// <param name="label">The label.</param>
    /// <param name="suffix">The data that follows the separator.</param>
    /// <returns>The concatenated bytes.</returns>
    public static byte[] WithSeparator(string label, ReadOnlySpan<byte> suffix)
    {
        byte[] labelBytes = Bytes(label);
        byte[] result = new byte[labelBytes.Length + 1 + suffix.Length];
        labelBytes.CopyTo(result, 0);
        result[labelBytes.Length] = SeparatorByte;
        suffix.CopyTo(result.AsSpan(labelBytes.Length + 1));
        return result;
    }

    /// <summary>
    /// Builds <c>label || 0x00 || first || second</c>.
    /// </summary>
    /// <param name="label">The label.</param>
    /// <param name="first">The first data field.</param>
    /// <param name="second">The second data field.</param>
    /// <returns>The concatenated bytes.</returns>
    public static byte[] WithSeparator(string label, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        byte[] labelBytes = Bytes(label);
        byte[] result = new byte[labelBytes.Length + 1 + first.Length + second.Length];
        labelBytes.CopyTo(result, 0);
        result[labelBytes.Length] = SeparatorByte;
        first.CopyTo(result.AsSpan(labelBytes.Length + 1));
        second.CopyTo(result.AsSpan(labelBytes.Length + 1 + first.Length));
        return result;
    }

    /// <summary>
    /// Builds <c>label || data</c> with no separator, the shape HMAC proofs use.
    /// </summary>
    /// <param name="label">The label.</param>
    /// <param name="data">The data that follows the label.</param>
    /// <returns>The concatenated bytes.</returns>
    public static byte[] Concatenate(string label, ReadOnlySpan<byte> data)
    {
        byte[] labelBytes = Bytes(label);
        byte[] result = new byte[labelBytes.Length + data.Length];
        labelBytes.CopyTo(result, 0);
        data.CopyTo(result.AsSpan(labelBytes.Length));
        return result;
    }

    /// <summary>
    /// Builds <c>label || first || second</c> with no separators.
    /// </summary>
    /// <param name="label">The label.</param>
    /// <param name="first">The first data field.</param>
    /// <param name="second">The second data field.</param>
    /// <returns>The concatenated bytes.</returns>
    public static byte[] Concatenate(string label, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        byte[] labelBytes = Bytes(label);
        byte[] result = new byte[labelBytes.Length + first.Length + second.Length];
        labelBytes.CopyTo(result, 0);
        first.CopyTo(result.AsSpan(labelBytes.Length));
        second.CopyTo(result.AsSpan(labelBytes.Length + first.Length));
        return result;
    }
}
