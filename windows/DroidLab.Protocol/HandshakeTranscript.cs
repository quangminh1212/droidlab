using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DroidLab.Protocol;

/// <summary>
/// Builds the DLWP/1 handshake transcript and its digest (RFC-0002 section 5.1).
/// </summary>
/// <remarks>
/// <para>
/// The transcript is the byte string both peers hash to bind the handshake. It is
/// the only input to the key schedule apart from the ECDH secret, so if the two
/// sides serialise it differently they derive different keys and the session
/// fails with <c>ERR_HANDSHAKE_MISMATCH</c>. That makes the exact byte layout a
/// wire-format concern rather than an implementation detail.
/// </para>
/// <para>
/// The layout is fixed:
/// </para>
/// <code>
///   "DLWP/1-handshake"       16 bytes ASCII literal
///   0x00                      1 byte separator
///   len(client_id)  u16 BE    2 bytes
///   client_id                UTF-8 bytes
///   0x00                      1 byte separator
///   len(agent_id)   u16 BE    2 bytes
///   agent_id                 UTF-8 bytes
///   0x00                      1 byte separator
///   client_nonce             32 bytes
///   agent_nonce              32 bytes
///   client_pub               32 bytes
///   agent_pub                32 bytes
/// </code>
/// <para>
/// The identifiers are length-prefixed and the four fixed-width fields are not.
/// Without the prefixes, <c>client_id="c"</c> with <c>agent_id="a"</c> would
/// serialise identically to <c>client_id="c\x00a"</c> with an empty
/// <c>agent_id</c>, letting an attacker steer two different handshakes onto one
/// transcript. The rejection vectors in <c>handshake-transcript.json</c> pin that
/// property.
/// </para>
/// <para>
/// The label is 16 bytes. An earlier revision of the vectors recorded 18, which
/// made every transcript disagree with the reference implementation; the
/// per-vector arithmetic is now recomputed by the verifier so it cannot regress.
/// </para>
/// </remarks>
public static class HandshakeTranscript
{
    /// <summary>The ASCII label that opens the transcript. Exactly 16 bytes.</summary>
    public const string Label = "DLWP/1-handshake";

    /// <summary>The number of bytes in <see cref="Label"/>.</summary>
    public const int LabelLength = 16;

    /// <summary>The separator byte that follows the label and each identifier.</summary>
    public const byte Separator = 0x00;

    /// <summary>The width in bytes of a nonce.</summary>
    public const int NonceLength = 32;

    /// <summary>The width in bytes of an X25519 or Ed25519 public key.</summary>
    public const int PublicKeyLength = 32;

    /// <summary>The width in bytes of the length prefix of an identifier.</summary>
    public const int LengthPrefixLength = 2;

    /// <summary>The total width of the four fixed-width trailing fields.</summary>
    public const int FixedWidthFieldsLength = NonceLength * 2 + PublicKeyLength * 2;

    /// <summary>
    /// The exact transcript length for a given pair of identifiers.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="agentId">The agent identifier.</param>
    /// <returns>The length in bytes.</returns>
    /// <remarks>
    /// This is the formula the vectors record per case:
    /// <c>16 + 1 + (2 + len(client_id)) + 1 + (2 + len(agent_id)) + 1 + 128</c>.
    /// Lengths are counted in UTF-8 bytes, not characters, because an identifier
    /// containing a non-ASCII character would otherwise be mis-sized.
    /// </remarks>
    public static int LengthFor(string clientId, string agentId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(agentId);

        return LabelLength
            + 1 + LengthPrefixLength + Utf8Length(clientId)
            + 1 + LengthPrefixLength + Utf8Length(agentId)
            + 1 + FixedWidthFieldsLength;
    }

    /// <summary>
    /// The inputs to a handshake transcript.
    /// </summary>
    /// <param name="ClientId">The client identifier, UTF-8.</param>
    /// <param name="AgentId">The agent identifier, UTF-8.</param>
    /// <param name="ClientNonce">32 bytes.</param>
    /// <param name="AgentNonce">32 bytes.</param>
    /// <param name="ClientPublicKey">The client's ephemeral X25519 public key, 32 bytes.</param>
    /// <param name="AgentPublicKey">The agent's ephemeral X25519 public key, 32 bytes.</param>
    public readonly record struct Inputs(
        string ClientId,
        string AgentId,
        byte[] ClientNonce,
        byte[] AgentNonce,
        byte[] ClientPublicKey,
        byte[] AgentPublicKey);

    /// <summary>
    /// Serialises the transcript exactly as both peers must.
    /// </summary>
    /// <param name="inputs">The handshake inputs.</param>
    /// <returns>The transcript bytes.</returns>
    /// <exception cref="ArgumentException">
    /// An identifier exceeds 65535 bytes, or a nonce or public key is not exactly
    /// 32 bytes. Both are protocol violations rather than truncation candidates:
    /// silently padding a short key would derive keys from material the peer never
    /// sent.
    /// </exception>
    public static byte[] Build(Inputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs.ClientId);
        ArgumentNullException.ThrowIfNull(inputs.AgentId);

        byte[] clientIdBytes = System.Text.Encoding.UTF8.GetBytes(inputs.ClientId);
        byte[] agentIdBytes = System.Text.Encoding.UTF8.GetBytes(inputs.AgentId);

        RequireIdentifierWidth(clientIdBytes, nameof(inputs));
        RequireIdentifierWidth(agentIdBytes, nameof(inputs));
        RequireWidth(inputs.ClientNonce, NonceLength, "client_nonce");
        RequireWidth(inputs.AgentNonce, NonceLength, "agent_nonce");
        RequireWidth(inputs.ClientPublicKey, PublicKeyLength, "client_pub");
        RequireWidth(inputs.AgentPublicKey, PublicKeyLength, "agent_pub");

        byte[] transcript = new byte[LengthFor(inputs.ClientId, inputs.AgentId)];
        Span<byte> writer = transcript;

        // A fixed-width label, so its length never depends on the input.
        "DLWP/1-handshake"u8.CopyTo(writer);

        int offset = LabelLength;
        offset = WriteSeparator(writer, offset);
        offset = WriteLengthPrefixed(writer, offset, clientIdBytes);
        offset = WriteSeparator(writer, offset);
        offset = WriteLengthPrefixed(writer, offset, agentIdBytes);
        offset = WriteSeparator(writer, offset);

        inputs.ClientNonce.CopyTo(writer[offset..]);
        offset += NonceLength;
        inputs.AgentNonce.CopyTo(writer[offset..]);
        offset += NonceLength;
        inputs.ClientPublicKey.CopyTo(writer[offset..]);
        offset += PublicKeyLength;
        inputs.AgentPublicKey.CopyTo(writer[offset..]);
        offset += PublicKeyLength;

        // The walk must land exactly on the end; a mismatch means LengthFor and
        // the writer disagree, which would produce a transcript that hashes
        // differently from the length the peer expects.
        if (offset != transcript.Length)
        {
            throw new InvalidOperationException(
                $"the transcript writer wrote {offset} bytes but LengthFor predicted {transcript.Length}");
        }

        return transcript;
    }

    /// <summary>
    /// Computes the transcript hash: SHA-256 over the transcript bytes.
    /// </summary>
    /// <param name="inputs">The handshake inputs.</param>
    /// <returns>The 32-byte digest.</returns>
    public static byte[] Hash(Inputs inputs) => SHA256.HashData(Build(inputs));

    /// <summary>
    /// Computes the transcript hash from already-serialised transcript bytes.
    /// </summary>
    /// <param name="transcript">The transcript bytes.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <remarks>
    /// Used by the receiver, which verifies the digest over the bytes it built
    /// rather than over a re-encoding of the parsed fields. Verifying over the
    /// built bytes is what catches a peer that serialised differently.
    /// </remarks>
    public static byte[] HashTranscript(ReadOnlySpan<byte> transcript) => SHA256.HashData(transcript);

    private static int WriteSeparator(Span<byte> buffer, int offset)
    {
        buffer[offset] = Separator;
        return offset + 1;
    }

    private static int WriteLengthPrefixed(Span<byte> buffer, int offset, byte[] value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..], (ushort)value.Length);
        offset += LengthPrefixLength;
        value.CopyTo(buffer[offset..]);
        return offset + value.Length;
    }

    private static void RequireIdentifierWidth(byte[] value, string what)
    {
        if (value.Length > ushort.MaxValue)
        {
            throw new ArgumentException(
                $"an identifier of {value.Length} bytes cannot be expressed in a 2-byte length prefix",
                what);
        }
    }

    private static void RequireWidth(byte[] value, int expected, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != expected)
        {
            throw new ArgumentException(
                $"{name} must be exactly {expected} bytes, got {value.Length}",
                name);
        }
    }

    private static int Utf8Length(string value) => System.Text.Encoding.UTF8.GetByteCount(value);
}
