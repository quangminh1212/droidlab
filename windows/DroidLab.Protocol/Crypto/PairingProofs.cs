using System.Security.Cryptography;

namespace DroidLab.Protocol.Crypto;

/// <summary>
/// The pairing and AUTH proofs of RFC-0002 sections 4 and 5, and the key
/// agreement checks that guard them.
/// </summary>
/// <remarks>
/// <para>
/// Four HMAC-SHA256 proofs, and the property that matters is that no two of them
/// can be confused for one another. Each prefixes its message with a distinct
/// label, so a proof captured for one purpose cannot be replayed into another:
/// </para>
/// <list type="bullet">
/// <item>The <b>agent proof</b> covers the agent nonce then the controller nonce.</item>
/// <item>The <b>controller proof</b> covers the same two nonces in the opposite
/// order and under a different label. The order swap is not decoration: a
/// transcript that concatenated them identically for both sides would let a peer
/// reflect a proof back as its own confirmation.</item>
/// <item>The <b>confirmation</b> covers both proofs, so it commits to what each
/// side actually sent rather than to what either claims.</item>
/// <item>The <b>AUTH proofs</b> cover the transcript hash, so they are bound to
/// the exact handshake that produced the keys rather than to the keys alone.</item>
/// </list>
/// <para>
/// Comparison is constant time throughout. A byte-wise comparison that returns
/// early leaks how many leading bytes of a guess were right, which is enough to
/// forge a proof one byte at a time.
/// </para>
/// </remarks>
public static class PairingProofs
{
    /// <summary>The width of every proof.</summary>
    public const int ProofLength = 32;

    /// <summary>Computes the agent's pairing proof.</summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="controllerNonce">The controller nonce, 32 bytes.</param>
    /// <param name="agentNonce">The agent nonce, 32 bytes.</param>
    /// <returns>The 32-byte proof.</returns>
    /// <remarks>
    /// Covers <c>agent_nonce || controller_nonce</c>, agent's nonce first.
    /// </remarks>
    public static byte[] AgentProof(
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> controllerNonce,
        ReadOnlySpan<byte> agentNonce)
    {
        byte[] message = Labels.Concatenate(Labels.PairingAgentProof, agentNonce, controllerNonce);
        return Hmac(pairingSecret, message);
    }

    /// <summary>Computes the controller's pairing proof.</summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="controllerNonce">The controller nonce, 32 bytes.</param>
    /// <param name="agentNonce">The agent nonce, 32 bytes.</param>
    /// <returns>The 32-byte proof.</returns>
    /// <remarks>
    /// Covers <c>controller_nonce || agent_nonce</c>, the opposite order to the
    /// agent's proof, which is what stops one being reflected as the other.
    /// </remarks>
    public static byte[] ControllerProof(
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> controllerNonce,
        ReadOnlySpan<byte> agentNonce)
    {
        byte[] message = Labels.Concatenate(Labels.PairingControllerProof, controllerNonce, agentNonce);
        return Hmac(pairingSecret, message);
    }

    /// <summary>Computes the pairing confirmation over both proofs.</summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="agentProof">The agent's proof, 32 bytes.</param>
    /// <param name="controllerProof">The controller's proof, 32 bytes.</param>
    /// <returns>The 32-byte confirmation.</returns>
    /// <remarks>
    /// Committing to both proofs rather than to the nonces means the confirmation
    /// fails if either side sent something other than what the other received,
    /// which is precisely the case a man in the middle creates.
    /// </remarks>
    public static byte[] Confirmation(
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> agentProof,
        ReadOnlySpan<byte> controllerProof)
    {
        byte[] message = Labels.Concatenate(Labels.PairingConfirmation, agentProof, controllerProof);
        return Hmac(pairingSecret, message);
    }

    /// <summary>Computes the controller's AUTH proof.</summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="transcriptHash">The handshake transcript hash, 32 bytes.</param>
    /// <returns>The 32-byte proof.</returns>
    /// <remarks>
    /// Covers <c>"DLWP/1-client" || transcript_hash</c> with no separator, which is
    /// the shape the vectors pin.
    /// </remarks>
    public static byte[] AuthClientProof(ReadOnlySpan<byte> pairingSecret, ReadOnlySpan<byte> transcriptHash)
    {
        RequireLength(transcriptHash, 32, nameof(transcriptHash));
        byte[] message = Labels.Concatenate(Labels.AuthClient, transcriptHash);
        return Hmac(pairingSecret, message);
    }

    /// <summary>Computes the agent's AUTH proof.</summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="transcriptHash">The handshake transcript hash, 32 bytes.</param>
    /// <returns>The 32-byte proof.</returns>
    public static byte[] AuthAgentProof(ReadOnlySpan<byte> pairingSecret, ReadOnlySpan<byte> transcriptHash)
    {
        RequireLength(transcriptHash, 32, nameof(transcriptHash));
        byte[] message = Labels.Concatenate(Labels.AuthAgent, transcriptHash);
        return Hmac(pairingSecret, message);
    }

    /// <summary>
    /// Verifies a proof in constant time.
    /// </summary>
    /// <param name="expected">The proof the verifier computed.</param>
    /// <param name="received">The proof the peer sent.</param>
    /// <returns><see langword="true"/> when they match.</returns>
    /// <remarks>
    /// A length mismatch is <see langword="false"/> without touching the contents,
    /// because there is nothing to compare; everything else goes through
    /// <see cref="CryptographicOperations.FixedTimeEquals"/>.
    /// </remarks>
    public static bool Verify(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> received) =>
        expected.Length == received.Length && CryptographicOperations.FixedTimeEquals(expected, received);

    /// <summary>
    /// Performs an X25519 key agreement through a supplied implementation,
    /// rejecting a low-order result.
    /// </summary>
    /// <param name="agreement">
    /// The curve implementation. RFC-0002 section 7 forbids implementing the
    /// primitive here, so it is supplied rather than written.
    /// </param>
    /// <param name="privateKey">The local private key, 32 bytes.</param>
    /// <param name="peerPublicKey">The peer's public key, 32 bytes.</param>
    /// <returns>The 32-byte shared secret.</returns>
    /// <exception cref="CryptographicException">
    /// The agreement produced an all-zero result, which means the peer sent a
    /// low-order point.
    /// </exception>
    /// <remarks>
    /// <para>
    /// The all-zero check is the contributory-behaviour requirement of RFC-0002
    /// section 7, and it is not optional. An attacker who sends a low-order point
    /// forces the shared secret to zero regardless of the local private key, so
    /// every peer they attack derives the same result. If that value is then fed
    /// into HKDF, the attacker knows the input keying material without knowing
    /// either private key, and the session keys follow from it.
    /// </para>
    /// <para>
    /// So this refuses rather than deriving. A receiver that derived keys from the
    /// zero value would have a session it believes is authenticated and an
    /// attacker who can read it, which is the worst of the available outcomes.
    /// </para>
    /// <para>
    /// <b>Why the implementation is a parameter.</b> RFC-0002 section 7 says an
    /// implementation MUST NOT invent its own primitives, and the .NET base class
    /// library available to this project has no X25519: it appears in
    /// <c>System.Security.Cryptography</c> only from .NET 10. Writing a Montgomery
    /// ladder here would violate the RFC and, worse, would produce code that looks
    /// right, passes these vectors, and leaks the private key through timing.
    /// The policy this project owns is the rejection rule, and that is what lives
    /// here; the curve arithmetic is the platform's or a reviewed library's, and
    /// which one is a decision for the shipping host rather than for the codec.
    /// </para>
    /// </remarks>
    public static byte[] X25519(
        IX25519 agreement,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(agreement);
        RequireLength(privateKey, 32, nameof(privateKey));
        RequireLength(peerPublicKey, 32, nameof(peerPublicKey));

        byte[] shared = agreement.DeriveSharedSecret(privateKey, peerPublicKey);

        if (shared.Length != 32)
        {
            CryptographicOperations.ZeroMemory(shared);
            throw new CryptographicException(
                $"the X25519 implementation returned {shared.Length} bytes rather than 32");
        }

        if (IsAllZero(shared))
        {
            CryptographicOperations.ZeroMemory(shared);
            throw new CryptographicException(
                "X25519 produced an all-zero shared secret: the peer public key is a low-order point, " +
                "so the result is the same for every private key and must not be used to derive keys");
        }

        return shared;
    }

    /// <summary>
    /// Whether a buffer is all zero.
    /// </summary>
    /// <param name="buffer">The buffer.</param>
    /// <returns><see langword="true"/> when every byte is zero.</returns>
    /// <remarks>
    /// Written without an early return so the check does not leak, through timing,
    /// which leading bytes of a peer key were zero. The value being checked is not
    /// secret, but a fixed shape here means the same helper can be used on one that
    /// is.
    /// </remarks>
    public static bool IsAllZero(ReadOnlySpan<byte> buffer)
    {
        byte accumulator = 0;

        foreach (byte value in buffer)
        {
            accumulator |= value;
        }

        return accumulator == 0;
    }

    /// <summary>Computes HMAC-SHA256.</summary>
    /// <param name="key">The key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 32-byte tag.</returns>
    private static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message) =>
        HMACSHA256.HashData(key, message);

    /// <summary>Validates a fixed-width input.</summary>
    /// <param name="value">The value.</param>
    /// <param name="expected">The required width.</param>
    /// <param name="name">The parameter name.</param>
    /// <exception cref="ArgumentException">The width is wrong.</exception>
    private static void RequireLength(ReadOnlySpan<byte> value, int expected, string name)
    {
        if (value.Length != expected)
        {
            throw new ArgumentException(
                $"{name} must be exactly {expected} bytes, got {value.Length}",
                name);
        }
    }

    /// <summary>Formats a proof as lowercase hex, for diagnostics and for the vectors.</summary>
    /// <param name="proof">The proof.</param>
    /// <returns>The hex string.</returns>
    /// <remarks>
    /// Lowercase, because that is what the vector files use for key material and
    /// digests. Formatting is done with the invariant culture so a host with a
    /// Turkish locale cannot produce a different case.
    /// </remarks>
    public static string ToHex(ReadOnlySpan<byte> proof) =>
        Convert.ToHexString(proof).ToLowerInvariant();

    /// <summary>Parses a proof from hex.</summary>
    /// <param name="hex">The hex string.</param>
    /// <returns>The bytes.</returns>
    /// <exception cref="FormatException">The string is not valid hex.</exception>
    public static byte[] FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return Convert.FromHexString(hex);
    }
}

/// <summary>
/// An X25519 key agreement implementation, supplied by the host.
/// </summary>
/// <remarks>
/// <para>
/// RFC-0002 section 7 requires X25519 per RFC 7748 and forbids an implementation
/// from inventing its own primitives. The .NET base class library available to
/// this project has no X25519 — it appears in
/// <c>System.Security.Cryptography</c> only from .NET 10 — so the primitive is
/// supplied rather than written. On a Windows host that means a reviewed library;
/// on Android it means the platform's XDH support, which the Kotlin sibling uses
/// directly.
/// </para>
/// <para>
/// The all-zero rejection that RFC-0002 also requires is deliberately <i>not</i>
/// part of this interface. It belongs to the protocol layer, where
/// <see cref="PairingProofs.X25519(IX25519, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
/// applies it once to every implementation, so that supplying a new one cannot
/// mean forgetting it.
/// </para>
/// </remarks>
public interface IX25519
{
    /// <summary>Derives the raw X25519 shared secret.</summary>
    /// <param name="privateKey">The local private key, 32 bytes.</param>
    /// <param name="peerPublicKey">The peer's public key, 32 bytes.</param>
    /// <returns>The raw shared secret, 32 bytes.</returns>
    byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey);
}
