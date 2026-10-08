using System.Security.Cryptography;
using System.Text;

namespace DroidLab.Protocol.Crypto;

/// <summary>
/// The DLWP/1 session key schedule (RFC-0002 section 5.1).
/// </summary>
/// <remarks>
/// <para>
/// One HKDF-Extract over <c>shared || pairing_secret</c> produces a single
/// pseudorandom key, and five HKDF-Expand calls with distinct info labels produce
/// the two record keys, the two nonce prefixes and the exporter. The shape is
/// deliberate:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Direction separation.</b> The controller-to-agent and agent-to-controller
/// keys come from different info labels, so a frame cannot be reflected back at
/// its sender and accepted. The vectors pin that the two differ.
/// </item>
/// <item>
/// <b>The transcript binds only the exporter.</b> The transcript hash is fed
/// into the exporter info and nowhere else, so a retransmitted <c>HELLO</c> with
/// the same session id does not change the record keys. Mixing it into the
/// record keys would break reconnection in exactly the case the handshake exists
/// to recover from, and a vector asserts the property directly.
/// </item>
/// <item>
/// <b>The session id is in the salt.</b> Changing only the session id changes
/// every output, which is what makes a replayed handshake useless to an attacker
/// who captured the earlier key material.
/// </item>
/// </list>
/// <para>
/// The salt is <c>"DLWP/1-session" || 0x00 || session_id</c>: the separator is
/// present, and <see cref="Labels.WithSeparator(string, ReadOnlySpan{byte})"/>
/// builds it so the two cannot drift.
/// </para>
/// </remarks>
public static class SessionKeySchedule
{
    /// <summary>The width of a record protection key.</summary>
    public const int KeyLength = 32;

    /// <summary>The width of a nonce prefix.</summary>
    public const int IvPrefixLength = 4;

    /// <summary>The width of the exporter output.</summary>
    public const int ExporterLength = 32;

    /// <summary>The width of the session id.</summary>
    public const int SessionIdLength = 16;

    /// <summary>The derived keys for one session, one set per direction.</summary>
    /// <param name="C2aKey">The controller-to-agent record key, 32 bytes.</param>
    /// <param name="A2cKey">The agent-to-controller record key, 32 bytes.</param>
    /// <param name="C2aIv">The controller-to-agent nonce prefix, 4 bytes.</param>
    /// <param name="A2cIv">The agent-to-controller nonce prefix, 4 bytes.</param>
    /// <param name="Exporter">The exporter value, 32 bytes. Available to higher layers, never used for record protection.</param>
    /// <param name="Salt">The salt the derivation used, for diagnostics and for the vectors.</param>
    /// <param name="Ikm">The input keying material the derivation used.</param>
    public sealed record Keys(
        byte[] C2aKey,
        byte[] A2cKey,
        byte[] C2aIv,
        byte[] A2cIv,
        byte[] Exporter,
        byte[] Salt,
        byte[] Ikm) : IDisposable
    {
        /// <summary>Clears the key material.</summary>
        /// <remarks>
        /// The salt and input keying material are cleared too: the input keying
        /// material contains the pairing secret, so leaving it reachable after
        /// the keys are derived would keep a long-lived secret in memory for the
        /// whole session.
        /// </remarks>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(C2aKey);
            CryptographicOperations.ZeroMemory(A2cKey);
            CryptographicOperations.ZeroMemory(C2aIv);
            CryptographicOperations.ZeroMemory(A2cIv);
            CryptographicOperations.ZeroMemory(Exporter);
            CryptographicOperations.ZeroMemory(Salt);
            CryptographicOperations.ZeroMemory(Ikm);
        }
    }

    /// <summary>
    /// Builds the HKDF salt for a session.
    /// </summary>
    /// <param name="sessionId">The session id, 16 bytes.</param>
    /// <returns>The salt bytes.</returns>
    /// <exception cref="ArgumentException">The session id is not 16 bytes.</exception>
    public static byte[] BuildSalt(ReadOnlySpan<byte> sessionId)
    {
        if (sessionId.Length != SessionIdLength)
        {
            throw new ArgumentException(
                $"session_id must be exactly {SessionIdLength} bytes, got {sessionId.Length}",
                nameof(sessionId));
        }

        return Labels.WithSeparator(Labels.SessionSalt, sessionId);
    }

    /// <summary>
    /// Builds the HKDF input keying material for a session: <c>shared || pairing_secret</c>.
    /// </summary>
    /// <param name="shared">The X25519 shared secret, 32 bytes.</param>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <returns>The input keying material.</returns>
    /// <exception cref="ArgumentException">Either input is not 32 bytes.</exception>
    public static byte[] BuildInputKeyMaterial(ReadOnlySpan<byte> shared, ReadOnlySpan<byte> pairingSecret)
    {
        if (shared.Length != 32)
        {
            throw new ArgumentException($"shared must be exactly 32 bytes, got {shared.Length}", nameof(shared));
        }

        if (pairingSecret.Length != 32)
        {
            throw new ArgumentException(
                $"pairing_secret must be exactly 32 bytes, got {pairingSecret.Length}",
                nameof(pairingSecret));
        }

        byte[] ikm = new byte[64];
        shared.CopyTo(ikm);
        pairingSecret.CopyTo(ikm.AsSpan(32));
        return ikm;
    }

    /// <summary>
    /// Derives the full set of session keys.
    /// </summary>
    /// <param name="sessionId">The session id, 16 bytes.</param>
    /// <param name="shared">The X25519 shared secret for this connection, 32 bytes.</param>
    /// <param name="pairingSecret">The pairing secret established during pairing, 32 bytes.</param>
    /// <param name="transcriptHash">The handshake transcript hash, 32 bytes.</param>
    /// <returns>The derived keys. The caller owns the instance and should dispose it.</returns>
    /// <exception cref="ArgumentException">An input has the wrong width.</exception>
    public static Keys Derive(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> shared,
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> transcriptHash)
    {
        if (transcriptHash.Length != 32)
        {
            throw new ArgumentException(
                $"transcript_hash must be exactly 32 bytes, got {transcriptHash.Length}",
                nameof(transcriptHash));
        }

        byte[] salt = BuildSalt(sessionId);
        byte[] ikm = BuildInputKeyMaterial(shared, pairingSecret);

        byte[] prk = Hkdf.Extract(salt, ikm);
        try
        {
            // The exporter info is the one derivation that is not a bare label:
            // RFC-0002 concatenates the transcript hash onto it, so the exporter
            // is bound to this specific handshake while the record keys are not.
            byte[] exporterInfo = Labels.Concatenate(Labels.Exporter, transcriptHash);

            return new Keys(
                C2aKey: Hkdf.Expand(prk, Labels.Bytes(Labels.C2aKey), KeyLength),
                A2cKey: Hkdf.Expand(prk, Labels.Bytes(Labels.A2cKey), KeyLength),
                C2aIv: Hkdf.Expand(prk, Labels.Bytes(Labels.C2aIv), IvPrefixLength),
                A2cIv: Hkdf.Expand(prk, Labels.Bytes(Labels.A2cIv), IvPrefixLength),
                Exporter: Hkdf.Expand(prk, exporterInfo, ExporterLength),
                Salt: salt,
                Ikm: ikm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    /// <summary>
    /// Derives only the exporter value, for a peer that needs it and nothing else.
    /// </summary>
    /// <param name="sessionId">The session id, 16 bytes.</param>
    /// <param name="shared">The X25519 shared secret, 32 bytes.</param>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="transcriptHash">The handshake transcript hash, 32 bytes.</param>
    /// <returns>The 32-byte exporter value.</returns>
    public static byte[] DeriveExporter(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> shared,
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> transcriptHash)
    {
        using Keys keys = Derive(sessionId, shared, pairingSecret, transcriptHash);
        return (byte[])keys.Exporter.Clone();
    }

    /// <summary>
    /// Derives the pairing secret (RFC-0002 section 4.5).
    /// </summary>
    /// <param name="shared">The ephemeral X25519 shared secret, 32 bytes.</param>
    /// <param name="staticShared">The X25519 secret between the controller identity key and the agent identity key, 32 bytes.</param>
    /// <param name="pairingToken">The pairing token from the QR code.</param>
    /// <param name="pairingId">The pairing id, used as the salt suffix.</param>
    /// <returns>The 32-byte pairing secret.</returns>
    /// <remarks>
    /// The input keying material includes both the ephemeral and the static
    /// Diffie-Hellman results. Including the static one is what makes the pairing
    /// secret depend on the two long-term identities as well as on the one-time
    /// token, so capturing the QR code alone does not let an attacker reproduce
    /// the secret at another time.
    /// </remarks>
    public static byte[] DerivePairingSecret(
        ReadOnlySpan<byte> shared,
        ReadOnlySpan<byte> staticShared,
        ReadOnlySpan<byte> pairingToken,
        ReadOnlySpan<byte> pairingId)
    {
        byte[] ikm = new byte[shared.Length + staticShared.Length + pairingToken.Length];
        shared.CopyTo(ikm);
        staticShared.CopyTo(ikm.AsSpan(shared.Length));
        pairingToken.CopyTo(ikm.AsSpan(shared.Length + staticShared.Length));

        byte[] salt = Labels.WithSeparator(Labels.PairingSalt, pairingId);

        try
        {
            byte[] prk = Hkdf.Extract(salt, ikm);
            try
            {
                return Hkdf.Expand(prk, Labels.Bytes(Labels.PairingSecretInfo), 32);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(prk);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>
    /// Derives the test key material used by the vectors (the seed rule from
    /// <c>crypto-primitives.json</c>).
    /// </summary>
    /// <param name="seed">The seed string.</param>
    /// <returns>The 32-byte derived value.</returns>
    /// <remarks>
    /// This is the <c>key(seed) = SHA-256("DLWP/1-test-key" || 0x00 || seed)</c>
    /// rule. It exists so the vector files contain no literal key bytes: every
    /// secret in them is derived from a readable seed, which keeps the files
    /// auditable and free of copy-paste errors.
    /// </remarks>
    public static byte[] DeriveTestKeyBytes(string seed)
    {
        byte[] input = Labels.WithSeparator(Labels.TestKeySeed, Encoding.UTF8.GetBytes(seed));
        return SHA256.HashData(input);
    }

    /// <summary>
    /// Derives the identity fingerprint shown to the operator (RFC-0002 section 3.2).
    /// </summary>
    /// <param name="identityPublicKey">The Ed25519 identity public key, 32 bytes.</param>
    /// <returns>The fingerprint, formatted as four uppercase hex groups of four digits.</returns>
    /// <remarks>
    /// The format is the first eight digest bytes, uppercase, grouped as
    /// <c>xxxx-xxxx-xxxx-xxxx</c>. It is short enough to read aloud and compare
    /// on both screens during pairing, which is the whole point: it is the one
    /// check that catches a man-in-the-middle at the only moment a QR code cannot.
    /// </remarks>
    public static string DeriveFingerprint(ReadOnlySpan<byte> identityPublicKey)
    {
        if (identityPublicKey.Length != 32)
        {
            throw new ArgumentException(
                $"identity_pub must be exactly 32 bytes, got {identityPublicKey.Length}",
                nameof(identityPublicKey));
        }

        byte[] digest = SHA256.HashData(Labels.WithSeparator(Labels.Fingerprint, identityPublicKey));
        string hex = Convert.ToHexString(digest.AsSpan(0, 8));

        // Uppercase hex, grouped in fours. Invariant culture, because the
        // fingerprint is compared between two machines.
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{hex[0..4]}-{hex[4..8]}-{hex[8..12]}-{hex[12..16]}");
    }

    /// <summary>
    /// Derives the 6-digit pairing confirmation code (RFC-0002 section 4.6).
    /// </summary>
    /// <param name="pairingSecret">The pairing secret, 32 bytes.</param>
    /// <param name="controllerNonce">The controller nonce, 32 bytes.</param>
    /// <param name="agentNonce">The agent nonce, 32 bytes.</param>
    /// <returns>The code as a zero-padded six-character string.</returns>
    /// <remarks>
    /// <c>decimal(uint32_be(digest[0..4]) mod 1000000)</c>, zero padded. The
    /// modulo is why the code is only a convenience check and not a
    /// cryptographic authenticator on its own: it has roughly 20 bits of
    /// entropy, which is enough for a human to compare and not enough to stand
    /// in for the proofs.
    /// </remarks>
    public static string DerivePairingCode(
        ReadOnlySpan<byte> pairingSecret,
        ReadOnlySpan<byte> controllerNonce,
        ReadOnlySpan<byte> agentNonce)
    {
        byte[] input = Labels.WithSeparator(Labels.PairingCode, pairingSecret);
        byte[] message = new byte[input.Length + controllerNonce.Length + agentNonce.Length];
        input.CopyTo(message, 0);
        controllerNonce.CopyTo(message.AsSpan(input.Length));
        agentNonce.CopyTo(message.AsSpan(input.Length + controllerNonce.Length));

        byte[] digest = SHA256.HashData(message);
        uint value = ((uint)digest[0] << 24) | ((uint)digest[1] << 16) | ((uint)digest[2] << 8) | digest[3];

        return (value % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }
}
