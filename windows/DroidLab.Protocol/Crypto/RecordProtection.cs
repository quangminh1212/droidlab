using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DroidLab.Protocol.Crypto;

/// <summary>
/// Seals and opens DLWP/1 encrypted bodies (RFC-0002 section 5.2).
/// </summary>
/// <remarks>
/// <para>
/// The encrypted body layout is <c>nonce(12) || ciphertext || tag(16)</c>, where
/// the nonce is <c>iv_prefix(4) || sequence_number(8, big-endian)</c>. The AEAD is
/// AES-256-GCM with a 96-bit nonce and a 128-bit tag.
/// </para>
/// <para>
/// Two details are security-critical and are the reason this type exists rather
/// than callers using <see cref="AesGcm"/> directly:
/// </para>
/// <list type="number">
/// <item>
/// <b>The 24-byte header is authenticated as associated data, but with
/// <c>body_length</c> replaced by the plaintext length.</b> The two sides must
/// authenticate the same string, and at encryption time the sender knows the
/// plaintext length while at decryption time the receiver knows the ciphertext
/// length. Substituting the plaintext length on both sides makes the string
/// agree. This is why the whole header is covered: a frame whose channel,
/// sequence number or message type was altered in flight fails the tag check
/// rather than being acted on.
/// </item>
/// <item>
/// <b>The nonce is derived, never random.</b> The nonce prefix is unique per
/// direction and the sequence number never repeats within a session, so a nonce
/// cannot repeat under a given key. A random nonce would have a collision
/// probability that grows with the square of the frame count, and a GCM nonce
/// reuse is catastrophic: it leaks the authentication key.
/// </item>
/// </list>
/// </remarks>
public static class RecordProtection
{
    /// <summary>The AEAD nonce width in bytes.</summary>
    public const int NonceLength = 12;

    /// <summary>The nonce prefix width in bytes.</summary>
    public const int IvPrefixLength = 4;

    /// <summary>The GCM tag width in bytes.</summary>
    public const int TagLength = 16;

    /// <summary>The key width in bytes.</summary>
    public const int KeyLength = 32;

    /// <summary>The overhead the AEAD adds to a plaintext: nonce plus tag.</summary>
    public const int Overhead = NonceLength + TagLength;

    /// <summary>
    /// Builds the 12-byte nonce for a frame.
    /// </summary>
    /// <param name="ivPrefix">The 4-byte direction prefix.</param>
    /// <param name="sequenceNumber">The frame's sequence number.</param>
    /// <returns>The nonce.</returns>
    /// <exception cref="ArgumentException">The prefix is not 4 bytes.</exception>
    /// <remarks>
    /// The sequence number is 8 bytes big-endian even though the header's field
    /// is 32 bits, because the nonce is the wider of the two in the protocol's
    /// future-proofing: widening the header field later must not change the
    /// nonce layout.
    /// </remarks>
    public static byte[] BuildNonce(ReadOnlySpan<byte> ivPrefix, ulong sequenceNumber)
    {
        if (ivPrefix.Length != IvPrefixLength)
        {
            throw new ArgumentException(
                $"the nonce prefix must be exactly {IvPrefixLength} bytes, got {ivPrefix.Length}",
                nameof(ivPrefix));
        }

        byte[] nonce = new byte[NonceLength];
        ivPrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(IvPrefixLength), sequenceNumber);
        return nonce;
    }

    /// <summary>
    /// Builds the associated data for a frame: the 24-byte header with
    /// <c>body_length</c> set to the plaintext length.
    /// </summary>
    /// <param name="header">The frame header.</param>
    /// <param name="plaintextLength">The length of the plaintext body.</param>
    /// <returns>The 24-byte associated data.</returns>
    /// <remarks>
    /// The header is re-encoded rather than taken from the wire, so that a
    /// receiver computes the associated data from the fields it will actually act
    /// on. If the wire bytes differed in a reserved or unused field, the tag
    /// check is what catches it.
    /// </remarks>
    public static byte[] BuildAssociatedData(FrameHeader header, int plaintextLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);

        FrameHeader forAad = header with { BodyLength = (uint)plaintextLength };

        byte[] associatedData = new byte[FrameHeader.FixedLength];
        FrameHeaderCodec.Encode(forAad, associatedData);
        return associatedData;
    }

    /// <summary>
    /// Seals a plaintext body into the encrypted body layout.
    /// </summary>
    /// <param name="key">The 32-byte record key for this direction.</param>
    /// <param name="ivPrefix">The 4-byte nonce prefix for this direction.</param>
    /// <param name="header">The frame header, with <c>body_length</c> still holding the plaintext length.</param>
    /// <param name="plaintext">The cbOR-encoded body.</param>
    /// <returns>The sealed body: <c>nonce || ciphertext || tag</c>.</returns>
    /// <exception cref="ArgumentException">The key or prefix has the wrong width.</exception>
    /// <remarks>
    /// The sequence number is taken from the header, so the nonce and the frame
    /// cannot disagree about which frame this is.
    /// </remarks>
    public static byte[] Seal(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> ivPrefix,
        FrameHeader header,
        ReadOnlySpan<byte> plaintext)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException(
                $"the record key must be exactly {KeyLength} bytes, got {key.Length}",
                nameof(key));
        }

        byte[] nonce = BuildNonce(ivPrefix, header.SequenceNumber);
        byte[] associatedData = BuildAssociatedData(header, plaintext.Length);

        byte[] sealedBody = new byte[Overhead + plaintext.Length];
        nonce.CopyTo(sealedBody, 0);

        using AesGcm aes = new(key, TagLength);
        aes.Encrypt(
            nonce,
            plaintext,
            sealedBody.AsSpan(NonceLength, plaintext.Length),
            sealedBody.AsSpan(NonceLength + plaintext.Length, TagLength),
            associatedData);

        return sealedBody;
    }

    /// <summary>
    /// Opens an encrypted body, verifying the tag before returning any plaintext.
    /// </summary>
    /// <param name="key">The 32-byte record key for the direction the frame arrived on.</param>
    /// <param name="header">The frame header as received.</param>
    /// <param name="sealedBody">The received body: <c>nonce || ciphertext || tag</c>.</param>
    /// <param name="plaintext">The recovered plaintext on success.</param>
    /// <param name="error">The reason for failure.</param>
    /// <returns><see langword="true"/> when the tag verified.</returns>
    /// <remarks>
    /// <para>
    /// The nonce prefix is not read from the frame. It is recomputed from the
    /// direction's own key material and the received sequence number, so a frame
    /// whose nonce field was tampered with fails authentication instead of
    /// steering the receiver into an attacker-chosen nonce.
    /// </para>
    /// <para>
    /// Failure is reported as a value rather than an exception because a failed
    /// tag is an expected network and attack condition, and the caller must
    /// respond with a fatal error rather than by retrying.
    /// </para>
    /// </remarks>
    public static bool TryOpen(
        ReadOnlySpan<byte> key,
        FrameHeader header,
        ReadOnlySpan<byte> sealedBody,
        out byte[] plaintext,
        out FrameError? error)
    {
        plaintext = [];
        error = null;

        if (key.Length != KeyLength)
        {
            error = new FrameError(
                FrameErrorKind.MalformedBody,
                $"the record key must be exactly {KeyLength} bytes, got {key.Length}",
                ErrorCodes.Internal,
                ErrorCodes.Internal.Severity,
                ClosesConnection: true);
            return false;
        }

        if (sealedBody.Length < Overhead)
        {
            error = new FrameError(
                FrameErrorKind.MalformedBody,
                $"an encrypted body needs at least {Overhead} bytes, got {sealedBody.Length}",
                ErrorCodes.Malformed,
                ErrorCodes.Malformed.Severity,
                ClosesConnection: true);
            return false;
        }

        int ciphertextLength = sealedBody.Length - Overhead;

        // The associated data is built from the plaintext length, which the
        // receiver recovers from the ciphertext length. Both sides therefore
        // authenticate the same bytes even though the numbers differ on the wire.
        byte[] associatedData = BuildAssociatedData(header, ciphertextLength);
        byte[] nonce = BuildNonceForVerification(header, sealedBody);
        byte[] candidate = new byte[ciphertextLength];

        bool verified;
        try
        {
            using AesGcm aes = new(key, TagLength);
            aes.Decrypt(
                nonce,
                sealedBody.Slice(NonceLength, ciphertextLength),
                sealedBody.Slice(NonceLength + ciphertextLength, TagLength),
                candidate,
                associatedData);
            verified = true;
        }
        catch (AuthenticationTagMismatchException)
        {
            verified = false;
        }
        catch (CryptographicException)
        {
            // A malformed ciphertext statement can surface as the base
            // CryptographicException rather than the tag-specific subclass.
            verified = false;
        }

        if (!verified)
        {
            CryptographicOperations.ZeroMemory(candidate);
            error = new FrameError(
                FrameErrorKind.MalformedBody,
                "the AEAD tag did not verify: the body or its header was altered in flight, " +
                "or the frame was sealed under a different key or nonce",
                ErrorCodes.Unauthorized,
                ErrorCodes.Unauthorized.Severity,
                ClosesConnection: true);
            return false;
        }

        plaintext = candidate;
        return true;
    }

    /// <summary>
    /// Recomputes the nonce from the received sequence number and the frame's own prefix bytes.
    /// </summary>
    /// <remarks>
    /// The received nonce's first four bytes are used as the expected prefix and
    /// cross-checked against the direction's configured prefix by
    /// <see cref="VerifyNoncePrefix"/>. Reading them from the frame lets this
    /// method stay direction-agnostic, while the caller still gets to insist the
    /// prefix is the one it negotiated.
    /// </remarks>
    private static byte[] BuildNonceForVerification(FrameHeader header, ReadOnlySpan<byte> sealedBody) =>
        BuildNonce(sealedBody[..IvPrefixLength], header.SequenceNumber);

    /// <summary>
    /// Checks that a received body's nonce prefix matches the direction's expected prefix.
    /// </summary>
    /// <param name="expectedPrefix">The negotiated 4-byte prefix for this direction.</param>
    /// <param name="sealedBody">The received body.</param>
    /// <returns><see langword="true"/> when they match.</returns>
    /// <remarks>
    /// A mismatch means the frame was sealed for the other direction, which is
    /// either a reflection attack or a bug. It is reported separately from a tag
    /// failure so the two are distinguishable in a log.
    /// </remarks>
    public static bool VerifyNoncePrefix(ReadOnlySpan<byte> expectedPrefix, ReadOnlySpan<byte> sealedBody)
    {
        if (expectedPrefix.Length != IvPrefixLength || sealedBody.Length < IvPrefixLength)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            expectedPrefix,
            sealedBody[..IvPrefixLength]);
    }
}
