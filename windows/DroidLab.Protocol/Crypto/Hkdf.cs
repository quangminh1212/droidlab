using System.Security.Cryptography;

namespace DroidLab.Protocol.Crypto;

/// <summary>
/// HKDF-SHA256 per RFC 5869, as used by the DLWP/1 key schedule.
/// </summary>
/// <remarks>
/// <para>
/// .NET 8 has <see cref="HKDF"/>, but this type is written out explicitly for
/// two reasons. First, the vector set pins the expand chain as a formula —
/// <c>T(1) = HMAC(prk, info || 0x01)</c>, <c>T(n) = HMAC(prk, T(n-1) || info || 0xnn)</c>
/// — and an implementation that follows the same formulation is directly
/// comparable to the Kotlin one. Second, the <c>exporter</c> derivation in
/// RFC-0002 concatenates a label with the transcript hash into the info field,
/// and having the primitive under our control means that concatenation is
/// visible at the call site rather than buried in an overload choice.
/// </para>
/// </remarks>
public static class Hkdf
{
    /// <summary>The digest width in bytes. SHA-256, so 32.</summary>
    public const int HashLength = 32;

    /// <summary>
    /// HKDF-Extract: computes the pseudorandom key from input keying material.
    /// </summary>
    /// <param name="salt">The salt. An empty salt is treated as <c>HashLen</c> zero bytes, per RFC 5869.</param>
    /// <param name="inputKeyMaterial">The input keying material.</param>
    /// <returns>The 32-byte pseudorandom key.</returns>
    public static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        // RFC 5869 section 2.2: "if not provided, it is set to a string of
        // HashLen zeros". Only an *absent* salt gets that treatment; a supplied
        // salt is used as-is however long it is. Clamping it to HashLen would
        // silently truncate, and RFC 5869 A.2 uses an 80-byte salt precisely to
        // catch that mistake.
        if (salt.Length == 0)
        {
            Span<byte> zeroed = stackalloc byte[HashLength];
            return HMACSha256(zeroed, inputKeyMaterial);
        }

        return HMACSha256(salt, inputKeyMaterial);
    }

    /// <summary>
    /// HKDF-Expand: expands a pseudorandom key to the requested length.
    /// </summary>
    /// <param name="prk">The pseudorandom key from <see cref="Extract"/>.</param>
    /// <param name="info">The context and application specific information.</param>
    /// <param name="length">The number of bytes to produce.</param>
    /// <returns>The output keying material.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="length"/> is negative or exceeds 255 * 32 bytes, which is
    /// the bound RFC 5869 places on the output of HKDF-Expand with SHA-256.
    /// </exception>
    public static byte[] Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        // RFC 5869 section 2.3: N = ceil(L/HashLen), and N must be <= 255
        // because the counter is a single byte.
        const int MaxLength = 255 * HashLength;
        if (length > MaxLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                length,
                $"HKDF-Expand with SHA-256 can produce at most {MaxLength} bytes");
        }

        byte[] output = new byte[length];
        if (length == 0)
        {
            return output;
        }

        // The blocked construction: T(n) = HMAC(prk, T(n-1) || info || n).
        byte[] previous = [];
        int written = 0;
        byte counter = 1;

        while (written < length)
        {
            byte[] message = new byte[previous.Length + info.Length + 1];
            previous.CopyTo(message, 0);
            info.CopyTo(message.AsSpan(previous.Length));
            message[^1] = counter;

            previous = HMACSha256(prk, message);

            int take = Math.Min(HashLength, length - written);
            previous.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
            counter++;
        }

        // The intermediate T blocks are key material; clear the one that survives
        // the loop so it is not left in a long-lived array.
        CryptographicOperations.ZeroMemory(previous);

        return output;
    }

    /// <summary>
    /// Performs HKDF-Extract followed by HKDF-Expand.
    /// </summary>
    /// <param name="salt">The salt, as a whole byte string including any separator.</param>
    /// <param name="inputKeyMaterial">The input keying material.</param>
    /// <param name="info">The info field.</param>
    /// <param name="length">The number of bytes to produce.</param>
    /// <returns>The output keying material.</returns>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> info,
        int length)
    {
        byte[] prk = Extract(salt, inputKeyMaterial);
        try
        {
            return Expand(prk, info, length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
        }
    }

    /// <summary>Computes HMAC-SHA256 over a byte buffer.</summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="message">The message.</param>
    /// <returns>The 32-byte tag.</returns>
    internal static byte[] HMACSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message) =>
        HMACSHA256.HashData(key, message);
}
