namespace DroidLab.Tests.Vectors;

/// <summary>
/// Decodes the binary encodings used inside the conformance vectors.
/// </summary>
/// <remarks>
/// <para>
/// The vector schemas declare two binary encodings, both documented in
/// <c>protocol/schema/README.md</c>:
/// </para>
/// <list type="bullet">
/// <item><c>base64</c> for opaque payloads such as media bytes.</item>
/// <item><c>base64url</c> for fixed-width key material, nonces, identifiers and
/// digests. It is unpadded, so that a value can be copied into a QR payload or a
/// filename without further escaping.</item>
/// </list>
/// <para>
/// The difference is not cosmetic: <see cref="Convert.FromBase64String"/> rejects
/// base64url because of the <c>-</c> and <c>_</c> alphabet, and it rejects
/// unpadded input. Reading a base64url field with the standard decoder throws
/// rather than silently producing wrong bytes, which is how this distinction was
/// found.
/// </para>
/// </remarks>
internal static class VectorBinary
{
    /// <summary>Decodes an unpadded base64url field.</summary>
    /// <param name="value">The base64url text, with or without padding.</param>
    /// <returns>The decoded bytes.</returns>
    internal static byte[] FromBase64Url(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        // Normalise to the standard alphabet, then pad to a multiple of four.
        string standard = value
            .Replace('-', '+')
            .Replace('_', '/');

        int remainder = standard.Length % 4;
        standard = remainder switch
        {
            0 => standard,
            2 => standard + "==",
            3 => standard + "=",
            _ => throw new FormatException(
                $"'{value}' is not valid base64url: a length of {value.Length} mod 4 == 1 cannot be decoded"),
        };

        return Convert.FromBase64String(standard);
    }

    /// <summary>
    /// Decodes a field that the schema marks as either base64 or base64url.
    /// </summary>
    /// <param name="value">The encoded text.</param>
    /// <returns>The decoded bytes.</returns>
    /// <remarks>
    /// Tried as base64url first. The two alphabets overlap for input containing
    /// only alphanumerics, and in that case both decoders agree, so the order
    /// only matters for the padded standard form, which base64url normalisation
    /// leaves unchanged.
    /// </remarks>
    internal static byte[] FromBase64Either(string value)
    {
        try
        {
            return FromBase64Url(value);
        }
        catch (FormatException)
        {
            return Convert.FromBase64String(value);
        }
    }

    /// <summary>Encodes bytes as unpadded base64url, for comparing against a vector.</summary>
    /// <param name="bytes">The bytes to encode.</param>
    /// <returns>The base64url text without padding.</returns>
    /// <remarks>
    /// System.Buffers.Text.Base64Url only exists from .NET 9, and this project
    /// targets .NET 8, so the alphabet swap is done by hand.
    /// </remarks>
    internal static string ToBase64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
