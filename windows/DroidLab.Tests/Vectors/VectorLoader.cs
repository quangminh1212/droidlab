using System.Text.Json;

namespace DroidLab.Tests.Vectors;

/// <summary>
/// Loads the shared DLWP/1 conformance vectors.
/// </summary>
/// <remarks>
/// <para>
/// The vectors in <c>protocol/vectors/</c> are the interoperability contract
/// (ADR-0007). Both the Kotlin and the C# codec load the same files and must
/// agree with them byte for byte, so a test that passes against a private copy
/// of the contract proves nothing.
/// </para>
/// <para>
/// The project file links the vectors into the output directory, so this class
/// reads the one true copy. If a file is missing the loader throws rather than
/// reporting zero vectors: a test suite that silently discovers nothing is the
/// failure mode that makes an unverified codec look verified.
/// </para>
/// </remarks>
public static class VectorLoader
{
    private static readonly string VectorDirectory =
        Path.Combine(AppContext.BaseDirectory, "vectors");

    private static readonly string RegistryPath =
        Path.Combine(AppContext.BaseDirectory, "registry", "dlwp-1.json");

    /// <summary>The directory holding the linked vector files.</summary>
    public static string Directory => VectorDirectory;

    /// <summary>
    /// Parses a vector file by name.
    /// </summary>
    /// <param name="fileName">File name including the extension, e.g. <c>framing-basic.json</c>.</param>
    /// <returns>The parsed document. The caller keeps ownership of the instance.</returns>
    /// <exception cref="FileNotFoundException">The vector file is not present in the output directory.</exception>
    public static JsonDocument Load(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        string path = Path.Combine(VectorDirectory, fileName);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"Conformance vector '{fileName}' was not found at '{path}'. The test project links " +
                "protocol/vectors/*.json into the output directory; a missing vector means the build " +
                "did not link the contract, and a suite that cannot find its contract must fail loudly.",
                path);
        }

        return JsonDocument.Parse(File.ReadAllBytes(path));
    }

    /// <summary>
    /// Returns the <c>vectors</c> array of a vector file.
    /// </summary>
    /// <param name="fileName">File name including the extension.</param>
    /// <returns>The elements of the <c>vectors</c> array.</returns>
    /// <exception cref="InvalidOperationException">The file has no <c>vectors</c> array.</exception>
    public static IReadOnlyList<JsonElement> Vectors(string fileName)
    {
        using JsonDocument document = Load(fileName);
        return Elements(document.RootElement, fileName, "vectors");
    }

    /// <summary>
    /// Returns an arbitrary array property of a vector file.
    /// </summary>
    /// <param name="fileName">File name including the extension.</param>
    /// <param name="property">The array property to read, e.g. <c>cases</c> or <c>rejection_vectors</c>.</param>
    /// <returns>The elements of the array, or an empty list when the property is absent.</returns>
    public static IReadOnlyList<JsonElement> Vectors(string fileName, string property)
    {
        using JsonDocument document = Load(fileName);
        if (!document.RootElement.TryGetProperty(property, out JsonElement array))
        {
            return [];
        }

        return Elements(document.RootElement, fileName, property);
    }

    /// <summary>
    /// Loads the machine-readable registries that RFC-0001 section 11 declares normative.
    /// </summary>
    /// <returns>The parsed registry document.</returns>
    /// <exception cref="FileNotFoundException">The registry is not present in the output directory.</exception>
    public static JsonDocument LoadRegistry()
    {
        if (!File.Exists(RegistryPath))
        {
            throw new FileNotFoundException(
                $"The DLWP/1 registry was not found at '{RegistryPath}'. Registry lookups cannot be " +
                "skipped: without the registry a codec cannot tell a known capability from an unknown one.",
                RegistryPath);
        }

        return JsonDocument.Parse(File.ReadAllBytes(RegistryPath));
    }

    private static List<JsonElement> Elements(JsonElement root, string fileName, string property)
    {
        if (!root.TryGetProperty(property, out JsonElement array) || array.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                $"Vector file '{fileName}' has no '{property}' array. The file does not have the shape " +
                "the loader expects, so no test could have been generated from it.");
        }

        // JsonElement values stay valid only while the parent JsonDocument is
        // alive, so each element is cloned into an independent instance.
        List<JsonElement> result = new(array.GetArrayLength());
        foreach (JsonElement element in array.EnumerateArray())
        {
            result.Add(element.Clone());
        }

        return result;
    }
}
