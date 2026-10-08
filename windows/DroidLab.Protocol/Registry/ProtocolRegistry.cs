using System.Collections.Frozen;
using System.Text.Json;

namespace DroidLab.Protocol.Registry;

/// <summary>
/// Who may send a message type.
/// </summary>
public enum Direction
{
    /// <summary>Only the controller may send it.</summary>
    ControllerToAgent,

    /// <summary>Only the agent may send it.</summary>
    AgentToController,

    /// <summary>Either side may send it.</summary>
    Both,
}

/// <summary>
/// Which channel a message type may appear on.
/// </summary>
public enum ChannelConstraint
{
    /// <summary>Only the control channel (channel 0).</summary>
    Control,

    /// <summary>Any channel, including the control channel.</summary>
    Any,
}

/// <summary>
/// One entry of the RFC-0001 section 4 message-type registry.
/// </summary>
/// <param name="Code">The wire code.</param>
/// <param name="Name">The symbolic name, e.g. <c>VIDEO_FRAME</c>.</param>
/// <param name="Direction">Who may send it.</param>
/// <param name="Channel">Which channel it may appear on.</param>
/// <param name="Encrypted">Whether the frame must carry the ENCRYPTED flag.</param>
public sealed record MessageType(
    byte Code,
    string Name,
    Direction Direction,
    ChannelConstraint Channel,
    bool Encrypted);

/// <summary>
/// One entry of the RFC-0001 section 7.1 capability registry.
/// </summary>
/// <param name="Name">The wire name, e.g. <c>screen.mirror</c>.</param>
/// <param name="Meaning">A one-line description, used in diagnostics.</param>
public sealed record Capability(string Name, string Meaning);

/// <summary>
/// The DLWP/1 registry, loaded from <c>protocol/registry/dlwp-1.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// The JSON file is the machine-readable encoding of RFC-0001 section 11, and
/// <c>protocol/tools/registry-check.mjs</c> enforces that the RFC and the file
/// agree in both directions. Loading it at runtime rather than transcribing it
/// into C# means a codec cannot silently disagree with the specification: if the
/// registry changes and the RFC does not, the build's own check fails before any
/// test runs.
/// </para>
/// <para>
/// The type is immutable once loaded and the lookups are frozen dictionaries, so
/// a message-type question on the hot path is a hash lookup rather than a scan.
/// </para>
/// </remarks>
public sealed class ProtocolRegistry
{
    private readonly FrozenDictionary<byte, MessageType> _messageTypesByCode;
    private readonly FrozenDictionary<string, MessageType> _messageTypesByName;
    private readonly FrozenDictionary<string, Capability> _capabilitiesByName;
    private readonly FrozenDictionary<byte, string> _messageTypeCapability;
    private readonly FrozenDictionary<string, uint> _defaultLimits;

    private ProtocolRegistry(
        IReadOnlyList<MessageType> messageTypes,
        IReadOnlyList<Capability> capabilities,
        IReadOnlyList<(byte MessageType, string Capability)> messageTypeCapabilities,
        IReadOnlyDictionary<string, uint> defaultLimits,
        IReadOnlyList<string> sessionEndReasons)
    {
        MessageTypes = messageTypes;
        Capabilities = capabilities;
        SessionEndReasons = sessionEndReasons;

        _messageTypesByCode = messageTypes.ToFrozenDictionary(m => m.Code);
        _messageTypesByName = messageTypes.ToFrozenDictionary(m => m.Name, StringComparer.Ordinal);
        _capabilitiesByName = capabilities.ToFrozenDictionary(c => c.Name, StringComparer.Ordinal);
        _messageTypeCapability = messageTypeCapabilities.ToFrozenDictionary(p => p.MessageType, p => p.Capability);
        _defaultLimits = defaultLimits.ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>Every registered message type.</summary>
    public IReadOnlyList<MessageType> MessageTypes { get; }

    /// <summary>Every registered capability.</summary>
    public IReadOnlyList<Capability> Capabilities { get; }

    /// <summary>The valid reasons for ending a session.</summary>
    public IReadOnlyList<string> SessionEndReasons { get; }

    /// <summary>Looks up a message type by its wire code.</summary>
    /// <param name="code">The code.</param>
    /// <returns>The entry, or <see langword="null"/> when the code is unregistered.</returns>
    /// <remarks>
    /// An unregistered code is answered with <c>ERR_UNSUPPORTED_MESSAGE</c> and
    /// does not end the session, per the registry's reply rule. That is why this
    /// returns null rather than throwing: an unknown code is a peer extension or
    /// a newer version, not a protocol violation.
    /// </remarks>
    public MessageType? FindMessageType(byte code) =>
        _messageTypesByCode.TryGetValue(code, out MessageType? type) ? type : null;

    /// <summary>Looks up a message type by its symbolic name.</summary>
    /// <param name="name">The name, e.g. <c>VIDEO_FRAME</c>.</param>
    /// <returns>The entry, or <see langword="null"/> when the name is unregistered.</returns>
    public MessageType? FindMessageType(string name) =>
        _messageTypesByName.TryGetValue(name, out MessageType? type) ? type : null;

    /// <summary>Looks up a capability by name.</summary>
    /// <param name="name">The capability name.</param>
    /// <returns>The entry, or <see langword="null"/> when the name is unregistered.</returns>
    public Capability? FindCapability(string name) =>
        _capabilitiesByName.TryGetValue(name, out Capability? capability) ? capability : null;

    /// <summary>Whether a capability name is registered.</summary>
    /// <param name="name">The capability name.</param>
    /// <returns><see langword="true"/> when registered.</returns>
    public bool IsKnownCapability(string name) => _capabilitiesByName.ContainsKey(name);

    /// <summary>
    /// The capability that gates a message type, or <see langword="null"/> when it is ungated.
    /// </summary>
    /// <param name="code">The message type code.</param>
    /// <returns>The capability name, or <see langword="null"/>.</returns>
    /// <remarks>
    /// Handshake, control and error frames are ungated: they must work before any
    /// capability has been negotiated. Everything else requires a capability,
    /// which is what makes the negotiation meaningful.
    /// </remarks>
    public string? CapabilityFor(byte code) =>
        _messageTypeCapability.TryGetValue(code, out string? capability) ? capability : null;

    /// <summary>The default value of a limit.</summary>
    /// <param name="name">The limit name, e.g. <c>max_frame_bytes</c>.</param>
    /// <returns>The default, or <see langword="null"/> when the limit is unregistered.</returns>
    public uint? DefaultLimit(string name) =>
        _defaultLimits.TryGetValue(name, out uint value) ? value : null;

    /// <summary>Every default limit, keyed by name.</summary>
    public IReadOnlyDictionary<string, uint> DefaultLimits => _defaultLimits;

    /// <summary>
    /// Loads the registry from the JSON file.
    /// </summary>
    /// <param name="path">Path to <c>dlwp-1.json</c>.</param>
    /// <returns>The loaded registry.</returns>
    /// <exception cref="FileNotFoundException">The registry file is absent.</exception>
    /// <exception cref="InvalidDataException">The registry is present but malformed.</exception>
    /// <remarks>
    /// A malformed registry is a hard failure rather than an empty one. A codec
    /// running with no registry would reject every message type as unknown while
    /// appearing to work, which is the failure mode that makes an unverified
    /// implementation look verified.
    /// </remarks>
    public static ProtocolRegistry LoadFromFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"the DLWP/1 registry was not found at '{path}'. The registry is the normative source for " +
                "message types, capabilities and limits, so a codec cannot run without it.",
                path);
        }

        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
        return FromJson(document.RootElement);
    }

    /// <summary>
    /// Builds a registry from an already-parsed JSON document.
    /// </summary>
    /// <param name="root">The registry root element.</param>
    /// <returns>The loaded registry.</returns>
    /// <exception cref="InvalidDataException">A required section is missing or malformed.</exception>
    public static ProtocolRegistry FromJson(JsonElement root)
    {
        List<MessageType> messageTypes = [];
        foreach (JsonElement entry in RequireArray(root, "message_types"))
        {
            messageTypes.Add(new MessageType(
                Code: entry.GetProperty("code").GetByte(),
                Name: entry.GetProperty("name").GetString()
                    ?? throw new InvalidDataException("a message type has a null name"),
                Direction: ParseDirection(entry.GetProperty("direction").GetString()),
                Channel: ParseChannel(entry.GetProperty("channel").GetString()),
                Encrypted: entry.GetProperty("encrypted").GetBoolean()));
        }

        List<Capability> capabilities = [];
        foreach (JsonElement entry in RequireArray(root, "capabilities"))
        {
            capabilities.Add(new Capability(
                Name: entry.GetProperty("name").GetString()
                    ?? throw new InvalidDataException("a capability has a null name"),
                Meaning: entry.GetProperty("meaning").GetString() ?? string.Empty));
        }

        List<(byte, string)> gated = [];
        foreach (JsonElement entry in RequireArray(root, "message_type_capability"))
        {
            gated.Add((
                entry.GetProperty("message_type").GetByte(),
                entry.GetProperty("capability").GetString()
                    ?? throw new InvalidDataException("a message_type_capability entry has a null capability")));
        }

        Dictionary<string, uint> limits = new(StringComparer.Ordinal);
        if (root.TryGetProperty("default_limits", out JsonElement limitsElement)
            && limitsElement.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in limitsElement.EnumerateObject())
            {
                limits[property.Name] = property.Value.GetUInt32();
            }
        }

        List<string> reasons = [];
        if (root.TryGetProperty("session_end_reasons", out JsonElement reasonsElement)
            && reasonsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement reason in reasonsElement.EnumerateArray())
            {
                if (reason.GetString() is { } text)
                {
                    reasons.Add(text);
                }
            }
        }

        return new ProtocolRegistry(messageTypes, capabilities, gated, limits, reasons);
    }

    /// <summary>
    /// Loads the registry from the copy that ships beside the assembly.
    /// </summary>
    /// <param name="baseDirectory">The directory holding the <c>registry</c> subdirectory.</param>
    /// <returns>The loaded registry.</returns>
    public static ProtocolRegistry LoadFromDirectory(string baseDirectory) =>
        LoadFromFile(Path.Combine(baseDirectory, "registry", "dlwp-1.json"));

    private static IEnumerable<JsonElement> RequireArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement array) || array.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"the registry has no '{name}' array");
        }

        return array.EnumerateArray();
    }

    private static Direction ParseDirection(string? value) => value switch
    {
        "controller_to_agent" => Direction.ControllerToAgent,
        "agent_to_controller" => Direction.AgentToController,
        "both" => Direction.Both,
        _ => throw new InvalidDataException($"unknown direction '{value}' in the registry"),
    };

    private static ChannelConstraint ParseChannel(string? value) => value switch
    {
        "control" => ChannelConstraint.Control,
        "any" => ChannelConstraint.Any,
        _ => throw new InvalidDataException($"unknown channel constraint '{value}' in the registry"),
    };
}
