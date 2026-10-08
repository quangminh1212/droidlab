using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Registry;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for capability negotiation and limit application (RFC-0001 section 7).
/// </summary>
public sealed class CapabilityNegotiationTests
{
    private const string VectorFile = "capabilities.json";

    /// <summary>
    /// The registry under test, built from the same file the codec ships with.
    /// </summary>
    /// <remarks>
    /// Loaded from the linked copy of <c>protocol/registry/dlwp-1.json</c> rather
    /// than from a transcribed constant, so these tests fail if the registry and
    /// the RFC ever diverge. A registry typed out by hand would agree with itself
    /// no matter what the specification said.
    /// </remarks>
    private static ProtocolRegistry Registry()
    {
        using JsonDocument document = VectorLoader.LoadRegistry();
        return ProtocolRegistry.FromJson(document.RootElement);
    }

    private static IEnumerable<JsonElement> NegotiationVectors() =>
        VectorLoader.Vectors(VectorFile, "negotiation_vectors");

    private static IEnumerable<JsonElement> ClampVectors() =>
        VectorLoader.Vectors(VectorFile, "limit_clamp_vectors");

    private static string[] Strings(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out JsonElement array) && array.ValueKind == JsonValueKind.Array
            ? [.. array.EnumerateArray().Select(e => e.GetString() ?? string.Empty)]
            : [];

    // ---- The registry itself ----------------------------------------------

    /// <summary>The registry loads and carries every section the codec needs.</summary>
    [Fact]
    public void RegistryLoadsEverySection()
    {
        ProtocolRegistry registry = Registry();

        Assert.Equal(42, registry.MessageTypes.Count);
        Assert.Equal(18, registry.Capabilities.Count);
        Assert.Equal(9, registry.DefaultLimits.Count);
        Assert.NotEmpty(registry.SessionEndReasons);
    }

    /// <summary>
    /// The registry's limits must match the vector's limits exactly.
    /// </summary>
    /// <remarks>
    /// This is the assertion for the spec defect where the vector carried a
    /// tenth limit, max_pending_handshakes, that RFC-0001 never declared, while
    /// section 8.2 depended on max_gesture_steps which the table omitted. The
    /// two are compared here as well as in the verifier, because the C# side
    /// must not be free to load a registry the vectors disagree with.
    /// </remarks>
    [Fact]
    public void RegistryLimitsMatchTheVectorLimits()
    {
        ProtocolRegistry registry = Registry();

        using JsonDocument document = VectorLoader.Load(VectorFile);
        JsonElement vectorLimits = document.RootElement.GetProperty("default_limits");

        SortedSet<string> vectorNames = [.. vectorLimits.EnumerateObject().Select(p => p.Name)];
        SortedSet<string> registryNames = [.. registry.DefaultLimits.Keys];

        Assert.Equal(vectorNames, registryNames);

        foreach (JsonProperty limit in vectorLimits.EnumerateObject())
        {
            Assert.Equal(limit.Value.GetUInt32(), registry.DefaultLimit(limit.Name));
        }
    }

    /// <summary>Every message type gated by a capability names a registered capability.</summary>
    [Fact]
    public void EveryGatedMessageTypeNamesARegisteredCapability()
    {
        ProtocolRegistry registry = Registry();

        foreach (MessageType type in registry.MessageTypes)
        {
            if (registry.CapabilityFor(type.Code) is { } capability)
            {
                Assert.True(
                    registry.IsKnownCapability(capability),
                    $"message type {type.Name} is gated by unknown capability '{capability}'");
            }
        }
    }

    /// <summary>
    /// Handshake, control, capability and error frames are usable before anything is negotiated.
    /// </summary>
    /// <remarks>
    /// If HELLO, HELLO_ACK, AUTH, ERROR or SESSION_END needed a capability, the
    /// session could never start and an empty negotiation could never even be
    /// reported. GET_CAPABILITIES and CAPABILITIES are in this set for the same
    /// reason one level up: they are how a controller asks what a device can do,
    /// so gating them behind a capability would mean the answer could only be
    /// requested by someone who already knew it.
    /// </remarks>
    [Theory]
    [InlineData("HELLO")]
    [InlineData("HELLO_ACK")]
    [InlineData("AUTH")]
    [InlineData("AUTH_OK")]
    [InlineData("PING")]
    [InlineData("PONG")]
    [InlineData("CHANNEL_OPEN")]
    [InlineData("CHANNEL_OPENED")]
    [InlineData("CHANNEL_CLOSE")]
    [InlineData("ERROR")]
    [InlineData("SESSION_END")]
    [InlineData("GET_CAPABILITIES")]
    [InlineData("CAPABILITIES")]
    public void SessionCriticalMessageTypesAreUngated(string name)
    {
        ProtocolRegistry registry = Registry();
        MessageType type = registry.FindMessageType(name) ?? throw new InvalidOperationException($"no {name}");

        Assert.Null(registry.CapabilityFor(type.Code));
        Assert.True(CapabilityNegotiation.IsMessageTypeUsable(registry, type.Code, []));
    }

    /// <summary>
    /// Device information is gated by <c>device.info</c>, deliberately.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The negotiate.empty-intersection vector's prose says the "device
    /// information and error channels must remain usable for diagnostics". Read
    /// strictly, that would make DEVICE_INFO ungated. The registry says
    /// otherwise: DEVICE_INFO and DEVICE_INFO_RESULT are gated by device.info,
    /// and device.info is an ordinary capability a controller may decline to
    /// offer.
    /// </para>
    /// <para>
    /// The registry is normative and the prose is not, so this test pins the
    /// registry's answer. Nothing is lost diagnostically: ERROR,
    /// GET_CAPABILITIES and CAPABILITIES are ungated, so a controller with an
    /// empty negotiated set can still ask the device what it supports and can
    /// still receive the refusal that says why. What it cannot do is read device
    /// metadata it did not negotiate for, which is the correct default for a
    /// capability that exposes hardware identifiers.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("DEVICE_INFO")]
    [InlineData("DEVICE_INFO_RESULT")]
    public void DeviceInformationIsGatedByTheDeviceInfoCapability(string name)
    {
        ProtocolRegistry registry = Registry();
        MessageType type = registry.FindMessageType(name) ?? throw new InvalidOperationException($"no {name}");

        Assert.Equal("device.info", registry.CapabilityFor(type.Code));
        Assert.False(CapabilityNegotiation.IsMessageTypeUsable(registry, type.Code, []));
        Assert.True(CapabilityNegotiation.IsMessageTypeUsable(registry, type.Code, ["device.info"]));
    }

    // ---- Negotiation -------------------------------------------------------

    /// <summary>Every negotiation vector reproduces from its own inputs.</summary>
    [Fact]
    public void EveryNegotiationVectorReproduces()
    {
        ProtocolRegistry registry = Registry();
        int count = 0;

        foreach (JsonElement vector in NegotiationVectors())
        {
            string id = vector.GetProperty("id").GetString()!;

            IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
                registry,
                Strings(vector, "agent_capabilities"),
                Strings(vector, "agent_disabled"),
                Strings(vector, "controller_offered"));

            string[] expected = Strings(vector, "expected_negotiated");

            Assert.Equal(expected.OrderBy(x => x, StringComparer.Ordinal), negotiated);
            count++;
        }

        Assert.True(count >= 7, $"expected at least 7 negotiation vectors, found {count}");
    }

    /// <summary>The negotiated set is the intersection, never the union.</summary>
    [Fact]
    public void NegotiationIsAnIntersection()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["screen.mirror", "input.touch", "input.key", "device.info"],
            [],
            ["screen.mirror"]);

        Assert.Equal(["screen.mirror"], negotiated);
    }

    /// <summary>A capability the controller never offered must not be negotiated.</summary>
    /// <remarks>
    /// An agent supporting something is not consent to use it. The controller's
    /// offer is how it states its intent, and an agent that returned capabilities
    /// the controller never asked for would be making decisions for it.
    /// </remarks>
    [Fact]
    public void UnofferedCapabilityIsNotNegotiated()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["screen.mirror", "shell.exec"],
            [],
            ["screen.mirror"]);

        Assert.DoesNotContain("shell.exec", negotiated);
    }

    /// <summary>An operator-disabled capability is absent even when both sides support it.</summary>
    [Fact]
    public void OperatorDisabledBeatsTheIntersection()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["screen.mirror", "shell.exec", "input.touch"],
            ["shell.exec"],
            ["screen.mirror", "shell.exec", "input.touch"]);

        Assert.Equal(["input.touch", "screen.mirror"], negotiated);
        Assert.DoesNotContain("shell.exec", negotiated);
    }

    /// <summary>An empty intersection is legal and not an error.</summary>
    [Fact]
    public void EmptyNegotiationIsLegal()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["shell.exec"],
            [],
            ["screen.mirror"]);

        Assert.Empty(negotiated);

        // The session is still diagnosable: the controller can ask what the
        // device supports and can receive the refusal, even with nothing
        // negotiated. These are ungated precisely for this case.
        foreach (string name in new[] { "GET_CAPABILITIES", "CAPABILITIES", "ERROR" })
        {
            Assert.True(
                CapabilityNegotiation.IsMessageTypeUsable(registry, registry.FindMessageType(name)!.Code, negotiated),
                $"{name} must remain usable when nothing was negotiated");
        }
    }

    /// <summary>An unknown capability name is ignored, in the offer and in the answer.</summary>
    [Fact]
    public void UnknownCapabilityNameIsIgnored()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["screen.mirror", "future.capability.v2"],
            [],
            ["screen.mirror", "future.capability.v2"]);

        Assert.Equal(["screen.mirror"], negotiated);
        Assert.DoesNotContain("future.capability.v2", negotiated);
    }

    /// <summary>A duplicated capability collapses to one entry.</summary>
    [Fact]
    public void DuplicateNamesCollapse()
    {
        ProtocolRegistry registry = Registry();

        IReadOnlyList<string> negotiated = CapabilityNegotiation.Negotiate(
            registry,
            ["screen.mirror", "screen.mirror", "input.touch"],
            [],
            ["screen.mirror", "screen.mirror"]);

        Assert.Equal(["screen.mirror"], negotiated);
    }

    /// <summary>The result is sorted, so it is a canonical value two peers can compare.</summary>
    [Fact]
    public void NegotiatedSetIsSortedAndStable()
    {
        ProtocolRegistry registry = Registry();

        string[] offered = ["telemetry.stats", "input.key", "clipboard.read", "screen.mirror"];

        IReadOnlyList<string> forward = CapabilityNegotiation.Negotiate(registry, offered, [], offered);
        IReadOnlyList<string> reversed = CapabilityNegotiation.Negotiate(registry, [.. offered.Reverse()], [],
            [.. offered.Reverse()]);

        Assert.Equal(forward, reversed);
        Assert.Equal(forward.OrderBy(x => x, StringComparer.Ordinal), forward);
    }

    // ---- Gating ------------------------------------------------------------

    /// <summary>A gated message type is refused with ERR_UNSUPPORTED_FEATURE.</summary>
    [Theory]
    [InlineData("VIDEO_FRAME")]
    [InlineData("INPUT_TOUCH")]
    [InlineData("SHELL_EXEC")]
    [InlineData("FILE_PULL")]
    [InlineData("CLIPBOARD_GET")]
    public void GatedMessageTypeIsRefusedWithoutItsCapability(string name)
    {
        ProtocolRegistry registry = Registry();
        MessageType type = registry.FindMessageType(name) ?? throw new InvalidOperationException($"no {name}");

        Assert.NotNull(registry.CapabilityFor(type.Code));
        Assert.False(CapabilityNegotiation.IsMessageTypeUsable(registry, type.Code, []));
        Assert.Equal(ErrorCodes.UnsupportedFeature, CapabilityNegotiation.RejectionFor(registry, type.Code, []));
    }

    /// <summary>A gated message type is usable once its capability is negotiated.</summary>
    [Fact]
    public void GatedMessageTypeIsUsableWithItsCapability()
    {
        ProtocolRegistry registry = Registry();

        byte videoFrame = registry.FindMessageType("VIDEO_FRAME")!.Code;
        byte shellExec = registry.FindMessageType("SHELL_EXEC")!.Code;

        Assert.True(CapabilityNegotiation.IsMessageTypeUsable(registry, videoFrame, ["screen.mirror"]));
        Assert.False(CapabilityNegotiation.IsMessageTypeUsable(registry, shellExec, ["screen.mirror"]));

        // A capability grants only what it names: screen.mirror must not enable
        // shell execution.
        Assert.Null(CapabilityNegotiation.RejectionFor(registry, videoFrame, ["screen.mirror"]));
    }

    /// <summary>An unregistered message type is refused with ERR_UNSUPPORTED_MESSAGE.</summary>
    /// <remarks>
    /// Distinct from ERR_UNSUPPORTED_FEATURE on purpose: an unknown message type
    /// is a version mismatch, while an unnegotiated capability usually means a
    /// device-side switch is off. The registry's reply rule says neither ends the
    /// session, so this must be a refusal rather than a protocol error.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(200)]
    [InlineData(255)]
    public void UnregisteredMessageTypeIsRefusedAsUnsupported(byte code)
    {
        ProtocolRegistry registry = Registry();

        Assert.Null(registry.FindMessageType(code));
        Assert.False(CapabilityNegotiation.IsMessageTypeUsable(registry, code, ["screen.mirror"]));
        Assert.Equal(ErrorCodes.UnsupportedMessage, CapabilityNegotiation.RejectionFor(registry, code, []));
    }

    /// <summary>Neither refusal ends the session.</summary>
    [Fact]
    public void UnsupportedRefusalsAreRecoverable()
    {
        Assert.False(ErrorCodes.UnsupportedMessage.IsFatal);
        Assert.False(ErrorCodes.UnsupportedFeature.IsFatal);
    }

    // ---- Limits ------------------------------------------------------------

    /// <summary>Every limit clamp vector reproduces.</summary>
    [Fact]
    public void EveryLimitClampVectorReproduces()
    {
        int count = 0;

        foreach (JsonElement vector in ClampVectors())
        {
            string id = vector.GetProperty("id").GetString()!;

            if (vector.TryGetProperty("expected_applied", out JsonElement expected)
                && vector.TryGetProperty("requested", out JsonElement requested))
            {
                // A vector that only exercises the screen rule omits agent_limits;
                // the protocol's own defaults stand in, so the vector is still
                // driven entirely by its own file.
                JsonElement agentLimits = vector.TryGetProperty("agent_limits", out JsonElement limits)
                    ? limits
                    : default;

                JsonElement screen = vector.TryGetProperty("screen", out JsonElement s) ? s : default;

                Limits.VideoGeometry geometry = Limits.ClampVideoGeometry(
                    requested.TryGetProperty("max_width", out JsonElement rw) ? rw.GetInt32() : 0,
                    requested.TryGetProperty("max_height", out JsonElement rh) ? rh.GetInt32() : 0,
                    requested.TryGetProperty("fps", out JsonElement rf) ? rf.GetInt32() : 0,
                    agentLimits.ValueKind == JsonValueKind.Object
                        ? agentLimits.GetProperty("max_video_width").GetInt32()
                        : (int)Registry().DefaultLimit("max_video_width")!,
                    agentLimits.ValueKind == JsonValueKind.Object
                        ? agentLimits.GetProperty("max_video_height").GetInt32()
                        : (int)Registry().DefaultLimit("max_video_height")!,
                    agentLimits.ValueKind == JsonValueKind.Object
                        ? agentLimits.GetProperty("max_video_fps").GetInt32()
                        : (int)Registry().DefaultLimit("max_video_fps")!,
                    screen.ValueKind == JsonValueKind.Object ? screen.GetProperty("width").GetInt32() : 0,
                    screen.ValueKind == JsonValueKind.Object ? screen.GetProperty("height").GetInt32() : 0);

                Assert.Equal(expected.GetProperty("width").GetInt32(), geometry.Width);
                Assert.Equal(expected.GetProperty("height").GetInt32(), geometry.Height);

                if (expected.TryGetProperty("fps", out JsonElement expectedFps))
                {
                    Assert.Equal(expectedFps.GetInt32(), geometry.Fps);
                }

                count++;
            }
        }

        Assert.True(count >= 2, $"expected at least 2 geometry clamp vectors, found {count}");
    }

    /// <summary>A request over the agent's video ceiling is clamped, not refused.</summary>
    [Fact]
    public void OverCeilingVideoRequestIsClamped()
    {
        Limits.VideoGeometry geometry = Limits.ClampVideoGeometry(
            requestedWidth: 2560, requestedHeight: 1440, requestedFps: 120,
            maxWidth: 1920, maxHeight: 1080, maxFps: 60);

        Assert.Equal(1920, geometry.Width);
        Assert.Equal(1080, geometry.Height);
        Assert.Equal(60, geometry.Fps);
    }

    /// <summary>A request larger than the screen is scaled to the screen's aspect ratio.</summary>
    /// <remarks>
    /// The vector's exact numbers: a 1920x1080 landscape request on a 1080x2400
    /// portrait screen becomes 486x1080. Both dimensions must be even, because
    /// H.264 cannot encode an odd dimension.
    /// </remarks>
    [Fact]
    public void OverScreenVideoRequestIsScaledToTheScreen()
    {
        Limits.VideoGeometry geometry = Limits.ClampVideoGeometry(
            requestedWidth: 1920, requestedHeight: 1080, requestedFps: 0,
            maxWidth: 1920, maxHeight: 1080, maxFps: 60,
            screenWidth: 1080, screenHeight: 2400);

        Assert.Equal(486, geometry.Width);
        Assert.Equal(1080, geometry.Height);
    }

    /// <summary>Both clamped dimensions are always even.</summary>
    [Theory]
    [InlineData(1920, 1080, 1080, 2400)]
    [InlineData(2560, 1440, 1440, 2960)]
    [InlineData(1281, 721, 1080, 2400)]
    [InlineData(100, 99, 0, 0)]
    [InlineData(3, 3, 0, 0)]
    public void ClampedGeometryIsAlwaysEvenAndPositive(int width, int height, int screenWidth, int screenHeight)
    {
        Limits.VideoGeometry geometry = Limits.ClampVideoGeometry(
            width, height, 0, 1920, 1080, 60, screenWidth, screenHeight);

        Assert.True(geometry.Width > 0);
        Assert.True(geometry.Height > 0);
        Assert.Equal(0, geometry.Width % 2);
        Assert.Equal(0, geometry.Height % 2);
    }

    /// <summary>Zero means "use your ceiling".</summary>
    [Fact]
    public void ZeroRequestMeansUseTheCeiling()
    {
        Limits.VideoGeometry geometry = Limits.ClampVideoGeometry(0, 0, 0, 1920, 1080, 60);

        Assert.Equal(1920, geometry.Width);
        Assert.Equal(1080, geometry.Height);
        Assert.Equal(60, geometry.Fps);
    }

    /// <summary>An oversized file chunk is refused, not truncated.</summary>
    /// <remarks>
    /// The limit exists to bound memory, so the request must be refused before
    /// any buffer is sized. Clamping it here would allocate the very thing the
    /// limit prevents.
    /// </remarks>
    [Fact]
    public void OversizedFileChunkIsRefused()
    {
        Assert.Equal(ErrorCodes.FrameTooLarge, Limits.ValidateFileChunk(4194304, 262144));
        Assert.Null(Limits.ValidateFileChunk(262144, 262144));
        Assert.Null(Limits.ValidateFileChunk(0, 262144));
    }

    /// <summary>A shell deadline over the agent's maximum is clamped.</summary>
    [Fact]
    public void OverLongShellTimeoutIsClamped()
    {
        Assert.Equal(30000, Limits.ClampShellTimeout(600000, 30000));
        Assert.Equal(5000, Limits.ClampShellTimeout(5000, 30000));
        Assert.Equal(30000, Limits.ClampShellTimeout(0, 30000));
    }

    /// <summary>An over-long gesture is a resource error, not a size error.</summary>
    /// <remarks>
    /// RFC-0001 section 8.2 requires ERR_RESOURCE_EXHAUSTED because an over-long
    /// gesture is a playback cost rather than a buffer cost. This is the rule
    /// that originally depended on a limit the RFC never declared.
    /// </remarks>
    [Fact]
    public void OverLongGestureIsAResourceError()
    {
        Assert.Equal(ErrorCodes.ResourceExhausted, Limits.ValidateGestureSteps(257, 256));
        Assert.Null(Limits.ValidateGestureSteps(256, 256));
        Assert.NotEqual(ErrorCodes.FrameTooLarge, Limits.ValidateGestureSteps(257, 256));
    }

    /// <summary>A non-positive video ceiling is a caller error, not a silent zero.</summary>
    [Theory]
    [InlineData(0, 1080)]
    [InlineData(1920, 0)]
    [InlineData(-1, 1080)]
    public void NonPositiveVideoCeilingIsRejected(int maxWidth, int maxHeight)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Limits.ClampVideoGeometry(100, 100, 30, maxWidth, maxHeight, 60));
    }
}
