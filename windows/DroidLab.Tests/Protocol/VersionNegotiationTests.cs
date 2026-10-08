using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for version negotiation (RFC-0001 sections 5 and 10).
/// </summary>
public sealed class VersionNegotiationTests
{
    private const string VectorFile = "version-negotiation.json";

    private static IEnumerable<JsonElement> Vectors() => VectorLoader.Vectors(VectorFile);

    private static IEnumerable<JsonElement> CiRules() => VectorLoader.Vectors(VectorFile, "ci_rules");

    private static ProtocolVersion[] Versions(JsonElement vector, string property) =>
        vector.TryGetProperty(property, out JsonElement array)
            ? [.. array.EnumerateArray().Select(e => ProtocolVersion.Parse(e.GetString()!))]
            : [];

    // ---- Version parsing ---------------------------------------------------

    /// <summary>A well-formed version parses into major and minor.</summary>
    [Theory]
    [InlineData("1.0", 1, 0)]
    [InlineData("1.1", 1, 1)]
    [InlineData("2.0", 2, 0)]
    [InlineData("255.255", 255, 255)]
    public void VersionParsesIntoMajorAndMinor(string text, byte major, byte minor)
    {
        ProtocolVersion version = ProtocolVersion.Parse(text);

        Assert.Equal(major, version.Major);
        Assert.Equal(minor, version.Minor);
        Assert.Equal(text, version.ToString());
    }

    /// <summary>
    /// A malformed version is rejected rather than guessed at.
    /// </summary>
    /// <remarks>
    /// A permissive parser is the same failure as a silent downgrade: it accepts
    /// something the format does not define and picks an interpretation. If the
    /// peer meant something else, the disagreement surfaces later as a decoding
    /// bug rather than as a version error.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("1")]
    [InlineData("1.")]
    [InlineData(".0")]
    [InlineData("1.0.3")]
    [InlineData("1.-1")]
    [InlineData("v1.0")]
    [InlineData("1.0 ")]
    [InlineData(" 1.0")]
    [InlineData("one.zero")]
    [InlineData("256.0")]
    [InlineData("1..0")]
    public void MalformedVersionIsRejected(string text)
    {
        Assert.False(ProtocolVersion.TryParse(text, out _));
        Assert.Throws<FormatException>(() => ProtocolVersion.Parse(text));
    }

    /// <summary>A null version is rejected rather than throwing.</summary>
    [Fact]
    public void NullVersionIsRejected()
    {
        Assert.False(ProtocolVersion.TryParse(null, out _));
    }

    /// <summary>Ordering is major first, then minor.</summary>
    [Fact]
    public void OrderingIsMajorThenMinor()
    {
        Assert.True(ProtocolVersion.Parse("2.0") > ProtocolVersion.Parse("1.9"));
        Assert.True(ProtocolVersion.Parse("1.2") > ProtocolVersion.Parse("1.1"));
        Assert.True(ProtocolVersion.Parse("1.0") == ProtocolVersion.Parse("1.0"));
        Assert.True(ProtocolVersion.Parse("1.0") >= ProtocolVersion.Parse("1.0"));
    }

    /// <summary>The version this codec implements is the major the header carries.</summary>
    [Fact]
    public void CurrentVersionMatchesTheHeaderMajor()
    {
        Assert.Equal(1, ProtocolVersion.Current.Major);
        Assert.Equal(ProtocolVersion.HeaderMajorVersion, ProtocolVersion.Current.Major);
        Assert.Equal("1.0", ProtocolVersion.Current.ToString());
    }

    // ---- The vector-driven rule -------------------------------------------

    /// <summary>Every version negotiation vector reproduces from its own inputs.</summary>
    [Fact]
    public void EveryVersionVectorReproduces()
    {
        int checked_ = 0;
        int skipped = 0;

        foreach (JsonElement vector in Vectors())
        {
            string id = vector.GetProperty("id").GetString()!;

            // Some vectors describe the header rule, a change-classification
            // rule or an answer-validation rule rather than a list intersection.
            if (!vector.TryGetProperty("controller_supported", out _)
                || !vector.TryGetProperty("agent_supported", out _))
            {
                skipped++;
                continue;
            }

            ProtocolVersion[] controller = Versions(vector, "controller_supported");
            ProtocolVersion[] agent = Versions(vector, "agent_supported");

            VersionNegotiationResult result = VersionNegotiation.Negotiate(controller, agent);

            bool expectSuccess = vector.TryGetProperty("expected_negotiated", out JsonElement expected)
                && expected.ValueKind == JsonValueKind.String;

            if (expectSuccess)
            {
                ProtocolVersion want = ProtocolVersion.Parse(expected.GetString()!);
                Assert.True(result.Succeeded, $"{id}: expected {want} but negotiation failed");
                Assert.Equal(want, result.Version);
                Assert.Null(result.Error);
            }
            else
            {
                Assert.False(result.Succeeded, $"{id}: expected no agreement but got {result.Version}");
                Assert.Null(result.Version);
                Assert.Equal(ErrorCodes.VersionMismatch, result.Error);
            }

            // A declared severity, when present, must be fatal.
            if (vector.TryGetProperty("expected_severity", out JsonElement severity))
            {
                Assert.Equal("fatal", severity.GetString());
                Assert.True(ErrorCodes.VersionMismatch.IsFatal);
            }

            checked_++;
        }

        Assert.True(checked_ >= 7, $"expected at least 7 negotiation vectors, checked {checked_}");
        Assert.True(skipped > 0, "expected some vectors to describe header or change rules, not intersections");
    }

    // ---- The rule itself ---------------------------------------------------

    /// <summary>The highest common version wins, not the controller's first preference.</summary>
    /// <remarks>
    /// The vector states this explicitly: a controller listing 2.0 first still
    /// agrees 1.1 when the agent knows 1.1 and 1.0. The answer must not depend on
    /// how either peer sorted its own list.
    /// </remarks>
    [Fact]
    public void HighestCommonVersionWinsRegardlessOfOrder()
    {
        ProtocolVersion[] controller = [ProtocolVersion.Parse("2.0"), ProtocolVersion.Parse("1.1"),
            ProtocolVersion.Parse("1.0")];
        ProtocolVersion[] agent = [ProtocolVersion.Parse("1.1"), ProtocolVersion.Parse("1.0")];

        Assert.Equal(ProtocolVersion.Parse("1.1"), VersionNegotiation.HighestCommonVersion(controller, agent));

        // Reversing either list must not change the answer.
        Assert.Equal(
            ProtocolVersion.Parse("1.1"),
            VersionNegotiation.HighestCommonVersion(controller, [.. agent.Reverse()]));
        Assert.Equal(
            ProtocolVersion.Parse("1.1"),
            VersionNegotiation.HighestCommonVersion([.. controller.Reverse()], agent));
    }

    /// <summary>An exact match is the common case.</summary>
    [Fact]
    public void ExactMatchAgrees()
    {
        ProtocolVersion[] both = [ProtocolVersion.Parse("1.0")];

        Assert.Equal(ProtocolVersion.Parse("1.0"), VersionNegotiation.HighestCommonVersion(both, both));
    }

    /// <summary>No overlap fails rather than picking something.</summary>
    [Fact]
    public void NoOverlapFails()
    {
        VersionNegotiationResult result = VersionNegotiation.Negotiate(
            [ProtocolVersion.Parse("2.0")],
            [ProtocolVersion.Parse("1.0")]);

        Assert.False(result.Succeeded);
        Assert.Null(result.Version);
        Assert.Equal(ErrorCodes.VersionMismatch, result.Error);
        Assert.True(result.Error!.IsFatal);
    }

    /// <summary>
    /// An unknown version is not treated as the version this implementation supports.
    /// </summary>
    /// <remarks>
    /// This is the silent-downgrade rule from the agent's side. A controller
    /// offering "9.9" must be refused, not interpreted as "you probably meant
    /// 1.0". Guessing here means two peers believe they agreed while disagreeing.
    /// </remarks>
    [Fact]
    public void UnknownVersionIsNotDowngraded()
    {
        VersionNegotiationResult result = VersionNegotiation.Negotiate(
            [ProtocolVersion.Parse("9.9")],
            [ProtocolVersion.Parse("1.0")]);

        Assert.False(result.Succeeded);
        Assert.Equal(ErrorCodes.VersionMismatch, result.Error);
    }

    /// <summary>An empty offer from either side fails rather than defaulting.</summary>
    [Fact]
    public void EmptyOfferFails()
    {
        Assert.False(VersionNegotiation.Negotiate([], [ProtocolVersion.Parse("1.0")]).Succeeded);
        Assert.False(VersionNegotiation.Negotiate([ProtocolVersion.Parse("1.0")], []).Succeeded);
        Assert.False(VersionNegotiation.Negotiate([], []).Succeeded);
    }

    // ---- The header rule ---------------------------------------------------

    /// <summary>The header's Version field carries the major number only.</summary>
    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)2)]
    [InlineData((byte)255)]
    public void HeaderVersionOtherThanOneIsAMismatch(byte headerVersion)
    {
        Assert.Equal(ErrorCodes.VersionMismatch, VersionNegotiation.ValidateHeaderVersion(headerVersion));
    }

    /// <summary>Major 1 is accepted, which covers every 1.x release.</summary>
    /// <remarks>
    /// This is why minor versions can be added without changing the frame
    /// layout: the header byte stays 1 and the full string travels in HELLO.
    /// </remarks>
    [Fact]
    public void HeaderVersionOneIsAccepted()
    {
        Assert.Null(VersionNegotiation.ValidateHeaderVersion(1));
    }

    // ---- The agent's answer ------------------------------------------------

    /// <summary>An agent answering an offered version is accepted.</summary>
    [Fact]
    public void AgentAnsweringAnOfferedVersionIsAccepted()
    {
        ProtocolVersion[] offered = [ProtocolVersion.Parse("1.1"), ProtocolVersion.Parse("1.0")];

        Assert.Null(VersionNegotiation.ValidateAgentAnswer(offered, ProtocolVersion.Parse("1.0")));
        Assert.Null(VersionNegotiation.ValidateAgentAnswer(offered, ProtocolVersion.Parse("1.1")));
    }

    /// <summary>An agent answering an unoffered version is a violation.</summary>
    /// <remarks>
    /// The vector's case: the controller offers only 1.1, the agent answers 1.0.
    /// The controller must abort rather than continue, because the agent has
    /// broken the rule and continuing would make the controller's version list
    /// meaningless.
    /// </remarks>
    [Fact]
    public void AgentAnsweringAnUnofferedVersionIsRejected()
    {
        ErrorCode? error = VersionNegotiation.ValidateAgentAnswer(
            [ProtocolVersion.Parse("1.1")],
            ProtocolVersion.Parse("1.0"));

        Assert.Equal(ErrorCodes.VersionMismatch, error);
        Assert.True(error!.IsFatal);
    }

    // ---- Change classification --------------------------------------------

    /// <summary>An additive change must not bump the major version.</summary>
    /// <remarks>
    /// A new message type, capability name or optional body key is ignored by an
    /// old peer, and the unknown-name rules in negotiation are what make that
    /// safe. Bumping the version for these would break compatibility for no
    /// reason and would make the version number stop meaning "the wire changed".
    /// </remarks>
    [Theory]
    [InlineData("add_capability_and_message_type")]
    [InlineData("add_optional_body_key")]
    [InlineData("add_message_type")]
    public void AdditiveChangeDoesNotBumpTheVersion(string changeKind)
    {
        Assert.False(VersionNegotiation.RequiresMajorBump(changeKind));
    }

    /// <summary>A breaking change requires a major bump.</summary>
    [Theory]
    [InlineData("change_default_of_video_codec")]
    [InlineData("change_field_meaning")]
    [InlineData("remove_field")]
    public void BreakingChangeRequiresAMajorBump(string changeKind)
    {
        Assert.True(VersionNegotiation.RequiresMajorBump(changeKind));
    }

    /// <summary>
    /// An unclassified change is refused rather than assumed additive.
    /// </summary>
    /// <remarks>
    /// The safe default for an unknown change is "this needs a major bump",
    /// because assuming additive is the answer that silently breaks old peers.
    /// Throwing forces the change to be classified deliberately instead of
    /// inheriting a permissive default.
    /// </remarks>
    [Fact]
    public void UnclassifiedChangeIsRefused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => VersionNegotiation.RequiresMajorBump("something_new_nobody_classified"));
    }

    /// <summary>
    /// The change kinds named in the vectors are all classified.
    /// </summary>
    /// <remarks>
    /// If a vector names a change kind this code cannot classify, the vector is
    /// describing a rule nothing implements. Checking each one against the
    /// classifier is what keeps the vector file and the codec from drifting.
    /// </remarks>
    [Fact]
    public void EveryVectorChangeKindIsClassified()
    {
        int seen = 0;

        foreach (JsonElement vector in Vectors())
        {
            if (!vector.TryGetProperty("change_kind", out JsonElement kind))
            {
                continue;
            }

            string name = kind.GetString()!;
            bool bumps = VersionNegotiation.RequiresMajorBump(name);

            if (vector.TryGetProperty("expected_version_bump", out JsonElement expected))
            {
                Assert.Equal(expected.GetBoolean(), bumps);
            }

            seen++;
        }

        Assert.True(seen >= 2, $"expected at least 2 change-classification vectors, found {seen}");
    }

    // ---- The CI rules the vectors describe --------------------------------

    /// <summary>
    /// Every CI rule names files that really exist where it says they do.
    /// </summary>
    /// <remarks>
    /// These rules are process, not runtime, so nothing else checks them. A rule
    /// that watches or requires a path which does not exist is a check that
    /// silently never fires, which is the failure mode the whole vector
    /// apparatus exists to avoid. The repository root is found by walking up
    /// from the test output directory.
    /// </remarks>
    [Fact]
    public void EveryCiRuleNamesRealFiles()
    {
        string root = FindRepositoryRoot();
        int rules = 0;

        foreach (JsonElement rule in CiRules())
        {
            string id = rule.GetProperty("id").GetString()!;

            foreach (string property in new[] { "watch", "require_touch", "require_registry" })
            {
                if (!rule.TryGetProperty(property, out JsonElement paths))
                {
                    continue;
                }

                foreach (JsonElement pathElement in paths.EnumerateArray())
                {
                    string path = pathElement.GetString()!;
                    if (path.StartsWith("protocol/vectors/", StringComparison.Ordinal) && path.EndsWith("/**", StringComparison.Ordinal))
                    {
                        continue; // a glob over a directory that must exist
                    }

                    string bare = path.Split('#')[0]
                        .Replace("/**", string.Empty, StringComparison.Ordinal);

                    Assert.True(
                        Directory.Exists(Path.Combine(root, bare)) || File.Exists(Path.Combine(root, bare)),
                        $"{id}: rule names '{path}', which does not exist in the repository");
                }
            }

            rules++;
        }

        Assert.True(rules >= 3, $"expected at least 3 CI rules, found {rules}");
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "package.json"))
                && Directory.Exists(Path.Combine(directory.FullName, "protocol")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "could not find the repository root above the test output directory; the CI rules name " +
            "repository-relative paths, so without the root they cannot be checked at all");
    }
}
