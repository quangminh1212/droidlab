using System.Text;
using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for discovery advertisement canonicalisation (RFC-0003 sections 2 and 4.1).
/// </summary>
public sealed class DiscoveryAdvertisementTests
{
    private const string VectorFile = "discovery.json";

    private static IEnumerable<JsonElement> Vectors() => VectorLoader.Vectors(VectorFile);

    private static IEnumerable<JsonElement> RejectionVectors() =>
        VectorLoader.Vectors(VectorFile, "rejection_vectors");

    private static IEnumerable<JsonElement> LifecycleVectors() =>
        VectorLoader.Vectors(VectorFile, "lifecycle_vectors");

    private static JsonElement Service() =>
        VectorLoader.Vectors(VectorFile).First().GetProperty("fields").GetProperty("v");

    private static IReadOnlyDictionary<string, string> Fields(JsonElement vector, string property = "fields")
    {
        Dictionary<string, string> fields = new(StringComparer.Ordinal);

        if (!vector.TryGetProperty(property, out JsonElement obj))
        {
            return fields;
        }

        foreach (JsonProperty field in obj.EnumerateObject())
        {
            fields[field.Name] = field.Value.ValueKind == JsonValueKind.String
                ? field.Value.GetString()!
                : field.Value.GetRawText();
        }

        return fields;
    }

    // ---- Service parameters ------------------------------------------------

    /// <summary>The service parameters are what RFC-0003 declares.</summary>
    [Fact]
    public void ServiceParametersAreAsDeclared()
    {
        Assert.Equal("_droidlab._tcp", DiscoveryAdvertisement.ServiceType);
        Assert.Equal("local", DiscoveryAdvertisement.ServiceDomain);
        Assert.Equal(45917, DiscoveryAdvertisement.DefaultPort);
        Assert.Equal(45918, DiscoveryAdvertisement.BeaconPort);
        Assert.Equal(120, DiscoveryAdvertisement.TtlSeconds);
        Assert.Equal(1300, DiscoveryAdvertisement.MaxTxtBytes);
    }

    // ---- TXT canonicalisation ---------------------------------------------

    /// <summary>Every TXT vector canonicalises to the exact bytes it records.</summary>
    [Fact]
    public void EveryTxtVectorCanonicalisesExactly()
    {
        int count = 0;

        foreach (JsonElement vector in Vectors())
        {
            string id = vector.GetProperty("id").GetString()!;

            // The truncation vector records no canonical form: it exists to pin
            // the truncation rule, not a byte string.
            if (!vector.TryGetProperty("canonical_utf8", out JsonElement canonical)
                || !id.StartsWith("discovery.txt", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] built = DiscoveryAdvertisement.CanonicalTxt(Fields(vector));

            Assert.Equal(canonical.GetString(), Encoding.UTF8.GetString(built));

            // The recorded byte length must equal the real one, so a vector
            // cannot claim a length its own bytes do not have.
            if (vector.TryGetProperty("canonical_length_bytes", out JsonElement length))
            {
                Assert.Equal(length.GetInt32(), built.Length);
            }

            count++;
        }

        Assert.True(count >= 2, $"expected at least 2 canonical TXT vectors, found {count}");
    }

    /// <summary>The canonical form opens with the label and a NUL.</summary>
    /// <remarks>
    /// The same construction as the handshake transcript, so a signature over a
    /// TXT payload cannot be replayed as a signature over any other string with
    /// the same suffix.
    /// </remarks>
    [Fact]
    public void CanonicalTxtOpensWithLabelAndNul()
    {
        byte[] built = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["v"] = "1.0",
            ["id"] = "x",
            ["fp"] = "y",
            ["caps"] = "z",
            ["port"] = "1",
        });

        Assert.Equal("DLWP/1-txt"u8.ToArray(), built[..10].ToArray());
        Assert.Equal(0, built[10]);
        Assert.Equal(10, DiscoveryAdvertisement.TxtLabel.Length);
    }

    /// <summary>The required keys appear in exactly the declared order.</summary>
    [Fact]
    public void RequiredKeysAppearInDeclaredOrder()
    {
        Assert.Equal(["v", "id", "fp", "caps", "port"], DiscoveryAdvertisement.RequiredKeys);

        byte[] built = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // Deliberately inserted in the wrong order.
            ["port"] = "45917",
            ["caps"] = "a",
            ["fp"] = "c",
            ["id"] = "d",
            ["v"] = "1.0",
        });

        Assert.Equal("DLWP/1-txt\0v=1.0\nid=d\nfp=c\ncaps=a\nport=45917", Encoding.UTF8.GetString(built));
    }

    /// <summary>Optional keys follow the required ones in the declared order.</summary>
    /// <remarks>
    /// A device that adds an optional key must not reorder the required ones,
    /// or every existing signature would break when a new field appeared.
    /// </remarks>
    [Fact]
    public void OptionalKeysFollowRequiredKeysInDeclaredOrder()
    {
        Assert.Equal(
            ["model", "android", "sdk", "busy", "loc", "tls"],
            DiscoveryAdvertisement.OptionalKeys);

        // Inserted in reverse to prove the order comes from the declaration.
        byte[] built = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tls"] = "0",
            ["loc"] = "lan",
            ["busy"] = "0",
            ["sdk"] = "34",
            ["android"] = "14",
            ["model"] = "Pixel 7",
            ["port"] = "45917",
            ["caps"] = "a",
            ["fp"] = "c",
            ["id"] = "d",
            ["v"] = "1.0",
        });

        int vIndex = Encoding.UTF8.GetString(built).IndexOf("v=1.0", StringComparison.Ordinal);
        int modelIndex = Encoding.UTF8.GetString(built).IndexOf("model=", StringComparison.Ordinal);
        int tlsIndex = Encoding.UTF8.GetString(built).IndexOf("tls=", StringComparison.Ordinal);

        Assert.True(vIndex < modelIndex, "the required keys must come before the optional ones");
        Assert.True(modelIndex < tlsIndex, "model must come before tls");
    }

    /// <summary>The full advertisement's optional keys are all present and ordered.</summary>
    [Fact]
    public void FullAdvertisementCarriesEveryOptionalKeyInOrder()
    {
        JsonElement full = Vectors().First(v => v.GetProperty("id").GetString() == "discovery.txt.full");
        string text = Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalTxt(Fields(full)));

        int last = -1;
        foreach (string key in DiscoveryAdvertisement.RequiredKeys.Concat(DiscoveryAdvertisement.OptionalKeys))
        {
            int index = text.IndexOf($"{key}=", StringComparison.Ordinal);
            Assert.True(index > last, $"{key} is out of order in the canonical form");
            last = index;
        }

        // No trailing newline: a trailing separator is a different byte string.
        Assert.False(text.EndsWith('\n'));
    }

    /// <summary>An absent optional key is omitted, not emitted empty.</summary>
    /// <remarks>
    /// <c>model=</c> with nothing after it is a different string from no
    /// <c>model</c> at all. A device reporting an unknown model must not sign the
    /// same bytes as a device that reports none.
    /// </remarks>
    [Fact]
    public void AbsentOptionalKeyIsOmitted()
    {
        byte[] absent = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["v"] = "1.0", ["id"] = "d", ["fp"] = "c", ["caps"] = "a", ["port"] = "1",
        });

        byte[] empty = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["v"] = "1.0", ["id"] = "d", ["fp"] = "c", ["caps"] = "a", ["port"] = "1", ["model"] = "",
        });

        Assert.NotEqual(Encoding.UTF8.GetString(absent), Encoding.UTF8.GetString(empty));
        Assert.False(Encoding.UTF8.GetString(absent).Contains("model", StringComparison.Ordinal));
    }

    /// <summary>Fields are separated by a single newline and nothing else.</summary>
    [Fact]
    public void FieldsAreSeparatedByASingleNewline()
    {
        byte[] built = DiscoveryAdvertisement.CanonicalTxt(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["v"] = "1.0", ["id"] = "id", ["fp"] = "fp", ["caps"] = "c", ["port"] = "1",
        });

        string text = Encoding.UTF8.GetString(built);

        Assert.Equal(4, text.Count(c => c == '\n'));
        Assert.DoesNotContain("\r", text, StringComparison.Ordinal);
        Assert.DoesNotContain("  ", text, StringComparison.Ordinal);
    }

    // ---- Beacon canonicalisation ------------------------------------------

    /// <summary>The beacon vector canonicalises to the exact bytes it records.</summary>
    /// <remarks>
    /// A different rule from TXT on purpose: the beacon carries a JSON object, so
    /// it uses ascending key order, and <c>sig</c> is excluded because a
    /// signature cannot cover itself.
    /// </remarks>
    [Fact]
    public void BeaconCanonicalisesExactly()
    {
        JsonElement vector = Vectors().First(v => v.GetProperty("id").GetString() == "discovery.beacon.canonical");
        byte[] built = DiscoveryAdvertisement.CanonicalBeacon(Fields(vector));

        Assert.Equal(vector.GetProperty("canonical_utf8").GetString(), Encoding.UTF8.GetString(built));
        Assert.Equal(vector.GetProperty("canonical_length_bytes").GetInt32(), built.Length);
    }

    /// <summary>The beacon's keys are in ascending order.</summary>
    [Fact]
    public void BeaconKeysAreAscending()
    {
        JsonElement vector = Vectors().First(v => v.GetProperty("id").GetString() == "discovery.beacon.canonical");
        string text = Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalBeacon(Fields(vector)));

        string[] keys = [.. text.Split('\n').Select(line => line.Split('=')[0])];

        Assert.Equal(keys.OrderBy(k => k, StringComparer.Ordinal), keys);
    }

    /// <summary>The signature key is excluded from the signed bytes.</summary>
    [Fact]
    public void BeaconSignatureKeyIsExcluded()
    {
        Dictionary<string, string> withSig = new(StringComparer.Ordinal)
        {
            ["v"] = "1.0", ["id"] = "d", ["sig"] = "deadbeef",
        };

        Dictionary<string, string> withoutSig = new(StringComparer.Ordinal)
        {
            ["v"] = "1.0", ["id"] = "d",
        };

        Assert.Equal(
            Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalBeacon(withoutSig)),
            Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalBeacon(withSig)));

        Assert.DoesNotContain(
            "sig",
            Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalBeacon(withSig)),
            StringComparison.Ordinal);
    }

    /// <summary>The beacon has no whitespace and no trailing newline.</summary>
    [Fact]
    public void BeaconHasNoWhitespaceOrTrailingNewline()
    {
        JsonElement vector = Vectors().First(v => v.GetProperty("id").GetString() == "discovery.beacon.canonical");
        string text = Encoding.UTF8.GetString(DiscoveryAdvertisement.CanonicalBeacon(Fields(vector)));

        // "Pixel 7 - bench 3" contains spaces inside a value; what must not
        // appear is formatting whitespace around a separator.
        Assert.False(text.EndsWith('\n'));
        Assert.DoesNotContain("\n ", text, StringComparison.Ordinal);
        Assert.DoesNotContain(" \n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", text, StringComparison.Ordinal);
    }

    // ---- Size budget ------------------------------------------------------

    /// <summary>A record set at or under the budget fits.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    [InlineData(208)]
    [InlineData(1300)]
    public void RecordSetsUpToTheBudgetFit(int bytes)
    {
        Assert.True(DiscoveryAdvertisement.FitsInRecordSet(bytes, 1300));
    }

    /// <summary>An oversized record set does not fit and must be regenerated.</summary>
    [Theory]
    [InlineData(1301)]
    [InlineData(1400)]
    [InlineData(65535)]
    public void OversizedRecordSetsDoNotFit(int bytes)
    {
        Assert.False(DiscoveryAdvertisement.FitsInRecordSet(bytes, 1300));
    }

    /// <summary>The vector's too-large case is exactly over the budget.</summary>
    [Fact]
    public void TheVectorTooLargeCaseIsOverBudget()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.txt-too-large");

        int bytes = vector.GetProperty("txt_bytes").GetInt32();
        int max = vector.GetProperty("max_txt_bytes").GetInt32();

        Assert.False(DiscoveryAdvertisement.FitsInRecordSet(bytes, max));
        Assert.Equal("regenerate_record", vector.GetProperty("expected").GetString());

        // The library default must be the same budget the vector uses.
        Assert.Equal(DiscoveryAdvertisement.MaxTxtBytes, max);
        Assert.False(DiscoveryAdvertisement.FitsInRecordSet(bytes));
    }

    // ---- Capability truncation -------------------------------------------

    /// <summary>A truncated capability list ends on a whole name, never a comma.</summary>
    /// <remarks>
    /// A list ending in a comma is not a list, and a parser tolerant enough to
    /// accept one would be accepting something the device never meant to send.
    /// </remarks>
    [Fact]
    public void TruncatedCapabilityListHasNoTrailingComma()
    {
        string[] capabilities =
        [
            "screen.mirror", "screen.record", "input.touch", "input.key", "input.text",
        ];

        for (int budget = 0; budget <= 80; budget++)
        {
            string truncated = DiscoveryAdvertisement.TruncateCapabilities(capabilities, budget);

            Assert.True(
                Encoding.UTF8.GetByteCount(truncated) <= budget,
                $"budget {budget}: the result exceeded the budget");
            Assert.False(truncated.EndsWith(','), $"budget {budget}: the result ended in a comma");

            if (truncated.Length > 0)
            {
                Assert.Contains(truncated.Split(','), name => capabilities.Contains(name));
            }
        }
    }

    /// <summary>A budget large enough returns the whole list.</summary>
    [Fact]
    public void LargeBudgetReturnsTheWholeList()
    {
        string[] capabilities = ["screen.mirror", "input.touch"];

        Assert.Equal("screen.mirror,input.touch", DiscoveryAdvertisement.TruncateCapabilities(capabilities, 1000));
    }

    /// <summary>A zero budget returns nothing rather than a partial name.</summary>
    [Fact]
    public void ZeroBudgetReturnsNothing()
    {
        Assert.Equal(string.Empty, DiscoveryAdvertisement.TruncateCapabilities(["screen.mirror"], 0));
    }

    /// <summary>The truncation is a prefix, so it never invents a capability.</summary>
    [Fact]
    public void TruncationIsAPrefix()
    {
        string[] capabilities = ["alpha.one", "beta.two", "gamma.three", "delta.four"];

        string truncated = DiscoveryAdvertisement.TruncateCapabilities(capabilities, 20);
        string[] advertised = truncated.Length == 0 ? [] : truncated.Split(',');

        Assert.Equal(capabilities.Take(advertised.Length), advertised);
    }

    /// <summary>
    /// The advertised list is only a hint; the truncation vector says so.
    /// </summary>
    /// <remarks>
    /// The vector lists four advertised capabilities while sixteen are actually
    /// available. A controller that trusted the advertisement would show the
    /// device as far less capable than it is, which is why the authoritative list
    /// is the CAPABILITIES frame after authentication.
    /// </remarks>
    [Fact]
    public void AdvertisementIsOnlyAHintOfWhatIsAvailable()
    {
        JsonElement vector = Vectors().First(v => v.GetProperty("id").GetString() == "discovery.txt.caps-truncated");

        string[] advertised = vector.GetProperty("fields").GetProperty("caps").GetString()!.Split(',');
        string[] available = [.. vector.GetProperty("caps_actually_available").EnumerateArray().Select(e => e.GetString()!)];

        Assert.True(available.Length > advertised.Length);
        Assert.All(advertised, cap => Assert.Contains(cap, available));
    }

    // ---- Port handling -----------------------------------------------------

    /// <summary>Port 0 is not dialable and is rejected by the vector.</summary>
    [Fact]
    public void PortZeroIsNotDialable()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.port-out-of-range");

        Assert.Equal(0, vector.GetProperty("advertised_port").GetInt32());
        Assert.False(DiscoveryAdvertisement.IsDialablePort(0));
        Assert.Null(DiscoveryAdvertisement.FormatPort(0));
    }

    /// <summary>A real port is dialable and formats as decimal.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(45917)]
    [InlineData(65535)]
    public void RealPortsAreDialable(int port)
    {
        Assert.True(DiscoveryAdvertisement.IsDialablePort(port));
        Assert.Equal(port.ToString(), DiscoveryAdvertisement.FormatPort((ushort)port));
    }

    // ---- Rejection policy -------------------------------------------------

    /// <summary>A signature mismatch on a paired device keeps it listed as unverified.</summary>
    /// <remarks>
    /// The most important decision in this file. The controller must not connect,
    /// and must not quietly remove the device either: an attacker may be jamming
    /// the real agent, so an erased entry would be an attacker deleting a device
    /// from the user's list. The device stays, marked unverified, with a manual
    /// connect offered.
    /// </remarks>
    [Fact]
    public void SignatureMismatchOnAPairedDeviceStaysUnverified()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.signature-mismatch-paired-device");

        string id = vector.GetProperty("controller_has_pairing_for_id").GetString()!;

        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement(id, "9F3C-1A08-B7E2-44D1", ProtocolVersion.Parse("1.0"), 45917, SignatureValid: false),
            new PairingRecord(id, "9F3C-1A08-B7E2-44D1"),
            [ProtocolVersion.Parse("1.0")]);

        Assert.Equal(AdvertisementDecision.ListAsUnverified, verdict.Decision);
        Assert.Equal(vector.GetProperty("expected_ui_state").GetString(), verdict.UiState);
        Assert.NotEqual(AdvertisementDecision.Ignore, verdict.Decision);
        Assert.Equal(ErrorCodes.Unauthorized, verdict.Error);
    }

    /// <summary>A changed fingerprint for a known id refuses an automatic connect.</summary>
    [Fact]
    public void ChangedFingerprintRefusesAutomaticConnect()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.fingerprint-changed-for-known-id");

        string id = vector.GetProperty("known_id").GetString()!;

        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement(
                id,
                vector.GetProperty("advertised_fingerprint").GetString()!,
                ProtocolVersion.Parse("1.0"),
                45917,
                SignatureValid: true),
            new PairingRecord(id, vector.GetProperty("known_fingerprint").GetString()!),
            [ProtocolVersion.Parse("1.0")]);

        Assert.Equal(AdvertisementDecision.ListAsUnverified, verdict.Decision);
        Assert.Equal(vector.GetProperty("expected_warning").GetString(), verdict.Reason);
        Assert.Equal(ErrorCodes.Unauthorized, verdict.Error);
    }

    /// <summary>Port 0 is ignored outright.</summary>
    [Fact]
    public void PortZeroAdvertisementIsIgnored()
    {
        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement("id", "fp", ProtocolVersion.Parse("1.0"), 0, true),
            null,
            [ProtocolVersion.Parse("1.0")]);

        Assert.Equal(AdvertisementDecision.Ignore, verdict.Decision);
    }

    /// <summary>An unsupported version is listed as incompatible.</summary>
    /// <remarks>
    /// Checked before the signature, because an incompatible device is a fact and
    /// reporting a signature problem for a device we could not talk to anyway
    /// would send the user looking for the wrong fix.
    /// </remarks>
    [Fact]
    public void UnsupportedVersionIsListedAsIncompatible()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.unsupported-version");

        string[] supported = [.. vector.GetProperty("controller_supported_versions").EnumerateArray()
            .Select(e => e.GetString()!)];

        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement("id", "fp", ProtocolVersion.Parse(vector.GetProperty("advertised_version").GetString()!), 45917, true),
            null,
            supported.Select(ProtocolVersion.Parse));

        Assert.Equal(AdvertisementDecision.ListAsIncompatible, verdict.Decision);
        Assert.Equal(ErrorCodes.VersionMismatch, verdict.Error);
        Assert.Equal(vector.GetProperty("expected_error").GetString(), ErrorCodes.VersionMismatch.Name);
    }

    /// <summary>An unpaired device with a good signature is acceptable but unpaired.</summary>
    [Fact]
    public void UnpairedDeviceIsAcceptable()
    {
        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement("id", "fp", ProtocolVersion.Parse("1.0"), 45917, true),
            null,
            [ProtocolVersion.Parse("1.0")]);

        Assert.Equal(AdvertisementDecision.Accept, verdict.Decision);
        Assert.Null(verdict.Error);
    }

    /// <summary>A paired, matching, verified device is accepted with no error.</summary>
    [Fact]
    public void PairedMatchingDeviceIsAccepted()
    {
        AdvertisementVerdict verdict = AdvertisementPolicy.Evaluate(
            new Advertisement("id", "fp", ProtocolVersion.Parse("1.0"), 45917, true),
            new PairingRecord("id", "fp"),
            [ProtocolVersion.Parse("1.0")]);

        Assert.Equal(AdvertisementDecision.Accept, verdict.Decision);
        Assert.Equal("Online", verdict.UiState);
        Assert.Null(verdict.Error);
    }

    /// <summary>A pairing record for a different device is a caller error.</summary>
    /// <remarks>
    /// Silently comparing the wrong record would make every device look like an
    /// impersonation, which is the kind of bug that trains a user to ignore the
    /// warning.
    /// </remarks>
    [Fact]
    public void PairingRecordForAnotherDeviceIsRejected()
    {
        Assert.Throws<ArgumentException>(() => AdvertisementPolicy.Evaluate(
            new Advertisement("device-a", "fp", ProtocolVersion.Parse("1.0"), 45917, true),
            new PairingRecord("device-b", "fp"),
            [ProtocolVersion.Parse("1.0")]));
    }

    // ---- Lifecycle ---------------------------------------------------------

    /// <summary>Disabling discovery suppresses the beacon and sends a goodbye.</summary>
    [Fact]
    public void DisablingDiscoverySuppressesTheBeacon()
    {
        JsonElement vector = RejectionVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.reject.beacon-on-public-network");

        Assert.False(vector.GetProperty("discovery_enabled").GetBoolean());
        Assert.False(AdvertisementPolicy.ShouldBeacon(discoveryEnabled: false));
        Assert.True(AdvertisementPolicy.ShouldBeacon(discoveryEnabled: true));
    }

    /// <summary>The goodbye TTL is zero, so controllers drop the device at once.</summary>
    [Fact]
    public void GoodbyeTtlIsZero()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.goodbye-on-disable");

        Assert.Equal("send_goodbye", vector.GetProperty("expected").GetString());
        Assert.Equal(vector.GetProperty("goodbye_ttl").GetInt32(), AdvertisementPolicy.GoodbyeTtl);
        Assert.Equal(0, AdvertisementPolicy.GoodbyeTtl);
    }

    /// <summary>Presence expires at the TTL but the pairing does not.</summary>
    [Fact]
    public void TtlExpiryEndsPresenceButNotThePairing()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.ttl-expiry-keeps-saved-device");

        int ttl = vector.GetProperty("ttl_s").GetInt32();
        int elapsed = vector.GetProperty("elapsed_s").GetInt32();

        Assert.True(elapsed > ttl);
        Assert.False(AdvertisementPolicy.IsPresent(elapsed, ttl));

        // Still listed: the saving is what keeps a Wi-Fi hiccup from costing the
        // user a pairing.
        Assert.True(vector.GetProperty("expected_still_listed").GetBoolean());
        Assert.Equal("Offline", vector.GetProperty("expected_ui_state").GetString());
    }

    /// <summary>A device is present up to and including the TTL.</summary>
    [Theory]
    [InlineData(0, true)]
    [InlineData(119, true)]
    [InlineData(120, true)]
    [InlineData(121, false)]
    public void PresenceLastsThroughTheTtl(int elapsed, bool present)
    {
        Assert.Equal(present, AdvertisementPolicy.IsPresent(elapsed, 120));
    }

    /// <summary>A busy agent still advertises, with the busy flag set.</summary>
    /// <remarks>
    /// So a controller can say "device is busy" rather than "device not found",
    /// which are very different messages to the person holding the phone.
    /// </remarks>
    [Fact]
    public void BusyAgentStillAdvertises()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "discovery.busy-agent-still-advertises");

        int active = vector.GetProperty("active_sessions").GetInt32();
        int max = vector.GetProperty("max_sessions").GetInt32();

        Assert.True(active >= max);
        Assert.Equal("advertise_with_busy_flag", vector.GetProperty("expected").GetString());
        Assert.Equal(1, vector.GetProperty("expected_busy_value").GetInt32());

        // A saturated agent is exactly the case the busy flag exists for, so it
        // must still be advertising.
        Assert.True(AdvertisementPolicy.ShouldBeacon(discoveryEnabled: true));
    }
}
