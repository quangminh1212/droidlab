using System.Globalization;
using System.Text;

namespace DroidLab.Protocol;

/// <summary>
/// Discovery advertisement canonicalisation (RFC-0003 sections 2 and 4.1).
/// </summary>
/// <remarks>
/// <para>
/// Two peers must agree byte for byte on what was signed, or a valid signature
/// fails to verify. That is the whole reason these rules exist and why they are
/// written out rather than left to "whatever the JSON serializer does":
/// </para>
/// <list type="bullet">
/// <item>
/// The TXT payload uses a <b>fixed key order</b>, not alphabetical. A reader can
/// then compare the specification, the vector and the code without consulting a
/// sort implementation, and a reordered key is a visible diff rather than a
/// silent signature failure.
/// </item>
/// <item>
/// The beacon uses <b>ascending key order</b> and no whitespace. It is a
/// different rule on purpose: the beacon carries a JSON object, so it cannot use
/// the TXT layout, and inventing one deterministic rule per carrier is clearer
/// than trying to share one.
/// </item>
/// <item>
/// The optional TXT keys are appended after <c>port</c> in a declared order when
/// present, so a device that adds a key does not reorder the required ones.
/// </item>
/// </list>
/// <para>
/// The label and a NUL come first, exactly as in the handshake transcript, so a
/// signature over a TXT payload cannot be replayed as a signature over anything
/// else with the same suffix bytes.
/// </para>
/// </remarks>
public static class DiscoveryAdvertisement
{
    /// <summary>The TXT canonicalisation label.</summary>
    public const string TxtLabel = "DLWP/1-txt";

    /// <summary>The MDNS service type.</summary>
    public const string ServiceType = "_droidlab._tcp";

    /// <summary>The mDNS domain.</summary>
    public const string ServiceDomain = "local";

    /// <summary>The default TCP port.</summary>
    public const ushort DefaultPort = 45917;

    /// <summary>The beacon UDP port.</summary>
    public const ushort BeaconPort = 45918;

    /// <summary>Record TTL in seconds.</summary>
    public const int TtlSeconds = 120;

    /// <summary>The largest TXT record set that is delivered reliably.</summary>
    public const int MaxTxtBytes = 1300;

    /// <summary>The required TXT keys, in canonical order.</summary>
    public static readonly IReadOnlyList<string> RequiredKeys = ["v", "id", "fp", "caps", "port"];

    /// <summary>The optional TXT keys, in canonical order.</summary>
    /// <remarks>
    /// Declared rather than discovered from a dictionary: the order is part of
    /// the wire format, and iterating a dictionary would make the signature
    /// depend on hash ordering.
    /// </remarks>
    public static readonly IReadOnlyList<string> OptionalKeys = ["model", "android", "sdk", "busy", "loc", "tls"];

    /// <summary>Field separators and the record prefix.</summary>
    public const char FieldSeparator = '\n';

    /// <summary>Builds the canonical TXT byte string that is signed.</summary>
    /// <param name="fields">The TXT key/value pairs. Unknown keys are ignored.</param>
    /// <returns>The canonical UTF-8 bytes.</returns>
    /// <remarks>
    /// Absent optional keys are omitted entirely rather than emitted empty: a
    /// <c>model=</c> with nothing after it is a different string from no
    /// <c>model</c> at all, and a device that reports an unknown model must not
    /// sign the same bytes as one that reports none.
    /// </remarks>
    public static byte[] CanonicalTxt(IReadOnlyDictionary<string, string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        StringBuilder builder = new();
        builder.Append(TxtLabel).Append('\0');

        bool first = true;

        foreach (string key in RequiredKeys.Concat(OptionalKeys))
        {
            if (!fields.TryGetValue(key, out string? value) || value is null)
            {
                continue;
            }

            if (!first)
            {
                builder.Append(FieldSeparator);
            }

            builder.Append(key).Append('=').Append(value);
            first = false;
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    /// <summary>Builds the canonical beacon byte string that is signed.</summary>
    /// <param name="fields">The beacon fields. The <c>sig</c> key is excluded.</param>
    /// <returns>The canonical UTF-8 bytes.</returns>
    /// <remarks>
    /// Ascending key order, <c>key=value</c> per line, no trailing newline, and
    /// <c>sig</c> excluded because a signature cannot cover itself.
    /// </remarks>
    public static byte[] CanonicalBeacon(IReadOnlyDictionary<string, string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        StringBuilder builder = new();
        bool first = true;

        foreach (string key in fields.Keys.Where(k => !string.Equals(k, "sig", StringComparison.Ordinal))
                     .OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!first)
            {
                builder.Append(FieldSeparator);
            }

            builder.Append(key).Append('=').Append(fields[key]);
            first = false;
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    /// <summary>
    /// Whether a record set fits the mDNS delivery budget.
    /// </summary>
    /// <param name="txtBytes">The canonical TXT length in bytes.</param>
    /// <param name="maxTxtBytes">The budget. Defaults to <see cref="MaxTxtBytes"/>.</param>
    /// <returns><see langword="true"/> when the record can be delivered in one response.</returns>
    /// <remarks>
    /// An oversized record set cannot be delivered reliably in a single mDNS
    /// response, so the agent must regenerate it rather than emit something that
    /// arrives truncated. A truncated record would fail signature verification
    /// and look like an attack rather than a size problem.
    /// </remarks>
    public static bool FitsInRecordSet(int txtBytes, int maxTxtBytes = MaxTxtBytes) =>
        txtBytes >= 0 && txtBytes <= maxTxtBytes;

    /// <summary>
    /// Formats a port for the TXT record.
    /// </summary>
    /// <param name="port">The advertised port.</param>
    /// <returns><see langword="null"/> when the port is not a valid advertised port.</returns>
    /// <remarks>
    /// Port 0 is not a port. An advertisement carrying it is malformed rather
    /// than unusual, and connecting to it would fail in a way that looks like a
    /// network fault rather than a bad record.
    /// </remarks>
    public static string? FormatPort(ushort port) =>
        port == 0 ? null : port.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Whether an advertised port can be dialled.
    /// </summary>
    /// <param name="port">The port from the advertisement.</param>
    /// <returns><see langword="true"/> when the port is usable.</returns>
    public static bool IsDialablePort(int port) => port is > 0 and <= 65535;

    /// <summary>
    /// Truncates a capability list to fit a byte budget, without a trailing comma.
    /// </summary>
    /// <param name="capabilities">The full capability list, in the order to advertise.</param>
    /// <param name="maxBytes">The budget for the <c>caps</c> value alone.</param>
    /// <returns>The prefix that fits, which may be empty.</returns>
    /// <remarks>
    /// <para>
    /// The result is a prefix, and a prefix is <b>advisory only</b>: it is not
    /// evidence that a capability is missing from the device. A controller must
    /// call <c>GET_CAPABILITIES</c> after connecting and use the
    /// <c>CAPABILITIES</c> frame, which is the authoritative list. Treating the
    /// advertisement as authoritative would mean a device looked less capable the
    /// more it had to say.
    /// </para>
    /// <para>
    /// No trailing comma, because a truncated list ending in a comma is not a
    /// list, and a parser that tolerates it would be accepting something the
    /// device never meant to send.
    /// </para>
    /// </remarks>
    public static string TruncateCapabilities(IEnumerable<string> capabilities, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);

        StringBuilder builder = new();

        foreach (string capability in capabilities)
        {
            if (capability.Length == 0 || capability.Contains(','))
            {
                // A comma inside a name would make the list ambiguous once split,
                // so such a name cannot be advertised at all.
                continue;
            }

            int added = capability.Length + (builder.Length == 0 ? 0 : 1);

            if (Encoding.UTF8.GetByteCount(builder.ToString()) + added > maxBytes)
            {
                break;
            }

            if (builder.Length > 0)
            {
                builder.Append(',');
            }

            builder.Append(capability);
        }

        return builder.ToString();
    }
}

/// <summary>
/// What a controller must do with an advertisement (RFC-0003 section 3).
/// </summary>
public enum AdvertisementDecision
{
    /// <summary>Dial it.</summary>
    Accept,

    /// <summary>Drop it silently; do not list the device.</summary>
    Ignore,

    /// <summary>Keep it listed, but never connect without the user asking.</summary>
    ListAsUnverified,

    /// <summary>Keep it listed as incompatible.</summary>
    ListAsIncompatible,
}

/// <summary>
/// One advertised device, as far as a controller can tell before connecting.
/// </summary>
/// <param name="DeviceId">The advertised device id.</param>
/// <param name="Fingerprint">The advertised fingerprint.</param>
/// <param name="Version">The advertised protocol version, or <see langword="null"/> when unparseable.</param>
/// <param name="Port">The advertised port.</param>
/// <param name="SignatureValid">Whether the signature verified, or <see langword="null"/> when unverifiable.</param>
public readonly record struct Advertisement(
    string DeviceId,
    string Fingerprint,
    ProtocolVersion? Version,
    int Port,
    bool? SignatureValid);

/// <summary>
/// A pairing record for a device the controller has already paired with.
/// </summary>
/// <param name="DeviceId">The device id.</param>
/// <param name="Fingerprint">The fingerprint recorded at pairing time.</param>
public readonly record struct PairingRecord(string DeviceId, string Fingerprint);

/// <summary>
/// The outcome of evaluating an advertisement.
/// </summary>
/// <param name="Decision">What the controller should do.</param>
/// <param name="Reason">A human-readable explanation, for the UI.</param>
/// <param name="UiState">The state to show, e.g. <c>Unverified</c>.</param>
/// <param name="Error">The error code to report, when there is one.</param>
public readonly record struct AdvertisementVerdict(
    AdvertisementDecision Decision,
    string Reason,
    string UiState,
    ErrorCode? Error);

/// <summary>
/// Decides what to do with a discovered advertisement (RFC-0003 section 3).
/// </summary>
/// <remarks>
/// The rejections are deliberately not all the same decision, because they mean
/// different things to the operator:
/// <list type="bullet">
/// <item>
/// A malformed or unsupported advertisement is <b>ignored</b> or listed as
/// incompatible.
/// </item>
/// <item>
/// A signature mismatch on a device we hold a pairing record for is the
/// interesting case. The controller must not connect, and it must <b>not</b>
/// silently forget the device either: an attacker may be jamming the real agent,
/// so dropping the entry would let a jammer erase a device from the user's list.
/// The device stays listed as unverified, with a manual connect offered.
/// </item>
/// <item>
/// A fingerprint that changed for a known id is treated as possible
/// impersonation and refuses automatic connection, with a warning.
/// </item>
/// </list>
/// </remarks>
public static class AdvertisementPolicy
{
    /// <summary>Evaluates an advertisement.</summary>
    /// <param name="advertisement">The advertisement.</param>
    /// <param name="pairing">The pairing record, or <see langword="null"/> when the device is unknown.</param>
    /// <param name="supportedVersions">The versions the controller supports.</param>
    /// <returns>The verdict.</returns>
    public static AdvertisementVerdict Evaluate(
        Advertisement advertisement,
        PairingRecord? pairing,
        IEnumerable<ProtocolVersion> supportedVersions)
    {
        ArgumentNullException.ThrowIfNull(supportedVersions);

        // Port 0 is not dialable, and it is malformed rather than unusual, so it
        // is ignored rather than listed: there is nothing to show the user.
        if (!DiscoveryAdvertisement.IsDialablePort(advertisement.Port))
        {
            return new AdvertisementVerdict(
                AdvertisementDecision.Ignore,
                $"ignored: port {advertisement.Port} is not a dialable port",
                "NotFound",
                null);
        }

        if (advertisement.Version is null)
        {
            return new AdvertisementVerdict(
                AdvertisementDecision.ListAsIncompatible,
                "listed as incompatible: the advertised version could not be parsed",
                "Incompatible",
                ErrorCodes.VersionMismatch);
        }

        // Version first: an incompatible device is a fact, and reporting a
        // signature problem for a device we could not talk to anyway would send
        // the user looking for the wrong fix.
        if (VersionNegotiation.HighestCommonVersion(supportedVersions, [advertisement.Version.Value]) is null)
        {
            return new AdvertisementVerdict(
                AdvertisementDecision.ListAsIncompatible,
                $"listed as incompatible: no common version with advertised {advertisement.Version}",
                "Incompatible",
                ErrorCodes.VersionMismatch);
        }

        if (pairing is not { } known)
        {
            // Unknown devices are listable; whether they are trusted is a
            // decision for the pairing flow, not for discovery.
            return new AdvertisementVerdict(
                AdvertisementDecision.Accept,
                "no pairing record: the device is discoverable but unpaired",
                "Discovered",
                null);
        }

        if (!string.Equals(known.DeviceId, advertisement.DeviceId, StringComparison.Ordinal))
        {
            // The caller passed a record for a different device, which is a
            // programming error rather than a device problem.
            throw new ArgumentException(
                $"the pairing record is for '{known.DeviceId}' but the advertisement is for " +
                $"'{advertisement.DeviceId}'",
                nameof(pairing));
        }

        if (advertisement.SignatureValid is false)
        {
            // Do not connect, and do not quietly remove it: an attacker may be
            // jamming the real agent, so an erased entry would be an attacker
            // deleting a device from the user's list.
            return new AdvertisementVerdict(
                AdvertisementDecision.ListAsUnverified,
                "kept as unverified: the signature did not verify for a device we have paired with",
                "Unverified",
                ErrorCodes.Unauthorized);
        }

        if (!string.Equals(known.Fingerprint, advertisement.Fingerprint, StringComparison.Ordinal))
        {
            return new AdvertisementVerdict(
                AdvertisementDecision.ListAsUnverified,
                "device identity changed - possible impersonation",
                "Unverified",
                ErrorCodes.Unauthorized);
        }

        return new AdvertisementVerdict(
            AdvertisementDecision.Accept,
            "paired device with a matching id, fingerprint and signature",
            "Online",
            null);
    }

    /// <summary>
    /// Whether the agent should emit a beacon.
    /// </summary>
    /// <param name="discoveryEnabled">Whether the operator has discovery enabled.</param>
    /// <returns><see langword="true"/> when a beacon may be emitted.</returns>
    /// <remarks>
    /// The beacon is a broadcast, so it is suppressed when the operator has
    /// turned discovery off. It must also never be unicast to an address the
    /// agent has not itself been contacted from, because that would let anyone
    /// who can send one packet make the device broadcast to an arbitrary target.
    /// </remarks>
    public static bool ShouldBeacon(bool discoveryEnabled) => discoveryEnabled;

    /// <summary>
    /// The TTL to send when discovery is disabled.
    /// </summary>
    /// <returns>Zero, meaning "forget this immediately".</returns>
    /// <remarks>
    /// A goodbye with TTL 0 tells controllers to drop the device now rather than
    /// wait out the record TTL, so turning discovery off takes effect at once
    /// instead of up to two minutes later.
    /// </remarks>
    public static int GoodbyeTtl => 0;

    /// <summary>
    /// Whether a device stays in the saved list after its presence expires.
    /// </summary>
    /// <param name="elapsedSeconds">Seconds since the last advertisement.</param>
    /// <param name="ttlSeconds">The record TTL. Defaults to <see cref="DiscoveryAdvertisement.TtlSeconds"/>.</param>
    /// <returns><see langword="true"/> while the device is still considered present.</returns>
    /// <remarks>
    /// Presence expiring is not the pairing expiring. An offline device stays in
    /// the saved list so the user can see it and reconnect later; removing it
    /// when it goes out of range would mean losing the pairing because of a
    /// Wi-Fi hiccup.
    /// </remarks>
    public static bool IsPresent(int elapsedSeconds, int ttlSeconds = DiscoveryAdvertisement.TtlSeconds) =>
        elapsedSeconds <= ttlSeconds;
}
