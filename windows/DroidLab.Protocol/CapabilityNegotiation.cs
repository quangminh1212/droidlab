using DroidLab.Protocol.Registry;

namespace DroidLab.Protocol;

/// <summary>
/// Negotiates capabilities and limits for a session (RFC-0001 section 7).
/// </summary>
/// <remarks>
/// <para>
/// Capability negotiation is a set intersection with two subtractions, and each
/// of the four rules matters:
/// </para>
/// <list type="number">
/// <item>
/// <b>Intersection.</b> A capability must be offered by the controller and
/// implemented by the agent. A capability the controller never offered never
/// appears, even though the agent supports it: the controller's refusal to offer
/// something is a decision, not an omission.
/// </item>
/// <item>
/// <b>Unknown names are ignored.</b> Not rejected. This is what lets a newer
/// peer advertise something an older one has never heard of without breaking the
/// session, which is the only way the protocol can grow.
/// </item>
/// <item>
/// <b>Operator-disabled wins.</b> A capability the operator turned off on the
/// device is absent even when both sides support and offer it. This is the rule
/// that makes the device-side switch real rather than advisory, and it is
/// checked before the intersection so no other rule can reintroduce it.
/// </item>
/// <item>
/// <b>An empty result is legal.</b> A session with nothing negotiated is
/// useless but not an error: the handshake completes, and the device
/// information and error channels stay usable for diagnostics. Failing the
/// handshake here would leave the operator with a device they cannot even ask
/// why it failed.
/// </item>
/// </list>
/// <para>
/// The result is sorted, so the negotiated set is a canonical value that two
/// implementations can compare directly rather than a bag that depends on
/// offer order.
/// </para>
/// </remarks>
public static class CapabilityNegotiation
{
    /// <summary>
    /// Computes the negotiated capability set.
    /// </summary>
    /// <param name="registry">The protocol registry, used to reject unknown names.</param>
    /// <param name="agentCapabilities">The capabilities the agent implements as advertised in <c>HELLO_ACK</c>.</param>
    /// <param name="agentDisabled">The capabilities the agent implements but the operator has disabled.</param>
    /// <param name="controllerOffered">The capabilities the controller offers in <c>AUTH</c>.</param>
    /// <returns>The negotiated capability names, sorted.</returns>
    /// <remarks>
    /// Unknown names are silently dropped rather than reported. That is the
    /// forward-compatibility rule, and it applies to the offer and to the
    /// answer equally: a controller must not be punished for offering something
    /// from a newer protocol revision.
    /// </remarks>
    public static IReadOnlyList<string> Negotiate(
        ProtocolRegistry registry,
        IEnumerable<string> agentCapabilities,
        IEnumerable<string> agentDisabled,
        IEnumerable<string> controllerOffered)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(agentCapabilities);
        ArgumentNullException.ThrowIfNull(agentDisabled);
        ArgumentNullException.ThrowIfNull(controllerOffered);

        // Sets throughout, because the protocol's rule is set-shaped: a
        // duplicated name is harmless and must not produce a duplicated result.
        HashSet<string> disabled = new(agentDisabled, StringComparer.Ordinal);
        HashSet<string> offered = new(controllerOffered, StringComparer.Ordinal);

        SortedSet<string> negotiated = new(StringComparer.Ordinal);

        foreach (string capability in agentCapabilities)
        {
            if (!registry.IsKnownCapability(capability))
            {
                // Unknown to this implementation: ignored, not rejected.
                continue;
            }

            if (disabled.Contains(capability))
            {
                // The operator's decision is final and is applied before the
                // intersection, so no later rule can bring it back.
                continue;
            }

            if (offered.Contains(capability))
            {
                negotiated.Add(capability);
            }
        }

        return [.. negotiated];
    }

    /// <summary>
    /// Whether a message type may be used under a negotiated capability set.
    /// </summary>
    /// <param name="registry">The protocol registry.</param>
    /// <param name="messageTypeCode">The message type code.</param>
    /// <param name="negotiated">The negotiated capability set.</param>
    /// <returns><see langword="true"/> when the message type is usable.</returns>
    /// <remarks>
    /// <para>
    /// Three separate questions, in order:
    /// </para>
    /// <list type="number">
    /// <item>Is the message type registered at all? If not, the answer is
    /// <c>ERR_UNSUPPORTED_MESSAGE</c>, which the registry's reply rule says must
    /// not end the session.</item>
    /// <item>Is a capability required for it, and is that capability
    /// negotiated? If not, the answer is <c>ERR_UNSUPPORTED_FEATURE</c>, also
    /// recoverable.</item>
    /// <item>Otherwise it is usable.</item>
    /// </list>
    /// <para>
    /// Keeping the two failures distinct matters because they mean different
    /// things to the operator: an unknown message type is probably a version
    /// mismatch, while an unnegotiated capability usually means a device-side
    /// switch is off and is fixable.
    /// </para>
    /// </remarks>
    public static bool IsMessageTypeUsable(
        ProtocolRegistry registry,
        byte messageTypeCode,
        IReadOnlyCollection<string> negotiated)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(negotiated);

        if (registry.FindMessageType(messageTypeCode) is null)
        {
            return false;
        }

        string? required = registry.CapabilityFor(messageTypeCode);
        if (required is null)
        {
            // Handshake, control and error frames are ungated: they must work
            // before anything has been negotiated, including when the
            // negotiated set is empty.
            return true;
        }

        return negotiated.Contains(required);
    }

    /// <summary>
    /// Classifies why a message type is unusable, for the error to send.
    /// </summary>
    /// <param name="registry">The protocol registry.</param>
    /// <param name="messageTypeCode">The message type code.</param>
    /// <param name="negotiated">The negotiated capability set.</param>
    /// <returns>The error code to answer with, or <see langword="null"/> when the type is usable.</returns>
    public static ErrorCode? RejectionFor(
        ProtocolRegistry registry,
        byte messageTypeCode,
        IReadOnlyCollection<string> negotiated)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(negotiated);

        if (registry.FindMessageType(messageTypeCode) is null)
        {
            return ErrorCodes.UnsupportedMessage;
        }

        string? required = registry.CapabilityFor(messageTypeCode);
        if (required is not null && !negotiated.Contains(required))
        {
            return ErrorCodes.UnsupportedFeature;
        }

        return null;
    }
}
