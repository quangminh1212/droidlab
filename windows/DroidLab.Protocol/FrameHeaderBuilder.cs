namespace DroidLab.Protocol;

/// <summary>
/// Builds a <see cref="FrameHeader"/> with sensible DLWP/1 defaults so a test or
/// a caller can vary exactly the field it cares about.
/// </summary>
/// <remarks>
/// The defaults are a valid control-channel frame: version 1, no flags, the fixed
/// 24-byte header, <c>PING</c>, channel 0, the first sequence number and an empty
/// body. A test that changes one field therefore fails for that field's reason
/// rather than because a sibling field was left at zero.
/// </remarks>
public sealed class FrameHeaderBuilder
{
    private byte _version = FrameHeader.ProtocolVersion;
    private byte _flags;
    private byte _headerLength = FrameHeader.FixedLength;
    private byte _messageType = 0x05;
    private uint _channelId;
    private uint _sequenceNumber = 1;
    private uint _acknowledgment;
    private uint _bodyLength;

    /// <summary>Sets the protocol version.</summary>
    /// <param name="version">The major version byte.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithVersion(byte version) => Set(ref _version, version);

    /// <summary>Sets the raw flag byte, including any reserved bits.</summary>
    /// <param name="flags">The flag byte.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithFlags(byte flags) => Set(ref _flags, flags);

    /// <summary>Sets the declared header length.</summary>
    /// <param name="headerLength">The header length byte.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithHeaderLength(byte headerLength) => Set(ref _headerLength, headerLength);

    /// <summary>Sets the message type.</summary>
    /// <param name="messageType">The message type byte.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithMessageType(byte messageType) => Set(ref _messageType, messageType);

    /// <summary>Sets the channel id.</summary>
    /// <param name="channelId">The channel id.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithChannelId(uint channelId) => Set(ref _channelId, channelId);

    /// <summary>Sets the sequence number.</summary>
    /// <param name="sequenceNumber">The sequence number.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithSequenceNumber(uint sequenceNumber) => Set(ref _sequenceNumber, sequenceNumber);

    /// <summary>Sets the acknowledgment field.</summary>
    /// <param name="acknowledgment">The acknowledgment value.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithAcknowledgment(uint acknowledgment) => Set(ref _acknowledgment, acknowledgment);

    /// <summary>Sets the declared body length.</summary>
    /// <param name="bodyLength">The body length in bytes.</param>
    /// <returns>This builder.</returns>
    public FrameHeaderBuilder WithBodyLength(uint bodyLength) => Set(ref _bodyLength, bodyLength);

    /// <summary>Produces the header.</summary>
    /// <returns>The configured header.</returns>
    public FrameHeader Build() => new()
    {
        Version = _version,
        Flags = _flags,
        HeaderLength = _headerLength,
        MessageType = _messageType,
        ChannelId = _channelId,
        SequenceNumber = _sequenceNumber,
        Acknowledgment = _acknowledgment,
        BodyLength = _bodyLength,
    };

    private FrameHeaderBuilder Set<T>(ref T field, T value)
        where T : struct
    {
        field = value;
        return this;
    }
}
