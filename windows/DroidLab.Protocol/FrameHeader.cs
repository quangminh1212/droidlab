namespace DroidLab.Protocol;

/// <summary>
/// The flag bits of a DLWP/1 frame header (RFC-0001 section 3.1).
/// </summary>
/// <remarks>
/// Bits 4–7 are reserved. A sender MUST set them to zero and a receiver MUST
/// ignore them, so they are deliberately absent from this enum: there is no
/// value an implementation could act on.
/// </remarks>
[Flags]
public enum FrameFlags : byte
{
    /// <summary>No flags set.</summary>
    None = 0x00,

    /// <summary>The body is AEAD-encrypted per RFC-0002 section 5. Set on every frame after <c>HELLO_ACK</c>.</summary>
    Encrypted = 0x01,

    /// <summary>The receiver should process this ahead of normal traffic. Only <c>PING</c>, <c>PONG</c>, <c>ERROR</c> and <c>SESSION_END</c> may set it.</summary>
    Urgent = 0x02,

    /// <summary>Last frame on this channel.</summary>
    EndOfStream = 0x04,

    /// <summary>The body was DEFLATE-compressed before encryption. Legal only when both peers advertised <c>compression.deflate</c>.</summary>
    Compressed = 0x08,
}

/// <summary>
/// The reserved flag bits (4–7). A receiver ignores these; a sender must leave
/// them clear.
/// </summary>
public static class FrameFlagsMask
{
    /// <summary>The mask of the four defined flag bits.</summary>
    public const byte Defined = 0x0F;

    /// <summary>The mask of the reserved flag bits, which must be zero on send and are ignored on receive.</summary>
    public const byte Reserved = 0xF0;
}

/// <summary>
/// The fixed 24-byte DLWP/1 frame header (RFC-0001 section 3).
/// </summary>
/// <remarks>
/// <para>
/// On the wire every multi-byte field is big-endian. The layout is:
/// </para>
/// <code>
///   offset  width  field
///   0       4      magic "DLWP"
///   4       1      version
///   5       1      flags
///   6       1      header_length
///   7       1      message_type
///   8       4      channel_id
///   12      4      sequence_number
///   16      4      acknowledgment
///   20      4      body_length
/// </code>
/// <para>
/// This type is a pure value: it validates nothing about protocol state, because
/// whether a frame is legal depends on the session state machine, not on the
/// header. Frame-level validity is <see cref="FrameValidator"/>'s job, and
/// state-level validity belongs to the session.
/// </para>
/// </remarks>
public readonly record struct FrameHeader
{
    /// <summary>The magic bytes, ASCII "DLWP".</summary>
    public static readonly byte[] Magic = "DLWP"u8.ToArray();

    /// <summary>The fixed header length in DLWP/1.</summary>
    public const byte FixedLength = 24;

    /// <summary>The protocol major version implemented by this codec.</summary>
    public const byte ProtocolVersion = 1;

    /// <summary>The ASCII magic, always <c>DLWP</c>.</summary>
    public string MagicText => "DLWP";

    /// <summary>Protocol major version. 1 for DLWP/1.</summary>
    public required byte Version { get; init; }

    /// <summary>The flag bits, including any reserved bits the peer set.</summary>
    /// <remarks>
    /// The raw byte is preserved rather than normalised, so that a receiver can
    /// tell an unclean sender from a clean one and so that a decode → encode
    /// round trip is byte-exact.
    /// </remarks>
    public required byte Flags { get; init; }

    /// <summary>Total header length in bytes, including this 24-byte prefix.</summary>
    public required byte HeaderLength { get; init; }

    /// <summary>The frame type, from the RFC-0001 section 4 registry.</summary>
    public required byte MessageType { get; init; }

    /// <summary>Logical channel. 0 is the control channel and is always valid.</summary>
    public required uint ChannelId { get; init; }

    /// <summary>Per-session sequence number. Starts at 1 and never repeats within a session.</summary>
    public required uint SequenceNumber { get; init; }

    /// <summary>Highest received sequence number on this channel, or 0 when not applicable.</summary>
    public required uint Acknowledgment { get; init; }

    /// <summary>Length of the body in bytes, excluding the header.</summary>
    public required uint BodyLength { get; init; }

    /// <summary>The defined flag bits only, with the reserved bits cleared.</summary>
    public FrameFlags DefinedFlags => (FrameFlags)(Flags & FrameFlagsMask.Defined);

    /// <summary>The reserved flag bits, which must be zero on a conformant sender.</summary>
    public byte ReservedFlags => (byte)(Flags & FrameFlagsMask.Reserved);

    /// <summary>The total on-wire size of the frame this header describes.</summary>
    public long TotalLength => HeaderLength + (long)BodyLength;

    /// <summary>Whether a given flag is set.</summary>
    /// <param name="flag">The flag to test.</param>
    /// <returns><see langword="true"/> when the bit is set.</returns>
    public bool HasFlag(FrameFlags flag) => (DefinedFlags & flag) == flag;

    /// <summary>
    /// Whether the header declares a message type that is encrypted per RFC-0001 section 4.
    /// </summary>
    /// <remarks>
    /// <c>HELLO</c> and <c>HELLO_ACK</c> are the only unencrypted frames; they carry
    /// the material the session keys are derived from, so they cannot be encrypted.
    /// </remarks>
    public bool MustBeEncrypted => MessageType is not 0x01 and not 0x02;
}
