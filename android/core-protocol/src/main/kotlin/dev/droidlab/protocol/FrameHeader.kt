package dev.droidlab.protocol

/**
 * The DLWP/1 fixed frame header (RFC-0001 section 3.1).
 *
 * The header is exactly 24 bytes on the wire and its fields are fixed-width and
 * big-endian, which is what makes a decoder possible without a schema and what lets a
 * receiver reject a frame from its first bytes rather than after reading all of it.
 *
 * @property version the protocol major version. Minor versions are not on the wire:
 *   1.2 and 1.0 both carry 1, because the header's job is to let a peer detect an
 *   incompatible *major* version before allocating anything, and a minor difference
 *   is negotiated in the handshake body.
 * @property flags the flag byte. Bits 0 to 3 are defined and bits 4 to 7 are
 *   reserved.
 * @property headerLength the header's own length, which is 24 for DLWP/1. The field
 *   exists so a future version can extend the header without breaking this one; a
 *   value other than 24 is not an error this version can process, and is refused
 *   rather than guessed at.
 * @property messageType the message type code. The registry is normative for what
 *   each value means.
 * @property channelId the channel the frame belongs to. Zero is the control channel.
 * @property sequenceNumber the frame's sequence number within its direction.
 * @property acknowledgment the sequence number being acknowledged, historically
 *   named; DLWP/1 does not use selective acknowledgement.
 * @property bodyLength the body length in bytes. For an encrypted frame this is the
 *   length of `nonce || ciphertext || tag`, not of the plaintext, and that is why the
 *   AAD has to be built from the plaintext length instead.
 */
data class FrameHeader(
    val version: Int,
    val flags: Int,
    val headerLength: Int,
    val messageType: Int,
    val channelId: Long,
    val sequenceNumber: Long,
    val acknowledgment: Long,
    val bodyLength: Long,
) {
    /** Whether the body is AEAD-protected. */
    val isEncrypted: Boolean get() = flags and Flags.ENCRYPTED != 0

    /** Whether the frame is marked urgent. */
    val isUrgent: Boolean get() = flags and Flags.URGENT != 0

    /** Whether this frame is the last of its channel's stream. */
    val isEndOfStream: Boolean get() = flags and Flags.END_OF_STREAM != 0

    /** Whether the body is compressed before encryption. */
    val isCompressed: Boolean get() = flags and Flags.COMPRESSED != 0

    /**
     * The reserved flag bits, 4 to 7, as they were received.
     *
     * Preserved rather than discarded, and not a reason to refuse the frame. A peer
     * that sets one is either a newer protocol version using the space for something
     * this one does not know, or a broken one; either way the frame's defined fields
     * are unambiguous, so refusing it would turn a forward-compatible change into an
     * outage. The value is kept so a re-encode can round-trip it and so a receiver
     * that does care can look.
     */
    val reservedFlags: Int get() = flags and Flags.RESERVED_MASK

    /** The total frame size, which is the header plus the body. */
    val totalLength: Long get() = headerLength.toLong() + bodyLength

    companion object {
        /** The header length DLWP/1 defines. */
        const val HEADER_LENGTH: Int = 24

        /** The ASCII magic that opens every frame. */
        const val MAGIC: Int = 0x444C5750 // "DLWP"
    }
}

/**
 * The flag bit values (RFC-0001 section 3.1).
 */
object Flags {
    /** Bit 0: the body is AEAD-protected. */
    const val ENCRYPTED = 0x01

    /** Bit 1: the frame is urgent and may overtake queued frames. */
    const val URGENT = 0x02

    /** Bit 2: this is the final frame of the channel's stream. */
    const val END_OF_STREAM = 0x04

    /** Bit 3: the body is compressed before encryption. */
    const val COMPRESSED = 0x08

    /** Bits 4 to 7 are reserved and must be preserved on decode. */
    const val RESERVED_MASK = 0xF0

    /** The flags DLWP/1 defines. */
    const val DEFINED_MASK = ENCRYPTED or URGENT or END_OF_STREAM or COMPRESSED
}
