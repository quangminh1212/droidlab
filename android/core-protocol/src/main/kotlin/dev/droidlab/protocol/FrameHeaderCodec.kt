package dev.droidlab.protocol

/**
 * The DLWP/1 frame header codec (RFC-0001 section 3.1).
 *
 * The decoder never throws on malformed input. Every failure is a
 * [FrameDecodeResult.Failure] carrying an [ErrorCode], because a receive path that can
 * throw is a receive path that a peer can crash by sending a packet, and because
 * "malformed" is a protocol outcome with a defined response rather than a programming
 * error.
 *
 * The encoder validates rather than truncating. A field that does not fit its width is
 * a bug in the caller, and silently masking it would produce a frame that decodes to
 * something the sender did not mean -- for a sequence number, that means silently
 * reusing one.
 */
object FrameHeaderCodec {
    /**
     * The result of decoding a header.
     */
    sealed interface FrameDecodeResult {
        /** A header was decoded. */
        data class Success(val header: FrameHeader, val bytesConsumed: Int) : FrameDecodeResult

        /**
         * The header could not be decoded.
         *
         * @property error the error to report.
         * @property reason a human-readable explanation, for logs and tests.
         * @property neededBytes how many bytes are required to make progress, or null
         *   when no amount would help and the frame is simply wrong. This is the
         *   difference between "send me more" and "this will never parse", and a
         *   receiver that cannot tell them apart will either wait forever on a bad
         *   frame or close on a good one that arrived in two packets.
         */
        data class Failure(
            val error: ErrorCode,
            val reason: String,
            val neededBytes: Int? = null,
        ) : FrameDecodeResult
    }

    /** Magic, then version, flags, header length and message type. */
    private const val OFFSET_MAGIC = 0
    private const val OFFSET_VERSION = 4
    private const val OFFSET_FLAGS = 5
    private const val OFFSET_HEADER_LENGTH = 6
    private const val OFFSET_MESSAGE_TYPE = 7
    private const val OFFSET_CHANNEL_ID = 8
    private const val OFFSET_SEQUENCE_NUMBER = 12
    private const val OFFSET_ACKNOWLEDGMENT = 16
    private const val OFFSET_BODY_LENGTH = 20

    /**
     * Decodes a header.
     *
     * @param bytes the buffer.
     * @param offset where the frame starts.
     * @return the result.
     */
    fun decode(bytes: ByteArray, offset: Int = 0): FrameDecodeResult {
        if (offset < 0 || offset > bytes.size) {
            return FrameDecodeResult.Failure(
                ErrorCode.MALFORMED,
                "offset $offset is outside a buffer of ${bytes.size} bytes",
            )
        }

        val available = bytes.size - offset

        // A short buffer is not malformed. It is what every frame looks like at the
        // start, and what every frame looks like when a transport splits it, so the
        // answer is to wait for more and the caller needs to know how much more.
        if (available < FrameHeader.HEADER_LENGTH) {
            return FrameDecodeResult.Failure(
                ErrorCode.MALFORMED,
                "the header needs ${FrameHeader.HEADER_LENGTH} bytes but $available are available",
                neededBytes = FrameHeader.HEADER_LENGTH,
            )
        }

        val magic = readUInt32(bytes, offset + OFFSET_MAGIC)
        if (magic != FrameHeader.MAGIC.toLong()) {
            // Fatal and not recoverable. Bytes that are not a frame cannot be skipped
            // to find one, because there is no framing to resynchronise on: any
            // offset might look like a magic sequence inside a body.
            return FrameDecodeResult.Failure(
                ErrorCode.MALFORMED,
                "magic is 0x${magic.toString(16)} rather than 0x444c5750",
            )
        }

        val version = bytes[offset + OFFSET_VERSION].toInt() and 0xFF
        if (version != ProtocolVersion.MAJOR) {
            // A version this implementation cannot process. The difference from a
            // malformed frame matters: the bytes are well formed, so the peer is
            // speaking a protocol this side does not, and the answer is a version
            // mismatch rather than a malformed-frame close.
            return FrameDecodeResult.Failure(
                ErrorCode.VERSION_MISMATCH,
                "version $version is not ${ProtocolVersion.MAJOR}",
            )
        }

        val headerLength = bytes[offset + OFFSET_HEADER_LENGTH].toInt() and 0xFF
        if (headerLength == 0) {
            // Zero is not a short header, it is a frame that claims to have no header
            // at all, which cannot be true of a frame whose magic has just been read.
            return FrameDecodeResult.Failure(
                ErrorCode.MALFORMED,
                "header length 0 is not a header",
            )
        }

        if (headerLength != FrameHeader.HEADER_LENGTH) {
            // Well formed but not this version's shape. Distinguishing this from a
            // malformed frame is what lets a receiver say "I cannot read this" rather
            // than "you sent garbage".
            return FrameDecodeResult.Failure(
                ErrorCode.UNSUPPORTED_HEADER,
                "header length $headerLength is not ${FrameHeader.HEADER_LENGTH}",
            )
        }

        val header = FrameHeader(
            version = version,
            flags = bytes[offset + OFFSET_FLAGS].toInt() and 0xFF,
            headerLength = headerLength,
            messageType = bytes[offset + OFFSET_MESSAGE_TYPE].toInt() and 0xFF,
            channelId = readUInt32(bytes, offset + OFFSET_CHANNEL_ID),
            sequenceNumber = readUInt32(bytes, offset + OFFSET_SEQUENCE_NUMBER),
            acknowledgment = readUInt32(bytes, offset + OFFSET_ACKNOWLEDGMENT),
            bodyLength = readUInt32(bytes, offset + OFFSET_BODY_LENGTH),
        )

        return FrameDecodeResult.Success(header, FrameHeader.HEADER_LENGTH)
    }

    /**
     * Encodes a header.
     *
     * @param header the header.
     * @return the 24 bytes, or the error code when a field does not fit.
     */
    fun encode(header: FrameHeader): EncodeResult {
        val failure = validate(header)
        if (failure != null) {
            return EncodeResult.Failure(failure)
        }

        val out = ByteArray(FrameHeader.HEADER_LENGTH)

        writeUInt32(out, OFFSET_MAGIC, FrameHeader.MAGIC.toLong())
        out[OFFSET_VERSION] = header.version.toByte()
        out[OFFSET_FLAGS] = header.flags.toByte()
        out[OFFSET_HEADER_LENGTH] = header.headerLength.toByte()
        out[OFFSET_MESSAGE_TYPE] = header.messageType.toByte()
        writeUInt32(out, OFFSET_CHANNEL_ID, header.channelId)
        writeUInt32(out, OFFSET_SEQUENCE_NUMBER, header.sequenceNumber)
        writeUInt32(out, OFFSET_ACKNOWLEDGMENT, header.acknowledgment)
        writeUInt32(out, OFFSET_BODY_LENGTH, header.bodyLength)

        return EncodeResult.Success(out)
    }

    /**
     * The result of encoding a header.
     */
    sealed interface EncodeResult {
        /** The bytes. */
        data class Success(val bytes: ByteArray) : EncodeResult {
            // A data class holding an array needs these by hand. Identity comparison
            // would make two equal frames unequal, which would make a round-trip test
            // fail for a reason that has nothing to do with the protocol.
            override fun equals(other: Any?): Boolean =
                other is Success && bytes.contentEquals(other.bytes)

            override fun hashCode(): Int = bytes.contentHashCode()
        }

        /** A field did not fit, or a header field is one this version may not send. */
        data class Failure(val error: ErrorCode, val reason: String) : EncodeResult
    }

    /**
     * Validates a header before encoding.
     *
     * @param header the header.
     * @return the error code and reason, or null when the header is encodable.
     */
    private fun validate(header: FrameHeader): Pair<ErrorCode, String>? {
        if (header.version != ProtocolVersion.MAJOR) {
            return ErrorCode.VERSION_MISMATCH to
                "version ${header.version} is not ${ProtocolVersion.MAJOR}"
        }

        if (header.headerLength != FrameHeader.HEADER_LENGTH) {
            return ErrorCode.UNSUPPORTED_HEADER to
                "header length ${header.headerLength} is not ${FrameHeader.HEADER_LENGTH}"
        }

        // Four bytes each, so anything above a uint32 is a caller bug rather than a
        // value to truncate.
        for ((name, value) in listOf(
            "channel id" to header.channelId,
            "sequence number" to header.sequenceNumber,
            "acknowledgment" to header.acknowledgment,
            "body length" to header.bodyLength,
        )) {
            if (value < 0 || value > UINT32_MAX) {
                return ErrorCode.MALFORMED to "$name $value does not fit in four bytes"
            }
        }

        if (header.flags < 0 || header.flags > 0xFF) {
            return ErrorCode.MALFORMED to "flags ${header.flags} does not fit in one byte"
        }

        if (header.messageType < 0 || header.messageType > 0xFF) {
            return ErrorCode.MALFORMED to
                "message type ${header.messageType} does not fit in one byte"
        }

        return null
    }

    /** The largest value a four-byte field holds. */
    private const val UINT32_MAX = 0xFFFFFFFFL

    /** Reads a big-endian uint32 widened to a Long, which is how Kotlin holds it. */
    internal fun readUInt32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xFF) shl 24) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
            (bytes[offset + 3].toLong() and 0xFF)

    /** Writes a big-endian uint32. */
    internal fun writeUInt32(bytes: ByteArray, offset: Int, value: Long) {
        bytes[offset] = ((value ushr 24) and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 3] = (value and 0xFF).toByte()
    }
}

/**
 * The protocol version DLWP/1 implements.
 */
object ProtocolVersion {
    /**
     * The major version.
     *
     * Only the major version is on the wire. A peer running 1.2 and one running 1.0
     * both send 1 here, because a minor difference is negotiable inside the handshake
     * and putting it in the header would turn a compatible pair into a mismatch.
     */
    const val MAJOR: Int = 1

    /** The full version this implementation speaks. */
    const val FULL: String = "1.0"
}
