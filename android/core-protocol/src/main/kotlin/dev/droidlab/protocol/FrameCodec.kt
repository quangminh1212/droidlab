package dev.droidlab.protocol

/**
 * A complete frame: a decoded header and its body.
 *
 * @property header the header.
 * @property body the body bytes exactly as they arrived. For an encrypted frame these
 *   are the ciphertext and not the plaintext, because decryption belongs to the session
 *   layer and not here -- this type is what the wire carried, and it must not pretend
 *   otherwise.
 */
data class Frame(val header: FrameHeader, val body: ByteArray) {
    /** The message type code. */
    val messageType: Int get() = header.messageType

    /** The channel. */
    val channelId: Long get() = header.channelId

    /** The sequence number. */
    val sequenceNumber: Long get() = header.sequenceNumber

    override fun equals(other: Any?): Boolean =
        other is Frame &&
            header == other.header &&
            body.contentEquals(other.body)

    override fun hashCode(): Int = 31 * header.hashCode() + body.contentHashCode()
}

/**
 * The DLWP/1 frame codec (RFC-0001 section 3).
 *
 * Assembling a frame from a stream is the part that is easy to get subtly wrong, so it
 * is stated here rather than left to callers:
 *
 * * A frame is `header_length + body_length` bytes, and the header's own length field
 *   is what makes that true of future versions rather than only of this one.
 * * A partial frame is not an error. It is what every frame looks like at the start and
 *   what a frame looks like when a transport splits it, so the answer is to wait for
 *   more, and the caller is told how many bytes that is.
 * * A body larger than the negotiated limit is refused from the header alone, before the
 *   body is read. This is the one that matters: a peer that declares a four-gigabyte body
 *   must not be able to make the receiver allocate for it, and the header is the only
 *   place to catch that, because by the time the body has been read the allocation has
 *   already happened.
 */
object FrameCodec {
    /** The default maximum frame body, from the registry's `max_frame_bytes`. */
    const val DEFAULT_MAX_FRAME_BYTES: Long = 16_777_216

    /**
     * The result of trying to read a frame from a buffer.
     */
    sealed interface ReadResult {
        /** A complete frame was read. */
        data class Success(val frame: Frame, val bytesConsumed: Int) : ReadResult

        /**
         * More bytes are needed.
         *
         * @property neededBytes the total frame length once known, or the header length
         *   when the header itself is still incomplete. This is not inferred from the
         *   error code by the caller, because "wait for more" and "this is garbage" lead
         *   to opposite actions and conflating them either hangs on a bad frame or
         *   closes on a good one that arrived in two packets.
         */
        data class NeedMoreBytes(val neededBytes: Int) : ReadResult

        /** The frame is wrong; the values are the error and why. */
        data class Failure(val error: ErrorCode, val reason: String) : ReadResult
    }

    /**
     * Reads one frame from the start of a buffer.
     *
     * @param bytes the buffer.
     * @param offset where the frame starts.
     * @param maxFrameBytes the largest body this side accepts.
     * @return the result.
     */
    fun read(
        bytes: ByteArray,
        offset: Int = 0,
        maxFrameBytes: Long = DEFAULT_MAX_FRAME_BYTES,
    ): ReadResult {
        if (maxFrameBytes < 0) {
            return ReadResult.Failure(ErrorCode.MALFORMED, "the frame size limit may not be negative")
        }

        when (val headerResult = FrameHeaderCodec.decode(bytes, offset)) {
            is FrameHeaderCodec.FrameDecodeResult.Failure -> {
                // A short header is the one decode failure that waiting can fix. Every
                // other one is a property of bytes that have already arrived.
                return if (headerResult.neededBytes != null) {
                    val available = bytes.size - offset
                    val missing = headerResult.neededBytes - available
                    ReadResult.NeedMoreBytes(available + missing)
                } else {
                    ReadResult.Failure(headerResult.error, headerResult.reason)
                }
            }

            is FrameHeaderCodec.FrameDecodeResult.Success -> {
                val header = headerResult.header

                // Size is checked from the header alone, before any body is read. The
                // point is to refuse before allocating: a declared length is a request
                // for memory, and a receiver that trusts it can be made to allocate
                // whatever a peer asks for.
                if (header.bodyLength > maxFrameBytes) {
                    return ReadResult.Failure(
                        ErrorCode.FRAME_TOO_LARGE,
                        "the body declares ${header.bodyLength} bytes, above the " +
                            "$maxFrameBytes this side accepts",
                    )
                }

                val totalLength = header.totalLength

                // A body length that would overflow the arithmetic rather than the
                // buffer. Four-byte fields make this reachable, so it is checked rather
                // than assumed: header 24 + body up to 2^32 - 1 fits a Long but not an
                // Int, and casting it would wrap to a length that could match a short
                // buffer.
                if (totalLength > Int.MAX_VALUE) {
                    return ReadResult.Failure(
                        ErrorCode.FRAME_TOO_LARGE,
                        "the frame would be $totalLength bytes, beyond what can be addressed",
                    )
                }

                val available = bytes.size - offset

                if (available < totalLength) {
                    return ReadResult.NeedMoreBytes(totalLength.toInt())
                }

                val body = bytes.copyOfRange(
                    offset + header.headerLength,
                    offset + header.headerLength + header.bodyLength.toInt(),
                )

                return ReadResult.Success(Frame(header, body), totalLength.toInt())
            }
        }
    }

    /**
     * Reads every complete frame from a buffer.
     *
     * @param bytes the buffer.
     * @param maxFrameBytes the largest body accepted.
     * @return the frames, and how many bytes were consumed. The remainder is the start
     *   of a frame that is still arriving.
     */
    fun readAll(
        bytes: ByteArray,
        maxFrameBytes: Long = DEFAULT_MAX_FRAME_BYTES,
    ): Pair<List<Frame>, Int> {
        val frames = mutableListOf<Frame>()
        var offset = 0

        while (offset < bytes.size) {
            when (val result = read(bytes, offset, maxFrameBytes)) {
                is ReadResult.Success -> {
                    frames.add(result.frame)
                    offset += result.bytesConsumed
                }

                // A partial trailing frame is the normal end of a read, not a failure:
                // the rest has not arrived yet.
                is ReadResult.NeedMoreBytes -> return frames to offset

                is ReadResult.Failure -> return frames to offset
            }
        }

        return frames to offset
    }

    /**
     * Builds a frame.
     *
     * @param messageType the message type code.
     * @param body the body bytes.
     * @param channelId the channel.
     * @param sequenceNumber the sequence number.
     * @param flags the flag byte.
     * @param acknowledgment the acknowledgment field.
     * @return the result.
     */
    fun build(
        messageType: Int,
        body: ByteArray,
        channelId: Long = 0,
        sequenceNumber: Long = 0,
        flags: Int = 0,
        acknowledgment: Long = 0,
    ): FrameHeaderCodec.EncodeResult {
        val header = FrameHeader(
            version = ProtocolVersion.MAJOR,
            flags = flags,
            headerLength = FrameHeader.HEADER_LENGTH,
            messageType = messageType,
            channelId = channelId,
            sequenceNumber = sequenceNumber,
            acknowledgment = acknowledgment,
            bodyLength = body.size.toLong(),
        )

        return when (val encoded = FrameHeaderCodec.encode(header)) {
            is FrameHeaderCodec.EncodeResult.Failure -> encoded

            is FrameHeaderCodec.EncodeResult.Success -> {
                val out = ByteArray(encoded.bytes.size + body.size)
                encoded.bytes.copyInto(out, 0)
                body.copyInto(out, encoded.bytes.size)
                FrameHeaderCodec.EncodeResult.Success(out)
            }
        }
    }

    /**
     * The AAD to authenticate an encrypted frame under (RFC-0002 section 3).
     *
     * @param header the frame's header.
     * @param plaintextLength the plaintext length, before encryption.
     * @return the 24-byte AAD.
     * @throws IllegalArgumentException when the length does not fit a four-byte field.
     *
     * The AAD is the header with `body_length` replaced by the *plaintext* length, and
     * that replacement is the whole reason this function exists rather than the caller
     * passing the header's own bytes.
     *
     * The header on the wire carries the ciphertext length, which is the plaintext
     * length plus the nonce and the tag. Authenticating the wire header directly would
     * therefore authenticate a value the sender could change by changing the nonce
     * length, and -- more importantly -- it would make the AAD depend on the encryption
     * parameters rather than only on the message, so two encryptors that agreed on the
     * plaintext but not on the nonce size would produce frames the other could not
     * verify. Substituting the plaintext length makes the AAD a function of the message
     * and of the header's non-encryption fields, which is what the sender and receiver
     * can agree on before encrypting.
     */
    fun buildAad(header: FrameHeader, plaintextLength: Int): ByteArray {
        require(plaintextLength >= 0) { "the plaintext length may not be negative" }

        if (plaintextLength.toLong() > 0xFFFFFFFFL) {
            throw IllegalArgumentException("the plaintext length does not fit in four bytes")
        }

        val aad = ByteArray(FrameHeader.HEADER_LENGTH)
        aad[0] = 0x44 // D
        aad[1] = 0x4C // L
        aad[2] = 0x57 // W
        aad[3] = 0x50 // P
        aad[4] = header.version.toByte()
        aad[5] = header.flags.toByte()
        aad[6] = header.headerLength.toByte()
        aad[7] = header.messageType.toByte()
        FrameHeaderCodec.writeUInt32(aad, 8, header.channelId)
        FrameHeaderCodec.writeUInt32(aad, 12, header.sequenceNumber)
        FrameHeaderCodec.writeUInt32(aad, 16, header.acknowledgment)
        FrameHeaderCodec.writeUInt32(aad, 20, plaintextLength.toLong())

        return aad
    }
}
