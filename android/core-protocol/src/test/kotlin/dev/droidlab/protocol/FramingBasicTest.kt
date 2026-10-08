package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Conformance tests for the frame codec, driven by `framing-basic.json`.
 *
 * Every assertion comes from the vector file rather than from the implementation, so a
 * change to the wire format has to be a change to the vector. That is what makes this a
 * conformance test rather than a unit test: the C# implementation is checked against the
 * same file, and the file is the only thing the two agree on.
 */
class FramingBasicTest {
    private companion object {
        const val VECTOR_FILE = "framing-basic.json"
    }

    /** The decoded form of a vector, as the file describes it. */
    private data class DecodedExpectation(
        val version: Int,
        val flags: Int,
        val headerLength: Int,
        val messageType: Int,
        val channelId: Long,
        val sequenceNumber: Long,
        val acknowledgment: Long,
        val bodyLength: Long,
        val bodyHex: String?,
    )

    /**
     * Reads the expectation out of a vector.
     *
     * The file states the decoded header and the body separately, and both are needed:
     * the header fields say whether the decode read the right bytes, and the body says
     * whether it found the right end.
     *
     * The body's hex is a sibling of `decoded` rather than a member of it, which is the
     * file's own layout rather than an oversight: the decoded object is what the header
     * claims, and the body hex is what actually followed it.
     */
    private fun expectation(vector: JsonValue): DecodedExpectation {
        val decoded = vector["decoded"] ?: error("a framing vector has no \"decoded\" object")
        val header = decoded["header"] ?: error("a decoded vector has no \"header\"")

        return DecodedExpectation(
            version = header["version"]!!.asInt(),
            flags = header["flags"]!!.asInt(),
            headerLength = header["header_length"]!!.asInt(),
            messageType = header["message_type"]!!.asInt(),
            channelId = header["channel_id"]!!.asLong(),
            sequenceNumber = header["sequence_number"]!!.asLong(),
            acknowledgment = header["acknowledgment"]!!.asLong(),
            bodyLength = header["body_length"]!!.asLong(),
            bodyHex = vector["body_hex"]?.asString(),
        )
    }

    /** The frame's hex, which the file names `frame`. */
    private fun frameHex(vector: JsonValue): String =
        vector["frame"]?.asString() ?: error("a framing vector has no \"frame\"");

    /**
     * Every framing vector decodes to the fields the file declares.
     */
    @Test
    fun everyFramingVectorDecodesAsDeclared() {
        val vectors = Vectors.array(VECTOR_FILE, "vectors")

        assertTrue(vectors.size >= 6, "the file declares at least six vectors")

        for (vector in vectors) {
            val id = vector["id"]!!.asString()
            val hex = frameHex(vector)
            val expected = expectation(vector)

            val result = FrameCodec.read(Vectors.hex(hex))

            assertTrue(result is FrameCodec.ReadResult.Success, "$id did not decode: $result")

            val frame = (result as FrameCodec.ReadResult.Success).frame
            val header = frame.header

            assertEquals(expected.version, header.version, "$id version")
            assertEquals(expected.flags, header.flags, "$id flags")
            assertEquals(expected.headerLength, header.headerLength, "$id header length")
            assertEquals(expected.messageType, header.messageType, "$id message type")
            assertEquals(expected.channelId, header.channelId, "$id channel id")
            assertEquals(expected.sequenceNumber, header.sequenceNumber, "$id sequence number")
            assertEquals(expected.acknowledgment, header.acknowledgment, "$id acknowledgment")
            assertEquals(expected.bodyLength, header.bodyLength, "$id body length")

            // The body's length is what the header declares, and its contents are what
            // the file says they are. Checking only the length would miss a decoder that
            // read the right count from the wrong offset.
            assertEquals(expected.bodyLength.toInt(), frame.body.size, "$id body size")

            if (expected.bodyHex != null) {
                assertEquals(
                    Vectors.hex(expected.bodyHex).toList(),
                    frame.body.toList(),
                    "$id body bytes",
                )
            }
        }
    }

    /**
     * A frame round-trips through encode and decode unchanged.
     */
    @Test
    fun everyFramingVectorRoundTrips() {
        for (vector in Vectors.array(VECTOR_FILE, "vectors")) {
            val id = vector["id"]!!.asString()
            val decoded = FrameCodec.read(Vectors.hex(frameHex(vector)))

            assertTrue(decoded is FrameCodec.ReadResult.Success, "$id did not decode")

            val frame = (decoded as FrameCodec.ReadResult.Success).frame

            when (val encoded = FrameCodec.build(
                messageType = frame.messageType,
                body = frame.body,
                channelId = frame.channelId,
                sequenceNumber = frame.sequenceNumber,
                flags = frame.flags,
                acknowledgment = frame.header.acknowledgment,
            )) {
                is FrameHeaderCodec.EncodeResult.Failure ->
                    error("$id failed to re-encode: ${encoded.reason}")

                is FrameHeaderCodec.EncodeResult.Success -> {
                    // Byte-identical, not merely equal after a second decode. A
                    // round-trip that changes the reserved bits or the acknowledgment
                    // field is still a round-trip only if equality is checked on the
                    // bytes.
                    assertEquals(
                        Vectors.hex(frameHex(vector)).toList(),
                        encoded.bytes.toList(),
                        "$id did not round-trip byte-identically",
                    )
                }
            }
        }
    }

    /**
     * A truncated frame reports how many more bytes it needs, at every prefix length.
     */
    @Test
    fun everyPrefixOfAFrameReportsHowMuchIsMissing() {
        for (vector in Vectors.array(VECTOR_FILE, "vectors")) {
            val id = vector["id"]!!.asString()
            val full = Vectors.hex(frameHex(vector))

            // The empty prefix is included: a read of nothing is how every frame
            // starts, and a decoder that treated it as an error would fail on the
            // first packet of every connection.
            for (length in 0 until full.size) {
                val prefix = full.copyOfRange(0, length)
                val result = FrameCodec.read(prefix)

                assertTrue(
                    result is FrameCodec.ReadResult.NeedMoreBytes,
                    "$id truncated to $length bytes did not ask for more: $result",
                )

                val needed = (result as FrameCodec.ReadResult.NeedMoreBytes).neededBytes

                assertTrue(
                    needed > length,
                    "$id truncated to $length bytes asked for $needed, which is not more than it has",
                )

                assertTrue(
                    needed <= full.size,
                    "$id truncated to $length bytes asked for $needed, beyond the frame's ${full.size}",
                )
            }
        }
    }

    /**
     * A body over the limit is refused from the header alone.
     */
    @Test
    fun anOversizedDeclaredBodyIsRefusedBeforeTheBodyIsRead() {
        // A header declaring a body of 0xFFFFFFFF, with no body at all. The refusal must
        // come from the header, because the point of the limit is to refuse before the
        // allocation: a receiver that waits for the body has already been made to.
        val headerOnly = Vectors.hex("444c575001011832000000000000000100000000ffffffff")

        val result = FrameCodec.read(headerOnly)

        assertTrue(result is FrameCodec.ReadResult.Failure, "an oversized body was not refused: $result")
        assertEquals(ErrorCode.FRAME_TOO_LARGE, (result as FrameCodec.ReadResult.Failure).error)
    }

    /**
     * The AAD uses the plaintext length, not the wire's body length.
     *
     * The vector lives in `crypto-session-keys.json` rather than in the framing file,
     * because it is a property of the record protection and not of the frame layout. The
     * distinction it pins down is the whole reason `buildAad` exists as a function: the
     * header on the wire carries the *ciphertext* length, which for an encrypted frame
     * is the plaintext plus a nonce and a tag, while the authenticated string carries the
     * plaintext length. Here the plaintext is empty, so the field is zero even though the
     * frame's own body length would be 28.
     */
    @Test
    fun theAadUsesThePlaintextLength() {
        val vector = Vectors.array("crypto-session-keys.json", "aead_vectors")
            .first { it["id"]!!.asString() == "aead.header-is-associated-data" }

        val decoded = vector["aad_decoded"] ?: error("the aad vector has no aad_decoded")

        val header = FrameHeader(
            version = decoded["version"]!!.asInt(),
            flags = decoded["flags"]!!.asInt(),
            headerLength = decoded["header_length"]!!.asInt(),
            messageType = decoded["message_type"]!!.asInt(),
            channelId = decoded["channel_id"]!!.asLong(),
            sequenceNumber = decoded["sequence_number"]!!.asLong(),
            acknowledgment = decoded["acknowledgment"]!!.asLong(),
            // The wire header's body length, which the AAD replaces. The vector's own
            // note says it would be 28: a 12-byte nonce and a 16-byte tag around an empty
            // plaintext.
            bodyLength = 28,
        )

        val expected = Vectors.hex(vector["aad_bytes"]!!.asString())

        assertEquals(
            vector["aad_length"]!!.asInt(),
            expected.size,
            "the vector's own declared length disagrees with its bytes",
        )

        val actual = FrameCodec.buildAad(header, plaintextLength = 0)

        assertEquals(expected.size, actual.size, "the AAD is the 24-byte header")
        assertEquals(expected.toList(), actual.toList(), "the AAD does not match the vector")

        // The substitution really is happening: the AAD's last four bytes are the
        // plaintext length, which differs from the wire header's body length. Without
        // this the test would pass on an implementation that copied the header.
        assertEquals(
            0,
            decoded["body_length"]!!.asInt(),
            "the vector's AAD field is the plaintext length",
        )

        assertTrue(
            header.bodyLength != decoded["body_length"]!!.asLong(),
            "the vector only tests the substitution if the two lengths differ",
        )
    }

    /**
     * An empty body is zero bytes and is the canonical form.
     */
    @Test
    fun anEmptyBodyIsZeroBytes() {
        // A parameterless message, such as PING, sends no body at all. The header says
        // zero and the frame is exactly 24 bytes.
        val framed = FrameCodec.build(messageType = 5, body = ByteArray(0))

        assertTrue(framed is FrameHeaderCodec.EncodeResult.Success, "an empty body failed to frame")

        assertEquals(
            FrameHeader.HEADER_LENGTH,
            (framed as FrameHeaderCodec.EncodeResult.Success).bytes.size,
            "a parameterless frame is the header and nothing else",
        )

        val read = FrameCodec.read(framed.bytes)

        assertTrue(read is FrameCodec.ReadResult.Success, "an empty body failed to read back")
        assertEquals(0, (read as FrameCodec.ReadResult.Success).frame.body.size)
    }

    /**
     * Reserved flag bits survive a decode and a re-encode.
     */
    @Test
    fun reservedFlagBitsArePreserved() {
        // flags 0xF1: the ENCRYPTED bit plus every reserved bit.
        val frame = Vectors.hex("444c575001f1180500000000000000010000000000000000")

        val decoded = FrameCodec.read(frame)

        assertTrue(decoded is FrameCodec.ReadResult.Success, "a frame with reserved bits was refused: $decoded")

        val header = (decoded as FrameCodec.ReadResult.Success).frame.header

        // Preserved, not rejected and not masked away. Refusing the frame would turn a
        // forward-compatible change into an outage, and masking would lose a value the
        // peer may need echoed back.
        assertEquals(0xF1, header.flags)
        assertEquals(0xF0, header.reservedFlags)
        assertTrue(header.isEncrypted, "bit 0 is still the encrypted flag")
    }
}
