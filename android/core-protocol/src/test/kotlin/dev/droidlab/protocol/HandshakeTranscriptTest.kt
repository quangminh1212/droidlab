package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Conformance tests for the handshake transcript, driven by `handshake-transcript.json`.
 *
 * Every assertion is byte-exact, and that is not pedantry here. The transcript is what the
 * AUTH proofs are computed over, so an implementation that produces a transcript agreeing
 * with itself and with no peer does not fail loudly -- it fails as an authentication error
 * on the other side, at the point where the two implementations are hardest to compare. The
 * vectors record the expected bytes and the expected length separately so that a
 * length-computing bug and a layout bug cannot hide behind each other.
 */
class HandshakeTranscriptTest {
    private companion object {
        const val VECTOR_FILE = "handshake-transcript.json"

        /** The sixteen hex-encoded bytes of the label, "DLWP/1-handshake". */
        const val LABEL_HEX = "444c57502f312d68616e647368616b65"
    }

    /** The two accepted vectors. */
    private fun vectors(): List<JsonValue> = Vectors.array(VECTOR_FILE, "vectors")

    /** The vectors that must be distinguishable rather than accepted. */
    private fun rejectionVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "rejection_vectors")

    /** A vector by id, failing if it is missing so a renamed vector cannot silently skip. */
    private fun vector(id: String): JsonValue =
        vectors().firstOrNull { it["id"]?.asString() == id }
            ?: error("handshake-transcript.json has no vector \"$id\"")

    /**
     * Builds the transcript a vector describes.
     *
     * The nonces and keys are base64url **unpadded** in this file, which is a different
     * alphabet from the base64 used for opaque payloads elsewhere. Decoding one as the other
     * produces bytes that decode without complaint and are simply wrong, so the two decoders
     * are kept apart rather than unified.
     */
    private fun build(v: JsonValue): ByteArray {
        val inputs = v["inputs"] ?: error("a transcript vector has no inputs")

        return HandshakeTranscript.build(
            clientId = inputs["client_id"]!!.asString(),
            agentId = inputs["agent_id"]!!.asString(),
            clientNonce = Vectors.base64Url(inputs["client_nonce"]!!.asString()),
            agentNonce = Vectors.base64Url(inputs["agent_nonce"]!!.asString()),
            clientPublicKey = Vectors.base64Url(inputs["client_pub"]!!.asString()),
            agentPublicKey = Vectors.base64Url(inputs["agent_pub"]!!.asString()),
        )
    }

    /**
     * Every vector produces exactly the declared bytes.
     */
    @Test
    fun everyVectorProducesItsDeclaredBytes() {
        assertTrue(vectors().size >= 2, "expected at least 2 transcript vectors")

        for (v in vectors()) {
            val id = v["id"]!!.asString()
            val expected = v["expected"] ?: error("$id has no expected object")

            val expectedBytes = Vectors.hex(expected["transcript_bytes"]!!.asString())
            val actual = build(v)

            assertEquals(expectedBytes.toList(), actual.toList(), "$id transcript bytes")

            // The declared length is checked against the produced bytes rather than against
            // the implementation's own length function, so a length bug cannot mask a layout
            // bug: the two are independent measurements of the same thing.
            assertEquals(
                expected["transcript_length_bytes"]!!.asInt(),
                actual.size,
                "$id declared length",
            )
        }
    }

    /**
     * Every vector's hash is the SHA-256 of its own declared bytes.
     */
    @Test
    fun everyVectorHashMatchesItsDeclaredBytes() {
        for (v in vectors()) {
            val id = v["id"]!!.asString()
            val expected = v["expected"]!!

            val bytes = Vectors.hex(expected["transcript_bytes"]!!.asString())
            val declaredHash = Vectors.hex(expected["transcript_sha256"]!!.asString())

            // Hashed from the vector's own bytes, not from the implementation's output. A
            // test that hashed its own transcript would pass even if both were wrong in the
            // same way, because the vector's bytes are the independent fact.
            assertEquals(
                declaredHash.toList(),
                HandshakeTranscript.hash(bytes).toList(),
                "$id declared hash is the SHA-256 of its declared bytes",
            )

            // And the implementation's output hashes to the same value.
            assertEquals(
                declaredHash.toList(),
                HandshakeTranscript.hash(build(v)).toList(),
                "$id hash of the built transcript",
            )
        }
    }

    /**
     * The transcript opens with the label and its separators in the right places.
     */
    @Test
    fun theLayoutIsTheDeclaredOne() {
        val v = vector("transcript.synthetic.basic")
        val bytes = build(v)

        // The label and the first separator, byte for byte.
        assertEquals(
            Vectors.hex(LABEL_HEX).toList(),
            bytes.copyOfRange(0, HandshakeTranscript.LABEL_LENGTH).toList(),
            "the transcript opens with \"DLWP/1-handshake\"",
        )

        assertEquals(
            HandshakeTranscript.SEPARATOR,
            bytes[HandshakeTranscript.LABEL_LENGTH].toInt() and 0xFF,
            "a separator follows the label",
        )

        // The declared identifier length prefixes, which are the parts that stop the
        // collision the rejection vectors describe.
        val expected = v["expected"]!!
        val clientPrefixAt = 17

        assertEquals(
            expected["client_id_length_prefix"]!!.asString(),
            hexOf(bytes, clientPrefixAt, 2),
            "the client_id length prefix",
        )

        // The agent's prefix follows: 2 (prefix) + the client id's bytes + 1 (separator).
        val clientIdLength = Vectors.hex(expected["client_id_length_prefix"]!!.asString())
            .let { ((it[0].toInt() and 0xFF) shl 8) or (it[1].toInt() and 0xFF) }

        val agentPrefixAt = clientPrefixAt + 2 + clientIdLength + 1

        assertEquals(
            expected["agent_id_length_prefix"]!!.asString(),
            hexOf(bytes, agentPrefixAt, 2),
            "the agent_id length prefix",
        )
    }

    /**
     * The length function agrees with the bytes it is meant to predict.
     */
    @Test
    fun theLengthFunctionAgreesWithTheBytes() {
        for (v in vectors()) {
            val id = v["id"]!!.asString()
            val inputs = v["inputs"]!!

            val predicted = HandshakeTranscript.length(
                inputs["client_id"]!!.asString(),
                inputs["agent_id"]!!.asString(),
            )

            assertEquals(build(v).size, predicted, "$id length function")
            assertEquals(v["expected"]!!["transcript_length_bytes"]!!.asInt(), predicted, "$id declared length")
        }

        // And the floor is what the vectors say it is. A derived constant checked against a
        // recorded one, because a mistake in the derivation would otherwise redefine the
        // format's own lower bound.
        assertEquals(
            HandshakeTranscript.MINIMUM_LENGTH,
            vector("transcript.minimum-length")["expected"]!!["transcript_length_bytes"]!!.asInt(),
            "MINIMUM_LENGTH matches the shortest vector",
        )

        // The formula from the file, evaluated independently:
        // 16 + 1 + (2+1) + 1 + (2+1) + 1 + 128.
        assertEquals(153, 16 + 1 + 3 + 1 + 3 + 1 + 128, "the file's arithmetic")
    }

    /**
     * Two different identifier splits never produce the same transcript.
     */
    @Test
    fun aLengthPrefixPreventsAnIdentifierCollision() {
        val minimum = vector("transcript.minimum-length")

        val rejection = rejectionVectors()
            .first { it["id"]!!.asString() == "transcript.reject.leading-separator-confusion" }

        // The collision the length prefixes exist to prevent: without them, client_id="c"
        // with agent_id="a" would serialise identically to client_id="c\x00a" with an empty
        // agent_id, so two different handshakes would share a transcript and therefore share
        // a proof.
        assertEquals("c", minimum["inputs"]!!["client_id"]!!.asString())
        assertEquals("a", minimum["inputs"]!!["agent_id"]!!.asString())
        assertEquals("c\u0000a", rejection["inputs"]!!["client_id"]!!.asString())
        assertEquals("", rejection["inputs"]!!["agent_id"]!!.asString())

        // The two transcripts must be distinct. That is the requirement; the mechanism is
        // discussed below rather than assumed.
        val minimumBytes = build(minimum)
        val rejectionBytes = build(rejection)

        assertTrue(
            !minimumBytes.contentEquals(rejectionBytes),
            "the two identifier splits must produce distinct transcripts",
        )

        // The rejection vector declares its own length, and it is one byte longer than the
        // floor: the empty agent_id still contributes its two-byte length prefix while the
        // client_id carries one extra byte.
        assertEquals(
            rejection["expected"]!!["transcript_length_bytes"]!!.asInt(),
            rejectionBytes.size,
            "the rejection vector's declared length",
        )

        assertEquals(
            minimumBytes.size + 1,
            rejectionBytes.size,
            "the collision attempt is exactly one byte longer than the floor",
        )

        // The length prefixes do the work, and the difference is the *prefix*, not the label
        // or the separators. The two transcripts share everything up to and including the
        // first separator and the first prefix, so the prefix is where they diverge:
        //
        //   floor    : 00 01 "c" 00 00 01 "a" 00 ...
        //   rejection: 00 03 "c\x00a" 00 00 00 "" 00 ...
        //
        // A reader can see that the second transcript's agent_id prefix is 0x0000 -- a
        // present, zero-length field -- where a form that simply omitted an empty identifier
        // would have nothing there at all. That present-but-empty prefix is what keeps the
        // two distinct, and it is why the format states the prefix as two bytes rather than
        // as "the identifier's bytes".
        val clientPrefixAt = HandshakeTranscript.LABEL_LENGTH + 1

        assertEquals(
            "0001",
            hexOf(minimumBytes, clientPrefixAt, 2),
            "the floor vector's client_id prefix is 1",
        )

        assertEquals(
            "0003",
            hexOf(rejectionBytes, clientPrefixAt, 2),
            "the rejection vector's client_id prefix is 3",
        )

        // The agent_id prefix sits after the separator that follows the client_id, and the
        // rejection vector's is zero -- present, and describing an empty identifier.
        val rejectionAgentPrefixAt = clientPrefixAt + 2 + 3 + 1

        assertEquals(
            "0000",
            hexOf(rejectionBytes, rejectionAgentPrefixAt, 2),
            "the rejection vector's agent_id prefix is 0 and is present",
        )

        // The two diverge at the prefix itself, which is the earliest point they could.
        assertTrue(
            minimumBytes[clientPrefixAt] != rejectionBytes[clientPrefixAt] ||
                minimumBytes[clientPrefixAt + 1] != rejectionBytes[clientPrefixAt + 1],
            "the two transcripts differ at the client_id length prefix",
        )
    }

    /**
     * The distinguished vector's declared inputs bracket the boundary.
     */
    @Test
    fun theTwoVectorsBracketTheFormat() {
        val minimum = vector("transcript.minimum-length")
        val basic = vector("transcript.synthetic.basic")

        // The shortest and a typical one, so a reader can see the format's floor and a real
        // case side by side. Both hashes differ, which is what a length-derived layout
        // implies.
        assertEquals(153, build(minimum).size)
        assertEquals(223, build(basic).size)

        assertTrue(
            !HandshakeTranscript.hash(build(minimum))
                .contentEquals(HandshakeTranscript.hash(build(basic))),
            "different transcripts hash differently",
        )
    }

    /**
     * A wrong-width field is refused rather than silently shifted.
     */
    @Test
    fun aWrongWidthFieldIsRefused() {
        val v = vector("transcript.minimum-length")
        val inputs = v["inputs"]!!

        val clientNonce = Vectors.base64Url(inputs["client_nonce"]!!.asString())
        val agentNonce = Vectors.base64Url(inputs["agent_nonce"]!!.asString())
        val clientPub = Vectors.base64Url(inputs["client_pub"]!!.asString())
        val agentPub = Vectors.base64Url(inputs["agent_pub"]!!.asString())

        // A 31-byte nonce would shift every field after it, producing a transcript of the
        // right length describing the wrong values. Refusing it is the difference between an
        // error here and an unexplained authentication failure on the peer.
        assertFailsWith<IllegalArgumentException>("a short nonce is refused") {
            HandshakeTranscript.build(
                "c",
                "a",
                clientNonce.copyOfRange(0, 31),
                agentNonce,
                clientPub,
                agentPub,
            )
        }

        assertFailsWith<IllegalArgumentException>("a short public key is refused") {
            HandshakeTranscript.build(
                "c",
                "a",
                clientNonce,
                agentNonce,
                clientPub.copyOf(31),
                agentPub,
            )
        }

        // An over-long identifier would wrap the two-byte prefix and produce a transcript
        // describing different identifiers than the ones given, which is a collision an
        // attacker could aim for.
        assertFailsWith<IllegalArgumentException>("an over-long identifier is refused") {
            HandshakeTranscript.length("x".repeat(65536), "a")
        }
    }

    /** Hex-encodes a slice of a byte array, for comparing against a vector's prefix field. */
    private fun hexOf(bytes: ByteArray, offset: Int, length: Int): String =
        bytes.copyOfRange(offset, offset + length)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
