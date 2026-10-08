package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Conformance tests for malformed input, driven by `malformed.json`.
 *
 * This is the file that decides whether a hostile or broken peer can be survived, so the
 * assertions are exact rather than approximate: every vector names the outcome, the error
 * and the severity, and all three are checked. Checking only the error code would miss a
 * classification that reports the right code with the wrong severity, which is the
 * difference between a session that continues and one that dies.
 */
class MalformedTest {
    private companion object {
        const val VECTOR_FILE = "malformed.json"

        /**
         * The registry the classifier is given.
         *
         * Hand-built rather than loaded, because this module has no runtime dependencies and
         * the registry is data. It carries only what the vectors exercise: the codes they
         * name, which messages are handshake messages, and the one capability gate the
         * `unknown-capability-command` vector needs.
         */
        val REGISTRY = object : Registry {
            // From protocol/registry/dlwp-1.json, only the codes these vectors use.
            private val types = mapOf(
                1 to MessageTypeDefinition(1, "HELLO", true, false),
                2 to MessageTypeDefinition(2, "HELLO_ACK", true, false),
                3 to MessageTypeDefinition(3, "AUTH", true, true),
                4 to MessageTypeDefinition(4, "AUTH_OK", true, true),
                5 to MessageTypeDefinition(5, "PING", false, true),
                50 to MessageTypeDefinition(50, "VIDEO_CONFIG", false, true),
                64 to MessageTypeDefinition(64, "INPUT_TOUCH", false, true),
                80 to MessageTypeDefinition(80, "SHELL_EXEC", false, true),
            )

            // SHELL_EXEC is gated on shell.exec; the rest are ungated. INPUT_TOUCH is gated
            // on input.touch, which the vector negotiates.
            private val capabilities = mapOf(
                64 to "input.touch",
                80 to "shell.exec",
            )

            override fun findMessageType(code: Int): MessageTypeDefinition? = types[code]

            override fun messageTypeCapability(code: Int): String? = capabilities[code]

            override val maxChannels: Int = 8
        }

        val CLASSIFIER = FrameClassifier(REGISTRY)

        const val MESSAGE_TYPE = 64
        const val HELLO_MESSAGE_TYPE = 1
    }

    /**
     * The outcome name a vector uses, mapped to the enum.
     *
     * The vector files use stable strings rather than numbers, so this mapping is the one
     * place the two vocabularies meet. An unrecognised name fails rather than defaulting,
     * because a vector naming an outcome this test does not know is a vector the test cannot
     * be checking.
     */
    private fun outcomeFor(name: String): FrameOutcome = when (name) {
        "accepted" -> FrameOutcome.Accepted
        "error_session_continues" -> FrameOutcome.ErrorSessionContinues
        "error_frame_then_close" -> FrameOutcome.ErrorFrameThenClose
        "close_connection" -> FrameOutcome.CloseConnection
        "wait_then_error_on_close" -> FrameOutcome.WaitThenErrorOnClose
        else -> error("unknown expected outcome \"$name\"")
    }

    /** All malformed vectors. */
    private fun vectors(): List<JsonValue> = Vectors.array(VECTOR_FILE, "vectors")

    /**
     * Builds a plaintext frame with no body on a given channel.
     *
     * It returns wire bytes rather than a `Frame`, because the classifier's entry point takes
     * bytes: the semantic vectors name a message type and a channel but carry no frame, so the
     * test has to build one, and building the bytes is what lets it go through the same path a
     * received frame does -- magic check, header, size, body -- rather than skipping to the
     * meaning. A helper rather than six fields at each call site, because repeating them is
     * where a copy-paste mistake would hide.
     *
     * The body is empty, which the cbOR reader accepts as the canonical encoding of a
     * parameterless message.
     *
     * @param messageType the message type code.
     * @param channelId the channel.
     * @return the frame's bytes.
     */
    private fun frame(messageType: Int, channelId: Long = 0): ByteArray {
        val header = FrameHeader(
            version = ProtocolVersion.MAJOR,
            flags = 0,
            headerLength = FrameHeader.HEADER_LENGTH,
            messageType = messageType,
            channelId = channelId,
            sequenceNumber = 0,
            acknowledgment = 0,
            bodyLength = 0,
        )

        return when (val encoded = FrameHeaderCodec.encode(header)) {
            is FrameHeaderCodec.EncodeResult.Failure ->
                error("the test's own frame failed to encode: ${encoded.reason}")

            is FrameHeaderCodec.EncodeResult.Success -> encoded.bytes
        }
    }

    /** A vector by id, failing if it is missing so a renamed vector cannot silently skip. */
    private fun vector(id: String): JsonValue =
        vectors().firstOrNull { it["id"]?.asString() == id }
            ?: error("malformed.json has no vector \"$id\"")

    /**
     * Classifies a vector that carries a raw frame.
     *
     * It goes through the classifier's `classify(bytes, context)` entry point rather than
     * reading the frame first and classifying that, and the difference is the whole point of
     * the `malformed.bad-magic` vector: bytes that are not a frame must close the connection
     * with no error frame, and that decision is made before the header is parsed. Reading the
     * frame first would turn the one case that closes without replying into an ordinary
     * malformed-frame error, which is the opposite of what the vector requires.
     *
     * @param v the vector.
     * @return the verdict the classifier produces.
     */
    private fun classifyFrameVector(v: JsonValue): FrameVerdict =
        CLASSIFIER.classify(
            Vectors.hex(v["frame"]!!.asString()),
            FrameClassifier.Context(
                // A first-frame vector is exactly the case where nothing is open yet.
                openChannels = emptySet(),
                negotiatedCapabilities = emptySet(),
                isFirstFrame = v["first_frame_message_type"] != null,
            ),
        )

    /**
     * Every vector that carries a raw frame produces its declared verdict.
     */
    @Test
    fun everyRawFrameVectorMatchesItsDeclaredOutcome() {
        val frameVectors = vectors().filter { it["frame"] != null }

        assertTrue(frameVectors.size >= 12, "expected at least 12 raw-frame vectors")

        for (v in frameVectors) {
            val id = v["id"]!!.asString()
            val expected = outcomeFor(v["expected"]!!.asString())
            val verdict = classifyFrameVector(v)

            assertEquals(expected, verdict.outcome, "$id outcome")
            assertEquals(
                v["expected_error"]?.asString()?.let { ErrorCode.fromWireName(it) },
                verdict.error,
                "$id error code",
            )

            // The severity is derived from the code rather than stored separately, which is
            // the point: a classification cannot report a fatal outcome with a recoverable
            // code, because there is only one place the severity lives.
            if (v["expected_severity"] != null) {
                val severity = v["expected_severity"]!!.asString()
                val fatal = severity == "fatal"

                if (fatal) {
                    assertTrue(
                        !verdict.sessionSurvives,
                        "$id is fatal so the session must not survive, got ${verdict.outcome}",
                    )
                } else {
                    assertTrue(
                        verdict.sessionSurvives,
                        "$id is $severity so the session must survive, got ${verdict.outcome}",
                    )
                }
            }
        }
    }

    /**
     * A frame that is not a DLWP/1 frame closes the connection with no error frame.
     */
    @Test
    fun aBadMagicClosesWithoutAnErrorFrame() {
        val v = vector("malformed.bad-magic")

        assertEquals("close_connection", v["expected"]!!.asString())

        val bytes = Vectors.hex(v["frame"]!!.asString())

        // The vector must actually carry a bad magic, or the test is asserting the rule
        // against a frame that does not exercise it.
        assertTrue(!CLASSIFIER.hasMagic(bytes), "the bad-magic vector must not start with DLWP")

        // Classified from the bytes, not from a decoded frame: the decision that matters is
        // that a wrong magic is caught before the header is parsed, and passing an
        // already-decoded frame would skip exactly the step being tested.
        val verdict = CLASSIFIER.classify(bytes)

        // No error frame, because there is nothing to reply to: bytes that are not a frame
        // give no framing to resynchronise on, since any offset might look like the magic
        // from the middle of a body.
        assertEquals(FrameOutcome.CloseConnection, verdict.outcome)
        assertTrue(!verdict.sessionSurvives, "a stream that is not DLWP/1 does not survive")

        // The bare-function form agrees, so the two entry points cannot drift apart.
        assertEquals(FrameOutcome.CloseConnection, CLASSIFIER.classifyNotAFrame().outcome)
    }

    /**
     * The decoder's own errors are preserved rather than collapsed into malformed.
     */
    @Test
    fun decodeErrorsArePreservedNotCollapsed() {
        // A peer told its frame was too large can split it; one told its frame was malformed
        // has nothing to act on. So the two must stay distinct all the way to the verdict.
        val tooLarge = CLASSIFIER.classifyDecodeFailure(ErrorCode.FRAME_TOO_LARGE)
        val unsupported = CLASSIFIER.classifyDecodeFailure(ErrorCode.UNSUPPORTED_HEADER)
        val mismatch = CLASSIFIER.classifyDecodeFailure(ErrorCode.VERSION_MISMATCH)

        assertEquals(ErrorCode.FRAME_TOO_LARGE, tooLarge.error)
        assertEquals(ErrorCode.UNSUPPORTED_HEADER, unsupported.error)
        assertEquals(ErrorCode.VERSION_MISMATCH, mismatch.error)

        for (verdict in listOf(tooLarge, unsupported, mismatch)) {
            assertEquals(
                FrameOutcome.ErrorFrameThenClose,
                verdict.outcome,
                "a structural failure gets an error frame and then closes",
            )
        }
    }

    /**
     * An unregistered message type is recoverable, not fatal.
     */
    @Test
    fun anUnknownMessageTypeIsRecoverable() {
        val v = vector("malformed.unknown-message-type")

        assertEquals("error_session_continues", v["expected"]!!.asString())

        val verdict = classifyFrameVector(v)

        assertEquals(ErrorCode.UNSUPPORTED_MESSAGE, verdict.error)
        assertEquals(FrameOutcome.ErrorSessionContinues, verdict.outcome)

        // Recoverable is the whole point: a newer peer sending a frame an older one has not
        // learned must not break the session, or every protocol addition is a breaking change.
        assertTrue(verdict.sessionSurvives, "an unknown message type must not end the session")
    }

    /**
     * A registered message the handshake did not grant is refused, and the session lives.
     */
    @Test
    fun aMessageWithoutItsCapabilityIsRefused() {
        val v = vector("malformed.unknown-capability-command")

        val messageType = v["message_type"]!!.asInt()
        val negotiated = v["negotiated_capabilities"]!!.asArray()
            .map { it.asString() }
            .toSet()

        assertEquals("error_session_continues", v["expected"]!!.asString())

        val verdict = CLASSIFIER.classify(
            frame(messageType),
            FrameClassifier.Context(negotiatedCapabilities = negotiated),
        )

        assertEquals(ErrorCode.UNSUPPORTED_FEATURE, verdict.error)
        assertTrue(verdict.sessionSurvives, "an ungranted capability must not end the session")

        // And granting it makes the difference, which is what shows the gate is being read
        // rather than the refusal happening by accident.
        val granted = CLASSIFIER.classify(
            frame(messageType),
            FrameClassifier.Context(negotiatedCapabilities = negotiated + "shell.exec"),
        )

        // Acceptance is a null error, not a code: there is no "accepted" error in the
        // registry, because a code means something went wrong.
        assertEquals(FrameOutcome.Accepted, granted.outcome, "the command is accepted once granted")
        assertNull(granted.error, "an accepted frame carries no error code")
    }

    /**
     * An operation on a channel that was never opened is refused.
     */
    @Test
    fun anUnopenedChannelIsRefused() {
        val v = vector("malformed.channel-not-opened")

        val messageType = v["message_type"]!!.asInt()
        val channelId = v["channel_id"]!!.asLong()
        val openChannels = v["open_channels"]!!.asArray().map { it.asLong() }.toSet()

        // The vector's own precondition: channel 0 is always open, so a test of this rule
        // needs a non-zero channel or it tests nothing.
        assertTrue(channelId != 0L, "the vector must name a non-zero channel")
        assertTrue(!openChannels.contains(channelId), "the vector's channel must not be open")

        val verdict = CLASSIFIER.classify(
            frame(messageType, channelId),
            FrameClassifier.Context(openChannels = openChannels),
        )

        assertEquals(ErrorCode.CHANNEL_UNKNOWN, verdict.error)
        assertTrue(verdict.sessionSurvives, "an unknown channel must not end the session")
    }

    /**
     * Opening one channel past the limit is refused without disturbing the others.
     */
    @Test
    fun theChannelLimitIsRefusedWithoutDisturbingOpenChannels() {
        val v = vector("malformed.channel-limit")

        val maxChannels = v["max_channels"]!!.asInt()
        val openChannels = v["open_channels"]!!.asArray().map { it.asLong() }.toSet()
        val requested = v["requested_channel"]!!.asLong()

        assertEquals(REGISTRY.maxChannels, maxChannels, "the vector's limit matches the registry")

        // Every open channel counts, the control channel included: the vector lists eight
        // channels, 0 through 7, against a limit of eight. Counting only the data channels
        // would see seven here and let a session reach nine, exceeding the limit the agent
        // advertised -- which is why this asserts the total and not the data channels.
        assertEquals(maxChannels, openChannels.size, "the vector must be exactly at the limit")

        val verdict = CLASSIFIER.classifyChannelOpen(requested, openChannels)

        assertEquals(ErrorCode.CHANNEL_LIMIT, verdict.error)
        assertTrue(verdict.sessionSurvives, "hitting the channel limit must not end the session")

        // One below the limit is accepted, which is the boundary the rule has to get right:
        // refusing at the limit would waste a channel, allowing one over would exceed it.
        val highest = openChannels.max()
        val oneBelow = openChannels.minus(highest)

        assertEquals(maxChannels - 1, oneBelow.size, "dropping the highest leaves one fewer")

        assertEquals(
            FrameOutcome.Accepted,
            CLASSIFIER.classifyChannelOpen(requested, oneBelow).outcome,
            "one below the limit is accepted",
        )
    }

    /**
     * A missing required key is malformed and fatal.
     */
    @Test
    fun aMissingRequiredKeyIsMalformedAndFatal() {
        val v = vector("malformed.missing-required-key")

        assertEquals("error_frame_then_close", v["expected"]!!.asString())

        val body = v["body"]!!.entries.keys
        val messageType = v["message_type"]!!.asInt()

        // INPUT_TOUCH requires at least the action and the pointers. The vector carries one.
        val required = setOf("action", "pointers")
        assertTrue(!body.containsAll(required), "the vector must actually be missing a required key")

        val verdict = CLASSIFIER.classifyBody(
            messageTypeCode = messageType,
            requiredKeys = required,
            presentKeys = body,
            knownKeys = required,
        )

        assertEquals(ErrorCode.MALFORMED, verdict.error)

        // Fatal, and the reason is worth stating: the body failed validation, so the peer
        // cannot be trusted to resynchronise, and continuing would leave both sides
        // disagreeing about what was requested.
        assertTrue(!verdict.sessionSurvives, "a missing required key must end the session")
    }

    /**
     * An unknown key in a body is ignored, not refused.
     */
    @Test
    fun anUnknownBodyKeyIsIgnored() {
        val v = vector("malformed.unknown-extra-key-ignored")

        assertEquals("accepted", v["expected"]!!.asString())

        val body = v["body"]!!.entries.keys
        val messageType = v["message_type"]!!.asInt()
        val known = setOf("action", "pointers")

        assertTrue(
            body.any { !known.contains(it) },
            "the vector must actually carry an unknown key",
        )

        val verdict = CLASSIFIER.classifyBody(
            messageTypeCode = messageType,
            requiredKeys = known,
            presentKeys = body,
            knownKeys = known,
        )

        // The forward-compatibility rule, and the one case in this file where a
        // strange-looking body is accepted. Rejecting an unknown key would make adding a
        // field a breaking change, so a receiver that rejects one is not strict, it is wrong.
        assertEquals(FrameOutcome.Accepted, verdict.outcome)
        assertNull(verdict.error)
    }

    /**
     * Every sequence vector produces its declared verdict.
     */
    @Test
    fun everySequenceVectorMatchesItsDeclaredOutcome() {
        val sequenceVectors = Vectors.array(VECTOR_FILE, "sequence_vectors")

        assertTrue(sequenceVectors.size >= 3, "expected at least 3 sequence vectors")

        for (v in sequenceVectors) {
            val id = v["id"]!!.asString()
            val numbers = v["sequence"]!!.asArray().map { it.asLong() }

            var highestSeen: Long? = null
            val accepted = mutableSetOf<Long>()
            var failure: FrameVerdict? = null
            var failureAt = -1

            for ((index, number) in numbers.withIndex()) {
                val verdict = CLASSIFIER.classifySequence(
                    sequenceNumber = number,
                    highestSeen = highestSeen,
                    seenBefore = accepted.contains(number),
                )

                if (verdict.outcome == FrameOutcome.Accepted) {
                    accepted.add(number)
                    if (highestSeen == null || number > highestSeen) highestSeen = number
                } else {
                    failure = verdict
                    failureAt = index
                    break
                }
            }

            val expectedError = v["expected_error"]?.asString()?.let { ErrorCode.fromWireName(it) }

            if (expectedError == null) {
                // The vector declares no error, so the whole sequence must be accepted.
                assertNull(
                    failure,
                    "$id declares no error but frame $failureAt was refused: ${failure?.error}",
                )
                assertTrue(
                    accepted.size == numbers.size,
                    "$id accepted ${accepted.size} of ${numbers.size}",
                )
            } else {
                assertNotNull(failure, "$id must be refused but every frame was accepted")
                assertEquals(expectedError, failure.error, "$id error code")
            }
        }
    }

    /**
     * A repeat and a reorder are separated by the seen-set, not the window.
     */
    @Test
    fun aRepeatIsNotAReorder() {
        // These are the two vectors that make the distinction necessary, and they are worth
        // asserting together because a window check alone accepts both.
        val repeat = CLASSIFIER.classifySequence(sequenceNumber = 3, highestSeen = 3, seenBefore = true)
        assertEquals(ErrorCode.REPLAY_DETECTED, repeat.error, "a repeat is a replay")

        val reorder = CLASSIFIER.classifySequence(sequenceNumber = 4, highestSeen = 5, seenBefore = false)
        assertEquals(FrameOutcome.Accepted, reorder.outcome, "a reorder within the window is legal")

        // Without a seen-set the head repeat is still caught, because zero behind is not
        // reordering: reordering means arriving later than a higher number.
        val headRepeat = CLASSIFIER.classifySequence(sequenceNumber = 3, highestSeen = 3)
        assertEquals(ErrorCode.REPLAY_DETECTED, headRepeat.error, "a head repeat is a replay")

        // Beyond the window is refused even when it has not been seen: accepting it would
        // mean buffering without bound waiting for frames that may never arrive.
        val farBehind = CLASSIFIER.classifySequence(
            sequenceNumber = 3,
            highestSeen = 40,
            seenBefore = false,
        )
        assertEquals(ErrorCode.REPLAY_DETECTED, farBehind.error, "beyond the window is refused")
    }

    /**
     * The reorder window is the boundary the vectors bracket.
     */
    @Test
    fun theReorderWindowBracketsItsBoundary() {
        val window = FrameClassifier.REORDER_WINDOW
        val head = 100L

        // Exactly at the window is accepted; one beyond is refused. Both are checked because
        // an off-by-one here either accepts a forged frame or rejects a late one.
        assertEquals(
            FrameOutcome.Accepted,
            CLASSIFIER.classifySequence(head - window, head, seenBefore = false).outcome,
            "exactly one window behind is accepted",
        )

        assertEquals(
            ErrorCode.REPLAY_DETECTED,
            CLASSIFIER.classifySequence(head - window - 1, head, seenBefore = false).error,
            "one beyond the window is refused",
        )
    }

    /**
     * The severity is a property of the code, and the registry agrees with the vectors.
     */
    @Test
    fun theSeverityComesFromTheCodeNotTheCallSite() {
        // Every code the vectors name is checked against the severity they declare, so a
        // classification cannot report a fatal outcome with a recoverable code.
        for (v in vectors()) {
            val errorName = v["expected_error"]?.asString() ?: continue
            val code = ErrorCode.fromWireName(errorName) ?: error("unknown code $errorName")
            val severity = v["expected_severity"]!!.asString()

            assertEquals(
                severity == "fatal",
                code.isFatal,
                "${v["id"]!!.asString()}: $errorName should be $severity",
            )
        }
    }

    /**
     * The classifier reports a verdict rather than throwing on anything.
     */
    @Test
    fun noInputProducesAnException() {
        // Every frame vector, every sequence vector, and a set of adversarial inputs, all
        // classified without an exception. A receive path that can throw is one a peer can
        // crash with a packet.
        for (v in vectors()) {
            if (v["frame"] != null) classifyFrameVector(v)
        }

        for (v in Vectors.array(VECTOR_FILE, "sequence_vectors")) {
            for (number in v["sequence"]!!.asArray().map { it.asLong() }) {
                CLASSIFIER.classifySequence(number, 0)
            }
        }

        // A zero-length buffer, a header-only buffer, and every truncation of a real frame.
        FrameCodec.read(ByteArray(0))

        val frame = Vectors.hex(
            vectors().first { it["frame"] != null }["frame"]!!.asString(),
        )

        for (length in 0..frame.size) {
            FrameCodec.read(frame.copyOfRange(0, length))
        }

        // If this test returns, nothing threw.
        assertTrue(true)
    }
}
