package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Conformance tests for the integration transcript, driven by `session-basic.json`.
 *
 * This file is different from the others: it is not a set of independent cases but one 19-step
 * exchange, and the property worth checking is that replaying it produces the states, the
 * sequence numbers and the negotiated values the file declares. A single wrong transition or a
 * single off-by-one in the numbering shows up as a divergence somewhere in the middle, which is
 * why the test walks the transcript rather than asserting on steps individually.
 *
 * The step that makes it worth having is 17. It deliberately replays a sequence number that was
 * already accepted, and the session must die for it. A transcript that only ever sent valid
 * frames would not exercise the monotonic rule at all -- and the monotonic rule is where an
 * implementation is most likely to be lenient, because leniency costs nothing until it is
 * attacked.
 */
class SessionReplayTest {
    private companion object {
        const val VECTOR_FILE = "session-basic.json"
    }

    /** The step at `index`, 1-based as the file numbers them. */
    private fun step(index: Int): JsonValue {
        val steps = Vectors.array(VECTOR_FILE, "steps")

        return steps.firstOrNull { it["step"]!!.asInt() == index }
            ?: error("session-basic.json has no step $index")
    }

    /** The `send` object of a step. */
    private fun send(index: Int): JsonValue = step(index)["send"] ?: error("step $index has no send")

    /** The message type code of a step's frame, resolved against the registry. */
    private fun messageType(index: Int): Int {
        val name = send(index)["name"]!!.asString()
        val code = SessionMessages.codeFor(name)
            ?: error("the message name \"$name\" in step $index is not one this implementation names")

        return code
    }

    /** Whether a step's frame is marked encrypted. */
    private fun isEncrypted(index: Int): Boolean = send(index)["encrypted"]?.asBoolean() ?: false

    /** A step's channel id. */
    private fun channelId(index: Int): Long = send(index)["channel_id"]!!.asLong()

    /** A step's sequence number. */
    private fun sequenceNumber(index: Int): Long = send(index)["sequence_number"]!!.asLong()

    /** Whether every `expect` string of a step contains `fragment`, across the given steps. */
    private fun expectationsContain(steps: IntRange, fragment: String): Boolean =
        steps.all { index ->
            val expect = step(index)["expect"]?.asArray()?.map { it.asString() } ?: emptyList()

            expect.any { it.contains(fragment) }
        }

    /** The actor of a step as a role. */
    private fun actor(index: Int): SessionRole =
        when (step(index)["actor"]!!.asString()) {
            "controller" -> SessionRole.CONTROLLER
            "agent" -> SessionRole.AGENT
            else -> error("step $index has an unknown actor")
        }

    /**
     * Every message code this implementation names is the registry's code.
     */
    @Test
    fun everyMessageCodeMatchesTheRegistry() {
        val registry = Vectors.registryMessageCodes()

        // The registry's JSON object uses 0-based keys, while each entry's `code` is 1-based.
        // Transcribing from the key instead of the field is silently plausible -- HELLO would be
        // 0 and the whole transcript would still run -- so every constant is checked against the
        // field rather than trusted.
        val expected = mapOf(
            "HELLO" to SessionMessages.HELLO,
            "HELLO_ACK" to SessionMessages.HELLO_ACK,
            "AUTH" to SessionMessages.AUTH,
            "AUTH_OK" to SessionMessages.AUTH_OK,
            "PING" to SessionMessages.PING,
            "PONG" to SessionMessages.PONG,
            "GET_CAPABILITIES" to SessionMessages.GET_CAPABILITIES,
            "CAPABILITIES" to SessionMessages.CAPABILITIES,
            "CHANNEL_OPEN" to SessionMessages.CHANNEL_OPEN,
            "CHANNEL_OPENED" to SessionMessages.CHANNEL_OPENED,
            "CHANNEL_CLOSE" to SessionMessages.CHANNEL_CLOSE,
            "VIDEO_START" to SessionMessages.VIDEO_START,
            "VIDEO_CONFIG" to SessionMessages.VIDEO_CONFIG,
            "VIDEO_FRAME" to SessionMessages.VIDEO_FRAME,
            "VIDEO_STOP" to SessionMessages.VIDEO_STOP,
            "INPUT_TOUCH" to SessionMessages.INPUT_TOUCH,
            "SHELL_EXEC" to SessionMessages.SHELL_EXEC,
            "DEVICE_INFO" to SessionMessages.DEVICE_INFO,
            "DEVICE_INFO_RESULT" to SessionMessages.DEVICE_INFO_RESULT,
            "ERROR" to SessionMessages.ERROR,
            "SESSION_END" to SessionMessages.SESSION_END,
        )

        for ((name, code) in expected) {
            val fromRegistry = registry[name]
                ?: throw AssertionError("dlwp-1.json has no message type named $name")

            assertEquals(fromRegistry, code, "$name is the registry's code")
        }

        // And the codes are all distinct, which a transposition would break without the
        // per-name assertion noticing when the two names swapped happen to be unused together.
        assertEquals(expected.size, expected.values.toSet().size, "every message code is distinct")

        // The two unencrypted types really are HELLO and HELLO_ACK, and the registry says so
        // independently.
        assertEquals(
            setOf("HELLO", "HELLO_ACK"),
            Vectors.registryUnencryptedMessages(),
            "only the handshake pair travels unencrypted",
        )
        assertEquals(
            setOf(SessionMessages.HELLO, SessionMessages.HELLO_ACK),
            SessionMessages.UNENCRYPTED,
            "the unencrypted set matches the registry",
        )
    }

    /**
     * The state machine's declared path is the one the transcript walks.
     */
    @Test
    fun theTranscriptWalksTheDeclaredPath() {
        val assertions = Vectors.load(VECTOR_FILE)["assertions"]!!

        val stateMachine = assertions["state_machine"]!!.asArray().map { it.asString() }

        // The declared path, as the file writes it. Asserted as a string rather than as a list
        // of transitions because the file's own text is what a reader checks the implementation
        // against.
        assertTrue(
            stateMachine.any { it == "idle -> discovering -> connecting -> handshaking -> authenticating -> established -> streaming -> closing -> closed" },
            "the declared path is the full one",
        )
        assertTrue(
            stateMachine.any { it == "any_state_on_fatal_error -> closing" },
            "a fatal error from any state goes to closing",
        )

        // Which is the property worth stating: from ANY live state. A fatal error during the
        // handshake and one during streaming both end at closing, so the transition cannot be
        // modelled as an edge from established.
        val live = SessionState.entries.filterNot { it.isTerminal }

        assertTrue(live.size >= 8, "there are at least eight live states")

        for (state in live) {
            if (state == SessionState.CLOSING) continue

            // An ERROR frame is legal from every live state, so a fatal one is reachable from
            // every live state.
            val outcome = runCatching { SessionTransitions.next(state, SessionRole.AGENT, SessionMessages.ERROR, 0) }

            assertTrue(outcome.isSuccess, "an ERROR frame is legal in ${state.name}")
        }
    }

    /**
     * The sequence numbering rule is per-direction.
     */
    @Test
    fun theSequenceNumbersArePerDirection() {
        val assertions = Vectors.load(VECTOR_FILE)["assertions"]!!

        val rule = assertions["sequence_numbers"]!!.asString()

        assertTrue(rule.contains("session-global"), "the counter is session-global")
        assertTrue(rule.contains("increase by one per frame sent by that side"), "it increases per frame by that side")
        assertTrue(rule.contains("The two directions number independently"), "the directions are independent")
        assertTrue(rule.contains("both sides legitimately use sequence number 1"), "both sides start at one")

        // Which the transcript demonstrates: step 1 and step 2 both use sequence number 1, from
        // different actors. Asserted, because it is the case a single shared counter gets wrong.
        assertEquals(1L, sequenceNumber(1), "the controller's first frame is 1")
        assertEquals(1L, sequenceNumber(2), "the agent's first frame is 1")
        assertFalse(actor(1) == actor(2), "and they are from different actors")

        // Within each direction the numbers increase by exactly one, with one deliberate
        // exception: the replayed frame in step 17.
        for (role in listOf(SessionRole.CONTROLLER, SessionRole.AGENT)) {
            val own = (1..19).filter { actor(it) == role }
            val replays = own.filter { step(it)["deliberate_replay"]?.asBoolean() == true }

            var previous: Long? = null

            for (index in own) {
                val current = sequenceNumber(index)

                if (replays.contains(index)) continue

                // Monotonic, NOT gapless. The transcript records the frames that matter rather
                // than every frame, so the controller goes 1, 2, 3, 4, 5 and then 8 -- its 6 and 7
                // are the agent's frames, numbered in the agent's own counter. My first version
                // demanded exactly one more and failed at step 13.
                if (previous != null) {
                    assertTrue(
                        current > previous,
                        "${role.name}'s sequence number at step $index advances past $previous (got $current)",
                    )
                }

                previous = current
            }
        }
    }

    /**
     * Replaying the transcript produces the declared states.
     */
    @Test
    fun replayingTheTranscriptReachesTheDeclaredStates() {
        val controller = SessionReplayer(SessionRole.CONTROLLER)
        val agent = SessionReplayer(SessionRole.AGENT)

        // Step 1: the controller sends HELLO. The agent has not received it yet, so only the
        // controller moves -- and the file says the agent is handshaking, which happens when it
        // receives the frame, not when it is sent.
        controller.send(messageType(1), sequenceNumber(1), isEncrypted(1))
        assertEquals(SessionState.HANDSHAKING, controller.state, "the controller is handshaking after HELLO")
        assertEquals(SessionState.IDLE, agent.state, "the agent has not seen the frame yet")
        assertFalse(controller.sentEncrypted, "HELLO is not encrypted, so nothing has been sent under a key")

        // Step 2: the agent receives HELLO and answers.
        assertEquals(
            ReceiveOutcome.Accepted,
            agent.receive(messageType(1), sequenceNumber(1), isEncrypted(1)),
            "the agent accepts HELLO",
        )
        assertEquals(SessionState.HANDSHAKING, agent.state, "the agent is handshaking after receiving HELLO")

        agent.send(messageType(2), sequenceNumber(2), isEncrypted(2))
        assertEquals(SessionState.AUTHENTICATING, agent.state, "the agent authenticates after HELLO_ACK")

        assertEquals(
            ReceiveOutcome.Accepted,
            controller.receive(messageType(2), sequenceNumber(2), isEncrypted(2)),
            "the controller accepts HELLO_ACK",
        )
        assertEquals(SessionState.AUTHENTICATING, controller.state, "the controller authenticates after HELLO_ACK")

        // Neither side has sent an encrypted frame yet, which the file asserts at step 1 and
        // which is the precondition for the AUTH frame in step 3 being the first.
        assertFalse(controller.sentEncrypted, "the controller has sent no encrypted frame")
        assertFalse(agent.sentEncrypted, "the agent has sent no encrypted frame")

        // Step 3: the controller's first encrypted frame.
        controller.send(messageType(3), sequenceNumber(3), isEncrypted(3))
        assertEquals(SessionState.ESTABLISHED, controller.state, "the controller is established after AUTH")
        assertTrue(controller.sentEncrypted, "AUTH is the controller's first encrypted frame")

        // Step 4: the agent authenticates and answers.
        assertEquals(
            ReceiveOutcome.Accepted,
            agent.receive(messageType(3), sequenceNumber(3), isEncrypted(3)),
            "the agent accepts AUTH",
        )

        agent.send(messageType(4), sequenceNumber(4), isEncrypted(4))
        assertEquals(SessionState.ESTABLISHED, agent.state, "the agent is established after AUTH_OK")

        assertEquals(
            ReceiveOutcome.Accepted,
            controller.receive(messageType(4), sequenceNumber(4), isEncrypted(4)),
            "the controller accepts AUTH_OK",
        )
        assertEquals(SessionState.ESTABLISHED, controller.state, "the controller stays established")

        // The file asserts at step 4 that the session is established.
        assertTrue(expectationsContain(4..4, "session established"), "step 4 declares the session established")

        // Step 7/8: a channel is opened on the control channel, and answered.
        assertEquals(
            ReceiveOutcome.Accepted,
            agent.receive(messageType(7), sequenceNumber(7), isEncrypted(7), channelId(7)),
            "the agent accepts CHANNEL_OPEN",
        )

        agent.send(messageType(8), sequenceNumber(8), isEncrypted(8), channelId(8))

        assertEquals(
            ReceiveOutcome.Accepted,
            controller.receive(messageType(8), sequenceNumber(8), isEncrypted(8), channelId(8)),
            "the controller accepts CHANNEL_OPENED",
        )

        // The agent allocates channel 1, which is odd because the controller offered it.
        assertEquals(1L, send(8)["body"]!!["channel_id"]!!.asLong(), "the agent allocated channel 1")

        // Step 9: VIDEO_START, which moves both sides into streaming.
        controller.send(messageType(9), sequenceNumber(9), isEncrypted(9), channelId(9))
        assertEquals(SessionState.STREAMING, controller.state, "the controller is streaming after VIDEO_START")

        assertEquals(
            ReceiveOutcome.Accepted,
            agent.receive(messageType(9), sequenceNumber(9), isEncrypted(9), channelId(9)),
            "the agent accepts VIDEO_START",
        )
        assertEquals(SessionState.STREAMING, agent.state, "the agent is streaming after receiving VIDEO_START")
    }

    /**
     * The transcript ends on the replayed frame, and that frame is fatal.
     */
    @Test
    fun theReplayedFrameEndsTheSession() {
        // Step 17 replays step 13's sequence number, and the file marks the step so the
        // verifier's own monotonicity check skips it. That marking is the evidence the replay is
        // deliberate rather than a mistake in the vector.
        assertTrue(
            step(17)["deliberate_replay"]!!.asBoolean(),
            "step 17 is marked as a deliberate replay",
        )

        assertEquals(
            sequenceNumber(13),
            sequenceNumber(17),
            "step 17 reuses step 13's sequence number rather than a new one",
        )
        // NOT compared against step 16: step 16 is the AGENT's frame and step 17 is the
        // controller's, and the two directions number independently. Both use 8 here for entirely
        // legitimate reasons, which is the point of numbering per direction.
        assertFalse(actor(16) == actor(17), "steps 16 and 17 are from different actors")

        // The replayed frame is on the same channel and from the same actor as the original.
        assertEquals(actor(13), actor(17), "the replay is from the same actor")
        assertEquals(channelId(13), channelId(17), "the replay is on the same channel")

        // And the frame differs only in its body, which is the point: a replay is distinguished
        // by its sequence number and not by its contents. A receiver that checked contents would
        // accept this one, because the body is different.
        assertFalse(
            send(13)["body"]!!["gesture_id"]!!.asLong() == send(17)["body"]!!["gesture_id"]!!.asLong(),
            "the replayed frame has a DIFFERENT body, so only the sequence number can catch it",
        )

        // Now the actual behaviour: replayed to a peer that already accepted 8, it is fatal.
        // Replay the WHOLE transcript up to step 16, both directions, rather than a hand-picked
        // subset. A subset is not a replay: the counts below only work out because every frame the
        // agent accepted is present, and leaving one out makes step 17 look like a legitimate
        // reorder instead of a repeat.
        val controller = SessionReplayer(SessionRole.CONTROLLER)
        val agent = SessionReplayer(SessionRole.AGENT)

        for (index in 1..16) {
            val role = actor(index)
            val type = messageType(index)
            val sequence = sequenceNumber(index)
            val encrypted = isEncrypted(index)
            val channel = channelId(index)

            if (role == SessionRole.CONTROLLER) {
                val peer = agent.receive(type, sequence, encrypted, channel)

                assertFalse(peer is ReceiveOutcome.Fatal, "the agent accepts step $index")
                controller.send(type, sequence, encrypted, channel)
            } else {
                val peer = controller.receive(type, sequence, encrypted, channel)

                assertFalse(peer is ReceiveOutcome.Fatal, "the controller accepts step $index")
                agent.send(type, sequence, encrypted, channel)
            }
        }

        // The agent has accepted up to sequence number 10 from the controller, and has already
        // seen 8 -- which is the frame step 17 repeats.
        assertEquals(10L, agent.lastReceived, "the agent has accepted up to sequence number 10")
        assertTrue(agent.received.contains(8L), "the agent has seen sequence number 8")

        val outcome = agent.receive(messageType(17), sequenceNumber(17), isEncrypted(17), channelId(17))

        assertTrue(outcome is ReceiveOutcome.Fatal, "the replayed frame is fatal")
        assertEquals(ErrorCode.REPLAY_DETECTED, (outcome as ReceiveOutcome.Fatal).code, "the code is ERR_REPLAY_DETECTED")
        assertEquals(SessionState.CLOSING, agent.state, "the agent moves to closing")

        // The sequence-advance guard, driven on its own. The frame has to be one the ROLE may
        // send in this state, or the role check throws first and the sequence check is never
        // reached -- which is why the mirror's mutation deleting the advance guard survived a
        // first version of this check that used the wrong frame.
        val guarded = SessionReplayer(SessionRole.AGENT)

        guarded.state = SessionState.HANDSHAKING
        guarded.lastSent = 5

        val backwards = runCatching { guarded.send(SessionMessages.HELLO_ACK, 5, false) }

        assertTrue(backwards.isFailure, "a non-advancing outgoing sequence number is refused")
        assertTrue(
            backwards.exceptionOrNull()?.message?.contains("does not advance") == true,
            "and it is the SEQUENCE check that refused, not the role or state check",
        )

        // Zero is refused: the numbering starts at one.
        val fresh = SessionReplayer(SessionRole.AGENT)

        fresh.state = SessionState.HANDSHAKING
        fresh.lastSent = 0

        assertTrue(
            runCatching { fresh.send(SessionMessages.HELLO_ACK, 0, false) }.isFailure,
            "sequence number zero is refused",
        )

        // A jump FORWARDS is allowed, because a transcript records the frames that matter rather
        // than every frame: the controller in this transcript sends 1,2,3,4,5 and then 8.
        val jumping = SessionReplayer(SessionRole.AGENT)

        jumping.state = SessionState.HANDSHAKING
        jumping.lastSent = 5

        assertTrue(
            runCatching { jumping.send(SessionMessages.HELLO_ACK, 8, false) }.isSuccess,
            "a jump forwards is allowed, because a transcript is not gapless",
        )

        // A recoverable fault and a fatal one are genuinely different, so the distinction is not
        // decorative: a frame out of state leaves the session alone, a repeat closes it.
        val outOfState = SessionReplayer(SessionRole.AGENT)
        val early = outOfState.receive(SessionMessages.CHANNEL_OPEN, 1, true, 0)

        assertTrue(early is ReceiveOutcome.Recoverable, "an out-of-state frame is recoverable")
        assertFalse(outOfState.state == SessionState.CLOSING, "a recoverable fault does not move the session to closing")

        // And the repeat is caught by the SEEN-SET rather than the window: 8 is inside the window
        // against a high-water mark of 10, so the window alone would accept it.
        val repeated = SessionReplayer(SessionRole.AGENT)

        repeated.received.add(8)
        repeated.received.add(9)
        repeated.received.add(10)
        repeated.lastReceived = 10

        val windowFloor = repeated.lastReceived!! - 32

        assertTrue(8 >= windowFloor, "8 is inside the window, so the window alone would accept it")

        val replayVerdict = repeated.receive(SessionMessages.INPUT_TOUCH, 8, true, 1)

        assertTrue(replayVerdict is ReceiveOutcome.Fatal, "the repeat inside the window is still fatal")
        assertEquals(ErrorCode.REPLAY_DETECTED, (replayVerdict as ReceiveOutcome.Fatal).code, "and reported as a replay")

        // The unencrypted set is exactly the handshake pair, enforced by the replayer.
        assertTrue(
            runCatching { SessionReplayer(SessionRole.CONTROLLER).send(SessionMessages.HELLO, 1, true) }.isFailure,
            "an encrypted HELLO is refused",
        )

        val plainAuth = SessionReplayer(SessionRole.CONTROLLER)

        plainAuth.state = SessionState.AUTHENTICATING

        assertTrue(
            runCatching { plainAuth.send(SessionMessages.AUTH, 1, false) }.isFailure,
            "an unencrypted AUTH is refused",
        )

        // And the session really is not usable afterwards. SESSION_END closes it.
        agent.send(messageType(19), sequenceNumber(19), isEncrypted(19), channelId(19))
        assertEquals(SessionState.CLOSED, agent.state, "SESSION_END closes the session")
    }

    /**
     * A recoverable fault does not end the session.
     */
    @Test
    fun aRecoverableFaultDoesNotEndTheSession() {
        // Step 15 asks for a shell command, and step 16 is the agent's refusal. The file is
        // explicit that the session survives and the video stream continues, so the two fault
        // severities are genuinely different behaviours rather than a documentation nicety.
        assertTrue(expectationsContain(16..16, "session survives"), "step 16 declares the session survives")
        assertTrue(expectationsContain(16..16, "video stream continues"), "step 16 declares the stream continues")

        // The refusal is ERR_UNSUPPORTED_FEATURE, which the registry makes recoverable. That is
        // the link between the error's severity and the session's fate, so it is asserted.
        assertEquals(
            "ERR_UNSUPPORTED_FEATURE",
            send(16)["body"]!!["code"]!!.asString(),
            "the refusal is ERR_UNSUPPORTED_FEATURE",
        )
        assertEquals(
            "recoverable",
            send(16)["body"]!!["severity"]!!.asString(),
            "and its severity is recoverable",
        )
        assertEquals(
            ErrorCode.UNSUPPORTED_FEATURE.severity,
            Severity.Recoverable,
            "the registry agrees it is recoverable",
        )

        // The fatal one, for contrast, is declared fatal in the body AND in the registry.
        assertEquals("fatal", send(18)["body"]!!["severity"]!!.asString(), "the replay error is fatal")
        assertEquals(ErrorCode.REPLAY_DETECTED.severity, Severity.Fatal, "the registry agrees it is fatal")

        // An ERROR frame does not itself change the state: whether the session survives depends
        // on the severity in the body, and the transition table deliberately does not read
        // bodies. So the agent stays where it was and the caller decides.
        val state = SessionTransitions.next(SessionState.STREAMING, SessionRole.AGENT, SessionMessages.ERROR, 1)

        assertEquals(SessionState.STREAMING, state, "an ERROR frame alone does not change the state")
    }

    /**
     * A shell command is refused because the capability was not negotiated.
     */
    @Test
    fun theShellCommandIsRefusedForWantOfACapability() {
        // Step 4's expectation names the reason in one line, and it is the link between the
        // capability negotiation and the shell policy: the command is not refused because it is
        // unsafe, but because the capability was never agreed to.
        assertTrue(
            expectationsContain(4..4, "shell.exec and app.install are absent from the negotiated set"),
            "step 4 declares shell.exec and app.install absent",
        )

        val negotiated = send(4)["body"]!!["negotiated"]!!["capabilities"]!!.asArray().map { it.asString() }

        assertFalse(negotiated.contains("shell.exec"), "shell.exec was not negotiated")
        assertFalse(negotiated.contains("app.install"), "app.install was not negotiated")

        // And the refusal is ERR_UNSUPPORTED_FEATURE rather than ERR_PERMISSION_DENIED, which is
        // the distinction worth pinning: an unnegotiated capability is a feature that was never
        // agreed to, not a permission that was refused. The two have different remedies -- a
        // renegotiation versus an operator grant -- so conflating them sends the operator the
        // wrong way.
        assertEquals(
            "ERR_UNSUPPORTED_FEATURE",
            send(16)["body"]!!["code"]!!.asString(),
            "an unnegotiated capability is an unsupported feature",
        )
        assertFalse(
            send(16)["body"]!!["code"]!!.asString() == ErrorCode.PERMISSION_DENIED.wireName,
            "it is not a permission denial",
        )
    }

    /**
     * The video request is clamped rather than refused.
     */
    @Test
    fun theVideoRequestIsClampedNotRefused() {
        // Step 9 asks for 2560x1440 at 120 fps against an agent whose limits are 1920x1080 at 60.
        assertTrue(
            expectationsContain(9..9, "must be clamped, not refused"),
            "step 9 declares the request is clamped rather than refused",
        )

        val request = send(9)["body"]!!
        val limits = Vectors.load(VECTOR_FILE)["preconditions"]!!["agent_limits"]!!

        assertTrue(request["max_width"]!!.asInt() > limits["max_video_width"]!!.asInt(), "the requested width exceeds the limit")
        assertTrue(request["max_height"]!!.asInt() > limits["max_video_height"]!!.asInt(), "the requested height exceeds the limit")
        assertTrue(request["fps"]!!.asInt() > limits["max_video_fps"]!!.asInt(), "the requested rate exceeds the limit")

        // And the agent's own answer, in step 10, is the negotiated configuration rather than an
        // error: an unachievable request is a parameter, not a protocol violation.
        val config = send(10)["body"]!!

        // NOT asserted as "each axis is within its limit", which is what I first wrote and what
        // fails: the agreed height 1920 exceeds the ceiling height 1080. The ceiling bounds the
        // REQUEST box, and the box is then oriented to the screen, so a landscape ceiling against
        // a portrait screen rotates to 1080x1920 -- the ceiling's own dimensions, swapped.
        //
        // What is conserved is the AREA, which is exactly what rotating a box does. Asserted as
        // the property rather than an axis comparison, because the axes only line up when the
        // screen happens to share the ceiling's aspect.
        val ceilingArea = limits["max_video_width"]!!.asInt() * limits["max_video_height"]!!.asInt()
        val agreedArea = config["width"]!!.asInt() * config["height"]!!.asInt()

        assertTrue(agreedArea <= ceilingArea, "the agreed area is within the ceiling area ($agreedArea <= $ceilingArea)")
        assertEquals(ceilingArea, agreedArea, "and here it uses the ceiling exactly")

        // The agreed box is the ceiling rotated into the screen's orientation.
        assertTrue(
            (config["width"]!!.asInt() == limits["max_video_height"]!!.asInt() &&
                config["height"]!!.asInt() == limits["max_video_width"]!!.asInt()) ||
                (config["width"]!!.asInt() == limits["max_video_width"]!!.asInt() &&
                    config["height"]!!.asInt() == limits["max_video_height"]!!.asInt()),
            "the agreed box is the ceiling in the screen orientation",
        )
        assertNotNull(config["csd"], "the agent sends its codec configuration with the size")

        // The screen is reported separately from the encoded size, because they differ: 1080x1920
        // of a 1080x2400 screen. An implementation that conflated them would size the tap
        // mapping from the wrong rectangle.
        assertEquals(1080, config["screen_width"]!!.asInt(), "the screen width is reported separately")
        assertEquals(2400, config["screen_height"]!!.asInt(), "the screen height is reported separately")
        assertFalse(
            config["width"]!!.asInt() == config["screen_height"]!!.asInt() &&
                config["height"]!!.asInt() == config["screen_height"]!!.asInt(),
            "the encoded size is not simply the screen size",
        )
    }

    /**
     * A tap is mapped from normalised coordinates.
     */
    @Test
    fun aTapIsMappedFromNormalisedCoordinates() {
        // Step 14 declares 5000/10000 -> 540,1200 on a 1080x2400 screen. Normalised coordinates
        // are what makes the mapping survive rotation, so the arithmetic is worth pinning.
        assertTrue(expectationsContain(14..14, "agent maps 5000/10000 onto 540,1200"), "step 14 declares the mapping")

        val body = send(14)["body"]!!
        val pointer = body["pointers"]!!.asArray().first()

        val x = pointer["x"]!!.asLong()
        val y = pointer["y"]!!.asLong()
        val width = body["screen_width"]!!.asLong()
        val height = body["screen_height"]!!.asLong()

        // Ten thousand, not 65536 and not 32767: a coordinate system whose denominator is stated
        // is one a reader can check, and the declared mapping is exactly a division by 10000.
        val mappedX = x * width / 10_000
        val mappedY = y * height / 10_000

        assertEquals(540L, mappedX, "$x maps to 540 across $width")
        assertEquals(1200L, mappedY, "$y maps to 1200 across $height")

        // The centre is the centre, which is the sanity property.
        assertEquals(width / 2, 5000L * width / 10_000, "5000 is the centre")

        // And the extremes reach the edges without exceeding them: 10000 maps to width, not
        // width + 1, because the coordinate is a position rather than an offset.
        assertEquals(width, 10_000L * width / 10_000, "the right edge is the width")
        assertEquals(0L, 0L * width / 10_000, "the left edge is zero")
    }

    /**
     * The sequence numbers of the transcript are internally consistent.
     */
    @Test
    fun theTranscriptNumbersItsFramesConsistently() {
        val steps = Vectors.array(VECTOR_FILE, "steps")

        assertEquals(19, steps.size, "the transcript has 19 steps")

        // Steps are numbered 1..19 with no gaps, so a reader can refer to "step 7" and be sure.
        assertEquals(
            (1..19).toList(),
            steps.map { it["step"]!!.asInt() },
            "the steps are numbered 1 to 19 in order",
        )

        // Every step names an actor and carries a frame.
        for (index in 1..19) {
            assertNotNull(step(index)["actor"], "step $index names an actor")
            assertNotNull(step(index)["send"], "step $index sends a frame")
            assertNotNull(send(index)["name"], "step $index's frame has a name")
        }

        // A step that answers another names which one, and the reference resolves.
        for (index in 1..19) {
            val recv = step(index)["recv"] ?: continue

            val referenced = recv.asString().removePrefix("step ").toInt()

            assertTrue(referenced in 1 until index, "step $index answers an earlier step ($referenced)")
            assertFalse(actor(referenced) == actor(index), "step $index answers the other actor's frame")
        }
    }
}
