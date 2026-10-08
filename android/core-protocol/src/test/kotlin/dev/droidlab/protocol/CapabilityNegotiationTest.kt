package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Conformance tests for capability and limit negotiation, driven by `capabilities.json`.
 *
 * Negotiation decides what the rest of the session is allowed to do, so a mistake here is not
 * contained: a capability that should have been refused stays usable for the session's whole
 * life, and a limit that should have been clamped lets a peer allocate a buffer the agent
 * cannot serve.
 *
 * Every assertion is over the vector's declared inputs and the vector's declared outputs. The
 * inputs are read from the file rather than written into the test, so a vector that changes
 * its scenario changes what is exercised.
 */
class CapabilityNegotiationTest {
    private companion object {
        const val VECTOR_FILE = "capabilities.json"
    }

    /** Every negotiation scenario. */
    private fun negotiationVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "negotiation_vectors")

    /** Every limit scenario. */
    private fun limitVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "limit_clamp_vectors")

    /** Every channel-direction scenario. */
    private fun directionVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "direction_vectors")

    /** The registry as the file lists it. */
    private fun registryFromFile(): List<String> =
        Vectors.array(VECTOR_FILE, "capability_registry").map { it.asString() }

    /** The default limits as the file lists them. */
    private fun limitsFromFile(): Map<String, Long> {
        val limits = Vectors.load(VECTOR_FILE)["default_limits"]
            ?: error("capabilities.json has no default_limits")

        return limits.asObject().mapValues { it.value.asLong() }
    }

    /** A vector by id, failing if it is missing so a renamed vector cannot silently skip. */
    private fun vector(id: String): JsonValue {
        val all = negotiationVectors() + limitVectors() + directionVectors()

        return all.firstOrNull { it["id"]?.asString() == id }
            ?: error("capabilities.json has no vector \"$id\"")
    }

    /** The names a vector lists, as a list. */
    private fun names(v: JsonValue, key: String): List<String> =
        (v[key] ?: error("vector has no \"$key\"")).asArray().map { it.asString() }

    /**
     * The registry in the file matches the one in the code, both ways.
     */
    @Test
    fun theRegistryMatchesTheFileInBothDirections() {
        val fromFile = registryFromFile().toSet()

        // Both directions, because one direction alone cannot catch a capability the code
        // knows and the file does not: an implementation advertising a name outside the
        // published registry is a conformance failure in the same way as omitting one.
        assertEquals(
            emptySet(),
            fromFile - CapabilityNegotiation.REGISTRY,
            "every capability in the file is known to the implementation",
        )

        assertEquals(
            emptySet(),
            CapabilityNegotiation.REGISTRY - fromFile,
            "every capability the implementation knows is in the file",
        )

        assertEquals(18, fromFile.size, "the registry has 18 capabilities")
    }

    /**
     * The default limits in the file match the ones in the code.
     */
    @Test
    fun theDefaultLimitsMatchTheFile() {
        val fromFile = limitsFromFile()
        val code = CapabilityNegotiation.Limits()

        val codeByName = mapOf(
            "max_frame_bytes" to code.maxFrameBytes.toLong(),
            "max_channels" to code.maxChannels.toLong(),
            "max_video_width" to code.maxVideoWidth.toLong(),
            "max_video_height" to code.maxVideoHeight.toLong(),
            "max_video_fps" to code.maxVideoFps.toLong(),
            "max_video_bitrate" to code.maxVideoBitrate.toLong(),
            "max_file_chunk" to code.maxFileChunk.toLong(),
            "shell_timeout_ms" to code.shellTimeoutMs.toLong(),
            "max_gesture_steps" to code.maxGestureSteps.toLong(),
        )

        // The file's own note records that this list once carried a tenth entry that appears
        // nowhere in the RFC, and that the fix was to remove it rather than add it to the RFC.
        // The size assertion is therefore the one that matters: it is what would catch that
        // entry coming back.
        assertEquals(9, fromFile.size, "the limits list has exactly nine entries")

        assertEquals(fromFile.keys, codeByName.keys, "the limit names match")

        for ((name, value) in fromFile) {
            assertEquals(value, codeByName[name], "the limit \"$name\" matches")
        }
    }

    /**
     * Every negotiation scenario produces its declared set.
     */
    @Test
    fun everyNegotiationVectorProducesItsDeclaredSet() {
        assertTrue(negotiationVectors().size >= 8, "expected at least 8 negotiation vectors")

        for (v in negotiationVectors()) {
            val id = v["id"]!!.asString()

            val negotiated = CapabilityNegotiation.negotiate(
                agentCapabilities = names(v, "agent_capabilities"),
                agentDisabled = names(v, "agent_disabled"),
                controllerOffered = names(v, "controller_offered"),
            )

            // Compared as a sorted list against the vector's declared list, because the
            // negotiated set is canonicalised by sorting. Comparing as sets would pass even
            // if the implementation returned a differently ordered sequence, and the order is
            // part of the contract: it is what two peers compute a transcript over.
            val expected = names(v, "expected_negotiated").sorted()

            assertEquals(expected, negotiated.toList(), "$id negotiated set")
        }
    }

    /**
     * A capability the controller never offered is never negotiated.
     */
    @Test
    fun aCapabilityTheControllerNeverOfferedIsNotNegotiated() {
        val v = vector("negotiate.controller-subset")

        val agent = names(v, "agent_capabilities")
        val offered = names(v, "controller_offered")

        // The scenario is only meaningful if the agent really does support more than the
        // controller offered; otherwise the test would pass for the wrong reason.
        assertTrue(
            agent.size > offered.size,
            "the agent must support more than the controller offered for this to test anything",
        )

        val negotiated = CapabilityNegotiation.negotiate(agent, emptyList(), offered)

        for (unsupported in agent - offered) {
            assertFalse(
                negotiated.contains(unsupported),
                "$unsupported is supported by the agent but was never offered, so it must not be negotiated",
            )
        }

        assertEquals(offered.sorted(), negotiated.toList())
    }

    /**
     * An operator's disable wins over both sides supporting a capability.
     */
    @Test
    fun anOperatorDisableWinsOverBothSidesSupportingIt() {
        val v = vector("negotiate.operator-disabled-wins-even-when-both-support-it")

        val agent = names(v, "agent_capabilities")
        val disabled = names(v, "agent_disabled")
        val offered = names(v, "controller_offered")

        // The scenario's whole point: the disabled capability is one both sides support, so
        // the intersection alone would include it and only the subtraction removes it.
        for (name in disabled) {
            assertTrue(name in agent, "$name is disabled and must also be supported, or subtraction proves nothing")
            assertTrue(name in offered, "$name is disabled and must also be offered, or subtraction proves nothing")
            assertTrue(name in agent.intersect(offered.toSet()), "$name is in the intersection before disabling")
        }

        val negotiated = CapabilityNegotiation.negotiate(agent, disabled, offered)

        for (name in disabled) {
            assertFalse(negotiated.contains(name), "$name is disabled by the operator and must not be negotiated")
        }

        assertEquals(names(v, "expected_negotiated").sorted(), negotiated.toList())
    }

    /**
     * A permission that was never granted is indistinguishable from disabled.
     */
    @Test
    fun anUngrantedPermissionIsDisabled() {
        val v = vector("negotiate.permission-not-granted-is-disabled")

        val agent = names(v, "agent_capabilities")
        val disabled = names(v, "agent_disabled")
        val offered = names(v, "controller_offered")

        // The scenario models an Android permission the user never granted. The protocol
        // cannot tell that apart from an operator disabling the capability, and it should
        // not try: both mean the capability is unusable, and one mechanism for both is one
        // place for the rule to be wrong.
        assertTrue(disabled.isNotEmpty(), "the vector must name a capability the permission gate removed")

        val negotiated = CapabilityNegotiation.negotiate(agent, disabled, offered)

        assertEquals(names(v, "expected_negotiated").sorted(), negotiated.toList())
    }

    /**
     * An empty intersection is a working session, not a failure.
     */
    @Test
    fun anEmptyIntersectionIsNotAFailure() {
        val v = vector("negotiate.empty-intersection")

        val negotiated = CapabilityNegotiation.negotiate(
            names(v, "agent_capabilities"),
            names(v, "agent_disabled"),
            names(v, "controller_offered"),
        )

        assertTrue(negotiated.isEmpty(), "the intersection is empty")

        // And the empty set serialises to the empty string, which is what a peer would send.
        // A session that negotiated nothing can still exchange device info and close cleanly,
        // so this is a valid outcome rather than an error to report.
        assertEquals("", CapabilityNegotiation.serialise(negotiated))

        assertEquals(
            names(v, "expected_negotiated"),
            negotiated.toList(),
            "an empty intersection is declared as such",
        )
    }

    /**
     * A name outside the registry is ignored rather than passed through.
     */
    @Test
    fun anUnknownCapabilityNameIsIgnored() {
        val v = vector("negotiate.unknown-capability-name-ignored")

        val agent = names(v, "agent_capabilities")

        // The vector must actually carry a name outside the registry, or it tests nothing.
        val unknown = agent.filter { it !in CapabilityNegotiation.REGISTRY }

        assertTrue(
            unknown.isNotEmpty(),
            "the vector must offer at least one name outside the registry; it carries ${agent.size} names",
        )

        val negotiated = CapabilityNegotiation.negotiate(
            agent,
            names(v, "agent_disabled"),
            names(v, "controller_offered"),
        )

        for (name in unknown) {
            assertFalse(
                negotiated.contains(name),
                "$name is not in the registry, so agreeing to it would promise something no side implements",
            )
        }

        // Forward compatibility: the unknown name is ignored, not an error. A future revision
        // may define it, and an implementation that failed the handshake would be unusable.
        assertEquals(names(v, "expected_negotiated").sorted(), negotiated.toList())
    }

    /**
     * Duplicate names normalise to one.
     */
    @Test
    fun duplicateNamesAreNormalised() {
        val v = vector("negotiate.duplicate-names-normalised")

        val agent = names(v, "agent_capabilities")

        // A duplicate is tolerated rather than refused, but it must not survive as two
        // entries: the negotiated set is serialised into the transcript, and "[a,a]" and
        // "[a]" are different byte strings for the same agreement.
        val duplicated = agent.size != agent.toSet().size
        val offered = names(v, "controller_offered")
        val duplicatedInOffer = offered.size != offered.toSet().size

        assertTrue(
            duplicated || duplicatedInOffer,
            "the vector must carry a duplicate for this to test anything",
        )

        val negotiated = CapabilityNegotiation.negotiate(agent, emptyList(), offered)

        assertEquals(
            negotiated.size,
            negotiated.toSet().size,
            "the negotiated set carries no duplicates",
        )

        assertEquals(names(v, "expected_negotiated").sorted(), negotiated.toList())
    }

    /**
     * Every limit scenario produces its declared result.
     */
    @Test
    fun everyLimitVectorProducesItsDeclaredResult() {
        assertTrue(limitVectors().size >= 4, "expected at least 4 limit vectors")

        for (v in limitVectors()) {
            when (v["id"]!!.asString()) {
                "limits.video-clamp-to-agent-maximum" -> assertVideoClamp(v, "expected_applied", null)
                "limits.video-clamp-to-screen-size" -> assertVideoClamp(v, "expected_applied", "screen")
                "limits.file-chunk-clamped" -> assertFileChunkRefusal(v)
                "limits.shell-timeout-clamped" -> assertShellTimeoutClamp(v)
                else -> error("unhandled limit vector ${v["id"]!!.asString()}")
            }
        }
    }

    /** Checks a video-clamp vector, optionally against a screen. */
    private fun assertVideoClamp(v: JsonValue, expectedKey: String, screenKey: String?) {
        val id = v["id"]!!.asString()
        val requested = v["requested"] ?: error("$id has no requested object")
        val limits = v["agent_limits"] ?: error("$id has no agent_limits object")
        val expected = v[expectedKey] ?: error("$id has no $expectedKey object")

        val agentLimits = CapabilityNegotiation.Limits(
            maxVideoWidth = limits["max_video_width"]!!.asInt(),
            maxVideoHeight = limits["max_video_height"]!!.asInt(),
            maxVideoFps = limits["max_video_fps"]?.asInt() ?: CapabilityNegotiation.Limits().maxVideoFps,
        )

        // A vector without a screen isolates the ceiling clamp, so the screen is the requested
        // size: with no capture surface to fit inside the ceiling, the effective size is the
        // ceiling itself. Substituting a very large screen here instead would be wrong in the
        // other direction -- it would make the scale vanish and collapse the result to the
        // 2x2 floor, testing neither clamp.
        val screen = screenKey?.let { v[it] }
        val screenWidth = screen?.get("width")?.asInt() ?: requested["max_width"]!!.asInt()
        val screenHeight = screen?.get("height")?.asInt() ?: requested["max_height"]!!.asInt()

        val applied = CapabilityNegotiation.clampVideo(
            requestedWidth = requested["max_width"]!!.asInt(),
            requestedHeight = requested["max_height"]!!.asInt(),
            requestedFps = requested["fps"]?.asInt() ?: expected["fps"]?.asInt() ?: 60,
            agentLimits = agentLimits,
            screenWidth = screenWidth,
            screenHeight = screenHeight,
        )

        assertEquals(expected["width"]!!.asInt(), applied.width, "$id effective width")
        assertEquals(expected["height"]!!.asInt(), applied.height, "$id effective height")

        if (expected["fps"] != null) {
            assertEquals(expected["fps"]!!.asInt(), applied.fps, "$id effective fps")
        }

        // H.264 requires even dimensions, and the vector's note records that both are even.
        assertEquals(0, applied.width % 2, "$id width is even")
        assertEquals(0, applied.height % 2, "$id height is even")

        // The clamp reduces, never increases. An implementation that returned the request
        // unchanged would satisfy "not larger than the screen" but ignore the agent's limits.
        if (screenKey == null) {
            assertTrue(
                applied.width <= requested["max_width"]!!.asInt(),
                "$id never returns more than was requested",
            )

            assertTrue(applied.fps <= agentLimits.maxVideoFps, "$id respects the frame-rate ceiling")
        }
    }

    /**
     * Capture never upscales a screen smaller than the ceiling.
     *
     * No vector exercises this rule: in both video vectors the scale factor is below one, so
     * the guard that caps it is inert and removing it changes neither result. The rule is
     * still a rule -- interpolating a small screen up to the ceiling would produce pixels
     * that carry no information while costing full bitrate -- so it is tested here rather
     * than left as unreachable code that a mutation would not catch.
     */
    @Test
    fun captureNeverUpscalesASmallerScreen() {
        // A ceiling above the screen on BOTH axes, so the scale factor would exceed one and
        // the guard is what stops it. This is the part that is easy to get wrong: a ceiling
        // larger on one axis only still produces a scale below one and scales down, so it does
        // not reach the guard at all.
        val applied = CapabilityNegotiation.clampVideo(
            requestedWidth = 3840,
            requestedHeight = 2160,
            requestedFps = 60,
            agentLimits = CapabilityNegotiation.Limits(maxVideoWidth = 3840, maxVideoHeight = 2160),
            screenWidth = 720,
            screenHeight = 1280,
        )

        // The screen's own size, unchanged: not scaled up to the 3840x2160 ceiling.
        assertEquals(720, applied.width, "a screen smaller than the ceiling on both axes is captured at its own size")
        assertEquals(1280, applied.height, "both axes stay at the screen's size")

        // And scaled down normally when the ceiling really is smaller, which brackets the rule.
        val scaled = CapabilityNegotiation.clampVideo(
            requestedWidth = 360,
            requestedHeight = 640,
            requestedFps = 60,
            agentLimits = CapabilityNegotiation.Limits(),
            screenWidth = 720,
            screenHeight = 1280,
        )

        assertEquals(360, scaled.width, "a ceiling smaller than the screen scales it down")
        assertEquals(640, scaled.height, "both axes scale together")

        // The aspect ratio survives the scale, which is the point of scaling rather than
        // cropping to the ceiling's shape.
        val screenRatio = 720.0 / 1280.0
        val scaledRatio = scaled.width.toDouble() / scaled.height.toDouble()

        assertTrue(
            kotlin.math.abs(screenRatio - scaledRatio) < 0.01,
            "the scaled result keeps the screen's ratio",
        )
    }

    /**
     * The screen's aspect ratio is preserved, not the request's.
     *
     * This is the rule the vector `limits.video-clamp-to-screen-size` settles, and it is easy
     * to get backwards in a way that still produces a plausible-looking size. A 1920x1080
     * request against a 1080x2400 portrait screen must produce a portrait result, because the
     * thing being scaled is the screen.
     */
    @Test
    fun theScreensAspectRatioIsPreservedNotTheRequests() {
        val v = vector("limits.video-clamp-to-screen-size")

        val requested = v["requested"]!!
        val screen = v["screen"]!!
        val expected = v["expected_applied"]!!

        val applied = CapabilityNegotiation.clampVideo(
            requestedWidth = requested["max_width"]!!.asInt(),
            requestedHeight = requested["max_height"]!!.asInt(),
            requestedFps = 60,
            agentLimits = CapabilityNegotiation.Limits(),
            screenWidth = screen["width"]!!.asInt(),
            screenHeight = screen["height"]!!.asInt(),
        )

        assertEquals(expected["width"]!!.asInt(), applied.width)
        assertEquals(expected["height"]!!.asInt(), applied.height)

        // The result is portrait, like the screen, even though the request was landscape.
        assertTrue(
            applied.height > applied.width,
            "the result is portrait because the screen is, even though the request is landscape",
        )

        // And the ratio matches the screen's, not the request's. Within one pixel, because the
        // dimensions are rounded to even numbers for H.264.
        val screenRatio = screen["width"]!!.asInt().toDouble() / screen["height"]!!.asInt().toDouble()
        val appliedRatio = applied.width.toDouble() / applied.height.toDouble()

        assertTrue(
            kotlin.math.abs(screenRatio - appliedRatio) < 0.01,
            "the result's ratio $appliedRatio matches the screen's $screenRatio, not the request's",
        )

        val requestRatio = requested["max_width"]!!.asInt().toDouble() / requested["max_height"]!!.asInt().toDouble()

        assertTrue(
            kotlin.math.abs(requestRatio - appliedRatio) > 0.5,
            "the result's ratio must NOT match the request's $requestRatio, which is the mistake this pins",
        )
    }

    /** Checks that an over-large file chunk is refused rather than truncated. */
    private fun assertFileChunkRefusal(v: JsonValue) {
        val id = v["id"]!!.asString()

        val verdict = CapabilityNegotiation.clampFileChunk(
            requestedChunk = v["requested_chunk"]!!.asInt(),
            agentMaxFileChunk = v["agent_max_file_chunk"]!!.asInt(),
        )

        assertEquals("rejected", v["expected"]!!.asString(), "$id is declared rejected")

        assertFalse(verdict.accepted, "$id is refused")
        assertEquals(v["expected_error"]!!.asString(), verdict.error?.name, "$id error code")

        // And it is refused rather than clamped: a truncated chunk would be a silently short
        // buffer the controller believes is full, which is indistinguishable from a short file.
        assertEquals(
            0,
            verdict.effectiveChunk,
            "$id reports no effective chunk, because there is none",
        )

        // One byte below the limit is accepted, which brackets the boundary.
        val oneBelow = CapabilityNegotiation.clampFileChunk(
            requestedChunk = v["agent_max_file_chunk"]!!.asInt(),
            agentMaxFileChunk = v["agent_max_file_chunk"]!!.asInt(),
        )

        assertTrue(oneBelow.accepted, "$id exactly at the limit is accepted")
        assertNull(oneBelow.error, "$id at the limit carries no error")
    }

    /** Checks that a long command deadline is clamped rather than refused. */
    private fun assertShellTimeoutClamp(v: JsonValue) {
        val id = v["id"]!!.asString()

        val applied = CapabilityNegotiation.clampShellTimeout(
            requestedTimeoutMs = v["requested_timeout_ms"]!!.asInt(),
            agentShellTimeoutMs = v["agent_shell_timeout_ms"]!!.asInt(),
        )

        assertEquals(v["expected_applied_timeout_ms"]!!.asInt(), applied, "$id applied timeout")

        // Clamped, not refused: a long deadline is a preference and running with a shorter one
        // still does what the controller asked.
        assertTrue(
            applied <= v["agent_shell_timeout_ms"]!!.asInt(),
            "$id never exceeds the agent's limit",
        )

        // A request under the limit is honoured unchanged.
        assertEquals(
            1000,
            CapabilityNegotiation.clampShellTimeout(1000, v["agent_shell_timeout_ms"]!!.asInt()),
            "$id honours a request under the limit",
        )
    }

    /**
     * Every channel-direction scenario produces its declared result.
     */
    @Test
    fun everyDirectionVectorProducesItsDeclaredResult() {
        assertTrue(directionVectors().size >= 2, "expected at least 2 direction vectors")

        for (v in directionVectors()) {
            when (v["id"]!!.asString()) {
                "negotiate.controller-allocates-odd-channel-ids" -> assertChannelParity(v)
                "negotiate.channel-id-reuse-requires-close" -> assertChannelReuseIsRefused(v)
                else -> error("unhandled direction vector ${v["id"]!!.asString()}")
            }
        }
    }

    /** Checks the parity partition over several allocations on each side. */
    private fun assertChannelParity(v: JsonValue) {
        val id = v["id"]!!.asString()

        assertEquals(v["controller_first"]!!.asLong(), 1L, "$id controller allocates 1 first")
        assertEquals(v["agent_first"]!!.asLong(), 2L, "$id agent allocates 2 first")

        val expectedController = v["expected_controller_sequence"]!!.asArray().map { it.asLong() }
        val expectedAgent = v["expected_agent_sequence"]!!.asArray().map { it.asLong() }

        // The sequences are built by repeated allocation, not read from the vector: a vector
        // that lists the expected ids is the check, and deriving the actual ones proves the
        // allocator produces them.
        val controller = buildSequence(expectedController.size) { last -> CapabilityNegotiation.nextChannelId(last, controller = true) }
        val agent = buildSequence(expectedAgent.size) { last -> CapabilityNegotiation.nextChannelId(last, controller = false) }

        assertEquals(expectedController, controller, "$id controller sequence")
        assertEquals(expectedAgent, agent, "$id agent sequence")

        // The partition: the two sequences never intersect, which is what lets both sides
        // allocate concurrently without a race.
        assertEquals(
            emptyList(),
            controller.intersect(agent.toSet()).toList(),
            "$id the two sides never propose the same id",
        )

        // And neither reaches channel 0, the control channel.
        for (sequence in listOf(controller, agent)) {
            assertFalse(sequence.contains(0L), "$id the control channel is never allocated")
        }

        // The parity holds for every element, which is the invariant rather than the example.
        for (odd in controller) {
            assertEquals(1L, odd % 2, "$id controller ids are odd")
        }

        for (even in agent) {
            assertEquals(0L, even % 2, "$id agent ids are even")
        }
    }

    /** Runs an allocator n times, threading the last allocation. */
    private fun buildSequence(length: Int, allocate: (Long?) -> Long?): List<Long> {
        val out = mutableListOf<Long>()
        var last: Long? = null

        repeat(length) {
            val next = allocate(last) ?: error("the allocator ran out of ids after ${out.size}")
            out.add(next)
            last = next
        }

        return out
    }

    /** Checks that reusing an open channel id is a state error, not a limit error. */
    private fun assertChannelReuseIsRefused(v: JsonValue) {
        val id = v["id"]!!.asString()

        val open = v["open_channels"]!!.asArray().map { it.asLong() }.toSet()
        val reopen = v["reopen_request"]!!.asLong()

        assertTrue(reopen in open, "$id the reopen target must already be open")

        val verdict = CapabilityNegotiation.openChannel(
            requested = reopen,
            openChannels = open,
            maxChannels = CapabilityNegotiation.Limits().maxChannels,
        )

        assertFalse(verdict.accepted, "$id an open channel is not reopened")

        // The fault is a state error specifically, and the code matters: reporting a limit
        // error would suggest retrying, when the correct response is to close the channel
        // first. A retry would loop forever against the same open id.
        assertEquals(v["expected_error"]!!.asString(), verdict.error?.name, "$id error code")

        // A fresh id is accepted, so the refusal is about reuse and not about opening.
        val fresh = CapabilityNegotiation.openChannel(
            requested = 3,
            openChannels = open,
            maxChannels = CapabilityNegotiation.Limits().maxChannels,
        )

        assertTrue(fresh.accepted, "$id an unopened id is accepted")
        assertNull(fresh.error, "$id an acceptable open carries no error")
    }

    /**
     * The channel limit counts every channel, the control channel included.
     */
    @Test
    fun theChannelLimitCountsTheControlChannel() {
        val max = CapabilityNegotiation.Limits().maxChannels

        // Channels 0 through 7 is eight channels against a limit of eight, so opening another
        // is refused. Counting only data channels would see seven here and allow a ninth.
        val atLimit = (0L until max.toLong()).toSet()

        assertEquals(max, atLimit.size, "the scenario is exactly at the limit")

        val refused = CapabilityNegotiation.openChannel(100, atLimit, max)

        assertFalse(refused.accepted, "opening past the limit is refused")
        assertEquals(ErrorCode.CHANNEL_LIMIT.name, refused.error?.name, "the fault is a limit, not a state")

        // One below is accepted.
        val oneBelow = atLimit - max.toLong() + 1

        val accepted = CapabilityNegotiation.openChannel(100, oneBelow, max)

        assertTrue(accepted.accepted, "one below the limit is accepted")
    }
}
