package dev.droidlab.protocol

/**
 * Capability and limit negotiation (RFC-0001 section 7).
 *
 * Negotiation runs once, at the end of the handshake, and its result is what every later
 * frame is checked against. It has three parts that are easy to conflate and must not be:
 *
 *  - **Which capabilities are usable.** The intersection of what the agent implements and
 *    what the controller offered, minus anything an operator has disabled on the agent.
 *  - **Which limits apply.** The agent's limits, clamped, so the controller can ask for more
 *    than the agent allows without the session failing.
 *  - **Which channel ids each side may allocate.** Partitioned by parity, so the two sides
 *    can allocate concurrently without a race.
 *
 * The direction of the rules matters and is not symmetric. A capability the controller never
 * offered is unusable even though the agent supports it, and a capability the operator
 * disabled is unusable even though both sides support it. Both are subtractions, and neither
 * can resurrect a capability the other one removed -- which is what stops a later negotiation
 * step from quietly re-granting something.
 *
 * The class is stateless. Negotiation is a pure function of three sets and a limit record,
 * and keeping it that way is what makes the vectors reproducible: the result cannot depend on
 * a session's history.
 */
object CapabilityNegotiation {
    /**
     * The capabilities an agent may advertise.
     *
     * Mirrors `protocol/registry/dlwp-1.json`. An agent advertising a name outside this set
     * is not an error -- the name is ignored, which is the forward-compatibility rule -- but
     * it also cannot be negotiated, so listing the known set is what separates "a capability
     * this controller is too old to use" from "a capability nobody implements".
     */
    val REGISTRY: Set<String> = setOf(
        "screen.mirror",
        "screen.record",
        "input.touch",
        "input.key",
        "input.text",
        "input.gesture",
        "clipboard.read",
        "clipboard.write",
        "shell.exec",
        "file.read",
        "file.write",
        "log.stream",
        "app.install",
        "app.launch",
        "device.info",
        "adb.wireless",
        "compression.deflate",
        "telemetry.stats",
    )

    /** The agent's default limits, matching RFC-0001 section 7.3 and the registry. */
    data class Limits(
        val maxFrameBytes: Int = 16_777_216,
        val maxChannels: Int = 8,
        val maxVideoWidth: Int = 1920,
        val maxVideoHeight: Int = 1080,
        val maxVideoFps: Int = 60,
        val maxVideoBitrate: Int = 16_000_000,
        val maxFileChunk: Int = 262_144,
        val shellTimeoutMs: Int = 30_000,
        val maxGestureSteps: Int = 256,
    )

    /**
     * Negotiates the usable capability set.
     *
     * @param agentCapabilities what the agent implements.
     * @param agentDisabled what an operator has disabled on the agent.
     * @param controllerOffered what the controller is willing to use.
     * @return the negotiated set, sorted ordinally so two implementations comparing their
     *   results compare the same sequence and not merely the same elements.
     *
     * The result is sorted rather than left in encounter order because a set has no order and
     * a transcript over it needs one. Two peers that each negotiated correctly but serialised
     * their sets in different orders would compute different transcript bytes and fail
     * authentication, with nothing in the logs pointing at the ordering.
     */
    fun negotiate(
        agentCapabilities: Collection<String>,
        agentDisabled: Collection<String>,
        controllerOffered: Collection<String>,
    ): SortedSet<String> {
        // Normalised to sets first: the vectors carry duplicates, and a duplicate in the
        // controller's offer is not an error but must not survive into the result as a
        // second copy, which would change any transcript computed over the list.
        val agent = agentCapabilities.toSet()
        val disabled = agentDisabled.toSet()
        val offered = controllerOffered.toSet()

        val negotiated = agent
            .intersect(offered)
            .subtract(disabled)
            // Names outside the registry are dropped rather than passed through. Passing an
            // unknown name to the caller would let an agent advertise a capability neither
            // side implements and have it appear granted, which is worse than not supporting
            // it: the controller would send frames for it and the agent would refuse them.
            .filter { it in REGISTRY }

        return negotiated.toSortedSet(String.CASE_INSENSITIVE_ORDER)
    }

    /**
     * The negotiated set's canonical serialised form.
     *
     * @param negotiated the set from [negotiate].
     * @return the names joined by commas, in sorted order.
     *
     * Exposed because the vectors compare against a sorted list and because a session records
     * the negotiated set in its transcript; having one function that produces the canonical
     * bytes keeps the two from drifting.
     */
    fun serialise(negotiated: Collection<String>): String =
        negotiated.toSortedSet(String.CASE_INSENSITIVE_ORDER).joinToString(",")

    /**
     * Whether a capability is usable in a session.
     *
     * @param negotiated the set from [negotiate].
     * @param capability the capability to check.
     * @return true when the capability was negotiated.
     */
    fun isGranted(negotiated: Collection<String>, capability: String): Boolean =
        capability in negotiated

    /**
     * Clamps a requested video configuration to what the agent and the screen allow.
     *
     * @param requestedWidth the width the controller asked for.
     * @param requestedHeight the height the controller asked for.
     * @param requestedFps the frame rate the controller asked for.
     * @param agentLimits the agent's limits.
     * @param screenWidth the capture surface's width.
     * @param screenHeight the capture surface's height.
     * @return the effective configuration.
     *
     * The clamping is a minimum on each axis, and the screen clamp is applied after the
     * agent's limit so that a request exceeding both is settled by whichever is smaller.
     *
     * The aspect ratio is preserved by fitting the requested box inside the screen's box,
     * and both dimensions are rounded to even numbers. Even dimensions are not cosmetic:
     * H.264 codes in 16x16 macroblocks and 4:2:0 chroma is subsampled by two in each
     * direction, so an odd width has no valid chroma layout and encoders either pad or refuse.
     * The vector's own note records that 486x1080 preserves the 1080:2400 ratio to within a
     * pixel with both dimensions even.
     */
    fun clampVideo(
        requestedWidth: Int,
        requestedHeight: Int,
        requestedFps: Int,
        agentLimits: Limits,
        screenWidth: Int,
        screenHeight: Int,
    ): VideoConfiguration {
        // The request is a ceiling on each axis, not a shape, and the SCREEN is the thing
        // that gets scaled. This is the part that is easy to get backwards: the effective
        // size is the screen's size scaled down to fit inside the requested box, so the
        // aspect ratio comes from the screen and not from the request.
        //
        // Getting it backwards letterboxes a screen whose orientation differs from the
        // request. A 1920x1080 request against a 1080x2400 portrait screen must give a
        // portrait 486x1080; deriving the ratio from the request instead gives a landscape
        // 1080x608, which is the wrong shape for the device being mirrored.
        val ceilingWidth = minOf(requestedWidth, agentLimits.maxVideoWidth)
        val ceilingHeight = minOf(requestedHeight, agentLimits.maxVideoHeight)

        // The agent's frame-rate ceiling applies regardless of the screen.
        val fps = minOf(requestedFps, agentLimits.maxVideoFps)

        // The smaller of the two axis ratios is the one that fits BOTH axes; the larger would
        // overflow one of them. The screen is fitted inside the ceiling, never upscaled: a
        // screen smaller than the ceiling is captured at its own resolution, because
        // interpolating up would add pixels carrying no information while still costing
        // bitrate.
        val scale = minOf(
            ceilingWidth.toDouble() / screenWidth.toDouble(),
            ceilingHeight.toDouble() / screenHeight.toDouble(),
        )

        // Only scale down. A ratio above one would mean the ceiling is larger than the screen
        // on both axes, and capturing at more pixels than the screen has is interpolation.
        val effectiveScale = minOf(1.0, scale)

        val width = even(kotlin.math.round(screenWidth * effectiveScale).toInt())
        val height = even(kotlin.math.round(screenHeight * effectiveScale).toInt())

        // A clamp can shrink a dimension to zero on an extreme request, which would be an
        // unusable configuration and, worse, a divide by zero in any caller computing a
        // stride. Two is the smallest even dimension that is still an image.
        return VideoConfiguration(maxOf(2, width), maxOf(2, height), fps)
    }

    /** An effective video configuration. */
    data class VideoConfiguration(val width: Int, val height: Int, val fps: Int)

    /** Rounds down to the nearest even number, which H.264 requires. */
    private fun even(value: Int): Int = if (value % 2 == 0) value else value - 1

    /**
     * Decides whether a requested file chunk is usable.
     *
     * @param requestedChunk the chunk size the controller asked for.
     * @param agentMaxFileChunk the agent's limit.
     * @return the verdict.
     *
     * Refused rather than truncated. The vector's note is the reason: truncation would mean
     * the controller allocated a buffer it believes is a full chunk, and a silently short
     * read is indistinguishable from a short file.
     */
    fun clampFileChunk(requestedChunk: Int, agentMaxFileChunk: Int): ChunkVerdict =
        if (requestedChunk > agentMaxFileChunk) {
            ChunkVerdict(accepted = false, error = ErrorCode.FRAME_TOO_LARGE, effectiveChunk = 0)
        } else {
            ChunkVerdict(accepted = true, error = null, effectiveChunk = requestedChunk)
        }

    /** The verdict for a requested file chunk. */
    data class ChunkVerdict(val accepted: Boolean, val error: ErrorCode?, val effectiveChunk: Int)

    /**
     * Clamps a requested command deadline.
     *
     * @param requestedTimeoutMs the deadline the controller asked for.
     * @param agentShellTimeoutMs the agent's limit.
     * @return the effective deadline.
     *
     * Clamped rather than refused, unlike a file chunk, and the difference is intentional: a
     * long deadline is a preference, and running the command with a shorter one still does
     * what the controller asked. A chunk size is a buffer allocation, and honouring a smaller
     * one without saying so is a silent data corruption.
     */
    fun clampShellTimeout(requestedTimeoutMs: Int, agentShellTimeoutMs: Int): Int =
        minOf(requestedTimeoutMs, agentShellTimeoutMs)

    /**
     * Allocates the next channel id for one side of a session.
     *
     * @param lastAllocated the last id this side allocated, or null if it has not allocated.
     * @param controller true for the controller, false for the agent.
     * @return the next id, or null when the id space is exhausted.
     *
     * Channel ids are partitioned by parity: the controller takes odd ids and the agent takes
     * even ones. The partition exists so that both sides can open channels concurrently
     * without a race, since neither can propose an id the other might also propose. Selecting
     * by parity rather than by rejecting a colliding proposal is what makes allocation
     * lock-free -- a reject-and-retry scheme would need a round trip per channel and could
     * livelock under load.
     *
     * Channel 0 is the control channel and is never allocated here, which the arithmetic
     * enforces: the sequences start at 1 and 2 and step by two, so neither reaches 0.
     */
    fun nextChannelId(lastAllocated: Long?, controller: Boolean): Long? {
        val first = if (controller) 1L else 2L

        val next = when (lastAllocated) {
            null -> first
            else -> lastAllocated + 2L
        }

        // A u32 channel id, so the space ends here rather than wrapping. Wrapping would
        // produce an id the peer may still have open, which is the one thing the parity
        // partition cannot protect against on its own.
        return if (next > MAX_CHANNEL_ID) null else next
    }

    /** The largest channel id, since the field is a u32. */
    const val MAX_CHANNEL_ID: Long = 0xFFFFFFFFL

    /**
     * Whether a channel id may be opened in a session.
     *
     * @param requested the id the side wants to open.
     * @param openChannels the ids already open.
     * @param maxChannels the agent's limit.
     * @return a verdict naming the fault, or acceptance.
     *
     * Reuse of an open id is a state error rather than a limit error, and the distinction
     * matters: the peer may still have frames queued for the old channel, so the two
     * encodings of "channel 1" would be interleaved in a way neither side could untangle.
     * Reporting it as a limit error would suggest retrying, which is exactly the wrong
     * response.
     */
    fun openChannel(
        requested: Long,
        openChannels: Set<Long>,
        maxChannels: Int,
    ): ChannelOpenVerdict {
        if (requested in openChannels) {
            return ChannelOpenVerdict(accepted = false, error = ErrorCode.BAD_STATE)
        }

        // Every open channel counts, the control channel included. The registry's
        // max_channels is a count of channels, not of data channels, so a session with
        // channels 0 through 7 is at the limit of 8.
        if (openChannels.size >= maxChannels) {
            return ChannelOpenVerdict(accepted = false, error = ErrorCode.CHANNEL_LIMIT)
        }

        return ChannelOpenVerdict(accepted = true, error = null)
    }

    /** The verdict for a channel-open request. */
    data class ChannelOpenVerdict(val accepted: Boolean, val error: ErrorCode?)
}
