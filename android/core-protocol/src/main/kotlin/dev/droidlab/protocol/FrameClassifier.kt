package dev.droidlab.protocol

// The only thing this layer takes from the cbOR reader: whether a body may be handed on.
// Named so that a reader can see the frame layer does not parse bodies, it only judges them.
import dev.droidlab.protocol.cbor.CborBody

/**
 * The outcome a malformed input must produce (RFC-0001 section 6).
 *
 * The distinction these four values carry is the one that matters operationally: whether
 * the connection survives. Treating a recoverable error as fatal closes a usable session;
 * treating a fatal one as recoverable means continuing after a peer has sent something the
 * receiver cannot interpret, which is how a desynchronised stream turns into a confusing
 * failure much later.
 */
enum class FrameOutcome {
    /**
     * The frame is accepted as-is.
     *
     * Two of the vectors land here and both matter. A reserved flag bit is preserved and
     * ignored, so a peer using those bits for something this version does not know is not
     * punished for it. An unknown body key is ignored for the same reason: section 3.2
     * requires a receiver to ignore what it does not recognise, because the alternative is
     * that adding a field to the protocol is a breaking change.
     */
    Accepted,

    /** An ERROR frame is sent and the session continues. */
    ErrorSessionContinues,

    /** An ERROR frame is sent and the connection is then closed. */
    ErrorFrameThenClose,

    /**
     * The connection is closed with no error frame.
     *
     * This is the answer to bytes that are not a frame at all. There is nothing to reply to
     * and nothing to resynchronise on, because an arbitrary offset might look like the
     * magic sequence from the middle of a body.
     */
    CloseConnection,

    /**
     * The input is incomplete rather than wrong; the error comes when the connection ends.
     *
     * A declared body that never fully arrives is not malformed, it is unfinished. The
     * difference decides whether a receiver waits or gives up, and getting it wrong means
     * either hanging on a truncated frame or closing on one that arrived in two packets.
     */
    WaitThenErrorOnClose,
}

/**
 * The verdict for one frame (RFC-0001 sections 4 and 6).
 *
 * @property outcome what the receiver must do.
 * @property error the error to report, or null when the frame is accepted.
 */
data class FrameVerdict(val outcome: FrameOutcome, val error: ErrorCode?) {
    /** Whether the session survives this verdict. */
    val sessionSurvives: Boolean
        get() = outcome == FrameOutcome.Accepted || outcome == FrameOutcome.ErrorSessionContinues
}

/**
 * Classifies a frame against the protocol registry and the session's state.
 *
 * This is deliberately stateless with respect to the session: the caller passes in what it
 * knows (the open channels, the negotiated capabilities, whether this is the first frame)
 * and gets back a verdict. Passing the state in rather than holding it means a classification
 * cannot depend on when it happened to be called, which is the property that makes the
 * malformed vectors reproducible.
 *
 * The order of the checks is normative, not incidental. Structural validity is settled
 * before anything that depends on the message type, because a frame whose header cannot be
 * parsed has no message type to look up; and size is settled before the body is examined,
 * because examining a body means having allocated for it.
 */
class FrameClassifier(private val registry: Registry) {
    /**
     * What the caller knows about the session when the frame arrives.
     *
     * @property channelId the channel the frame arrived on.
     * @property messageType the message type code, or null when the header was unreadable.
     * @property openChannels the channel ids currently open, excluding the control channel.
     * @property negotiatedCapabilities the capabilities agreed in the handshake.
     * @property isFirstFrame whether this is the first frame of a new session.
     */
    data class Context(
        val channelId: Long = 0,
        val messageType: Int? = null,
        val openChannels: Set<Long> = emptySet(),
        val negotiatedCapabilities: Set<String> = emptySet(),
        val isFirstFrame: Boolean = false,
    )

    /**
     * Classifies a structural decode failure.
     *
     * @param error the code the decoder produced.
     * @return the verdict.
     *
     * `ERR_FRAME_TOO_LARGE` and `ERR_UNSUPPORTED_HEADER` arrive here already labelled, and
     * they are kept rather than collapsed into `ERR_MALFORMED`: a peer that is told its
     * frame was too large can split it, while one told its frame was malformed has nothing
     * to act on.
     */
    fun classifyDecodeFailure(error: ErrorCode): FrameVerdict = when (error) {
        ErrorCode.VERSION_MISMATCH,
        ErrorCode.UNSUPPORTED_HEADER,
        ErrorCode.FRAME_TOO_LARGE,
        -> FrameVerdict(FrameOutcome.ErrorFrameThenClose, error)

        // Everything else from the decoder is a malformed frame. A bad magic never reaches
        // here: bytes that are not a frame are classified by classifyNotAFrame, because
        // there is nothing to answer.
        else -> FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.MALFORMED)
    }

    /**
     * Classifies a raw frame, including whether bytes that are not a frame at all.
     *
     * @param bytes the frame's bytes.
     * @param context what the caller knows about the session.
     * @return the verdict.
     *
     * This is the entry point a receive path should use, because the order of the checks is
     * part of the protocol rather than an implementation detail:
     *
     * 1. **Is this a frame at all?** A wrong magic means the stream is not DLWP/1, so the
     *    connection closes with no error frame -- there is nothing to reply to and no
     *    framing to resynchronise on, since any offset might look like the magic from the
     *    middle of a body. This is checked before the header is validated, and it is why the
     *    `malformed.bad-magic` vector expects `close_connection` while every other malformed
     *    frame expects an error frame first.
     * 2. **Is the header valid?** then **is it small enough?** -- in that order, because a
     *    size check needs a parsed length, and refusing on size before parsing would mean
     *    trusting bytes that have not been validated.
     * 3. **Is the body well-formed?** then **what does the message mean?**
     */
    fun classify(bytes: ByteArray, context: Context = Context()): FrameVerdict {
        // The magic is checked directly rather than inferred from the decoder's error, so
        // that the one case which closes without replying is decided here, where the reason
        // is visible, and cannot be changed by an unrelated decoder edit.
        if (bytes.size >= 4 && !hasMagic(bytes)) {
            return classifyNotAFrame()
        }

        return when (val read = FrameCodec.read(bytes)) {
            is FrameCodec.ReadResult.Failure -> classifyDecodeFailure(read.error)

            // An unfinished frame is not malformed; the error comes when the connection ends
            // without the rest arriving. Folding it into malformed would close on a frame
            // that simply arrived in two packets.
            is FrameCodec.ReadResult.NeedMoreBytes ->
                FrameVerdict(FrameOutcome.WaitThenErrorOnClose, ErrorCode.IO)

            is FrameCodec.ReadResult.Success -> classifyFrame(read.frame, context)
        }
    }

    /**
     * Classifies a decoded frame, body included.
     *
     * @param frame the frame.
     * @param context what the caller knows about the session.
     * @return the verdict.
     */
    private fun classifyFrame(frame: Frame, context: Context): FrameVerdict {
        val messageType = registry.findMessageType(frame.messageType)

        // 4. The body must be well-formed cbOR before its meaning is considered. This runs
        // before the message-type lookup for a reason that is easy to get backwards: a body
        // that is not cbOR at all cannot be handed to any per-message parser, so reporting
        // "unknown message type" for it would name the wrong fault and send a peer looking
        // in the wrong place. Structural validity is a property of the frame; the message
        // type is a property of the meaning.
        if (!isWellFormedBody(frame)) {
            return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.MALFORMED)
        }

        // An unknown message type is recoverable and explicit. It has to be distinct from a
        // malformed frame: the frame is well formed and the peer is speaking a version this
        // one does not, so the session can continue and the peer learns what was not
        // understood. Collapsing the two would end sessions on a forward-compatible change.
        if (messageType == null) {
            return FrameVerdict(FrameOutcome.ErrorSessionContinues, ErrorCode.UNSUPPORTED_MESSAGE)
        }

        // The first frame of a session must be HELLO, whatever it is. Checked after the
        // body's well-formedness, because the point is to refuse a session that started
        // wrong rather than to interpret the first thing an unauthenticated peer sent.
        //
        // Note the rule is not "the first frame must be a handshake message": PING is a
        // perfectly ordinary registered message and is still refused here, which is what the
        // malformed.first-frame-not-hello vector pins. Restricting the check to handshake
        // types would let a peer open with any of the other 38 messages, which is most of
        // the surface the check exists to close.
        if (context.isFirstFrame && frame.messageType != MessageTypes.HELLO) {
            return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.UNEXPECTED_MESSAGE)
        }

        // A message that needs a capability the handshake did not grant. Recoverable, and
        // per-message rather than per-session: a controller may legitimately send one command
        // the device cannot serve and everything else must keep working.
        val capability = registry.messageTypeCapability(frame.messageType)
        if (capability != null && capability != ANY_CAPABILITY &&
            !context.negotiatedCapabilities.contains(capability)
        ) {
            return FrameVerdict(FrameOutcome.ErrorSessionContinues, ErrorCode.UNSUPPORTED_FEATURE)
        }

        // A frame on a channel that was never opened. The control channel is always open.
        if (frame.channelId != 0L && !context.openChannels.contains(frame.channelId)) {
            return FrameVerdict(FrameOutcome.ErrorSessionContinues, ErrorCode.CHANNEL_UNKNOWN)
        }

        return FrameVerdict(FrameOutcome.Accepted, null)
    }

    /**
     * Whether a frame's body is a well-formed cbOR map.
     *
     * @param frame the frame.
     * @return whether the body may be handed to a per-message parser.
     *
     * A body is checked only when it is readable as plaintext, and the plaintext test is the
     * thing that matters here. An encrypted body is `nonce || ciphertext || tag`, so running
     * the cbOR reader over it asks whether a random-looking byte string happens to parse as
     * cbOR -- a question with no meaning whose answer is "no" almost always. A receiver that
     * checked it anyway would reject every encrypted frame, which is the failure mode of
     * doing a plaintext check on ciphertext, and it is why this is stated rather than
     * implied by a flag check buried in the reader.
     */
    private fun isWellFormedBody(frame: Frame): Boolean {
        if (frame.header.isEncrypted) {
            return true
        }

        return CborBody.isWellFormedMap(frame.body)
    }

    /**
     * Whether the bytes start with the DLWP magic.
     *
     * @param bytes the bytes.
     * @return whether they do.
     */
    internal fun hasMagic(bytes: ByteArray): Boolean =
        bytes[0] == 0x44.toByte() && // D
            bytes[1] == 0x4C.toByte() && // L
            bytes[2] == 0x57.toByte() && // W
            bytes[3] == 0x50.toByte() // P

    /**
     * Classifies bytes that did not start with the magic.
     *
     * @return the verdict: closed, with no error frame.
     */
    fun classifyNotAFrame(): FrameVerdict =
        FrameVerdict(FrameOutcome.CloseConnection, ErrorCode.MALFORMED)

    /**
     * Classifies opening one more channel.
     *
     * @param requestedChannel the channel being opened.
     * @param openChannels the channels already open.
     * @return the verdict.
     *
     * The limit counts every open channel, the control channel included, because that is
     * what the registry's `max_channels` means and what the `malformed.channel-limit` vector
     * encodes: it lists eight channels, 0 through 7, against a limit of 8. Excluding the
     * control channel here would let a session reach nine and quietly exceed the limit the
     * agent advertised, which is the kind of off-by-one that only shows up under load.
     */
    fun classifyChannelOpen(requestedChannel: Long, openChannels: Set<Long>): FrameVerdict {
        if (openChannels.size >= registry.maxChannels) {
            return FrameVerdict(FrameOutcome.ErrorSessionContinues, ErrorCode.CHANNEL_LIMIT)
        }

        // A channel that is already open is refused rather than replaced. Reusing an id
        // would silently rebind a stream that other state still refers to.
        if (openChannels.contains(requestedChannel)) {
            return FrameVerdict(FrameOutcome.ErrorSessionContinues, ErrorCode.CHANNEL_LIMIT)
        }

        return FrameVerdict(FrameOutcome.Accepted, null)
    }

    /**
     * Classifies a body against the message's required and optional keys.
     *
     * @param messageTypeCode the message type code.
     * @param requiredKeys the keys the message requires.
     * @param presentKeys the keys the body carries.
     * @param knownKeys the keys the message defines.
     * @return the verdict.
     *
     * An unknown key is accepted and ignored, which is the section 3.2 rule and the reason
     * this takes the known keys separately from the required ones. Refusing an unknown key
     * would make adding a field a breaking change, so a receiver that rejects one is not
     * being strict, it is being wrong.
     */
    fun classifyBody(
        messageTypeCode: Int,
        requiredKeys: Set<String>,
        presentKeys: Set<String>,
        knownKeys: Set<String>,
    ): FrameVerdict {
        for (required in requiredKeys) {
            if (!presentKeys.contains(required)) {
                // A missing required key is malformed rather than "unsupported": the frame
                // is the right message type and cannot be acted on as one.
                return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.MALFORMED)
            }
        }

        // A key that is neither required nor known is ignored, not refused.
        for (present in presentKeys) {
            if (!knownKeys.contains(present) && !requiredKeys.contains(present)) {
                return FrameVerdict(FrameOutcome.Accepted, null)
            }
        }

        return FrameVerdict(FrameOutcome.Accepted, null)
    }

    /**
     * Classifies a sequence number against the highest already accepted.
     *
     * @param sequenceNumber the number that arrived.
     * @param highestSeen the highest accepted so far, or null when nothing has been.
     * @param seenBefore whether this exact number has already been accepted, or null when
     *   the caller does not track that.
     * @param window the reorder window.
     * @return the verdict.
     *
     * The two failures this separates are not the same failure. A number **ahead** of the
     * highest seen is normal, and a gap up to the window is legal reordering that a
     * receiver must tolerate because the transport does not guarantee order.
     *
     * A number **already accepted** is a replay, and it is indistinguishable from legal
     * reordering by a high-water mark alone: the vector `[1,2,3,3]` repeats the head, and
     * `[1,2,3,5,4,6]` goes four behind the head, so a window check accepts both. That is
     * exactly the defect this parameter exists to close -- only a seen-set separates them,
     * which is why `seenBefore` is checked *before* the window rather than after.
     *
     * A number more than `window` behind the head is refused rather than accepted, because
     * accepting it would require buffering without bound to know whether the frames in
     * between will ever arrive.
     */
    fun classifySequence(
        sequenceNumber: Long,
        highestSeen: Long?,
        seenBefore: Boolean? = null,
        window: Long = REORDER_WINDOW,
    ): FrameVerdict {
        if (highestSeen == null) {
            return FrameVerdict(FrameOutcome.Accepted, null)
        }

        // Checked first, and deliberately. A seen number is a replay whatever its distance
        // from the head, so the window must not get the chance to excuse it.
        if (seenBefore == true) {
            return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.REPLAY_DETECTED)
        }

        if (sequenceNumber > highestSeen) {
            return FrameVerdict(FrameOutcome.Accepted, null)
        }

        val behind = highestSeen - sequenceNumber

        if (behind > window) {
            return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.REPLAY_DETECTED)
        }

        // A repeat of the head, with no seen-set supplied, is still a repeat: zero behind is
        // not reordering, because reordering means arriving later than a higher number.
        if (behind == 0L) {
            return FrameVerdict(FrameOutcome.ErrorFrameThenClose, ErrorCode.REPLAY_DETECTED)
        }

        // Within the window and strictly behind: legal reordering.
        return FrameVerdict(FrameOutcome.Accepted, null)
    }

    companion object {
        /**
         * How far behind the highest accepted number a frame may arrive and still be treated
         * as reordering.
         *
         * Sized for a LAN, where a reorder deeper than this means the frame is not late, it
         * is lost or forged. Making it larger buys nothing and costs a receiver the right to
         * discard state it can no longer justify holding.
         */
        const val REORDER_WINDOW: Long = 32

        /**
         * The capability value meaning "no capability gate".
         *
         * A string rather than null, because the registry spells an ungated message
         * `"any"` and the classifier has to read the registry as it is. Normalising it to
         * null here would hide a registry value this code does not understand behind one it
         * treats as ungated, which is the wrong direction: an unrecognised gate should
         * refuse, not admit.
         */
        const val ANY_CAPABILITY: String = "any"
    }
}

/**
 * The protocol registry the classifier consults, as a narrow interface.
 *
 * Narrow on purpose: the classifier needs four lookups and nothing else, so taking the whole
 * registry would let a future change give it access to state it has no business reading. The
 * implementation is the caller's, because the registry is data and where it is loaded from
 * is not this class's decision.
 */
interface Registry {
    /**
     * Finds a message type by its code.
     *
     * @param code the code.
     * @return the message type, or null when the code is not one this version knows.
     */
    fun findMessageType(code: Int): MessageTypeDefinition?

    /**
     * The capability a message type is gated on.
     *
     * @param code the code.
     * @return the capability name, `"any"`, or null when the message is ungated.
     */
    fun messageTypeCapability(code: Int): String?

    /** The largest number of data channels a session may have open at once. */
    val maxChannels: Int
}

/**
 * What the registry says about one message type.
 *
 * @property code the wire code.
 * @property name the registry name.
 * @property isHandshake whether this is part of the handshake rather than the session.
 * @property isEncrypted whether the message must be sent inside the encrypted stream.
 */
data class MessageTypeDefinition(
    val code: Int,
    val name: String,
    val isHandshake: Boolean,
    val isEncrypted: Boolean,
)

/**
 * The message type codes named by the protocol logic.
 *
 * Only the codes the codec itself has to name appear here. The rest are data: they live in
 * the registry and are looked up, so a new message type is a registry change and not a code
 * change.
 */
object MessageTypes {
    /** `HELLO`, the first frame of a session. */
    const val HELLO = 1

    /** `HELLO_ACK`, the agent's answer. */
    const val HELLO_ACK = 2

    /** `AUTH`, the first encrypted frame. */
    const val AUTH = 3

    /** `AUTH_OK`, the agent's confirmation. */
    const val AUTH_OK = 4
}
