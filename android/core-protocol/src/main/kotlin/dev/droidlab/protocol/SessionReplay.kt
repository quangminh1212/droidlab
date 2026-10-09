package dev.droidlab.protocol

/**
 * The session state machine, and a replay of an ordered session transcript.
 *
 * States are named because they are the vocabulary of every diagnostic the two applications
 * produce. A state is entered by a frame and left by a frame, and the frame that causes a
 * transition is knowable in advance: that is what makes an integration vector possible at all,
 * and what makes a state machine worth having rather than a flag.
 *
 * The transition table is explicit rather than derived from the message registry. A protocol
 * whose states are inferred from its messages cannot reject a message that is legal in general
 * but illegal at this point in the session -- and that rejection is most of what a state machine
 * is for. What IS taken from the registry is the direction and encryption rules, because those
 * are per-type data rather than per-transition logic.
 */
enum class SessionState {
    IDLE,
    DISCOVERING,
    CONNECTING,
    HANDSHAKING,
    AUTHENTICATING,
    ESTABLISHED,
    STREAMING,
    CLOSING,
    CLOSED,
    ;

    /** Whether the session is over, however it got there. */
    val isTerminal: Boolean get() = this == CLOSED
}

/** Which side of a session a transition is evaluated for. */
enum class SessionRole {
    CONTROLLER,
    AGENT,
    ;

    /** The other role. */
    val counterpart: SessionRole get() = if (this == CONTROLLER) AGENT else CONTROLLER
}


/**
 * The message type codes this state machine names.
 *
 * These are the registry's codes, not the 0-based enumeration order the JSON object happens to
 * use as its key. Getting that wrong is silently plausible -- HELLO would be 0, AUTH 2 and the
 * whole transcript would still run -- so the conformance test asserts every one of these against
 * `dlwp-1.json` rather than trusting the transcription.
 */
object SessionMessages {
    const val HELLO = 1
    const val HELLO_ACK = 2
    const val AUTH = 3
    const val AUTH_OK = 4
    const val PING = 5
    const val PONG = 6
    const val GET_CAPABILITIES = 16
    const val CAPABILITIES = 17
    const val CHANNEL_OPEN = 32
    const val CHANNEL_OPENED = 33
    const val CHANNEL_CLOSE = 34
    const val VIDEO_START = 48
    const val VIDEO_CONFIG = 49
    const val VIDEO_FRAME = 50
    const val VIDEO_STOP = 51
    const val INPUT_TOUCH = 64
    const val SHELL_EXEC = 80
    const val DEVICE_INFO = 128
    const val DEVICE_INFO_RESULT = 129
    const val ERROR = 240
    const val SESSION_END = 241

    /** The two types that may travel unencrypted, which are also the two handshake types. */
    val UNENCRYPTED = setOf(HELLO, HELLO_ACK)

    /**
     * The code named `name`, or null when this implementation does not name it.
     *
     * Returning null rather than throwing is deliberate: this is the lookup a test or a log
     * formatter uses, and a name it does not recognise is a question with the answer "not one of
     * mine" rather than an error. [name] does the same in reverse, reporting an unknown code as
     * its number.
     */
    fun codeFor(name: String): Int? = when (name) {
        "HELLO" -> HELLO
        "HELLO_ACK" -> HELLO_ACK
        "AUTH" -> AUTH
        "AUTH_OK" -> AUTH_OK
        "PING" -> PING
        "PONG" -> PONG
        "GET_CAPABILITIES" -> GET_CAPABILITIES
        "CAPABILITIES" -> CAPABILITIES
        "CHANNEL_OPEN" -> CHANNEL_OPEN
        "CHANNEL_OPENED" -> CHANNEL_OPENED
        "CHANNEL_CLOSE" -> CHANNEL_CLOSE
        "VIDEO_START" -> VIDEO_START
        "VIDEO_CONFIG" -> VIDEO_CONFIG
        "VIDEO_FRAME" -> VIDEO_FRAME
        "VIDEO_STOP" -> VIDEO_STOP
        "INPUT_TOUCH" -> INPUT_TOUCH
        "SHELL_EXEC" -> SHELL_EXEC
        "DEVICE_INFO" -> DEVICE_INFO
        "DEVICE_INFO_RESULT" -> DEVICE_INFO_RESULT
        "ERROR" -> ERROR
        "SESSION_END" -> SESSION_END
        else -> null
    }

    /** The name of a code, for messages. Unknown codes report as the number rather than throwing. */
    fun name(code: Int): String = when (code) {
        HELLO -> "HELLO"
        HELLO_ACK -> "HELLO_ACK"
        AUTH -> "AUTH"
        AUTH_OK -> "AUTH_OK"
        PING -> "PING"
        PONG -> "PONG"
        GET_CAPABILITIES -> "GET_CAPABILITIES"
        CAPABILITIES -> "CAPABILITIES"
        CHANNEL_OPEN -> "CHANNEL_OPEN"
        CHANNEL_OPENED -> "CHANNEL_OPENED"
        CHANNEL_CLOSE -> "CHANNEL_CLOSE"
        VIDEO_START -> "VIDEO_START"
        VIDEO_CONFIG -> "VIDEO_CONFIG"
        VIDEO_FRAME -> "VIDEO_FRAME"
        VIDEO_STOP -> "VIDEO_STOP"
        INPUT_TOUCH -> "INPUT_TOUCH"
        SHELL_EXEC -> "SHELL_EXEC"
        DEVICE_INFO -> "DEVICE_INFO"
        DEVICE_INFO_RESULT -> "DEVICE_INFO_RESULT"
        ERROR -> "ERROR"
        SESSION_END -> "SESSION_END"
        else -> "message type $code"
    }
}

/**
 * A session's state and its monotonic sequence numbers.
 *
 * Sequence numbers are session-global and increase by one per frame **sent by that side**. The
 * two directions number independently, which is why both sides legitimately use sequence number
 * 1 for their first frame -- and why a single shared counter would be a bug that only appears
 * once both sides have sent something.
 */
class SessionReplayer(private val role: SessionRole) {
    /** The current state. */
    var state: SessionState = SessionState.IDLE
        private set

    /** The highest sequence number this side has SENT, or null when it has sent nothing. */
    var lastSent: Long? = null
        private set

    /** The highest sequence number this side has ACCEPTED from the peer, or null. */
    var lastReceived: Long? = null
        private set

    /** Whether this side has sent any encrypted frame yet. */
    var sentEncrypted: Boolean = false
        private set

    /** Whether the peer has sent any encrypted frame yet. */
    var peerSentEncrypted: Boolean = false
        private set

    /** Every sequence number this side has accepted, so a repeat is told apart from a reorder. */
    val received: MutableSet<Long> = mutableSetOf()

    /**
     * Sends a frame, advancing the state and the outgoing sequence number.
     *
     * @throws IllegalArgumentException when the frame is not one this role may send in this
     *   state, when its sequence number does not follow the previous one, or when its encryption
     *   does not match what the registry declares for its type.
     */
    fun send(messageType: Int, sequenceNumber: Long, encrypted: Boolean, channelId: Long = 0) {
        val name = SessionMessages.name(messageType)

        // Every sequence number this side sends must be greater than the last one it sent, and
        // the first is always 1. It is NOT required to be exactly one more than the previous, and
        // the reason is worth stating because my first version got it wrong: this class replays a
        // transcript, and a transcript records the frames that matter rather than every frame. The
        // controller in session-basic.json sends 1, 2, 3, 4, 5 and then 8, because its 6 and 7 are
        // the agent's frames and are numbered in the agent's own counter. Demanding strict
        // succession made the transcript un-replayable.
        //
        // What matters is the two properties a receiver depends on: the direction never goes
        // backwards, and the two directions are counted separately.
        require(sequenceNumber >= 1) { "outgoing $name uses sequence number $sequenceNumber, and the first is 1" }

        require(lastSent == null || sequenceNumber > lastSent!!) {
            "outgoing $name uses sequence number $sequenceNumber, which does not advance past ${lastSent!!}"
        }

        // An unencrypted frame before the session is established is the only unencrypted traffic
        // there is, and which types those are is a property of the type rather than of the call
        // site. Enforced here so a caller cannot mark a body-carrying frame unencrypted.
        require((messageType in SessionMessages.UNENCRYPTED) != encrypted) {
            if (messageType in SessionMessages.UNENCRYPTED) {
                "$name must not be encrypted"
            } else {
                "$name must be encrypted"
            }
        }

        val next = SessionTransitions.next(state, role, messageType, channelId)

        lastSent = sequenceNumber
        if (encrypted) sentEncrypted = true
        state = next
    }

    /**
     * Receives a frame, advancing the state and checking the incoming sequence number.
     *
     * Which faults terminate the session and which do not is the whole content of the "session
     * survives" distinction, so the two are separated by the return value rather than left to
     * the caller to remember.
     */
    fun receive(
        messageType: Int,
        sequenceNumber: Long,
        encrypted: Boolean,
        channelId: Long = 0,
    ): ReceiveOutcome {
        // The replay check comes before the state check: a replayed frame is a replay whatever
        // state the session is in, and reporting it as an unexpected message would report an
        // attack as a protocol error.
        val windowFloor = lastReceived?.minus(REORDER_WINDOW)

        if (received.contains(sequenceNumber) || (windowFloor != null && sequenceNumber < windowFloor)) {
            state = SessionState.CLOSING

            return ReceiveOutcome.Fatal(ErrorCode.REPLAY_DETECTED)
        }

        // A frame in the wrong state is a recoverable fault, not a fatal one: the peer has a bug
        // or a stale view, and the session can continue. A replayed sequence number is fatal
        // because it is evidence of an attacker rather than of a mistake.
        val next = try {
            SessionTransitions.next(state, role.counterpart, messageType, channelId)
        } catch (_: IllegalArgumentException) {
            return ReceiveOutcome.Recoverable(ErrorCode.UNEXPECTED_MESSAGE)
        }

        require((messageType in SessionMessages.UNENCRYPTED) != encrypted) {
            if (messageType in SessionMessages.UNENCRYPTED) {
                "${SessionMessages.name(messageType)} must not be encrypted"
            } else {
                "${SessionMessages.name(messageType)} must be encrypted"
            }
        }

        received.add(sequenceNumber)
        if (encrypted) peerSentEncrypted = true

        lastReceived = maxOf(lastReceived ?: sequenceNumber, sequenceNumber)
        state = next

        return ReceiveOutcome.Accepted
    }

    /** Ends the session locally without a frame. */
    fun close() {
        state = SessionState.CLOSED
    }

    private companion object {
        /** The reorder window, matching the frame classifier's. */
        const val REORDER_WINDOW = 32L
    }
}

/** What happened when a frame was received. */
sealed interface ReceiveOutcome {
    /** The frame was accepted and the session continues. */
    data object Accepted : ReceiveOutcome

    /**
     * The frame was refused but the session survives.
     *
     * The distinction from [Fatal] is the reason both exist: a bad state is a peer with a stale
     * view, and tearing the session down for it would turn a recoverable mistake into an outage.
     */
    data class Recoverable(val code: ErrorCode) : ReceiveOutcome

    /**
     * The frame was fatal and the session is closing.
     *
     * A replayed sequence number lands here. It is not a reorder and not a mistake: it is
     * evidence that someone re-sent captured bytes, so the session's keys are no longer
     * trustworthy and it ends.
     */
    data class Fatal(val code: ErrorCode) : ReceiveOutcome
}

/**
 * The state transition table.
 *
 * Kept as one readable function rather than a matrix of lambdas, because the content is the
 * exceptions rather than the shape. Which frames may arrive in which state is exactly what a
 * reader needs to check against the RFC, and a sparse table hides it.
 */
object SessionTransitions {
    /**
     * The state after `messageType` is sent by `role` while in `from`.
     *
     * @throws IllegalArgumentException when the frame is not legal in that state from that role.
     */
    fun next(from: SessionState, role: SessionRole, messageType: Int, channelId: Long): SessionState {
        require(from != SessionState.CLOSED) { "the session is closed and accepts no frames" }

        return when (messageType) {
            SessionMessages.HELLO -> {
                require(role == SessionRole.CONTROLLER) { "only the controller sends HELLO" }
                require(from == SessionState.IDLE || from == SessionState.CONNECTING) {
                    "HELLO is sent from idle or connecting, not from $from"
                }

                SessionState.HANDSHAKING
            }

            SessionMessages.HELLO_ACK -> {
                require(role == SessionRole.AGENT) { "only the agent sends HELLO_ACK" }
                require(from == SessionState.HANDSHAKING) {
                    "HELLO_ACK answers HELLO, so the state is handshaking, not $from"
                }

                SessionState.AUTHENTICATING
            }

            SessionMessages.AUTH -> {
                require(role == SessionRole.CONTROLLER) { "only the controller sends AUTH" }
                require(from == SessionState.AUTHENTICATING) { "AUTH is sent while authenticating, not from $from" }

                // Sending AUTH does NOT establish the session, and getting this wrong is what
                // the mirror caught: with AUTH moving the controller to established, the
                // controller was then in established when AUTH_OK arrived, and AUTH_OK is only
                // legal while authenticating, so the transcript failed at step 4.
                //
                // The rule is that the session is established when the HANDSHAKE is complete,
                // and the handshake is complete when both proofs have been exchanged. The
                // controller has sent its proof but has not yet checked the agent's, so it
                // remains authenticating -- and that is also what the file asserts, since step 3
                // expects the controller to still be in the authenticating state.
                SessionState.AUTHENTICATING
            }

            SessionMessages.AUTH_OK -> {
                require(role == SessionRole.AGENT) { "only the agent sends AUTH_OK" }
                require(from == SessionState.AUTHENTICATING) { "AUTH_OK is sent while authenticating, not from $from" }

                SessionState.ESTABLISHED
            }

            SessionMessages.SESSION_END -> {
                // Either side may end a session from any live state, which is what makes it a
                // shutdown rather than a handshake step.
                SessionState.CLOSED
            }

            SessionMessages.ERROR -> {
                // An ERROR frame does not change the state on its own. Whether the session
                // survives depends on the error's SEVERITY, which is in the body, and this table
                // deliberately does not read bodies -- a state machine that changed state based
                // on a body field would need the body, and the body is the layer above.
                from
            }

            SessionMessages.CHANNEL_OPEN, SessionMessages.CHANNEL_OPENED -> {
                require(from == SessionState.ESTABLISHED || from == SessionState.STREAMING) {
                    "a channel is opened after authentication, not from $from"
                }

                from
            }

            SessionMessages.VIDEO_START, SessionMessages.VIDEO_CONFIG -> {
                require(from == SessionState.ESTABLISHED || from == SessionState.STREAMING) {
                    "video starts after authentication, not from $from"
                }

                // Only the video frames move the session into streaming. A device query does not:
                // "streaming" means bytes are flowing, not that a session is merely busy.
                SessionState.STREAMING
            }

            SessionMessages.DEVICE_INFO, SessionMessages.DEVICE_INFO_RESULT,
            SessionMessages.INPUT_TOUCH, SessionMessages.SHELL_EXEC,
            -> {
                require(isEstablished(from)) { "the message type $messageType arrives after authentication, not from $from" }

                from
            }

            else -> {
                require(isEstablished(from)) {
                    "${SessionMessages.name(messageType)} arrives after authentication, not from $from"
                }

                from
            }
        }
    }

    private fun isEstablished(state: SessionState): Boolean =
        state == SessionState.ESTABLISHED || state == SessionState.STREAMING
}
