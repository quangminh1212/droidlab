package dev.droidlab.protocol.crypto

/**
 * The replay window and the X25519 contributory check (RFC-0002 section 7).
 *
 * Two rules, both of which fail closed:
 *
 *  - **A sequence number is accepted at most once.** A repeat terminates the session rather
 *    than being dropped, because a repeat means either a broken peer or an attacker replaying,
 *    and neither is a condition to continue through.
 *  - **A shared secret that is all zero is refused.** X25519 returns zero for any low-order
 *    point, so a peer that sends one can force a known key. Deriving from it would give both
 *    sides the same key an attacker already knows, which is a complete break rather than a
 *    weakness.
 *
 * The window exists because UDP-like reordering is real: frames may arrive out of order, and a
 * receiver that required strict monotonicity would reject legitimate traffic. So there is a
 * window of 32, and the rules inside it are stated in terms of what has already been accepted
 * rather than in terms of arrival order.
 */
object ReplayProtection {
    /** The reordering window, as the vectors declare it. */
    const val WINDOW: Int = 32

    /**
     * Classifies an arriving sequence number.
     *
     * @param sequenceNumber the arriving sequence number.
     * @param highestAccepted the highest sequence number accepted so far, or null when nothing
     *   has been accepted. Nullable rather than defaulting to zero, because "nothing accepted
     *   yet" is genuinely not the number zero: with a zero default the first frame numbered 0
     *   would look like a repeat.
     * @param seenBefore the sequence numbers already accepted, used to tell a repeat from a
     *   reorder. A duplicate is not a reorder and the two must not be conflated: a reorder is
     *   31 behind and legitimate, a repeat is the same number twice and is an attack.
     * @param window the window size.
     * @return a verdict.
     *
     * The order of the checks is the whole content of this function:
     *
     *  1. A number already accepted is a replay, whatever the window says. This has to come
     *     first because the seen-set is what distinguishes a repeat from a reorder, and a
     *     window check alone cannot: a repeat of a number inside the window is inside the
     *     window, so it would be accepted a second time.
     *  2. A number more than `window` behind the highest accepted has fallen out of the window
     *     and can never be accepted, so it is a replay too. It is not held for later, because
     *     the window's purpose is to bound how much state a receiver keeps.
     *  3. Anything else is in the window or ahead of it, and is accepted.
     */
    fun classify(
        sequenceNumber: Long,
        highestAccepted: Long?,
        seenBefore: Set<Long>? = null,
        window: Int = WINDOW,
    ): SequenceVerdict {
        // 1. A repeat, checked before the window: a number inside the window that has already
        //    been accepted must not be accepted twice, and the window alone cannot tell the
        //    difference between that and a legitimate reorder.
        if (seenBefore != null && sequenceNumber in seenBefore) {
            return SequenceVerdict(accepted = false, replay = true)
        }

        if (highestAccepted == null) {
            // Nothing accepted yet, so there is no window to fall out of. The first frame sets
            // the high-water mark.
            return SequenceVerdict(accepted = true, replay = false)
        }

        // 2. Behind the window's trailing edge. Compared with the window plus one, because the
        //    window is inclusive of the slot `window` behind: with a high-water mark of 1000
        //    and a window of 32, 968 is the oldest acceptable number and 967 is out.
        val oldestAcceptable = highestAccepted - window

        if (sequenceNumber < oldestAcceptable) {
            return SequenceVerdict(accepted = false, replay = true)
        }

        // 3. In the window or ahead of it.
        return SequenceVerdict(accepted = true, replay = false)
    }

    /** Whether a sequence number may be accepted. */
    data class SequenceVerdict(val accepted: Boolean, val replay: Boolean)

    /**
     * Checks an X25519 shared secret for the all-zero result.
     *
     * @param sharedSecret the output of a key agreement.
     * @return true when the secret is usable.
     *
     * X25519 returns all zero for every low-order input point, so a peer choosing one of those
     * points can force a shared secret it already knows. Refusing the all-zero result is the
     * contributory-behaviour check: it requires that each side actually contributed to the
     * secret, and it is the reason a peer cannot dictate the session key.
     *
     * The check is on the *output* rather than on the input point. Rejecting a list of known
     * low-order points would work too, but the list is a finite and implementation-dependent
     * set, while the output condition is exactly the property that matters. Checking the
     * property is more robust than checking a list of things that have it.
     *
     * A constant-time comparison is not needed here, and that is worth saying because it looks
     * like an oversight. The value being compared against is a fixed public constant and the
     * input is a value the peer already knows it sent, so neither the timing nor the result
     * reveals anything a peer does not have. Constant-time comparison is applied where it
     * matters -- to tags and proofs, in [RecordProtection] and [PairingProofs].
     *
     * @param sharedSecret the output of a key agreement.
     * @return true when the secret is usable.
     */
    fun isUsableSharedSecret(sharedSecret: ByteArray): Boolean {
        if (sharedSecret.size != 32) return false

        // Folded rather than early-returned, so the function takes the same path for a secret
        // whose first byte is zero and one whose last byte is. Not a timing defence -- see
        // above -- but it means a reader cannot misread the short-circuit as one.
        var accumulator = 0

        for (byte in sharedSecret) {
            accumulator = accumulator or (byte.toInt() and 0xFF)
        }

        return accumulator != 0
    }
}
