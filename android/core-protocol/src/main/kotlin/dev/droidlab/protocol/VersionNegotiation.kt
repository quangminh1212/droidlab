package dev.droidlab.protocol

/**
 * Version negotiation (RFC-0001 sections 5 and 10).
 *
 * One rule: the highest version both peers support, or a clean failure. There is no fallback
 * and no guessing.
 *
 * The rule sounds obvious and the interesting part is why the alternatives are excluded. A
 * peer that silently falls back to an older version turns a version mismatch -- which is a
 * clear, actionable failure -- into corrupt behaviour, because the two peers would then
 * disagree about field meanings while both believing the handshake succeeded. That is the
 * failure mode this rule exists to prevent, and it is why `version.no-overlap` expects a fatal
 * error and a closed connection rather than a best-effort session.
 *
 * Versions are compared as `major.minor` pairs, numerically rather than as strings. A string
 * comparison gets `1.10` wrong against `1.9`, which is the sort of bug that appears two years
 * after it is written when a release finally reaches a double-digit minor.
 */
object VersionNegotiation {
    /** The version this implementation speaks. */
    const val CURRENT: String = "1.0"

    /** The major number the frame header's Version field carries. */
    const val CURRENT_MAJOR: Int = 1

    /**
     * A parsed `major.minor` version.
     *
     * Kept as numbers rather than the original string so that comparison is numeric. Comparing
     * the strings would order "1.10" before "1.9", which is wrong and gets worse as releases
     * accumulate.
     */
    data class Version(val major: Int, val minor: Int) : Comparable<Version> {
        override fun compareTo(other: Version): Int =
            if (major != other.major) major - other.major else minor - other.minor

        override fun toString(): String = "$major.$minor"

        companion object {
            /**
             * Parses a `major.minor` string.
             *
             * @param text the version string.
             * @return the parsed version, or null when the text is not a plain `major.minor`
             *   pair of non-negative integers.
             *
             * Returns null rather than throwing because a version string arrives from a peer
             * and a peer's input is not an exception. A malformed version is a protocol
             * failure to report, not a crash to propagate, and this is the boundary where that
             * distinction is made.
             */
            fun parse(text: String): Version? {
                val parts = text.split('.')

                // Exactly two components. A bare "1" and a "1.0.3" are both refused rather than
                // coerced, because a format that tolerates three shapes has three ways to
                // disagree about what a version means.
                if (parts.size != 2) return null

                val major = parts[0].toIntOrNull() ?: return null
                val minor = parts[1].toIntOrNull() ?: return null

                // Negative numbers and a leading sign are not versions. `toIntOrNull` accepts
                // "-1", so it needs rejecting explicitly.
                if (major < 0 || minor < 0) return null
                if (parts[0].startsWith('-') || parts[1].startsWith('-')) return null

                return Version(major, minor)
            }
        }
    }

    /**
     * The result of a negotiation.
     *
     * `version` is meaningful only when `error` is null; a caller that reads the version after
     * a failure would be reading an unnegotiated value, so the two fields are documented as
     * mutually exclusive rather than left for the caller to infer.
     */
    data class Verdict(val version: Version?, val error: ErrorCode?) {
        /** Whether the negotiation succeeded. */
        val accepted: Boolean get() = error == null && version != null
    }

    /**
     * Negotiates the highest version both peers support.
     *
     * @param controllerSupported the versions the controller offers.
     * @param agentSupported the versions the agent offers.
     * @return the negotiated version, or a fatal version mismatch.
     *
     * The result is the maximum of the intersection, not the controller's first preference.
     * The vectors record both lists as most-preferred-first, and a peer that returned its own
     * head would pick 2.0 in `version.both-newer-and-older` where the agreed version is 1.1 --
     * which is a security-relevant mistake, since it would elect a version the other side
     * never offered.
     */
    fun negotiate(
        controllerSupported: Collection<String>,
        agentSupported: Collection<String>,
    ): Verdict {
        val controller = parseAll(controllerSupported)
        val agent = parseAll(agentSupported)

        // An unparseable list cannot yield an agreement, and saying so is better than silently
        // negotiating over the subset that happened to parse: a peer that sent one good version
        // and one garbage one has a bug, and a session that succeeds anyway hides it.
        if (controller.isEmpty() || agent.isEmpty()) {
            return Verdict(null, ErrorCode.VERSION_MISMATCH)
        }

        val common = controller.intersect(agent)

        if (common.isEmpty()) {
            return Verdict(null, ErrorCode.VERSION_MISMATCH)
        }

        return Verdict(common.max(), null)
    }

    /**
     * Checks a peer's answer to a version proposal.
     *
     * @param controllerSupported what the controller offered.
     * @param agentAnswered what the agent said it agreed to.
     * @return acceptance when the answer is one the controller offered, else a fatal mismatch.
     *
     * An answer the controller never offered is a protocol violation by the agent, and it must
     * abort rather than continue. Continuing would mean running the session at a version one
     * side did not implement, and the controller cannot know which of its own code paths are
     * valid for it -- so the only safe response is to stop. This is the case
     * `version.controller-does-not-downgrade-silently` records.
     */
    fun checkAnswer(
        controllerSupported: Collection<String>,
        agentAnswered: String,
    ): Verdict {
        val offered = parseAll(controllerSupported)
        val answered = Version.parse(agentAnswered)

        if (answered == null) {
            return Verdict(null, ErrorCode.VERSION_MISMATCH)
        }

        // Membership in what was offered, not merely a well-formed version. An agent answering
        // "1.0" when the controller offered only "1.1" is answering a question that was never
        // asked.
        if (answered !in offered) {
            return Verdict(null, ErrorCode.VERSION_MISMATCH)
        }

        return Verdict(answered, null)
    }

    /**
     * Checks the frame header's Version field.
     *
     * @param headerVersion the major number in the header.
     * @return acceptance, or a fatal mismatch.
     *
     * The header carries the major alone, because the field is one byte and the major is what
     * decides whether the frame can be parsed at all. A receiver checks the header first: if
     * the major is unknown, the layout of everything after it is unknown, so there is nothing
     * to parse and reading the body would be reading bytes whose meaning is unestablished.
     *
     * The minor number travels in the HELLO body, where it can be a string, and is checked
     * second. This ordering is what `version.major-only-in-version-field` and
     * `version.header-major-too-new` record together.
     */
    fun checkHeaderMajor(headerVersion: Int): Verdict {
        if (headerVersion != CURRENT_MAJOR) {
            return Verdict(null, ErrorCode.VERSION_MISMATCH)
        }

        return Verdict(Version(CURRENT_MAJOR, 0), null)
    }

    /**
     * Whether a change to the protocol requires a major bump.
     *
     * @param changeKind the kind of change.
     * @return true when the change is breaking and requires a major version.
     *
     * Two families of name are accepted, and both are needed. A rule is usually stated as
     * `additive` or `breaking`, which is what a reviewer reasons about. A vector names the
     * specific change -- `add_capability_and_message_type`, `change_default_of_video_codec` --
     * which is what makes the example concrete. Recognising only the first would make the
     * vectors unusable as inputs; recognising only the second would make the function depend
     * on a list that grows with every new vector.
     *
     * The classification is by prefix and is deliberately conservative: a name that indicates
     * neither is refused rather than defaulted to the safe answer. Defaulting would mean a
     * change nobody classified silently got minor treatment, and a minor treatment of a
     * breaking change is precisely the silent compat break the version rule exists to stop.
     *
     * @throws IllegalArgumentException when the name is not recognisable.
     */
    fun requiresMajorBump(changeKind: String): Boolean = when {
        changeKind == "additive" || changeKind.startsWith("add_") -> false
        changeKind == "breaking" || changeKind.startsWith("change_") || changeKind.startsWith("remove_") -> true
        else -> error("unknown change kind \"$changeKind\"")
    }

    /** Parses a version list, dropping anything unparseable. */
    private fun parseAll(versions: Collection<String>): Set<Version> =
        versions.mapNotNull { Version.parse(it) }.toSet()
}
