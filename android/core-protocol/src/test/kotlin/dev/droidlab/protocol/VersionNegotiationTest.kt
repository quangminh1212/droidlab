package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Conformance tests for version negotiation, driven by `version-negotiation.json`.
 *
 * The rule is "highest common version or fail", and the vectors spend most of their length on
 * the failure half. That is the right emphasis: the success cases are all one shape, and the
 * cases that matter are the ones where a plausible implementation would silently continue --
 * falling back to an older version, or electing a version one side never offered.
 */
class VersionNegotiationTest {
    private companion object {
        const val VECTOR_FILE = "version-negotiation.json"
    }

    /** Every vector. */
    private fun vectors(): List<JsonValue> = Vectors.array(VECTOR_FILE, "vectors")

    /** The vectors that negotiate a list against a list. */
    private fun pairVectors(): List<JsonValue> =
        vectors().filter { it["controller_supported"] != null && it["agent_answered"] == null }

    /** A vector by id, failing if it is missing so a renamed vector cannot silently skip. */
    private fun vector(id: String): JsonValue =
        vectors().firstOrNull { it["id"]?.asString() == id }
            ?: error("version-negotiation.json has no vector \"$id\"")

    /** The strings a vector lists under a key. */
    private fun versions(v: JsonValue, key: String): List<String> =
        (v[key] ?: error("vector has no \"$key\"")).asArray().map { it.asString() }

    /**
     * The file's declared rule is the one the implementation applies.
     */
    @Test
    fun theRuleIsHighestCommonVersionOrFail() {
        val file = Vectors.load(VECTOR_FILE)

        assertEquals(
            "highest_common_version_or_fail",
            file["rule"]!!.asString(),
            "the file declares the rule the implementation applies",
        )

        // And the negotiated version is never a value outside both lists, which is what
        // "common" means. Checked over every pair vector rather than only the no-overlap ones.
        for (v in pairVectors()) {
            val negotiated = VersionNegotiation.negotiate(
                versions(v, "controller_supported"),
                versions(v, "agent_supported"),
            )

            val declared = v["expected_negotiated"]

            if (declared == null || declared is JsonValue.Nul) {
                assertFalse(negotiated.accepted, "${v["id"]!!.asString()} is declared a failure")
                continue
            }

            val agreed = negotiated.version?.toString()

            assertTrue(
                versions(v, "controller_supported").contains(agreed),
                "${v["id"]!!.asString()} negotiated a version the controller did not offer",
            )

            assertTrue(
                versions(v, "agent_supported").contains(agreed),
                "${v["id"]!!.asString()} negotiated a version the agent did not offer",
            )
        }
    }

    /**
     * Every pair vector negotiates its declared version.
     */
    @Test
    fun everyPairVectorNegotiatesItsDeclaredVersion() {
        assertTrue(pairVectors().size >= 7, "expected at least 7 pair vectors")

        for (v in pairVectors()) {
            val id = v["id"]!!.asString()

            val negotiated = VersionNegotiation.negotiate(
                versions(v, "controller_supported"),
                versions(v, "agent_supported"),
            )

            val declaredVersion = v["expected_negotiated"]
            val declaredError = v["expected_error"]

            if (declaredError != null && declaredError !is JsonValue.Nul) {
                assertFalse(negotiated.accepted, "$id is declared a failure")

                assertEquals(
                    declaredError.asString(),
                    negotiated.error?.name,
                    "$id error code",
                )

                assertNull(negotiated.version, "$id carries no version when it fails")
            } else {
                assertTrue(negotiated.accepted, "$id is declared a success")

                assertEquals(
                    declaredVersion!!.asString(),
                    negotiated.version?.toString(),
                    "$id negotiated version",
                )

                assertNull(negotiated.error, "$id carries no error when it succeeds")
            }
        }
    }

    /**
     * The agreed version is the highest common one, not the controller's first preference.
     */
    @Test
    fun theHighestCommonVersionWinsNotTheFirstPreference() {
        val v = vector("version.both-newer-and-older")

        val controller = versions(v, "controller_supported")
        val agent = versions(v, "agent_supported")

        // The scenario is only interesting if the lists are ordered most-preferred-first and
        // the first preferences differ, so the test would be checking something real.
        assertEquals("2.0", controller.first(), "the controller's first preference is the newer 2.0")
        assertEquals("1.1", agent.first(), "the agent's first preference is 1.1")
        assertTrue(controller.first() != agent.first(), "the two first preferences differ")

        val negotiated = VersionNegotiation.negotiate(controller, agent)

        assertEquals("1.1", negotiated.version?.toString(), "the highest common version is 1.1")

        // Explicitly not the controller's head. An implementation that returned its own first
        // preference would elect 2.0, a version the agent never offered -- which is the
        // security-relevant half of this rule, not merely a preference mismatch.
        assertTrue(
            negotiated.version?.toString() != controller.first(),
            "the result is not the controller's first preference",
        )

        assertEquals(v["expected_negotiated"]!!.asString(), negotiated.version?.toString())
    }

    /**
     * Versions compare numerically, so a double-digit minor sorts above a single-digit one.
     */
    @Test
    fun versionsCompareNumericallyNotLexically() {
        // The bug this pins: string comparison orders "1.10" before "1.9", because '1' < '9'.
        assertTrue(
            VersionNegotiation.Version.parse("1.10")!! > VersionNegotiation.Version.parse("1.9")!!,
            "1.10 is greater than 1.9 numerically",
        )

        // And it changes a real negotiation result: with both offered, 1.10 must win.
        val negotiated = VersionNegotiation.negotiate(
            listOf("1.9", "1.10"),
            listOf("1.9", "1.10"),
        )

        assertEquals("1.10", negotiated.version?.toString(), "1.10 is preferred over 1.9")

        // The major still dominates the minor.
        assertTrue(
            VersionNegotiation.Version.parse("2.0")!! > VersionNegotiation.Version.parse("1.99")!!,
            "a higher major beats any minor",
        )
    }

    /**
     * A malformed version is refused rather than coerced.
     */
    @Test
    fun aMalformedVersionIsRefused() {
        // A format that tolerates several shapes has several ways to disagree about meaning,
        // so only a plain major.minor pair is accepted.
        for (text in listOf("1", "1.0.0", "1.", ".1", "one.zero", "", "-1.0", "1.-0", "1 .0")) {
            assertNull(
                VersionNegotiation.Version.parse(text),
                "\"$text\" is not a version",
            )
        }

        // And a list where nothing parses yields a mismatch rather than an empty agreement.
        val negotiated = VersionNegotiation.negotiate(listOf("garbage"), listOf("1.0"))

        assertFalse(negotiated.accepted, "a list with no parseable version cannot agree")
        assertEquals(ErrorCode.VERSION_MISMATCH, negotiated.error)
    }

    /**
     * Neither side downgrades silently.
     */
    @Test
    fun neitherSideDowngradesSilently() {
        // The agent is asked for a version it does not know and must refuse, rather than
        // assuming the controller meant 1.0.
        val agentRefuses = vector("version.agent-does-not-downgrade-silently")

        val agentVerdict = VersionNegotiation.negotiate(
            versions(agentRefuses, "controller_supported"),
            versions(agentRefuses, "agent_supported"),
        )

        assertFalse(agentVerdict.accepted, "the agent refuses a version it does not know")
        assertEquals(ErrorCode.VERSION_MISMATCH, agentVerdict.error)

        // The controller is answered with a version it never offered and must abort.
        val controllerRefuses = vector("version.controller-does-not-downgrade-silently")

        val controllerVerdict = VersionNegotiation.checkAnswer(
            versions(controllerRefuses, "controller_supported"),
            controllerRefuses["agent_answered"]!!.asString(),
        )

        assertFalse(controllerVerdict.accepted, "the controller refuses an unoffered answer")
        assertEquals(ErrorCode.VERSION_MISMATCH, controllerVerdict.error)

        // The answer is well-formed, which is the point: it is refused for being unoffered,
        // not for being unparseable. A check that only validated the format would accept it.
        assertTrue(
            VersionNegotiation.Version.parse(controllerRefuses["agent_answered"]!!.asString()) != null,
            "the rejected answer is a well-formed version, so the rejection is about membership",
        )

        // And an answer the controller did offer is accepted, which brackets the rule.
        val accepted = VersionNegotiation.checkAnswer(listOf("1.1", "1.0"), "1.0")

        assertTrue(accepted.accepted, "an offered answer is accepted")
        assertEquals("1.0", accepted.version?.toString())
    }

    /**
     * A mismatch is fatal, not recoverable.
     */
    @Test
    fun aVersionMismatchIsFatal() {
        for (v in vectors()) {
            val error = v["expected_error"] ?: continue

            if (error is JsonValue.Nul) continue

            assertEquals("ERR_VERSION_MISMATCH", error.asString(), "${v["id"]!!.asString()} uses the version error")

            // Fatal, because the header's version field is what decides how everything after
            // it is parsed. There is no partial recovery: a receiver that does not know the
            // version does not know the frame's shape.
            assertEquals(
                "fatal",
                v["expected_severity"]!!.asString(),
                "${v["id"]!!.asString()} is declared fatal",
            )
        }
    }

    /**
     * The header's major is checked before the body's full string.
     */
    @Test
    fun theHeaderMajorIsCheckedBeforeTheBodyString() {
        val v = vector("version.major-only-in-version-field")

        // The header carries the major alone, which is 1 for every 1.x release, while the
        // minor travels in the HELLO body where it can be a string.
        assertEquals(1, v["header_version_field"]!!.asInt(), "the header carries the major only")
        assertEquals("1.1", v["hello_proto_string"]!!.asString(), "the body carries the full version")
        assertEquals("accepted", v["expected"]!!.asString(), "a known major with a newer minor is accepted")

        // The ordering is the substance: a frame whose major is unknown cannot be parsed, so
        // the header check has to come first and stand alone.
        assertTrue(
            VersionNegotiation.checkHeaderMajor(v["header_version_field"]!!.asInt()).accepted,
            "the known major passes the header check",
        )

        // The header field is the major, so 1 is all a 1.x frame can say. The MINOR is what
        // the body carries, and this vector's 1.1 does NOT negotiate against a peer that knows
        // only 1.0: the rule is highest COMMON version, and 1.0 and 1.1 share none.
        //
        // That is the honest reading, and worth stating because "a minor bump is compatible"
        // is a tempting gloss the rule does not implement. Compatibility of a minor bump is a
        // property of the change (below), not of the negotiation: what makes an additive
        // change safe is that an old peer ignores what it does not know, while the version
        // lists are the versions a peer can SPEAK -- not a range it tolerates.
        val negotiated = VersionNegotiation.negotiate(
            listOf("1.0"),
            listOf(v["hello_proto_string"]!!.asString()),
        )

        assertFalse(
            negotiated.accepted,
            "1.0 and 1.1 share no version, so the negotiation fails",
        )

        assertEquals(ErrorCode.VERSION_MISMATCH, negotiated.error, "and it fails as a version mismatch")

        // A peer that knows both agrees the HIGHEST common one, which is 1.1 -- not 1.0, even
        // though 1.0 is also common. Taking the lower common version would be a silent
        // downgrade, which is exactly the behaviour the rule exists to prevent.
        val common = VersionNegotiation.negotiate(
            listOf("1.1", "1.0"),
            listOf(v["hello_proto_string"]!!.asString()),
        )

        assertEquals("1.1", common.version?.toString(), "the highest common version wins")

        // A too-new major is fatal and is refused without reading the body.
        val tooNew = vector("version.header-major-too-new")

        val refused = VersionNegotiation.checkHeaderMajor(tooNew["header_version_field"]!!.asInt())

        assertFalse(refused.accepted, "an unknown major fails")
        assertEquals(ErrorCode.VERSION_MISMATCH, refused.error)
        assertNull(refused.version, "no version is negotiated when the header is refused")

        // And the known major passes, so the check is discriminating rather than refusing all.
        assertTrue(VersionNegotiation.checkHeaderMajor(1).accepted, "the known major is accepted")
    }

    /**
     * An additive change is a minor bump and a breaking one a major.
     */
    @Test
    fun anAdditiveChangeIsNotAMajorBump() {
        val additive = vector("version.additive-change-is-not-a-major-bump")

        // The kinds are descriptive names, not the literals "additive" and "breaking". What
        // makes a change additive or breaking is the DECLARED bump, which is the field the
        // rule actually reads -- so the test asserts that field rather than the name.
        assertFalse(
            additive["expected_version_bump"]!!.asBoolean(),
            "an additive change does not bump the version",
        )

        assertTrue(
            VersionNegotiation.requiresMajorBump("additive").not(),
            "an additive change is a minor bump",
        )

        val breaking = vector("version.breaking-change-requires-major-bump")

        assertTrue(
            breaking["expected_version_bump"]!!.asBoolean(),
            "a breaking change bumps the version",
        )

        assertTrue(
            VersionNegotiation.requiresMajorBump("breaking"),
            "a breaking change requires a major bump",
        )

        // The two vectors must describe different kinds, or the pair tests nothing.
        assertTrue(
            additive["change_kind"]!!.asString() != breaking["change_kind"]!!.asString(),
            "the two change kinds differ",
        )

        // An old peer must keep working by ignoring what it does not know, which is the same
        // forward-compatibility rule the malformed and capability surfaces pin elsewhere --
        // stated here as the reason a minor bump is safe.
        assertTrue(
            additive["old_peer_behaviour"]!!.asString().contains("ignore_unknown_key"),
            "the additive change relies on an old peer ignoring unknown keys",
        )

        // A breaking change names the documents it must touch, which is the process half of
        // the rule: a wire change that leaves the RFC and the vectors alone is unpinned drift.
        val documents = breaking["required_documents"]!!.asArray().map { it.asString() }

        assertTrue(documents.isNotEmpty(), "a breaking change names its documents")

        assertTrue(
            documents.any { it.startsWith("docs/rfc/") },
            "a breaking change touches the RFC",
        )

        assertTrue(
            documents.any { it.startsWith("protocol/vectors/") },
            "a breaking change touches the vectors, or the change is unpinned",
        )
    }

    /**
     * The version list is ordered most-preferred-first on both sides.
     */
    @Test
    fun theListsAreOrderedMostPreferredFirst() {
        // The ordering is declared in the file rather than inferred, because the negotiation
        // result depends on it being the ordering and not an accident of how a set iterates.
        val v = vector("version.both-newer-and-older")

        val controller = versions(v, "controller_supported").map { VersionNegotiation.Version.parse(it)!! }
        val agent = versions(v, "agent_supported").map { VersionNegotiation.Version.parse(it)!! }

        for ((name, list) in listOf("controller" to controller, "agent" to agent)) {
            assertEquals(
                list.sortedDescending(),
                list,
                "the $name's list is most-preferred-first",
            )
        }
    }
}
