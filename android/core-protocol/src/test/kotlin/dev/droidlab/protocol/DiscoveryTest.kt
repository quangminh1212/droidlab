package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Conformance tests for the discovery advertisement, driven by `discovery.json`.
 *
 * The advertisement is signed, so the canonical byte string is part of the wire format rather
 * than a display concern. Most of what follows compares the built bytes against the vector's own
 * `canonical_utf8` character for character, because that is the only comparison that catches the
 * mistakes worth catching: a trailing newline, a reordered key, a forgotten NUL.
 */
class DiscoveryTest {
    private companion object {
        const val VECTOR_FILE = "discovery.json"
    }

    /** A discovery vector by id, failing when it is missing so a rename cannot silently skip. */
    private fun vector(id: String): JsonValue =
        Vectors.array(VECTOR_FILE, "vectors").firstOrNull { it["id"]?.asString() == id }
            ?: error("discovery.json has no vector \"$id\"")

    /** A rejection vector by id. */
    private fun rejection(id: String): JsonValue =
        Vectors.array(VECTOR_FILE, "rejection_vectors").firstOrNull { it["id"]?.asString() == id }
            ?: error("discovery.json has no rejection vector \"$id\"")

    /** A lifecycle vector by id. */
    private fun lifecycle(id: String): JsonValue =
        Vectors.array(VECTOR_FILE, "lifecycle_vectors").firstOrNull { it["id"]?.asString() == id }
            ?: error("discovery.json has no lifecycle vector \"$id\"")

    /** A vector's `fields` object as plain strings. */
    private fun fields(v: JsonValue): Map<String, String> =
        buildMap {
            for ((key, value) in v["fields"]!!.asObject()) {
                when (value) {
                    is JsonValue.Str -> put(key, value.asString())
                    is JsonValue.Num -> put(key, value.asString())
                    else -> throw AssertionError("field \"$key\" is neither a string nor a number")
                }
            }
        }

    /** Builds a vector's canonical bytes and asserts they match the vector's own text. */
    private fun assertCanonical(v: JsonValue) {
        val id = v["id"]!!.asString()

        val built = DiscoveryAdvertisement.canonicalTxt(fields(v)).toString(Charsets.UTF_8)
        val declared = v["canonical_utf8"]!!.asString()

        assertEquals(declared, built, "$id produces its declared canonical bytes")

        // And the declared length is the byte length of those bytes, counted rather than taken
        // from the file, because a length that agrees with a wrong string proves nothing.
        val declaredLength = v["canonical_length_bytes"]!!.asInt()

        assertEquals(
            declaredLength,
            built.toByteArray(Charsets.UTF_8).size,
            "$id declared length matches its bytes",
        )
    }

    /** Every service constant the file declares. */
    private fun assertServiceConstants() {
        val service = Vectors.load(VECTOR_FILE)["service"]!!

        assertEquals(
            DiscoveryAdvertisement.SERVICE_TYPE,
            service["type"]!!.asString(),
            "the service type matches",
        )
        assertEquals(DiscoveryAdvertisement.DOMAIN, service["domain"]!!.asString(), "the domain matches")
        assertEquals(
            DiscoveryAdvertisement.DEFAULT_PORT,
            service["default_port"]!!.asInt(),
            "the default port matches",
        )
        assertEquals(
            DiscoveryAdvertisement.BEACON_PORT,
            service["beacon_port"]!!.asInt(),
            "the beacon port matches",
        )
        assertEquals(
            DiscoveryAdvertisement.TTL_SECONDS,
            service["ttl_seconds"]!!.asInt(),
            "the TTL matches",
        )
        assertEquals(
            DiscoveryAdvertisement.MAX_TXT_BYTES,
            service["max_txt_bytes"]!!.asInt(),
            "the size budget matches",
        )
    }

    /**
     * The service constants are the ones this implementation uses.
     */
    @Test
    fun theServiceConstantsAreTheOnesUsed() {
        assertServiceConstants()

        // The beacon is one above the service port, and never the service port itself: a beacon
        // delivered to the service port would be parsed as a connection attempt.
        assertFalse(
            DiscoveryAdvertisement.BEACON_PORT == DiscoveryAdvertisement.DEFAULT_PORT,
            "the beacon port is not the service port",
        )

        assertEquals(
            DiscoveryAdvertisement.DEFAULT_PORT + 1,
            DiscoveryAdvertisement.BEACON_PORT,
            "the beacon port is the next one up",
        )

        // The budget is the mDNS delivery limit, not a figure chosen for comfort: a larger
        // record set cannot be delivered reliably in one response, so an agent must not build it.
        assertEquals(
            DiscoveryAdvertisement.MAX_TXT_BYTES,
            1300,
            "the budget is the mDNS limit",
        )
    }

    /**
     * The canonicalisation rule is the fixed-order one.
     */
    @Test
    fun theCanonicalisationIsFixedOrder() {
        val txt = Vectors.load(VECTOR_FILE)["txt_canonicalisation"]!!

        val rule = txt["rule"]!!.asString()

        // Three properties the rule states, each of which the builder has to get right.
        assertTrue(rule.contains("exactly this order"), "the key order is fixed")
        assertTrue(rule.contains("separated by 0x0A"), "the separator is a newline")
        assertTrue(rule.contains("with the label and a NUL first"), "the label and a NUL come first")
        assertTrue(rule.contains("No trailing newline"), "there is no trailing newline")

        // The form: the label, a NUL, then the five keys joined by newlines.
        val form = txt["form"]!!.asString()

        assertEquals(
            "\"DLWP/1-txt\" || 0x00 || \"v=\" || v || 0x0A || \"id=\" || id || 0x0A || \"fp=\" || fp || " +
                "0x0A || \"caps=\" || caps || 0x0A || \"port=\" || port",
            form,
            "the declared form matches",
        )

        // The order is deliberately not alphabetical, and the file says why. Worth asserting,
        // because a reader who assumed a sort would produce a different signature and this is
        // the only place the reason is written down.
        val note = txt["note"]!!.asString()

        assertTrue(note.contains("fixed rather than alphabetical"), "the order is fixed, not sorted")
        assertFalse(
            DiscoveryAdvertisement.REQUIRED_KEYS.sorted() == DiscoveryAdvertisement.REQUIRED_KEYS,
            "the fixed order differs from the sorted order, so the distinction is real",
        )

        // The optional keys have their own declared order.
        val declaredExtra = txt["extra_key_order"]!!.asArray().map { it.asString() }

        assertEquals(
            DiscoveryAdvertisement.OPTIONAL_KEYS,
            declaredExtra,
            "the optional key order matches",
        )
    }

    /**
     * Every advertisement vector builds to its declared bytes.
     */
    @Test
    fun everyAdvertisementBuildsToItsDeclaredBytes() {
        val vectors = Vectors.array(VECTOR_FILE, "vectors")

        assertTrue(vectors.size >= 4, "expected at least 4 advertisement vectors")

        // The minimal and full records, then the beacon.
        for (id in listOf("discovery.txt.minimal", "discovery.txt.full")) {
            assertCanonical(vector(id))
        }
    }

    /**
     * The full record is 87 bytes longer than the minimal one.
     */
    @Test
    fun theOptionalKeysAddTheDeclaredBytes() {
        val minimal = vector("discovery.txt.minimal")
        val full = vector("discovery.txt.full")

        val minimalBytes = DiscoveryAdvertisement.canonicalTxt(fields(minimal))
        val fullBytes = DiscoveryAdvertisement.canonicalTxt(fields(full))

        // The file says 87, measured rather than estimated, and the note is worth checking
        // because it is the sort of figure that goes stale when a key is added.
        assertEquals(
            fullBytes.size - minimalBytes.size,
            87,
            "the optional keys add 87 bytes",
        )

        // And both records place their required keys in the same fixed order, which is what the
        // ordering rule is actually about.
        //
        // NOT asserted as "the full record is the minimal record with fields appended": the two
        // vectors describe different devices, so their id, fingerprint and capability VALUES
        // differ too. My first version of this check claimed the prefix relation and failed,
        // which is the useful outcome -- the claim was wrong, not the implementation.
        fun keyOrder(text: String): List<String> =
            text.split("\n").mapIndexed { index, line ->
                (if (index == 0) line.substringAfter('\u0000') else line).substringBefore('=')
            }

        val minimalKeys = keyOrder(minimalText)

        assertTrue(
            keyOrder(fullText).take(5) == minimalKeys.take(5),
            "both records order their required keys the same way",
        )

        assertEquals(
            DiscoveryAdvertisement.REQUIRED_KEYS,
            keyOrder(fullText).take(5),
            "the required keys are in the fixed order",
        )

        // The extra keys appear in the declared order, not alphabetically.
        val fullText = fullBytes.toString(Charsets.UTF_8)
        val positions = DiscoveryAdvertisement.OPTIONAL_KEYS.map { fullText.indexOf("\n$it=") }

        for (position in positions) {
            assertTrue(position > 0, "every optional key is present")
        }

        assertEquals(
            positions.sorted(),
            positions,
            "the optional keys appear in the declared order",
        )
    }

    /**
     * A record carries no trailing newline and no stray separator.
     */
    @Test
    fun aRecordHasNoTrailingNewline() {
        val built = DiscoveryAdvertisement.canonicalTxt(fields(vector("discovery.txt.minimal")))
        val text = built.toString(Charsets.UTF_8)

        // The mistake this guards: appending the separator after every field rather than
        // between fields. The result is one byte longer, looks identical in a terminal, and
        // signs differently.
        assertFalse(text.endsWith("\n"), "the record does not end with a newline")
        assertFalse(text.endsWith("\u0000"), "the record does not end with a NUL")

        // Exactly five separators for six parts: the label and NUL, then five keys.
        assertEquals(
            DiscoveryAdvertisement.REQUIRED_KEYS.size - 1,
            text.count { it == '\n' },
            "there is one separator between each pair of fields and none after the last",
        )

        // The label and its NUL are the first thing in the record.
        assertTrue(
            text.startsWith("${DiscoveryAdvertisement.TXT_LABEL}\u0000"),
            "the record opens with the label and a NUL",
        )

        // And the separator is only ever a newline, never a NUL: an extra NUL would terminate
        // the string for a C consumer and truncate the record silently.
        assertEquals(1, text.count { it == '\u0000' }, "there is exactly one NUL, after the label")
    }

    /**
     * A key the specification does not define is not appended.
     */
    @Test
    fun anUnknownKeyIsNotSigned() {
        val base = fields(vector("discovery.txt.minimal"))

        val withExtra = DiscoveryAdvertisement.canonicalTxt(base + ("surprise" to "payload"))

        assertEquals(
            DiscoveryAdvertisement.canonicalTxt(base).toList(),
            withExtra.toList(),
            "an undefined key does not change the signed bytes",
        )

        // Which matters because the record is signed: letting an arbitrary key into the
        // canonical form would let a third party extend what the agent's signature covers.
        assertFalse(
            withExtra.toString(Charsets.UTF_8).contains("surprise"),
            "the undefined key does not appear",
        )
    }

    /**
     * A missing required key is refused rather than written empty.
     */
    @Test
    fun aMissingRequiredKeyIsRefused() {
        for (key in DiscoveryAdvertisement.REQUIRED_KEYS) {
            val incomplete = fields(vector("discovery.txt.minimal")) - key

            val result = runCatching { DiscoveryAdvertisement.canonicalTxt(incomplete) }

            assertTrue(result.isFailure, "omitting the required key \"$key\" is refused")
            assertTrue(
                result.exceptionOrNull()?.message?.contains(key) == true,
                "the refusal names the missing key \"$key\"",
            )
        }

        // A missing OPTIONAL key is not refused: its absence is the normal case, and the record
        // simply does not carry it.
        val withoutOptional = DiscoveryAdvertisement.canonicalTxt(
            fields(vector("discovery.txt.full")) - "model",
        )

        assertFalse(
            withoutOptional.toString(Charsets.UTF_8).contains("model="),
            "a missing optional key is simply absent",
        )
    }

    /**
     * A value containing a newline is refused.
     */
    @Test
    fun aNewlineInAValueIsRefused() {
        val base = fields(vector("discovery.txt.minimal"))

        // A value with a newline would let one field forge the appearance of another, and the
        // record is signed, so the injected key would be signed too.
        val result = runCatching { DiscoveryAdvertisement.canonicalTxt(base + ("model" to "Pixel\nid=evil")) }

        assertTrue(result.isFailure, "a newline inside a value is refused")
        assertTrue(
            result.exceptionOrNull()?.message?.contains("model") == true,
            "the refusal names the offending key",
        )
    }

    /**
     * The beacon's canonicalisation is ascending, not fixed order.
     */
    @Test
    fun theBeaconIsCanonicalisedInAscendingOrder() {
        val v = vector("discovery.beacon.canonical")

        val beaconFields = v["fields"]!!.asObject()

        val built = DiscoveryAdvertisement.canonicalBeacon(
            buildMap {
                for ((key, value) in beaconFields) {
                    put(
                        key,
                        when (value) {
                            is JsonValue.Str -> value.asString()
                            is JsonValue.Num -> if (value.integral) value.asLong() else value.asString().toDouble()
                            else -> throw AssertionError("the beacon field \"$key\" is neither a string nor a number")
                        },
                    )
                }
            },
        )

        val declared = v["canonical_utf8"]!!.asString()

        assertEquals(declared, built.toString(Charsets.UTF_8), "the beacon builds to its declared bytes")
        assertEquals(
            v["canonical_length_bytes"]!!.asInt(),
            built.size,
            "the beacon's declared length matches its bytes",
        )

        // Ascending key order, which differs from the TXT rule on purpose -- the beacon carries
        // a JSON object, so it needs its own deterministic rule rather than a second
        // hand-written list to keep in step.
        assertEquals(
            "busy=0\nfp=9F3C-1A08-B7E2-44D1\nid=11111111-2222-4333-8444-555555555555\n" +
                "name=Pixel 7 - bench 3\nport=45917\nv=1.0",
            declared,
            "the beacon's fields are in ascending key order",
        )

        val keys = declared.split("\n").map { it.substringBefore('=') }

        assertEquals(keys.sorted(), keys, "the beacon keys are ascending")

        // The vector's own `fields` happen to already be in ascending order, so building them
        // proves nothing about the sort. A map inserted in a DIFFERENT order is what makes the
        // rule testable, and without it deleting the sort passes every check above.
        //
        // This is not hypothetical: mutation-testing found exactly that, because the fields in
        // the vector file are written in an order that is already sorted.
        val insertedOutOfOrder = linkedMapOf<String, Any>(
            "v" to "1.0",
            "port" to 45917,
            "name" to "Pixel 7 - bench 3",
            "id" to "i",
            "fp" to "f",
            "busy" to 0,
        )

        assertEquals(
            "busy=0\nfp=f\nid=i\nname=Pixel 7 - bench 3\nport=45917\nv=1.0",
            DiscoveryAdvertisement.canonicalBeacon(insertedOutOfOrder).toString(Charsets.UTF_8),
            "a beacon inserted out of order is still built in ascending order",
        )

        // And a number field is written without a decimal point or quotes: `busy=0`, not
        // `busy=0.0` and not `busy="0"`.
        assertTrue(declared.contains("busy=0\n") || declared.startsWith("busy=0\n"), "an integer field is bare")
        assertTrue(declared.contains("port=45917"), "a port is written as an integer")
        assertFalse(declared.contains("\""), "the beacon carries no quoting")
    }

    /**
     * A rejected advertisement never leads to a connection.
     */
    @Test
    fun aBadSignatureIsIgnoredNotConnected() {
        val v = rejection("discovery.reject.signature-mismatch-paired-device")

        assertEquals(false, v["signature_valid"]!!.asBoolean(), "the vector's signature is invalid")
        assertEquals("ignore_advertisement", v["expected"]!!.asString(), "the advertisement is ignored")
        assertEquals("Unverified", v["expected_ui_state"]!!.asString(), "the device is shown as unverified")

        // And the device is NOT removed from the list. This is the part worth asserting: an
        // attacker who jams the real agent and advertises in its place could otherwise clear the
        // device from the UI, which is a denial of service dressed up as a safety measure.
        assertEquals(
            "11111111-2222-4333-8444-555555555555",
            v["controller_has_pairing_for_id"]!!.asString(),
            "the controller holds a pairing record",
        )

        val action = v["note_on_action"]!!.asString()

        assertTrue(action.contains("must not connect"), "the controller must not connect")
        assertTrue(action.contains("must also not quietly remove the device"), "the device is not removed")
    }

    /**
     * A changed fingerprint for a known id is refused.
     */
    @Test
    fun aChangedFingerprintIsRefused() {
        val v = rejection("discovery.reject.fingerprint-changed-for-known-id")

        val known = v["known_fingerprint"]!!.asString()
        val advertised = v["advertised_fingerprint"]!!.asString()

        assertEquals("11111111-2222-4333-8444-555555555555", v["known_id"]!!.asString(), "the id matches a record")

        // The id is the same and the fingerprint is not. Worth asserting the difference, because
        // the whole vector is inert if the two fingerprints happen to be equal.
        assertFalse(known == advertised, "the fingerprint really did change")

        assertEquals(
            "refuse_automatic_connect",
            v["expected"]!!.asString(),
            "an automatic connect is refused",
        )
        assertTrue(
            v["expected_warning"]!!.asString().contains("possible impersonation"),
            "the warning names impersonation as the possibility",
        )

        // The warning says "possible", not "certain": a reinstalled agent with a new identity
        // key produces the same signal, and the operator decides.
        assertFalse(
            v["expected_warning"]!!.asString().contains("confirmed"),
            "the warning does not claim certainty",
        )
    }

    /**
     * The remaining rejections are the declared ones.
     */
    @Test
    fun theOtherRejectionsAreAsDeclared() {
        // Port zero means "pick one", which is not an address to connect to.
        val port = rejection("discovery.reject.port-out-of-range")

        assertEquals(0, port["advertised_port"]!!.asInt(), "the vector's port is zero")
        assertFalse(DiscoveryAdvertisement.isUsablePort(0), "port zero is not usable")
        assertTrue(DiscoveryAdvertisement.isUsablePort(1), "port one is usable")
        assertTrue(DiscoveryAdvertisement.isUsablePort(65535), "port 65535 is usable")
        assertFalse(DiscoveryAdvertisement.isUsablePort(65536), "port 65536 is not usable")
        assertFalse(DiscoveryAdvertisement.isUsablePort(-1), "a negative port is not usable")

        // An unsupported version is listed rather than hidden, so the operator can see the
        // device and understand why it cannot be used.
        val version = rejection("discovery.reject.unsupported-version")

        assertEquals("9.0", version["advertised_version"]!!.asString(), "the advertised version is 9.0")

        val supported = version["controller_supported_versions"]!!.asArray().map { it.asString() }

        assertEquals(listOf("1.0"), supported, "the controller supports 1.0 only")
        assertFalse(supported.contains("9.0"), "the advertised major is not supported")

        assertEquals("list_as_incompatible", version["expected"]!!.asString(), "it is listed as incompatible")
        assertEquals(
            "ERR_VERSION_MISMATCH",
            version["expected_error"]!!.asString(),
            "the fault is a version mismatch",
        )

        // A record over the budget must be regenerated, not truncated: a truncated record set
        // is undeliverable in one response, so publishing it loses the advertisement entirely.
        val large = rejection("discovery.reject.txt-too-large")

        val bytes = large["txt_bytes"]!!.asInt()
        val max = large["max_txt_bytes"]!!.asInt()

        assertEquals(DiscoveryAdvertisement.MAX_TXT_BYTES, max, "the vector's budget is the implementation's")
        assertFalse(DiscoveryAdvertisement.fitsTxtBudget(bytes), "$bytes bytes does not fit a $max budget")
        assertTrue(DiscoveryAdvertisement.fitsTxtBudget(max), "exactly the budget fits")
        assertEquals("regenerate_record", large["expected"]!!.asString(), "the record is regenerated")

        // The beacon is a broadcast, so it is only sent when discovery is on, and there is no
        // unicast fallback.
        val beacon = rejection("discovery.reject.beacon-on-public-network")

        assertEquals(false, beacon["discovery_enabled"]!!.asBoolean(), "discovery is disabled")
        assertFalse(DiscoveryAdvertisement.mayBeacon(false), "no beacon when discovery is off")
        assertTrue(DiscoveryAdvertisement.mayBeacon(true), "a beacon when discovery is on")

        assertTrue(
            beacon["note"]!!.asString().contains("must not unicast it to an address it has not itself been contacted from"),
            "there is no unicast fallback",
        )
    }

    /**
     * The capability list is advisory, and a truncated one is not evidence.
     */
    @Test
    fun aTruncatedCapabilityListIsAdvisory() {
        val v = vector("discovery.txt.caps-truncated")

        val advertised = fields(v)["caps"]!!.split(",")
        val available = v["caps_actually_available"]!!.asArray().map { it.asString() }

        // The advertised list is a strict subset: the record was truncated to fit the budget.
        assertTrue(advertised.size < available.size, "the advertised list is shorter than the available set")

        for (capability in advertised) {
            assertTrue(available.contains(capability), "the advertised \"$capability\" really is available")
        }

        // And capabilities are available that were not advertised, which is the whole point:
        // a controller that trusted the record would refuse features the agent has.
        val missing = available.filterNot { advertised.contains(it) }

        assertTrue(missing.isNotEmpty(), "some available capabilities were not advertised")
        assertTrue(missing.contains("screen.record"), "screen.record is available but not advertised")

        // The advertised list has no trailing comma, because a trailing comma produces an empty
        // element that a naive split turns into a capability named "".
        assertFalse(fields(v)["caps"]!!.endsWith(","), "the capability list has no trailing comma")
        assertFalse(fields(v)["caps"]!!.contains(",,"), "the capability list has no empty element")

        // The vector's own note says the advertised list is a hint. Asserted rather than
        // paraphrased, because this is the rule a controller implementation must not get wrong.
        assertTrue(
            v["note_on_trust"]!!.asString().contains("Only the CAPABILITIES frame after authentication is authoritative"),
            "only the post-authentication frame is authoritative",
        )
    }

    /**
     * The lifecycle rules are the declared ones.
     */
    @Test
    fun theLifecycleRulesAreAsDeclared() {
        // Disabling discovery withdraws the advertisement straight away. The goodbye carries a
        // TTL of ZERO, not the normal record TTL, and the difference is the point: waiting for a
        // two-minute record to expire would leave a disabled agent listed with no way for a
        // controller to tell it apart from one that merely went to sleep.
        //
        // My first version asserted the goodbye reused the normal TTL. The vector says zero.
        val goodbye = lifecycle("discovery.goodbye-on-disable")

        assertEquals(0, goodbye["goodbye_ttl"]!!.asInt(), "the goodbye has a TTL of zero")
        assertFalse(
            goodbye["goodbye_ttl"]!!.asInt() == DiscoveryAdvertisement.TTL_SECONDS,
            "the goodbye does not use the normal TTL",
        )
        assertEquals("send_goodbye", goodbye["expected"]!!.asString(), "a goodbye is sent")

        // An expired advertisement keeps the device in the list. Removing it on expiry would
        // make a sleeping phone look like a phone that was uninstalled, and the operator's
        // saved pairing is the thing that makes the difference visible.
        val expiry = lifecycle("discovery.ttl-expiry-keeps-saved-device")

        assertTrue(
            expiry["elapsed_s"]!!.asInt() > expiry["ttl_s"]!!.asInt(),
            "the vector's elapsed time is past the TTL",
        )
        assertEquals(
            true,
            expiry["expected_still_listed"]!!.asBoolean(),
            "an expired device stays listed",
        )

        val state = expiry["expected_ui_state"]!!.asString()

        assertFalse(state.isEmpty(), "the expiry has a UI state")
        assertFalse(
            state.contains("removed"),
            "the expired device is not removed from the list",
        )

        // A busy agent still advertises, with the busy flag set. It does not withdraw: a
        // controller that cannot see the device at all also cannot see that it is busy, so the
        // operator is left with no way to tell "off" from "full".
        val busy = lifecycle("discovery.busy-agent-still-advertises")

        assertTrue(
            busy["active_sessions"]!!.asInt() >= busy["max_sessions"]!!.asInt(),
            "the vector's agent really is at its session limit",
        )

        val busyFields = busy["expected"]!!.asString()

        assertTrue(busyFields.contains("advertis"), "a busy agent still advertises")

        // A NUMBER, not the string "1". The flag travels as an integer field in the beacon and
        // as a bare `busy=0` in a TXT record, so asserting the string form would pass against a
        // value that could never be serialised the same way twice.
        assertEquals(1, busy["expected_busy_value"]!!.asInt(), "the busy flag is set")

        // And a changed address triggers a fresh announcement rather than waiting for the TTL,
        // because the old address is simply wrong until it does.
        val moved = lifecycle("discovery.reannounce-after-address-change")

        assertEquals("interface_address_changed", moved["trigger"]!!.asString(), "the trigger is an address change")
        assertEquals(
            "re_register_service",
            moved["expected"]!!.asString(),
            "an address change re-registers the service rather than waiting for the TTL",
        )
    }
}
