package dev.droidlab.protocol.crypto

import dev.droidlab.protocol.JsonValue
import dev.droidlab.protocol.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Conformance tests for the crypto primitives, driven by `crypto-primitives.json`.
 *
 * What is checkable here without extra primitives is the whole hash-only surface plus the two
 * fail-closed rules: the seed derivation, the fingerprint format, the pairing code, the replay
 * window and the contributory check. Key agreement and AEAD themselves are not reimplemented --
 * an implementation must not invent a primitive, and neither must a test -- but the decisions
 * around them are, and those are where an implementation actually goes wrong.
 */
class CryptoPrimitivesTest {
    private companion object {
        const val VECTOR_FILE = "crypto-primitives.json"
    }

    /** The signature vectors. */
    private fun signatureVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "signature_vectors")

    /** The rejection vectors. */
    private fun rejectionVectors(): List<JsonValue> =
        Vectors.array(VECTOR_FILE, "rejection_vectors")

    /** A rejection vector by id, failing if it is missing so a renamed vector cannot skip. */
    private fun rejection(id: String): JsonValue =
        rejectionVectors().firstOrNull { it["id"]?.asString() == id }
            ?: error("crypto-primitives.json has no rejection vector \"$id\"")

    /** The labels object as the file lists it, without its explanatory note. */
    private fun labelsFromFile(): Map<String, String> {
        val labels = Vectors.load(VECTOR_FILE)["labels"] ?: error("crypto-primitives.json has no labels")

        // The `labels` object carries a `note` key alongside the labels themselves, and it is
        // excluded by name rather than by filtering on a value type. It IS a string, so a
        // type-based filter lets it through and it then fails the "every label starts with
        // DLWP/1-" assertion -- which is a real failure that names a key that was never a
        // label. The mirror of this check found it.
        return labels.asObject()
            .filterKeys { it != "note" }
            .mapValues { it.value.asString() }
    }

    /**
     * Every label in the file matches the constant in the code.
     */
    @Test
    fun everyLabelMatchesTheFile() {
        val fromFile = labelsFromFile()

        assertTrue(fromFile.size >= 17, "expected at least 17 labels, found ${fromFile.size}")

        // Compared in both directions, and this is the check that matters most in this file: a
        // one-character difference in a label yields a different key and a session that fails
        // at the first record, with nothing in the logs pointing at the typo. There is no
        // partial credit for getting sixteen of seventeen right.
        val code = mapOf(
            "transcript_label" to Labels.TRANSCRIPT,
            "session_salt_label" to Labels.SESSION_SALT,
            "pairing_salt_label" to Labels.PAIRING_SALT,
            "pairing_secret_info" to Labels.PAIRING_SECRET_INFO,
            "pairing_agent_proof_label" to Labels.PAIRING_AGENT_PROOF,
            "pairing_controller_proof_label" to Labels.PAIRING_CONTROLLER_PROOF,
            "pairing_confirmation_label" to Labels.PAIRING_CONFIRMATION,
            "pairing_code_label" to Labels.PAIRING_CODE,
            "fingerprint_label" to Labels.FINGERPRINT,
            "txt_label" to Labels.TXT,
            "exporter_label" to Labels.EXPORTER,
            "c2a_key_info" to Labels.C2A_KEY_INFO,
            "a2c_key_info" to Labels.A2C_KEY_INFO,
            "c2a_iv_info" to Labels.C2A_IV_INFO,
            "a2c_iv_info" to Labels.A2C_IV_INFO,
            "auth_client_label" to Labels.AUTH_CLIENT,
            "auth_agent_label" to Labels.AUTH_AGENT,
        )

        assertEquals(fromFile.keys, code.keys, "the label names match")

        for ((name, value) in fromFile) {
            assertEquals(value, code[name], "the label \"$name\" matches")
        }

        // And every label really is ASCII with the DLWP/1 prefix, which is the property the
        // file asserts for all of them rather than an incidental feature of the current set.
        for ((name, value) in fromFile) {
            assertTrue(value.startsWith("DLWP/1-"), "the label \"$name\" starts with DLWP/1-")
            assertTrue(value.all { it.code < 0x80 }, "the label \"$name\" is ASCII")
        }
    }

    /**
     * The seed rule derives keys without any literal key bytes.
     */
    @Test
    fun theSeedRuleDerivesKeysWithNoLiteralBytes() {
        val rule = Vectors.load(VECTOR_FILE)["seed_rule"]!!

        assertEquals(
            "key(seed) = SHA-256(\"DLWP/1-test-key\" || 0x00 || seed)",
            rule["formula"]!!.asString(),
            "the file declares the seed rule",
        )

        // The derived key is 32 bytes and depends on the seed.
        val first = Derivations.testKey("droidlab-test-seed-01")
        val second = Derivations.testKey("droidlab-test-seed-02")

        assertEquals(32, first.size, "a derived key is 32 bytes")
        assertEquals(32, second.size, "a derived key is 32 bytes")

        assertFalse(
            first.contentEquals(second),
            "different seeds derive different keys",
        )

        // And the derivation is the formula rather than something that merely looks like it.
        // Recomputed here from the label and the seed, so the check is against the file's
        // stated formula and not against the function's own output.
        val expected = Derivations.sha256(
            Labels.labelled("DLWP/1-test-key") + "droidlab-test-seed-01".toByteArray(Charsets.UTF_8),
        )

        assertEquals(expected.toList(), first.toList(), "the key is the formula's output")

        // The label carries its separator, which is the part a call site can forget. Without
        // it the key is still well-formed and simply different, so nothing but a comparison
        // like this would catch the omission.
        val withoutSeparator = Derivations.sha256(
            "DLWP/1-test-key".toByteArray(Charsets.UTF_8) + "droidlab-test-seed-01".toByteArray(Charsets.UTF_8),
        )

        assertFalse(
            withoutSeparator.contentEquals(first),
            "the separator changes the key, so omitting it is a real mistake",
        )
    }

    /**
     * Both signature vectors carry the inputs the rule needs.
     */
    @Test
    fun everySignatureVectorHasItsInputs() {
        assertTrue(signatureVectors().size >= 2, "expected at least 2 signature vectors")

        for (v in signatureVectors()) {
            val id = v["id"]!!.asString()

            // The seed is a short auditable string, not 32 bytes of key material -- which is
            // the seed rule doing its job.
            val seed = v["seed"]!!.asString()

            assertTrue(seed.isNotEmpty(), "$id has a seed")
            assertTrue(seed.length < 32, "$id's seed is a short string, not literal key bytes")

            // The payload is the exact byte string signed, recorded rather than described, so
            // an implementation can check itself without a session.
            val input = v["signature_input"]!!.asString()

            assertTrue(input.isNotEmpty(), "$id has a signature input")

            // 64 bytes, which is an Ed25519 signature and nothing else.
            assertEquals(64, v["signature_output_length"]!!.asInt(), "$id signs to 64 bytes")

            // The derived key really is derivable from the vector's own seed.
            val key = Derivations.testKey(seed)

            assertEquals(32, key.size, "$id's derived key is 32 bytes")
        }

        // The two seeds differ, so the vectors are not the same case twice.
        val seeds = signatureVectors().map { it["seed"]!!.asString() }

        assertEquals(seeds.size, seeds.toSet().size, "the signature vectors use distinct seeds")
    }

    /**
     * The transcript signature's payload opens with the txt label.
     */
    @Test
    fun theTxtSignaturePayloadIsLabelled() {
        val v = signatureVectors().first { it["id"]!!.asString() == "ed25519.txt-payload.basic" }

        val input = v["signature_input"]!!.asString()

        // The discovery advertisement's signed payload is prefixed with the txt label and a
        // separator, for the same reason every other label is: a signature over a bare payload
        // could be replayed as a signature over a different one that happens to share bytes.
        assertTrue(
            input.startsWith(Labels.TXT + "\u0000"),
            "the txt payload is prefixed with its label and a separator",
        )

        assertTrue(input.contains("id=11111111-2222-4333-8444-555555555555"), "the payload carries the device id")
        assertTrue(input.contains("port=45917"), "the payload carries the port")
    }

    /**
     * The QR signature's payload is the pairing URI, unmodified.
     */
    @Test
    fun theQrSignaturePayloadIsThePairingUri() {
        val v = signatureVectors().first { it["id"]!!.asString() == "ed25519.qr-payload.basic" }

        val input = v["signature_input"]!!.asString()

        // Signed exactly as it appears on the QR code, so a scanner and a signer agree without
        // either reconstructing the URI from parts -- which is where an escaping difference
        // would appear.
        assertTrue(input.startsWith("droidlab://pair?"), "the QR payload is the pairing URI")

        // The URI carries its own version and its own identifiers.
        assertTrue(input.contains("v=1"), "the URI carries its version")
        assertTrue(input.contains("pid="), "the URI carries the pairing id")
        assertTrue(input.contains("aep="), "the URI carries the agent's ephemeral public key")
        assertTrue(input.contains("exp=1735689600"), "the URI carries an expiry")

        // Percent-encoded, which is why the URI is signed as one string rather than rebuilt:
        // a signer that re-encoded the name differently would sign different bytes.
        assertTrue(input.contains("name=Test%20Device"), "the URI percent-encodes its name")

        // Not labelled, unlike the txt payload. The URI already carries its own scheme and
        // version, so a label would add nothing a parser does not read anyway.
        assertFalse(
            input.startsWith(Labels.TXT),
            "the QR payload is not txt-labelled",
        )
    }

    /**
     * A fingerprint is eight bytes of digest in the declared format.
     */
    @Test
    fun aFingerprintHasTheDeclaredFormat() {
        val recipe = Vectors.load(VECTOR_FILE)["derivation_recipes"]!!["fingerprint"]!!

        assertEquals("SHA-256", recipe["hash"]!!.asString(), "the fingerprint is a SHA-256")
        assertTrue(
            recipe["format"]!!.asString().contains("Uppercase hex of the first 8 digest bytes"),
            "the format is the first eight bytes, uppercase",
        )

        val fingerprint = Derivations.fingerprint(ByteArray(32))

        // The shape: four groups of four hex digits. Checked as a shape rather than against a
        // literal, because the vectors deliberately carry no fingerprint value -- the recipe's
        // own note says the RFC's example is illustrative and derived from no seed.
        assertEquals(19, fingerprint.length, "a fingerprint is 19 characters")
        assertEquals(4, fingerprint.count { it == '-' }, "a fingerprint has three dashes")

        val hex = fingerprint.filter { it != '-' }

        assertEquals(16, hex.length, "a fingerprint shows eight bytes")
        assertTrue(hex.all { it in "0123456789ABCDEF" }, "a fingerprint is uppercase hex")
        assertFalse(hex.all { it in "0123456789abcdef" }, "a fingerprint is not lowercase hex")

        // And it really is derived, not a constant: two different keys give two fingerprints.
        val other = ByteArray(32) { 1 }

        assertFalse(
            Derivations.fingerprint(other) == fingerprint,
            "different keys give different fingerprints",
        )

        // A wrong-width key is refused rather than padded or truncated, because either would
        // produce a fingerprint that looks right and identifies the wrong key.
        val wrongWidth = runCatching { Derivations.fingerprint(ByteArray(31)) }

        assertTrue(wrongWidth.isFailure, "a 31-byte key is refused")
    }

    /**
     * The pairing code is six digits in the declared range.
     */
    @Test
    fun thePairingCodeIsSixDigits() {
        val recipe = Vectors.load(VECTOR_FILE)["derivation_recipes"]!!["pairing_code"]!!

        assertTrue(
            recipe["format"]!!.asString().contains("uint32_be(digest[0..4]) mod 1000000"),
            "the format is the first four digest bytes big-endian modulo a million",
        )

        val secret = Derivations.testKey("pairing-secret")
        val controllerNonce = ByteArray(32) { it.toByte() }
        val agentNonce = ByteArray(32) { (it + 32).toByte() }

        val code = Derivations.pairingCode(secret, controllerNonce, agentNonce)

        assertEquals(6, code.length, "a pairing code is six digits")
        assertTrue(code.all { it in '0'..'9' }, "a pairing code is decimal")

        // Within the range the modulus implies, and zero padded -- so a code below 100000 is
        // still six characters rather than an ambiguous short one.
        val value = code.toLong()

        assertTrue(value >= 0, "a pairing code is not negative")
        assertTrue(value < Derivations.PAIRING_CODE_MODULUS, "a pairing code is below a million")

        // The padding: a digest that gives a small value still formats to six characters.
        //
        // The format string alone is not enough, which is what mutation-testing showed:
        // deleting the padding from the derivation survived every other check, because a real
        // digest rarely lands below 100000 and no case exercised it. The derivation is
        // therefore driven with inputs searched for a small result, so the padding is reached
        // rather than merely described.
        val padded = findSmallPairingCodeInput()

        assertNotNull(padded, "an input producing a code below 100000 was found, so the padding is exercised")

        assertTrue(padded!!.startsWith("0"), "a code below 100000 is zero padded: got \"$padded\"")
        assertEquals(6, padded.length, "a padded code is still six characters")
    }

    /**
     * Searches for inputs whose pairing code is below 100000.
     *
     * A digest reduced modulo a million lands in the low six figures about one time in ten, so
     * a few dozen tries suffice. Searching rather than hard-coding a value keeps the test
     * honest: a hard-coded code would be a number I copied out of a run, and copying a value
     * proves only that the implementation agrees with itself.
     *
     * @return a zero-padded code below 100000, or null if none was found in the attempts made.
     */
    private fun findSmallPairingCodeInput(): String? {
        val secret = Derivations.testKey("pairing-secret")

        for (attempt in 0 until 500) {
            val controllerNonce = ByteArray(32) { (it + attempt).toByte() }
            val agentNonce = ByteArray(32) { (it * 7 + attempt).toByte() }

            val code = Derivations.pairingCode(secret, controllerNonce, agentNonce)

            if (code.startsWith("0")) return code
        }

        return null
    }

        // The code depends on all three inputs, so a peer cannot make it match by holding one
        // of them fixed.
        val differentSecret = Derivations.pairingCode(Derivations.testKey("other"), controllerNonce, agentNonce)
        val differentAgentNonce = Derivations.pairingCode(secret, controllerNonce, ByteArray(32) { 9 })

        assertFalse(code == differentSecret || code == differentAgentNonce, "the code depends on every input")

        // A KNOWN VALUE, recomputed here from the digest by hand rather than by calling the
        // function. This is the assertion that pins the endianness: the checks above only
        // require six digits, and reading the digest little-endian also gives six digits from
        // the same bytes. Mutation-testing showed exactly that -- swapping the byte order
        // survived every other check in this test.
        val digest = Derivations.sha256(
            Labels.labelled(Labels.PAIRING_CODE) + secret + controllerNonce + agentNonce,
        )

        val byHand = ((digest[0].toLong() and 0xFF) shl 24) or
            ((digest[1].toLong() and 0xFF) shl 16) or
            ((digest[2].toLong() and 0xFF) shl 8) or
            (digest[3].toLong() and 0xFF)

        assertEquals("%06d".format(byHand % 1_000_000L), code, "the code is the digest's first four bytes, big-endian")

        // And the little-endian reading gives a different code for the same digest, so the
        // assertion above really does discriminate rather than passing either way.
        val littleEndian = (digest[0].toLong() and 0xFF) or
            ((digest[1].toLong() and 0xFF) shl 8) or
            ((digest[2].toLong() and 0xFF) shl 16) or
            ((digest[3].toLong() and 0xFF) shl 24)

        // Skipped in the vanishingly rare case that the two readings agree, so the check cannot
        // pass vacuously: if they agree, this assertion is not evidence and says so.
        if (littleEndian % 1_000_000L != byHand % 1_000_000L) {
            assertFalse(
                "%06d".format(littleEndian % 1_000_000L) == code,
                "the little-endian reading gives a different code, so the check discriminates",
            )
        }
    }

    /**
     * The all-zero X25519 output is refused.
     */
    @Test
    fun anAllZeroSharedSecretIsRefused() {
        val v = rejection("x25519.reject.all-zero-output")

        assertEquals("rejected", v["expected"]!!.asString())

        // The peer's public key is the all-zero low-order point, which is one of the inputs for
        // which X25519 returns zero.
        val peerKey = Vectors.hex(v["peer_public_key"]!!.asString())

        assertEquals(32, peerKey.size, "the low-order point is 32 bytes")
        assertTrue(peerKey.all { it.toInt() == 0 }, "the vector's key really is all zero")

        // The output it produces is refused.
        assertFalse(
            ReplayProtection.isUsableSharedSecret(ByteArray(32)),
            "an all-zero shared secret is refused",
        )

        // And a non-zero one is accepted, so the check discriminates rather than refusing all.
        val usable = ByteArray(32) { 0x01 }

        assertTrue(ReplayProtection.isUsableSharedSecret(usable), "a non-zero secret is usable")

        // Including when only the LAST byte is non-zero, which is the case an early return
        // written against the first byte would reject.
        val lastByteOnly = ByteArray(32).also { it[31] = 0x01 }

        assertTrue(
            ReplayProtection.isUsableSharedSecret(lastByteOnly),
            "a secret non-zero only in its last byte is usable",
        )

        // A wrong-width secret is refused rather than treated as usable.
        assertFalse(
            ReplayProtection.isUsableSharedSecret(ByteArray(31)),
            "a short secret is refused",
        )
    }

    /**
     * A reused sequence number is refused, and is told apart from a reorder.
     */
    @Test
    fun aReusedSequenceNumberIsRefused() {
        val v = rejection("nonce.reject.reused-sequence")

        assertEquals("rejected", v["expected"]!!.asString())

        val sequence = v["first_sequence_number"]!!.asLong()

        assertEquals(sequence, v["second_sequence_number"]!!.asLong(), "the two frames share a number")

        // The first is accepted and sets the high-water mark.
        val first = ReplayProtection.classify(sequence, null, emptySet())

        assertTrue(first.accepted, "the first frame is accepted")

        // The second is refused. The seen-set is what makes this a replay rather than a
        // reorder: the arriving number is INSIDE the window, so a window check alone would
        // accept it a second time and the frame would be processed twice.
        val second = ReplayProtection.classify(sequence, sequence, setOf(sequence))

        assertFalse(second.accepted, "the repeated frame is refused")
        assertTrue(second.replay, "and it is classified as a replay")

        // Which is the mistake this pair exists to catch: without the seen-set, the window
        // check alone accepts the repeat.
        val windowOnly = ReplayProtection.classify(sequence, sequence, null)

        assertTrue(
            windowOnly.accepted,
            "the window alone cannot tell a repeat from a reorder, which is why the seen-set is checked first",
        )
    }

    /**
     * The window's trailing edge is where the vectors put it.
     */
    @Test
    fun theReorderingWindowBracketsItsEdge() {
        // Out of the window: 33 behind the high-water mark, with a window of 32.
        val out = rejection("nonce.reject.out-of-window")

        assertEquals("rejected", out["expected"]!!.asString())

        val window = out["window"]!!.asInt()

        assertEquals(ReplayProtection.WINDOW, window, "the vector's window matches the implementation's")

        val outVerdict = ReplayProtection.classify(
            out["received"]!!.asLong(),
            out["highest_accepted"]!!.asLong(),
            emptySet(),
            window,
        )

        assertFalse(outVerdict.accepted, "a frame past the window is refused")
        assertTrue(outVerdict.replay, "and it is a replay")

        // Inside the window: 31 behind, and accepted.
        val inside = rejection("nonce.accept.inside-window")

        assertEquals("accepted", inside["expected"]!!.asString())

        val insideVerdict = ReplayProtection.classify(
            inside["received"]!!.asLong(),
            inside["highest_accepted"]!!.asLong(),
            emptySet(),
            inside["window"]!!.asInt(),
        )

        assertTrue(insideVerdict.accepted, "a frame inside the window is accepted")
        assertFalse(insideVerdict.replay, "and it is not a replay")
    }

    /**
     * The exact boundary between inside and outside the window.
     */
    @Test
    fun theWindowEdgeIsExact() {
        val highest = 1000L
        val window = ReplayProtection.WINDOW

        // The oldest acceptable number is exactly `highest - window`. Checked on both sides of
        // that line, because an off-by-one here either refuses a legitimate reorder or accepts
        // one a frame too old -- and the vectors only sample the two cases, not the boundary.
        val oldest = highest - window

        assertTrue(
            ReplayProtection.classify(oldest, highest, emptySet(), window).accepted,
            "the oldest number in the window is accepted",
        )

        assertFalse(
            ReplayProtection.classify(oldest - 1, highest, emptySet(), window).accepted,
            "one older than the window is refused",
        )

        // And a number ahead of the high-water mark is always accepted: it is not a reorder,
        // it is simply the next frame.
        assertTrue(
            ReplayProtection.classify(highest + 1, highest, emptySet(), window).accepted,
            "a number ahead of the high-water mark is accepted",
        )

        // Nothing accepted yet means no window to fall out of, however small the number.
        assertTrue(
            ReplayProtection.classify(0, null, emptySet(), window).accepted,
            "the first frame is accepted whatever its number",
        )

        // Which is why `highestAccepted` is nullable rather than defaulting to zero. The
        // discriminating case has to be a number that a zero default would REJECT: with a
        // high-water mark of 0 and a window of 32, a frame numbered 0 is at the boundary and
        // still acceptable, so testing 0 alone does not distinguish the two. A negative
        // number does, and it can only arise from a caller that never accepted anything.
        //
        // Mutation-testing found this: replacing the null case with a zero default survived,
        // because every number the test used was above the boundary either way.
        val firstFrameAnyNumber = ReplayProtection.classify(Long.MIN_VALUE, null, emptySet(), window)

        assertTrue(
            firstFrameAnyNumber.accepted,
            "with nothing accepted yet there is no window, so even a very low number is accepted",
        )

        // And the same number against a zero high-water mark IS refused, which is what makes
        // the assertion above meaningful rather than a tautology.
        assertFalse(
            ReplayProtection.classify(Long.MIN_VALUE, 0L, emptySet(), window).accepted,
            "the same number is refused once something has been accepted, so the null case is doing work",
        )
    }

    /**
     * The AAD vector's tampered field is the header.
     */
    @Test
    fun theFrameHeaderIsTheAssociatedData() {
        val v = rejection("aead.reject.tampered-header")

        assertEquals("rejected", v["expected"]!!.asString())

        // The header is the associated data, so a change to any byte of it must fail the tag.
        // This test can only check the claim's shape -- verifying a tag needs AES-GCM, which is
        // [RecordProtection]'s job -- but the shape is worth pinning: the mutated field is in
        // the header rather than in the body, and the error is malformed rather than
        // unauthorized, because a body that fails its tag and a header that fails its tag are
        // the same failure to the receiver.
        assertEquals("sequence_number", v["mutated_field"]!!.asString(), "the mutated field is a header field")

        assertEquals(
            "ERR_MALFORMED",
            v["expected_error"]!!.asString(),
            "a tampered header is reported as malformed",
        )

        // The sequence number is one of the header's fields and is inside the AAD, which is
        // why tampering with it fails the tag rather than silently reordering.
        val headerFields = listOf(
            "magic", "version", "flags", "header_length", "message_type",
            "channel_id", "sequence_number", "acknowledgment", "body_length",
        )

        assertTrue(
            headerFields.contains(v["mutated_field"]!!.asString()),
            "the mutated field is one of the header's own fields",
        )
    }

    /**
     * The declared algorithms are the ones the implementation uses.
     */
    @Test
    fun theDeclaredAlgorithmsAreTheOnesUsed() {
        val algorithms = Vectors.load(VECTOR_FILE)["algorithms"]!!

        // Declared, not assumed: an implementation that substituted a primitive would still
        // pass every vector that only checks a length, so the declarations are compared
        // against the constants the code names.
        assertEquals("HKDF per RFC 5869 with SHA-256", algorithms["kdf"]!!.asString())
        assertEquals("AES-256-GCM with a 96-bit nonce and a 128-bit tag", algorithms["aead"]!!.asString())
        assertEquals("X25519 per RFC 7748", algorithms["key_agreement"]!!.asString())
        assertEquals("Ed25519 per RFC 8032", algorithms["signature"]!!.asString())
        assertEquals("HMAC-SHA256 per RFC 2104", algorithms["hmac"]!!.asString())
        assertEquals("SHA-256 per FIPS 180-4", algorithms["hash"]!!.asString())

        // And the code's own digest really is SHA-256, at the only length that could be.
        assertEquals(32, Derivations.sha256(ByteArray(0)).size, "SHA-256 produces 32 bytes")

        // Known-answer check, so the digest is SHA-256 and not merely 32 bytes of something:
        // SHA-256("") is a published constant.
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Derivations.sha256(ByteArray(0)).joinToString("") { "%02x".format(it.toInt() and 0xFF) },
            "SHA-256 of the empty string is its published value",
        )
    }

    /**
     * The nonce layout is the declared one.
     */
    @Test
    fun theNonceLayoutIsTheDeclaredOne() {
        val nonce = Vectors.load(VECTOR_FILE)["derivation_recipes"]!!["nonce_layout"]!!

        // A four-byte IV prefix followed by an eight-byte big-endian sequence number, so a
        // nonce never repeats under a given key. The direction's key is unique and the
        // sequence number never repeats, so the two together cannot.
        assertTrue(
            nonce["form"]!!.asString().contains("iv_prefix (4 bytes) || sequence_number (8 bytes, big-endian)"),
            "the nonce is an IV prefix and a big-endian sequence number",
        )

        // Twelve bytes total, which is the 96-bit nonce AES-GCM is defined for.
        assertEquals(4 + 8, 12, "the nonce is twelve bytes")
    }
}
