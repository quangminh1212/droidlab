package dev.droidlab.protocol.crypto

import java.security.MessageDigest

/**
 * The DLWP/1 crypto labels and the derivations built only from a hash (RFC-0002).
 *
 * Every byte string this protocol uses is derived from something, and none is written down as
 * a literal. That is what `crypto-primitives.json`'s seed rule is about: `key(seed) =
 * SHA-256("DLWP/1-test-key" || 0x00 || seed)`. The vectors therefore carry a short seed rather
 * than 32 bytes of key material, a reader can audit the whole file, and a copy-paste error in
 * a key is impossible because there are no keys to paste.
 *
 * The labels are exact ASCII, case-sensitive, and used either as an HKDF info string or as an
 * HMAC message prefix. The file's own note is the reason they are centralised here rather than
 * written at each call site: a one-character difference yields a different key and a session
 * that fails at the first record, with nothing in the logs pointing at the typo.
 *
 * The class covers what can be computed from a hash alone, which is deliberately the whole of
 * the pairing and fingerprint arithmetic. Key agreement and AEAD need their own primitives and
 * live in [PairingProofs] and [RecordProtection]. Keeping the hash-only parts separate is not
 * tidiness: it means the seed rule, the fingerprint format, the pairing code and the pairing
 * proofs are all checkable without a session, which is exactly what the vectors do.
 */
object Labels {
    /** The ASCII label that opens the handshake transcript. */
    const val TRANSCRIPT: String = "DLWP/1-handshake"

    /** The HKDF salt label for the session key schedule. */
    const val SESSION_SALT: String = "DLWP/1-session"

    /** The HKDF salt label for the pairing secret. */
    const val PAIRING_SALT: String = "DLWP/1-pairing"

    /** The HKDF info for the pairing secret. */
    const val PAIRING_SECRET_INFO: String = "DLWP/1-pairing-secret"

    /** The HMAC prefix for the agent's pairing proof. */
    const val PAIRING_AGENT_PROOF: String = "DLWP/1-pairing-agent"

    /** The HMAC prefix for the controller's pairing proof. */
    const val PAIRING_CONTROLLER_PROOF: String = "DLWP/1-pairing-controller"

    /** The HMAC prefix for the pairing confirmation. */
    const val PAIRING_CONFIRMATION: String = "DLWP/1-pairing-confirm"

    /** The hash prefix for the pairing code. */
    const val PAIRING_CODE: String = "DLWP/1-pairing-code"

    /** The hash prefix for an identity fingerprint. */
    const val FINGERPRINT: String = "DLWP/1-fingerprint"

    /** The signing label for the discovery advertisement text payload. */
    const val TXT: String = "DLWP/1-txt"

    /** The exporter label. */
    const val EXPORTER: String = "DLWP/1-exporter"

    /** The HKDF info for the controller-to-agent key. */
    const val C2A_KEY_INFO: String = "DLWP/1-c2a-key"

    /** The HKDF info for the agent-to-controller key. */
    const val A2C_KEY_INFO: String = "DLWP/1-a2c-key"

    /** The HKDF info for the controller-to-agent IV prefix. */
    const val C2A_IV_INFO: String = "DLWP/1-c2a-iv"

    /** The HKDF info for the agent-to-controller IV prefix. */
    const val A2C_IV_INFO: String = "DLWP/1-a2c-iv"

    /** The HMAC prefix for the client's AUTH proof. */
    const val AUTH_CLIENT: String = "DLWP/1-client"

    /** The HMAC prefix for the agent's AUTH proof. */
    const val AUTH_AGENT: String = "DLWP/1-agent"

    /** The prefix of the test-key derivation, used only by vectors. */
    const val TEST_KEY: String = "DLWP/1-test-key"

    /** The separator byte that follows every label. */
    const val SEPARATOR: Int = 0x00

    /**
     * A label as bytes followed by the separator.
     *
     * @param label the label.
     * @return the label's ASCII bytes and one zero byte.
     *
     * Offered as one function because the separator is not optional and is easy to forget at a
     * call site. A label without its separator still produces a key, so the mistake is silent
     * until two implementations disagree -- which is the failure mode the file's `labels` note
     * describes.
     */
    fun labelled(label: String): ByteArray {
        // Encoded as ASCII explicitly rather than through the platform charset. On the JVM and
        // on Android the default is UTF-8 and the result is identical, but a transcript or key
        // must not depend on a locale a caller could change.
        val bytes = ByteArray(label.length + 1)

        for ((index, char) in label.withIndex()) {
            require(char.code < 0x80) { "label \"$label\" contains a non-ASCII character at $index" }
            bytes[index] = char.code.toByte()
        }

        bytes[label.length] = SEPARATOR.toByte()

        return bytes
    }
}

/**
 * The SHA-256-only derivations: the test-key rule, fingerprints and the pairing code.
 *
 * These are separated from the HMAC and AEAD work because they need no secret and no session,
 * which makes them the parts a reader can verify by hand and a test can verify without
 * setting anything up.
 */
object Derivations {
    /** A SHA-256 digest's length. */
    const val DIGEST_LENGTH: Int = 32

    /**
     * Hashes data with SHA-256.
     *
     * @param data the data.
     * @return the 32-byte digest.
     */
    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Applies the file's seed rule: `SHA-256("DLWP/1-test-key" || 0x00 || seed)`.
     *
     * @param seed the seed string.
     * @return the derived 32-byte key.
     *
     * The rule exists so that no key material appears literally in a vector file. A reader can
     * see where every byte came from, and a wrong key cannot be introduced by mis-transcribing
     * one.
     */
    fun testKey(seed: String): ByteArray =
        sha256(Labels.labelled(Labels.TEST_KEY) + seed.toByteArray(Charsets.UTF_8))

    /** The number of digest bytes a fingerprint shows. */
    const val FINGERPRINT_BYTES: Int = 8

    /** The number of nibbles in a fingerprint's hex form, including the dashes' worth. */
    const val FINGERPRINT_HEX_LENGTH: Int = 19

    /**
     * Derives an identity fingerprint.
     *
     * @param identityPublicKey the 32-byte public key.
     * @return the fingerprint as `xxxx-xxxx-xxxx-xxxx`, uppercase hex.
     *
     * Eight bytes -- 64 bits -- of the digest, not all 32. That is a deliberate truncation: the
     * fingerprint is what a human reads out loud to confirm a pairing, so it has to be short
     * enough to compare by eye. Sixty-four bits is far beyond what anyone will collide by
     * accident, and the pairing proofs carry the real authentication, so the fingerprint is
     * purely a display aid rather than a security boundary.
     */
    fun fingerprint(identityPublicKey: ByteArray): String {
        require(identityPublicKey.size == 32) {
            "a public key is 32 bytes, not ${identityPublicKey.size}"
        }

        val digest = sha256(Labels.labelled(Labels.FINGERPRINT) + identityPublicKey)

        // Uppercase hex of the first eight bytes, grouped in fours. Uppercase because the
        // format is what a user compares against a screen, and case differences read as
        // differences when they are not.
        val hex = digest.copyOfRange(0, FINGERPRINT_BYTES)
            .joinToString("") { "%02X".format(it.toInt() and 0xFF) }

        return "${hex.substring(0, 4)}-${hex.substring(4, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}"
    }

    /**
     * Derives the pairing code a user compares on both screens.
     *
     * @param pairingSecret the 32-byte pairing secret.
     * @param controllerNonce the controller's 32-byte nonce.
     * @param agentNonce the agent's 32-byte nonce.
     * @return six decimal digits, zero padded.
     *
     * The code is `uint32_be(digest[0..4]) mod 1000000` formatted to six digits. Two details
     * matter and both are easy to get wrong:
     *
     *  - The first four digest bytes are read BIG-ENDIAN, so the same digest gives the same
     *    number on every platform.
     *  - The result is zero padded, so a code below 100000 is still six digits. Without the
     *    padding, a short code would be ambiguous to compare and a trivially small one -- say
     *    "7" -- would be a plausible mistake rather than a conspicuous one.
     *
     * The modulo also introduces a slight bias, since 2^32 is not a multiple of 10^6. That is
     * acceptable here only because the code is a human confirmation aid rather than a secret:
     * the proofs are what authenticate, and the code's job is to let a person notice a
     * mismatch. A biased source for a display value is a different thing from a biased source
     * for a key.
     */
    fun pairingCode(
        pairingSecret: ByteArray,
        controllerNonce: ByteArray,
        agentNonce: ByteArray,
    ): String {
        require(controllerNonce.size == 32) { "a nonce is 32 bytes, not ${controllerNonce.size}" }
        require(agentNonce.size == 32) { "a nonce is 32 bytes, not ${agentNonce.size}" }

        val digest = sha256(
            Labels.labelled(Labels.PAIRING_CODE) + pairingSecret + controllerNonce + agentNonce,
        )

        // Big-endian, because the format says big-endian and a little-endian read gives a
        // different number from the same digest.
        val value = ((digest[0].toLong() and 0xFF) shl 24) or
            ((digest[1].toLong() and 0xFF) shl 16) or
            ((digest[2].toLong() and 0xFF) shl 8) or
            (digest[3].toLong() and 0xFF)

        return "%06d".format(value % 1_000_000L)
    }

    /** The modulus the pairing code is reduced by, matching the six-digit format. */
    const val PAIRING_CODE_MODULUS: Long = 1_000_000L
}
