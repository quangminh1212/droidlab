package dev.droidlab.protocol

import java.security.MessageDigest

/**
 * The handshake transcript (RFC-0001 section 5.4, RFC-0002 section 5.1).
 *
 * The transcript is the byte string both peers agree on, and its SHA-256 is bound into the
 * AUTH proofs. It is what stops an on-path attacker from splicing two handshakes together:
 * the proof covers every value that identified the peers, so an attacker who changes any of
 * them cannot produce a proof the other side accepts.
 *
 * The layout is deliberately explicit and not compact:
 *
 * ```
 *   "DLWP/1-handshake"     16 bytes, ASCII, no terminator
 *   0x00                    1 byte separator
 *   u16-BE length, client_id
 *   0x00                    1 byte separator
 *   u16-BE length, agent_id
 *   0x00                    1 byte separator
 *   client_nonce           32 bytes, no prefix
 *   agent_nonce            32 bytes, no prefix
 *   client_pub             32 bytes, no prefix
 *   agent_pub              32 bytes, no prefix
 * ```
 *
 * The identifiers are length-prefixed and the four fixed-width fields are not, and that
 * asymmetry is the point. Without the prefixes, `client_id = "c"` with `agent_id = "a"` would
 * serialise to the same bytes as `client_id = "c\x00a"` with an empty `agent_id`, so two
 * different handshakes would share a transcript and therefore share a proof. The vector
 * `transcript.reject.leading-separator-confusion` pins exactly that collision, and it is why
 * this class writes the lengths itself rather than concatenating whatever it is given.
 *
 * The four fixed-width fields need no prefix because their width is part of the format: a
 * nonce is 32 bytes or it is not a nonce. Adding a prefix there would add nothing a length
 * check does not already provide.
 */
object HandshakeTranscript {
    /** The ASCII label that opens the transcript. */
    const val LABEL: String = "DLWP/1-handshake"

    /** The label's length in bytes. */
    const val LABEL_LENGTH: Int = 16

    /** The separator between components. */
    const val SEPARATOR: Int = 0x00

    /** A nonce's width. */
    const val NONCE_LENGTH: Int = 32

    /** A public key's width. */
    const val PUBLIC_KEY_LENGTH: Int = 32

    /**
     * The shortest a transcript can be, which is two one-character identifiers.
     *
     * 16 (label) + 1 (separator) + 2 + 1 (client id) + 1 (separator) + 2 + 1 (agent id)
     * + 1 (separator) + 128 (four 32-byte fields) = 153.
     *
     * Recorded as a constant rather than derived, so a mistake in the derivation cannot
     * silently redefine the floor: the vectors carry the same number and a test checks the
     * two agree.
     */
    const val MINIMUM_LENGTH: Int = 153

    /**
     * The largest identifier this format can carry.
     *
     * The length prefix is two bytes, so this is a real limit rather than a defensive one,
     * and it has to be checked: a longer identifier would wrap the prefix and produce a
     * transcript that describes different identifiers than the ones given, which is a
     * collision an attacker could aim for.
     */
    const val MAX_IDENTIFIER_LENGTH: Int = 0xFFFF

    /**
     * Builds the transcript.
     *
     * @param clientId the controller's identifier, as UTF-8.
     * @param agentId the agent's identifier, as UTF-8.
     * @param clientNonce the controller's nonce, exactly 32 bytes.
     * @param agentNonce the agent's nonce, exactly 32 bytes.
     * @param clientPublicKey the controller's public key, exactly 32 bytes.
     * @param agentPublicKey the agent's public key, exactly 32 bytes.
     * @return the transcript bytes.
     * @throws IllegalArgumentException when a field is the wrong width.
     */
    fun build(
        clientId: String,
        agentId: String,
        clientNonce: ByteArray,
        agentNonce: ByteArray,
        clientPublicKey: ByteArray,
        agentPublicKey: ByteArray,
    ): ByteArray {
        val clientIdBytes = clientId.toByteArray(Charsets.UTF_8)
        val agentIdBytes = agentId.toByteArray(Charsets.UTF_8)

        requireIdentifierLength(clientIdBytes.size, "client_id")
        requireIdentifierLength(agentIdBytes.size, "agent_id")

        // Fixed-width fields are checked rather than truncated. A 31-byte nonce would shift
        // every field after it, producing a transcript that is the right length and describes
        // the wrong values -- a failure that would otherwise surface as an authentication
        // error on the peer and be very hard to trace back to here.
        requireWidth(clientNonce, NONCE_LENGTH, "client_nonce")
        requireWidth(agentNonce, NONCE_LENGTH, "agent_nonce")
        requireWidth(clientPublicKey, PUBLIC_KEY_LENGTH, "client_pub")
        requireWidth(agentPublicKey, PUBLIC_KEY_LENGTH, "agent_pub")

        val out = ByteArray(
            LABEL_LENGTH + 1 + 2 + clientIdBytes.size + 1 + 2 + agentIdBytes.size + 1 +
                (NONCE_LENGTH * 2) + (PUBLIC_KEY_LENGTH * 2),
        )

        var offset = 0

        // The label is written as ASCII bytes rather than through the platform charset. On
        // Android and the JVM the default is UTF-8 and this is identical, but a transcript
        // must not depend on a locale setting that a caller could change.
        for (char in LABEL) {
            out[offset++] = char.code.toByte()
        }

        out[offset++] = SEPARATOR.toByte()

        offset = writeLengthPrefixed(out, offset, clientIdBytes)
        out[offset++] = SEPARATOR.toByte()

        offset = writeLengthPrefixed(out, offset, agentIdBytes)
        out[offset++] = SEPARATOR.toByte()

        clientNonce.copyInto(out, offset)
        offset += NONCE_LENGTH

        agentNonce.copyInto(out, offset)
        offset += NONCE_LENGTH

        clientPublicKey.copyInto(out, offset)
        offset += PUBLIC_KEY_LENGTH

        agentPublicKey.copyInto(out, offset)

        return out
    }

    /**
     * Hashes a transcript.
     *
     * @param transcript the transcript bytes.
     * @return the 32-byte SHA-256.
     *
     * SHA-256 because the transcript only needs collision resistance: an attacker who could
     * find two handshakes with the same transcript hash could make one peer's proof validate
     * for the other's values. It does not need to be a MAC, because the transcript is not
     * secret -- both peers exchange every component in the clear -- and the proof over it is
     * where the authentication lives.
     */
    fun hash(transcript: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(transcript)

    /**
     * Builds a transcript and hashes it.
     *
     * @return the transcript and its hash.
     */
    fun buildAndHash(
        clientId: String,
        agentId: String,
        clientNonce: ByteArray,
        agentNonce: ByteArray,
        clientPublicKey: ByteArray,
        agentPublicKey: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val transcript = build(
            clientId,
            agentId,
            clientNonce,
            agentNonce,
            clientPublicKey,
            agentPublicKey,
        )

        return transcript to hash(transcript)
    }

    /**
     * The length a transcript will have, without building it.
     *
     * @param clientId the controller's identifier.
     * @param agentId the agent's identifier.
     * @return the length in bytes.
     *
     * Exposed because the vectors record the length and the arithmetic separately, and a
     * length computed the same way the bytes are would agree with any mistake. A caller that
     * checks the two against each other is checking the format rather than the implementation.
     */
    fun length(clientId: String, agentId: String): Int =
        LABEL_LENGTH + 1 + 2 + clientId.toByteArray(Charsets.UTF_8).size + 1 +
            2 + agentId.toByteArray(Charsets.UTF_8).size + 1 +
            (NONCE_LENGTH * 2) + (PUBLIC_KEY_LENGTH * 2)

    /** Writes a two-byte big-endian length then the bytes; returns the new offset. */
    private fun writeLengthPrefixed(out: ByteArray, offset: Int, value: ByteArray): Int {
        var at = offset

        out[at++] = ((value.size ushr 8) and 0xFF).toByte()
        out[at++] = (value.size and 0xFF).toByte()

        value.copyInto(out, at)
        at += value.size

        return at
    }

    /** Requires an identifier to fit its two-byte length prefix. */
    private fun requireIdentifierLength(length: Int, name: String) {
        require(length <= MAX_IDENTIFIER_LENGTH) {
            "$name is $length bytes, above the $MAX_IDENTIFIER_LENGTH a two-byte prefix holds"
        }
    }

    /** Requires a field to be exactly the width the format fixes. */
    private fun requireWidth(value: ByteArray, expected: Int, name: String) {
        require(value.size == expected) {
            "$name is ${value.size} bytes but the format fixes it at $expected"
        }
    }
}
