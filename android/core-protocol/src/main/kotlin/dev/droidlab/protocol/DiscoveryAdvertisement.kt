package dev.droidlab.protocol

/**
 * The discovery advertisement's canonicalisation rules.
 *
 * An advertisement is signed, so both sides must produce the same bytes from the same fields.
 * That makes the ordering a wire-format detail rather than a presentation choice: two
 * implementations that agree on every field but disagree on key order produce two different
 * signatures, and the receiver reports a forgery.
 *
 * The two forms are deliberately different, and the file says why. The TXT form uses a fixed
 * literal order -- stated in the specification, in the vector and in the code -- so that all
 * three can be compared without consulting a sort implementation. The beacon form is ascending,
 * because it carries a JSON object and needs its own deterministic rule rather than a second
 * hand-written list to keep in step.
 */
object DiscoveryAdvertisement {
    /** The mDNS service type advertisements are published under. */
    const val SERVICE_TYPE = "_droidlab._tcp"

    /** The mDNS domain. `local` means link-local, which is the only scope an advertisement may use. */
    const val DOMAIN = "local"

    /** The pairwise label every TXT record opens with, before the fields. */
    const val TXT_LABEL = "DLWP/1-txt"

    /** The separator between the fields. A newline, so the record is legible in a packet capture. */
    const val FIELD_SEPARATOR = 0x0A

    /** The five keys every advertisement must carry, in the order they are written. */
    val REQUIRED_KEYS = listOf("v", "id", "fp", "caps", "port")

    /**
     * The optional keys, in the order they are appended after `port` when present.
     *
     * Fixed rather than alphabetical, for the same reason the required keys are: the order is
     * part of the signed bytes, and a sort would make it depend on a collation the specification
     * does not choose.
     */
    val OPTIONAL_KEYS = listOf("model", "android", "sdk", "busy", "loc", "tls")

    /** The port an agent listens on when it is not overriding the default. */
    const val DEFAULT_PORT = 45917

    /** The port a beacon is sent to. One above the service port, and never the service port. */
    const val BEACON_PORT = 45918

    /** How long an advertisement stays valid without a refresh. */
    const val TTL_SECONDS = 120

    /** The largest TXT record set the agent may publish, because mDNS delivers it in one response. */
    const val MAX_TXT_BYTES = 1300

    /** The signature over an advertisement. Ed25519, so 64 bytes. */
    const val SIGNATURE_LENGTH_BYTES = 64

    /**
     * Builds the canonical TXT bytes for an advertisement.
     *
     * The label and a NUL come first, then the fields joined by newlines with **no trailing
     * newline**. The trailing newline is the mistake worth naming: it is invisible in most
     * places the value appears, it produces a different signature, and nothing in the record
     * says which form is correct.
     *
     * @param fields the advertisement's fields. Keys outside [REQUIRED_KEYS] and [OPTIONAL_KEYS]
     *   are ignored rather than appended, because a signed record must not grow a field the
     *   specification does not define.
     */
    fun canonicalTxt(fields: Map<String, String>): ByteArray {
        val builder = StringBuilder()

        builder.append(TXT_LABEL)
        builder.append('\u0000')

        val ordered = REQUIRED_KEYS + OPTIONAL_KEYS

        for ((index, key) in ordered.withIndex()) {
            val value = fields[key]

            // A missing required key is refused rather than written as empty. An empty
            // `port=` and an absent one are different records, and only one of them is legal.
            if (value == null) {
                if (key in REQUIRED_KEYS) {
                    throw IllegalArgumentException("the required key \"$key\" is missing")
                }

                continue
            }

            if (value.contains('\n')) {
                throw IllegalArgumentException("the value of \"$key\" contains a newline")
            }

            if (index > 0) {
                // The separator goes BETWEEN fields, never after the last one. Appending it
                // per-field would leave a trailing newline.
                val hasPredecessor = ordered.take(index).any { fields.containsKey(it) }

                if (hasPredecessor) builder.append('\u000A')
            }

            builder.append(key).append('=').append(value)
        }

        return builder.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Builds the canonical beacon bytes from a set of typed fields.
     *
     * Ascending key order, no whitespace, `key=value` joined by newlines. Every field except a
     * signature is covered, which is why this is a separate method from [canonicalTxt] rather
     * than the same code with a flag.
     */
    fun canonicalBeacon(fields: Map<String, Any>): ByteArray {
        val ordered = fields.keys.sorted()

        return ordered.joinToString("\n") { key ->
            val value = fields[key]

            when (value) {
                is String -> "$key=$value"
                is Number -> "$key=$value"
                else -> throw IllegalArgumentException("the field \"$key\" is neither a string nor a number")
            }
        }.toByteArray(Charsets.UTF_8)
    }

    /**
     * Whether a TXT record set fits the size budget.
     */
    fun fitsTxtBudget(byteCount: Int): Boolean = byteCount in 0..MAX_TXT_BYTES

    /**
     * Whether an advertised port is one a controller may use.
     *
     * Port zero means "pick one", which is not an address a controller can connect to, so it is
     * rejected rather than treated as a default.
     */
    fun isUsablePort(port: Int): Boolean = port in 1..65535

    /**
     * Whether a beacon may be sent at all.
     *
     * The beacon is a broadcast on the local segment. When discovery is off there is no beacon,
     * and there is no unicast fallback: an agent must not send to an address it has not itself
     * been contacted from, or it becomes a reflector.
     */
    fun mayBeacon(discoveryEnabled: Boolean): Boolean = discoveryEnabled
}
