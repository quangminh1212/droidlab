package dev.droidlab.protocol.cbor

/**
 * A cbOR value as DLWP/1 uses it (RFC-0001 section 3.2, RFC 8949).
 *
 * The model is deliberately narrow. DLWP/1 bodies are maps with text keys, and the
 * values are the small set below -- no tags, no indefinite lengths, no 64-bit integers,
 * no floating point. Modelling only what the protocol uses is what lets the reader
 * reject everything else rather than having to decide what a tag means, and a reader
 * that accepts more than the protocol defines is a reader whose two implementations can
 * disagree about a frame they both accept.
 *
 * Unknown *keys* are a different matter and are kept: a newer peer may add a key, and
 * section 3.2 requires a receiver to ignore what it does not know. Keeping them here is
 * what makes that possible, and what makes an unknown key distinguishable from a
 * malformed body.
 */
sealed interface CborValue {
    /** A map with text keys. */
    data class Map(val entries: LinkedHashMap<String, CborValue>) : CborValue {
        /** The value for a key, or null when absent. */
        operator fun get(key: String): CborValue? = entries[key]

        /** Whether a key is present. */
        operator fun contains(key: String): Boolean = entries.containsKey(key)
    }

    /** A text string. */
    data class Text(val value: String) : CborValue

    /** A byte string. */
    data class Bytes(val value: ByteArray) : CborValue {
        override fun equals(other: Any?): Boolean =
            other is Bytes && value.contentEquals(other.value)

        override fun hashCode(): Int = value.contentHashCode()
    }

    /** An unsigned integer. */
    data class Unsigned(val value: Long) : CborValue {
        init {
            require(value >= 0) { "an unsigned cbOR integer may not be negative" }
        }
    }

    /** A negative integer, held as the value itself rather than the encoded form. */
    data class Negative(val value: Long) : CborValue {
        init {
            require(value < 0) { "a negative cbOR integer must be negative" }
        }
    }

    /** A boolean. */
    data class Bool(val value: Boolean) : CborValue

    /** Null. */
    data object Null : CborValue

    /** An array. */
    data class Array(val items: List<CborValue>) : CborValue
}

/**
 * The one entry point the classifier needs into the cbOR reader.
 *
 * A named object rather than a direct call to `CborReader` from the classifier, because the
 * classifier's question is narrow -- "may this body be handed to a per-message parser?" --
 * and giving it the reader would also give it the ability to parse bodies, which is the
 * message layer's job and not the frame layer's. The layer model in the RFC keeps those
 * apart for the same reason it keeps L1 free of policy.
 */
object CborBody {
    /**
     * Whether a body is a well-formed cbOR map.
     *
     * @param body the body bytes.
     * @return whether it decodes as a map.
     *
     * An empty body is accepted, and that is a rule rather than a convenience: section 3.2
     * makes zero bytes the canonical encoding of a message with no parameters, so a receiver
     * that rejected it would refuse every parameterless message. `0xA0` is accepted too,
     * because a sender that encodes the empty map explicitly is not wrong.
     *
     * Everything else DLWP/1 does not use is refused: indefinite lengths, tags, 64-bit
     * arguments, floats, invalid UTF-8 and non-shortest integer encodings. The last of those
     * matters most for interoperability, because two encoders that disagree about the
     * shortest form produce different bytes for the same message, and a transcript hash over
     * those bytes would not match.
     */
    fun isWellFormedMap(body: ByteArray): Boolean = CborReader.isWellFormedMap(body)
}

/**
 * Why a body could not be decoded.
 *
 * @property reason a stable machine-readable reason.
 */
class CborException(val reason: String) : Exception(reason)

/**
 * A strict cbOR reader for DLWP/1 bodies.
 *
 * Every rejection here is a deliberate narrowing rather than an implementation shortcut.
 * RFC 8949 permits indefinite lengths, tags, floating point and multi-byte encodings of
 * small integers; DLWP/1 uses none of them, and accepting them would mean two
 * implementations could agree that a frame is well formed while disagreeing about what
 * it means, which is exactly the failure a canonical encoding exists to prevent.
 *
 * The one place this is strict rather than lenient matters for interoperability: an
 * integer must use the shortest encoding that fits. A value sent as `0x18 0x05` is
 * rejected even though a reader that unpacked it would agree on the value, because two
 * encoders that disagree about the shortest form produce different bytes for the same
 * message, and a transcript hash over those bytes would not match.
 */
class CborReader(private val bytes: ByteArray, private var offset: Int = 0) {
    /** How many bytes have been consumed. */
    val position: Int get() = offset

    /** Whether the reader is at the end of its buffer. */
    val atEnd: Boolean get() = offset >= bytes.size

    companion object {
        /** The major type shift, since a cbOR byte is `major << 5 | additional`. */
        private const val MAJOR_SHIFT = 5

        /** The additional-information mask. */
        private const val ADDITIONAL_MASK = 0x1F

        /** Additional information 24: the argument is the next byte. */
        private const val ADDITIONAL_UINT8 = 24

        /** Additional information 25: the next two bytes, big-endian. */
        private const val ADDITIONAL_UINT16 = 25

        /** Additional information 26: the next four bytes, big-endian. */
        private const val ADDITIONAL_UINT32 = 26

        /** Additional information 27: the next eight bytes, big-endian. */
        private const val ADDITIONAL_UINT64 = 27

        /** Additional information 31: indefinite length, which DLWP/1 does not use. */
        private const val ADDITIONAL_INDEFINITE = 31

        /** Major type 0: unsigned integer. */
        const val MAJOR_UNSIGNED = 0

        /** Major type 1: negative integer. */
        const val MAJOR_NEGATIVE = 1

        /** Major type 2: byte string. */
        const val MAJOR_BYTES = 2

        /** Major type 3: text string. */
        const val MAJOR_TEXT = 3

        /** Major type 4: array. */
        const val MAJOR_ARRAY = 4

        /** Major type 5: map. */
        const val MAJOR_MAP = 5

        /** Major type 6: tag, which DLWP/1 does not use. */
        const val MAJOR_TAG = 6

        /** Major type 7: simple values and floats. */
        const val MAJOR_SIMPLE = 7

        /** The empty body, which is what a parameterless message sends. */
        private const val EMPTY_MAP = 0xA0.toByte()

        /**
         * Whether a body is a well-formed cbOR map.
         *
         * An empty body is accepted, and that is a rule rather than a convenience:
         * section 3.2 makes zero bytes the canonical encoding of I-heard-you for a
         * message with no parameters, and a receiver that rejected it would refuse
         * every parameterless message. `0xA0` is also accepted, because a sender that
         * encodes the empty map explicitly is not wrong.
         *
         * @param body the body bytes.
         * @return whether it decodes as a map.
         */
        fun isWellFormedMap(body: ByteArray): Boolean = try {
            if (body.isEmpty()) {
                true
            } else {
                CborReader(body).readMap()
                true
            }
        } catch (_: CborException) {
            false
        }
    }

    /** Peeks at the next major type without consuming it. */
    fun peekMajorType(): Int {
        if (offset >= bytes.size) {
            throw CborException("unexpected end of body")
        }

        return (bytes[offset].toInt() and 0xFF) ushr MAJOR_SHIFT
    }

    /** Whether the next item is an empty body, which is zero bytes. */
    fun isEmptyBody(): Boolean = bytes.isEmpty()

    /**
     * Reads a map with text keys.
     *
     * @return the map.
     * @throws CborException when the body is not a map.
     */
    fun readMap(): CborValue.Map {
        if (bytes.isEmpty()) {
            throw CborException("an empty body is not a map to read here")
        }

        val (major, argument) = readHeader()

        if (major != MAJOR_MAP) {
            throw CborException("expected a map but found major type $major")
        }

        // A definite length is required. An indefinite map would need a break byte and
        // would allow two encodings of the same map, which is what the protocol's
        // canonical form exists to prevent.
        val count = argument

        val entries = LinkedHashMap<String, CborValue>(count.toInt())

        for (index in 0 until count) {
            val keyMajor = peekMajorType()

            if (keyMajor != MAJOR_TEXT) {
                throw CborException("a map key must be a text string but found major type $keyMajor")
            }

            val key = readText()

            if (entries.containsKey(key)) {
                // A duplicate key is refused rather than last-one-wins. Two peers that
                // resolved a duplicate differently would disagree about the message
                // while both accepting it, which is the disagreement the whole
                // canonical-encoding rule exists to prevent.
                throw CborException("duplicate map key \"$key\"")
            }

            entries[key] = readValue()
        }

        return CborValue.Map(entries)
    }

    /**
     * Reads a text string at the current position.
     *
     * @return the string.
     */
    fun readText(): String {
        val (major, length) = readHeader()

        if (major != MAJOR_TEXT) {
            throw CborException("expected a text string but found major type $major")
        }

        if (length > bytes.size - offset) {
            throw CborException("a text string of $length bytes runs past the end of the body")
        }

        val start = offset
        offset += length.toInt()

        return decodeUtf8(bytes, start, length.toInt())
    }

    /**
     * Reads any value.
     *
     * @return the value.
     */
    fun readValue(): CborValue {
        if (offset >= bytes.size) {
            throw CborException("unexpected end of body")
        }

        val major = peekMajorType()

        return when (major) {
            MAJOR_UNSIGNED -> {
                val (_, value) = readHeader()
                CborValue.Unsigned(value)
            }

            MAJOR_NEGATIVE -> {
                // cbOR encodes -1 as 0, -2 as 1, and so on. The stored value is the
                // number itself, so the conversion happens here rather than at every
                // call site.
                val (_, value) = readHeader()
                CborValue.Negative(-1L - value)
            }

            MAJOR_BYTES -> {
                val (_, length) = readHeader()
                requireBytes(length)
                val start = offset
                offset += length.toInt()
                CborValue.Bytes(bytes.copyOfRange(start, offset))
            }

            MAJOR_TEXT -> CborValue.Text(readText())

            MAJOR_ARRAY -> {
                val (_, count) = readHeader()
                val items = ArrayList<CborValue>(count.toInt())
                for (index in 0 until count) {
                    items.add(readValue())
                }
                CborValue.Array(items)
            }

            MAJOR_MAP -> readMap()

            MAJOR_TAG -> throw CborException(
                "tags are not part of DLWP/1 bodies; a tagged value has no defined meaning here",
            )

            MAJOR_SIMPLE -> {
                val (_, argument) = readHeader()
                when (argument) {
                    20L -> CborValue.Bool(false)
                    21L -> CborValue.Bool(true)
                    22L -> CborValue.Null

                    // 23 is "undefined" and 24 to 27 are floats and simple values.
                    // None is used, and a float in particular would make the canonical
                    // form ambiguous for values an integer could also express.
                    else -> throw CborException(
                        "simple value $argument is not part of DLWP/1 bodies",
                    )
                }
            }

            else -> throw CborException("major type $major is not defined")
        }
    }

    /**
     * Reads an item's header, which is the major type and its argument.
     *
     * @return the major type and argument.
     */
    private fun readHeader(): Pair<Int, Long> {
        if (offset >= bytes.size) {
            throw CborException("unexpected end of body")
        }

        val initial = bytes[offset].toInt() and 0xFF
        offset++

        val major = initial ushr MAJOR_SHIFT
        val additional = initial and ADDITIONAL_MASK

        return when {
            additional < ADDITIONAL_UINT8 -> major to additional.toLong()

            additional == ADDITIONAL_UINT8 -> major to readBigEndian(1)

            additional == ADDITIONAL_UINT16 -> major to readBigEndian(2)

            additional == ADDITIONAL_UINT32 -> major to readBigEndian(4)

            // 64-bit arguments are read but then range-checked by the caller that needs
            // them; a body may not carry one because DLWP/1 has no 64-bit integers.
            additional == ADDITIONAL_UINT64 -> throw CborException(
                "a 64-bit argument is not part of DLWP/1 bodies",
            )

            additional == ADDITIONAL_INDEFINITE -> throw CborException(
                "indefinite lengths are not part of DLWP/1 bodies",
            )

            // 28 to 30 are reserved by RFC 8949 and must not appear.
            else -> throw CborException("additional information $additional is reserved")
        }
    }

    /** Reads an n-byte big-endian unsigned integer. */
    private fun readBigEndian(length: Int): Long {
        requireBytes(length.toLong())

        var value = 0L
        repeat(length) {
            value = (value shl 8) or (bytes[offset].toLong() and 0xFF)
            offset++
        }

        // A multi-byte argument that would fit in a shorter one is not the shortest
        // encoding, so it is refused. Accepting it would let two encoders produce
        // different bytes for the same value.
        val minimum = when {
            value < 24 -> 0
            value <= 0xFF -> 1
            value <= 0xFFFF -> 2
            value <= 0xFFFFFFFFL -> 4
            else -> 8
        }

        if (length > minimum && length > 0) {
            throw CborException(
                "the argument $value uses $length bytes where $minimum would do; " +
                    "DLWP/1 requires the shortest encoding",
            )
        }

        return value
    }

    /** Requires that many bytes remain. */
    private fun requireBytes(length: Long) {
        if (length < 0 || length > bytes.size - offset) {
            throw CborException("an item of $length bytes runs past the end of the body")
        }
    }

    /**
     * Decodes UTF-8, rejecting invalid sequences.
     *
     * The JDK's own decoder is strict by default, which is what is wanted: a body with
     * invalid UTF-8 is malformed, and a reader that substituted replacement characters
     * would turn a malformed frame into a subtly different valid one.
     */
    private fun decodeUtf8(source: ByteArray, from: Int, length: Int): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)

        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(source, from, length)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw CborException("the text string is not valid UTF-8: ${e.message}")
        }
    }

    /** Whether a byte is the empty map, which is also a canonical empty body. */
    fun isEmptyMapByte(): Boolean = offset < bytes.size && bytes[offset] == EMPTY_MAP
}
