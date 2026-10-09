package dev.droidlab.protocol

import java.io.File

/**
 * Loads the shared conformance vectors from `protocol/vectors/`.
 *
 * The vectors are read from the repository rather than copied into this module, and the
 * path arrives as a system property set by the build. That is the whole point of
 * ADR-0007: the vectors are the only interop contract between the Kotlin and C#
 * implementations, so a copy would be a second source of truth, and the copy that is not
 * checked by both sides is the one that drifts.
 *
 * This class deliberately does not use a JSON library. The protocol core has no runtime
 * dependencies -- a wire-format library that forces a JSON parser on every consumer is a
 * decision that belongs to the application -- and the vectors are fixture data, not
 * something the library itself reads. The small parser below handles exactly the JSON
 * the vector files contain, and it fails loudly on anything outside that, which is the
 * right behaviour for a test fixture: a vector file using an unsupported construct
 * should break the test, not be silently skipped.
 */
object Vectors {
    private val root: File by lazy {
        val configured = System.getProperty("droidlab.vectors")
            ?: error(
                "the droidlab.vectors system property is not set; the test task in " +
                    "build.gradle.kts sets it to protocol/vectors",
            )

        val directory = File(configured)

        if (!directory.isDirectory) {
            error("the vector directory $configured does not exist or is not a directory")
        }

        directory
    }

    /**
     * The parsed contents of a vector file.
     *
     * @param fileName the file name, such as `framing-basic.json`.
     * @return the parsed value.
     */
    fun load(fileName: String): JsonValue {
        val file = File(root, fileName)

        if (!file.isFile) {
            error("the vector file $fileName is missing from ${root.absolutePath}")
        }

        return JsonParser(file.readText(Charsets.UTF_8)).parse()
    }

    /**
     * The elements of an array property.
     *
     * @param fileName the file.
     * @param property the property name.
     * @return the elements.
     */
    fun array(fileName: String, property: String): List<JsonValue> {
        val file = load(fileName)
        val value = file[property]
            ?: error("$fileName has no property \"$property\"")

        return value.asArray()
    }

    /**
     * The parsed normative registry, `protocol/registry/dlwp-1.json`.
     *
     * Read from the vector root's sibling rather than through [load], because the registry is
     * not a vector: it is the normative document the vectors are checked against, and a test
     * that compared the vectors to the registry would be comparing a thing to itself. Reading
     * it here lets a test check the CODE against the normative source, which is the direction
     * that catches a transcription error.
     *
     * @return the parsed registry.
     */
    fun registry(): JsonValue {
        val file = File(root.parentFile, "registry/dlwp-1.json")

        if (!file.isFile) {
            error("the registry is missing from ${file.absolutePath}")
        }

        return JsonParser(file.readText(Charsets.UTF_8)).parse()
    }

    /**
     * The registry's message types, keyed by name.
     *
     * The registry stores them as an object whose keys are a 0-based enumeration order while
     * each entry's `code` field is the 1-based wire value. This returns the wire values, because
     * that is what a header carries -- and returning the keys instead is the mistake the check
     * that uses this exists to catch.
     *
     * @return the wire code of each message type, by name.
     * The registry stores `message_types` as an ARRAY of entries, each carrying its own `code`
     * and `name`. Reading it as an object keyed by index -- which an earlier version of this
     * helper did -- fails with a ClassCastException the moment it runs, because the parsed value
     * is an `Arr` and not an `Obj`. The array is the right shape for a registry entry list: the
     * position carries no meaning, and treating a position as a code is exactly the mistake this
     * helper exists to prevent.
     *
     * @return the wire code of each message type, by name.
     */
    fun registryMessageCodes(): Map<String, Int> =
        buildMap {
            for (definition in registry()["message_types"]!!.asArray()) {
                put(definition.require("name").asString(), definition.require("code").asInt())
            }
        }

    /**
     * The registry's message names that may travel unencrypted.
     *
     * @return the names.
     */
    fun registryUnencryptedMessages(): Set<String> =
        buildSet {
            for (definition in registry()["message_types"]!!.asArray()) {
                if (!definition.require("encrypted").asBoolean()) {
                    add(definition.require("name").asString())
                }
            }
        }

    /**
     * Decodes base64, rejecting anything the alphabet does not contain.
     *
     * @param text the base64 text.
     * @return the bytes.
     */
    fun base64(text: String): ByteArray = java.util.Base64.getDecoder().decode(text)

    /**
     * Decodes unpadded base64url.
     *
     * The vectors use base64 for opaque payloads and base64url without padding for key
     * material and identifiers, and the two are different alphabets. Decoding one as the
     * other produces bytes that decode without complaint and are simply wrong, so they
     * are kept separate here rather than unified.
     *
     * @param text the base64url text.
     * @return the bytes.
     */
    fun base64Url(text: String): ByteArray = java.util.Base64.getUrlDecoder().decode(text)

    /** Decodes lowercase hex. */
    fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "hex text must have an even length" }

        return ByteArray(text.length / 2) { index ->
            val high = Character.digit(text[index * 2], 16)
            val low = Character.digit(text[index * 2 + 1], 16)

            require(high >= 0 && low >= 0) { "invalid hex at index ${index * 2}" }

            ((high shl 4) or low).toByte()
        }
    }
}

/**
 * A parsed JSON value.
 *
 * A sealed hierarchy rather than a `JsonElement` wrapper: it makes an unhandled case a
 * compile error, and it lets a missing property throw with the property's name rather
 * than producing a default that a test then asserts against.
 */
sealed interface JsonValue {
    /** An object. */
    data class Obj(val entries: LinkedHashMap<String, JsonValue>) : JsonValue

    /** An array. */
    data class Arr(val items: List<JsonValue>) : JsonValue

    /** A string. */
    data class Str(val value: String) : JsonValue

    /** A number, held as a Long when it is integral and a Double otherwise. */
    data class Num(val value: Double, val integral: Long?) : JsonValue

    /** A boolean. */
    data class Bool(val value: Boolean) : JsonValue

    /** Null. */
    data object Nul : JsonValue

    /**
     * This value as a string.
     *
     * A number is rendered rather than rejected, because the vectors carry numeric fields
     * (a port, an API level) that a test compares against a string, and forcing every call site
     * to branch on `Num` first would put the same branch in a dozen tests. A non-scalar is a
     * fixture mistake and throws with the type's name.
     */
    fun asString(): String = when (this) {
        is Str -> value
        is Num -> integral?.toString() ?: value.toString()
        is Bool -> value.toString()
        else -> throw ClassCastException("cannot read $this as a string")
    }

    /**
     * This value as a string, or `null` when it is cbOR/JSON `null`.
     *
     * Needed because a vector's `expected_error` is present and `null` for the vectors that are
     * declared to succeed. Kotlin's `?.` does not help there: the property exists, so the safe
     * call proceeds, and what it reaches is [Nul] rather than a missing value. The alternative
     * -- testing `is JsonValue.Nul` at every call site -- puts the same three-line branch in a
     * dozen tests, and one test that forgot it crashed on the *fixture* rather than the rule
     * (see `MalformedTest.everyRawFrameVectorMatchesItsDeclaredOutcome`).
     *
     * @return the string, or `null` for an explicit null.
     */
    fun asStringOrNull(): String? = if (this is Nul) null else asString()

    /** This value as an integer. */
    fun asInt(): Int = (this as Num).let { it.integral?.toInt() ?: it.value.toInt() }

    /** This value as a long. */
    fun asLong(): Long = (this as Num).let { it.integral ?: it.value.toLong() }

    /** This value as a boolean. */
    fun asBoolean(): Boolean = (this as Bool).value

    /** This value as an array. */
    fun asArray(): List<JsonValue> = (this as Arr).items

    /**
     * This value as an object, keyed by property name.
     *
     * Returns a plain map rather than the `Obj` so that a caller which only wants the entries
     * -- to check a set of names, or to compare two objects by key -- does not depend on the
     * `Obj` type and cannot accidentally mutate the parsed document.
     */
    fun asObject(): Map<String, JsonValue> = (this as Obj).entries.toMap()

    /**
     * The property of an object, or `null` when this is not an object or the key is absent.
     *
     * Declared on the interface rather than only on [Obj] because the parser returns a
     * `JsonValue`, and a caller that has just loaded a file starts from one. With the operator
     * on `Obj` alone, `loaded["vectors"]` does not compile -- which is one of the errors the
     * module shipped with, and the reason this is here rather than on the subclass where it
     * looks tidier.
     *
     * @param key the property name.
     * @return the value, or `null`.
     */
    operator fun get(key: String): JsonValue? = (this as? Obj)?.entries?.get(key)

    /**
     * The property of an object, or a failure naming it.
     *
     * @param key the property name.
     * @return the value.
     */
    fun require(key: String): JsonValue =
        get(key) ?: throw NoSuchElementException("no property \"$key\" in $this")
}

/**
 * A minimal JSON parser for the vector files.
 *
 * It handles the subset the vectors use and rejects the rest. That is deliberate: a
 * fixture that quietly tolerated a construct would hide a mistake in the vector, and the
 * vectors are normative, so a mistake in one is a mistake in the specification.
 */
private class JsonParser(private val text: String) {
    private var index = 0

    /** Parses the whole document. */
    fun parse(): JsonValue {
        skipWhitespace()
        val value = parseValue()
        skipWhitespace()

        require(index == text.length) {
            "unexpected trailing content at index $index"
        }

        return value
    }

    private fun parseValue(): JsonValue {
        skipWhitespace()

        require(index < text.length) { "unexpected end of input" }

        return when (text[index]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> JsonValue.Str(parseString())
            't' -> parseLiteral("true", JsonValue.Bool(true))
            'f' -> parseLiteral("false", JsonValue.Bool(false))
            'n' -> parseLiteral("null", JsonValue.Nul)
            else -> parseNumber()
        }
    }

    private fun parseObject(): JsonValue {
        index++ // {
        skipWhitespace()

        val entries = LinkedHashMap<String, JsonValue>()

        if (index < text.length && text[index] == '}') {
            index++
            return JsonValue.Obj(entries)
        }

        while (true) {
            skipWhitespace()
            val key = parseString()
            skipWhitespace()

            require(index < text.length && text[index] == ':') {
                "expected ':' after the key \"$key\" at index $index"
            }

            index++
            val value = parseValue()

            // A duplicate key in a normative vector file is refused rather than
            // last-one-wins, the same rule the cbOR reader applies for the same reason.
            require(!entries.containsKey(key)) { "duplicate key \"$key\" in a JSON object" }

            entries[key] = value

            skipWhitespace()
            require(index < text.length) { "unterminated object" }

            when (text[index]) {
                ',' -> index++
                '}' -> {
                    index++
                    return JsonValue.Obj(entries)
                }

                else -> error("expected ',' or '}' at index $index")
            }
        }
    }

    private fun parseArray(): JsonValue {
        index++ // [
        skipWhitespace()

        val items = mutableListOf<JsonValue>()

        if (index < text.length && text[index] == ']') {
            index++
            return JsonValue.Arr(items)
        }

        while (true) {
            items.add(parseValue())
            skipWhitespace()

            require(index < text.length) { "unterminated array" }

            when (text[index]) {
                ',' -> index++
                ']' -> {
                    index++
                    return JsonValue.Arr(items)
                }

                else -> error("expected ',' or ']' at index $index")
            }
        }
    }

    private fun parseString(): String {
        require(index < text.length && text[index] == '"') {
            "expected a string at index $index"
        }

        index++
        val out = StringBuilder()

        while (true) {
            require(index < text.length) { "unterminated string" }
            val char = text[index++]

            when {
                char == '"' -> return out.toString()

                char == '\\' -> {
                    require(index < text.length) { "unterminated escape" }

                    when (val escaped = text[index++]) {
                        '"' -> out.append('"')
                        '\\' -> out.append('\\')
                        '/' -> out.append('/')
                        'b' -> out.append('\b')
                        'f' -> out.append('\u000C')
                        'n' -> out.append('\n')
                        'r' -> out.append('\r')
                        't' -> out.append('\t')

                        'u' -> {
                            require(index + 4 <= text.length) { "truncated \\u escape" }
                            val code = text.substring(index, index + 4).toInt(16)
                            index += 4
                            out.append(code.toChar())
                        }

                        else -> error("unknown escape \\$escaped at index ${index - 1}")
                    }
                }

                else -> out.append(char)
            }
        }
    }

    private fun parseLiteral(literal: String, value: JsonValue): JsonValue {
        require(text.startsWith(literal, index)) { "expected $literal at index $index" }
        index += literal.length
        return value
    }

    private fun parseNumber(): JsonValue {
        val start = index

        if (index < text.length && (text[index] == '-' || text[index] == '+')) index++

        while (index < text.length && text[index].isDigit()) index++

        var integral = true

        if (index < text.length && text[index] == '.') {
            integral = false
            index++
            while (index < text.length && text[index].isDigit()) index++
        }

        if (index < text.length && (text[index] == 'e' || text[index] == 'E')) {
            integral = false
            index++

            if (index < text.length && (text[index] == '-' || text[index] == '+')) index++

            while (index < text.length && text[index].isDigit()) index++
        }

        val slice = text.substring(start, index)
        require(slice.isNotEmpty()) { "expected a number at index $start" }

        return if (integral) {
            JsonValue.Num(slice.toDouble(), slice.toLong())
        } else {
            JsonValue.Num(slice.toDouble(), null)
        }
    }

    private fun skipWhitespace() {
        while (index < text.length && text[index].isWhitespace()) index++
    }
}
