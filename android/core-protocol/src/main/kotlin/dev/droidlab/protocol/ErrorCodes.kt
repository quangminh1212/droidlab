package dev.droidlab.protocol

// GENERATED FROM protocol/registry/dlwp-1.json -- DO NOT EDIT BY HAND.
//
// Regenerate with:  node protocol/tools/generate-kotlin-error-codes.cjs
//
// The registry is normative and this file is derived from it, so a change to an
// error code is a change to the registry and then a regeneration. Hand-editing
// here would create a second source of truth, and the copy that is not checked is
// the one that drifts.

/**
 * The DLWP/1 error codes (RFC-0001 section 6).
 */
enum class ErrorCode(val wireName: String, val severity: Severity) {
    /** `ERR_UNSUPPORTED_MESSAGE` -- recoverable. */
    UNSUPPORTED_MESSAGE("ERR_UNSUPPORTED_MESSAGE", Severity.Recoverable),

    /** `ERR_UNSUPPORTED_FEATURE` -- recoverable. */
    UNSUPPORTED_FEATURE("ERR_UNSUPPORTED_FEATURE", Severity.Recoverable),

    /** `ERR_UNSUPPORTED_HEADER` -- fatal. */
    UNSUPPORTED_HEADER("ERR_UNSUPPORTED_HEADER", Severity.Fatal),

    /** `ERR_FRAME_TOO_LARGE` -- fatal. */
    FRAME_TOO_LARGE("ERR_FRAME_TOO_LARGE", Severity.Fatal),

    /** `ERR_MALFORMED` -- fatal. */
    MALFORMED("ERR_MALFORMED", Severity.Fatal),

    /** `ERR_VERSION_MISMATCH` -- fatal. */
    VERSION_MISMATCH("ERR_VERSION_MISMATCH", Severity.Fatal),

    /** `ERR_HANDSHAKE_MISMATCH` -- fatal. */
    HANDSHAKE_MISMATCH("ERR_HANDSHAKE_MISMATCH", Severity.Fatal),

    /** `ERR_UNAUTHORIZED` -- fatal. */
    UNAUTHORIZED("ERR_UNAUTHORIZED", Severity.Fatal),

    /** `ERR_PAIRING_REQUIRED` -- fatal. */
    PAIRING_REQUIRED("ERR_PAIRING_REQUIRED", Severity.Fatal),

    /** `ERR_PAIRING_REVOKED` -- fatal. */
    PAIRING_REVOKED("ERR_PAIRING_REVOKED", Severity.Fatal),

    /** `ERR_REPLAY_DETECTED` -- fatal. */
    REPLAY_DETECTED("ERR_REPLAY_DETECTED", Severity.Fatal),

    /** `ERR_BAD_STATE` -- recoverable. */
    BAD_STATE("ERR_BAD_STATE", Severity.Recoverable),

    /** `ERR_UNEXPECTED_MESSAGE` -- fatal. */
    UNEXPECTED_MESSAGE("ERR_UNEXPECTED_MESSAGE", Severity.Fatal),

    /** `ERR_CHANNEL_UNKNOWN` -- recoverable. */
    CHANNEL_UNKNOWN("ERR_CHANNEL_UNKNOWN", Severity.Recoverable),

    /** `ERR_CHANNEL_LIMIT` -- recoverable. */
    CHANNEL_LIMIT("ERR_CHANNEL_LIMIT", Severity.Recoverable),

    /** `ERR_PERMISSION_DENIED` -- recoverable. */
    PERMISSION_DENIED("ERR_PERMISSION_DENIED", Severity.Recoverable),

    /** `ERR_NOT_ALLOWED` -- recoverable. */
    NOT_ALLOWED("ERR_NOT_ALLOWED", Severity.Recoverable),

    /** `ERR_TIMEOUT` -- recoverable. */
    TIMEOUT("ERR_TIMEOUT", Severity.Recoverable),

    /** `ERR_BUSY` -- recoverable. */
    BUSY("ERR_BUSY", Severity.Recoverable),

    /** `ERR_RESOURCE_EXHAUSTED` -- recoverable. */
    RESOURCE_EXHAUSTED("ERR_RESOURCE_EXHAUSTED", Severity.Recoverable),

    /** `ERR_IO` -- recoverable. */
    IO("ERR_IO", Severity.Recoverable),

    /** `ERR_INTERNAL` -- fatal. */
    INTERNAL("ERR_INTERNAL", Severity.Fatal),
    ;

    /**
     * Whether this error ends the session.
     *
     * Fatal errors must be followed by SESSION_END and the connection must close.
     * A recoverable one aborts only the affected operation or channel, and the
     * session continues, which is what makes the difference worth modelling rather
     * than leaving to each call site to decide.
     */
    val isFatal: Boolean get() = severity == Severity.Fatal

    companion object {
        private val byWireName: Map<String, ErrorCode> = entries.associateBy { it.wireName }

        /**
         * Finds a code by its wire name.
         *
         * @param wireName the name, as it appears on the wire and in the registry.
         * @return the code, or null when it is not one this version knows.
         */
        fun fromWireName(wireName: String): ErrorCode? = byWireName[wireName]
    }
}

/**
 * The three severities the registry defines.
 */
enum class Severity {
    /** Informational; the session continues. */
    Warning,

    /** Aborts only the affected operation or channel; the session continues. */
    Recoverable,

    /** Must be followed by SESSION_END, and the sender must close the connection. */
    Fatal,
}
