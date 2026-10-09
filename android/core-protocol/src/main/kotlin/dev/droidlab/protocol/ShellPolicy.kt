package dev.droidlab.protocol

/**
 * The shell policy, in executable form.
 *
 * **No shell is ever used.** Every rule names an executable and a literal argument vector, and
 * the agent executes exactly that vector with no interpreter in between. That is the single
 * decision everything else here follows from: there is no string to escape, no metacharacter to
 * expand, and no quoting rule to get wrong, because there is no place a string could be
 * reinterpreted. A command that looks like it contains a metacharacter is not sanitised -- its
 * argument simply fails to match the rule's pattern, and it is refused.
 *
 * Three separate facts decide a verdict, and the reason codes exist to keep them apart:
 *
 * 1. **The operator's grant.** Whether shell is enabled at all for this pairing, and at which
 *    level. This is checked first and it is the only fact that yields `denied_by_operator`,
 *    because it is the only one an operator can change.
 * 2. **The deny list.** Bare executable basenames. A deny entry always wins, is checked before
 *    any rule matching, and yields `deny_listed`.
 * 3. **The allow list for the context**, then the rule's own argument patterns. A path outside
 *    the vetted directories or a binary with no rule yields `not_in_allow_list`; a binary WITH a
 *    rule whose argument vector does not match yields `argument_rejected`.
 *
 * The last distinction is the one worth stating, because collapsing it is the easy mistake and
 * it sends the operator the wrong way. `not_in_allow_list` means "this context does not permit
 * this rule" and the remedy is to change the grant. `argument_rejected` means "it does" and the
 * remedy is to fix the argument.
 */
object ShellPolicy {
    /** The directories an executable may come from. Nothing else is executed, ever. */
    val VETTED_DIRECTORIES = listOf("/system/bin/", "/system/xbin/")

    /** The longest command line, in bytes, that the policy will consider. */
    const val MAX_COMMAND_LINE_BYTES = 4096

    /**
     * The exit code an interrupted command reports.
     *
     * 128 + 9, which is SIGKILL, and it is reported rather than a bare failure because the
     * controller has to tell a timeout apart from a command that ran and failed.
     */
    const val TIMEOUT_EXIT_CODE = 137

    /** The most output an execution may produce before the rest is discarded. */
    const val OUTPUT_CAP_BYTES = 4_194_304

    /** The fewest audit entries the device must retain. */
    const val MINIMUM_RETAINED_AUDIT_ENTRIES = 500

    /** The rejections that suspend shell for a pairing, and the window they are counted in. */
    const val SUSPENSION_THRESHOLD = 20

    /** The window the rejections are counted in. */
    const val SUSPENSION_WINDOW_SECONDS = 60

    /** How long a pairing's shell stays suspended once the threshold is reached. */
    const val SUSPENSION_DURATION_SECONDS = 300

    /** The fields every audit entry carries, executed or blocked. */
    val REQUIRED_AUDIT_FIELDS = listOf(
        "timestamp",
        "rule_id",
        "exe",
        "args",
        "exit_code",
        "controller_fingerprint",
        "blocked",
    )

    /**
     * Why a command was refused.
     *
     * The wire names are the reason codes in the vector file, and they are attached to the events
     * rather than produced by a formatter, so a code cannot be spelled one way in the policy and
     * another in a log.
     */
    enum class Rejection(val wireName: String) {
        /** The operator has not enabled shell for this pairing, or revoked it. */
        DENIED_BY_OPERATOR("denied_by_operator"),

        /** The executable's basename is on the deny list. */
        DENY_LISTED("deny_listed"),

        /** No rule for this executable applies in this context. */
        NOT_IN_ALLOW_LIST("not_in_allow_list"),

        /** A rule applies, but the argument vector does not match its patterns. */
        ARGUMENT_REJECTED("argument_rejected"),
    }

    /** How much a grant permits. */
    enum class AllowLevel {
        /** Only rules that do not mutate device state. */
        READ_ONLY,

        /** Also the rules that do. */
        READ_WRITE,
        ;

        /** Whether a rule of the given mutability is permitted at this level. */
        fun permits(mutating: Boolean): Boolean = !mutating || this == READ_WRITE
    }

    /**
     * One rule: an executable, a literal argument prefix, and patterns for the rest.
     *
     * @param id the rule's name, which is what the audit log records.
     * @param executable the absolute path.
     * @param argvPrefix the literal arguments that must appear first, matched exactly.
     * @param maxArgs how many arguments may follow the prefix.
     * @param argPatterns one pattern per argument after the prefix.
     * @param timeoutMs the rule's own deadline, because a log read and a package install do not
     *   deserve the same one.
     * @param mutating whether the rule changes device state. This is what the allow LEVEL gates,
     *   independently of whether the rule is in the context's allow list.
     */
    data class Rule(
        val id: String,
        val executable: String,
        val argvPrefix: List<String>,
        val maxArgs: Int,
        val argPatterns: List<String>,
        val timeoutMs: Int,
        val mutating: Boolean,
    )

    /**
     * The operator's grant for one pairing.
     *
     * @param shellGranted whether shell is enabled at all.
     * @param allowLevel how much is permitted when it is.
     * @param allowedRules the rules permitted in this context.
     * @param deniedRules the executable basenames always refused.
     * @param allowStdin always false: there is no shell, so there is nothing to feed.
     * @param maxCommandLineBytes the context's own cap, which cannot exceed [MAX_COMMAND_LINE_BYTES].
     */
    data class Context(
        val shellGranted: Boolean,
        val allowLevel: AllowLevel,
        val allowedRules: Set<String>,
        val deniedRules: Set<String>,
        val allowStdin: Boolean = false,
        val maxCommandLineBytes: Int = MAX_COMMAND_LINE_BYTES,
    )

    /** What the policy decided. */
    sealed interface Verdict {
        /** The command may run under `rule`. */
        data class Allowed(val rule: Rule) : Verdict

        /** The command must not run. */
        data class Rejected(val code: ErrorCode, val reason: Rejection) : Verdict
    }

    /**
     * Decides whether a command may run.
     *
     * @param context the grant.
     * @param rules every rule the agent knows. Kept as a parameter rather than a field so the
     *   policy is a pure function and a test can drive it with the vectors' own rules.
     * @param executable the command's absolute path.
     * @param arguments the argument vector, exactly as it will be passed to the process.
     * @return the verdict.
     */
    fun evaluate(
        context: Context,
        rules: List<Rule>,
        executable: String,
        arguments: List<String>,
    ): Verdict {
        // 1. The operator's grant, first and alone. It is the only fact that yields
        //    denied_by_operator, because it is the only one the operator can change, and
        //    reporting a missing grant as a missing rule would send them hunting in the wrong
        //    place.
        if (!context.shellGranted) {
            return Verdict.Rejected(ErrorCode.PERMISSION_DENIED, Rejection.DENIED_BY_OPERATOR)
        }

        val basename = executable.substringAfterLast('/')

        // 2. The deny list, before any rule matching and by BASENAME. A deny entry wins over an
        //    allow entry in the same context, which is what makes it a deny list rather than a
        //    tie-break: the two are never compared.
        //
        //    Checked by basename rather than by path because the point is to refuse the
        //    EXECUTABLE, and a rule cannot vouch for a binary the policy has specifically
        //    excluded -- including when the path differs, which is the case the basename form
        //    catches and a path form does not.
        //
        //    An EMPTY basename is deliberately not folded in here. It is refused by the path
        //    check below as not_in_allow_list, and my first version reported deny_listed for it --
        //    naming a deny rule that does not exist.
        if (context.deniedRules.contains(basename)) {
            return Verdict.Rejected(ErrorCode.NOT_ALLOWED, Rejection.DENY_LISTED)
        }

        // 3. The path must be absolute and in a vetted directory. Checked before the rules, so a
        //    binary dropped in /data/local/tmp is refused even when something with its name is
        //    allow-listed elsewhere.
        if (!isVettedPath(executable)) {
            return Verdict.Rejected(ErrorCode.NOT_ALLOWED, Rejection.NOT_IN_ALLOW_LIST)
        }

        // 4. The command line cap. Checked before a pattern is applied, because a pathological
        //    argument must be refused in bounded time and the cap is what makes that true without
        //    relying on the regex engine. The vector that pins this is explicit that the cap is
        //    what rejects it, not a backtracking limit.
        if (commandLineLength(executable, arguments) > context.maxCommandLineBytes) {
            return Verdict.Rejected(ErrorCode.NOT_ALLOWED, Rejection.ARGUMENT_REJECTED)
        }

        // 5. The allow list for this context, filtered by the level and identified by the RULE,
        //    which includes its argv prefix.
        //
        //    The prefix is part of what makes a rule that rule, NOT part of its argument checking.
        //    `dumpsys window2` does not match the `window` rule, and no other rule for `dumpsys`
        //    applies, so NO RULE APPLIES and the verdict is not_in_allow_list. My first version
        //    checked the prefix in the argument stage and reported argument_rejected, which says a
        //    rule applied and its argument was wrong -- a different fact with a different remedy,
        //    and the vectors answer not_in_allow_list.
        //
        //    A mutating rule in a read_only context is likewise NOT in that context's list, which
        //    is why the level gate also yields not_in_allow_list: the level is a property of the
        //    grant, not of the argument.
        val applicable = rules.filter { rule ->
            context.allowedRules.contains(rule.id) &&
                context.allowLevel.permits(rule.mutating) &&
                signatureMatches(rule, executable, arguments)
        }

        if (applicable.isEmpty()) {
            return Verdict.Rejected(ErrorCode.NOT_ALLOWED, Rejection.NOT_IN_ALLOW_LIST)
        }

        // 6. A rule applies, so its ARGUMENTS are now checked against its patterns. Only here
        //    does a mismatch become argument_rejected. Trying all of them rather than the first is
        //    what lets `dumpsys window` and `dumpsys meminfo` be two rules over one executable;
        //    stopping at the first would make the verdict depend on the order they were listed in.
        val matched = applicable.firstOrNull { rule -> argumentsMatch(rule, executable, arguments) }

        if (matched == null) {
            // A rule applied and its arguments did not match. This is a DIFFERENT fact from "no
            // rule", and the remedy differs, so it gets a different reason code.
            return Verdict.Rejected(ErrorCode.NOT_ALLOWED, Rejection.ARGUMENT_REJECTED)
        }

        return Verdict.Allowed(matched)
    }

    /**
     * Whether an executable is an absolute path inside a vetted directory.
     *
     * The path is separated into its directory and its basename, and the DIRECTORY is compared
     * for EQUALITY against the vetted list. That is the whole rule, and it is deliberately two
     * tests and no more.
     *
     * The longer version this replaced checked four things: that the path was absolute, that its
     * basename was not `.`/`..`/empty, that it contained no `..` segment, and that it contained no
     * double slash. Driving every one of them against every input shape showed that three changed
     * no answer: once the directory is compared for equality, a relative path, a traversal path
     * and a doubled slash all name a directory that is not a vetted one, so the comparison
     * refuses them without help. Only the basename test changed anything, and only for a path
     * like `/system/bin/`, whose directory IS vetted but whose basename is empty.
     *
     * The redundant three were removed rather than kept as decoration, because a guard that no
     * input can distinguish from its absence is a guard that will silently stop working the day
     * the comparison below changes -- and a mutation test rightly reports it as one that survives.
     *
     * Nothing here RESOLVES the path. Resolving is exactly what an attacker wants:
     * `/system/bin/../../data/local/tmp/payload` resolves into a vetted directory and then out of
     * it, and a resolver with a bug is a check with a bug. Comparing the literal directory
     * segment cannot be walked past, because `..` is a directory name that is not on the list.
     */
    fun isVettedPath(executable: String): Boolean {
        val lastSlash = executable.lastIndexOf('/')

        // There must be a directory to compare, and something after it. A path with no separator
        // (`getprop`) or a separator at position zero (`/getprop`) has no vetted directory.
        if (lastSlash <= 0) return false

        val directory = executable.substring(0, lastSlash + 1)
        val basename = executable.substring(lastSlash + 1)

        // The basename must name a program. `.` and `..` name directories, and an empty basename
        // means the path ended at a separator -- which matters because `/system/bin/` has a
        // vetted DIRECTORY and would otherwise be accepted as an executable.
        if (basename.isEmpty() || basename == "." || basename == "..") return false

        // The comparison is for EQUALITY on the directory, not `startsWith` on the whole path. A
        // `startsWith` test accepts `/system/binfoo/bar`, whose leading characters merely spell a
        // vetted directory, and accepts the vetted directory itself.
        return VETTED_DIRECTORIES.contains(directory)
    }

    /**
     * Whether a rule is the rule for this command: the executable and the literal argv prefix.
     *
     * This is what IDENTIFIES the rule, so its failure means no rule applies at all. The prefix is
     * matched literally and exactly, at the front, and there is no interpretation of any argument:
     * this compares strings, and a string containing a semicolon is a string containing a
     * semicolon.
     */
    fun signatureMatches(rule: Rule, executable: String, arguments: List<String>): Boolean {
        if (rule.executable != executable) return false

        // The prefix must be present, in order and exact.
        if (arguments.size < rule.argvPrefix.size) return false

        for ((index, expected) in rule.argvPrefix.withIndex()) {
            if (arguments[index] != expected) return false
        }

        return true
    }

    /**
     * Whether a rule's arguments match, given that its signature already has.
     *
     * Only a failure here is `argument_rejected`, because only here is there a rule that applies.
     */
    fun argumentsMatch(rule: Rule, executable: String, arguments: List<String>): Boolean {
        if (!signatureMatches(rule, executable, arguments)) return false

        val rest = arguments.drop(rule.argvPrefix.size)

        // The count is capped as well as each argument, so a rule cannot be turned into a
        // denial-of-service by a sufficiently long argument vector even when every element is
        // individually acceptable.
        if (rest.size > rule.maxArgs) return false

        for ((index, argument) in rest.withIndex()) {
            val pattern = rule.argPatterns.getOrNull(index)

            // A rule with fewer patterns than arguments it permits would accept an unconstrained
            // argument, so the missing pattern is a refusal rather than a pass.
            if (pattern == null) return false

            if (!Regex(pattern).matches(argument)) return false
        }

        return true
    }

    /** Both halves, for a caller that wants the whole answer. */
    fun matches(rule: Rule, executable: String, arguments: List<String>): Boolean =
        signatureMatches(rule, executable, arguments) && argumentsMatch(rule, executable, arguments)

    /**
     * The command line's length in bytes.
     *
     * Counted as the bytes the process would receive, which is what the cap is about, rather than
     * as characters: a multi-byte character is more than one byte of command line, and counting
     * characters would let a 4096-character argument exceed the limit.
     */
    fun commandLineLength(executable: String, arguments: List<String>): Int {
        val separatorBytes = arguments.size

        return executable.toByteArray(Charsets.UTF_8).size +
            arguments.sumOf { it.toByteArray(Charsets.UTF_8).size } +
            separatorBytes
    }

    /**
     * How many bytes of output are kept.
     *
     * Truncating rather than refusing is deliberate: the first four megabytes of a log are useful
     * and the alternative is to return nothing at all. The exit code is preserved and the
     * truncation is flagged, so the controller can say what happened rather than silently
     * reporting a shorter output as if it were complete.
     */
    fun retainedOutputBytes(produced: Int): Int = minOf(produced, OUTPUT_CAP_BYTES)

    /** Whether output of this size was truncated. */
    fun isTruncated(produced: Int): Boolean = produced > OUTPUT_CAP_BYTES

    /**
     * Whether a pairing's shell is suspended after this many rejections.
     *
     * The count is of REJECTIONS, not of commands: a session that issues a hundred accepted
     * commands and gets one refused is not an attacker, and a session that gets twenty refused in
     * a minute is worth stopping whatever its intentions.
     */
    fun isSuspended(rejectionsInWindow: Int): Boolean = rejectionsInWindow >= SUSPENSION_THRESHOLD
}
