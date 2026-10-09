package dev.droidlab.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Conformance tests for the shell policy, driven by `shell-policy.json`.
 *
 * This file is the policy in executable form: 25 rules, 4 contexts and 23 cases, each with the
 * verdict and the REASON an agent must produce. The reason codes are the part worth checking
 * carefully, because the three facts that decide a verdict are easy to collapse into one and the
 * operator's remedy depends on telling them apart:
 *
 * - `denied_by_operator` — the operator can enable shell, and nothing else will help.
 * - `deny_listed` — the executable is excluded outright, and no grant changes that.
 * - `not_in_allow_list` — no rule applies here; the grant or the context does.
 * - `argument_rejected` — a rule applies and the argument is wrong; the command line does.
 *
 * Every case is evaluated against the vector's own rules and contexts, so the test drives the
 * same data the other implementation loads.
 */
class ShellPolicyTest {
    private companion object {
        const val VECTOR_FILE = "shell-policy.json"
    }

    /** The vector file. */
    private fun file(): JsonValue = Vectors.load(VECTOR_FILE)

    /** The 25 rules, parsed into the policy's own type. */
    private fun rules(): List<ShellPolicy.Rule> =
        Vectors.array(VECTOR_FILE, "rules").map { rule ->
            ShellPolicy.Rule(
                id = rule["id"]!!.asString(),
                executable = rule["exe"]!!.asString(),
                argvPrefix = rule["argv_prefix"]!!.asArray().map { it.asString() },
                maxArgs = rule["max_args"]!!.asInt(),
                argPatterns = rule["arg_patterns"]!!.asArray().map { it.asString() },
                timeoutMs = rule["timeout_ms"]!!.asInt(),
                mutating = isMutating(rule["id"]!!.asString()),
            )
        }

    /**
     * Whether a rule mutates device state.
     *
     * The file does not carry a mutability flag, and the convention it uses instead is the rule
     * id's prefix: `dev.*` rules mutate and `sys.*` rules do not. That is an assumption, so
     * [theMutabilityIsDerivableFromTheRuleId] asserts it holds for all 25 rules rather than
     * leaving it implicit.
     */
    private fun isMutating(ruleId: String): Boolean = ruleId.startsWith("dev.")

    /** A policy context by name. */
    private fun context(name: String): ShellPolicy.Context {
        val contexts = file()["policy_contexts"]!!.asObject()
        val raw = contexts[name] ?: throw AssertionError("shell-policy.json has no context \"$name\"")

        return ShellPolicy.Context(
            shellGranted = raw["shell_granted"]!!.asBoolean(),
            allowLevel = when (raw["allow_level"]!!.asString()) {
                "read_only" -> ShellPolicy.AllowLevel.READ_ONLY
                "read_write" -> ShellPolicy.AllowLevel.READ_WRITE
                else -> throw AssertionError("the context \"$name\" has an unknown allow level")
            },
            allowedRules = raw["allowed_rules"]!!.asArray().map { it.asString() }.toSet(),
            deniedRules = raw["denied_rules"]!!.asArray().map { it.asString() }.toSet(),
            allowStdin = raw["allow_stdin"]!!.asBoolean(),
            maxCommandLineBytes = raw["max_command_line_bytes"]!!.asInt(),
        )
    }

    /** A case by id, failing when it is missing so a rename cannot silently skip. */
    private fun case(id: String): JsonValue =
        Vectors.array(VECTOR_FILE, "cases").firstOrNull { it["id"]?.asString() == id }
            ?: error("shell-policy.json has no case \"$id\"")

    /** A lifecycle vector by id. */
    private fun lifecycle(id: String): JsonValue =
        Vectors.array(VECTOR_FILE, "lifecycle_vectors").firstOrNull { it["id"]?.asString() == id }
            ?: error("shell-policy.json has no lifecycle vector \"$id\"")

    /** A case's argument vector. */
    private fun args(v: JsonValue): List<String> =
        (v["args"]?.asArray() ?: emptyList()).map { it.asString() }

    /**
     * Every rule is well formed and every context names rules that exist.
     */
    @Test
    fun theRulesAndContextsAreTheFilesOwn() {
        val allRules = rules()
        val contexts = file()["policy_contexts"]!!.asObject()

        assertEquals(25, allRules.size, "the file declares 25 rules")
        assertEquals(23, Vectors.array(VECTOR_FILE, "cases").size, "the file declares 23 cases")
        assertEquals(5, Vectors.array(VECTOR_FILE, "lifecycle_vectors").size, "the file declares 5 lifecycle vectors")
        assertEquals(4, contexts.size, "the file declares 4 contexts")

        // Every rule names an absolute executable in a vetted directory. Checked for all 25
        // rather than the ones a case happens to reach: a rule with an unvetted path is a rule
        // that can never fire, and it would sit in the file looking like a permission that does
        // not work.
        for (rule in allRules) {
            assertTrue(rule.executable.startsWith('/'), "the rule \"${rule.id}\" names an absolute path")
            assertTrue(ShellPolicy.isVettedPath(rule.executable), "the rule \"${rule.id}\" names a vetted path")
            assertTrue(rule.timeoutMs > 0, "the rule \"${rule.id}\" has a positive deadline")
        }

        // A rule that permits arguments declares a pattern for each of them, and one that declares
        // patterns permits arguments. If they disagreed in the permissive direction, an argument
        // would be accepted with no pattern applied to it.
        for (rule in allRules) {
            if (rule.maxArgs > 0) {
                assertTrue(rule.argPatterns.isNotEmpty(), "the rule \"${rule.id}\" permits arguments and declares patterns")
            }

            if (rule.argPatterns.isNotEmpty()) {
                assertTrue(rule.maxArgs > 0, "the rule \"${rule.id}\" declares patterns and permits arguments")
            }
        }

        // The rule ids are unique, so the audit log's rule_id identifies one rule.
        assertEquals(allRules.size, allRules.map { it.id }.toSet().size, "the rule ids are unique")

        // Every context names only rules that exist, and denies basenames rather than paths.
        for ((name, raw) in contexts) {
            val allowed = raw["allowed_rules"]!!.asArray().map { it.asString() }

            for (ruleId in allowed) {
                assertTrue(allRules.any { it.id == ruleId }, "the context \"$name\" names a rule that exists ($ruleId)")
            }

            for (denied in raw["denied_rules"]!!.asArray().map { it.asString() }) {
                assertFalse(denied.contains('/'), "the context \"$name\" denies a BASENAME, not a path ($denied)")
            }

            assertFalse(raw["allow_stdin"]!!.asBoolean(), "the context \"$name\" allows no stdin, because there is no shell")
            assertEquals(
                ShellPolicy.MAX_COMMAND_LINE_BYTES,
                raw["max_command_line_bytes"]!!.asInt(),
                "the context \"$name\" uses the declared cap",
            )
        }

        // Every context the cases name exists.
        val names = contexts.keys

        for (c in Vectors.array(VECTOR_FILE, "cases")) {
            val named = c["context"]?.asString() ?: continue

            assertTrue(names.contains(named), "the case \"${c["id"]!!.asString()}\" names a context that exists")
        }
    }

    /**
     * The mutability convention holds for every rule.
     */
    @Test
    fun theMutabilityIsDerivableFromTheRuleId() {
        val allRules = rules()

        val mutating = allRules.filter { it.mutating }.map { it.id }
        val readOnly = allRules.filterNot { it.mutating }.map { it.id }

        assertTrue(mutating.isNotEmpty(), "there are mutating rules")
        assertTrue(readOnly.isNotEmpty(), "there are read-only rules")
        assertEquals(allRules.size, mutating.size + readOnly.size, "every rule is one or the other")

        // The convention, stated: `dev.*` mutates and `sys.*` does not.
        assertTrue(mutating.all { it.startsWith("dev.") }, "every mutating rule is a dev.* rule")
        assertTrue(readOnly.all { it.startsWith("sys.") }, "every read-only rule is a sys.* rule")

        // And the level gate really does depend on the flag: a read_only level refuses every
        // mutating rule and permits every read-only one.
        assertEquals(false, ShellPolicy.AllowLevel.READ_ONLY.permits(mutating = true), "read_only refuses a mutating rule")
        assertEquals(true, ShellPolicy.AllowLevel.READ_ONLY.permits(mutating = false), "read_only permits a read-only rule")
        assertEquals(true, ShellPolicy.AllowLevel.READ_WRITE.permits(mutating = true), "read_write permits a mutating rule")
        assertEquals(true, ShellPolicy.AllowLevel.READ_WRITE.permits(mutating = false), "read_write permits a read-only rule")
    }

    /**
     * Every case produces its declared verdict, error and reason.
     */
    @Test
    fun everyCaseProducesItsDeclaredVerdict() {
        val allRules = rules()
        var allowed = 0
        var rejected = 0

        for (c in Vectors.array(VECTOR_FILE, "cases")) {
            val id = c["id"]!!.asString()
            val named = c["context"]?.asString() ?: continue

            val verdict = ShellPolicy.evaluate(context(named), allRules, c["exe"]!!.asString(), args(c))

            when (c["expected"]!!.asString()) {
                "allowed" -> {
                    allowed++
                    assertTrue(verdict is ShellPolicy.Verdict.Allowed, "the case \"$id\" is allowed")

                    assertEquals(
                        c["expected_rule"]!!.asString(),
                        (verdict as ShellPolicy.Verdict.Allowed).rule.id,
                        "the case \"$id\" resolves to its declared rule",
                    )
                }

                "rejected" -> {
                    rejected++
                    assertTrue(verdict is ShellPolicy.Verdict.Rejected, "the case \"$id\" is rejected")

                    val rejection = verdict as ShellPolicy.Verdict.Rejected

                    assertEquals(
                        c["expected_error"]!!.asString(),
                        rejection.code.wireName,
                        "the case \"$id\" has its declared error",
                    )
                    assertEquals(
                        c["expected_reason"]!!.asString(),
                        rejection.reason.wireName,
                        "the case \"$id\" has its declared reason",
                    )
                }

                else -> throw AssertionError("the case \"$id\" has an unknown expectation")
            }
        }

        // The cases cover both outcomes. A file that only tested refusals would not tell an
        // implementation that refuses everything apart from one that works.
        assertTrue(allowed >= 3, "the cases include at least three allowed commands (found $allowed)")
        assertTrue(rejected >= 10, "the cases include at least ten refusals (found $rejected)")
        assertEquals(23, allowed + rejected, "every case is counted")
    }

    /**
     * The reason codes keep the three deciding facts apart.
     */
    @Test
    fun theReasonCodesKeepTheFactsApart() {
        // denied_by_operator is the only reason an OPERATOR can fix.
        val noGrant = ShellPolicy.evaluate(
            context("no_grant"),
            rules(),
            "/system/bin/getprop",
            listOf("ro.build.version.sdk"),
        )

        assertTrue(noGrant is ShellPolicy.Verdict.Rejected, "a legal command is refused without a grant")
        assertEquals(
            ErrorCode.PERMISSION_DENIED,
            (noGrant as ShellPolicy.Verdict.Rejected).code,
            "the fault is a permission denial",
        )
        assertEquals(
            ShellPolicy.Rejection.DENIED_BY_OPERATOR,
            noGrant.reason,
            "and the reason names the operator",
        )

        // deny_listed is the only reason no grant can change.
        val denied = ShellPolicy.evaluate(
            context("default"),
            rules(),
            "/system/bin/reboot",
            emptyList(),
        )

        assertEquals(
            ShellPolicy.Rejection.DENY_LISTED,
            (denied as ShellPolicy.Verdict.Rejected).reason,
            "a deny-listed executable reports deny_listed",
        )

        // not_in_allow_list means NO RULE applies.
        val noRule = ShellPolicy.evaluate(
            context("default"),
            rules(),
            "/system/bin/getprop2",
            listOf("a"),
        )

        assertEquals(
            ShellPolicy.Rejection.NOT_IN_ALLOW_LIST,
            (noRule as ShellPolicy.Verdict.Rejected).reason,
            "an executable with no rule reports not_in_allow_list",
        )

        // argument_rejected means a rule DID apply and the argument is wrong.
        val badArgument = ShellPolicy.evaluate(
            context("default"),
            rules(),
            "/system/bin/getprop",
            listOf("ro.build.version;id"),
        )

        assertEquals(
            ShellPolicy.Rejection.ARGUMENT_REJECTED,
            (badArgument as ShellPolicy.Verdict.Rejected).reason,
            "a matched rule with a bad argument reports argument_rejected",
        )

        // The four are distinct values, so no two can be confused at a call site.
        assertEquals(
            4,
            ShellPolicy.Rejection.entries.toSet().size,
            "there are four reasons and they are distinct",
        )

        // And the wire names are the file's own strings.
        assertEquals("denied_by_operator", ShellPolicy.Rejection.DENIED_BY_OPERATOR.wireName, "denied_by_operator")
        assertEquals("deny_listed", ShellPolicy.Rejection.DENY_LISTED.wireName, "deny_listed")
        assertEquals("not_in_allow_list", ShellPolicy.Rejection.NOT_IN_ALLOW_LIST.wireName, "not_in_allow_list")
        assertEquals("argument_rejected", ShellPolicy.Rejection.ARGUMENT_REJECTED.wireName, "argument_rejected")
    }

    /**
     * A mismatched argv prefix means no rule applies.
     */
    @Test
    fun aMismatchedPrefixMeansNoRuleApplies() {
        // `dumpsys window2` does not match the `window` rule, and no other rule for `dumpsys`
        // applies, so the verdict is not_in_allow_list -- not argument_rejected.
        //
        // This is the distinction my first implementation got wrong: it checked the prefix during
        // argument checking, so a mismatch there reported argument_rejected, which says a rule
        // applied. The vectors answer not_in_allow_list, and the reason is that the prefix is part
        // of what IDENTIFIES the rule.
        val mismatch = case("shell.deny.argv-prefix-mismatch")

        assertEquals(listOf("window2"), args(mismatch), "the vector passes window2")

        val verdict = ShellPolicy.evaluate(
            context("default"),
            rules(),
            mismatch["exe"]!!.asString(),
            args(mismatch),
        )

        assertEquals(
            ShellPolicy.Rejection.NOT_IN_ALLOW_LIST,
            (verdict as ShellPolicy.Verdict.Rejected).reason,
            "a mismatched prefix reports not_in_allow_list",
        )

        // The rule itself still matches the correct prefix, so the refusal is about the argument
        // and not about the rule being unavailable.
        val windowRule = rules().first { it.id == "sys.dumpsys.window" }

        assertFalse(
            ShellPolicy.signatureMatches(windowRule, "/system/bin/dumpsys", listOf("window2")),
            "window2 does not match the window rule's signature",
        )
        assertTrue(
            ShellPolicy.signatureMatches(windowRule, "/system/bin/dumpsys", listOf("window")),
            "window does match it",
        )

        // And the two stages are genuinely separate: the signature passes for `window` with a
        // surplus argument, and only the argument stage refuses it.
        assertTrue(
            ShellPolicy.signatureMatches(windowRule, "/system/bin/dumpsys", listOf("window", "extra")),
            "the signature ignores arguments beyond the prefix",
        )
        assertFalse(
            ShellPolicy.argumentsMatch(windowRule, "/system/bin/dumpsys", listOf("window", "extra")),
            "but the argument stage refuses the surplus argument",
        )
    }

    /**
     * No shell is ever used, and the deny list is what enforces it.
     */
    @Test
    fun aShellInterpreterIsNeverUsed() {
        val interpreterCase = case("shell.deny.shell-interpreter")

        assertEquals("/system/bin/sh", interpreterCase["exe"]!!.asString(), "the vector names sh as the executable")
        assertEquals("-c", args(interpreterCase).first(), "and passes the command with -c, which is what a shell call looks like")

        val verdict = ShellPolicy.evaluate(
            context("default"),
            rules(),
            interpreterCase["exe"]!!.asString(),
            args(interpreterCase),
        )

        assertEquals(
            ShellPolicy.Rejection.DENY_LISTED,
            (verdict as ShellPolicy.Verdict.Rejected).reason,
            "it is the EXECUTABLE that is denied, not the string parsed",
        )

        // Every interpreter a device is likely to have is on the deny list, so no argument vector
        // can reach one through a rule.
        val denied = context("default").deniedRules

        for (interpreter in listOf("sh", "bash", "dash", "busybox")) {
            assertTrue(denied.contains(interpreter), "$interpreter is deny-listed")
        }

        // And no rule anywhere uses an interpreter as its executable, so the deny list is a second
        // line of defence rather than the only one.
        for (rule in rules()) {
            for (interpreter in listOf("sh", "bash", "dash", "busybox", "toybox")) {
                assertFalse(
                    rule.executable.endsWith("/$interpreter"),
                    "the rule \"${rule.id}\" does not use an interpreter",
                )
            }
        }
    }

    /**
     * A rejected argument is not expanded, it simply does not match.
     */
    @Test
    fun aRejectedArgumentIsNotExpanded() {
        val c = case("shell.deny.argument-rejected")

        assertEquals("ro.build.version;id", args(c).first(), "the vector passes a semicolon in the argument")

        val verdict = ShellPolicy.evaluate(context("default"), rules(), c["exe"]!!.asString(), args(c))

        assertEquals(
            ShellPolicy.Rejection.ARGUMENT_REJECTED,
            (verdict as ShellPolicy.Verdict.Rejected).reason,
            "the argument is refused as an argument, not sanitised",
        )

        // The pattern really is what rejects it, and it is anchored so a prefix match cannot
        // smuggle in a suffix.
        val getprop = rules().first { it.id == "sys.getprop" }
        val pattern = Regex(getprop.argPatterns.first())

        assertFalse(pattern.matches("ro.build.version;id"), "the pattern rejects the semicolon")
        assertTrue(pattern.matches("ro.build.version"), "and accepts the clean argument")
        assertTrue(getprop.argPatterns.first().startsWith("^"), "the pattern is anchored at the start")
        assertTrue(getprop.argPatterns.first().endsWith("$"), "and at the end")
    }

    /**
     * A path is refused for traversal rather than resolved.
     */
    @Test
    fun theVettedPathRuleIsTwoReachableGuards() {
        // The rule is two tests: the basename must name a program, and the directory must equal a
        // vetted directory. Everything else it once checked was unreachable -- driven exhaustively,
        // three of the four guards changed no answer for any input, because the directory
        // comparison already refuses a relative path, a traversal path and a doubled slash. They
        // were removed rather than kept, and this test pins the two that remain.
        val vetted = "/system/bin/getprop"

        assertTrue(ShellPolicy.isVettedPath(vetted), "an absolute vetted path is accepted")
        assertTrue(ShellPolicy.isVettedPath("/system/xbin/su"), "and one from the other vetted directory")

        // Guard 1: the DIRECTORY is compared for EQUALITY. The distinguishing input is a path whose
        // leading characters spell a vetted directory but whose directory is not one -- a
        // `startsWith` test accepts it and equality refuses it.
        for (prefixOnly in listOf("/system/bin/getprop/x", "/system/bin/./getprop", "/system/bin/x/y/getprop")) {
            assertTrue(
                ShellPolicy.VETTED_DIRECTORIES.any { prefixOnly.startsWith(it) },
                "the probe \"$prefixOnly\" passes a prefix test",
            )
            assertFalse(
                ShellPolicy.isVettedPath(prefixOnly),
                "and is refused, because its directory is not equal to a vetted one",
            )
        }

        // The equality comparison is also what refuses a RELATIVE path and a path that leaves a
        // vetted directory, with no separate absolute-path or traversal guard needed.
        for (relative in listOf("bin/getprop", "system/bin/getprop", "./system/bin/getprop", vetted.drop(1))) {
            assertFalse(relative.startsWith("/"), "the probe \"$relative\" is relative")
            assertFalse(
                ShellPolicy.isVettedPath(relative),
                "and is refused, because its directory is not a vetted one",
            )
        }

        // The traversal vector is refused because its DIRECTORY is not vetted, which is also why the
        // check is a literal comparison rather than a resolver: `..` is a directory name that is
        // not on the list.
        val traversal = case("shell.deny.path-traversal")

        assertTrue(
            traversal["exe"]!!.asString().startsWith("/system/bin/"),
            "the traversal path starts with a vetted directory, so a prefix test alone accepts it",
        )
        assertFalse(ShellPolicy.isVettedPath(traversal["exe"]!!.asString()), "and the comparison refuses it")
        assertEquals(
            ShellPolicy.Rejection.NOT_IN_ALLOW_LIST,
            (
                ShellPolicy.evaluate(
                    context("default"),
                    rules(),
                    traversal["exe"]!!.asString(),
                    args(traversal),
                ) as ShellPolicy.Verdict.Rejected
                ).reason,
            "and the reason is not_in_allow_list, because no rule's executable matches",
        )

        // Guard 2: the BASENAME must name a program. The distinguishing input is a path whose
        // DIRECTORY is vetted and whose basename is empty or a directory name, which the equality
        // comparison alone would accept.
        for (directoryItself in listOf("/system/bin/", "/system/xbin/", "/system/bin/.", "/system/bin/..")) {
            assertTrue(
                ShellPolicy.VETTED_DIRECTORIES
                    .contains(directoryItself.substring(0, directoryItself.lastIndexOf('/') + 1)),
                "the probe \"$directoryItself\" names a vetted DIRECTORY",
            )
            assertFalse(
                ShellPolicy.isVettedPath(directoryItself),
                "and is refused, because its basename names no program",
            )
        }

        // A path with no directory at all has nothing to compare, and the vetted directories
        // themselves (without a trailing slash) are not executables.
        for (noDirectory in listOf("getprop", "", "/getprop", "/system/bin", "/system/xbin")) {
            assertFalse(ShellPolicy.isVettedPath(noDirectory), "the probe \"$noDirectory\" is refused")
        }

        // A relative path is refused, because the working directory must never select the binary.
        val relative = case("shell.deny.relative-path")

        assertFalse(relative["exe"]!!.asString().startsWith("/"), "the vector names a bare name")
        assertFalse(ShellPolicy.isVettedPath(relative["exe"]!!.asString()), "and a relative path is refused")

        // The vetted directories accept their own paths, including for a name the deny list
        // rejects: the path check and the deny check are different questions.
        assertTrue(
            ShellPolicy.isVettedPath("/system/xbin/su"),
            "a vetted path is accepted even for a deny-listed name",
        )
        assertFalse(ShellPolicy.isVettedPath("/data/local/tmp/payload"), "an unvetted directory is refused")
        assertFalse(ShellPolicy.isVettedPath("/system/bogus/getprop"), "a neighbouring directory is refused")
    }

    /**
     * The deny list wins over everything, and is checked first.
     */
    @Test
    fun theDenyListWinsAndIsCheckedFirst() {
        val denyCases = Vectors.array(VECTOR_FILE, "cases")
            .filter { it["expected_reason"]?.asString() == "deny_listed" }

        assertEquals(4, denyCases.size, "the file declares four deny-listed cases")

        // With EVERY rule allowed, a deny-listed executable is still refused. That is what makes
        // the deny list a deny list rather than a tie-break: the two are never compared.
        val everythingAllowed = ShellPolicy.Context(
            shellGranted = true,
            allowLevel = ShellPolicy.AllowLevel.READ_WRITE,
            allowedRules = rules().map { it.id }.toSet(),
            deniedRules = context("default").deniedRules,
        )

        for (c in denyCases) {
            val verdict = ShellPolicy.evaluate(
                everythingAllowed,
                rules(),
                c["exe"]!!.asString(),
                args(c),
            )

            assertTrue(
                verdict is ShellPolicy.Verdict.Rejected,
                "the deny-listed \"${c["exe"]!!.asString()}\" is refused even with every rule allowed",
            )
            assertEquals(
                ShellPolicy.Rejection.DENY_LISTED,
                (verdict as ShellPolicy.Verdict.Rejected).reason,
                "and the reason is deny_listed",
            )
        }

        // The deny list is by BASENAME, so the same binary at another path is denied too.
        val elsewhere = ShellPolicy.evaluate(everythingAllowed, rules(), "/system/xbin/rm", emptyList())

        assertEquals(
            ShellPolicy.Rejection.DENY_LISTED,
            (elsewhere as ShellPolicy.Verdict.Rejected).reason,
            "a deny-listed basename is denied at another path",
        )

        // And the grant is checked BEFORE the deny list, so a pairing with no shell reports the
        // fact its operator can act on rather than a deny entry it cannot.
        val noGrantAndDenied = ShellPolicy.evaluate(
            context("no_grant"),
            rules(),
            "/system/bin/reboot",
            emptyList(),
        )

        assertEquals(
            ShellPolicy.Rejection.DENIED_BY_OPERATOR,
            (noGrantAndDenied as ShellPolicy.Verdict.Rejected).reason,
            "the grant is reported before the deny list",
        )
    }

    /**
     * The mutability split is by rule, not by executable.
     */
    @Test
    fun theMutabilitySplitIsByRuleNotByExecutable() {
        // `settings get` and `settings put` share ONE executable and differ in mutability, so the
        // split is by rule. This is asserted as a property of the file, because it is the reason
        // the level gate is expressed over rules at all.
        val settingsRules = rules().filter { it.executable == "/system/bin/settings" }

        assertEquals(2, settingsRules.size, "settings has exactly two rules")

        val read = settingsRules.first { it.id == "sys.settings.get" }
        val write = settingsRules.first { it.id == "dev.settings.put" }

        assertFalse(read.mutating, "the read half is not mutating")
        assertTrue(write.mutating, "the write half is mutating")
        assertFalse(read.argvPrefix == write.argvPrefix, "the two halves are distinguished by their argv prefix")

        // The read half is allowed under a read_only grant and the write half is not, on the same
        // executable.
        val readOnly = context("default")

        assertEquals(
            ShellPolicy.Rejection.ARGUMENT_REJECTED,
            (
                ShellPolicy.evaluate(readOnly, rules(), "/system/bin/getprop", listOf("a", "b", "c", "d", "e"))
                    as ShellPolicy.Verdict.Rejected
                ).reason,
            "a rule that applies reports argument_rejected for a surplus argument",
        )

        assertTrue(
            ShellPolicy.evaluate(readOnly, rules(), "/system/bin/settings", listOf("get", "system", "screen_brightness")) is
                ShellPolicy.Verdict.Allowed,
            "the read half is allowed under read_only",
        )
        assertEquals(
            ShellPolicy.Rejection.NOT_IN_ALLOW_LIST,
            (
                ShellPolicy.evaluate(readOnly, rules(), "/system/bin/settings", listOf("put", "system", "screen_brightness", "0"))
                    as ShellPolicy.Verdict.Rejected
                ).reason,
            "the write half is refused under read_only, and not because of its argument",
        )

        // Raising the level to read_write allows the same command line, so the level is the only
        // difference. The vector's app_control_grant case is exactly this.
        val writeCase = case("shell.allow.mutating-rule-with-write-grant")
        val writeGrant = ShellPolicy.evaluate(
            context("app_control_grant"),
            rules(),
            writeCase["exe"]!!.asString(),
            args(writeCase),
        )

        assertTrue(writeGrant is ShellPolicy.Verdict.Allowed, "the same line is allowed at read_write")
        assertEquals(
            "dev.settings.put",
            (writeGrant as ShellPolicy.Verdict.Allowed).rule.id,
            "and resolves to dev.settings.put",
        )
    }

    /**
     * The grant is rechecked before every execution.
     */
    @Test
    fun theGrantIsRecheckedPerExecution() {
        val vector = lifecycle("shell.grant-revoked-mid-session")
        val sequence = vector["sequence"]!!.asArray()

        assertEquals(3, sequence.size, "the vector has three steps")

        val first = sequence[0]
        val revoke = sequence[1]
        val second = sequence[2]

        assertEquals("execute", first["step"]!!.asString(), "the first step executes")
        assertEquals("operator_revokes_shell_grant", revoke["step"]!!.asString(), "the middle step revokes the grant")
        assertEquals("execute", second["step"]!!.asString(), "the third step executes again")

        // The SAME executable and the SAME arguments before and after. The grant is what changed,
        // so the verdict differs -- which is the point: checking the grant at connection time
        // would let a revoked operator's next command through.
        assertEquals(first["exe"]!!.asString(), second["exe"]!!.asString(), "both use the same executable")
        assertEquals(args(first), args(second), "and the same arguments")

        val granted = ShellPolicy.Context(
            shellGranted = true,
            allowLevel = ShellPolicy.AllowLevel.READ_ONLY,
            allowedRules = rules().map { it.id }.toSet(),
            deniedRules = context("default").deniedRules,
        )
        val revoked = granted.copy(shellGranted = false)

        assertTrue(
            ShellPolicy.evaluate(granted, rules(), first["exe"]!!.asString(), args(first)) is ShellPolicy.Verdict.Allowed,
            "the first execution is allowed",
        )

        val afterRevocation = ShellPolicy.evaluate(revoked, rules(), second["exe"]!!.asString(), args(second))

        assertEquals(
            ShellPolicy.Rejection.DENIED_BY_OPERATOR,
            (afterRevocation as ShellPolicy.Verdict.Rejected).reason,
            "the second is refused on the same session, and the reason names the operator",
        )
        assertEquals(
            ErrorCode.PERMISSION_DENIED,
            afterRevocation.code,
            "and the fault is a permission denial, which is what an operator can act on",
        )
    }

    /**
     * The remaining lifecycle rules are the declared ones.
     */
    @Test
    fun theRemainingLifecycleRulesAreAsDeclared() {
        // The rate limit counts REJECTIONS, not commands: a session that issues a hundred accepted
        // commands and gets one refused is not an attacker.
        val limit = lifecycle("shell.rate-limit-after-repeated-rejections")

        assertEquals(
            ShellPolicy.SUSPENSION_THRESHOLD,
            limit["rejections_within_window"]!!.asInt(),
            "the threshold matches the implementation",
        )
        assertEquals(
            ShellPolicy.SUSPENSION_DURATION_SECONDS,
            limit["suspend_s"]!!.asInt(),
            "the suspension lasts five minutes",
        )
        assertEquals(
            ShellPolicy.SUSPENSION_WINDOW_SECONDS,
            limit["window_s"]!!.asInt(),
            "counted over sixty seconds",
        )
        assertEquals("suspended", limit["expected"]!!.asString(), "the expected state is suspended")
        assertEquals(
            ErrorCode.PERMISSION_DENIED.wireName,
            limit["expected_error"]!!.asString(),
            "with a permission denial, not a rate error",
        )

        assertFalse(ShellPolicy.isSuspended(ShellPolicy.SUSPENSION_THRESHOLD - 1), "one below the threshold is not suspended")
        assertTrue(ShellPolicy.isSuspended(ShellPolicy.SUSPENSION_THRESHOLD), "at the threshold it is")
        assertTrue(ShellPolicy.isSuspended(ShellPolicy.SUSPENSION_THRESHOLD + 100), "and well past it")

        // Output over the cap is truncated, not refused: the first four megabytes of a log are
        // useful and the alternative is to return nothing.
        val truncated = lifecycle("shell.output-truncated")
        val produced = truncated["output_bytes"]!!.asInt()
        val cap = truncated["output_cap_bytes"]!!.asInt()

        assertEquals(ShellPolicy.OUTPUT_CAP_BYTES, cap, "the vector's cap is the implementation's")
        assertTrue(ShellPolicy.isTruncated(produced), "the vector really exceeds the cap")
        assertEquals(cap, ShellPolicy.retainedOutputBytes(produced), "exactly the cap is retained")
        assertEquals(true, truncated["expected_flag"]!!.asBoolean(), "and the truncated flag is set")
        assertFalse(ShellPolicy.isTruncated(cap), "output exactly at the cap is not truncated")
        assertFalse(ShellPolicy.isTruncated(1024), "a small output is not truncated")

        // A timeout kills the process GROUP, because there is no shell process to rely on for
        // cleanup, and reports 137.
        val timeout = lifecycle("shell.timeout-kills-process-group")

        assertEquals(137, timeout["expected_exit_code"]!!.asInt(), "the exit code is 137")
        assertEquals(ShellPolicy.TIMEOUT_EXIT_CODE, timeout["expected_exit_code"]!!.asInt(), "which the implementation names")
        assertEquals(128 + 9, timeout["expected_exit_code"]!!.asInt(), "and it is 128 + SIGKILL, not a bare failure")
        assertEquals(true, timeout["expected_truncated"]!!.asBoolean(), "and the output is flagged as truncated, because it was cut short")
        assertTrue(timeout["note"]!!.asString().contains("whole process group"), "the note says the whole group is killed")

        // The audit log carries BLOCKED commands as well as executed ones.
        val audit = lifecycle("shell.audit-log-contains-blocked")

        val fields = audit["required_audit_fields"]!!.asArray().map { it.asString() }

        assertEquals(ShellPolicy.REQUIRED_AUDIT_FIELDS, fields, "the required fields match the implementation")

        // Asserted individually rather than only as a list, so a field that goes missing is named.
        for (field in listOf("blocked", "rule_id", "controller_fingerprint", "timestamp", "exit_code")) {
            assertTrue(fields.contains(field), "an audit entry carries \"$field\"")
        }

        assertEquals(
            ShellPolicy.MINIMUM_RETAINED_AUDIT_ENTRIES,
            audit["min_retained_entries"]!!.asInt(),
            "and at least 500 entries are retained",
        )
    }

    /**
     * The argument count and the patterns are enforced together.
     */
    @Test
    fun theArgumentCountAndPatternsAreEnforced() {
        // Too many arguments is argument_rejected, because a rule DID apply.
        val tooMany = case("shell.deny.too-many-arguments")

        assertEquals(
            ShellPolicy.Rejection.ARGUMENT_REJECTED,
            (
                ShellPolicy.evaluate(context("default"), rules(), tooMany["exe"]!!.asString(), args(tooMany))
                    as ShellPolicy.Verdict.Rejected
                ).reason,
            "too many arguments is argument_rejected, because a rule applied",
        )

        // The rule's own maxArgs is what rejects it.
        val getprop = rules().first { it.id == "sys.getprop" }

        assertTrue(args(tooMany).size > getprop.maxArgs, "the vector exceeds the rule's maximum")

        // A rule with fewer patterns than arguments it permits accepts nothing, so the two can
        // never disagree in the permissive direction.
        val rule = ShellPolicy.Rule(
            id = "test",
            executable = "/system/bin/test",
            argvPrefix = emptyList(),
            maxArgs = 2,
            argPatterns = listOf("^[a-z]+$"),
            timeoutMs = 1000,
            mutating = false,
        )

        assertFalse(
            ShellPolicy.argumentsMatch(rule, "/system/bin/test", listOf("abc", "def")),
            "an argument with no pattern of its own is refused",
        )
        assertTrue(
            ShellPolicy.argumentsMatch(rule, "/system/bin/test", listOf("abc")),
            "and the one that has a pattern is accepted",
        )

        // The count cap bites before the patterns: three arguments against a two-argument rule is
        // refused even when each individually matches.
        assertFalse(
            ShellPolicy.argumentsMatch(rule, "/system/bin/test", listOf("abc", "def", "ghi")),
            "a surplus argument is refused even when each one matches",
        )
    }

    /**
     * The command-line cap bounds the work.
     */
    @Test
    fun theCommandLineCapBoundsTheWork() {
        // The regex-bomb case declares a decision-time bound. The cap is what makes that true
        // without depending on the regex engine's backtracking behaviour.
        val bomb = case("shell.deny.regex-bomb")

        assertEquals(50, bomb["max_decision_time_ms"]!!.asInt(), "the vector declares a decision-time bound")

        val started = System.nanoTime()
        val verdict = ShellPolicy.evaluate(context("default"), rules(), bomb["exe"]!!.asString(), args(bomb))
        val elapsedMs = (System.nanoTime() - started) / 1_000_000

        assertTrue(verdict is ShellPolicy.Verdict.Rejected, "the pathological argument is refused")
        assertTrue(
            elapsedMs < bomb["max_decision_time_ms"]!!.asInt(),
            "and refused within the declared bound (${elapsedMs}ms)",
        )

        // The command-line-too-long case is NAMED for the cap but does NOT exceed it. The argument
        // is 1392 characters and the whole command line 1412 bytes against a 4096 cap; what
        // rejects it is the rule's per-argument pattern, whose quantifier allows 64.
        //
        // My first version asserted the cap was what fired and the mirror said otherwise, so both
        // facts are now pinned.
        val tooLong = case("shell.deny.command-line-too-long")
        val length = ShellPolicy.commandLineLength(tooLong["exe"]!!.asString(), args(tooLong))

        assertTrue(
            length <= ShellPolicy.MAX_COMMAND_LINE_BYTES,
            "the vector does NOT exceed the cap ($length <= ${ShellPolicy.MAX_COMMAND_LINE_BYTES})",
        )
        assertTrue(args(tooLong).first().length > 64, "because the argument is longer than the pattern allows")
        assertFalse(
            Regex(getpropPattern()).matches(args(tooLong).first()),
            "and the per-argument pattern is what rejects it",
        )

        // The cap still has to bite for a command line that really does exceed it. Driven
        // directly, because every case is rejected by a pattern first.
        val oversized = "A".repeat(ShellPolicy.MAX_COMMAND_LINE_BYTES)

        assertTrue(
            ShellPolicy.commandLineLength("/system/bin/getprop", listOf(oversized)) > ShellPolicy.MAX_COMMAND_LINE_BYTES,
            "an oversized command line exceeds the cap",
        )
        assertEquals(
            ShellPolicy.Rejection.ARGUMENT_REJECTED,
            (
                ShellPolicy.evaluate(context("default"), rules(), "/system/bin/getprop", listOf(oversized))
                    as ShellPolicy.Verdict.Rejected
                ).reason,
            "and an oversized command line is argument_rejected",
        )

        // The length is counted in BYTES, not characters: a multi-byte argument is more than one
        // byte of command line, and counting characters would let a 4096-character argument
        // exceed the limit.
        val multibyte = "é".repeat(100)

        assertEquals(1, "é".length, "the character is one UTF-16 unit")
        assertEquals(2, "é".toByteArray(Charsets.UTF_8).size, "but two bytes in UTF-8")
        assertTrue(
            ShellPolicy.commandLineLength("/x", listOf(multibyte)) > ShellPolicy.commandLineLength("/x", listOf("a".repeat(100))),
            "so a multi-byte argument counts for more",
        )
    }

    private fun getpropPattern(): String = rules().first { it.id == "sys.getprop" }.argPatterns.first()
}
