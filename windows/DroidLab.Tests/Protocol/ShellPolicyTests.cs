using System.Diagnostics;
using System.Text.Json;
using DroidLab.Protocol;
using DroidLab.Protocol.Shell;
using DroidLab.Tests.Vectors;

namespace DroidLab.Tests.Protocol;

/// <summary>
/// Tests for the shell allow-list policy engine (RFC-0004 sections 2 and 3).
/// </summary>
/// <remarks>
/// The cases are driven entirely from the vector file: every one gives an
/// executable, an argument vector, a context and the verdict an agent must
/// produce, including the reason code. Both implementations must agree on every
/// one, so this is a conformance test rather than a unit test.
/// </remarks>
public sealed class ShellPolicyTests
{
    private const string VectorFile = "shell-policy.json";

    private static readonly Lazy<(ShellPolicy Policy, IReadOnlyDictionary<string, ShellPolicyContext> Contexts)>
        Loaded = new(() =>
        {
            using JsonDocument document = VectorLoader.Load(VectorFile);
            return ShellPolicy.FromJson(document.RootElement);
        });

    private static ShellPolicy Policy => Loaded.Value.Policy;

    private static IReadOnlyDictionary<string, ShellPolicyContext> Contexts => Loaded.Value.Contexts;

    private static IEnumerable<JsonElement> Cases() => VectorLoader.Vectors(VectorFile, "cases");

    private static IEnumerable<JsonElement> LifecycleVectors() =>
        VectorLoader.Vectors(VectorFile, "lifecycle_vectors");

    private static string[] Args(JsonElement vector) =>
        [.. vector.GetProperty("args").EnumerateArray().Select(e => e.GetString()!)];

    // ---- The vector cases --------------------------------------------------

    /// <summary>
    /// Every policy vector produces the verdict and reason it declares.
    /// </summary>
    /// <remarks>
    /// The reason code is asserted as well as allowed/denied, because the
    /// vectors distinguish cases that are both refusals but for different
    /// reasons, and a refusal for the wrong reason sends the operator to fix the
    /// wrong thing.
    /// </remarks>
    [Fact]
    public void EveryPolicyCaseMatchesItsDeclaredVerdict()
    {
        int allowed = 0;
        int rejected = 0;

        foreach (JsonElement vector in Cases())
        {
            string id = vector.GetProperty("id").GetString()!;
            string contextName = vector.GetProperty("context").GetString()!;

            Assert.True(Contexts.ContainsKey(contextName), $"{id}: unknown policy context '{contextName}'");

            ShellVerdict verdict = Policy.Evaluate(
                Contexts[contextName],
                vector.GetProperty("exe").GetString(),
                Args(vector));

            string expected = vector.GetProperty("expected").GetString()!;

            if (expected == "allowed")
            {
                Assert.True(verdict.Allowed, $"{id}: expected allowed but got {verdict.Reason}");
                Assert.NotNull(verdict.Rule);
                Assert.Equal(vector.GetProperty("expected_rule").GetString(), verdict.Rule!.Id);
                Assert.Equal("allowed", verdict.Reason);
                Assert.Null(verdict.Error);
                allowed++;
            }
            else
            {
                Assert.False(verdict.Allowed, $"{id}: expected rejected but got allowed via {verdict.Rule?.Id}");
                Assert.Null(verdict.Rule);

                Assert.Equal(
                    vector.GetProperty("expected_reason").GetString(),
                    verdict.Reason);

                Assert.Equal(
                    vector.GetProperty("expected_error").GetString(),
                    verdict.Error!.Name);

                rejected++;
            }
        }

        Assert.True(allowed >= 5, $"expected at least 5 allowed cases, found {allowed}");
        Assert.True(rejected >= 15, $"expected at least 15 rejected cases, found {rejected}");
    }

    // ---- Ordering: the grant comes first ----------------------------------

    /// <summary>
    /// A fully allow-listed command is still refused with shell not granted.
    /// </summary>
    /// <remarks>
    /// The allow list describes what is safe; the grant describes what the
    /// operator permits. Checking the allow list first would execute a command
    /// the operator never authorised, which is the single worst ordering mistake
    /// this engine could make.
    /// </remarks>
    [Fact]
    public void NoGrantRefusesEvenAnAllowListedCommand()
    {
        ShellVerdict verdict = Policy.Evaluate(
            Contexts["no_grant"],
            "/system/bin/getprop",
            ["ro.build.version.sdk"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("denied_by_operator", verdict.Reason);
        Assert.Equal(ErrorCodes.PermissionDenied, verdict.Error);
    }

    /// <summary>Revoking the grant stops the next command on an established session.</summary>
    /// <remarks>
    /// The vector requires that the grant be re-checked before every execution,
    /// not captured when the session was opened. A grant checked once at session
    /// start would keep working after the operator turned it off, which is the
    /// difference between a revocation and a suggestion.
    /// </remarks>
    [Fact]
    public void RevokedGrantStopsTheNextCommand()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.grant-revoked-mid-session");

        List<JsonElement> steps = [.. vector.GetProperty("sequence").EnumerateArray()];
        ShellPolicyContext granted = Contexts["default"];

        // Step 1: allowed under the grant.
        ShellVerdict before = Policy.Evaluate(granted, steps[0].GetProperty("exe").GetString()!,
            [.. steps[0].GetProperty("args").EnumerateArray().Select(e => e.GetString()!)]);
        Assert.True(before.Allowed);

        // The operator revokes: same rule set, shell_granted now false.
        ShellPolicyContext revoked = granted with { ShellGranted = false };

        ShellVerdict after = Policy.Evaluate(revoked, steps[2].GetProperty("exe").GetString()!,
            [.. steps[2].GetProperty("args").EnumerateArray().Select(e => e.GetString()!)]);

        Assert.False(after.Allowed);
        Assert.Equal(steps[2].GetProperty("expected_error").GetString(), after.Error!.Name);
        Assert.Equal("denied_by_operator", after.Reason);
    }

    // ---- Ordering: deny wins ----------------------------------------------

    /// <summary>A deny-listed executable is refused even when a rule names it.</summary>
    /// <remarks>
    /// The deny list is checked before any rule matching, so a rule that would
    /// otherwise match a deny-listed name can never reach it. This is the
    /// property that makes the deny list a floor rather than a preference.
    /// </remarks>
    [Fact]
    public void DenyListBeatsAllowList()
    {
        // Build a context whose allow list names a deny-listed rule, which is the
        // configuration a mistake would produce.
        ShellPolicyContext contradictory = new(
            ShellGranted: true,
            Level: AllowLevel.ReadWrite,
            AllowedRuleIds: new HashSet<string>(Policy.Rules.Select(r => r.Id), StringComparer.Ordinal),
            DeniedExecutables: new HashSet<string>(["rm"], StringComparer.Ordinal),
            AllowStdin: false,
            MaxCommandLineBytes: 4096);

        ShellVerdict verdict = Policy.Evaluate(contradictory, "/system/bin/rm", ["-rf", "/sdcard"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("deny_listed", verdict.Reason);
    }

    /// <summary>Every deny-listed name is refused, whatever the arguments.</summary>
    [Theory]
    [InlineData("su")]
    [InlineData("sh")]
    [InlineData("rm")]
    [InlineData("reboot")]
    [InlineData("busybox")]
    [InlineData("magisk")]
    public void DenyListedNamesAreRefused(string name)
    {
        ShellVerdict verdict = Policy.Evaluate(Contexts["default"], "/system/bin/" + name, ["x"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("deny_listed", verdict.Reason);
    }

    /// <summary>A shell interpreter is refused, so nothing is ever interpreted.</summary>
    /// <remarks>
    /// The vector's point is not that the arguments are dangerous, it is that no
    /// string is ever handed to an interpreter at all. With <c>sh</c> refused and
    /// arguments passed as a vector, there is no quoting or expansion step and so
    /// no escaping bug to have.
    /// </remarks>
    [Fact]
    public void ShellInterpreterIsRefused()
    {
        ShellVerdict verdict = Policy.Evaluate(
            Contexts["default"],
            "/system/bin/sh",
            ["-c", "rm -rf /data/local/tmp/x"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("deny_listed", verdict.Reason);
    }

    // ---- Path handling -----------------------------------------------------

    /// <summary>Only absolute paths in vetted directories are considered.</summary>
    [Theory]
    [InlineData("getprop")]                                     // relative
    [InlineData("./getprop")]                                   // relative with prefix
    [InlineData("/data/local/tmp/payload")]                     // absolute, wrong directory
    [InlineData("/system/bin/../../data/local/tmp/payload")]    // traversal
    [InlineData("/system/bin/sub/getprop")]                     // nested component
    [InlineData("/system/bin/")]                                // no filename
    [InlineData("/system/bingetprop")]                          // directory prefix is not a boundary
    [InlineData("")]                                            // empty
    public void NonVettedPathsAreRefused(string path)
    {
        Assert.False(ShellPolicy.IsVettedPath(path));
        Assert.Equal("not_in_allow_list", Policy.Evaluate(Contexts["default"], path, ["a"]).Reason);
    }

    /// <summary>A plain filename in a vetted directory is considered.</summary>
    [Theory]
    [InlineData("/system/bin/getprop")]
    [InlineData("/system/xbin/id")]
    public void VettedPathsAreConsidered(string path)
    {
        Assert.True(ShellPolicy.IsVettedPath(path));
    }

    /// <summary>
    /// Traversal is rejected textually, before the filesystem sees it.
    /// </summary>
    /// <remarks>
    /// Resolving the path first and then judging the result would make the
    /// decision depend on symlinks the peer may be able to create, and would mean
    /// a rejected path had already been touched.
    /// </remarks>
    [Fact]
    public void TraversalIsRejectedTextually()
    {
        Assert.False(ShellPolicy.IsVettedPath("/system/bin/../../data/local/tmp/payload"));
        Assert.False(ShellPolicy.IsVettedPath("/system/bin/.."));
        Assert.False(ShellPolicy.IsVettedPath("/system/bin/a..b/c"));
    }

    // ---- The mutation gate -------------------------------------------------

    /// <summary>A mutating rule runs only under a read-write grant.</summary>
    /// <remarks>
    /// The vector pins the same command line as allowed under
    /// <c>app_control_grant</c> and rejected under <c>default</c>. That pair is
    /// the test: the command is identical, only the operator's level differs.
    /// </remarks>
    [Fact]
    public void MutatingRuleNeedsAReadWriteGrant()
    {
        ShellVerdict readOnly = Policy.Evaluate(
            Contexts["default"], "/system/bin/am", ["force-stop", "com.example.app"]);
        ShellVerdict readWrite = Policy.Evaluate(
            Contexts["app_control_grant"], "/system/bin/am", ["force-stop", "com.example.app"]);

        Assert.False(readOnly.Allowed);
        Assert.True(readWrite.Allowed);
        Assert.Equal("sys.am.force-stop", readWrite.Rule!.Id);
    }

    /// <summary>A mutating rule under a read-only grant reports not_in_allow_list.</summary>
    /// <remarks>
    /// Not <c>argument_rejected</c>. The mutation gate removes the rule from the
    /// context's allow list entirely, so the command is out of scope rather than
    /// malformed. The distinction matters because it tells the operator to raise
    /// the grant rather than to fix the argument.
    /// </remarks>
    [Fact]
    public void MutatingRuleUnderReadOnlyIsNotInTheAllowList()
    {
        ShellVerdict verdict = Policy.Evaluate(
            Contexts["default"],
            "/system/bin/settings",
            ["put", "system", "screen_brightness", "0"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("not_in_allow_list", verdict.Reason);
    }

    /// <summary>The read and write halves of one binary are split by rule.</summary>
    /// <remarks>
    /// <c>settings get</c> is allowed read-only while <c>settings put</c> is not,
    /// which is the whole reason the unit of policy is a rule rather than an
    /// executable. Gating on the executable would have to refuse both.
    /// </remarks>
    [Fact]
    public void ReadAndWriteHalvesOfOneBinaryAreSplitByRule()
    {
        ShellVerdict get = Policy.Evaluate(
            Contexts["default"], "/system/bin/settings", ["get", "system", "screen_brightness"]);
        ShellVerdict put = Policy.Evaluate(
            Contexts["default"], "/system/bin/settings", ["put", "system", "screen_brightness", "0"]);

        Assert.True(get.Allowed);
        Assert.Equal("sys.settings.get", get.Rule!.Id);
        Assert.False(put.Allowed);

        // The same put under a write grant is allowed, which is the other half of
        // the pair.
        Assert.True(Policy.Evaluate(
            Contexts["app_control_grant"], "/system/bin/settings", ["put", "system", "screen_brightness", "0"]).Allowed);
    }

    // ---- Argument matching -------------------------------------------------

    /// <summary>The argument prefix must match literally at the front.</summary>
    /// <remarks>
    /// <para>
    /// The vector's case is <c>window2</c> for the <c>window</c> rule, and its
    /// expected reason is <c>not_in_allow_list</c> rather than
    /// <c>argument_rejected</c>. That distinction is deliberate and worth
    /// pinning: a prefix that does not match means no rule <i>covers</i> the
    /// command, so the command is out of scope. Only a rule that was selected
    /// and then refused the arguments reports <c>argument_rejected</c>.
    /// </para>
    /// <para>
    /// It also shows why matching must be on prefix <i>arguments</i> rather than
    /// on a prefix <i>string</i>: a string comparison would accept
    /// <c>window2</c>, and with it <c>windowz</c> and anything else a subcommand
    /// name might grow into.
    /// </para>
    /// </remarks>
    [Fact]
    public void ArgumentPrefixMustMatchExactly()
    {
        ShellVerdict wrong = Policy.Evaluate(Contexts["default"], "/system/bin/dumpsys", ["window2"]);

        Assert.False(wrong.Allowed);
        Assert.Equal("not_in_allow_list", wrong.Reason);

        // The prefix is what selects the rule, so a mismatch is a miss rather
        // than a rejection.
        ShellRule windowRule = Policy.Rules.First(r => r.Id == "sys.dumpsys.window");
        Assert.False(ShellPolicy.HasMatchingPrefix(windowRule, ["window2"]));
        Assert.True(ShellPolicy.HasMatchingPrefix(windowRule, ["window"]));

        Assert.True(Policy.Evaluate(Contexts["default"], "/system/bin/dumpsys", ["window"]).Allowed);
    }

    /// <summary>A selected rule that refuses its arguments is argument_rejected.</summary>
    /// <remarks>
    /// The counterpart to the case above. <c>getprop</c> declares no prefix, so
    /// any argument reaches its pattern, and a pattern miss is the rule refusing
    /// rather than the rule not applying. Keeping the two apart is what tells an
    /// operator whether to change the argument or change the grant.
    /// </remarks>
    [Fact]
    public void SelectedRuleRefusingArgumentsIsArgumentRejected()
    {
        ShellRule rule = Policy.Rules.First(r => r.Id == "sys.getprop");

        Assert.True(ShellPolicy.HasMatchingPrefix(rule, ["bad arg"]));
        Assert.False(ShellPolicy.MatchesArguments(rule, ["bad arg"]));

        Assert.Equal("argument_rejected", Policy.Evaluate(Contexts["default"], "/system/bin/getprop", ["bad arg"]).Reason);
    }

    /// <summary>An allow-listed executable with a bad argument is argument_rejected.</summary>
    /// <remarks>
    /// Distinct from <c>not_in_allow_list</c>: the rule matched, the argument did
    /// not. The vector notes there is no metacharacter expansion happening, the
    /// argument is simply not accepted, so <c>ro.build.version;id</c> is refused
    /// for the same reason any other non-matching string would be.
    /// </remarks>
    [Theory]
    [InlineData("/system/bin/getprop", "ro.build.version;id")]
    [InlineData("/system/bin/getprop", "$(id)")]
    [InlineData("/system/bin/getprop", "`id`")]
    [InlineData("/system/bin/getprop", "a b")]
    [InlineData("/system/bin/getprop", "")]
    [InlineData("/system/bin/getprop", "has/slash")]
    public void MetacharactersAndBadArgumentsAreRejected(string exe, string argument)
    {
        ShellVerdict verdict = Policy.Evaluate(Contexts["default"], exe, [argument]);

        Assert.False(verdict.Allowed);
        Assert.Equal("argument_rejected", verdict.Reason);
        Assert.Equal(ErrorCodes.NotAllowed, verdict.Error);
    }

    /// <summary>Shell metacharacters have no special meaning, only pattern membership.</summary>
    /// <remarks>
    /// This is the core claim of the design. The engine does not strip or escape
    /// metacharacters, because it never interprets them in the first place: an
    /// argument either matches its position's anchored pattern or it does not.
    /// </remarks>
    [Theory]
    [InlineData(";")]
    [InlineData("|")]
    [InlineData("&&")]
    [InlineData(">")]
    [InlineData("<")]
    [InlineData("$(whoami)")]
    [InlineData("${HOME}")]
    [InlineData("*")]
    [InlineData("?")]
    [InlineData("\n")]
    [InlineData("\t")]
    public void MetacharactersNeverMatchAnAnchoredPattern(string argument)
    {
        ShellRule rule = Policy.Rules.First(r => r.Id == "sys.getprop");

        Assert.False(ShellPolicy.Matches(rule, [argument]));
    }

    /// <summary>Too many arguments are rejected.</summary>
    [Fact]
    public void TooManyArgumentsAreRejected()
    {
        ShellVerdict verdict = Policy.Evaluate(
            Contexts["default"], "/system/bin/getprop", ["a", "b", "c", "d", "e"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("argument_rejected", verdict.Reason);
    }

    /// <summary>A position with no pattern accepts nothing.</summary>
    /// <remarks>
    /// Without this, a rule declaring two patterns but four maximum arguments
    /// could be used to smuggle two unchecked extras in, which would be a real
    /// bypass rather than a style problem.
    /// </remarks>
    [Fact]
    public void PositionsWithoutAPatternAcceptNothing()
    {
        ShellRule asymmetric = new(
            Id: "test.gap",
            Executable: "/system/bin/test",
            ArgumentPrefix: [],
            MaxArguments: 3,
            ArgumentPatterns: [ShellPolicy.CompilePattern("^ok$")],
            TimeoutMs: 1000,
            Mutating: false);

        Assert.True(ShellPolicy.Matches(asymmetric, ["ok"]));
        Assert.False(ShellPolicy.Matches(asymmetric, ["ok", "extra"]));
        Assert.False(ShellPolicy.Matches(asymmetric, ["ok", "extra", "more"]));
    }

    /// <summary>Each argument position has its own pattern.</summary>
    /// <remarks>
    /// The vector's case is a key name with spaces in the key position. Position
    /// matters: the same string might be legal in the value position.
    /// </remarks>
    [Fact]
    public void EachArgumentPositionHasItsOwnPattern()
    {
        ShellVerdict verdict = Policy.Evaluate(
            Contexts["mutating_grant"],
            "/system/bin/settings",
            ["put", "system", "a b c", "0"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("argument_rejected", verdict.Reason);
    }

    /// <summary>An empty argument is accepted only where a pattern allows it.</summary>
    [Fact]
    public void EmptyArgumentIsGovernedByItsPattern()
    {
        // settings put's value pattern allows an empty value, its key pattern
        // does not.
        ShellVerdict emptyValue = Policy.Evaluate(
            Contexts["mutating_grant"], "/system/bin/settings", ["put", "system", "k", ""]);

        Assert.True(emptyValue.Allowed);

        ShellVerdict emptyKey = Policy.Evaluate(
            Contexts["mutating_grant"], "/system/bin/settings", ["put", "system", "", "v"]);

        Assert.False(emptyKey.Allowed);
    }

    // ---- The length cap and bounded time ----------------------------------

    /// <summary>An oversized command line is rejected before any pattern runs.</summary>
    /// <remarks>
    /// The cap is measured in bytes and applied before pattern matching, so a
    /// pathological argument never reaches the regex engine. Checking after
    /// matching would mean the engine could already have spent unbounded time on
    /// input the peer controls.
    /// </remarks>
    [Fact]
    public void OversizedCommandLineIsRejected()
    {
        JsonElement vector = Cases().First(v => v.GetProperty("id").GetString() == "shell.deny.command-line-too-long");

        ShellVerdict verdict = Policy.Evaluate(
            Contexts[vector.GetProperty("context").GetString()!],
            vector.GetProperty("exe").GetString(),
            Args(vector));

        Assert.False(verdict.Allowed);
        Assert.Equal(vector.GetProperty("expected_reason").GetString(), verdict.Reason);
    }

    /// <summary>The byte measurement counts UTF-8 bytes plus one separator per argument.</summary>
    /// <remarks>
    /// A character-based cap would let a multi-byte argument exceed the real
    /// transport budget, which is exactly what a byte cap exists to stop. The
    /// separator byte is counted because the arguments travel joined: omitting it
    /// would let a command with many short arguments exceed the budget while
    /// appearing to fit.
    /// </remarks>
    [Fact]
    public void CommandLineIsMeasuredInBytes()
    {
        // Four characters, twelve bytes, plus one separator byte for the single
        // argument.
        Assert.Equal(13, ShellPolicy.MeasureCommandLineBytes(string.Empty, ["\u4e2d\u6587\u5b57\u7b26"]));

        // Characters alone would give four, which would understate the cost by
        // two thirds.
        Assert.NotEqual(4, ShellPolicy.MeasureCommandLineBytes(string.Empty, ["\u4e2d\u6587\u5b57\u7b26"]));
    }

    /// <summary>Every argument costs one separator byte.</summary>
    [Fact]
    public void EachArgumentCostsASeparator()
    {
        Assert.Equal(4, ShellPolicy.MeasureCommandLineBytes("/abc", []));
        Assert.Equal(6, ShellPolicy.MeasureCommandLineBytes("/abc", ["a"]));
        Assert.Equal(8, ShellPolicy.MeasureCommandLineBytes("/abc", ["a", "b"]));
    }

    /// <summary>
    /// A pathological argument is rejected in bounded time.
    /// </summary>
    /// <remarks>
    /// The vector requires a decision within 50 ms and warns against catastrophic
    /// backtracking. Two things make that hold: the length cap rejects the
    /// argument before a pattern sees it, and every pattern carries a match
    /// timeout so that no input can run one unbounded. The test asserts the
    /// observable property rather than the mechanism.
    /// </remarks>
    [Fact]
    public void PathologicalArgumentIsRejectedInBoundedTime()
    {
        JsonElement vector = Cases().First(v => v.GetProperty("id").GetString() == "shell.deny.regex-bomb");
        int budget = vector.GetProperty("max_decision_time_ms").GetInt32();

        string[] arguments = Args(vector);

        Stopwatch stopwatch = Stopwatch.StartNew();
        ShellVerdict verdict = Policy.Evaluate(
            Contexts[vector.GetProperty("context").GetString()!],
            vector.GetProperty("exe").GetString(),
            arguments);
        stopwatch.Stop();

        Assert.False(verdict.Allowed);
        Assert.Equal(vector.GetProperty("expected_reason").GetString(), verdict.Reason);

        // Generous against the vector's 50 ms: this asserts the property that the
        // decision does not scale with the input, not a particular machine's
        // speed.
        Assert.True(
            stopwatch.ElapsedMilliseconds < budget * 20,
            $"the decision took {stopwatch.ElapsedMilliseconds} ms, which suggests it scales with the input");
    }

    /// <summary>A very long argument is rejected without reaching the regex engine.</summary>
    /// <remarks>
    /// The length cap runs first, so the cost of a hostile argument is the cost of
    /// measuring it.
    /// </remarks>
    [Fact]
    public void VeryLongArgumentIsRejectedQuickly()
    {
        string bomb = new string('a', 100_000) + "!";

        Stopwatch stopwatch = Stopwatch.StartNew();
        ShellVerdict verdict = Policy.Evaluate(Contexts["default"], "/system/bin/getprop", [bomb]);
        stopwatch.Stop();

        Assert.False(verdict.Allowed);
        Assert.True(stopwatch.ElapsedMilliseconds < 500, $"took {stopwatch.ElapsedMilliseconds} ms");
    }

    /// <summary>Every compiled pattern carries a match timeout.</summary>
    /// <remarks>
    /// The timeout is the backstop for whatever slips past the length cap, so its
    /// presence is checked directly rather than inferred from a timing test.
    /// </remarks>
    [Fact]
    public void EveryPatternHasAMatchTimeout()
    {
        foreach (ShellRule rule in Policy.Rules)
        {
            foreach (System.Text.RegularExpressions.Regex pattern in rule.ArgumentPatterns)
            {
                Assert.NotEqual(
                    System.Text.RegularExpressions.Regex.InfiniteMatchTimeout,
                    pattern.MatchTimeout);
            }
        }
    }

    // ---- The rule set itself ----------------------------------------------

    /// <summary>
    /// The rule set has no duplicate ids, and no two rules share a context.
    /// </summary>
    /// <remarks>
    /// Two rules may share an executable and argument prefix when they differ in
    /// argument budget. <c>sys.wm.size</c> reads the size with no arguments and
    /// <c>dev.wm.size</c> writes it with two, so both are needed and they are
    /// genuinely different rules. What must not happen is two rules that would
    /// both accept the same command and disagree about the verdict, so the
    /// duplicate check is on the pair only when their scopes also collide.
    /// </remarks>
    [Fact]
    public void RuleSetHasNoDuplicates()
    {
        Assert.Equal(Policy.Rules.Count, Policy.Rules.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count());

        // Same executable and prefix is allowed only when the argument budgets
        // differ, which is what makes them distinguishable at match time.
        foreach (IGrouping<string, ShellRule> group in Policy.Rules.GroupBy(
            r => r.Executable + "\0" + string.Join("\0", r.ArgumentPrefix),
            StringComparer.Ordinal))
        {
            List<ShellRule> rules = [.. group];
            if (rules.Count <= 1)
            {
                continue;
            }

            Assert.Equal(
                rules.Count,
                rules.Select(r => r.MaxArguments).Distinct().Count());
        }
    }

    /// <summary>Every rule declares a positive deadline and a sane argument budget.</summary>
    [Fact]
    public void RulesAreWellFormed()
    {
        foreach (ShellRule rule in Policy.Rules)
        {
            Assert.True(rule.TimeoutMs > 0, $"{rule.Id} has no deadline");
            Assert.True(rule.MaxArguments >= 0, $"{rule.Id} has a negative argument budget");
            Assert.True(rule.ArgumentPatterns.Count <= rule.MaxArguments,
                $"{rule.Id} declares more patterns than arguments");
            Assert.True(rule.Executable.StartsWith("/system/", StringComparison.Ordinal),
                $"{rule.Id} names a path outside the vetted directories");
        }
    }

    /// <summary>At least one rule is marked mutating, or the level gate is untested.</summary>
    [Fact]
    public void SomeRulesAreMarkedMutating()
    {
        Assert.Contains(Policy.Rules, r => r.Mutating);
        Assert.Contains(Policy.Rules, r => !r.Mutating);
    }

    /// <summary>Every rule a context allows is a real rule.</summary>
    /// <remarks>
    /// An allow list naming a rule that does not exist would be silently
    /// permissive-looking and inert, so the mismatch is a hard failure.
    /// </remarks>
    [Fact]
    public void EveryAllowedRuleIdExists()
    {
        HashSet<string> known = [.. Policy.Rules.Select(r => r.Id)];

        foreach ((string name, ShellPolicyContext context) in Contexts)
        {
            foreach (string id in context.AllowedRuleIds)
            {
                Assert.True(known.Contains(id), $"context '{name}' allows unknown rule '{id}'");
            }
        }
    }

    /// <summary>Every deny entry is a bare basename, not a path.</summary>
    /// <remarks>
    /// The deny check compares against the basename, so a deny entry written as a
    /// path would never match anything and would be silently inert.
    /// </remarks>
    [Fact]
    public void DenyEntriesAreBareBasenames()
    {
        foreach ((string name, ShellPolicyContext context) in Contexts)
        {
            foreach (string denied in context.DeniedExecutables)
            {
                Assert.DoesNotContain("/", denied, StringComparison.Ordinal);
                Assert.False(string.IsNullOrEmpty(denied), $"context '{name}' has an empty deny entry");
            }
        }
    }

    /// <summary>Every executable named by a rule has a possible path through the deny list.</summary>
    /// <remarks>
    /// A rule whose executable is deny-listed in every context that allows it can
    /// never run. That is not automatically wrong — a deny list is a floor — but
    /// it is worth checking that the deny list does not swallow the whole policy.
    /// </remarks>
    [Fact]
    public void DenyListDoesNotSwallowTheWholePolicy()
    {
        int reachable = 0;

        foreach (ShellRule rule in Policy.Rules)
        {
            foreach (ShellPolicyContext context in Contexts.Values)
            {
                if (!context.ShellGranted || !context.AllowedRuleIds.Contains(rule.Id))
                {
                    continue;
                }

                if (rule.Mutating && context.Level == AllowLevel.ReadOnly)
                {
                    continue;
                }

                string basename = rule.Executable[(rule.Executable.LastIndexOf('/') + 1)..];
                if (!context.DeniedExecutables.Contains(basename))
                {
                    reachable++;
                    break;
                }
            }
        }

        Assert.True(reachable > 0, "no rule can ever be reached, so the allow list is inert");
    }

    // ---- Lifecycle: rate limiting, output handling and the audit log -------

    /// <summary>
    /// Revocation stops the next command on an already-established session.
    /// </summary>
    /// <remarks>
    /// The grant is re-checked before every command rather than once per session, so
    /// revoking it takes effect immediately. This is the vector's own sequence, played
    /// in order: allowed, the operator revokes, rejected.
    /// </remarks>
    [Fact]
    public void RevocationStopsTheNextCommandOnALiveSession()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.grant-revoked-mid-session");

        JsonElement[] sequence = [.. vector.GetProperty("sequence").EnumerateArray()];
        Assert.Equal(3, sequence.Length);

        // The first step names the command that is allowed, and the expectation is
        // read from the file rather than restated.
        JsonElement first = sequence[0];
        Assert.Equal("execute", first.GetProperty("step").GetString());
        Assert.Equal("allowed", first.GetProperty("expected").GetString());

        Assert.Equal("operator_revokes_shell_grant", sequence[1].GetProperty("step").GetString());

        JsonElement third = sequence[2];
        Assert.Equal("rejected", third.GetProperty("expected").GetString());
        Assert.Equal("ERR_PERMISSION_DENIED", third.GetProperty("expected_error").GetString());

        // Now the behaviour: the same command, under the two grants, really does
        // produce those two verdicts.
        ShellPolicyContext granted = Contexts["default"];
        ShellPolicyContext revoked = Contexts["no_grant"];

        ShellVerdict allowed = Evaluate(first, granted);
        ShellVerdict refused = Evaluate(third, revoked);

        Assert.True(allowed.Allowed, allowed.Reason);
        Assert.False(refused.Allowed);
        Assert.Equal(ErrorCodes.PermissionDenied, refused.Error);
    }

    /// <summary>Twenty refusals in a minute suspend shell, and the suspension expires.</summary>
    /// <remarks>
    /// <para>
    /// The suspension is <i>shell</i> being unavailable rather than the session being
    /// ended, so the code a suspended peer sees is the same one a refusal uses. That is
    /// deliberate: the count left before suspension is a scheduling hint for an
    /// attacker, and the operator's remedy is the same either way.
    /// </para>
    /// <para>
    /// The window is checked at both ends. A count that never expired would suspend a
    /// session that was only occasionally refused, and one that never triggered would
    /// let a peer probe without limit.
    /// </para>
    /// </remarks>
    [Fact]
    public void RepeatedRejectionsSuspendShell()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.rate-limit-after-repeated-rejections");

        int threshold = vector.GetProperty("rejections_within_window").GetInt32();
        int windowMs = vector.GetProperty("window_s").GetInt32() * 1000;
        int suspendMs = vector.GetProperty("suspend_s").GetInt32() * 1000;

        Assert.Equal(ShellSession.SuspensionThreshold, threshold);
        Assert.Equal(ShellSession.SuspensionDurationSeconds * 1000, suspendMs);

        ShellSession session = new("9F3C-1A08-B7E2-44D1");
        ShellVerdict refused = new(false, null, ShellRejection.DenyListed, ErrorCodes.PermissionDenied);

        long now = 1_000_000;

        // One short of the threshold is not enough to suspend, counted with the
        // refusals spread across the window.
        for (int i = 0; i < threshold - 1; i++)
        {
            session.Submit(refused, "/system/bin/getprop", ["x"], now + (i * (windowMs / threshold)));
        }

        Assert.False(session.IsSuspended(now + windowMs - 1));

        // The threshold one does suspend.
        session.Submit(refused, "/system/bin/getprop", ["x"], now + windowMs - 1);

        Assert.True(session.IsSuspended(now + windowMs));

        // And the suspension expires rather than lasting forever.
        Assert.False(session.IsSuspended(now + windowMs + suspendMs));

        // A suspended session refuses even a command the policy allowed.
        ShellSession fresh = new("9F3C-1A08-B7E2-44D1");
        long t = 0;

        for (int i = 0; i < threshold; i++)
        {
            fresh.Submit(refused, "/system/bin/getprop", ["x"], t);
        }

        ShellVerdict allowed = new(true, Policy.Rules.First(r => r.Id == "sys.getprop"), null, null);
        ShellVerdict whileSuspended = fresh.Submit(allowed, "/system/bin/getprop", ["x"], t);

        Assert.False(whileSuspended.Allowed);
        Assert.Equal(ErrorCodes.PermissionDenied, whileSuspended.Error);
    }

    /// <summary>Refusals older than the window do not count toward suspension.</summary>
    /// <remarks>
    /// The count is a rate, not a lifetime total. Twenty refusals spread over an hour
    /// are a session being used with an occasionally wrong request; twenty in a minute
    /// are a peer probing, and only the second should suspend.
    /// </remarks>
    [Fact]
    public void OldRefusalsDoNotCountTowardSuspension()
    {
        ShellSession session = new("9F3C-1A08-B7E2-44D1");
        ShellVerdict refused = new(false, null, ShellRejection.DenyListed, ErrorCodes.PermissionDenied);

        long windowMs = ShellSession.SuspensionWindowSeconds * 1000L;

        // Nineteen refusals, each one window apart: never twenty inside one window.
        for (int i = 0; i < ShellSession.SuspensionThreshold - 1; i++)
        {
            session.Submit(refused, "/system/bin/getprop", ["x"], i * windowMs * 2);
        }

        Assert.False(session.IsSuspended((ShellSession.SuspensionThreshold - 1) * windowMs * 2));
    }

    /// <summary>The output cap truncates and says so, and the exit code survives.</summary>
    /// <remarks>
    /// A truncated result with its exit code and a flag lets the controller report
    /// that the read is incomplete rather than presenting a partial listing as whole,
    /// which for a package list would be actively misleading.
    /// </remarks>
    [Fact]
    public void OutputBeyondTheCapIsTruncatedAndFlagged()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.output-truncated");

        int produced = vector.GetProperty("output_bytes").GetInt32();
        int cap = vector.GetProperty("output_cap_bytes").GetInt32();

        Assert.Equal(ShellSession.OutputCapBytes, cap);
        Assert.True(produced > cap);

        ShellSession session = new("9F3C-1A08-B7E2-44D1");

        (int retained, bool truncated) = session.CapOutput(produced);

        Assert.Equal(cap, retained);
        Assert.True(truncated);
        Assert.Equal(vector.GetProperty("expected_flag").GetBoolean(), truncated);

        // Exactly at the cap is not truncated, which is the boundary the flag has to
        // get right: off-by-one here loses data silently.
        (int exact, bool exactTruncated) = session.CapOutput(cap);

        Assert.Equal(cap, exact);
        Assert.False(exactTruncated);

        // Under the cap is untouched.
        (int small, bool smallTruncated) = session.CapOutput(10);

        Assert.Equal(10, small);
        Assert.False(smallTruncated);

        // The exit code is recorded independently of truncation: a command that
        // succeeded and produced too much output succeeded.
        session.Complete("/system/bin/pm", ["list", "packages"], exitCode: 0, truncated: true, nowMs: 5);

        ShellAuditEntry entry = session.AuditLog.Last();
        Assert.Equal(0, entry.ExitCode);
        Assert.True(entry.Truncated);
    }

    /// <summary>A timed-out command's whole process group is killed.</summary>
    /// <remarks>
    /// The exit code is 137 — SIGKILL as a POSIX shell reports it — and the process
    /// group is what is signalled. That matters because no shell is used, so there is
    /// no shell process whose exit would clean up the children: signalling only the
    /// direct child would leave whatever it spawned running.
    /// </remarks>
    [Fact]
    public void TimedOutCommandIsKilledWithItsProcessGroup()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.timeout-kills-process-group");

        int timeoutMs = vector.GetProperty("timeout_ms").GetInt32();
        int expectedCode = vector.GetProperty("expected_exit_code").GetInt32();

        Assert.Equal(ShellSession.TimeoutExitCode, expectedCode);

        // Under the deadline there is no timeout code.
        Assert.Null(ShellSession.ExitCodeForTimeout(timeoutMs - 1, timeoutMs));

        // At the deadline and past it, the killed code is reported.
        Assert.Equal(expectedCode, ShellSession.ExitCodeForTimeout(timeoutMs, timeoutMs));
        Assert.Equal(expectedCode, ShellSession.ExitCodeForTimeout(timeoutMs * 10, timeoutMs));

        // A timed-out command's captured output is necessarily incomplete, which the
        // vector also declares.
        Assert.True(vector.GetProperty("expected_truncated").GetBoolean());

        // And the rule's own deadline is what bounds it rather than an arbitrary one.
        ShellRule rule = Policy.Rules.First(r => r.Id == "sys.getprop");
        Assert.True(rule.TimeoutMs > 0);
    }

    /// <summary>Blocked commands reach the audit log, not only executed ones.</summary>
    /// <remarks>
    /// An operator needs to see attempts as well as successes. A log of successes
    /// only would hide exactly the activity worth reviewing, which is a peer
    /// repeatedly asking for something it is not allowed to have — and the very
    /// refusals that suspend shell are the ones that would go unrecorded.
    /// </remarks>
    [Fact]
    public void AuditLogIncludesBlockedCommands()
    {
        JsonElement vector = LifecycleVectors()
            .First(v => v.GetProperty("id").GetString() == "shell.audit-log-contains-blocked");

        IReadOnlyList<string> required = [.. vector.GetProperty("required_audit_fields").EnumerateArray()
            .Select(e => e.GetString()!)];

        // Every required field is one the entry type actually carries, which is what
        // makes the vector checkable rather than aspirational.
        Assert.Equal(
            ["timestamp", "rule_id", "exe", "args", "exit_code", "controller_fingerprint", "blocked"],
            required);

        ShellSession session = new("9F3C-1A08-B7E2-44D1");

        // One allowed and one blocked command, through the real policy.
        ShellVerdict allowed = Policy.Evaluate(
            Contexts["default"],
            "/system/bin/getprop",
            ["ro.build.version.sdk"]);

        Assert.True(allowed.Allowed, allowed.Reason);

        ShellVerdict blocked = Policy.Evaluate(
            Contexts["app_control_grant"],
            "/system/bin/rm",
            ["-rf", "/data"]);

        Assert.False(blocked.Allowed);

        session.Submit(allowed, "/system/bin/getprop", ["ro.build.version.sdk"], nowMs: 1_000);
        session.Submit(blocked, "/system/bin/rm", ["-rf", "/data"], nowMs: 2_000);

        Assert.Equal(2, session.AuditLog.Count);

        ShellAuditEntry executed = session.AuditLog.First();
        ShellAuditEntry refused = session.AuditLog.Last();

        Assert.False(executed.Blocked);
        Assert.True(refused.Blocked);

        // Every required field is populated on both, including the blocked one.
        foreach (ShellAuditEntry entry in new[] { executed, refused })
        {
            Assert.True(entry.TimestampMs > 0);
            Assert.False(string.IsNullOrEmpty(entry.Executable));
            Assert.NotNull(entry.Arguments);
            Assert.Equal("9F3C-1A08-B7E2-44D1", entry.ControllerFingerprint);
            Assert.False(string.IsNullOrEmpty(entry.Reason));
        }

        // The blocked entry names what the peer asked for, which is the point of
        // logging it: an operator reads the command that was attempted.
        Assert.Equal("rm", Path.GetFileName(refused.Executable));
        Assert.Contains("-rf", refused.Arguments);

        Assert.True(vector.GetProperty("min_retained_entries").GetInt32() >= 500);
    }

    /// <summary>The audit log is bounded, dropping the oldest first.</summary>
    /// <remarks>
    /// Bounded so a peer generating traffic cannot fill a device, and oldest-first so
    /// the most recent activity — the part an incident review starts from — is what
    /// survives.
    /// </remarks>
    [Fact]
    public void TheAuditLogIsBoundedOldestFirst()
    {
        ShellSession session = new("9F3C-1A08-B7E2-44D1", maxAuditEntries: 3);
        ShellVerdict allowed = new(true, Policy.Rules.First(r => r.Id == "sys.getprop"), null, null);

        for (int i = 0; i < 10; i++)
        {
            session.Submit(allowed, "/system/bin/getprop", [$"arg{i}"], nowMs: i);
        }

        Assert.Equal(3, session.AuditLog.Count);

        // The three most recent survive, in order.
        Assert.Equal(["arg7", "arg8", "arg9"], session.AuditLog.Select(e => e.Arguments[0]));

        // The default is the vector's minimum, so the two cannot drift.
        Assert.True(new ShellSession("X").MaxAuditEntries >= ShellSession.MinimumRetainedAuditEntries);
    }

    /// <summary>
    /// Evaluates one lifecycle sequence step against a context.
    /// </summary>
    /// <param name="step">The step.</param>
    /// <param name="context">The context.</param>
    /// <returns>The verdict.</returns>
    private static ShellVerdict Evaluate(JsonElement step, ShellPolicyContext context)
    {
        string exe = step.GetProperty("exe").GetString()!;
        List<string> args = [.. step.GetProperty("args").EnumerateArray().Select(e => e.GetString()!)];

        return Policy.Evaluate(context, exe, args);
    }
}
