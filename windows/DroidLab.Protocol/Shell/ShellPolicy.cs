using System.Collections.Frozen;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DroidLab.Protocol.Shell;

/// <summary>
/// The allow level of an operator's shell grant (RFC-0004 section 2).
/// </summary>
public enum AllowLevel
{
    /// <summary>Only rules that are not marked mutating.</summary>
    ReadOnly,

    /// <summary>Also rules marked mutating.</summary>
    ReadWrite,
}

/// <summary>
/// Why a command was refused.
/// </summary>
public enum ShellRejection
{
    /// <summary>The operator has not enabled shell for this pairing, or revoked it.</summary>
    DeniedByOperator,

    /// <summary>The executable's basename is on the deny list.</summary>
    DenyListed,

    /// <summary>No rule in this context matched the executable, prefix and arguments.</summary>
    NotInAllowList,

    /// <summary>A rule matched but an argument did not.</summary>
    ArgumentRejected,

    /// <summary>The full command line exceeded the context's byte budget.</summary>
    CommandLineTooLong,
}

/// <summary>
/// One allow-list rule (RFC-0004 section 2.1).
/// </summary>
/// <param name="Id">The rule identifier, e.g. <c>sys.getprop</c>.</param>
/// <param name="Executable">The absolute path the rule permits.</param>
/// <param name="ArgumentPrefix">Literal arguments that must appear at the front of the vector.</param>
/// <param name="MaxArguments">The greatest number of arguments the rule accepts.</param>
/// <param name="ArgumentPatterns">One pattern per accepted argument position.</param>
/// <param name="TimeoutMs">The rule's own deadline.</param>
/// <param name="Mutating">Whether the rule changes device state.</param>
public sealed record ShellRule(
    string Id,
    string Executable,
    IReadOnlyList<string> ArgumentPrefix,
    int MaxArguments,
    IReadOnlyList<Regex> ArgumentPatterns,
    int TimeoutMs,
    bool Mutating);

/// <summary>
/// An operator's shell grant for one pairing (RFC-0004 section 2).
/// </summary>
/// <param name="ShellGranted">Whether the operator has enabled shell at all.</param>
/// <param name="Level">The allow level.</param>
/// <param name="AllowedRuleIds">The rule ids this grant permits.</param>
/// <param name="DeniedExecutables">Deny-listed executable basenames.</param>
/// <param name="AllowStdin">Whether a command may be given standard input.</param>
/// <param name="MaxCommandLineBytes">The command-line byte budget.</param>
public sealed record ShellPolicyContext(
    bool ShellGranted,
    AllowLevel Level,
    IReadOnlySet<string> AllowedRuleIds,
    IReadOnlySet<string> DeniedExecutables,
    bool AllowStdin,
    int MaxCommandLineBytes);

/// <summary>
/// The outcome of evaluating a command.
/// </summary>
/// <param name="Allowed">Whether the command may run.</param>
/// <param name="Rule">The matching rule when allowed.</param>
/// <param name="Rejection">Why it was refused when not allowed.</param>
/// <param name="Error">The error code to report.</param>
public readonly record struct ShellVerdict(
    bool Allowed,
    ShellRule? Rule,
    ShellRejection? Rejection,
    ErrorCode? Error)
{
    /// <summary>The stable machine-readable reason string, as the vectors name it.</summary>
    public string Reason => Rejection switch
    {
        ShellRejection.DeniedByOperator => "denied_by_operator",
        ShellRejection.DenyListed => "deny_listed",
        ShellRejection.NotInAllowList => "not_in_allow_list",
        ShellRejection.ArgumentRejected => "argument_rejected",
        ShellRejection.CommandLineTooLong => "argument_rejected",
        null => "allowed",
        _ => throw new InvalidOperationException($"unclassified rejection {Rejection}"),
    };
}

/// <summary>
/// The DLWP/1 shell allow-list policy engine (RFC-0004 sections 2 and 3).
/// </summary>
/// <remarks>
/// <para>
/// This engine exists so that <b>no string is ever handed to an interpreter</b>.
/// The executable is an absolute path from a vetted directory and the arguments
/// are a vector, never a command line. That decision is what removes quoting,
/// globbing, variable expansion and redirection from the threat model entirely:
/// there is nothing to escape, so there is nothing to get wrong.
/// </para>
/// <para>
/// Four ordering rules carry the security weight, and each is checked in the
/// order below for a reason:
/// </para>
/// <list type="number">
/// <item>
/// <b>The operator grant is checked first.</b> A command that is fully
/// allow-listed is still refused when shell has not been granted, because the
/// allow list describes what is <i>safe</i>, not what is <i>permitted</i>.
/// </item>
/// <item>
/// <b>The deny list is checked before any rule matching.</b> A deny entry always
/// wins, so a deny-listed name can never be reached by a rule that would
/// otherwise match it.
/// </item>
/// <item>
/// <b>The executable is an absolute path, basename-matched for deny and
/// path-matched for allow.</b> A relative path or a traversing path is rejected
/// outright, so the working directory can never be used to smuggle a binary in.
/// </item>
/// <item>
/// <b>The mutation flag and the allow level are separate facts.</b> A mutating
/// rule is not in a read-only context's allow list at all, which is why an
/// otherwise well-formed mutating command reports <c>not_in_allow_list</c>
/// rather than <c>argument_rejected</c>.
/// </item>
/// </list>
/// <para>
/// Argument patterns are anchored and length-bounded, and the command line is
/// measured in bytes against a cap <b>before</b> any pattern runs. Both details
/// are deliberate: an unbounded pattern applied to an unbounded input is how a
/// policy engine becomes a denial-of-service vector. The engine must decide in
/// bounded time regardless of what the peer sends.
/// </para>
/// </remarks>
public sealed class ShellPolicy
{
    /// <summary>The directories a permitted executable may live in.</summary>
    /// <remarks>
    /// An allow list of directories rather than a check for "absolute path": an
    /// absolute path to <c>/data/local/tmp</c> is where an attacker who already
    /// has write access would put a payload, and a name that merely looks
    /// harmless must not be enough.
    /// </remarks>
    public static readonly IReadOnlyList<string> VettedDirectories = ["/system/bin/", "/system/xbin/"];

    /// <summary>The rejection to report when a length cap is hit.</summary>
    public static readonly ErrorCode DeniedByOperatorError = ErrorCodes.PermissionDenied;

    /// <summary>The error for anything the allow list refuses.</summary>
    public static readonly ErrorCode NotAllowedError = ErrorCodes.NotAllowed;

    private readonly FrozenDictionary<string, IReadOnlyList<ShellRule>> _rulesByExecutable;

    private ShellPolicy(IReadOnlyList<ShellRule> rules)
    {
        Rules = rules;

        // Indexed by executable so a lookup is a hash hit rather than a scan over
        // the whole rule set for every command.
        _rulesByExecutable = rules
            .GroupBy(r => r.Executable, StringComparer.Ordinal)
            .ToFrozenDictionary(g => g.Key, g => (IReadOnlyList<ShellRule>)[.. g], StringComparer.Ordinal);
    }

    /// <summary>Every rule, in declaration order.</summary>
    public IReadOnlyList<ShellRule> Rules { get; }

    /// <summary>Builds a policy from rules.</summary>
    /// <param name="rules">The rules.</param>
    /// <returns>The policy.</returns>
    public static ShellPolicy FromRules(IReadOnlyList<ShellRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return new ShellPolicy(rules);
    }

    /// <summary>
    /// Compiles a pattern with a bound on backtracking.
    /// </summary>
    /// <param name="pattern">The pattern text.</param>
    /// <returns>The compiled regular expression.</returns>
    /// <exception cref="ArgumentException">The pattern is malformed.</exception>
    /// <remarks>
    /// A match timeout is set on every pattern because the vectors include a
    /// pathological argument and require a decision in bounded time. Without a
    /// timeout, a catastrophic-backtracking pattern is a denial of service that
    /// arrives as a single crafted command. <see cref="RegexOptions.NonBacktracking"/>
    /// would remove the risk in principle but cannot express every construct the
    /// rules use, so a timeout is the honest bound.
    /// </remarks>
    public static Regex CompilePattern(string pattern)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern);

        return new Regex(
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.Compiled,
            TimeSpan.FromMilliseconds(50));
    }

    /// <summary>Loads the policy rules and contexts from the vector file.</summary>
    /// <param name="path">Path to <c>shell-policy.json</c>.</param>
    /// <returns>The policy, with its contexts.</returns>
    /// <exception cref="FileNotFoundException">The policy file is absent.</exception>
    public static (ShellPolicy Policy, IReadOnlyDictionary<string, ShellPolicyContext> Contexts) LoadFromFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"the shell policy was not found at '{path}'. The allow list is the only thing standing " +
                "between a paired controller and command execution on the device, so it cannot default " +
                "to permissive and it cannot default to empty-but-working; there is nothing safe to guess.",
                path);
        }

        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
        return FromJson(document.RootElement);
    }

    /// <summary>Builds the policy and contexts from a parsed policy document.</summary>
    /// <param name="root">The policy root element.</param>
    /// <returns>The policy, with its contexts.</returns>
    public static (ShellPolicy Policy, IReadOnlyDictionary<string, ShellPolicyContext> Contexts) FromJson(JsonElement root)
    {
        List<ShellRule> rules = [];

        foreach (JsonElement entry in RequireArray(root, "rules").EnumerateArray())
        {
            List<Regex> patterns = [];
            foreach (JsonElement pattern in entry.GetProperty("arg_patterns").EnumerateArray())
            {
                patterns.Add(CompilePattern(pattern.GetString()!));
            }

            rules.Add(new ShellRule(
                Id: entry.GetProperty("id").GetString()!,
                Executable: entry.GetProperty("exe").GetString()!,
                ArgumentPrefix: [.. entry.GetProperty("argv_prefix").EnumerateArray().Select(e => e.GetString()!)],
                MaxArguments: entry.GetProperty("max_args").GetInt32(),
                ArgumentPatterns: patterns,
                TimeoutMs: entry.GetProperty("timeout_ms").GetInt32(),
                Mutating: entry.TryGetProperty("mutating", out JsonElement mutating) && mutating.GetBoolean()));
        }

        Dictionary<string, ShellPolicyContext> contexts = new(StringComparer.Ordinal);

        foreach (JsonProperty context in RequireObject(root, "policy_contexts").EnumerateObject())
        {
            JsonElement value = context.Value;

            contexts[context.Name] = new ShellPolicyContext(
                ShellGranted: value.GetProperty("shell_granted").GetBoolean(),
                Level: value.GetProperty("allow_level").GetString() switch
                {
                    "read_only" => AllowLevel.ReadOnly,
                    "read_write" => AllowLevel.ReadWrite,
                    _ => throw new InvalidDataException(
                        $"unknown allow_level '{value.GetProperty("allow_level").GetString()}' in context " +
                        $"'{context.Name}'; an unrecognised level must not default to either, because " +
                        "guessing read_write is a privilege escalation and guessing read_only silently " +
                        "refuses work the operator granted"),
                },
                AllowedRuleIds: new HashSet<string>(
                    value.GetProperty("allowed_rules").EnumerateArray().Select(e => e.GetString()!),
                    StringComparer.Ordinal),
                DeniedExecutables: new HashSet<string>(
                    value.GetProperty("denied_rules").EnumerateArray().Select(e => e.GetString()!),
                    StringComparer.Ordinal),
                AllowStdin: value.GetProperty("allow_stdin").GetBoolean(),
                MaxCommandLineBytes: value.GetProperty("max_command_line_bytes").GetInt32());
        }

        return (FromRules(rules), contexts);
    }

    /// <summary>
    /// Evaluates a command against a context.
    /// </summary>
    /// <param name="context">The operator's grant.</param>
    /// <param name="executable">The absolute path of the executable.</param>
    /// <param name="arguments">The argument vector.</param>
    /// <returns>The verdict.</returns>
    /// <remarks>
    /// No string here is ever assembled into a command line and handed to an
    /// interpreter. The executable and the vector stay separate all the way to
    /// <c>Process.Start</c>, which is why no argument needs escaping and why
    /// there is no escaping bug to have.
    /// </remarks>
    public ShellVerdict Evaluate(
        ShellPolicyContext context,
        string? executable,
        IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(arguments);

        // 1. The operator's grant, before anything else. A safe command is not a
        // permitted one.
        if (!context.ShellGranted)
        {
            return new ShellVerdict(false, null, ShellRejection.DeniedByOperator, DeniedByOperatorError);
        }

        if (string.IsNullOrEmpty(executable))
        {
            return new ShellVerdict(false, null, ShellRejection.NotInAllowList, NotAllowedError);
        }

        // 2. The deny list wins, and it is checked before any rule matching, so
        // a deny-listed name cannot be reached by an allow rule.
        string basename = PathOfBasename(executable);
        if (context.DeniedExecutables.Contains(basename))
        {
            return new ShellVerdict(false, null, ShellRejection.DenyListed, NotAllowedError);
        }

        // 3. The path must be absolute and in a vetted directory. This is checked
        // before the length cap only because it is cheaper and rejects more; the
        // cap still applies to anything that gets past it.
        if (!IsVettedPath(executable))
        {
            return new ShellVerdict(false, null, ShellRejection.NotInAllowList, NotAllowedError);
        }

        // 4. The command-line budget, measured before any pattern runs. An
        // unbounded input into a pattern engine is a denial of service.
        if (MeasureCommandLineBytes(executable, arguments) > context.MaxCommandLineBytes)
        {
            return new ShellVerdict(false, null, ShellRejection.CommandLineTooLong, NotAllowedError);
        }

        // 5. Rule matching. Every matching rule is considered and one must
        // accept; a rule that matches the executable but rejects an argument
        // reports argument_rejected, which is a different fact from "no rule
        // covers this command" and is separated so the operator can tell a typo
        // from a missing grant.
        if (!_rulesByExecutable.TryGetValue(executable, out IReadOnlyList<ShellRule>? candidates))
        {
            return new ShellVerdict(false, null, ShellRejection.NotInAllowList, NotAllowedError);
        }

        bool sawSelectedRule = false;
        bool sawArgumentMismatch = false;

        foreach (ShellRule rule in candidates)
        {
            // The mutation gate and the allow level are separate facts. A
            // mutating rule under a read-only grant is not in the allow list for
            // that context at all, so it is not merely skipped here: it must not
            // contribute an argument mismatch either. Reporting
            // argument_rejected for a rule the context does not contain would
            // tell the operator to fix an argument when the real answer is that
            // the grant does not cover the command.
            if (rule.Mutating && context.Level == AllowLevel.ReadOnly)
            {
                continue;
            }

            if (!context.AllowedRuleIds.Contains(rule.Id))
            {
                continue;
            }

            // Selection and acceptance are two steps, and the vectors
            // distinguish them.
            if (!HasMatchingPrefix(rule, arguments))
            {
                // The rule was not selected at all: the executable is allow
                // listed but no rule covers this subcommand, so the command is
                // simply not in the allow list. The vector's dumpsys window2
                // case is this, and it is not argument_rejected.
                continue;
            }

            sawSelectedRule = true;

            if (MatchesArguments(rule, arguments))
            {
                return new ShellVerdict(true, rule, null, null);
            }

            sawArgumentMismatch = true;
        }

        // A rule was selected and then rejected the argument vector, which is a
        // different fact from no rule covering the command: the operator needs to
        // know whether to fix an argument or to change the grant.
        return sawSelectedRule && sawArgumentMismatch
            ? new ShellVerdict(false, null, ShellRejection.ArgumentRejected, NotAllowedError)
            : new ShellVerdict(false, null, ShellRejection.NotInAllowList, NotAllowedError);
    }

    /// <summary>Whether a rule selects a command, judging only by the prefix.</summary>
    /// <param name="rule">The rule.</param>
    /// <param name="arguments">The argument vector.</param>
    /// <returns><see langword="true"/> when the rule is selected by the prefix.</returns>
    /// <remarks>
    /// Prefix matching is a separate step from argument acceptance because the
    /// vectors treat the two failures differently: a prefix that does not match
    /// means no rule covers the command at all
    /// (<c>not_in_allow_list</c>), while a matched rule whose argument pattern
    /// rejects means the rule covered it and refused
    /// (<c>argument_rejected</c>). Collapsing them would tell the operator to fix
    /// an argument when the right answer is that nothing covers the subcommand.
    /// </remarks>
    public static bool HasMatchingPrefix(ShellRule rule, IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(arguments);

        if (arguments.Count < rule.ArgumentPrefix.Count)
        {
            return false;
        }

        for (int i = 0; i < rule.ArgumentPrefix.Count; i++)
        {
            if (!string.Equals(arguments[i], rule.ArgumentPrefix[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Whether the arguments of an already-selected rule are acceptable.</summary>
    /// <param name="rule">The rule, already selected by <see cref="HasMatchingPrefix"/>.</param>
    /// <param name="arguments">The argument vector.</param>
    /// <returns><see langword="true"/> when the rule accepts the arguments.</returns>
    public static bool MatchesArguments(ShellRule rule, IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(arguments);

        int trailing = arguments.Count - rule.ArgumentPrefix.Count;

        if (trailing < 0 || trailing > rule.MaxArguments)
        {
            return false;
        }

        // Each remaining argument is checked against its own position's pattern.
        // A position with no pattern accepts nothing, so a rule that declares
        // fewer patterns than max_args cannot be used to smuggle extras in.
        for (int i = 0; i < trailing; i++)
        {
            if (i >= rule.ArgumentPatterns.Count)
            {
                return false;
            }

            string argument = arguments[rule.ArgumentPrefix.Count + i];

            // The length cap runs before the pattern, so a pathological input
            // never reaches the regex engine at all.
            if (argument.Length > 4096)
            {
                return false;
            }

            if (!rule.ArgumentPatterns[i].IsMatch(argument))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Whether a rule accepts an argument vector.</summary>
    /// <param name="rule">The rule.</param>
    /// <param name="arguments">The argument vector.</param>
    /// <returns><see langword="true"/> when the rule accepts it.</returns>
    public static bool Matches(ShellRule rule, IReadOnlyList<string> arguments) =>
        HasMatchingPrefix(rule, arguments) && MatchesArguments(rule, arguments);

    /// <summary>The basename of a path, unescaped by hand rather than by the OS.</summary>
    /// <param name="path">The path.</param>
    /// <returns>The final path component.</returns>
    private static string PathOfBasename(string path)
    {
        int slash = path.LastIndexOf('/');
        return slash >= 0 ? path[(slash + 1)..] : path;
    }

    /// <summary>
    /// Whether a path is absolute and inside a vetted directory.
    /// </summary>
    /// <param name="executable">The path.</param>
    /// <returns><see langword="true"/> when the path may be considered.</returns>
    /// <remarks>
    /// The traversal check is textual and happens before any filesystem call, so
    /// <c>/system/bin/../../data/local/tmp/payload</c> is rejected as written
    /// rather than resolved to a real path and then judged. A real-path check
    /// would depend on symlinks the peer may be able to create.
    /// </remarks>
    public static bool IsVettedPath(string executable)
    {
        if (string.IsNullOrEmpty(executable) || executable[0] != '/')
        {
            return false;
        }

        if (executable.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (string directory in VettedDirectories)
        {
            if (!executable.StartsWith(directory, StringComparison.Ordinal))
            {
                continue;
            }

            string remainder = executable[directory.Length..];

            // Must be a plain filename: one component, non-empty, no separator.
            if (remainder.Length > 0 && !remainder.Contains('/'))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Measures the byte length of a command line.
    /// </summary>
    /// <param name="executable">The executable path.</param>
    /// <param name="arguments">The argument vector.</param>
    /// <returns>The total bytes, counting one separator per argument.</returns>
    /// <remarks>
    /// Measured in bytes rather than characters: a multi-byte character occupies
    /// more of the transport budget than it looks like, and a character-based cap
    /// would let a UTF-8 argument exceed the real limit.
    /// </remarks>
    public static int MeasureCommandLineBytes(string executable, IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        int total = Encoding.UTF8.GetByteCount(executable ?? string.Empty);

        foreach (string argument in arguments)
        {
            total += Encoding.UTF8.GetByteCount(argument) + 1;
        }

        return total;
    }

    private static JsonElement RequireArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement array) || array.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"the shell policy has no '{name}' array");
        }

        return array;
    }

    private static JsonElement RequireObject(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement obj) || obj.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"the shell policy has no '{name}' object");
        }

        return obj;
    }
}
