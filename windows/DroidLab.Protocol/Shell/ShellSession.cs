using DroidLab.Protocol.Registry;

namespace DroidLab.Protocol.Shell;

/// <summary>
/// One executed or refused shell command, as the device audit log records it.
/// </summary>
/// <param name="TimestampMs">When the attempt happened, in milliseconds since the epoch.</param>
/// <param name="RuleId">The rule that governed it, or null when none matched.</param>
/// <param name="Executable">The executable path that was requested.</param>
/// <param name="Arguments">The arguments that were requested.</param>
/// <param name="ExitCode">The exit code, or null when it did not run.</param>
/// <param name="ControllerFingerprint">The controller's fingerprint.</param>
/// <param name="Blocked">Whether the command was refused.</param>
/// <param name="Truncated">Whether the captured output was truncated.</param>
/// <param name="Reason">The stable reason string from the policy.</param>
/// <remarks>
/// <para>
/// A <i>blocked</i> command appears here with the same fields as an executed one, and
/// that is the point rather than an accident of a shared type: an operator reviewing
/// the log needs to see attempts as well as successes. A log of successes only would
/// hide exactly the activity worth reviewing, which is a peer repeatedly asking for
/// something it is not allowed to have.
/// </para>
/// <para>
/// The controller's fingerprint is recorded because the log's reader needs to know
/// <i>who</i> asked, and the pairing id would not survive a re-pairing. It is a
/// fingerprint rather than an identity key because the log is written to the device
/// and may be exported, and the log has no need for material that could be used to
/// impersonate the controller.
/// </para>
/// </remarks>
public sealed record ShellAuditEntry(
    long TimestampMs,
    string? RuleId,
    string Executable,
    IReadOnlyList<string> Arguments,
    int? ExitCode,
    string ControllerFingerprint,
    bool Blocked,
    bool Truncated,
    string Reason);

/// <summary>
/// The lifecycle rules an established shell session obeys (RFC-0004 section 6).
/// </summary>
/// <remarks>
/// <para>
/// These are the rules that are about a session rather than about one command: how
/// often it may be refused before it is suspended, how much output one command may
/// produce, and what the audit log holds. They live here rather than in
/// <see cref="ShellPolicy"/> because the policy answers "may this command run" and
/// has no state, while all three of these are stateful and answered over time.
/// </para>
/// <para>
/// The class holds two counters and a ring, and each exists because of a rule:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Rejections are counted in a sliding window.</b> The grant is re-checked before
/// every command, so revoking it stops the next one even on an established session —
/// but a peer that keeps asking after being refused is doing something the session
/// should stop tolerating, so twenty refusals in a minute suspend shell for five.
/// The suspension is a delay rather than a disconnect because the rest of the session
/// is unaffected: only shell is.
/// </item>
/// <item>
/// <b>Output is capped and the loss is recorded, not hidden.</b> A truncated result
/// with its exit code and a flag lets the controller say "this is incomplete" rather
/// than showing a partial read as if it were whole, which for something like a
/// package listing would be actively misleading.
/// </item>
/// <item>
/// <b>The audit log is bounded but generous.</b> Five hundred entries is enough that
/// an incident is still visible after the fact, and bounded so a device cannot be
/// filled by a peer generating traffic.
/// </item>
/// </list>
/// </remarks>
public sealed class ShellSession
{
    /// <summary>The refusal count that suspends shell, per the lifecycle vector.</summary>
    public const int SuspensionThreshold = 20;

    /// <summary>The window those refusals are counted in, in seconds.</summary>
    public const int SuspensionWindowSeconds = 60;

    /// <summary>How long shell is suspended for, in seconds.</summary>
    public const int SuspensionDurationSeconds = 300;

    /// <summary>The output cap, in bytes, from the vector.</summary>
    public const int OutputCapBytes = 4_194_304;

    /// <summary>The exit code recorded for a process group killed on timeout.</summary>
    /// <remarks>137 is 128 + 9, which is how a POSIX shell reports SIGKILL.</remarks>
    public const int TimeoutExitCode = 137;

    /// <summary>The minimum audit entries retained, from the vector.</summary>
    public const int MinimumRetainedAuditEntries = 500;

    private readonly List<long> _rejectionTimesMs = [];
    private readonly Queue<ShellAuditEntry> _auditLog = new();
    private long _suspendedUntilMs;

    /// <summary>Creates a session.</summary>
    /// <param name="controllerFingerprint">The controller's fingerprint, for the audit log.</param>
    /// <param name="maxAuditEntries">How many audit entries to retain.</param>
    /// <param name="outputCapBytes">The output cap.</param>
    public ShellSession(
        string controllerFingerprint,
        int maxAuditEntries = MinimumRetainedAuditEntries,
        int outputCapBytes = OutputCapBytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(controllerFingerprint);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAuditEntries, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(outputCapBytes, 1);

        ControllerFingerprint = controllerFingerprint;
        MaxAuditEntries = maxAuditEntries;
        OutputCapBytesProperty = outputCapBytes;
    }

    /// <summary>The controller's fingerprint.</summary>
    public string ControllerFingerprint { get; }

    /// <summary>How many audit entries are retained.</summary>
    public int MaxAuditEntries { get; }

    /// <summary>The output cap in bytes.</summary>
    public int OutputCapBytesProperty { get; }

    /// <summary>Whether shell is currently suspended.</summary>
    /// <param name="nowMs">The current time.</param>
    /// <returns>Whether it is suspended.</returns>
    public bool IsSuspended(long nowMs) => nowMs < _suspendedUntilMs;

    /// <summary>When a suspension ends, or null when it has not been suspended.</summary>
    public long? SuspendedUntilMs => _suspendedUntilMs == 0 ? null : _suspendedUntilMs;

    /// <summary>The audit log, oldest first.</summary>
    public IReadOnlyCollection<ShellAuditEntry> AuditLog => _auditLog;

    /// <summary>
    /// Decides whether a command may be attempted now, and records the refusal.
    /// </summary>
    /// <param name="verdict">The policy's verdict.</param>
    /// <param name="executable">The requested executable.</param>
    /// <param name="arguments">The requested arguments.</param>
    /// <param name="nowMs">The current time.</param>
    /// <returns>The verdict to act on.</returns>
    /// <remarks>
    /// A suspension is reported as <c>ERR_PERMISSION_DENIED</c>, the same code a
    /// policy refusal uses, and that is deliberate: a suspended peer must not be able
    /// to tell how many of its refusals it has left, because that number is a
    /// scheduling hint for an attacker and the operator's remedy is the same either
    /// way. The suspension itself is enforced here rather than in the policy, which is
    /// stateless and could not enforce it.
    /// </remarks>
    public ShellVerdict Submit(
        ShellVerdict verdict,
        string executable,
        IReadOnlyList<string> arguments,
        long nowMs)
    {
        ArgumentNullException.ThrowIfNull(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        // A suspended session refuses before the policy is consulted. Re-evaluating
        // would allow the same command through, which is exactly what the suspension
        // exists to prevent.
        if (IsSuspended(nowMs))
        {
            ShellVerdict suspended = new(
                false,
                null,
                ShellRejection.DeniedByOperator,
                ErrorCodes.PermissionDenied);

            Record(verdict, executable, arguments, nowMs, exitCode: null, truncated: false, blocked: true);
            return suspended;
        }

        if (verdict.Allowed)
        {
            Record(verdict, executable, arguments, nowMs, exitCode: 0, truncated: false, blocked: false);
            return verdict;
        }

        RecordRejection(nowMs);
        Record(verdict, executable, arguments, nowMs, exitCode: null, truncated: false, blocked: true);

        return verdict;
    }

    /// <summary>Records a completed command's exit code and truncation.</summary>
    /// <param name="executable">The executable that ran.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="exitCode">Its exit code.</param>
    /// <param name="truncated">Whether its output was truncated.</param>
    /// <param name="nowMs">The current time.</param>
    public void Complete(
        string executable,
        IReadOnlyList<string> arguments,
        int exitCode,
        bool truncated,
        long nowMs)
    {
        ArgumentNullException.ThrowIfNull(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        Record(
            new ShellVerdict(true, null, null, null),
            executable,
            arguments,
            nowMs,
            exitCode,
            truncated,
            blocked: false);
    }

    /// <summary>
    /// Cap a command's captured output, reporting whether anything was lost.
    /// </summary>
    /// <param name="produced">How many bytes the command produced.</param>
    /// <returns>The bytes to keep and whether the result is incomplete.</returns>
    /// <remarks>
    /// This is the arithmetic of the cap, kept where the cap is defined so the two
    /// cannot drift. The exit code is not touched: a command that succeeded and
    /// produced too much output succeeded.
    /// </remarks>
    public (int Retained, bool Truncated) CapOutput(int produced)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(produced);

        return produced <= OutputCapBytesProperty
            ? (produced, false)
            : (OutputCapBytesProperty, true);
    }

    /// <summary>
    /// The exit code to record for a command that exceeded its deadline.
    /// </summary>
    /// <param name="elapsedMs">How long it ran.</param>
    /// <param name="timeoutMs">Its deadline.</param>
    /// <returns>The exit code, or null when it did not time out.</returns>
    /// <remarks>
    /// 137 is SIGKILL as a POSIX shell reports it, and the process group is what is
    /// killed. That matters because no shell is used, so there is no shell process
    /// whose exit would clean up the children: signalling only the direct child would
    /// leave whatever it spawned running.
    /// </remarks>
    public static int? ExitCodeForTimeout(long elapsedMs, int timeoutMs)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(elapsedMs);
        ArgumentOutOfRangeException.ThrowIfLessThan(timeoutMs, 1);

        return elapsedMs >= timeoutMs ? TimeoutExitCode : null;
    }

    /// <summary>Counts a refusal and suspends when the threshold is reached.</summary>
    /// <param name="nowMs">The current time.</param>
    private void RecordRejection(long nowMs)
    {
        long windowStart = nowMs - (SuspensionWindowSeconds * 1000L);

        // Drop everything older than the window, so the count is a rate rather than a
        // lifetime total. A lifetime total would eventually suspend a session that
        // was only occasionally refused.
        _rejectionTimesMs.RemoveAll(t => t < windowStart);
        _rejectionTimesMs.Add(nowMs);

        if (_rejectionTimesMs.Count >= SuspensionThreshold)
        {
            _suspendedUntilMs = nowMs + (SuspensionDurationSeconds * 1000L);
        }
    }

    /// <summary>Appends an audit entry, dropping the oldest when full.</summary>
    /// <param name="verdict">The verdict.</param>
    /// <param name="executable">The executable.</param>
    /// <param name="arguments">The arguments.</param>
    /// <param name="nowMs">The time.</param>
    /// <param name="exitCode">The exit code.</param>
    /// <param name="truncated">Whether the output was truncated.</param>
    /// <param name="blocked">Whether it was refused.</param>
    private void Record(
        ShellVerdict verdict,
        string executable,
        IReadOnlyList<string> arguments,
        long nowMs,
        int? exitCode,
        bool truncated,
        bool blocked)
    {
        // A refused command has no rule, so the reason string is the policy's and the
        // rule id is null. Both are kept: the reason tells the reader why, and the id
        // tells it what would have governed the command had it been allowed.
        string reason = blocked && verdict.Rejection is not null
            ? new ShellVerdict(false, null, verdict.Rejection, verdict.Error).Reason
            : "allowed";

        if (_auditLog.Count >= MaxAuditEntries)
        {
            _auditLog.Dequeue();
        }

        _auditLog.Enqueue(new ShellAuditEntry(
            nowMs,
            verdict.Rule?.Id,
            executable,
            [.. arguments],
            exitCode,
            ControllerFingerprint,
            blocked,
            truncated,
            reason));
    }
}
