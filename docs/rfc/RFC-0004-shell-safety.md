# RFC-0004 — Shell Safety Policy

| Field | Value |
| ----- | ----- |
| **RFC number** | 0004 |
| **Title** | Shell Safety Policy |
| **Status** | Accepted |
| **Protocol version** | `1.0` |
| **Depends on** | [RFC-0001](RFC-0001-wire-protocol.md), [RFC-0002](RFC-0002-pairing-and-session-security.md) |

---

## Abstract

The `shell.exec` capability is the most dangerous part of DroidLab: it lets a
desktop peer run programs on the phone. This document defines the default-deny
policy, the allow-list grammar, the operator consent flow, the audit
requirements and the mandatory confirmations for destructive commands. It
applies to the agent's `SHELL_EXEC` handler and to the controller's UI that
drives it.

## 1. Principles

1. **Default deny.** A command runs only if it matches an allow-list rule *and*
   the operator has enabled shell access for that pairing.
2. **No shell interpretation.** The agent executes `command` with `args` as an
   argument vector. It MUST NOT invoke `sh -c`, `Runtime.exec(String)` or any
   API that expands metacharacters.
3. **Least privilege.** Rules are scoped to the narrowest executable path and,
   where possible, to a fixed argument prefix.
4. **Visible.** Every executed command appears in the device's audit log and in
   the controller's session log.
5. **Revocable.** The operator can turn shell access off at any time; existing
   sessions lose the capability immediately, not at the next reconnect.
6. **Reversible preference.** Read-only commands are prefered over mutating
   ones: when a rule could be expressed either way, the policy uses the form
   that cannot modify state.

## 2. Allow-list model

A rule is:

```
{
  "id": "sys.getprop",
  "exe": "/system/bin/getprop",
  "argv_prefix": [],            // optional fixed leading arguments
  "max_args": 4,
  "arg_patterns": ["^[A-Za-z0-9._-]{1,64}$"],   // regexes, one per position
  "timeout_ms": 5000,
  "allow_stdin": false,
  "description": "Read a system property"
}
```

Matching order:

1. If `exe` matches a **deny** rule, reject with `ERR_NOT_ALLOWED`
   (`details.reason = "deny_listed"`). Deny rules always win.
2. If no allow rule matches `exe`, reject with `ERR_NOT_ALLOWED`
   (`details.reason = "not_in_allow_list"`).
3. If a matching allow rule exists, validate `argv_prefix` and every argument
   against `arg_patterns`. A mismatch rejects with `ERR_NOT_ALLOWED`
   (`details.reason = "argument_rejected"`).
4. If the operator has not enabled shell for this pairing, reject with
   `ERR_PERMISSION_DENIED`.
5. Execute with a hard deadline of `min(timeout_ms, limits.shell_timeout_ms)`.

Regexes MUST be anchored and MUST be evaluated with a linear-time engine or a
length cap to avoid catastrophic backtracking; the agent additionally caps the
total command-line length at 4096 bytes.

## 3. Default rule set

### 3.1 Allowed by default (read-only)

| Rule id | Executable | Purpose |
| ------- | ---------- | ------- |
| `sys.getprop` | `/system/bin/getprop` | Read system properties. |
| `sys.dumpsys.cpuinfo` | `/system/bin/dumpsys` with `argv_prefix: ["cpuinfo"]` | CPU information. |
| `sys.dumpsys.meminfo` | `/system/bin/dumpsys` with `argv_prefix: ["meminfo"]` | Memory information. |
| `sys.dumpsys.battery` | `/system/bin/dumpsys` with `argv_prefix: ["battery"]` | Battery state. |
| `sys.dumpsys.window` | `/system/bin/dumpsys` with `argv_prefix: ["window"]` | Window state for test assertions. |
| `sys.dumpsys.activity` | `/system/bin/dumpsys` with `argv_prefix: ["activity"]` | Activity stack, used to wait for a screen. |
| `sys.dumpsys.package` | `/system/bin/dumpsys` with `argv_prefix: ["package"]` | Package state. |
| `sys.pm.list` | `/system/bin/pm` with `argv_prefix: ["list"]` | Installed packages. |
| `sys.pm.path` | `/system/bin/pm` with `argv_prefix: ["path"]` | APK path of a package. |
| `sys.am.force-stop` | `/system/bin/am` with `argv_prefix: ["force-stop"]` | Stop an app under test. |
| `sys.am.start` | `/system/bin/am` with `argv_prefix: ["start", "-n"]` | Start a specific component. |
| `sys.wm.size` | `/system/bin/wm` with `argv_prefix: ["size"]` | Current display size. |
| `sys.wm.density` | `/system/bin/wm` with `argv_prefix: ["density"]` | Current density. |
| `sys.settings.get` | `/system/bin/settings` with `argv_prefix: ["get"]` | Read a settings value. |
| `sys.ip` | `/system/bin/ip` with `argv_prefix: ["-o", "addr", "show"]` | Interface addresses. |
| `sys.netstat` | `/system/bin/netstat` | Connection list. |
| `sys.ps` | `/system/bin/ps` | Process list. |
| `sys.log.cat` | `/system/bin/logcat` with `argv_prefix: ["-d"]` | Dump the log buffer once (streaming uses `log.stream`). |
| `sys.uptime` | `/system/bin/uptime` | Uptime, useful for flakiness forensics. |
| `sys.date` | `/system/bin/date` | Clock, for log correlation. |
| `sys.screencap` | `/system/bin/screencap` with `argv_prefix: ["-p"]` | Single screenshot to stdout. |

### 3.2 Allowed only with an explicit operator grant

| Rule id | Executable | Guard |
| ------- | ---------- | ----- |
| `dev.input` | `/system/bin/input` | Requires the "Simulate input" switch; complements `input.*` frames when a test needs a real `input` invocation. |
| `dev.settings.put` | `/system/bin/settings` with `argv_prefix: ["put"]` | Requires "Modify device settings"; each call is logged with old and new value. |
| `dev.wm.size` | `/system/bin/wm` with `argv_prefix: ["size"]` | Requires "Change display size"; auto-reverted on session end when `revert_on_end` is set. |
| `dev.pm.grant` | `/system/bin/pm` with `argv_prefix: ["grant"]` | Requires "Grant runtime permissions". |
| `dev.pm.revoke` | `/system/bin/pm` with `argv_prefix: ["revoke"]` | Requires "Revoke runtime permissions". |
| `dev.pm.clear` | `/system/bin/pm` with `argv_prefix: ["clear"]` | Requires "Clear app data"; this deletes data and is never automatic. |
| `dev.logcat.buffer` | `/system/bin/logcat` with `argv_prefix: ["-b", "all", "-c"]` | Clears log buffers; requires "Manage log buffers". |

### 3.3 Always denied

| Executable or pattern | Reason |
| --------------------- | ------ |
| `su`, `sudo`, `magisk*` | Privilege escalation. |
| `sh`, `bash`, `dash`, `busybox` | Shell interpretation defeats argv-only execution. |
| `rm` | Irreversible deletion outside the scoped file API. |
| `dd`, `mkfs*`, `fstrim` | Block-device level operations. |
| `reboot`, `shutdown`, `svc`, `stop`, `start` | Device lifecycle; only the operator, on the device, may trigger these. |
| `pm uninstall`, `pm install` with a path outside the scoped file root | Package removal; installation goes through `app.install`. |
| `am broadcast` to system actions | Covert control channels; a test can use the app under test instead. |
| `setprop` on any key other than `debug.*` under an explicit grant | Persistent system modification. |
| Anything matching `*persist.*`, `*/data/system/*`, `*/proc/sys/*` as a write target | System configuration. |
| Any command whose resolved path is outside `/system/bin`, `/system/xbin`, `/vendor/bin`, `/apex/*/bin`, `/data/local/tmp` | Unvetted binaries. |

## 4. Operator consent flow

1. The agent's pairing detail screen shows a row per capability with a switch.
   Shell is **off** by default.
2. Turning shell on shows a dialog naming exactly what becomes possible and
   requiring an explicit confirmation gesture (a switch plus a confirm button,
   never a single tap).
3. The grant is per pairing, not global. Two controllers have two independent
   shell grants.
4. The grant can be narrowed to "read-only rules only" (§3.1), which is the
   RECOMMENDED setting for a shared lab device.
5. Revoking the grant MUST take effect immediately: the handler re-checks the
   grant before every execution and answers `ERR_PERMISSION_DENIED` afterwards.
6. The agent MUST keep a rolling audit log of at least the last 500 executions
   containing timestamp, rule id, executable, arguments, exit code and the
   controller's fingerprint. The log is visible on the device and exportable by
   the operator only.
7. The controller MUST display executed commands in the session log. A controller
   MUST NOT hide commands from its own log, even in "quiet" mode.

## 5. Controller-side rules

1. The UI MUST NOT offer a free-form shell box unless shell is enabled on the
   device; when it is, the box MUST show the rule that will match before
   execution and MUST reject input that matches no rule, client-side, with the
   same reason the agent would return.
2. Destructive or state-changing commands (`pm clear`, `settings put`,
   `wm size`, buffer clears) MUST require a second confirmation showing the
   exact argument vector.
3. The controller MUST persist a per-session command log and MUST make it
   exportable for test reports.
4. Automation clients that drive the controller API inherit the same policy:
   the API rejects commands that the policy would reject, and cannot bypass the
   operator's device-side grant.
5. A command that times out MUST be reported as a timeout, not as a failure of
   the device; the controller MUST NOT retry a mutating command automatically.

## 6. Failure and abuse handling

| Situation | Agent behaviour |
| --------- | --------------- |
| Unknown executable | `ERR_NOT_ALLOWED`, `details.reason = "not_in_allow_list"` |
| Deny-listed executable | `ERR_NOT_ALLOWED`, `details.reason = "deny_listed"`, audit entry marked `blocked` |
| Argument fails its pattern | `ERR_NOT_ALLOWED`, `details.reason = "argument_rejected"` |
| Shell grant disabled | `ERR_PERMISSION_DENIED` |
| Command exceeds deadline | Kill the process group, `SHELL_EXIT { exit_code: 137, truncated: true }` |
| Output exceeds 4 MiB | Truncate, set `truncated: true` in `SHELL_EXIT`, keep the exit code |
| 20 rejections in 60 s from one pairing | Suspend shell for that pairing for 5 minutes and surface a notification on the device |

## 7. Testing requirements

A conforming agent MUST ship tests that prove:

* every deny-listed executable is rejected even when an allow rule would
  otherwise match it,
* `sh -c "rm -rf /"` cannot execute, because `sh` is denied and arguments are
  never interpreted,
* a regex-bomb argument is rejected within a bounded time,
* revoking the shell grant stops execution on an already-established session,
* the audit log contains every executed and every blocked command.

The shared vectors `protocol/vectors/shell-policy.json` list
`(exe, args, policy) → verdict` cases that both implementations must reproduce.
