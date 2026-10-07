# ADR-0006 — Drive wireless debugging through the platform ADB server

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

DroidLab's headline promise is that a Windows machine can treat an Android device
as a test environment. Two families of capability are involved:

1. **DroidLab-native capabilities** — mirroring, touch and key injection, clipboard,
   scoped shell, scoped file transfer, log streaming. These are implemented by the
   agent and carried inside DLWP/1.
2. **ADB capabilities** — anything the Android SDK toolchain expects: `install`,
   `shell`, `push`, `pull`, `logcat`, `screenrecord`, port forwarding, and
   integration with IDE tooling and CI steps that invoke `adb` directly.

The second family creates a design choice. Either DroidLab implements its own
equivalent of every ADB operation and hopes tooling stops caring about `adb`, or
DroidLab arranges for the *real* `adb` on the workstation to reach the device
over Wi-Fi.

Android 11 (API 30) added **wireless debugging** to the platform: `adb pair` with
a code, then `adb connect host:port`, after which the device behaves like a
USB-attached target for every ADB client on that workstation. The device keeps
`adbd` listening on a port, and the workstation's own ADB server manages the
transport.

## Decision

Prefer the platform's wireless-debugging path. The agent's job is to **make the
workstation's ADB server reach the device reliably and safely**: report the
device's wireless-debugging endpoint, detect whether `adbd` is in TCP mode,
surface the pairing state, and expose the outcome through DLWP/1
(`DEVICE_INFO_RESULT.adb_*` and the `adb.wireless` capability). The Windows
controller's `DroidLab.Adb` module drives the workstation's `adb` server
(`adb pair`, `adb connect`, `adb disconnect`, `adb -s <serial> …`) and shows the
resulting serial to the user.

DroidLab implements ADB-equivalent features natively **only** where the platform
does not offer them or where an operator has deliberately not enabled wireless
debugging. Those native features are the `shell.*`, `file.*`, `app.*`, `log.*`
and `input.*` families specified in RFC-0001. `ADB_MODE=auto|native|external`
selects the path.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| Bundle the `adb` binary on both sides and speak the ADB wire protocol from DroidLab | The ADB protocol is undocumented, version-coupled and asymmetric; reimplementing it would be a large, fragile surface, and the result would still not be the ADB server that IDE tooling connects to. |
| Push `scrcpy-server` and drive it over a socket (the scrcpy model) | Requires a working shell and a `/data/local/tmp` write, i.e. it presupposes ADB. It would make the native path depend on the thing it is meant to replace. |
| Implement everything natively and never use `adb` | Fails the real requirement: CI steps, IDE integrations and existing scripts call `adb`. A test environment that does not answer to `adb` is not a test environment for most teams. |
| Ask the user to run `adb tcpip 5555` and `adb connect` manually | That is precisely the friction DroidLab exists to remove. It remains available as a documented escape hatch. |
| Require a USB cable once to bootstrap | Reasonable, and it is a supported bootstrap path, but it cannot be the only one: the machine may not have a cable or a free port, and the device may be mounted in a rack. |

## Consequences

### Positive

* The device becomes a first-class ADB target, so anything that already speaks
  `adb` — IDEs, Gradle tasks, `uiautomator`, Appium-with-ADB, CI scripts — works
  unchanged.
* DroidLab does not reimplement ADB; the platform maintains it.
* A single addressable serial per device makes multi-device scripted testing
  straightforward (`adb -s <serial>`).
* When wireless debugging is not available (old Android, MDM policy, operator
  refusal), the native DLWP/1 families still deliver mirroring, input and scoped
  file access, so the product degrades rather than dies.

### Negative

* The user must enable Developer Options and Wireless Debugging on the device.
  The agent mitigates this with a guided flow, `adb.wireless` capability
  reporting, and deep links to the relevant settings screens where the platform
  allows them.
* Android's wireless-debugging port changes across reboots and re-pairings, so
  the stored endpoint goes stale. The controller must therefore always re-resolve
  the endpoint before use and must not cache a serial across device reboots.
* `adb pair` uses a 6-digit code that must be read off the device by a human.
  This is a second, unavoidable pairing step with a different trust model from
  DLWP/1 pairing; the UI must keep the two clearly separate, and documentation
  must not imply that DLWP/1 pairing grants ADB access.
* Wireless debugging is a debugging channel: it is powerful and, on a shared
  network, the operator must be able to turn it off. The agent exposes an
  explicit switch and never enables it silently.

### Neutral

* `adb` port 5555 (classic `adb tcpip`) and the modern pairing ports both work;
  the controller tries the stored endpoint, then the discovered one, then asks
  the user.

## Compliance

* The controller MUST NOT implement its own ADB wire protocol.
* Every ADB operation the UI offers MUST be expressible as an invocation of the
  workstation's `adb` binary, and the module that does so MUST be the only place
  in the codebase that spawns it.
* The agent MUST NOT enable wireless debugging without an explicit operator
  action, and MUST report the current state truthfully in `DEVICE_INFO_RESULT`
  (`adb_wireless_enabled`, `adb_endpoint`, `adb_pairing_required`).
* Documentation MUST state the two-pairing model: DLWP/1 pairing for DroidLab's
  own session, Android wireless debugging for ADB tooling.
