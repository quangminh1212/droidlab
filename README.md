<div align="center">

# DroidLab

**Turn an Android phone into a wireless test device for a Windows machine.**

Mirror the screen, drive it with touch and keyboard input, run scoped shell
commands, move files and stream logs — over Wi-Fi, with no cable and no cloud.

[![Protocol](https://img.shields.io/badge/protocol-DLWP%2F1-2f6f4e)](#the-dlwp1-protocol)
[![Conformance](https://img.shields.io/badge/conformance-84%2F84%20checks-2f6f4e)](#verifying-the-protocol)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![Android](https://img.shields.io/badge/android-11%2B%20(API%2030%2B)-3ddc84)](#requirements)
[![Windows](https://img.shields.io/badge/windows-10%20%7C%2011-0078d4)](#requirements)

</div>

---

## What this is

DroidLab is two applications that pair with each other:

| Component | Ships as | Runs on | Role |
| --------- | -------- | ------- | ---- |
| **DroidLab Agent** | `.apk` | Android 11+ | Captures the screen, injects input, exposes scoped shell, files, clipboard and logs. |
| **DroidLab Controller** | `.exe` | Windows 10/11 | Discovers devices, pairs, renders the mirrored screen, sends input, drives `adb`. |

Once paired, the phone behaves like a **local test device** attached to the
workstation: you can see it, tap it, script it, and point existing `adb`-aware
tooling at it.

> **Status: specification complete; the protocol codecs are implemented in C#, Rust and
> Kotlin.** The wire protocol, the security model, the shell safety policy and the
> 84-check conformance vector set are finished. The C# implementation is complete
> (`dotnet test` → 583 passing, 0 warnings), and the **Rust reference core** compiles and
> passes its own suite (`cargo test` → 78 passing, `cargo clippy -D warnings` clean) — see
> [ADR-0008](docs/adr/ADR-0008-rust-as-the-reference-core.md) for why Rust is the core and
> the other two are siblings. The Kotlin sibling exists with conformance tests wired to the
> same vectors — **but it has never been compiled**, because this project has no Android SDK
> or Gradle available to it. That distinction is stated wherever it applies and is not
> glossed over. See [Roadmap](#roadmap) for what is done and what is not, and
> [Verifying the protocol](#verifying-the-protocol) for exactly what is proven.

### What you get

- **Screen mirroring** — device-side H.264 encoding, hardware decode on the host,
  low-latency access-unit streaming. Nothing is sent through a cloud service.
- **Full input control** — touch with multi-pointer gestures, keycodes, text
  commit, scroll. The phone reacts as if you were holding it.
- **A real `adb` target** — the workstation's own ADB server reaches the device
  over Wi-Fi, so IDEs, Gradle tasks, `uiautomator` and CI scripts work unchanged.
- **Scoped shell, not a remote root shell** — an explicit, auditable allow-list of
  commands with per-argument validation. No shell interpreter is ever spawned.
- **Files, clipboard and logs** — scoped file transfer, clipboard sync and
  `logcat` streaming, all inside the same authenticated session.
- **Pairing by QR code** — no typing IP addresses, ports or codes.

---

## Why it exists

Testing on a physical Android device normally means a USB cable, a shared
screen, or a cloud device farm. A cable pins the phone to one machine and one
desk. A device farm puts source, logs and screen content on someone else's
infrastructure.

DroidLab takes the middle path: **the device stays on your desk and on your
LAN**, but behaves like a network-attached test target. The only thing that
leaves the machine is what you explicitly send.

---

## Architecture

```text
        ┌─────────────────────────────────────────────────────────────┐
        │                    Windows workstation                      │
        │                                                             │
        │   ┌─────────────────────────────────────────────────────┐   │
        │   │  DroidLab Controller  (DroidLab.App, WPF)           │   │
        │   │    mirror view · input · shell · files · logs       │   │
        │   └───────────┬─────────────────────────┬───────────────┘   │
        │               │                         │                   │
        │   ┌───────────▼───────────┐ ┌───────────▼───────────────┐   │
        │   │ DroidLab.Protocol     │ │ DroidLab.Adb              │   │
        │   │ DLWP/1 codec, crypto  │ │ drives the local adb      │   │
        │   └───────────┬───────────┘ │ server (adb pair/connect) │   │
        │               │             └───────────┬───────────────┘   │
        └───────────────┼─────────────────────────┼───────────────────┘
                        │                         │
                        │  DLWP/1 over TCP        │  ADB wire protocol
                        │  AES-256-GCM sealed     │  (platform-provided)
                        │                         │
        ┌───────────────▼─────────────────────────▼───────────────────┐
        │                  Android device (Wi-Fi / LAN)               │
        │                                                             │
        │   ┌─────────────────────────────────────────────────────┐   │
        │   │  DroidLab Agent  (foreground service)               │   │
        │   │    MediaProjection → MediaCodec (H.264)             │   │
        │   │    Accessibility/InputManager injection             │   │
        │   │    scoped shell · files · clipboard · logcat        │   │
        │   └─────────────────────────┬───────────────────────────┘   │
        │                             │                               │
        │                   ┌─────────▼──────────┐                    │
        │                   │ adbd (TCP mode)    │ ← enabled only by   │
        │                   │ wireless debugging │   the operator      │
        │                   └────────────────────┘                    │
        └─────────────────────────────────────────────────────────────┘
```

### The two-pairing model

This is the single most misunderstood part of the design, so it is stated
explicitly:

| | **DLWP/1 pairing** | **Android wireless debugging** |
| --- | --- | --- |
| **Trust anchor** | QR code scanned by the controller | 6-digit code read off the device |
| **Protects** | Mirroring, input, shell, files, logs | `adb`, and everything built on it |
| **Grants** | A DroidLab session | An ADB transport |
| **Specified in** | [RFC-0002](docs/rfc/RFC-0002-pairing-and-session-security.md) | Android platform |
| **Required for** | Every DroidLab feature | Only `adb`-based tooling |

**DLWP/1 pairing does not grant ADB access, and pairing ADB does not grant a
DroidLab session.** They are separate ceremonies with separate secrets. The
agent never enables wireless debugging silently — it is an explicit operator
action, and its state is always reported truthfully.

DroidLab implements its own mirroring, input, shell, file and log paths so that
the product still works when wireless debugging is unavailable — an old device,
an MDM policy, or an operator who has refused it.

---

## The DLWP/1 protocol

**DLWP/1** (DroidLab Wire Protocol, version 1) is the only contract between the
two apps. Neither app may reference the other's code; behavioural equivalence is
enforced by shared conformance vectors
([ADR-0007](docs/adr/ADR-0007-conformance-vectors-as-the-interop-contract.md)).

| Property | Choice | Rationale |
| -------- | ------ | --------- |
| Transport | Length-framed TCP, 24-byte header | Fixed offsets, no parsing ambiguity |
| Control body | [cbOR](https://www.rfc-editor.org/rfc/rfc8949), text keys | Compact, strictly canonical, no floats |
| Key agreement | X25519 ephemeral ECDH | Forward secrecy per session |
| Record protection | AES-256-GCM, derived nonces | Confidentiality + integrity per frame |
| Authentication | HMAC-SHA256 over the transcript | Mutual, binds both nonces and public keys |
| Versioning | Highest common version, no best-effort parsing | Fail loudly, never guess |

Full specification: **[RFC-0001 — DLWP/1](docs/rfc/RFC-0001-wire-protocol.md)**.

### Specification documents

| Document | Contents |
| -------- | -------- |
| [RFC-0001](docs/rfc/RFC-0001-wire-protocol.md) | Wire protocol: framing, message types, errors, capabilities, limits |
| [RFC-0002](docs/rfc/RFC-0002-pairing-and-session-security.md) | Pairing ceremony, threat model, key schedule, replay and revocation |
| [RFC-0003](docs/rfc/RFC-0003-discovery.md) | mDNS/DNS-SD discovery and advertisement canonicalisation |
| [RFC-0004](docs/rfc/RFC-0004-shell-safety.md) | Shell allow-list policy and argument validation |
| [ADR index](docs/adr/README.md) | Why the architecture is shaped this way |
| [Architecture overview](docs/architecture/OVERVIEW.md) | Component responsibilities and data flow |
| [Repository rules](docs/architecture/REPOSITORY.md) | Layout and dependency rules (R1–R7) |

---

## How it works

### 1. Discovery

The agent advertises `_droidlab._tcp` over mDNS/DNS-SD. The advertisement is
signed with the agent's Ed25519 identity key, and the payload is canonicalised
deterministically so the signature is unambiguous. A controller that holds a
pairing record for the advertised id verifies the signature; a mismatch means
the advertisement is forged and is treated as an attack, not a warning.

### 2. Pairing

```text
  Controller                                Agent
      │                                       │
      │  1. scan QR  ─────────────────────────►│  (out of band: camera)
      │     { agent_id, agent_pub, token }    │
      │                                       │
      │  2. HELLO          (cleartext) ──────►│  client_id, client_pub, nonces
      │  ◄──────  HELLO_ACK (cleartext)       │  agent_pub, capabilities
      │                                       │
      │  both sides compute:                  │
      │     transcript_hash = SHA-256(transcript)
      │     session keys    = HKDF(ECDH, transcript_hash)
      │                                       │
      │  3. AUTH           (encrypted) ──────►│  HMAC(pairing_secret, transcript_hash)
      │  ◄──────  AUTH_OK  (encrypted)        │  session_id, negotiated capabilities
      │                                       │
      │  ── session established ──            │
```

A **6-digit confirmation code** derived from both public keys is shown on both
screens. Comparing it by eye detects a man-in-the-middle during the pairing
ceremony itself — the one moment the QR code alone cannot protect.

The pairing token is single-use with a 120-second lifetime. Failed attempts are
rate-limited: 5 per minute, then pairing locks for 5 minutes.

### 3. Session

Every frame after `HELLO_ACK` is sealed. Sequence numbers are session-global and
strictly increasing; a repeat is `ERR_REPLAY_DETECTED` and is **fatal**. Either
side can revoke a pairing at any time, which immediately denies future sessions.

### 4. Mirroring

Following the shape proven by `scrcpy` ([ADR-0005](docs/adr/ADR-0005-scrcpy-compatible-video-path.md)):

```text
MediaProjection → encoder Surface → MediaCodec (H.264) → access units
    → DLWP/1 VIDEO_FRAME → Windows hardware decode → render
```

Codec configuration (SPS/PPS) travels once in `VIDEO_CONFIG`. No RTP, no WebRTC,
no media server.

### 5. ADB over Wi-Fi

The controller's `DroidLab.Adb` module is the **only** place in the codebase that
spawns `adb` ([ADR-0006](docs/adr/ADR-0006-adb-over-wifi-instead-of-adbd-bridge.md)):

```powershell
adb pair  192.168.1.42:37105  # once, with the 6-digit code from the device
adb connect 192.168.1.42:5555 # afterwards
adb -s 192.168.1.42:5555 shell pm list packages
```

Once connected, the device is a first-class ADB target for every tool on the
workstation. DroidLab does **not** reimplement the ADB wire protocol — that path
is undocumented, version-coupled, and would still not be the ADB server that IDEs
connect to.

### 6. Shell safety

Shell access is an allow-list, not a shell. There is no `sh -c` anywhere in the
design.

- Each rule pins an absolute executable path, a literal `argv_prefix`, a maximum
  argument count, and a per-position regex for every operand.
- Deny-listed binaries (`su`, `sh`, `rm`, `reboot`, …) always win over allow
  entries, and are checked first.
- A separate **allow level** (`read_only` vs `read_write`) gates *mutating* rules,
  so a vetted command still cannot change device state without a higher grant.
- Operator consent is the final gate: without it, even a perfectly matching rule
  is refused with `ERR_PERMISSION_DENIED`.
- Arguments are matched literally. Nothing is word-split, globbed or expanded.
- Repeated rejections rate-limit and suspend shell for that pairing, and surface
  a notification on the device.

Policy source of truth: [RFC-0004](docs/rfc/RFC-0004-shell-safety.md).

---

## Requirements

| | Requirement |
| --- | --- |
| **Android** | 11 (API 30) or newer; Developer Options available |
| **Windows** | 10 or 11, x64 or arm64 |
| **Network** | Both devices on the same LAN. No internet access required. |
| **ADB** (optional) | Platform-tools on `PATH`, for `adb`-based tooling only |
| **Build from source** | JDK 17+, Android SDK 34+, .NET 8 SDK, Node.js 20+ |

---

## Building from source

```bash
git clone https://github.com/quangminh1212/droidlab.git
cd droidlab

# Protocol checks — no toolchain beyond Node.js required
npm ci
npm run check
```

```powershell
# Android agent  ->  android/app/build/outputs/apk/release/app-release.apk
cd android
.\gradlew :app:assembleRelease

# Windows controller  ->  windows/DroidLab.App/bin/Release/net8.0-windows/DroidLab.App.exe
cd ..\windows
dotnet publish DroidLab.App -c Release
```

---

## Installing

### Android agent

Installation, in order:

1. Enable Developer Options (tap *Build number* seven times).
2. Install the APK: `adb install -r app-release.apk`, or open it on the device.
3. Open DroidLab Agent and grant the permissions it asks for. Each is used for
   exactly one documented feature:

   | Permission | Used for |
   | ---------- | -------- |
   | `POST_NOTIFICATIONS` | The mandatory foreground-service notification |
   | `FOREGROUND_SERVICE_MEDIA_PROJECTION` | Capturing the screen |
   | `ACCESS_NETWORK_STATE` / `INTERNET` | The LAN session |

   The agent declares no `INTERNET`-adjacent permission beyond the session, and
   ships no analytics, no crash reporter and no telemetry endpoint.

### Windows controller

To install:

1. Run `DroidLab.App.exe`. It is a normal desktop application and does not
   require elevation.
2. The first launch opens the device list and waits for an agent to appear.

---

## Pairing, step by step

1. On the **Android** device, open DroidLab Agent and tap **Show pairing code**.
2. On **Windows**, open DroidLab Controller, choose **Pair device**, and scan the
   QR code with the device's camera or by entering the shown payload.
3. Both screens display the **same 6-digit confirmation code**. Compare them.
4. Confirm on both devices. The pairing is stored, and the device appears in the
   controller's list from then on.

To also use `adb`-based tooling:

1. On the device, enable **Developer Options → Wireless debugging**.
2. In DroidLab Controller, choose **Enable ADB** and enter the 6-digit wireless
   debugging code shown on the device.

> These are two different codes on two different screens, by design. Step 3 of
> the pairing walkthrough protects the DroidLab session; the wireless-debugging
> code protects the ADB transport.

---

## Verifying the protocol

The protocol is the contract, so it is machine-checked. Every check runs with nothing
but Node.js — no Android SDK, no .NET, no Gradle:

```bash
npm run check
```

**1. Registry drift check** — fails if the normative registries in RFC-0001 and
their machine-readable encoding disagree, in either direction:

```text
message types    : RFC 42 / registry 42
error codes      : RFC 22 / registry 22
capability names : RFC 18 / registry 18
default limits   : RFC  9 / registry  9

The RFC and the machine-readable registry agree exactly, in both directions.
```

**2. Conformance vector check** — 84 checks over 10 vector files:

```text
vector files     : 10
checks executed  : 84
checks passed    : 84
checks failed    : 0
warnings         : 0

All vectors are internally consistent and agree with the RFC registries.
```

**3. Generated-file check** — the Kotlin error codes are generated from the registry
rather than hand-written, and this step regenerates them and fails if the committed copy
differs:

```text
ok    kotlin error codes is current
ok    1 generated file(s) verified
```

A generated file that is committed and never checked is worse than a hand-written one:
it looks authoritative and cannot be edited, so when it drifts from its source nobody
notices and readers trust the stale copy.

**4. Kotlin conformance mirror** — the Android protocol core cannot be compiled here, so
its arithmetic is reimplemented in JavaScript within the gate and run against the same
vector files. This is evidence for the Kotlin's *logic* and never for its compilation:

```text
ok    1461 Kotlin-mirrored checks hold against the real vectors
ok    framing decode, prefix arithmetic, round-trip, AAD and reserved flags
ok    cbOR shortest-encoding boundaries and the canonical empty body
ok    all 22 malformed vectors and all 3 sequence vectors classify as declared

NOTE  This validates the Kotlin logic, NOT that the Kotlin compiles.
```

**5. Mutation check** — breaks the mirrored logic on purpose, one rule at a time, and
fails if the gate does not notice. A check that cannot fail is worse than no check,
because it reports coverage of a rule nothing is testing:

```text
ok    baseline passes with 1461 checks
ok    63 mutations declared
ok    all 63 mutations caught
ok    the gate passes again after restoring
```

**6. Rust reference core** — the whole protocol, compiled and tested on every commit. This
is the only step whose result is evidence that an implementation **compiles and runs** as
well as that its logic is right:

```text
cargo fmt --all --check                         -> clean
cargo clippy --all-targets --all-features -D warnings -> clean
cargo test --all-features                       -> 79 passed, 0 failed
```

The suite is 78 integration tests plus the crate's own doctest, and it reads the same
`protocol/vectors/` files the other two do. Four claims it makes that nothing else did:

* **The framing vectors' bodies are not valid cbOR.** Four of the six carry a truncated
  tail of the body their own `decoded.body` describes, with one length prefix off by one.
  Neither the C# suite nor the Kotlin mirror had ever parsed a `body_hex` as cbOR, so two
  implementations passed over it. See
  [docs/findings/framing-body-not-cbor.md](docs/findings/framing-body-not-cbor.md).
* **`RegistryConformanceTests` does not exist.** `ErrorCode.cs` documents a test that
  asserts its table agrees with `protocol/registry/dlwp-1.json`; nothing in the repository
  does. The severity table is correct today, but by hand. See
  [docs/findings/no-registry-severity-check.md](docs/findings/no-registry-severity-check.md).
* **The registry assigns no numbers to error codes.** Unlike `message_types`, whose entries
  carry `"code": 1`, error-code entries have only `code` and `severity` — so an error code
  is identified on the wire only by its name.
* **The transport's savings are measured, not claimed.** 720 bytes of header recomputation
  saved over a one-second 60 fps stream, zero allocations per borrowed frame, and a
  compression threshold calibrated against the 81-byte hot-path body the vectors name.

This step exists because it has already found real holes. A video-clamp guard was inert
for every vector input; three crypto checks could not fail — the pairing code's byte
order, its zero padding, and the replay window's null high-water mark; and the beacon's
ascending key order could not fail, because the fields in the vector file are written in
an order that is already sorted. Seven of the session state machine's transition guards
survived as well, including the sequence-advance rule. Each of them *looked* covered until
a mutation survived.

The shell policy's path check was the same lesson in reverse. It tested four things, and
mutation testing showed that three of them changed no answer for ANY input: once the
executable's directory is compared for equality against the vetted list, a relative path, a
traversal path and a doubled slash all name a directory that is not on that list, so the
comparison refuses them without help. The three were deleted rather than kept, because a guard
that no input can distinguish from its absence is one that will silently stop working the day
the comparison changes.

**6. README consistency check** — reads the numbers out of this file and fails if they
no longer match the run (43 checks):

```text
ok    checks passed = 84 (README and the run agree)
ok    checks failed = 0 (README and the run agree)
ok    warnings = 0 (README and the run agree)
ok    error codes = 22 (registry and README agree)

All 43 README checks passed.
```

### What is verified, and what is not

The three implementations are siblings under ADR-0007: the vectors are the only interop
contract between them, and no language is the reference for another *by construction*. Rust
is the **reference core** in a narrower, practical sense that ADR-0008 defines: it is the one
that compiles and runs here, so a disagreement starts its investigation there. They are *not*
verified to the same degree, and the difference matters.

| | Rust (`rust/crates/droidlab-protocol`) | C# (`windows/DroidLab.Protocol`) | Kotlin (`android/core-protocol`) |
| --- | --- | --- | --- |
| Builds here | ✅ `cargo test`, `cargo clippy -D warnings` | ✅ `dotnet test` | ❌ no Android SDK, no Gradle |
| Conformance vectors | 🟡 framing + cbOR + registry + limits; crypto and session pending | ✅ 84/84 | ⚠️ wired to the same files; **never run** |
| Unit tests | ✅ 79 passing, 0 warnings | ✅ 583 passing, 0 warnings | ⚠️ written; **never compiled** |
| Panics in the codec | 🚫 denied by lint (`unwrap`, `expect`, `panic`, indexing) | ⚠️ no exceptions in the codec by convention | ⚠️ no exceptions in the codec by convention |
| Warnings as errors | ✅ `-D warnings`, `RUSTFLAGS=-D warnings` in CI | ✅ `TreatWarningsAsErrors=true` | ✅ configured, unenforced here |

The Kotlin side cannot be built on a machine without an Android SDK and Gradle, which is
the case for the environment this was written in. What that means concretely:

- The **fixture assumptions** were checked by reading the same field names out of the same
  vector files with a script. This caught three real mistakes — a wrong field name, a
  field in the wrong nesting, and the AAD vector being in `crypto-session-keys.json`
  rather than `framing-basic.json`.
- The **arithmetic** most likely to be wrong (prefix-length handling, the cbOR
  shortest-encoding rule, the output cap, the suspension window) was ported to
  JavaScript and run against the real vectors, and it holds.
- None of that is evidence that the Kotlin **compiles**. A file that has never been
  through a compiler is unverified, and calling it verified because a port of its logic
  passes would be exactly the kind of claim the rest of this repository refuses to make.
- The Kotlin mirror is a workaround with a known blind spot: it cannot see a type error, a
  missing symbol, or a wrong import. It stays because it checks arithmetic nothing else
  does, and it should be retired once the Kotlin compiles in CI — not kept because it is
  cheap.

Rust does not have that blind spot, which is the whole reason it is the core. Its 79 tests
run on every commit and its output is evidence that the code exists, compiles, and behaves.


The vectors are the interoperability contract. Two independent implementations —
the Kotlin codec and the C# codec — load the same files and must produce byte-identical
results. A vector that cannot be reproduced from its own inputs is treated as a defect,
because it makes wrong behaviour look verified.

| Vector file | Pins |
| ----------- | ---- |
| `framing-basic.json` | Byte-exact frame encodings, header offsets, map-key order |
| `malformed.json` | Every malformed input and the exact error, code and severity it must produce |
| `handshake-transcript.json` | Transcript layout, length prefixes, `transcript_hash` |
| `crypto-primitives.json` | Seed rule, HKDF schedule, AEAD construction |
| `crypto-session-keys.json` | Session key derivation and direction separation |
| `capabilities.json` | Capability negotiation and limit clamping |
| `discovery.json` | Advertisement canonicalisation and signature coverage |
| `shell-policy.json` | Allow-list verdicts, reasons and level gating |
| `session-basic.json` | A full session, including replay and error handling |
| `version-negotiation.json` | Highest-common-version selection |

---

## Repository layout

```text
droidlab/
├── docs/
│   ├── rfc/                 Normative specifications (RFC-0001 … 0004)
│   ├── adr/                 Architecture Decision Records + index
│   ├── architecture/        Overview, repository rules and dependency rules
│   └── operations/          Runbooks and release process
├── protocol/                Language-neutral source of truth
│   ├── registry/            Machine-readable normative registries
│   ├── schema/              JSON Schema for every DLWP/1 frame
│   ├── vectors/             Conformance vectors (the interop contract)
│   └── tools/               Registry drift checker, vector verifier
├── rust/                    Rust reference core (ADR-0008)
│   └── crates/
│       └── droidlab-protocol/  DLWP/1 codec, cbOR, limits, wire efficiency  ← builds & tests
├── android/                 Android agent — the APK
│   └── core-protocol/       DLWP/1 codec (mirrors DroidLab.Protocol)        ← exists, uncompiled
├── windows/                 Windows controller — the EXE
│   ├── DroidLab.Protocol/   DLWP/1 codec, crypto, session state             ← exists
│   └── DroidLab.Tests/      xUnit suite (583 tests)                         ← exists
├── docs/findings/           Defects found in the fixtures and the specs
├── scripts/                 Build and release automation
└── .github/                 CI workflows and templates
```

Modules marked `← exists` are the ones implemented today; the rest of the tree is
planned and is listed here so its boundaries are fixed before the code that has to
respect them is written. Nothing is claimed to exist that does not.

The `rust/crates/droidlab-protocol`, `android/core-protocol` and `windows/DroidLab.Protocol`
codecs are **siblings, not shared libraries**. They must not reference each other; the
vectors are what keeps them honest. Dependency rules R1–R7 are specified in
[docs/architecture/REPOSITORY.md](docs/architecture/REPOSITORY.md) and enforced in review.
Rust is the **reference core** in the sense ADR-0008 defines — the one that compiles and runs
here, so a disagreement starts its investigation there — which is not the same as being
authoritative over the other two.

After a lesson learned the hard way, the vectors are also treated as **code under review**.
Finding that four of six `framing-basic.json` bodies are not valid cbOR, after two
implementations had passed over them, is what established that a fixture can be wrong and
that nothing was checking the fixtures themselves. The Rust suite reads them, and where it
cannot yet assert them it asserts that it cannot.

---

## Roadmap

| Milestone | Scope | Status |
| --------- | ----- | ------ |
| **M0 — Specification** | RFC-0001…0004, ADRs, schemas, registries, conformance vectors, verifiers | ✅ Complete |
| **M1 — Protocol codecs** | C# codec (583 tests, 84/84 vectors); Rust reference core (79 tests, framing/cbOR/registry/limits wired); Kotlin sibling written and **not yet compiled** | 🟡 C# done, Rust in progress, Kotlin unverified |
| **M2 — Pairing + discovery** | QR pairing, mDNS advertisement and verification, session establishment | ⬜ Planned |
| **M3 — Mirror + input** | MediaProjection capture, H.264 streaming, hardware decode, touch/key/text | ⬜ Planned |
| **M4 — Shell + files + logs** | Allow-listed shell, scoped file transfer, clipboard, logcat | ⬜ Planned |
| **M5 — ADB integration** | `adb pair`/`connect` flow, endpoint re-resolution, serial surfacing | ⬜ Planned |
| **M6 — Release engineering** | Signed APK/EXE, CI matrix, reproducible builds, release notes | ⬜ Planned |

M1 is split rather than marked done, because its three implementations are not in the same
state. The C# codec passes every vector under `dotnet test`. The Rust core compiles, lints
clean, and passes 79 tests — but its conformance coverage is partial: framing, cbOR, the
error-code registry and the limits are wired to the real vectors, while the crypto,
handshake, discovery, session and shell modules are still to port. The Kotlin codec is
written and never compiled, because this project's environment has no Android SDK or Gradle.
Marking M1 complete would assert something untrue about two of the three, which is the
failure mode that [What is verified, and what is not](#what-is-verified-and-what-is-not)
exists to avoid.

---

## Security

The threat model is written down rather than assumed — see
[RFC-0002 §2](docs/rfc/RFC-0002-pairing-and-session-security.md). In short:

**Protected against:** passive eavesdroppers, active on-path attackers who inject
or replay, impersonating agents on the LAN, connection attempts without a
pairing secret, QR-code replay, pairing-token brute force, and listener flooding.

**Deliberately not protected against:** a compromised or rooted endpoint, traffic
metadata, a network operator who also sees the QR code, and first-use
authentication across the internet — DLWP/1 is a LAN protocol.

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md). Do not open a
public issue for a security report.

---

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

The one rule that matters most: **one logical change per commit**, using
[Conventional Commits](https://www.conventionalcommits.org/). Every commit must
leave `npm run check` green. Changing the wire format means changing the RFC, the
schema, the vectors and both codecs together — in that order.

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).

DroidLab's repository layout and parts of its documentation structure are
inspired by the IETF RFC and CNCF ADR conventions. Third-party dependencies and
the alternatives considered are recorded in [DEPENDENCIES.md](DEPENDENCIES.md).

<div align="center">
<sub>Built for people who test on real devices.</sub>
</div>
