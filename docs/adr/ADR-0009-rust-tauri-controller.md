# ADR-0009 — The Windows controller is Rust and Tauri, and the C# codec becomes a fixture

| Field | Value |
| ----- | ----- |
| **Status** | Accepted |
| **Date** | 2026-10-09 |
| **Supersedes** | [ADR-0002](ADR-0002-native-apps-over-cross-platform.md), in part — see §"What this supersedes" |
| **Amends** | [ADR-0008](ADR-0008-rust-as-the-reference-core.md) — Rust is no longer only a reference core |
| **Depends on** | [ADR-0007](ADR-0007-conformance-vectors-as-the-interop-contract.md) |

---

## Context

ADR-0002 chose native applications: a Kotlin agent on Android and a **C# / WPF** controller on
Windows. ADR-0008 then made Rust the reference core, on the grounds that it was the only
implementation of DLWP/1 in the repository that compiled and ran, and explicitly said it did not
supersede ADR-0002 or make C# second-class.

Three things have changed, and the third is decisive.

1. **The Rust core is now more complete than the C# one, not less.** It covers the frame header,
   cbOR, the error registry, limits, wire efficiency, crypto, pairing, classification, capability
   negotiation, version negotiation, discovery and the shell policy — every one of the ten vector
   files wired to the versions on disk, 235 tests, clean under `clippy -D warnings`.

2. **The Kotlin now compiles too**, so the "Rust is the only thing that runs" argument has been
   retired — see [`kotlin-never-compiled.md`](../findings/kotlin-never-compiled.md). Rust is
   still the reference core, but no longer for that reason.

3. **The controller needs a UI, and the choice is now between two stacks that both work.** The
   argument for C# was that it was the native, lower-risk choice. That argument has to be
   re-examined rather than assumed, because building the controller in Tauri would let it link
   the Rust core **directly as a library** instead of reimplementing DLWP/1 a third time in a
   process that must agree with the other two byte for byte.

The maintainer's decision is to move the controller to **Rust + Tauri**. This ADR records the
reasoning, the evidence that the stack works here, and what happens to the C# code.

## Evidence

A spike was built before this ADR was written, because "Tauri should work on Windows" is a claim
worth replacing with a measurement. It lives in `scratch/tauri-spike/` and is deliberately
throwaway.

Prerequisites, verified on this machine rather than assumed:

| Requirement | Found |
| ----------- | ----- |
| WebView2 runtime | **154.0.4258.62**, registered for the machine |
| Rust | 1.98.0 |
| MSVC linker | VS 2022 Community, MSVC 14.44.35207, `Hostx64\x64\link.exe` |
| crates.io reachable | Yes |

Results:

| Measurement | Value |
| ----------- | ----- |
| First release build | **1 min 05 s** (after a warm cargo registry) |
| Incremental release build | 78.7 s |
| Release binary | **8.13 MB**, single `.exe`, no bundler |
| Cold start | Window titled `DroidLab spike` within 5 s |
| Resident set | **27.2 MB** working set |
| WebView2 child processes | 12 |
| `invoke` round trip | Works — JS called two Rust commands and rendered both results |
| Dependencies pulled in | **407** crates in `Cargo.lock` |

Two findings from the spike that a plan would have missed:

* **`tauri` and `tauri-build` version independently** — 2.12.2 and 2.7.1. Pinning both to the
  same number fails to resolve, and a plan that assumed "Tauri 2.x" would have hit it on the
  first build.
* **`frontendDist` resolves relative to the directory holding `tauri.conf.json`**, not the
  package root. `../ui` from a config at the crate root points outside the crate and fails
  inside a `proc macro`, which reports it as a panic rather than as a configuration error.

## Decision

**The Windows controller is a Rust + Tauri 2 application that links `droidlab-protocol` directly.**

The consequences that matter:

* There is **one** implementation of DLWP/1 in the Windows process, not two. The controller's
  business logic and its protocol logic cannot disagree, because they are the same crate.
* The conformance story gets simpler in one direction and must be watched in the other. The
  controller no longer needs to agree with the Rust core because it *is* the Rust core; what it
  must still do is agree with the **Kotlin agent**, which is unchanged and remains governed by
  ADR-0007's vectors.
* The Tauri webview is an **untrusted rendering surface**. The controller renders device video,
  device file names, device log output and device-supplied strings. Every one of those crosses
  a process boundary from the phone. The CSP in the spike (`default-src 'self'`) is the floor,
  not the policy, and `invoke` is the only channel.

### What this supersedes

* **ADR-0002 is superseded for the controller only.** The Android agent stays Kotlin and native;
  that half of ADR-0002 stands, including its reasoning about not shipping a cross-platform
  runtime to the phone.
* **ADR-0008 is amended, not superseded.** Rust remains the reference core. It is additionally
  now the product language for the controller, which strengthens its position without changing
  what "reference" means under ADR-0007: the vectors are still the only interop contract and no
  implementation is authoritative by construction.
* **ADR-0003 (cbOR over JSON) and ADR-0004 (custom security layer) are unaffected.** Both are
  protocol decisions and neither is touched by the language of the controller.
* **ADR-0006 (ADB over Wi-Fi, no adbd bridge) is unaffected but becomes more likely to be
  revisited**, because the research found that ADB's pairing protocol needs BoringSSL's
  non-standard SPAKE2 and that the host-owned QR flow avoids the six-digit transcription
  entirely. That is an M5 decision, not this one.

## What happens to the C# code

**`windows/DroidLab.Protocol` and `windows/DroidLab.Tests` are retired as product code and kept
as a conformance fixture.**

They are not deleted, and the reason is the opposite of sentiment:

* 583 passing tests are evidence about DLWP/1's rules, written independently of the Rust core.
  Deleting them would delete an oracle. A third implementation that disagrees is information;
  three implementations that agree are stronger than two.
* They keep the C# exit open. If Tauri disappoints at M3's performance requirements — and video
  decode is the plausible place it would — the cost of returning is bounded, because the codec
  is still there and still passing.
* They are already wired to the same vectors, so their maintenance cost is near zero for as long
  as the vectors do not change.

What changes is their **status**:

| | Before | After |
| --- | --- | --- |
| Role | The controller's protocol codec | A second conformance oracle |
| Builds in CI | Yes, as the `windows` job | Yes, unchanged — a passing oracle that stops being built is a passive one |
| May be referenced by the controller | n/a | **No.** The controller is Rust; the C# is a sibling under ADR-0007's R3 rule, as it always was |
| Prevents changes to the vectors | No | No — but a vector change must now keep three implementations agreeing, which is the point |

The `windows/DroidLab.App`, `DroidLab.Core`, `DroidLab.Discovery`, `DroidLab.Adb` and
`DroidLab.Mirror` projects listed in `docs/architecture/REPOSITORY.md` are **cancelled**: they
were planned and never written, and they will never exist now. A new controller tree is defined
by this ADR's implementation work, and `REPOSITORY.md` must be updated to match — including its
layer diagram, which currently shows WPF at L4.

## Consequences

### Positive

* One protocol implementation on Windows instead of two, which removes a whole class of
  "the codec disagrees with the core" defect that ADR-0007's vector discipline exists to detect.
* An 8 MB binary with a 27 MB working set, against a WPF self-contained publish that lands in
  the tens to low hundreds of megabytes.
* The controller is written in the language the protocol core is written in, so a change to the
  core is a change the controller sees at compile time rather than a change it discovers at
  runtime.
* Tauri's capability and permission model gives the "what may the webview reach" question a
  declarative answer rather than a code-review answer.

### Negative

* **407 crates** enter the build. Each is a supply-chain and an audit surface, and the project's
  own dependency policy (R7: Apache-2.0-compatible only) now has 407 things to check rather than
  the handful the Rust core pulls in. This needs a real answer before M6, not a shrug.
* A webview is a **browser**, with a browser's patch cadence. On Windows that is WebView2, which
  updates with Edge and can change under an installed application.
* **Video decode is not yet proven.** The spike showed a window and an IPC round trip; it did
  not show a 60 fps H.264 stream through a webview. M3 must establish this early, and the
  fallback (native decode into a shared surface, bypassing the webview) must be designed for
  rather than discovered.
* The 583 C# tests become a maintenance obligation with no product to serve. That cost is real
  and is accepted deliberately, for the oracle value in the table above.
* Contributors who know C#/WPF and not Rust now have a steeper path. `CONTRIBUTING.md` says
  nothing about this yet and must.

### Neutral

* The repository gains a fifth and sixth language in its tree (`Rust` for the controller,
  TypeScript/HTML for the UI, alongside the existing Rust, C#, Kotlin and JavaScript). This is
  the price of the ADR-0007 sibling model applied to a product rather than a library.

## Obligations this creates

1. **Prove video decode before M3 is called done.** A webview rendering 60 fps H.264 is the
   single largest technical risk this ADR accepts. It is tested in the first week of M3, not
   the last, and a negative result means either a native decode path or a reversal of this ADR.
2. **Audit the 407 crates against R7** before M6. GPL/AGPL/SSPL anywhere in the tree fails the
   project's own rule, and the spike did not check.
3. **Write the CSP and capability allow-list as a design artefact**, not as a config field. The
   controller renders untrusted strings from a device it does not control.
4. **Update `docs/architecture/REPOSITORY.md`** — the directory map, the layer diagram and the
   dependency rules all describe a WPF controller that will not exist.
5. **Keep the C# job in CI.** An oracle that stops being exercised silently becomes a false one.
6. **Retire the spike.** `scratch/tauri-spike/` is evidence for this ADR and nothing else. It is
   not a foundation to build on, and the real controller starts from a clean tree.

## Alternatives considered

| Alternative | Why not |
| ----------- | ------- |
| **Keep WPF/C#, as ADR-0002 says** | It works and is lower-risk, and this was a genuinely close decision. It loses because it requires the controller to reimplement DLWP/1 a third time in a process that must agree with the Rust core byte for byte, and every such reimplementation is a place the three can drift. The cost is paid continuously; Tauri's cost is paid once, at M3's decode question. |
| **Rust with a native Windows GUI (egui, iced, slint)** | Avoids the webview and its patch cadence, and would make video decode a solved problem rather than an open one. Rejected because the UI work — a device list, a session view, a settings tree, log and shell panes — is the work a web toolkit does best, and because video can be decoded natively into a surface regardless of which toolkit draws the rest of the chrome. Worth revisiting if M3's decode question goes badly. |
| **Rust core + Electron front end** | A Chromium per install is a heavier answer to the same question, with a larger CVE surface and no benefit over WebView2 on a Windows-only product. |
| **Keep both: WPF product and Rust core, sharing nothing** | This is the current state, and it is the state that produces the drift ADR-0007 exists to detect. It is the most expensive option in the long run, not the cheapest. |
| **Delete the C# codec now that Rust ships the product** | Simpler tree, and it throws away 583 independent tests of the protocol's rules and the only other implementation that can disagree with the Rust core. Rejected: a second oracle is worth more than a tidy directory. |

## References

* [ADR-0002](ADR-0002-native-apps-over-cross-platform.md) — native apps over a cross-platform stack
* [ADR-0007](ADR-0007-conformance-vectors-as-the-interop-contract.md) — vectors as the interop contract
* [ADR-0008](ADR-0008-rust-as-the-reference-core.md) — Rust as the reference core
* [ADR-0006](ADR-0006-adb-over-wifi-instead-of-adbd-bridge.md) — ADB over Wi-Fi
* [docs/findings/kotlin-never-compiled.md](../findings/kotlin-never-compiled.md)
* `scratch/tauri-spike/` — the spike this ADR's measurements come from
