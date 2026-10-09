# Repository layout and dependency rules

DroidLab is a polyglot monorepo. This file is the single source of truth for
**where code lives** and **which layer may depend on which**. Reviewers reject
pull requests that violate the dependency rules below.

> **Revised by [ADR-0009](../adr/ADR-0009-rust-tauri-controller.md) (2026-10-09).** The Windows
> controller is Rust + Tauri, not WPF. The `windows/DroidLab.App`, `DroidLab.Core`,
> `DroidLab.Discovery`, `DroidLab.Adb` and `DroidLab.Mirror` projects this file used to plan are
> **cancelled** — they were never written and will not be. `windows/DroidLab.Protocol` and
> `windows/DroidLab.Tests` remain, but change status: they are a **conformance oracle**, not the
> controller's codec, and no controller code may reference them.

## Directory map

```text
droidlab/
├── docs/                          Human-facing documentation
│   ├── rfc/                       Specification documents (normative)
│   ├── architecture/              Design notes, diagrams, decisions
│   ├── operations/                Runbooks, troubleshooting, release process
│   ├── findings/                  Defects found in fixtures, specs and the environment
│   └── adr/                       Architecture Decision Records
├── protocol/                      Language-neutral protocol source of truth
│   ├── schema/                    JSON Schema for every DLWP/1 frame
│   ├── vectors/                   Machine-readable conformance test vectors
│   └── tools/                     Generators and vector verifiers
├── rust/                          Rust protocol core (ADR-0008)
│   └── crates/
│       └── droidlab-protocol/     DLWP/1 codec, cbOR, crypto, session, shell policy
├── rust/controller/               Windows controller — the EXE (ADR-0009)
│   ├── src-tauri/                 Session manager, ADB client, capture, Tauri commands
│   └── ui/                        TypeScript + HTML rendered in the WebView2 surface
├── android/                       Android agent (the APK)
│   ├── app/                       Application module, UI, foreground service
│   ├── core-protocol/             DLWP/1 codec, pairing crypto, session state
│   ├── core-capture/              MediaProjection capture + H.264 encoding
│   ├── core-control/              Input injection, clipboard, shell, file transfer
│   └── gradle/                    Wrapper and version catalogue
├── windows/                       Conformance oracle, NOT the controller (ADR-0009)
│   ├── DroidLab.Protocol/         Second independent DLWP/1 codec (C#)
│   └── DroidLab.Tests/            xUnit suite — 583 tests, a second oracle under ADR-0007
├── scripts/                       Build, release and developer automation
└── .github/                       CI/CD workflows and repository templates
```

## Layer model

```text
        ┌──────────────────────────────────────────────────────┐
        │  L4  UI / Shell                                      │
        │      android/app        rust/controller/ui           │
        └───────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────────────┐
        │  L3  Feature services                                │
        │      capture · control · mirror · adb                 │
        └───────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────────────┐
        │  L2  Session & orchestration                         │
        │      pairing, transport, state machine                │
        └───────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────────────┐
        │  L1  Protocol (spec + codec)                         │
        │      protocol/ · droidlab-protocol · core-protocol    │
        └───────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────────────┐
        │  L0  Platform / stdlib / third-party                  │
        └──────────────────────────────────────────────────────┘
```

Note what is **not** at L1 any more: `windows/DroidLab.Protocol` is not part of the product's
dependency graph. It sits beside the product checking it, and the two must not import one another.

## Dependency rules

| Rule | Statement |
| ---- | --------- |
| R1   | Dependencies point **downwards only**. L*n* may reference L*n-1* or lower, never higher. |
| R2   | `protocol/` contains **no executable product code**. It holds schemas, vectors and generators only; the generators may not be imported by apps. |
| R3   | The three implementations — `droidlab-protocol` (Rust), `windows/DroidLab.Protocol` (C#) and `android/core-protocol` (Kotlin) — are **siblings**. They must not reference each other; behavioural equivalence is enforced by shared test vectors. |
| R4   | Android modules may not reference `rust/**` or `windows/**`, and vice versa. The only contract between the apps is the DLWP/1 specification in `docs/rfc/`. |
| R5   | Test projects may reference anything; product code may never reference a test project. |
| R6   | Adding a third-party dependency to L1 or L2 requires an ADR in `docs/adr/`. L3/L4 additions require a review comment justifying size, licence and maintenance. |
| R7   | Every dependency must be Apache-2.0-compatible. GPL/AGPL/SSPL dependencies are rejected. |
| **R8** | **The controller links `droidlab-protocol` and never re-implements DLWP/1.** ADR-0009 chose the Tauri stack precisely so the Windows process has one protocol implementation. A second one inside the controller is the defect that ADR exists to prevent. |

## Naming conventions

| Artefact | Convention | Example |
| -------- | ---------- | ------- |
| RFC documents | `RFC-NNNN-kebab-title.md` | `RFC-0001-wire-protocol.md` |
| ADR documents | `ADR-NNNN-kebab-title.md` | `ADR-0009-rust-tauri-controller.md` |
| JSON schemas | `<snake_case>.schema.json` | `video_frame.schema.json` |
| Test vectors | `<layer>-<feature>.json` | `crypto-hkdf-vectors.json` |
| Kotlin packages | `dev.droidlab.<module>` | `dev.droidlab.protocol` |
| Rust crates | `droidlab-<module>` | `droidlab-protocol` |
| Tauri commands | `snake_case` verb phrases | `connect_device`, `start_mirror` |
| C# namespaces | `DroidLab.<Module>` | `DroidLab.Protocol` |
| TypeScript modules | `kebab-case.ts` | `session-store.ts` |

## Where does a change go?

1. **Wire format changes** → edit `docs/rfc/`, bump `PROTOCOL_VERSION`, update
   `protocol/schema/`, add `protocol/vectors/`, then implement in `droidlab-protocol`
   and `android/core-protocol` — **and check the change still passes in
   `windows/DroidLab.Protocol`**, which is the third implementation and the one that
   catches a change made to satisfy only one codec.
2. **New capability** → add a capability flag in RFC-0001 §7, a Kotlin handler in the agent,
   a Tauri command and UI affordance in the controller, and an end-to-end test.
3. **New third-party library** → open an ADR first (see rule R6). The controller's Tauri
   dependency tree is the largest single addition the project has made (407 crates at
   ADR-0009's writing) and is audited against R7 before M6.
4. **Anything user visible** → update `README.md` and `docs/operations/`.
