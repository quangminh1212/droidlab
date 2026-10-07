# Repository layout and dependency rules

DroidLab is a polyglot monorepo. This file is the single source of truth for
**where code lives** and **which layer may depend on which**. Reviewers reject
pull requests that violate the dependency rules below.

## Directory map

```
droidlab/
├── docs/                          Human-facing documentation
│   ├── rfc/                       Specification documents (normative)
│   ├── architecture/              Design notes, diagrams, decisions
│   ├── operations/                Runbooks, troubleshooting, release process
│   └── adr/                       Architecture Decision Records
├── protocol/                      Language-neutral protocol source of truth
│   ├── schema/                    JSON Schema for every DLWP/1 frame
│   ├── vectors/                   Machine-readable conformance test vectors
│   └── tools/                     Generators and vector verifiers
├── android/                       Android agent (the APK)
│   ├── app/                       Application module, UI, foreground service
│   ├── core-protocol/             DLWP/1 codec, pairing crypto, session state
│   ├── core-capture/              MediaProjection capture + H.264 encoding
│   ├── core-control/              Input injection, clipboard, shell, file transfer
│   └── gradle/                    Wrapper and version catalogue
├── windows/                       Windows controller (the EXE)
│   ├── DroidLab.App/              WPF shell, views, view models
│   ├── DroidLab.Core/             Domain model, orchestration, session manager
│   ├── DroidLab.Protocol/         DLWP/1 codec (mirrors core-protocol)
│   ├── DroidLab.Discovery/        mDNS/DNS-SD browse + advertise
│   ├── DroidLab.Adb/              ADB server client (wireless debugging)
│   ├── DroidLab.Mirror/           Decode and render the video stream
│   └── DroidLab.Tests/            xUnit test suite
├── scripts/                       Build, release and developer automation
└── .github/                       CI/CD workflows and repository templates
```

## Layer model

```
        ┌──────────────────────────────────────────────┐
        │  L4  UI / Shell                              │
        │      android/app          windows/DroidLab.App│
        └───────────────────────┬──────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────┐
        │  L3  Feature services                        │
        │      capture · control · mirror · adb         │
        └───────────────────────┬──────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────┐
        │  L2  Session & orchestration                 │
        │      pairing, transport, state machine        │
        └───────────────────────┬──────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────┐
        │  L1  Protocol (spec + codec)                 │
        │      protocol/ · core-protocol · Protocol     │
        └───────────────────────┬──────────────────────┘
                                │
        ┌───────────────────────▼──────────────────────┐
        │  L0  Platform / stdlib / third-party          │
        └──────────────────────────────────────────────┘
```

## Dependency rules

| Rule | Statement |
| ---- | --------- |
| R1   | Dependencies point **downwards only**. L*n* may reference L*n-1* or lower, never higher. |
| R2   | `protocol/` contains **no executable product code**. It holds schemas, vectors and generators only; the generators may not be imported by apps. |
| R3   | `DroidLab.Protocol` (C#) and `android/core-protocol` (Kotlin) are **siblings**, not shared libraries. They must not reference each other; behavioural equivalence is enforced by shared test vectors. |
| R4   | Android modules may not reference `windows/**` and vice versa. The only contract between the two apps is the DLWP/1 specification in `docs/rfc/`. |
| R5   | Test projects may reference anything; product code may never reference a test project. |
| R6   | Adding a third-party dependency to L1 or L2 requires an ADR in `docs/adr/`. L3/L4 additions require a review comment justifying size, licence and maintenance. |
| R7   | Every dependency must be Apache-2.0-compatible. GPL/AGPL/SSPL dependencies are rejected. |

## Naming conventions

| Artefact | Convention | Example |
| -------- | ---------- | ------- |
| RFC documents | `RFC-NNNN-kebab-title.md` | `RFC-0001-wire-protocol.md` |
| ADR documents | `ADR-NNNN-kebab-title.md` | `ADR-0002-use-kotlin-coroutines.md` |
| JSON schemas | `<snake_case>.schema.json` | `video_frame.schema.json` |
| Test vectors | `<layer>-<feature>.json` | `crypto-hkdf-vectors.json` |
| Kotlin packages | `io.droidlab.<module>` | `io.droidlab.protocol` |
| C# namespaces | `DroidLab.<Module>` | `DroidLab.Protocol` |

## Where does a change go?

1. **Wire format changes** → edit `docs/rfc/`, bump `PROTOCOL_VERSION`, update
   `protocol/schema/`, add `protocol/vectors/`, then implement in both codecs.
2. **New capability** → add a capability flag in RFC-0001 §7, an Android handler,
   a Windows view model command, and an end-to-end test.
3. **New third-party library** → open an ADR first (see rule R6).
4. **Anything user visible** → update `README.md` and `docs/operations/`.
