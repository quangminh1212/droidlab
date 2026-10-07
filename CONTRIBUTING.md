# Contributing to DroidLab

Thanks for taking the time to contribute. This document is the short version of
how work gets done here; the long version is in
[docs/architecture/REPOSITORY.md](docs/architecture/REPOSITORY.md).

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Before you start](#before-you-start)
- [Development setup](#development-setup)
- [Making a change](#making-a-change)
- [Commit convention](#commit-convention)
- [One feature, one commit](#one-feature-one-commit)
- [Testing requirements](#testing-requirements)
- [Pull-request checklist](#pull-request-checklist)
- [Code style](#code-style)
- [Documentation](#documentation)
- [Protocol changes](#protocol-changes)
- [Security](#security)
- [Licence](#licence)

## Ways to contribute

* **Bug reports** — use the bug report template. Include the agent and controller
  versions, the protocol version, and the `droidlab-verify` output if the problem
  involves interoperability.
* **Feature requests** — use the feature request template. Describe the test
  workflow you are trying to run, not the implementation you have in mind.
* **Documentation** — typos, unclear steps and missing troubleshooting entries
  are all welcome, and are the easiest first contribution.
* **Protocol proposals** — open an RFC pull request. See
  [Protocol changes](#protocol-changes).
* **Code** — start with an issue so we can agree on the approach before you write
  a large patch. Small, obviously-correct fixes can go straight to a pull request.

## Before you start

* Read [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) — it
  explains the two-app model in ten minutes.
* Read the RFC that covers the area you are touching. If your change affects the
  wire format, that RFC is [RFC-0001](docs/rfc/RFC-0001-wire-protocol.md).
* Check the dependency rules. In particular: the Android and Windows apps share
  **no runtime code**, only the specification and the conformance vectors.
* If you are adding a third-party dependency to a protocol or session layer,
  open an ADR first.

## Development setup

### Prerequisites

| Tool | Version | Needed for |
| ---- | ------- | ---------- |
| JDK | 17 | Android build |
| Android SDK | Platform 34, Build-Tools 34.0.0, Platform-Tools | Android build and `adb` |
| .NET SDK | 9.0 | Windows build |
| Node.js | 20+ | Vector linting and commit tooling |
| Git | 2.40+ | Everything |

`scripts/dev-doctor.ps1` checks all of the above and prints exactly what is
missing.

### Clone and build

```powershell
git clone https://github.com/quangminh1212/droidlab.git
cd droidlab

# 1. Verify every conformance vector is internally consistent (fast)
npm ci
npm run test:protocol

# 2. Android agent
cd android
./gradlew :app:assembleDebug          # produces app/build/outputs/apk/debug/app-debug.apk
./gradlew :core-protocol:test         # protocol unit tests
cd ..

# 3. Windows controller
cd windows
dotnet build DroidLab.sln -c Debug
dotnet test DroidLab.Tests/DroidLab.Tests.csproj
cd ..
```

There is no need to own an Android device to work on most of the project: the
protocol layer, the vectors, the Windows session manager and the ADB client are
all testable without one. `scripts/run-emulator.ps1` starts the system image that
is already configured for manual end-to-end checks.

## Making a change

1. **Branch** from `main`: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`,
   `refactor/<slug>`, `chore/<slug>`, `test/<slug>`.
2. **Keep it scoped.** One logical change per branch and per pull request.
3. **Write tests first** for anything with observable behaviour. See
   [Testing requirements](#testing-requirements).
4. **Run the full local gate** before pushing:

   ```powershell
   scripts/check.ps1
   ```

   It runs the vector lint, the Kotlin tests, the C# tests and the formatting
   checks, and stops at the first failure.
5. **Open the pull request** and fill in the template completely. A pull request
   with an empty "How was this verified?" section will be sent back.

## Commit convention

DroidLab uses [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
The changelog is generated from commit messages, so the format is not cosmetic.

```
<type>(<scope>): <subject>

<body>

<footer>
```

| Element | Rules |
| ------- | ----- |
| `type` | One of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. |
| `scope` | Optional but recommended. Use a module or area: `protocol`, `agent`, `controller`, `discovery`, `pairing`, `capture`, `input`, `adb`, `mirror`, `docs`, `ci`. |
| `subject` | Imperative mood, lower case, no trailing period, at most 72 characters. |
| `body` | Wrapped at 72 columns. Explain **why**, not what — the diff says what. |
| `footer` | `BREAKING CHANGE: …`, `Refs: #123`, `Co-authored-by: …`. |

Examples:

```
feat(protocol): add HEVC negotiation to VIDEO_START

The AVC-only path forces re-encoding on devices whose hardware encoder is
more efficient with HEVC, which costs roughly 30% bitrate at the same
quality on the target devices. Negotiate the codec from the capability
list and keep AVC as the default so older controllers are unaffected.

Refs: #142
```

```
fix(pairing): reject QR payloads whose exp has passed

An expired QR image could still be scanned from a screenshot and would
produce a session against a stale ephemeral key, surfacing as a confusing
handshake mismatch. Validate exp before opening the socket.

Refs: #151
```

```
docs(rfc): specify the replay window in RFC-0002

BREAKING CHANGE: the reordering window is now explicitly 32 frames;
implementations that accepted unbounded reordering are non-conformant.
```

## One feature, one commit

This rule is deliberate and is enforced by review.

**Every self-contained function, capability or fix gets its own commit.** A
commit should be reviewable on its own, revertible on its own, and should leave
`main` in a state where the full test suite passes. Concretely:

* Do not batch unrelated changes. "Add ADB client and fix a typo in the README"
  is two commits.
* Do not commit a half-finished function. If a feature genuinely needs several
  steps, make each step a commit that builds and passes tests: the types and
  schema first, then the implementation, then the wiring, then the UI.
* Do not use `git commit -a` to sweep up whatever is dirty. Stage explicitly.
* A pull request may contain many commits; that is expected and preferred over
  one large squashed commit. The repository does **not** squash on merge.
* Each commit message describes the one thing that commit does. If you cannot
  write the subject line in imperative mood as a single action, the commit is
  doing too much.

Practical loop:

```powershell
git add android/core-protocol/src/main/kotlin/io/droidlab/protocol/FrameCodec.kt
git add android/core-protocol/src/test/kotlin/io/droidlab/protocol/FrameCodecTest.kt
npm run test:protocol
git commit -m "feat(protocol): implement DLWP/1 frame encoding" -m "Encodes the 24-byte header and a cbOR body, and pins the layout against protocol/vectors/framing-basic.json so the Kotlin and C# codecs cannot drift."
```

Commits must be **signed or verifiable by the author's configured identity**, and
`git config user.email` must match the address on the commits. Do not commit with
a placeholder identity.

## Testing requirements

| Change | Required evidence |
| ------ | ----------------- |
| Protocol codec (either language) | Unit tests **and** a passing `droidlab-verify` run over `protocol/vectors/`. |
| Protocol-visible behaviour | A new or updated vector in `protocol/vectors/`, plus the code that consumes it. |
| Security or pairing logic | Tests for the success path, the failure path and the replay/abuse path. No exceptions. |
| Android feature | JVM unit tests for the logic; an instrumented test where platform APIs are involved. |
| Windows feature | xUnit tests for the logic and the view model; UI code at least smoke-tested by hand and the steps written in the pull request. |
| Bug fix | A test that fails before the fix and passes after. State the failing test name in the pull request. |
| Documentation only | No test required; a link check and a spell check still run in CI. |

Never delete or weaken a test to make a change pass. If a test is genuinely
wrong, fix it in its own commit and explain why in the message.

## Pull-request checklist

Copy this into the description and tick every line. Reviewers use it as the
acceptance list.

```markdown
### Summary
One paragraph: what changes and why.

### Type of change
- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (see footer)
- [ ] Documentation
- [ ] Refactor / chore

### Components touched
- [ ] Android agent
- [ ] Windows controller
- [ ] Protocol / vectors / RFC
- [ ] Docs / CI / build

### How was this verified?
Exact commands and their observed results. "It works" is not evidence.

### Checklist
- [ ] The branch is up to date with `main`.
- [ ] Commits follow Conventional Commits and each commit is one logical change.
- [ ] `scripts/check.ps1` passes locally.
- [ ] New or changed behaviour has tests.
- [ ] Public behaviour is documented (README, RFC, or docs/).
- [ ] No secrets, keys, tokens or personal paths are committed.
- [ ] No new third-party dependency, or an ADR is included and linked.
- [ ] The wire format is unchanged, or RFC-0001, `protocol/schema/` and
      `protocol/vectors/` are all updated together.
- [ ] I have read CONTRIBUTING.md and agree to the licence terms.
```

## Code style

Formatting is automated; do not argue about it in review.

| Language | Tool | Command |
| -------- | ---- | ------- |
| Kotlin | `ktlint` via the Gradle plugin | `./gradlew ktlintFormat` |
| C# | `dotnet format` | `dotnet format DroidLab.sln` |
| Markdown | `markdownlint-cli2` | `npm run lint:md` |
| Everything | `.editorconfig` | handled by your editor |

Naming and structure conventions are in
[docs/architecture/REPOSITORY.md](docs/architecture/REPOSITORY.md).

Beyond formatting:

* Prefer clarity over cleverness. A slightly longer function that a reviewer
  understands in one pass beats a dense one that saves three lines.
* No unbounded queues, no unbounded retries, no unbounded caches. Every one of
  those must state its high-water mark, its drop or backoff policy and expose a
  counter.
* No swallowed exceptions. Catch, then either handle, rethrow with context, or
  log at a level that a bug report will surface.
* Do not log secrets, and do not log file contents from the device.
* Public APIs need doc comments; internal ones need clear names. Do not write a
  comment that restates the code.

## Documentation

Update documentation in the same pull request as the code it describes.

| If you change | Update |
| ------------- | ------ |
| A user-visible feature | `README.md` and, if it has steps, `docs/operations/` |
| A CLI flag or API surface | The reference section that documents it |
| The wire format | `docs/rfc/RFC-0001-wire-protocol.md`, `protocol/schema/`, `protocol/vectors/` |
| A dependency or a structural decision | A new ADR |
| Anything a user must do differently after upgrading | `CHANGELOG.md` (the release tooling reads it) |

## Protocol changes

The wire format is a public contract, so it has its own process:

1. **Open an RFC pull request** that modifies the relevant RFC document. Do not
   open a code pull request first.
2. State in the RFC whether the change is **additive** (new frame, flag,
   capability or optional key) or **breaking** (changed semantics, removed field,
   changed default).
3. Add the JSON Schema in `protocol/schema/`.
4. Add executable vectors in `protocol/vectors/` — including negative vectors for
   every new rejection path.
5. Once the RFC is accepted, implement the codec in **both** languages and wire
   up the feature.
6. CI enforces that an RFC or schema change without a vector change fails, and
   that vectors pass in both implementations.

A breaking change requires a new protocol version, an entry in RFC-0001 §10 and a
migration note in the release notes. There is no silent downgrade path.

## Security

Do not report vulnerabilities in a public issue. See
[SECURITY.md](SECURITY.md) for the private channels, the response targets and the
scope. If your contribution touches pairing, key derivation, record protection,
the shell policy or file scoping, say so in the pull request so a maintainer with
security context reviews it.

## Licence

DroidLab is licensed under the [Apache License 2.0](LICENSE). By submitting a
pull request you agree that your contribution is licensed under the same terms,
and you confirm you have the right to submit it. Do not paste code from a project
whose licence is incompatible; do not paste code whose licence you have not
checked.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report
unacceptable behaviour to the maintainers listed there.

## Questions

Open a discussion, or ask in the pull request. There are no silly questions about
the protocol; if a sentence in an RFC is ambiguous, that is a documentation bug
and we want to fix it.
