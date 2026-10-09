# ADR-0008 — Rust is the reference core, and C# and Kotlin are siblings

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-02 |
| Deciders | DroidLab maintainers |
| Related | ADR-0002, ADR-0007 |

## Context

ADR-0002 chose native apps: a Kotlin agent on Android and a C# controller on Windows. ADR-0007 then
made the conformance vectors the only interoperability contract between them, explicitly declining to
make either implementation authoritative by construction.

That pair of decisions has an assumption underneath it that turned out to be false: that both
implementations could be **run**. In this development environment the C# can be compiled and tested —
583 tests pass — but the Kotlin cannot. There is no Android SDK and no Gradle, and installing them is
not a matter of a package manager. So the Kotlin has never been through a compiler here, and no commit
in this repository may claim that it has.

> **Correction (2026-10-09, after this ADR was accepted).** The sentence above is wrong in its second
> half, and it is left standing because an ADR is a record of what was decided and on what grounds,
> not a document to be quietly revised when the grounds change. The Kotlin builds.
>
> Two facts were wrong. `android/core-protocol` is a **plain Kotlin/JVM module with no Android
> dependency**, which its own `build.gradle.kts` states; and this machine had a full Android SDK all
> along, at `C:\Users\GHC\AndroidSdk`. The one thing missing was `ANDROID_HOME`, and every check that
> concluded "no SDK" was reading that variable rather than looking at the disk. A `gradle wrapper` then
> supplied the rest, and the module compiled, tested, and failed in 1111 places and then 10 more.
>
> So the reasoning in this ADR is intact and its premise is not. Rust was already the right core for the
> reason given — it compiles and runs — and the Kotlin now does too, which strengthens the sibling model
> rather than weakening it: three implementations, three builds, one set of vectors. The mirror is kept
> for the reason in the consequences below, not retired, because it checks arithmetic the compiler does
> not. See `docs/findings/kotlin-never-compiled.md` and `docs/findings/kotlin-suite-ten-failures.md`.
>
> The transferable lesson is in the last bullet of the consequences.

The response so far was the Kotlin mirror: `protocol/tools/check-kotlin-vectors.cjs` ports the Kotlin's
arithmetic to JavaScript and runs it against the real vector files. It is a genuine technique and it has
found real defects — six in the frame classifier, one video clamp, one AUTH transition, one
sequence-numbering rule. But its own output says what it is:

```text
ok    1461 Kotlin-mirrored checks hold against the real vectors
NOTE  This validates the Kotlin logic, NOT that the Kotlin compiles.
      android/core-protocol has never been through a compiler here.
```

That note is honest and the limitation is real. A mirror proves what the *author* understood the code
to mean. It is silent on type errors, on borrow-style mistakes, on a function that does not exist, on
an import that resolves to the wrong symbol. And it is a second implementation maintained by hand,
which means the mirror and the Kotlin can disagree — a defect class that exists only because the
verification technique was invented to work around not having a compiler. Multiplied across three
languages, the mirrors are a maintenance burden with a failure mode of their own.

Rust closes the gap for a narrow, practical reason: **it compiles and runs here.** `cargo test` and
`cargo clippy -- -D warnings` produce real evidence on every commit, with no virtual device, no
emulator, and no cross-compilation.

## Decision

**Rust is the reference core of DLWP/1.** It lives in `rust/crates/droidlab-protocol`, implements the
whole protocol, and is the standard against which the other two are read.

The careful part of this decision is what "reference" does **not** mean:

* It does **not** supersede ADR-0007. The vectors remain the only normative encoding, and none of the
  three implementations is authoritative over the others by construction. A disagreement is still
  resolved by reading the vectors, not by pointing at Rust.
* It does **not** make the C# or the Kotlin second-class. They are **siblings**: the products ship on
  Android and Windows, and Rust ships no user-visible executable today.
* It does **not** retire the Kotlin mirror. The mirror checks the Kotlin's arithmetic, which nothing
  else does, and it should stay until the Kotlin compiles in CI.

What "reference" means is narrower and testable: **when the three disagree, Rust is the one whose
behaviour can be run rather than inferred, so it is where the investigation starts.** It is also where
the encoding decisions are cheapest to change, because a change costs one `cargo test` instead of a
two-language fixture edit.

Rust is additionally where the transport's efficiency work lives. The wire-level helpers in
`src/wire.rs` — a borrowing frame view, a cached header template, and a compression rule — are the kind
of code that must be measured to be believed, and measurements belong somewhere a test can assert on
them.

## Alternatives considered

| Option | Why not |
| ----- | ------- |
| Keep two implementations and rely on the Kotlin mirror | The mirror cannot see a type error, a missing symbol, or a wrong import, and it is a hand-maintained second implementation of the same logic. It also cannot be the *product*: nothing runs on a phone because a Node script agrees with it. |
| Make C# the reference core | It compiles here, so this was the closest alternative. Rejected because it makes the Windows controller authoritative over the Android agent, which inverts the dependency: the agent is the side with the device, the platform escalation, and the shell policy. It would also put the efficiency work in a language where the transport is not the bottleneck. |
| Add Gradle and the Android SDK to CI | The right long-term answer for the Kotlin, and it is not in competition with this ADR — see the consequences. It does not help this repository today, where no Android SDK is installable, and it would still leave the protocol's efficiency unmeasured. |
| Generate all three codecs from one schema | Raises the toolchain cost across three languages (ADR-0007 considered and declined it), and code generation would not have caught the defect that motivated this ADR: a vector file whose bodies are not valid cbOR. A generated codec reads the same broken fixtures. |
| Write the core in C or C++ | Same compilation property as Rust with none of the safety. This crate denies `unwrap`, `expect`, `panic` and indexing on the library target, because a panic in a codec reachable from the network is a denial of service. That property is enforced by the compiler rather than by review. |

## Consequences

### What this buys

* **A compiler on every commit.** Every claim about the protocol's behaviour is now backed by a run,
  not by a mirror. The 78 tests in `rust/crates/droidlab-protocol/tests` and the crate's own doctest
  are real evidence in a way the mirror's output is not.
* **A place defects surface.** The first Rust test run over the framing vectors found that **four of
  the six vectors in `framing-basic.json` carry bodies that are not valid cbOR** — a truncated tail of
  the body their own `decoded.body` describes, with one length prefix off by one
  (`docs/findings/framing-body-not-cbor.md`). Neither the C# suite nor the Kotlin mirror had ever
  parsed a `body_hex` as cbOR, so two implementations had passed over it. This is the concrete
  argument for the decision, and it arrived before the crate was three commits old.
* **A registry check that was claimed and missing.** `ErrorCode.cs` documents a
  `RegistryConformanceTests` that asserts its table agrees with `protocol/registry/dlwp-1.json`. That
  test does not exist anywhere in the repository (`docs/findings/no-registry-severity-check.md`). The
  Rust suite now has the check.
* **Measured efficiency.** The transport's optimizations are asserted in tests —
  720 bytes of header recomputation saved over a one-second 60 fps stream, zero allocations per
  borrowed frame, and a compression threshold calibrated against the 81-byte hot-path body the vectors
  name.

### What this costs

* **A third implementation to keep in step.** Every protocol change now touches three codebases. The
  mitigation is that the vectors are still the contract, so the change is driven by a fixture edit and
  a failing test in each language rather than by three people reading the same prose.
* **A second Rust target that does not exist yet.** The Tauri desktop shell and the Rust CLI tester are
  planned and unbuilt. Until they exist, this crate is a library with tests and no user.
* **Rust's async and FFI surface is not yet chosen.** The transport will need a runtime and the Android
  side will need JNI or a sidecar process. This ADR deliberately does not decide that, because deciding
  it now would be deciding it without the measurements.

### Obligations this creates

1. **The truthfulness rule is now stricter, not looser.** `cargo test` passing is evidence. The Kotlin
   mirror passing is not, and nothing may describe it otherwise. The mirror's own output must keep
   saying so.
2. **CI must run the Rust gate.** `.github/workflows/ci.yml` does. ~~and it deliberately has **no Kotlin
   job**~~ — **superseded by the correction above:** there is now a `kotlin` job, because the module
   builds with a JDK and the committed wrapper and no Android SDK. The reasoning that produced the
   absence — a job that cannot run would have to be skipped, and a skipped job reports success — was
   sound; the belief that it could not run was not.
3. **The Kotlin must compile in CI eventually.** ~~This ADR does not fix that and must not be read as
   excusing it.~~ **Done**, per the correction above. Two amendments to how this obligation resolves:
   the mirror is **not** retired, because it checks arithmetic the compiler does not and keeps working
   when the module does not compile; and the mirror is no longer the Kotlin's only evidence, which was
   the condition under which this ADR said the workaround was tolerable.
4. **A defect found in a fixture is a protocol-owner decision.** Regenerating the four broken bodies in
   `framing-basic.json` is the honest fix and is **not** done by this ADR, because changing committed
   conformance vectors is a change to the interop contract, not a side effect of adding an
   implementation.
5. **A claim that something cannot be built here is a claim to verify against the disk, not against an
   environment variable.** This is the lesson the correction above paid for. "No Android SDK" was
   concluded from `ANDROID_HOME` being unset while the SDK sat at `C:\Users\GHC\AndroidSdk`, and that
   conclusion kept 1111 compile errors and ten test failures out of sight behind a note that was honest
   about everything except its premise.

## References

* [ADR-0007](ADR-0007-conformance-vectors-as-the-interop-contract.md) — vectors as the interop contract
* [ADR-0002](ADR-0002-native-apps-over-cross-platform.md) — native apps over a cross-platform stack
* [docs/findings/kotlin-never-compiled.md](../findings/kotlin-never-compiled.md)
* [docs/findings/kotlin-suite-ten-failures.md](../findings/kotlin-suite-ten-failures.md)
* [docs/findings/framing-body-not-cbor.md](../findings/framing-body-not-cbor.md)
* [docs/findings/no-registry-severity-check.md](../findings/no-registry-severity-check.md)
* `rust/crates/droidlab-protocol/`
* `android/core-protocol/`
