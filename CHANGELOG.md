# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **RFC-0001** — DroidLab Wire Protocol (DLWP/1) specification: transport, framing,
  version negotiation, error model, and capability discovery.
- **RFC-0002** — Pairing, mutual authentication and session security: QR pairing,
  X25519 key exchange, HKDF-SHA256 derivation, AES-256-GCM record encryption,
  replay protection and device revocation.
- Repository foundation: licence, contribution guide, security policy, code of
  conduct, issue and pull-request templates, CI skeleton.
- **RFC-0003** — discovery and advertisement.
- **RFC-0004** — shell safety policy.
- Conformance vectors: 10 files, 84 checks, with a verifier, a registry drift
  checker, a generated-file checker, a Kotlin conformance mirror and a mutation
  check. All 63 declared mutations are caught.
- **ADR-0008** — Rust is the reference core, and C# and Kotlin are siblings.
- **Rust reference core** (`rust/crates/droidlab-protocol`), which compiles and
  tests on every commit: the frame header and its codec, the protocol error-code
  registry with severities, the cbOR reader and writer, the session limits, the
  wire-efficiency helpers, the crypto primitives (labels, the seed rule, the HKDF
  key schedule, AES-256-GCM, the handshake transcript), pairing (fingerprint, code,
  proofs, X25519 and Ed25519), frame classification and its schema checks, the
  message-type registry, capability negotiation with limit clamping, version
  negotiation, discovery advertisement, the session state machine with sequence
  numbering and replay detection, and the shell policy. **235 tests** across
  seventeen test binaries, all ten vector files wired to the versions on disk,
  `cargo clippy -D warnings` clean, `cargo fmt --check` clean, and CI runs the gate.
- **The Kotlin protocol core builds, tests and is gated in CI**
  (`android/core-protocol`). It had never been compiled, on the belief that this
  project's environment had no Android SDK or Gradle. It had both — the module is a
  plain Kotlin/JVM module with no Android dependency, and `ANDROID_HOME` was simply
  unset. The first build found **1111 compile errors**; the first test run then found
  **10 failures**. All 105 tests now pass, warnings are errors, and a `kotlin` job in
  CI compiles and tests the module on every commit. Verified with a JDK 17 and the
  committed Gradle wrapper, with no Android SDK needed. See
  `docs/findings/kotlin-never-compiled.md` and
  `docs/findings/kotlin-suite-ten-failures.md`.
- `npm run check:kotlin-build` and `npm run check:all` — the gate that compiles and
  tests the Kotlin core. `npm run check` stays Node-only, as documented.

### Fixed

- **The Kotlin module's 1111 compile errors**: a `SortedSet` import that was never
  added, a `Pair<ErrorCode, String>` handed where an `ErrorCode` and a `String` were
  wanted, an `operator fun get` declared on `JsonValue.Obj` while every caller holds
  the `JsonValue` interface, and a block of assertions left outside its enclosing
  function by an earlier edit.
- **The Kotlin suite's 10 failures**, sorted rather than merely silenced:
  * Six were wrong assertions — a fingerprint asserted to have four dashes when it has
    three and the assertion's own message said three; a count of 7 pair vectors where
    the file has 6; `ESTABLISHED` expected after the controller sends `AUTH`, when the
    session is established on `AUTH_OK`; a "one below the limit" set built by adding
    instead of removing; a length refusal asserted on `HandshakeTranscript.length`,
    which does not validate, rather than `build`, which does; and `ErrorCode.name`
    compared against wire names that carry an `ERR_` prefix.
  * Four were defects in `Vectors.kt`, the shared fixture reader:
    `Nul.asString()` threw on the legal `"expected_error": null` that every succeeding
    vector carries, so two tests died on the fixture; `agent_limits` was required while
    one vector omits it deliberately to exercise the defaults; and `registryMessageCodes`
    read `message_types` as an object keyed by index when the registry stores an array
    of entries that each carry their own `code`.
  * **No product defect was found.** The state machine, the fingerprint derivation, the
    channel limit and the transcript validation were all correct.
- Five vector defects, each found by the Rust core and each recorded as a finding
  rather than worked around:
  * `docs/findings/framing-body-not-cbor.md` — four of the six vectors in
    `protocol/vectors/framing-basic.json` carry a `body_hex` that is not the cbOR
    encoding their own `decoded.body` describes. The bytes are a truncated tail of
    the true body and one length prefix is off by one. This is the first
    implementation in this repository to decode those bodies as cbOR; neither the C#
    suite nor the Kotlin mirror had. The tests pin the defect rather than
    accommodate it.
  * `docs/findings/no-registry-severity-check.md` — `windows/DroidLab.Protocol/ErrorCode.cs`
    documents a `RegistryConformanceTests` that asserts its severity table agrees with
    `protocol/registry/dlwp-1.json`. No such test exists in the repository. The Rust
    suite now has the check.
  * `docs/findings/auth-label-lengths-wrong-in-prose.md` —
    `crypto-session-keys.json`'s `auth.proofs.baseline` note claims `"DLWP/1-client"`
    is 15 bytes and `"DLWP/1-agent"` is 14. They are **13 and 12**. The derivation is
    unaffected; only the note is wrong.
  * `docs/findings/discovery-length-arithmetic-does-not-sum.md` —
    `discovery.txt.minimal`'s `canonical_length_arithmetic` has 21 terms summing to
    **141** while it claims `= 121`. The `canonical_utf8` string and
    `canonical_length_bytes` are both correct at 121; the hand-written arithmetic is
    stale, and it gives `id`'s value as 21 where the UUID is 36.
  * `docs/findings/session-controller-sequence-gap.md` —
    `session-basic.json`'s controller sequence numbers are
    `1, 2, 3, 4, 5, 8, 9, 10` and **skip 6 and 7**, contradicting the vector's own
    `sequence_numbers` assertion that they "increase by one per frame sent by that
    side". The skipped values are exactly the numbers the agent used for its two
    `VIDEO_FRAME`s, which is the signature of a transcription slip. The agent's
    numbering is contiguous.

### Note

The Rust core is a **reference** in the sense ADR-0008 defines, and not in the sense
of being normative: the vectors remain the only interop contract, and none of the
three implementations is authoritative by construction. All three now compile and
pass their tests, so the "two of three" caveat this note used to carry is gone —
and what replaced it is narrower. M1 is complete in the sense that three
implementations of one specification agree with one set of vectors, and no
handshake has ever crossed a socket, because nothing in M2 exists yet.

The Kotlin mirror stays. It was never the reason the module went unbuilt, and it
checks arithmetic the compiler does not and keeps working when the module does not
compile; `check:kotlin-build` checks the whole class of defect the mirror cannot see.
Retiring either would trade one blind spot for another.

[Unreleased]: https://github.com/quangminh1212/droidlab/commits/main
