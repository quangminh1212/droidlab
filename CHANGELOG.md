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
  fourteen conformance suites, all ten vector files wired to the versions on disk,
  `cargo clippy -D warnings` clean, `cargo fmt --check` clean, and CI runs the gate.

### Fixed

- Five vector defects, each found by the Rust core and each recorded as a finding
  rather than worked around:
  - `docs/findings/framing-body-not-cbor.md` — four of the six vectors in
    `protocol/vectors/framing-basic.json` carry a `body_hex` that is not the cbOR
    encoding their own `decoded.body` describes. The bytes are a truncated tail of
    the true body and one length prefix is off by one. This is the first
    implementation in this repository to decode those bodies as cbOR; neither the C#
    suite nor the Kotlin mirror had. The tests pin the defect rather than
    accommodate it.
  - `docs/findings/no-registry-severity-check.md` — `windows/DroidLab.Protocol/ErrorCode.cs`
    documents a `RegistryConformanceTests` that asserts its severity table agrees with
    `protocol/registry/dlwp-1.json`. No such test exists in the repository. The Rust
    suite now has the check.
  - `docs/findings/auth-label-lengths-wrong-in-prose.md` —
    `crypto-session-keys.json`'s `auth.proofs.baseline` note claims `"DLWP/1-client"`
    is 15 bytes and `"DLWP/1-agent"` is 14. They are **13 and 12**. The derivation is
    unaffected; only the note is wrong.
  - `docs/findings/discovery-length-arithmetic-does-not-sum.md` —
    `discovery.txt.minimal`'s `canonical_length_arithmetic` has 21 terms summing to
    **141** while it claims `= 121`. The `canonical_utf8` string and
    `canonical_length_bytes` are both correct at 121; the hand-written arithmetic is
    stale, and it gives `id`'s value as 21 where the UUID is 36.
  - `docs/findings/session-controller-sequence-gap.md` —
    `session-basic.json`'s controller sequence numbers are
    `1, 2, 3, 4, 5, 8, 9, 10` and **skip 6 and 7**, contradicting the vector's own
    `sequence_numbers` assertion that they "increase by one per frame sent by that
    side". The skipped values are exactly the numbers the agent used for its two
    `VIDEO_FRAME`s, which is the signature of a transcription slip. The agent's
    numbering is contiguous.

### Note

The Rust core is a **reference** in the sense ADR-0008 defines, and not in the sense
of being normative: the vectors remain the only interop contract, and none of the
three implementations is authoritative by construction. The Kotlin has never been
compiled in this environment — no Android SDK, no Gradle — and the Kotlin mirror is
evidence for its arithmetic only, never for its compilation.

[Unreleased]: https://github.com/quangminh1212/droidlab/commits/main
