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
  registry with severities, the cbOR reader and writer, the session limits, and the
  wire-efficiency helpers. 79 tests pass, `cargo clippy -D warnings` is clean, and
  CI runs the gate.

### Fixed

- `docs/findings/framing-body-not-cbor.md` — four of the six vectors in
  `protocol/vectors/framing-basic.json` carry a `body_hex` that is not the cbOR
  encoding their own `decoded.body` describes. The bytes are a truncated tail of
  the true body and one length prefix is off by one. Found by the Rust core, which
  is the first implementation in this repository to decode those bodies as cbOR;
  neither the C# suite nor the Kotlin mirror had. The tests pin the defect rather
  than accommodate it.
- `docs/findings/no-registry-severity-check.md` — `windows/DroidLab.Protocol/ErrorCode.cs`
  documents a `RegistryConformanceTests` that asserts its severity table agrees with
  `protocol/registry/dlwp-1.json`. No such test exists in the repository. The Rust
  suite now has the check.

### Note

The Rust core is a **reference** in the sense ADR-0008 defines, and not in the sense
of being normative: the vectors remain the only interop contract, and none of the
three implementations is authoritative by construction. The Kotlin has never been
compiled in this environment — no Android SDK, no Gradle — and the Kotlin mirror is
evidence for its arithmetic only, never for its compilation.

[Unreleased]: https://github.com/quangminh1212/droidlab/commits/main
