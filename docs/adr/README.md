# Architecture Decision Records

An ADR captures one decision, the alternatives that were considered, and the
consequences. ADRs are immutable once accepted: to change a decision, add a new
ADR that supersedes the old one. Rule R6 in
[docs/architecture/REPOSITORY.md](../architecture/REPOSITORY.md) requires an ADR
before any third-party dependency is added to protocol or session layers.

## Index

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](ADR-0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](ADR-0002-native-apps-over-cross-platform.md) | Native apps instead of a cross-platform stack | Accepted |
| [0003](ADR-0003-cbor-over-json.md) | cbOR over JSON for control frames | Accepted |
| [0004](ADR-0004-custom-security-layer-over-tls.md) | A purpose-built security layer instead of TLS | Accepted |
| [0005](ADR-0005-scrcpy-compatible-video-path.md) | Reuse the scrcpy-compatible H.264 path for video | Accepted |
| [0006](ADR-0006-adb-over-wifi-instead-of-adbd-bridge.md) | Drive wireless debugging through the platform ADB server | Accepted |
| [0007](ADR-0007-conformance-vectors-as-the-interop-contract.md) | Conformance vectors are the interoperability contract | Accepted |
| [0008](ADR-0008-rust-as-the-reference-core.md) | Rust is the reference core, and C# and Kotlin are siblings | Accepted |

## Template

```markdown
# ADR-NNNN — Title

| Field | Value |
| ----- | ----- |
| Status | Proposed / Accepted / Superseded by ADR-XXXX |
| Date | YYYY-MM-DD |
| Deciders | names |

## Context

What forces are at play? What is the problem?

## Decision

What we will do, stated in one paragraph, in the active voice.

## Alternatives considered

| Option | Why not |
| ------ | ------- |

## Consequences

### Positive

### Negative

### Neutral

## Compliance

How a reviewer checks that the decision is being followed.
```
