# ADR-0007 — Conformance vectors are the interoperability contract

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

There are two DLWP/1 implementations — Kotlin in the Android agent and C# in the
Windows controller (ADR-0002). They are written by different people, in
different languages, on different platforms, and they must agree **byte for
byte**: a frame produced by one and parsed by the other must round-trip exactly,
and a malformed frame must be rejected with the same error code on both sides.
Divergence is not a style issue; it is a broken product.

The usual methods to keep two implementations aligned are:

* a shared generated-code toolchain (a schema compiler and code generators),
* an integration test suite that runs both implementations against each other,
* a prose specification plus review discipline.

DroidLab has a prose specification (RFC-0001) and three languages' worth of
toolchain pain if it generates code, plus a CI cost for end-to-end tests that
require an actual phone.

## Decision

The **conformance vectors in `protocol/vectors/` are normative**. They are the
machine-checkable expression of the specification and the only accepted evidence
of interoperability. Vectors are hand-authored, hex-exact, human-readable JSON
files that both implementations consume through a shared runner. A change to the
wire format is incomplete — and fails CI — until:

1. `docs/rfc/` is updated,
2. `protocol/schema/` is updated,
3. `protocol/vectors/` contains or updates vectors that pin the new behaviour,
4. all vectors pass in both implementations.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| Generate both codecs from one schema | Attractive in principle; in practice a generator must emit idiomatic Kotlin and idiomatic C#, so it becomes a code-generation project with its own tests, and generated code hides the wire format behind an abstraction. It also cannot express semantic rules such as "reject non-increasing sequence numbers". |
| Prose specification plus review | The specification is necessary but not sufficient: two well-meaning reviewers will read "big-endian" or "ignored" differently, and nothing fails when they do. |
| An end-to-end test that pairs a real phone with a real PC in CI | Requires a device farm, is slow and flaky, and does not cover error paths such as a malformed frame or a replayed sequence number. It is a good *additional* check, not the primary one. |
| A shared C library with bindings on both sides | Reintroduces the native toolchain cost rejected in ADR-0002, and conflicts with rule R3 (the two protocol modules are siblings, not shared code). |
| Vectors only for the crypto layer | Insufficient: framing, header length, flag handling and the error model are equally capable of diverging. |

## Consequences

### Positive

* Interoperability is checked by CI on every pull request, in seconds, on both
  platforms, without any device.
* The vectors double as executable documentation: a newcomer can read a frame in
  hex and the map it decodes to.
* Error-path coverage is natural: negative vectors state the expected error code,
  so "reject the malformed frame" is tested as strictly as "parse the good one".
* A third-party implementation can prove conformance without reading DroidLab's
  code — which is what makes the specification meaningful.

### Negative

* Hand-authored hex is tedious and error-prone. Mitigated by
  `protocol/tools/` generators that produce candidate vectors from a description
  and by the vector linter (`npm run test:protocol`), which checks internal
  consistency (lengths match, digests recompute, error codes exist in the
  registry).
* Vectors must be maintained in lockstep with the RFC. The CI gate makes this
  mandatory rather than optional, which is the point.
* Some behaviour is hard to pin in a vector, notably timing. The vector set
  deliberately covers only deterministic behaviour; timing is covered by the
  performance budgets in `docs/operations/`.

### Neutral

* The runner is deliberately a small script, not a framework, so it can run in
  any CI environment. Both implementations expose a CLI (`droidlab-verify`) that
  loads the same vector directory and reports pass/fail per vector id.

## Compliance

* A pull request that changes `docs/rfc/RFC-0001-wire-protocol.md` or
  `protocol/schema/` without touching `protocol/vectors/` fails CI.
* A pull request that adds a vector whose expected error code is absent from
  RFC-0001 §6.2 fails CI.
* `droidlab-verify` must report zero failures on both implementations before a
  release is tagged.
