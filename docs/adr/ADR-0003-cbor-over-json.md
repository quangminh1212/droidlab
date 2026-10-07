# ADR-0003 — cbOR over JSON for control frames

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

DLWP/1 frames need a structured body. Two natural choices dominate: JSON and
cbOR. DroidLab sends binary values (nonces, public keys, AEAD nonces, codec
configuration, file chunks up to 256 KiB) and, at 60 fps, up to 60 small control
or video frames per second per session.

Relevant forces:

* Binary fields must travel without base64 inflation (33% overhead) or awkward
  escaping.
* Frame bodies must be small: a touch move frame should stay under 64 bytes.
* Both a Kotlin and a C# codec must be implementable without pulling in a large
  dependency, and both must be deterministic for test vectors.
* Human debuggability matters during development, but not on the wire.

## Decision

Use **cbOR (RFC 8949)** with **text-string keys** for every DLWP/1 body. Binary
fields are cbOR byte strings. Integers are cbOR integers; the protocol defines no
floating-point fields. A `--pretty-json` debugging mode in both implementations
translates a frame to JSON for logs only and is never a wire format.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| JSON + base64 binary | 33% size inflation on codec config and file chunks, and every binary field needs a spec-defined base64 variant. Base64 also invites inconsistent padding and URL-safe/standard confusion. |
| JSON + a hand-rolled binary side-channel | Two encodings, two schemas, two sets of bugs. |
| MessagePack | Comparable to cbOR, but the canonicalisation rules for map ordering are less crisply specified, which weakens the deterministic test vectors. |
| Protobuf | Excellent tooling, but it requires a schema compiler and generated code in both builds, and proto3 cannot express "unknown fields must be preserved" as cleanly for the forward-compatibility rule DLWP/1 relies on. |
| Hand-rolled binary with fixed layouts | Smallest and fastest, but adding a field becomes a breaking change and debugging is painful. |
| cbOR with integer keys | Smaller on the wire, but unreadable in a hexdump and error-prone when hand-writing vectors. The size gain (~2 bytes per key) does not pay for the readability loss in the document that defines interoperability. |

## Consequences

### Positive

* Binary fields are native: no base64, no escaping.
* A touch frame body is on the order of 40 bytes.
* Deterministic encoding (definite lengths, sorted or as-specified key order) is
  achievable and is required for the conformance vectors.
* Unknown keys are ignored by design, which gives the protocol genuine forward
  compatibility without a compiler.

### Negative

* Both implementations need a cbOR codec; the project must implement or vendor
  one and, per rule R6, that requires this ADR.
* Frames are not eyeball-readable; developers need the debug translator.
* Reviewers must check that a change does not accidentally make encoding
  non-deterministic (for example, by using a hash-map iteration order where a
  sorted order is required).

### Neutral

* Half-precision and float support exist in cbOR but are unused; both codecs
  reject them for protocol fields.

## Compliance

* Every message body in `docs/rfc/RFC-0001-wire-protocol.md` is specified as a
  cbOR map with text keys and types.
* `protocol/schema/*.schema.json` describes the logical structure (JSON Schema
  is the documentation format; cbOR is the wire format).
* `protocol/vectors/framing-*.json` contains hex-encoded frames that must
  round-trip byte-for-byte in both implementations.
* A pull request that adds a float field, an integer key, or a non-deterministic
  map ordering is rejected.
