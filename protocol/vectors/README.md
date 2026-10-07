# Canonical byte encoding and key material

This file fixes the exact byte strings that every conforming implementation must
produce. Both codecs load it: the Kotlin one
(`android/core-protocol/src/test/kotlin/io/droidlab/protocol/ConformanceTest.kt`)
and the C# one (`windows/DroidLab.Tests/Protocol/ConformanceTests.cs`).

See [RFC-0001 section 3](../docs/rfc/RFC-0001-wire-protocol.md) and
[RFC-0002 section 4](../docs/rfc/RFC-0002-pairing-and-session-security.md).

## Framing

`frame` is the complete on-wire frame, hex encoded, header followed by body.
`decoded` is the same frame expressed as a cbOR item in cbOR diagnostic notation
(RFC 8949 section 8), with map keys in the order the encoder emits them.

`encoding_rules` states the canonical choices that make the bytes unique. An
implementation that produces different bytes for the same logical message is
non-conformant even if it can parse its own output.

## Labels

`labels` are the exact ASCII strings that are hashed or used as HKDF info.
They include the length prefixes and the direction, and they are
case-sensitive. A one-character difference produces a different key and a
session that fails at the first record.

## Seed rule

Key material in this file is derived from a single one-byte seed so that vectors
stay readable and so that both implementations reproduce them without embedding
fixed key bytes:

```
key(seed) = SHA-256( "DLWP/1-test-key" || 0x00 || seed )   # 32 bytes
```

For ed25519, `key(seed)` is used as the 32-byte seed of the private key
(RFC 8032 section 5.1.5), and the public key is derived from it. For X25519,
`key(seed)` is the scalar with the standard clamping applied by the
implementation (RFC 7748 section 5), and the public key is derived from it.

`signature_input` is a UTF-8 string; `signature_output` is the 64-byte Ed25519
signature in hex. An implementation must reproduce `signature_output` exactly
for the given seed, which pins both the seed handling and the signature scheme.

## What is deliberately absent

* Timestamps, nonce reuse and sequence-number overflow behaviour, because those
  are covered by behavioural vectors rather than byte vectors.
* Any platform-specific clamping, endianness or allocator detail, so that the
  same vectors apply to a JVM and to .NET.
