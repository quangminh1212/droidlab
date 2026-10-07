# Protocol schemas

This directory holds the JSON Schema descriptions of every DLWP/1 message body.
They are the **documentation** form of the protocol: the wire form is cbOR
(ADR-0003), and the normative, machine-checked form is the vector set in
[`../vectors/`](../vectors/).

## Files

| Schema | Covers |
| ------ | ------ |
| [`frame_header.schema.json`](frame_header.schema.json) | The fixed 24-byte frame header (RFC-0001 §3). |
| [`message.schema.json`](message.schema.json) | A whole frame: header plus decoded body, plus the message-name registry. |
| [`error.schema.json`](error.schema.json) | `ERROR` bodies and the error-code registry (RFC-0001 §6). |
| [`capabilities.schema.json`](capabilities.schema.json) | `GET_CAPABILITIES`, `CAPABILITIES`, the capability-name registry, and the `limits` map (RFC-0001 §7). |
| [`pairing.schema.json`](pairing.schema.json) | `PAIR_REQUEST`, `PAIR_RESPONSE`, `PAIR_CONFIRM`, `PAIR_REJECT`, `PAIR_STATUS` (RFC-0002 §4.6). |
| [`session.schema.json`](session.schema.json) | Handshake, channel, shell, file, clipboard, device, log, app and session-end bodies (RFC-0001 §5, §7.4, §8). |
| [`video.schema.json`](video.schema.json) | `VIDEO_START`, `VIDEO_CONFIG`, `VIDEO_FRAME`, `VIDEO_STOP`, `VIDEO_STATS` (RFC-0001 §8.1). |
| [`input.schema.json`](input.schema.json) | `INPUT_TOUCH`, `INPUT_KEY`, `INPUT_TEXT`, `INPUT_SCROLL`, `INPUT_GESTURE` (RFC-0001 §8.2). |

## Conventions

* **Binary fields** are declared with `"contentEncoding": "base64"` (opaque bytes,
  such as media payloads) or `"contentEncoding": "base64url"` (fixed-width key
  material, nonces, ids and digests, so the JSON vectors stay compact and match
  the QR payload encoding). On the wire both are cbOR byte strings.
* **Integers only.** The protocol defines no floating-point fields, so schemas
  never use `"type": "number"`. Where a physical quantity would naturally be a
  float (touch pressure, scroll fraction), the schema uses an integer in a fixed
  scale and documents the scale.
* **`additionalProperties`** is `false` for closed sets (registries such as the
  error-code list) and `true` for extensible maps such as `details` and `params`,
  matching the RFC-0001 §3.2 rule that unknown keys are ignored rather than
  rejected.
* **Defaults** in a schema are the defaults in the RFC. They are advisory for
  readers; an implementation must use the RFC value.

## Relationship to the vectors

A schema says what a message *looks like*. A vector says what a message *is*, in
hex, and what must happen when it is wrong. Both must change together:

```powershell
# Fails if a schema or RFC changed without a matching vector change
npm run test:protocol
```

## Validating by hand

```powershell
# Validate a single decoded message against the whole schema set
node protocol/tools/test-vectors/verify.mjs --schema protocol/vectors/session-basic.json
```

The verifier is deliberately dependency-free so it runs in any CI environment.
