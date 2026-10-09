# Finding: `framing-basic.json` bodies are not valid cbOR

**Status:** open, verified against the committed vectors by the Rust reference core.

## Summary

Four of the six vectors in `protocol/vectors/framing-basic.json` carry a `body_hex` (and a
matching `frame`) whose bytes are **not the cbOR encoding** that the same vector's `decoded.body`
and `body_layout_example` describe. The recorded bytes are a truncated tail of the true body, cut
at an arbitrary offset, and they do not parse as a single cbOR document.

The two other vectors declare a zero-length body and are correct.

## Evidence

Take `framing.error.recoverable`. Its `decoded.body` is:

```json
{"code":"ERR_NOT_ALLOWED","message":"command is not in the allow list",
 "severity":"recoverable","request_type":80,"request_seq":905,
 "details":{"reason":"not_in_allow_list"}}
```

Its own `body_layout_example` says the body is `a4 65 636f6465 6d 4552525f…` — a four-pair map
whose first key is `code`.

Its `body_hex` is 70 bytes beginning `65 72 61 62` — the ASCII text `erab`. Decoded as cbOR that
is the text string `"erab"` followed by more text, not a map. The true body, reconstructed from
`decoded.body` in the RFC-0001 key order, is **149 bytes** and begins `a6 64 636f6465 6f 4552525f…`.

Aligning the two shows the recorded bytes are the true body's tail, and they diverge at one more
character:

```text
true  : "…a1 66 726561736f6e 71 6e6f745f696e5f…"   ('q' = 0x71 → a 17-byte text string)
record: "…a1 66 726561736f6e 72 6e6f745f696e5f…"   ('r' = 0x72 → an 18-byte text string)
```

`not_in_allow_list` is 17 bytes. So the vector's length prefix is off by one **as well as** the
body being cut short — the defect cannot be repaired by re-slicing alone.

### A second, independent disagreement: the `ENCRYPTED` flag

The same fixture disagrees with itself about encryption. Three of the four body-carrying vectors
set the `ENCRYPTED` flag (`0x01`), but carry **plaintext cbOR**:

```text
framing.hello.canonical              flags=0x0  encrypted=false  body starts  f7 00 0b 61 31 2e 30
framing.input-touch.normalised       flags=0x1  encrypted=TRUE   body starts  74 75 72 65 5f 69 64
framing.end-of-stream.channel-close  flags=0x5  encrypted=TRUE   body starts  61 73 6f 6e
framing.error.recoverable            flags=0x1  encrypted=TRUE   body starts  65 72 61 62
```

An encrypted body is `nonce(12) || ciphertext || tag(16)`, so a real encrypted frame's first bytes
would be an opaque nonce. These begin with printable ASCII. `framing.input-touch.normalised`'s body
opens `ture`; `framing.error.recoverable`'s opens `erab`.

The count matters: only **one** of the four body-carrying vectors (HELLO) is both cleartext and
carries a body. So a test that reasons "the flag is clear, therefore the body is checkable cbOR"
reaches exactly one vector, not four.

A standalone decode of all six bodies:

```text
framing.ping.empty-body              body_length=0    actual=0    ok (empty)
framing.pong-with-urgent-and-ack     body_length=0    actual=0    ok (empty)
framing.hello.canonical              body_length=247  actual=247  REJECTED: major 7 not permitted
framing.input-touch.normalised       body_length=81   actual=81   REJECTED: trailing 60 bytes
framing.end-of-stream.channel-close  body_length=18   actual=18   REJECTED: trailing 16 bytes
framing.error.recoverable            body_length=70   actual=70   REJECTED: trailing 64 bytes
```

## Why this went unnoticed

`body_hex` is internally consistent: for every vector it equals `frame[24 .. 24+body_length]`
exactly, and `body_length` matches both. So every existing check passes.

The reason nothing caught it is narrower and worth stating plainly: **neither the C# suite nor the
Kotlin mirror has ever parsed a `body_hex` as cbOR.** The C# `FrameClassifier` tests build their
own body bytes; the Kotlin mirror ports arithmetic and never reads these fields. The framing tests
in both languages check the 24-byte header and stop at byte 24.

The Rust reference core is the first implementation in this repository to decode these bodies, and
it found this within its first run. That is the argument for having a core that compiles.

The tests that now pin the defect are in
`rust/crates/droidlab-protocol/tests/cbor_rules.rs`:

* `the_cleartext_bodies_are_known_to_be_malformed` — asserts the four bodies do **not** parse, and
  fails the day they are corrected, which is the signal to re-enable the real assertions.
* `every_vector_declares_a_body_length_that_matches_its_bytes` — asserts the invariant that *does*
  hold, and counts that three of the four carry `ENCRYPTED` with a plaintext body.

Asserting a defect is unusual and deliberate here. Without it the finding is a document nobody
reads, and the tempting "fix" is to loosen the reader until it accepts these bytes — which would
break the encoding uniqueness the whole vector approach depends on.

## Consequence

The cbOR reader is **not** the thing at fault; it correctly refuses each body. The vectors are at
fault, and until they are corrected the following cannot be asserted anywhere:

* that a DLWP/1 body rounds trips through cbOR byte for byte;
* that `decoded.body` and `body_hex` describe the same message;
* that the canonical key order in `map_key_order` is the order the vectors' bytes actually use.

Nothing about the 24-byte header is affected: `framing-basic.json` remains sound as a **framing**
vector file, and all six header round-trips hold.

## Options

1. **Regenerate the four bodies** from their `decoded.body` in the RFC-0001 key order, with the
   lengths the `body_layout_example` implies, and re-derive `frame` and `body_length`. This fixes
   the file and makes the cbOR assertions available. It changes committed vector bytes, so it is a
   protocol-visible change and belongs in a changelog entry.
2. **Split the file.** Keep `framing-basic.json` as framing-only and move the bodies into a new
   `cbor-bodies.json` with correct bytes. The framing vectors then stop claiming something they do
   not demonstrate.
3. **Document the limitation** and have the Rust tests assert framing only, leaving the cbOR rules
   covered by hand-written cases. Cheapest, and it leaves a known-bad file in the tree.

Option 1 is the honest one. It is not done here because changing committed conformance vectors is a
decision for the protocol owner, not a side effect of adding a fourth implementation.
