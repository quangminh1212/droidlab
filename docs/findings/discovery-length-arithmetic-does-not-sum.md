# Finding: `discovery.json`'s TXT length arithmetic does not sum to its own recorded length

**Status:** open — a protocol-owner decision is needed.
**Found by:** the Rust port, `crates/droidlab-protocol/tests/discovery_conformance.rs`,
`the_recorded_length_arithmetic_adds_up`.
**Severity:** documentation only. No code that reads the CANONICAL STRING is affected; the vector's
`canonical_utf8` and `canonical_length_bytes` are both correct.

## What is recorded

`vectors[0]`, `discovery.txt.minimal`:

```
canonical_utf8:            "DLWP/1-txt\0v=1.0\nid=11111111-2222-4333-8444-555555555555\nfp=9F3C-1A08-B7E2-44D1\ncaps=screen.mirror,input.touch\nport=45917"
canonical_length_bytes:    121
canonical_length_arithmetic:
  "10 (\"DLWP/1-txt\") + 1 (NUL) + 5 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 3 + 2 + 21 + 2 + 28 + 5 + 5 + 2 + 21 + 5 + 5 = 121"
```

## The defect

The arithmetic has **21 addends summing to 141**, and it claims the total is 121.

```
10 + 1 + 5 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 3 + 2 + 21 + 2 + 28 + 5 + 5 + 2 + 21 + 5 + 5
= 141
```

So the recorded arithmetic is **20 bytes too large**, and its own `= 121` contradicts its own terms. Every
other number in the vector is right:

| recorded | value | correct? |
| --- | --- | --- |
| `canonical_utf8` | 121 bytes | ✅ verified, byte for byte |
| `canonical_length_bytes` | 121 | ✅ matches the string |
| the arithmetic's terms | sum to 141 | ❌ |
| the arithmetic's stated total | 121 | ✅ as a total, ❌ as the sum of its own terms |

## Why the terms cannot be repaired by adjusting the total

The terms are also at the **wrong granularity and in the wrong order**. They decompose as
`label, NUL, bare-key-length, 1, value-length, ...` — 21 numbers — whereas the canonical form decomposes
into 17:

```
10 (label) + 1 (NUL)
  + 1 (v=)     + 3 (1.0)
  + 2 (id=)    + 36 (the UUID)
  + 2 (fp=)    + 19 (the fingerprint)
  + 4 (caps=)  + 25 (the capability list)
  + 4 (port=)  + 5 (45917)
  + 4 (the \n separators)
= 121
```

Two things are missing from the recorded arithmetic as written:

1. **The four `\n` separators.** 117 without them, 121 with them.
2. **The `=` between each key and its value**, five of them, if the terms are meant to be
   `key = value` triples rather than `key-length, separator-length, value-length`.

And the values are wrong: the recorded arithmetic gives `id`'s value as a run of `21` where the UUID is
36 bytes, and `caps` as `28` where the list is 25. Those look like leftover numbers from an earlier
revision of the vector — the UUID is now 36 characters, so `21` cannot be current.

The recorded 21-term shape matches neither reading, so **the arithmetic cannot be corrected by changing
its total**; the terms themselves are stale.

## The trap this is the opposite of

This repository has already found a fixture where three inserted bytes were exactly cancelled by a
`body_length + 3`, so every length check agreed while the meaning was wrong
(`docs/findings/framing-body-not-cbor.md`). This is the mirror image and it is a mild relief: here the
redundant number is **not** compensating, it is simply wrong, and the two independent records of the same
fact — the string and the total — **agree with each other and disagree with the third**.

That is worth noting for the process. The vector carries the same quantity three times
(`canonical_utf8`, `canonical_length_bytes`, and the arithmetic), which is why the inconsistency is
visible at all. A vector carrying `canonical_length_bytes` alone would have hidden it: the length is
right, so a length check passes.

## What the Rust port does about it

`the_recorded_length_arithmetic_adds_up` now:

1. parses the terms and asserts their sum against `canonical_length_bytes`, which **fails today** with
   `sum to 141 ... and the vector records 121`. The test is left asserting the CORRECT relationship, so it
   stays red until the fixture is fixed — the alternative, asserting the defect, would let a *correct*
   fix fail.
2. asserts the first term is the label's length and the second is the 1-byte NUL, which is what makes the
   terms' MEANING pinned rather than only their count.
3. asserts `terms.len() >= 20`, so a loop that reads no terms cannot pass vacuously.

The rest of the discovery tests pass, including a byte-exact check of `canonical_utf8` for all three TXT
vectors, so the wire format itself is unimplemented in no respect.

## Verification

```
$ node -e '...'      # the terms, summed
terms: 10 + 1 + 5 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 3 + 2 + 21 + 2 + 28 + 5 + 5 + 2 + 21 + 5 + 5
count: 21
sum of recorded terms: 141
recorded total:        121
actual canonical length: 121
```

```
$ cargo test --test discovery_conformance the_recorded_length_arithmetic_adds_up
discovery.txt.minimal: the arithmetic terms [10, 1, 5, 4, 4, 4, 4, 4, 4, 2, 3, 2, 21, 2, 28, 5, 5, 2, 21, 5, 5]
  sum to 141 and the vector records 121
```

## Options

1. **Regenerate the arithmetic from the canonical form** (recommended). It is derivable from
   `canonical_utf8`, so it cannot drift again if it is generated rather than written by hand. The
   corrected terms for `discovery.txt.minimal` are the 17 above, or the same 17 with the separators folded
   into an adjacent term.
2. **Delete `canonical_length_arithmetic`.** The `canonical_utf8` and `canonical_length_bytes` pair already
   pins the length, and the arithmetic is the only part that can disagree with itself.
3. **Leave it and document it.** Not recommended: the arithmetic exists precisely to show where the bytes
   come from, and a reader who sums it will conclude their implementation is wrong.

Option 1 is preferred on the same reasoning as the framing finding: the vector's prose is the
specification, and a hand-written derivation of a derivable quantity is a second source of truth that has
now been caught disagreeing.
