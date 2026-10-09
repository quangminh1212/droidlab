# Finding: `session-basic.json`'s controller sequence numbers skip 6 and 7

**Status:** open — a protocol-owner decision is needed.
**Found by:** the Rust port, `crates/droidlab-protocol/tests/session_conformance.rs`,
`the_two_directions_number_independently`.
**Severity:** documentation only. The transcript's FRAMES are all correct and every one of them is a real
DLWP/1 message; only the numbering is inconsistent with the vector's own stated rule.

## What is recorded

The transcript's own assertion says:

> `sequence_numbers`: "Sequence numbers are session-global and increase by one per frame sent by that side.
> The two directions number independently, which is why both sides legitimately use sequence number 1 for
> their first frame."

The two directions, as recorded:

| step | actor | frame | `sequence_number` |
| --- | --- | --- | --- |
| 1 | controller | HELLO | 1 |
| 3 | controller | AUTH | 2 |
| 5 | controller | DEVICE_INFO | 3 |
| 7 | controller | CHANNEL_OPEN | 4 |
| 9 | controller | VIDEO_START | 5 |
| **13** | **controller** | **INPUT_TOUCH** | **8** ← |
| 14 | controller | INPUT_TOUCH | 9 |
| 15 | controller | SHELL_EXEC | 10 |
| 17 | controller | INPUT_TOUCH (replay) | 8 |

```
controller seqs: 1, 2, 3, 4, 5, 8, 9, 10, 8
agent      seqs: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
```

The **agent's** numbering is exactly what the assertion describes: contiguous from 1, increasing by one.

The **controller's** is not. It goes 1, 2, 3, 4, 5 and then jumps to 8. The two missing numbers, **6 and
7**, are exactly the numbers the agent used for its two `VIDEO_FRAME`s in steps 11 and 12:

| step | actor | frame | `sequence_number` |
| --- | --- | --- | --- |
| 11 | agent | VIDEO_FRAME | 6 |
| 12 | agent | VIDEO_FRAME | 7 |

## Why the shape of the gap points at a transcription slip

The controller's numbering is contiguous on both sides of the video section. Steps 1–9 give 1–5 with no
gap, and steps 13–15 give 8–10 with no gap. What is missing is precisely the pair `6, 7`, and precisely
where the agent was using `6, 7`.

That is the signature of the controller's numbers for the post-video frames having been taken from the
agent's counter rather than from its own. If the controller had simply omitted two frames, the numbers
after the omission would continue from 5 — that is, step 13 would be 6 — and there would be no gap at all.
Instead the numbers resume at exactly the value the *other* counter had reached.

Note also that step 17's replay is marked as re-sending "the same sequence number as step 13", i.e. 8, and
that is internally consistent whichever way the gap is resolved: if step 13 became 6, the replay would
become 6 as well.

## Why it matters, and why it does not break anything today

The assertion is a **MUST** about numbering: a sender that skips numbers makes its peer's gap detection
fire for no reason, and — more importantly — a receiver that relied on contiguity instead of a window
would either stall waiting for 6 and 7 or reject 8 as a replay. No implementation should rely on
contiguity, and the DLWP/1 reorder window is explicitly designed not to; that is why no vector catches this
and why the frame-level classification tests all pass.

But it means the transcript cannot be used as written to check a sender's numbering. A tester who asserted
"the controller's numbers are contiguous from 1" — which is what the assertion says — would mark a correct
implementation as failing.

It also means the two records disagree: the `sequence_numbers` assertion says "increase by one", and the
`steps` array does not. This is the same shape as
`docs/findings/discovery-length-arithmetic-does-not-sum.md` — a hand-written derivation of a derivable
quantity, caught disagreeing with its own source.

## What the Rust port does about it

`the_two_directions_number_independently` walks the transcript with one [`SequenceCounter`] per actor, and
it does **not** paper over the gap. It:

1. asserts the **agent's** numbering exactly, which is the claim the assertion makes and which holds;
2. records the controller's gap explicitly as `Some((13, 6, 8))` — the step, the number the counter
   expected, and the number recorded — and asserts those three values, so a correction to the vector fails
   the test loudly rather than being absorbed;
3. asserts that the skipped numbers `[6, 7]` are exactly the agent's two `VIDEO_FRAME` sequence numbers,
   which is what makes the diagnosis above checkable rather than a story;
4. asserts the controller's step list is `[1, 3, 5, 7, 9, 13, 14, 15, 17]` and that the agent's two
   `VIDEO_FRAME`s are at steps 11 and 12, which is what pins the census;
5. asserts the `deliberate_replay` exception separately, since a replay is deliberately not a fresh number.

The replay's own detection is unaffected, and is tested end to end: sequence 8 is accepted at step 13,
step 14's 9 is the next number, and step 17's re-send of 8 is `SequenceVerdict::Duplicate` with
`is_fatal()`, `ErrorCode::ReplayDetected`, `Severity::Fatal`, and the `protocol_error` reason on the
`SESSION_END`.

## Options

1. **Renumber the controller's steps 13–15 to 6, 7, 8** (recommended). This makes the transcript match its
   own assertion, and it makes the replay at step 17 a re-send of 6 rather than of 8. The change is
   confined to `session-basic.json`: three `sequence_number` values in the controller's frames, the error
   body's `request_seq` at step 18 (8, which names the replayed frame), and the note at step 17 that
   identifies "the same sequence number as step 13".
2. **Insert the two missing controller frames** (6 and 7), so the numbering becomes contiguous without
   renumbering. This requires inventing two frames, which the transcript does not contain, so it is a
   larger change and it changes what the transcript covers.
3. **Amend the `sequence_numbers` assertion** to say that the controller's numbering has a gap here and
   why. Not recommended: the gap is not a case the transcript means to pin, and an assertion that documents
   an accidental gap makes it permanent.

Option 1 is preferred, on the same reasoning as the discovery finding: the vector is the specification, and
where it disagrees with itself the derivable reading — "increase by one per frame sent by that side" —
should win over the incidental numbers.

## Verification

```
$ node -e '...'    # the two counters, walked independently
step actor      name              seq  ctr-counter  agent-counter
   1 controller HELLO                1
   2 agent      HELLO_ACK            1
   ...
   9 controller VIDEO_START          5
  10 agent      VIDEO_CONFIG         5
  11 agent      VIDEO_FRAME          6
  12 agent      VIDEO_FRAME          7
  13 controller INPUT_TOUCH          8 <-- GAP (expected 6)
  14 controller INPUT_TOUCH          9
  15 controller SHELL_EXEC          10
  16 agent      ERROR                8
  17 controller INPUT_TOUCH          8 <-- deliberate_replay
  18 agent      ERROR                9
  19 agent      SESSION_END         10

controller seqs: 1,2,3,4,5,8,9,10,8
agent seqs: 1,2,3,4,5,6,7,8,9,10
```

```
$ cargo test --test session_conformance
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
