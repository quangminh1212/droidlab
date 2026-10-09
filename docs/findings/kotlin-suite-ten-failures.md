# Finding: the Kotlin suite's ten failures, and what each one was

**Status:** fixed. Recorded because the classification matters more than the fix.

Compiling `android/core-protocol` for the first time surfaced 1111 errors. Fixing those
([`kotlin-never-compiled.md`](kotlin-never-compiled.md)) let the tests *run* for the first time,
and 10 of 105 then failed. They are not one kind of thing, and sorting them was the useful part:

| # | Test | Cause | Verdict |
| - | ---- | ----- | ------- |
| 1 | `CryptoPrimitivesTest.aFingerprintHasTheDeclaredFormat` | Asserted 4 dashes; a fingerprint has 3, and the assertion's own message said "three" | Test wrong |
| 2 | `VersionNegotiationTest.everyPairVectorNegotiatesItsDeclaredVersion` | Required 7 pair vectors; the file has 6 | Test wrong |
| 3 | `SessionReplayTest.replayingTheTranscriptReachesTheDeclaredStates` | Expected `ESTABLISHED` after the controller sends `AUTH` | Test wrong |
| 4 | `CapabilityNegotiationTest.theChannelLimitCountsTheControlChannel` | Built its "one below the limit" set by adding instead of removing | Test wrong |
| 5 | `HandshakeTranscriptTest.aWrongWidthFieldIsRefused` | Asserted on `length()`, which does not validate; `build()` does | Test wrong |
| 6 | `CapabilityNegotiationTest.everyDirectionVectorProducesItsDeclaredResult` | Compared `ErrorCode.name` (`BAD_STATE`) against the wire name (`ERR_BAD_STATE`) | Test wrong |
| 7 | `MalformedTest.everyRawFrameVectorMatchesItsDeclaredOutcome` | `Nul.asString()` on a legal `"expected_error": null` | Harness wrong |
| 8 | `MalformedTest.theSeverityComesFromTheCodeNotTheCallSite` | Same, via `expected_severity` | Harness wrong |
| 9 | `CapabilityNegotiationTest.everyLimitVectorProducesItsDeclaredResult` | Required `agent_limits`, which one legal vector omits on purpose | Harness wrong |
| 10 | `SessionReplayTest.everyMessageCodeMatchesTheRegistry` | Read `message_types` as an object; the registry stores an array | Harness wrong |

**No product defect was found.** The state machine, the fingerprint derivation, the channel
limit, the transcript validation and the registry reading are all correct, and four of the ten
failures were the test disagreeing with code that was right.

That is worth stating plainly because the opposite result was expected. The reasonable
prediction, given a suite that had never been executed, was that some assertions had been
written to match buggy behaviour -- a test written against an implementation rather than against
a specification often encodes the bug. It did not happen here, and the reason is visible in the
comments: the assertions cite the vectors and the RFC rather than the implementation's output.

## The four harness defects are the more interesting half

Numbers 7-10 are not test mistakes. They are defects in `Vectors.kt`, the shared fixture reader,
and each one made a *legal* vector file crash the test that read it:

* **`Nul.asString()` (#7, #8).** `expected_error` is present-and-null on every vector declared to
  succeed. Kotlin's `?.` does not skip it: the key exists, so the safe call proceeds and reaches
  the `Nul` object. Two tests died on the fixture rather than on the rule. Fixed by
  `asStringOrNull()`, which is the method that should have existed from the start -- the reader
  cannot treat "explicitly null" and "absent" as the same thing, because the vectors use both.

* **`agent_limits` required (#9).** One clamp vector tests the *screen* clamp and omits the
  limits object to exercise the defaults. The helper demanded it. A fixture reader that rejects a
  legal fixture is a reader that reports its own assumption as the fixture's defect.

* **`registryMessageCodes` (#10).** It iterated `message_types` as an object and destructured
  `(key, value)`. The registry stores an **array** of entries, each carrying its own `code`. The
  helper also documented, one line above itself, that the registry's keys are "a 0-based
  enumeration order while each entry's `code` field is the 1-based wire value" -- a claim about an
  object that does not exist. The array form is the better design, because a position in a list
  carrying meaning is exactly the confusion the helper was written to prevent.

## Why the JavaScript mirror did not catch any of this

It does not read `Vectors.kt`. It reimplements the arithmetic the *product* code performs and
runs that against the vectors directly. The fixture reader, the tests and their assertions are
all outside its scope, and that scope is defensible -- it is a mirror of the protocol, not of the
suite. The consequence is simply that "1461 Kotlin-mirrored checks hold" was never a statement
about any of the ten failures above, and it never claimed to be.

## The lesson

Ten failures, four of them in shared infrastructure, all of them invisible until something
executed the code. The mirror was checking the right thing and the repository drew the right
conclusion from it; what was missing was not a better mirror but a compiler. A test suite that
has never run is not evidence of anything, and its size is not evidence either -- 105 tests
looked like coverage and were, until now, a description of intent.
