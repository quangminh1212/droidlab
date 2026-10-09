# The AUTH proof label lengths in `crypto-session-keys.json` are wrong

## Summary

`protocol/vectors/crypto-session-keys.json`'s `auth.proofs.baseline` vector states, in its own
`derived.note`:

> `"DLWP/1-client"` is 15 bytes and `"DLWP/1-agent"` is 14, so the two message strings differ in both
> label and length; the proofs must therefore differ even for identical inputs.

The labels are **13** and **12** bytes.

The vector contradicts itself, and the half that is right is the hex. Its own
`derived.client_proof_message_hex` and `derived.agent_proof_message_hex` decode to:

```text
client: "DLWP/1-client@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_"   45 bytes, label prefix 13
agent:  "DLWP/1-agent@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_"    44 bytes, label prefix 12
```

Both were produced by prefixing the label to a 32-byte transcript hash (`0x40`–`0x5F`), and the
recorded bytes have the label at 13 and 12 bytes. The two messages are 45 and 44 bytes, which is
consistent with 13 + 32 and 12 + 32. The prose says 15 and 14, which would make them 47 and 46.

## Why it went unnoticed

The **conclusion** the note draws survives the error. The claim being supported is that the two
labels differ in both content and length, and 13 vs 12 satisfies that exactly as 15 vs 14 would. So
every check that read the note as a justification for "the two proofs must differ" passed, because
the proofs *do* differ, for the reason stated.

Nothing compared the numbers. The three implementations all derive the labels from constants — none
derives a length from the prose — so no test had a reason to look.

## Why it is worth fixing

It is a **false statement in a normative file**. The vectors are the interoperability contract
([ADR-0007](../../docs/adr/ADR-0007-conformance-vectors-as-the-interop-contract.md)), and a reader
implementing from this file has been told the wrong byte count. A reader who trusts the number over
the hex will construct a 15-byte label — appending two bytes, or padding — and produce proofs that
agree with nothing. That is precisely the class of defect the file exists to prevent, and it is now
capable of causing it.

The failure would appear as an authentication failure with correct-looking inputs, which is expensive
to diagnose when the reasoning is "but the specification says 15 bytes".

## What the tests do

`rust/crates/droidlab-protocol/tests/crypto_conformance.rs`:

* `the_auth_proof_label_lengths_in_the_vector_prose_are_wrong` **asserts the defect**. It reads the
  vector's note, asserts it still claims 15 and 14, and then measures the labels out of the vector's
  own recorded hex. If somebody corrects the prose, this test fails and points at the note — so the
  correction cannot pass silently.
* `hmac_labeled_prefixes_the_message` asserts the true lengths, 13 and 12, with a comment recording
  that the vector's prose says otherwise and why the hex is the correct half.
* Every other label length in the crate is checked against `crypto-primitives.json`'s `labels` object
  by registry name in `the_labels_match_the_vector_file`, in both directions. This is the only label
  whose length appears in prose rather than as a value, which is why it is the only one that drifted.

## The fix, and why it is not in this change

Correct the note to say 13 and 12 bytes:

```diff
-      "note": "\"DLWP/1-client\" is 15 bytes and \"DLWP/1-agent\" is 14, so the two message strings
+      "note": "\"DLWP/1-client\" is 13 bytes and \"DLWP/1-agent\" is 12, so the two message strings
```

That is a one-line change and it is **a change to a committed conformance vector**, which is a change
to the interoperability contract rather than a side effect of adding an implementation. The same
reasoning applies as for
[`framing-body-not-cbor.md`](framing-body-not-cbor.md): a protocol-owner decision, recorded here
rather than taken here.

Unlike that finding, this one has no effect on any implementation. Nothing needs to change except the
sentence.

## Verifying the claim

```console
$ node -e "console.log('DLWP/1-client'.length, 'DLWP/1-agent'.length)"
13 12

$ node -e "
const v=require('./protocol/vectors/crypto-session-keys.json')
  .vectors.find(x=>x.id==='auth.proofs.baseline');
const cb=Buffer.from(v.derived.client_proof_message_hex,'hex');
const ab=Buffer.from(v.derived.agent_proof_message_hex,'hex');
console.log(cb.length, cb.indexOf(0x40));
console.log(ab.length, ab.indexOf(0x40));
"
45 13
44 12
```

## Related

* [`framing-body-not-cbor.md`](framing-body-not-cbor.md) — a larger defect in `framing-basic.json`
* [`no-registry-severity-check.md`](no-registry-severity-check.md) — a documented check that does not
  exist
