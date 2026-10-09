# Finding: no test compares any implementation's severities with the registry

**Status:** open. Verified by reading the sources; the Rust reference core now has the check.

## Summary

`windows/DroidLab.Protocol/ErrorCode.cs` states, in its own documentation, that a registry
conformance test exists and that severity drift fails the build:

> The registry is declared normative by RFC-0001 section 11, and its machine-readable encoding is
> `protocol/registry/dlwp-1.json`. The table below is a mirror of that file, and
> `RegistryConformanceTests` asserts the two agree: a code or severity that exists here but not in
> the registry, or the reverse, fails the build.

**There is no `RegistryConformanceTests`.** Nothing in `windows/DroidLab.Tests` reads
`error_codes` out of the registry, and no test anywhere compares a severity table with the
registry's.

## What is actually checked

* `protocol/tools/registry-check.mjs` validates the registry file's own shape and internal
  consistency. It does not read C# or Kotlin.
* `FrameClassifierTests.ErrorSeveritiesAreAsTheVectorsRequire` checks severities **against the
  vectors**, not against the registry. That is a real check, but the vectors name only the codes
  they exercise, so a code no vector mentions is unchecked.
* `VectorLoader` copies the registry next to the test binaries, and `CapabilityNegotiationTests`
  reads it — for capabilities, not for error severities.

## Why it matters

Severity is not decoration. RFC-0001 §6.2 makes a fatal error close the session and a recoverable
one leave it alone, so a code whose severity differs between the controller and the agent produces
a session where one side tears down the connection and the other waits for the next frame. That is
a hang, and it is the kind that appears only under a fault, which is exactly when the two
implementations are least likely to be compared.

The state today is correct — the Rust table matches the registry on all 22 codes, and the C# table
matches too — but it is correct by hand, and nothing would notice it ceasing to be.

## A second gap: the registry defines a `warning` severity that nothing models

`protocol/registry/dlwp-1.json` defines three severities in `error_severity_semantics`:

```json
{
  "warning":     "Informational; the session continues.",
  "recoverable": "Aborts only the affected operation or channel; the session continues.",
  "fatal":       "MUST be followed by SESSION_END, and the sender MUST close the connection."
}
```

`warning` is described as informational and explicitly leaves the session running. No implementation
has a `warning` case: the C# `ErrorSeverity` enum and the Rust `Severity` enum each have exactly
`Recoverable` and `Fatal`.

This is currently harmless, because **all 22 registered codes are `recoverable` or `fatal`** — 11 of
each — so no message can carry a `warning` severity today. It becomes a defect the moment a code is
registered with it, and the failure would be silent: a strict enum decode of the string `"warning"`
either errors or, worse, falls into a default.

Because the enum cannot represent the value, the one place it can bite is the ERROR message body,
where a peer sends its severity as a cbOR text string. A receiver that must accept any registered
severity needs a third case, or needs to document that it treats `warning` as recoverable.

## The check that now exists

`rust/crates/droidlab-protocol/tests/error_code_registry.rs` reads
`protocol/registry/dlwp-1.json` and asserts, for every code:

* the wire name matches;
* the severity matches; and
* every code the registry declares is present, and every code present is in the registry.

It is not a substitute for the C# test that was never written, and it does not make the Kotlin
correct. It does mean that one implementation is now checked against the normative file, which is
what the C# comment claimed of itself.

## Recommended follow-up

1. Write the C# test the comment already claims, or delete the claim from the comment. A
   documentation claim of a nonexistent safety net is worse than no claim, because it stops someone
   from building the real one.
2. Decide what `warning` means. Either remove it from the registry, or add the case to all three
   implementations and to the ERROR body's decoder.
