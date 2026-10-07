# ADR-0001 — Record architecture decisions

| Field | Value |
| ----- | ----- |
| Status | Accepted |
| Date | 2025-01-01 |
| Deciders | DroidLab maintainers |

## Context

DroidLab spans two platforms, two languages, a wire protocol and a security
model. Decisions made in one pull request (which primitive, which library, which
layer owns a concern) are easy to forget and easy to reverse accidentally. The
project needs a lightweight, durable record that a newcomer can read in order.

## Decision

Every decision that is architectural — affects more than one module, constrains
future work, or adds a third-party dependency to a protocol or session layer —
is recorded as an ADR under `docs/adr/`, using the template in
[README.md](README.md). ADRs are append-only; superseding an ADR means adding a
new one that references it.

## Alternatives considered

| Option | Why not |
| ------ | ------- |
| Comments in code | Invisible to someone orienting in the repository, and lost when the file is refactored. |
| A wiki | Lives outside the repository, goes stale, and cannot be reviewed in the same pull request as the code. |
| A single `DECISIONS.md` | Grows unbounded, produces merge conflicts on every concurrent change, and hides chronology. |

## Consequences

### Positive

* Design rationale is reviewable in the same pull request as the change.
* Newcomers can read the ADR index instead of asking "why is it like this?".
* Rule R6 of the repository layout has a concrete mechanism.

### Negative

* A small amount of writing overhead per decision.
* Contributors must learn the template.

### Neutral

* The ADR set is documentation only; it is not compiled or executed.

## Compliance

A reviewer rejects a pull request that adds a protocol- or session-layer
dependency without a corresponding ADR in the same pull request.
