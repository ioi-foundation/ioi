# ADR 0037: Room Attempts Retain The Exact Host Admission Owner

- Status: Accepted
- Date: 2026-08-26
- Owners: OutcomeRoom / Attempt contract owners / ioi.ai orchestration
  application
- Refines: ADR 0030 (rooms are a composition), ADR 0036 (hosted native
  participation)
- Confidence: settled by repository-owner ruling after live M04.8 evidence.

## Context

The canonical `OutcomeRoom` contract permits `host_domain_ref` to name either
the accountable `system://` host or a separately resolved `domain://` host.
The current M04.7 hosted profile deliberately chooses the first form: the field
must equal the exact active room System because general domain-owner resolution
does not exist.

The room-scoped `Attempt` coordinate had a narrower `domain://`-only pattern.
That made an honest Attempt over an M04.7 room contract-invalid. Converting the
System ref into an invented domain alias would make the frozen coordinate pass
the schema while ceasing to describe admitted room truth.

## Decision

`Attempt.bound_coordinates.outcome_room.host_domain_ref` accepts the same
`system:// | domain://` alternatives as `OutcomeRoom.host_domain_ref` and
retains the room value byte-for-byte.

The runtime derives this coordinate from the admitted room projection. It does
not accept a caller-supplied coordinate, rewrite schemes, infer a deployment
domain from configuration, or mint an alias. The existing room-head control
hash remains the coordinate's freshness boundary.

This is a contract correction, not a new lifecycle or authority path. It does
not change the room System's admission ownership, GoalRun application state,
or the kernel truth owned by Session, launch, thread, HarnessInvocation, and
their child records.

## Consequences

- M04.7 System-hosted rooms can admit schema-valid room-scoped Attempts.
- A future profile that resolves an actual `domain://` host remains valid.
- Fixtures must prove the `system://` form, and runtime tests must prove that
  the exact room value is frozen rather than synthesized.
- Cross-domain discovery and federation remain on the M11 lane; this decision
  creates neither.

## Reversal

A later owner may narrow the Attempt coordinate back to `domain://` only after
shipping an admitted, replayable System-to-domain ownership binding and making
M04.7 consume it. Existing Attempts would then require an explicit migration;
silent scheme rewriting is not an allowed reversal.
