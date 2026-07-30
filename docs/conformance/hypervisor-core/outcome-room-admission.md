# OutcomeRoom hosted-admission conformance

Status: target runnable conformance contract. Registered schemas and fixtures,
the hosted owner-plane Rust tests, and the isolated OutcomeRoom verifier are
runnable; no M4 stage, product, independent-party, federation, or release claim
is admitted by this document.

Canonical inputs:
[`collaborative-pursuit.md`](../../architecture/foundations/objects/collaborative-pursuit.md),
[`collaborative-outcome-pattern.md`](../../architecture/domains/ioi-ai/collaborative-outcome-pattern.md),
[`api-object-model.md`](../../architecture/components/agentgres/api-object-model.md),
and [`api.md`](../../architecture/components/daemon-runtime/api.md).

Last audited: 2026-07-30.

## Scope

This suite owns hosted OutcomeRoom package/genesis/System binding, reciprocal
room/GoalRun membership, `RoomAdmittedObjectBase`, derived graph and discussion
projections, and the participant/frontier/claim/attempt/finding/challenge
admission refusals required by M4. Federated admission, external participant
portability, settlement, and public acceptance remain separate targets.

Every positive case validates the registered contract for the object being
admitted and, for a mutable room child, the registered
`RoomAdmittedObjectBase` contract. Passing JSON shape alone is insufficient:
the runtime case must prove exact heads, owner-plane resolution, admission
receipt, resulting room revision, transition commitment, state root, and
receipt root.

## Required cases

### ORA-1 — Room identity is a bounded System

A room may become `open` or `active` only when its package, release, genesis,
System, constitution, active profiles, host domain, ordering policy, and
Agentgres state refs resolve to the same logical room. Substitute, absent, or
stale coordinates refuse without a room transition.

### ORA-2 — Child admission is compare-and-swap

Participant, frontier, claim, attempt, finding, challenge, result, and delta
writes bind the exact room revision and predecessor commitment. Unknown issuer,
expired participant lease, wrong room/System, changed-body replay, stale head,
missing payload root, missing decision, missing receipt, non-monotonic sequence,
or mismatched resulting roots refuses before shared truth changes.

### ORA-3 — GoalRun membership is reciprocal and atomic

Attach and detach compare the exact room and GoalRun heads and commit the room's
`member_goal_run_refs` and the GoalRun's `outcome_room_ref` under one receipt.
Either missing backlink, a foreign room, duplicate membership, a stale side, or
a partial commit makes the relation unavailable. No list response or client
state repairs it.

### ORA-4 — Graph projection is derived, complete, and non-writable

`CollaborativeWorkGraph` binds one room revision/root, the reciprocal GoalRun
set, every included owner-plane ref, source receipts, and label set. A missing
child backlink, cross-room child, unresolved object, or mismatched source root
refuses the projection or marks the affected plane typed-unavailable. Direct
client graph writes and `authoritative: true` are schema and runtime refusals.

### ORA-5 — Discussion projection is label-bound

`OutcomeRoomDiscussionProjection` binds the same room revision/root, source
receipts, visibility policy, information-flow labels, permitted subjects,
message refs, redaction summaries, and replay cursor. Raw private message bytes,
unpermitted subjects, absent labels, stale source roots, `authoritative: true`,
or `client_writable: true` refuse. The projection grants no membership,
authority, acceptance, or truth.

### ORA-6 — Attempt, result, and finding lineage cannot drift

Attempt creation resolves the admitted GoalRun, frontier, active claim, and
participant coordinates. Submitted WorkResult and OutcomeDelta backlinks must
resolve to the same room and GoalRun. Finding admission binds the exact Attempt,
WorkResult, historical participant, and same-room predecessor. Cross-room,
missing, substituted, or stale lineage refuses without rewriting history.

### ORA-7 — Challenges interlock acceptance

An admitted unresolved VerifierChallenge over a result, finding, verifier,
evidence, eligibility, or decision keeps affected acceptance/verdict projections
blocked or disputed according to the room policy. A UI status, score, or receipt
presence cannot synthesize resolution.

### ORA-8 — Crash, replay, and export remain honest

Crash between intent and finalization converges to exactly one admitted result
or an explicit unresolved obligation; it never duplicates the child or advances
only one reciprocal edge. Same-body replay returns the existing receipt.
Changed-body replay refuses. Export and replay omit disallowed private context
and reproduce the same graph and discussion source commitments.

## Runnable ownership

- Schema/fixture admission: `npm run check:architecture-contract-bar`.
- Hosted graph positive, denial, stale-head, cross-room, crash/replay, and
  challenge interlock: `node apps/hypervisor/scripts/verify-hypervisor-outcome-room-plane.mjs`.
- Ported client partial-plane and no-invented-row behavior:
  `node apps/hypervisor/scripts/verify-hypervisor-surface-modules.mjs`.
- M4 must add a focused aggregate runner that invokes the exact owner-plane
  Rust tests and the two commands above; until that runner and retained literals
  exist, this remains `target_runnable`, not `active_invariant` and not M4 proof.

## Nonclaims and stop rules

- Stop on any proposed direct graph/message projection write, client-owned room
  truth, unilateral backlink repair, or status-derived acceptance.
- Stop if a schema is registered without positive and negative fixtures or if a
  runtime path accepts an object without validating both its family contract
  and `RoomAdmittedObjectBase`.
- Stop if hosted proof is presented as federation, portable exit, external
  participant, settlement, independent verification, product, or release proof.
- A process exit code is not retained evidence; M4 literal-exit contracts remain
  the only implementation-program closure carriers.
