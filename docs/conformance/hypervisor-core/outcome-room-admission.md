# OutcomeRoom hosted-admission conformance

Status: `active_invariant` for the selected hosted M4 profile only. Registered
schemas and fixtures, owner-plane Rust tests, a count-pinned 98-assertion
fresh-process aggregate, and the fail-closed 140-assertion OutcomeRoom wrapper
make the hosted room/System, admission, projection, refusal, and recovery cases
below executable gates. The current M5 lifecycle profile remains target
behavior. This document admits no M4 stage, product, independent-party,
federation, settlement, P0, or release claim; retained proof and status remain
owned by the implementation program.

Canonical inputs:
[`collaborative-pursuit.md`](../../architecture/foundations/objects/collaborative-pursuit.md),
[`collaborative-outcome-pattern.md`](../../architecture/domains/ioi-ai/collaborative-outcome-pattern.md),
[`api-object-model.md`](../../architecture/components/agentgres/api-object-model.md),
and [`api.md`](../../architecture/components/daemon-runtime/api.md).

Last audited: 2026-07-30.

## Scope

This suite owns two explicitly separated profiles. The selected M4 profile owns
hosted OutcomeRoom package/genesis/System binding, reciprocal room/GoalRun
membership, `RoomAdmittedObjectBase` for the minimum room `WorkResult` and
`OutcomeDelta` children, derived graph and discussion projections, crash/replay,
and export non-leakage. The M5 profile owns live participation-request,
participant-lease, offer, frontier, claim, attempt, finding, and challenge
admission plus the challenge interlock. Provisional v2 schemas are registered
for frontier, claim, Attempt, Finding, VerifierChallenge, and the distinct
`ParticipantStateBundle` exit shape. Current participation-request,
participant-lease, and resource/capability-offer contracts are not registered.
Every M5 lifecycle remains honest-empty in M4; schema admission does not make a
lifecycle profile runnable. Federated admission, external participant
portability, settlement, and public acceptance remain separate targets.

Every positive case validates the registered v2 room-depth contract for the
object being admitted and, for a mutable room child, the registered
`RoomAdmittedObjectBase` v2 contract. Predecessor v1 schemas and fixtures are
historical source-disposition artifacts only: M4 admits no public compatibility
route, the canonical family returns typed `410` retirement refusals, and v1
records cannot establish the M4 room-admission proof. Passing JSON shape alone is insufficient:
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

Every admitted child binds the exact room revision and predecessor commitment.
In the M4 profile this is executable for daemon-derived `WorkResult` and
owner-proposed `OutcomeDelta`: wrong room/System, caller-owned field or verdict,
stale head, missing payload root, missing decision, missing receipt,
non-monotonic sequence, or mismatched resulting roots refuses before shared
truth changes. Room creation additionally refuses changed bytes at its
deterministic request identity. Unknown-issuer and expired-participant-lease
cases, plus the equivalent live admission matrix for participant, frontier,
claim, attempt, finding, and challenge, belong to the M5 profile and cannot be
credited to M4.

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

### ORA-6 — Result lineage cannot drift; attempt/finding depth follows in M5

The M4 profile requires submitted WorkResult and OutcomeDelta backlinks to
resolve to the same room and GoalRun; cross-room, missing, substituted, or stale
lineage refuses without rewriting history. A room WorkResult's canonical
`artifact://...` result ref must resolve through one admitted
`StorageBackendWriteAdmission` to immutable payload bytes whose hash and size
match the successful invocation execution receipt after the candidate workspace
is removed and the daemon restarts. A successful software invocation remains
`waiting_on_conductor` while that receipt, output facts, and deterministic
verification are only candidate truth. It becomes `completed` only in the same
convergence path that binds its canonical `work_result_ref`,
`profile_result_ref`, and `ImplementationResultPayloadEnvelope`; a premature
completed status or an invocation/result backlink on only one side fails this
case. The M4 cut does not produce or claim the provisional
full `ArtifactRef` envelope. Missing bytes, a substituted ref or admission, a
hash/size mismatch, or duplicate custody truth makes the result unavailable and
cannot advance the room.

Every room result label ref resolves to one durable registered
`InformationFlowLabel` with the exact deterministic parent closure. An
OutcomeDelta inherits the complete label set of its admitted WorkResult
proposer and may add labels, but cannot omit, replace, or weaken any inherited
label. Unknown labels, incomplete closure, or label substitution refuses before
owner or room mutation. The M5 profile additionally requires
Attempt creation to resolve the admitted GoalRun, frontier, active claim, and
participant coordinates, and Finding admission to bind the exact Attempt,
WorkResult, historical participant, and same-room predecessor.

### ORA-7 — Challenges interlock acceptance (M5 profile)

An admitted unresolved VerifierChallenge over a result, finding, verifier,
evidence, eligibility, or decision keeps affected acceptance/verdict projections
blocked or disputed according to the room policy. A UI status, score, or receipt
presence cannot synthesize resolution. M4 proves that challenge collections and
challenge-derived product states remain absent rather than invented; live
challenge admission and interlock are an M5 executable obligation.

### ORA-8 — Crash, replay, and export remain honest

Crash between intent and finalization converges the same retained admission
intent and operation to exactly one admitted child and its existing receipt, or
to an explicit unresolved obligation; it never duplicates the child or advances
only one reciprocal edge. An operation with a canonical idempotency identity
returns its prior result for an exact replay and refuses changed bytes. A
post-terminal WorkResult or OutcomeDelta request has no canonical idempotency
field in the current durable contract, so it may refuse typed but must not
mutate. Export and replay omit disallowed private context and reproduce the same
graph and discussion source commitments.

## Runnable ownership

- Schema/fixture admission: `npm run check:architecture-contract-bar`.
- Hosted graph positive, denial, stale-head, cross-room, result/delta lineage,
  crash/replay, honest-empty M5 families, and export non-leakage:
  `node apps/hypervisor/scripts/verify-hypervisor-outcome-room-plane.mjs`.
- Fresh bounded-System package/genesis/System compilation, constitutional and
  Agentgres admission, reciprocal membership, result lineage, recovery, replay,
  and selected ported-shell projection:
  `node apps/hypervisor/scripts/verify-m4-outcome-room-system-spine.mjs`.
- Ported client partial-plane and no-invented-row behavior:
  `node apps/hypervisor/scripts/verify-hypervisor-surface-modules.mjs`.
- The selected profile remains an `active_invariant` only while the wrapper and
  each count-pinned constituent are green with no skipped, blocked, or dark
  assertions. A red gate blocks new evidence. Even a green gate is not a
  retained M4 literal and cannot transition the work item or stage by itself.

## Nonclaims and stop rules

- Stop on any proposed direct graph/message projection write, client-owned room
  truth, unilateral backlink repair, or status-derived acceptance.
- Stop if a schema is registered without positive and negative fixtures or if a
  runtime path accepts an object without validating both its family contract
  and `RoomAdmittedObjectBase`.
- Stop if hosted proof is presented as federation, portable exit, external
  participant, settlement, independent verification, product, or release proof.
- Stop if registered M5 lifecycle schemas or honest-empty projections are cited
  as runtime participant/frontier/claim/attempt/finding/challenge admission or
  challenge-interlock proof.
- A process exit code is not retained evidence; M4 literal-exit contracts remain
  the only implementation-program closure carriers.
