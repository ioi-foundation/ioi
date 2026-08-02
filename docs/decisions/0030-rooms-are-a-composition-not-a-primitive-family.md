# ADR 0030: Rooms Are A Composition, Not A Primitive Family

- Status: Accepted
- Date: 2026-07-31
- Owners: collaborative pursuit objects / Agentgres truth / daemon runtime /
  ioi.ai orchestration application / Hypervisor core surfaces
- Refines: ADR 0003, ADR 0015, ADR 0020, ADR 0022
- Confidence: settled by owner ruling

## Context

ADR 0022 allocated the goal/room family to the ioi.ai orchestration
application. It did not decide whether an OutcomeRoom should own a second
admission mechanism beside the bounded-System and Agentgres mechanisms from
which the application is composed.

Canon consistently describes composition. Requirement 20 of
`web4-and-ioi-stack.md` says that the reusable OutcomeRoom package instantiates
each persistent room through genesis as a bounded DAS over one or more
GoalRuns. Requirement 22 requires room machinery to appear only where the
actual work boundary needs it. `collaborative-outcome-pattern.md` likewise says
that an OutcomeRoom composes existing owner objects and does not create a peer
runtime.

The admitted implementation diverged. `RoomAdmittedObjectBase` v2 made every
mutable room child carry a room-owned policy, decision, receipt, sequence,
revision, transition commitment, state root, and receipt root. The daemon then
minted a room transition, receipt, and roots and admitted those as distinct
Agentgres records. That is a second semantic admission and receipt spine, even
though Agentgres remains the storage substrate beneath it.

The accompanying room compare-and-swap does not justify that spine. Agentgres
already admits operations against expected object heads or expected absence,
and a bounded-System transition already binds its expected predecessor
commitment. The implementation itself expresses room succession as an
Agentgres expected-absent reservation keyed by the room and predecessor. The
requirement is legitimate; the room-specific primitive is not.

## Decision

**An OutcomeRoom is an ioi.ai application-domain composition instantiated as a
bounded System. It is not a second admission plane.**

```text
COMPOSE FROM (existing owners remain unchanged)
  System genesis + constitution          governance boundary and stable system_id
  bounded-System transition chain        sequence and predecessor continuity
  Agentgres operation-backed admission   expected heads, policy, decision,
                                          accepted operation, receipts and roots
  GoalRun                                 bounded pursuit over the frontier
  thread/session/runtime primitives       events, forks, managed sessions,
                                          harness binding, attach and launch
  WorkResult / OutcomeDelta               generic result seam

KEEP AS APPLICATION VOCABULARY
  OutcomeRoom, CollaborativeWorkGraph, WorkFrontierItem, WorkClaimLease,
  Attempt, Finding, VerifierChallenge and ParticipantStateBundle

KEEP AS A NON-AUTHORITATIVE TYPED BINDING
  SystemScopedObjectBinding: system_id, parent_scope_ref,
  proposed_or_issued_by_ref, payload_root and object-owned timestamps. This
  substrate-generic binding scopes a payload; it owns no admission verdict,
  sequence, head, transition, receipt or root. The ioi.ai application maps an
  OutcomeRoom to parent_scope_ref rather than exporting room vocabulary into
  foundations.

REMOVE
  RoomAdmittedObjectBase and every room-owned admission_policy_ref,
  admission_decision_ref, admission_receipt_ref, admitted_sequence,
  resulting_room_revision, resulting_transition_commitment_ref,
  resulting_room_state_root and resulting_receipt_root.
```

Compare-and-swap is an admission precondition, not a room primitive. A mutation
binds the expected Agentgres object head or heads. When the enclosing System
requires a single ordered transition, the operation also binds that System
chain's expected predecessor commitment. A product API may expose a derived
`expected_room_revision` token, but the daemon must resolve it to the exact
canonical head and it must not be stored as room-owned admitted truth.

### Consequential sub-rulings

1. **One canonical admission.** Application policy may determine whether a
   room mutation is admissible, but the consequential result becomes truth
   exactly once: as an enclosing-System Agentgres operation.
2. **One canonical chain per room System.** Room lineage projects the
   bounded-System sequence, transition commitment, state root, and receipt
   root backed by Agentgres. It never mints parallel room roots.
3. **Evidence references remain legitimate.** Typed objects may reference
   canonical Agentgres decisions, operations, and receipts. They may not mint
   or own parallel admission metadata. This refines ownership, not the use of
   evidence refs.
4. **Rooms are optional by construction.** Direct local work and a single
   GoalRun do not acquire room machinery merely because the room package
   exists.
5. **Composition does not erase room identity.** Genesis still creates one
   durable OutcomeRoom bounded-System instance with its own application-domain
   aggregate and stable `system_id`.
6. **Workflow Compositor remains complementary.** It may supply immutable
   WorkflowTemplates used by room work, but it does not own the live
   CollaborativeWorkGraph. Package compilation, genesis, the ioi.ai
   application, the daemon, and Agentgres retain their existing distinct
   responsibilities.

## Non-Goals

- No change to ADR 0022's layer allocation; rooms remain ioi.ai domain objects.
- No change to AIIP packet families.
- No removal of the reusable OutcomeRoom package or persistent room identity.
- No weakening of participant leases, authority checks, information-flow
  controls, challenge interlocks, or retained positive and negative evidence.
- No claim that one Agentgres root is global across independently governed
  Systems or domains.

This continues ADR 0022 consequential sub-ruling 6: substrate-generic
guarantees stay substrate-owned. In particular, INV-37, `ReceiptObligation`,
idempotent receipted crossings, and ADR 0020's resolved-admission-evidence
discipline apply to room operations without being re-declared by the room
family.

## Consequences

- M4 must prove package-to-genesis composition and ordinary System/Agentgres
  admission with room-scoped preconditions. Its prior room-admission-spine exit
  contract cannot close the restated stage.
- M5 remains on hold until the M4 successor contract is admitted.
- The room contract registry retains the domain vocabulary as typed shapes and
  replaces `RoomAdmittedObjectBase` with a non-authoritative scoping binding.
- `outcome-room-admission.md` targets Agentgres expected-head and bounded-System
  predecessor checks rather than room-generated admission receipts and roots.
- The current room transition, head-reservation, receipt, admitted-object, and
  root implementation is migration input, not conforming evidence for this
  ruling.

## Cost Of Being Wrong And Reversal

The most plausible contrary case is a cross-System federated room for which no
single System owns ordering. That case remains outside the selected hosted
profile until M12/M13. If it later requires another protocol, the reversal is
an explicit federated admission design with its own trust and ownership
argument. It is not permission to preserve a second hosted-room spine now.

## Canonical References

- `docs/architecture/foundations/objects/collaborative-pursuit.md`
- `docs/architecture/foundations/web4-and-ioi-stack.md`
- `docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md`
- `docs/architecture/components/agentgres/api-object-model.md`
- `docs/architecture/components/agentgres/doctrine.md`
- `docs/conformance/hypervisor-core/outcome-room-admission.md`
