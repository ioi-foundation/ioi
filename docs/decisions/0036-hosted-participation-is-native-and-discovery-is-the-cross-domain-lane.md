# ADR 0036: Hosted Participation Is Native; Discovery Is The Cross-Domain Lane

- Status: Accepted — contract layer only. No runtime code lands under this ADR.
- Date: 2026-08-26
- Owners: collaborative pursuit objects / ioi.ai orchestration application /
  daemon runtime receipt registry / architecture contract registry
- Refines: ADR 0030 (rooms are a composition), ADR 0022 (goal orchestration is
  an application layer), ADR 0020 (unified admission and resolved evidence)
- Confidence: settled by owner ruling. Agent-implemented under program
  authority and owner-reversible.

## Context

`M04.7` made each durable OutcomeRoom compile through genesis into a bounded
System with a declared admission mode and a typed `SystemScopedObjectBinding`.
`M04.8` is the unit that makes room work *claimable by someone who is not you*.

Canon already owns the object shapes. What it did not decide is what a
participation request means when the requester is **already inside the room's
own bounded System**.

The canonical `RoomParticipationRequestEnvelope` names `room_discovery_ref` as
a required `room-discovery://` coordinate, because the section that owns it
describes cross-domain and Network/Open participation: an independently
operated Worker discovers a public objective through a policy-bound projection
and submits a typed request through AIIP. That is the right shape for the lane
it was written for.

It is the wrong shape for the hosted same-system lane. An invited participant,
or one native to the L0 host, has no cross-domain gap for a discovery
projection to close. Requiring one would force the room to publish a public
advertisement in order to accept a private invitation — inverting the privacy
posture the discovery object exists to protect — or would force every hosted
implementation to mint a synthetic discovery record that advertises nothing.
Either outcome makes the contract lie about what happened.

`OutcomeRoomDiscovery` publication and `ParticipantStateBundle` export are
externally owned producers on the `M11` interop horizon. `M04.8` must not
depend on them, and must not grow a discovery contract to fake them.

## Decision

**Hosted same-system participation is a first-class native lane. Discovery is
the cross-domain lane, required exactly where a cross-domain gap exists.**

### D1 — Ten named hosted lifecycles: six already registered, four newly registered

`M04.8` produces exactly ten named lifecycles. **Six** already carry registered
contracts and are not touched here; **four** are registered by this ADR.

A fifth contract, `CollaborationTermsEnvelope`, is registered alongside them as
a necessary **auxiliary** pulled forward by D3 — participant and claim
contracts must bind exact accepted terms, so the terms object cannot stay
unregistered. It is not an eleventh lifecycle, and registering it does not
widen `M04.8`'s lifecycle count.

```text
NAMED LIFECYCLES — ALREADY REGISTERED (6, unchanged)
  LocalAgentPairingSession   foundations/objects/local-agent-pairing-session-envelope/v1
  WorkFrontierItem           applications/ioi-ai/work-frontier-item/v3
  WorkClaimLease             applications/ioi-ai/work-claim-lease/v3
  Attempt                    applications/ioi-ai/attempt/v3
  Finding                    applications/ioi-ai/finding/v3
  VerifierChallenge          applications/ioi-ai/verifier-challenge/v3

NAMED LIFECYCLES — REGISTERED BY THIS ADR (4)
  RoomParticipationRequest   applications/ioi-ai/room-participation-request/v3
  RoomParticipantLease       applications/ioi-ai/room-participant-lease/v3
  ResourceOffer              applications/ioi-ai/resource-offer/v3
  CapabilityOffer            applications/ioi-ai/capability-offer/v3

AUXILIARY CONTRACT — REGISTERED BY THIS ADR (1, not a lifecycle)
  CollaborationTermsEnvelope foundations/objects/collaboration-terms-envelope/v1
```

Five contract registrations therefore land in total: the four named lifecycles
above plus the one auxiliary. Pairing continues to use the existing foundations
`LocalAgentPairingSessionEnvelope` v1 contract. No pairing contract is added,
forked, or mutated.

### D2 — The null-discovery rule, and where it is enforced

`RoomParticipationRequest.room_discovery_ref` may be null **only** when both
hold:

- `coordination_topology` is `hosted_admission`, and
- `admission_owner_ref` equals the exact `system_binding.system_id`.

Every other request must carry a non-null `room-discovery://` ref. This is
enforced by two rules in
`invariant://ioi/applications/ioi-ai/room-participation-request/hosted-native-admission/v3`,
not by prose:

| Rule | Operator | Force |
|---|---|---|
| `…discovery.required_outside_hosted_admission` | `non_empty_when_in` | a `federated_admission` request can never omit discovery |
| `…hosted_native.requires_same_system_admission_owner` | `any_of(non_empty ∨ fields_equal)` | whenever discovery is null, the admission owner **is** the room system |

Together the two are exactly the ruled constraint. Neither alone is: the first
permits a hosted request to name a foreign admission owner, and the second
permits a federated request whose owner happens to equal the system id. Each
is proved by a negative fixture that differs from a passing fixture in exactly
one field, so neither rule can pass for the wrong reason.

### D3 — CollaborationTerms is registered minimally, as identity plus an exact root

Participant and claim contracts must bind *exact accepted terms*, so the terms
object cannot stay unregistered. The registered `ioi.collaboration-terms.v1`
shape carries terms identity, version, predecessor, the immutable
`terms_body_root` under the `ioi.collaboration-terms-body.v1` projection, one
bounded scope, the proposer, and lifecycle status.

The bargain's *contents* stay outside the registered shape and remain hashed
into `terms_body_root`. This is not an omission: the canonical owner already
states that the legal-principal binding is a dormant target and that **no field
from it exists in the registered `ioi.collaboration-terms.v1` shape**. This ADR
holds that line. The registered contract adds no legal-person assertion, no
party-role or activation machinery, no economics, no settlement, no payout, and
no external federation.

### D4 — `WorkEligibilityMatchReceipt` is evidence admission and nothing else

`WorkEligibilityMatchReceipt` joins the exhaustive receipt-type registry. It
freezes the exact input coordinates a later claim must revalidate. It creates
no allocation, no claim, and no execution authority; `allocation_created`,
`claim_created`, and `execution_authority_granted` are structurally `false`.
Claim admission recomputes prerequisite coverage and rechecks resource-offer
expiry against freshly committed wallet.network `resolved_at_ms` immediately
before linearization, so a stale match receipt can never stand in for a live
claim check.

### D5 — TTL and heartbeat compose; they do not get an object

Lease freshness is evaluated against wallet.network `resolved_at_ms` and
`receipt://` lease receipts. **No heartbeat schema and no heartbeat contract is
added.** The default participant lease is time-bounded; a null `expires_at` or
`ttl_seconds` is admissible only when
`unbounded_term_exception_decision_ref` proves the governed exception, which
two invariant rules enforce independently.

### D6 — Contribution lineage composes; it does not get an object

Contribution is expressed through the existing `Attempt`, `Finding`,
`WorkResult`, and `OutcomeDelta` refs. **No `Contribution` object is
invented.** ADR 0030's structural law applies: a room composes existing owners
and does not mint a second spine beside them.

### D7 — Offers are issued through a lease, never self-minted

A participant acts in a room only through a current `participant-lease://` ref.
`system://` is a valid issuer only for a room-system-authored scheduling,
expiry, or policy transition. Both offer contracts enforce this on their
`system_binding.proposed_or_issued_by_ref`, and `RoomParticipantLease` enforces
the stronger form: a lease is issued by the room System, so a participant
cannot mint its own membership.

## Non-Claims

This ADR does **not**:

- create an `OutcomeRoomDiscovery` contract, or move discovery/`ParticipantStateBundle`
  producers off the `M11` horizon;
- assert any legal-person binding, settlement, payout, reward basis, or
  consideration;
- define acceptance, verdict, or adjudication logic;
- define AIIP channels, marketplace listing, or external federation behavior;
- take ownership of GoalRun, Session, launch, thread, or `HarnessInvocation`
  semantics;
- land runtime code. Nothing here is wired into a daemon handler, and
  `canon-to-code-delta.md` is deliberately untouched because no runtime state
  changed.

Registration is not implementation. A registered contract with green fixtures
proves the shape and its invariants are exact and portable; it proves nothing
about a running system.

## Consequences

- Hosted rooms can admit native and invited participants without publishing a
  public advertisement, and without a synthetic discovery record.
- The privacy posture of `OutcomeRoomDiscovery` is preserved: it stays the
  cross-domain instrument it was written to be.
- `M11` inherits a clean seam. A federated request is structurally forced to
  carry discovery, so the cross-domain lane cannot silently degrade into the
  hosted one when interop lands.
- Five new contracts join the generated Rust and TypeScript projections, so
  drift between registry and projection is CI-detectable.
- The contract layer now runs ahead of the runtime for this family. That gap is
  intentional and is recorded here rather than hidden.

## Cost Of Being Wrong And Reversal

The blast radius is a contract-layer registration with no runtime consumer, so
reversal is cheap while that remains true.

If the hosted lane proves wrong — for example, if an owner later rules that
every participation request must be discoverable for audit — the reversal is:
delete the two discovery rules from the invariant profile, make
`room_discovery_ref` non-nullable in the v3 schema, and drop the hosted-native
fixtures. No data migration is implied today because no runtime writes these
objects yet.

The reversal cost rises the moment a daemon handler persists a
`RoomParticipationRequest` with a null `room_discovery_ref`. **Before that
handler lands, this decision should be re-confirmed**, because after it lands
the null-discovery records exist and backfilling a discovery projection for
them would mean publishing advertisements retroactively — which the decision
exists to avoid.

Reversing D3 is more expensive in a different direction: widening the
registered terms shape toward settlement or legal-person fields would cross the
dormant legal-principal target that
[`../architecture/foundations/objects/interop-and-collaboration-terms.md`](../architecture/foundations/objects/interop-and-collaboration-terms.md#collaborationtermsenvelope)
holds closed, and requires an accountable owner ruling, not a program decision.
This ADR deliberately does not enroll itself as an owner of that target.

## Affected Surfaces

| Surface | Change |
|---|---|
| `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json` | five new contract entries |
| `…/schemas/{collaboration-terms-envelope.v1,room-participation-request.v3,room-participant-lease.v3,resource-offer.v3,capability-offer.v3}.schema.json` | new closed schemas |
| `…/schemas/invariants/*` | five new invariant profiles, eleven rules |
| `…/schemas/fixtures/*` | 28 new fixtures (10 positive, 18 negative); golden corpus bar 703 → 731 |
| `crates/types/src/app/generated/architecture_contracts.rs` | regenerated projection |
| `packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts` | regenerated projection |
| `docs/architecture/domains/ioi-ai/collaborative-pursuit.md` | hosted-lane section; offer shapes moved under their own heading |
| `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md` | `WorkEligibilityMatchReceipt` registered and bounded |
| daemon runtime, apps, scripts | **unchanged** |

## Canonical References

- [`../architecture/domains/ioi-ai/collaborative-pursuit.md`](../architecture/domains/ioi-ai/collaborative-pursuit.md)
- [`../architecture/domains/ioi-ai/collaborative-outcome-pattern.md`](../architecture/domains/ioi-ai/collaborative-outcome-pattern.md)
- [`../architecture/foundations/objects/interop-and-collaboration-terms.md`](../architecture/foundations/objects/interop-and-collaboration-terms.md)
- [`../architecture/foundations/objects/bounded-system-genesis.md`](../architecture/foundations/objects/bounded-system-genesis.md)
- [`../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`](../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`./0030-rooms-are-a-composition-not-a-primitive-family.md`](./0030-rooms-are-a-composition-not-a-primitive-family.md)
- [`./0022-goal-orchestration-application-layer-and-clean-slate.md`](./0022-goal-orchestration-application-layer-and-clean-slate.md)
- [`./0020-unified-goal-run-admission-and-resolved-evidence.md`](./0020-unified-goal-run-admission-and-resolved-evidence.md)
