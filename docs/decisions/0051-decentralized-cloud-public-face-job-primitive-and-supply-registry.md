# ADR 0051: decentralized.cloud Is A Branded Public Front, A Job Primitive, And A Supply Registry — Never A Second Spine

Status: Accepted

Date: 2026-09-04

## Context

`decentralized.cloud` canon
([`cloud.md`](../architecture/domains/decentralized/cloud.md)) defines a
resource-intelligence engine that proposes infrastructure-capacity candidates
and explicitly does not own provider accounts, authority, execution, restore
truth, or settlement. The engine is built: intent/candidate/refresh/source/
advisory routes, seven provider quote sources, an explicit placement decision
with alternatives and reason codes, and wallet-gated cross-provider failover.
Its only consumer is the Hypervisor daemon. Nothing is served at the
`decentralized.cloud` origin; there is no public API, SDK, explorer, or
third-party front door; `fee_object_minted` is `false` everywhere and no
`RoutingDecisionReceipt` exists.

The owner has ruled that this product face is underused and that the estate
should pursue it as a standalone product: one unified API through which a
human or an agent obtains compute, storage, network, or runtime capacity across
local machines, customer infrastructure, hyperscalers, GPU marketplaces, and
DePIN networks without learning the venue names — with the receipt as the
product, not the price comparison. The owner further ruled that the estate may
later operate its own supply (IOI managed capacity and independently contributed
capacity) behind the same face.

Two structural risks follow. The first is that a standalone brand acquires its
own authority path, provider integrations, or receipt format and becomes a
second spine — the class of defect
[ADR 0031](./0031-goalrun-execution-composes-thread-orchestration.md) and
[ADR 0034](./0034-thread-fork-is-the-delegation-primitive-subagents-are-its-surface.md)
close for orchestration: a product composes owned primitives and never keeps a
parallel spine of its own. The second is that
first-party supply is preferred by the router, which destroys the aggregator's
neutrality and violates
[`marketplace-neutrality.md`](../architecture/domains/marketplace-neutrality.md).

## Decision

### 1. Brand is not owner

`decentralized.cloud` may be served as a standalone public product face:
a candidate API/SDK/explorer at the `decentralized.cloud` origin, and a branded
job API. Every ownership boundary in `cloud.md` § *Does Not Own* is unchanged.
The job API **is** Hypervisor's optimized-placement lane exposed under the
brand: candidates come from the engine, authorization from wallet.network,
execution from Hypervisor, truth from Agentgres, settlement per the declared
profile. The face has no private authority store, no private provider
integrations, no private receipt format, and no private placement scorer.

### 2. One job primitive, human or agent

The public unit of work is `CloudJobRequest`: a composition envelope over
`CloudResourceIntent` that binds a budget reference, a deadline or duration,
receipt requirements, and the caller kind (`human | agent`). It is not a
second intent type and it is not authority. A human caller authorizes through
a wallet grant; an agent caller draws down a scoped `CapabilityLease`. Both
cross the same gate ladder (budget discovery → quote freshness → wallet lease →
execute → spend reconciliation → failover) and receive identical receipts.
The caller never holds provider credentials.

### 3. Local capacity is a venue

The local machine, LAN hosts, customer clusters, and HypervisorOS nodes are
candidate sources (`local_capacity`) alongside cloud and DePIN sources.
Contention on local capacity is a placement input, not an exception path.
`Run local` and `Use my infrastructure` remain user choices and are never
routed away from silently.

### 4. First-party supply is a neutral candidate

The estate may operate two supply forms behind the face: **managed capacity**
(IOI or a partner as provider-of-record, priced as managed infrastructure) and
**contributed supply** (independent operators registering capacity through
`CloudSupplyRegistration`). Both enter placement as ordinary candidates,
scored by the same evidence as every other venue. Every `PlacementDecision`
that includes first-party supply must record whether it won or lost and why,
against the named alternatives. Registry metadata belongs to
`decentralized.cloud`; provider accounts, credentials, and custody belong to
the Hypervisor provider plane; contributor settlement follows the declared
settlement profile.

### 5. The fee is a minted receipt or nothing

A routing/procurement fee exists only as a minted `RoutingDecisionReceipt`,
and one may be minted only when at least two **real** (non-simulator,
evidence-bearing, unexpired) candidates were compared and the decision names
the challengeable routing value created. Simulator candidates never satisfy the
comparison. Direct connected infrastructure never carries a routing fee.

### 6. L1 stays sparse

Ordinary jobs settle locally. Only commitments that require multi-party
non-repudiation between parties with no shared trust root — supply
registration roots, reliability stake, provider disputes, cross-party spend
reconciliation, reputation roots — reach IOI L1, and only when the declared
enrollment and settlement profiles select it. Per-job L1 transactions are
forbidden (marketplace-neutrality invariant 14).

### 7. Serving posture (owner-reversible)

The public face is served by the Hypervisor daemon under the existing
auth-gated rollout posture at the `decentralized.cloud` origin, with no second
principal store, session plane, or credential vault. Public candidate reads are
evidence-bearing and rate-bounded; every mutating call is wallet-gated exactly
as the daemon's own routes are. The owner may relocate the serving surface, but
not the ownership boundaries above.

### 8. Redundancy is a declared posture, never a silent multiplier

The face routes every resource class canon names — compute, storage, network,
runtime, security — not GPU marketplaces alone, and it may **enact
redundancy** when the caller declares it. `CloudJobRequest` carries a
`RedundancyPosture` of `none | warm_standby | active_active` with a required
provider-class diversity and an explicit budget multiplier the caller
authorizes. Reactive failover (the existing `FailoverPlan`) remains available
under every posture. Proactive redundancy opens one spend exposure per
replica, is receipted per replica, and is never applied by default, by
policy inference, or by a fallback the caller did not authorize.

Stateless workloads (hosting, previews, inference endpoints, workbenches) may
be replicated across venues once `network.dns` and `network.tls` adapters
exist. Stateful workloads are not made active-active by routing: storage
availability is not restore validity, so state redundancy is a custody
question that stays behind the "later" gate with the database, queue, and
cache classes.

## Consequences

- Canon gains a *Public Product Face* and a *Supply Registry* section in
  `cloud.md`, the `CloudJobRequest` and `CloudSupplyRegistration` objects, the
  `local_capacity` and `contributed_supply` candidate sources, and the
  `network.dns` / `network.tls` resource classes pulled forward because hosting
  is in scope, and a *Redundancy* section with the `RedundancyPosture` field.
  Anti-patterns for own-pool preference, caller-held credentials, and silent
  redundancy are added.
- `marketplace-neutrality.md` extends first-party seed-supply neutrality to
  compute supply. `economic-flywheel-and-pricing-boundaries.md` binds the
  optimized-placement fee to the minted receipt and adds contributed-supply
  economics.
- The implementation guide gains a product-composition module (M15) and an
  acceptance journey (ACC-21) that compose over M09, M07, M03, and M06 owners.
  Live settled spend is not a new unit; it remains `M09.6`.
- Nothing in this ADR is built. Every object it names is `planned` until its
  delta row records closure on tracked evidence. Corporate structure,
  capitalization, and brand licensing are business decisions outside canon;
  this ADR fixes only what the architecture permits and forbids.

## Nonclaims

- No claim that any venue's live spend path other than the single bounded Akash
  proof is exercised.
- No claim that a public origin, SDK, explorer, or third-party caller exists.
- No claim that a `RoutingDecisionReceipt` has been minted or that any fee is
  charged.
- No claim about AKT, Akash, or any third-party network's economics.
