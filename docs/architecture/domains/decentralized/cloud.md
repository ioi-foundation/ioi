# decentralized.cloud — the Hypervisor daemon's native contract

Status: alpha canon; the daemon-side contract for `decentralized.cloud`.
Canonical owner: this file for the objects, routes and typed absences the
Hypervisor daemon implements for `decentralized.cloud` — the native contract the
cloud consumes through its provider-adapter boundary. The PRODUCT is specified in
[`cloud/`](./cloud/README.md) (thesis, resource model, console, control plane,
adapters, placement, compute, storage, network, identity, money, observability,
recovery, API, roadmap) and re-scoped by
[`cloud/adr/0001`](./cloud/adr/0001-decentralized-cloud-is-a-product.md).
Supersedes: the earlier version of this file that defined `decentralized.cloud`
as a read-only public face over the daemon with an owns / does-not-own list; that
framing is retired by ADR 0001 (decentralized.cloud is a product with its own
resource model, control plane and ledger; the daemon is one adapter target).
Superseded by: `cloud/` for everything about the product; this file keeps only
what the daemon does today.
Last alignment pass: 2026-09-08 (ADR 0001: re-scoped to the native contract).
Doctrine status: canonical
Implementation status: mixed (candidate plane + quote sources + guarded lifecycles over the BYO provider plane are built; the job envelope is admitted and dry-run only; `local_capacity`, supply registry, fee object and redundancy postures beyond `none` are absent — see the typed-absence sweep below)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/decentralized_cloud_routes.rs`
  - `apps/hypervisor/scripts/verify-hypervisor-cloud-candidate-plane.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-vast-candidate-adapter.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-vast-lifecycle.mjs`
  - `apps/decentralized-cloud/scripts/verify-decentralized-cloud-face.mjs` (the console's gate against this contract)
Last implementation audit: 2026-09-04 (route sweep; the built candidate-plane claims retain their 2026-07-05 basis)

## How this file relates to the product specification

Under [ADR 0001](./cloud/adr/0001-decentralized-cloud-is-a-product.md) the daemon is
an execution and acquisition substrate behind the adapter contract in
[`cloud/040-provider-abstraction.md`](./cloud/040-provider-abstraction.md), and a
runtime the cloud's own services may be placed on. What follows is what the
adapter may claim about it: the resource classes it validates, the objects it
holds, the routes it answers, and — by name — what it does not do yet. For every
object the spec primitive it maps to is stated, so the two documents cannot drift
into two vocabularies for one thing.

| Native object (this file) | Spec primitive ([`cloud/010`](./cloud/010-resource-model.md)) | Note |
| --- | --- | --- |
| `CloudResourceIntent` | `ResourceClaim` (internal) under an `Application` / `Service` | The intent is a claim; the Application above it is the spec's, not yet the daemon's |
| `CloudJobRequest` | `Job` + `Plan` (admit = plan; dry run = plan execution stopped at placement) | One envelope, human or agent; the caller_kind resolver is the estate's authority backend |
| `CloudResourceCandidate` | `Offer` (observed market cache) | Evidence-bound and expiring; never a reservation |
| `PlacementDecision` | `Plan`'s selected placement → `Allocation` on execution | Advisory and decision are evidence, never authority |
| `PlacementDecisionReceipt` | `ExternalEffect` / evidence reference on the `Operation` | Explicitly not a `RoutingDecisionReceipt`; no fee minted |
| `ResourceLease` | `ProviderLease` (adapter state) | Provider-native; cannot authorize spend |
| `CustodyPlan` | [`cloud/070`](./cloud/070-storage.md) storage class + retention contract | The daemon holds custody posture; the cloud owns the storage contract |
| `FailoverPlan` | Recovery within an approved Execution Envelope ([`cloud/030`](./cloud/030-control-plane.md) §12.2) | Reactive failover exists; proactive redundancy does not |
| `SpendEstimate` | `Quote` + `SpendGrant` ([`cloud/100`](./cloud/100-money.md)) | Daemon-side reconciliation against `external_spend` |
| `RedundancyPosture` | `Placement Policy` diversity + service objectives ([`cloud/050`](./cloud/050-placement-and-supply.md)) | Only `none` is accepted today |
| `CloudSupplyRegistration` | `Provider` + `Offer` in the provider registry ([`cloud/040`](./cloud/040-provider-abstraction.md)) | Absent today |

The spec's Application, Service, Deployment, LogicalReplicaSlot, WorkloadAttempt,
Endpoint, Bucket, Volume, Network, Domain, ledger and settlement objects have no
native counterpart in the daemon; they are the cloud's own, per ADR 0001.

## Native resource classes

Start bounded. The first resource classes are:

```text
compute.vm
compute.microvm
compute.container
compute.gpu_runtime
storage.object
storage.block
storage.archive
storage.cas
network.ip_lease
network.ingress
network.dns
network.tls
runtime.model_server
runtime.browser
runtime.workbench
security.tee
security.ctee
```

`network.dns` and `network.tls` are pulled forward (ADR 0051) because hosting a
site or preview is in the job API's scope; a hosted endpoint without a name and
a certificate is not a delivered job. Later classes such as databases, queues,
caches, observability, and higher PaaS surfaces may be added only after adapter
contracts, authority semantics, receipts, custody posture, and restore/failover
behavior are real.

## Native lifecycle (how the daemon places today)

```text
user, agent, app, automation, or Hypervisor requests infrastructure capacity
  -> Hypervisor creates a placement context from environment/runtime/custody needs
  -> Hypervisor or wallet.network asks resource sources for candidates
  -> decentralized.cloud, direct provider adapters, user-specified providers,
     local capacity (the requesting machine, LAN hosts, customer clusters,
     HypervisorOS nodes), managed Hypervisor capacity, contributed supply,
     DePIN markets, storage backends, or customer-cloud inventories return
     candidates
  -> Hypervisor evaluates policy, runtime class, custody, privacy, region,
     GPU/model availability, restore posture, cost, latency, reliability,
     failover, adapter maturity, and support boundary
  -> wallet.network authorizes exact spend, credential use, grants, and
     revocation posture where required
  -> Hypervisor selects or rejects a PlacementDecision
  -> Hypervisor provisions through the selected provider adapter
  -> provider, storage, network, or runtime performs
  -> Hypervisor emits ProviderOperationReceipt, SpendReceipt, and state-root
     evidence as applicable
  -> Agentgres records admitted truth, receipts, state roots, and restore
     validity
  -> IOI L1 receives settlement/dispute/public commitments only when the
     declared enrollment and settlement profiles select it
```

## Native objects

### CloudResourceIntent

`CloudResourceIntent` describes requested infrastructure capacity before route
selection. It is not authority.

```rust
struct CloudResourceIntent {
    intent_ref: ResourceIntentRef,
    requester_ref: PrincipalOrAgentRef,
    user_placement_choice: UserPlacementChoice, // run_local |
                                                // use_my_infrastructure |
                                                // pick_a_cloud |
                                                // let_hypervisor_choose
    placement_source: PlacementSource, // connected | managed | optimized
    selection_mode: SelectionMode,      // local | user_pinned |
                                        // policy_pinned | auto | failover
    runtime_class: RuntimeClass,
    resource_classes: Vec<ResourceClass>,
    compute: Option<ComputeRequirement>,
    gpu: Option<GpuRequirement>,
    storage: Vec<StorageRequirement>,
    network: Vec<NetworkRequirement>,
    custody_posture: CustodyPosture, // Standard | Private
    privacy_requirements: Vec<PrivacyRequirement>,
    region_preferences: Vec<RegionRef>,
    budget_policy_ref: Option<PolicyRef>,
    failover_policy_ref: Option<PolicyRef>,
    support_boundary: SupportBoundary,
    evidence_refs: Vec<EvidenceRef>
}
```

### CloudJobRequest

`CloudJobRequest` is the public unit of work behind the job API (ADR 0051). It
is a **composition envelope** over exactly one `CloudResourceIntent`, not a
second intent type, and it is not authority. It binds the three things a
caller must state and the one thing it must get back:

```rust
struct CloudJobRequest {
    job_ref: CloudJobRef,
    intent: CloudResourceIntent,
    caller_kind: CallerKind,              // human | agent
    authority_ref: AuthorityRef,          // wallet grant (human) or
                                          // CapabilityLease draw-down (agent);
                                          // never a provider credential
    budget_ref: BudgetRef,                // an existing external_spend budget;
                                          // never an inline amount
    deadline: JobDeadline,                // absolute deadline or max duration
    receipt_requirements: ReceiptRequirements, // placement, provider-operation,
                                          // spend, failover, offline-verifiable
    failover_policy_ref: Option<PolicyRef>,
    redundancy: RedundancyPosture,        // none | warm_standby | active_active
                                          // + diversity + budget multiplier;
                                          // see § Redundancy
    evidence_refs: Vec<EvidenceRef>
}
```

Rules:

```text
a human and an agent submit the same envelope and receive the same receipts
the caller kind changes the authority path, never the placement or the price
budget is discovered before any mutation; a request without a resolvable
  budget is refused by name (budget_undiscovered_before_mutation)
the request is complete only when its receipt chain is complete; a job whose
  provider vanished mid-run is complete only after failover or a receipted
  refusal
the venue name is evidence in the receipt, not an input to the request
redundancy is declared or absent; it is never inferred, defaulted, or applied
  by a fallback the caller did not authorize
```

### CloudResourceCandidate

`CloudResourceCandidate` is a proposed resource route from
`decentralized.cloud`, direct provider adapters, customer inventories, DePIN
markets, storage networks, managed capacity, or user-specified routes.

It is not authority and cannot execute until selected into an approved
`PlacementDecision` or equivalent Hypervisor placement object.

Every candidate must carry candidate evidence. A resource candidate without
source, adapter, observed timestamp, expiry, coverage state, and evidence refs
is not placement-eligible.

```rust
struct CloudResourceCandidate {
    candidate_ref: CloudCandidateRef,
    source: CloudSourceRef,          // decentralized.cloud | direct_provider |
                                     // customer_inventory | local_capacity |
                                     // managed_capacity | contributed_supply |
                                     // depin_market | storage_network |
                                     // user_specified
    adapter_ref: AdapterRef,
    provider_kind: ProviderKind,
    resource_classes: Vec<ResourceClass>,
    runtime_class: RuntimeClass,
    quote_ref: Option<ProviderQuoteRef>,
    spend_estimate_ref: Option<SpendEstimateRef>,
    custody_plan_ref: Option<CustodyPlanRef>,
    failover_plan_ref: Option<FailoverPlanRef>,
    provider_reliability_score_ref: Option<EvidenceRef>,
    region: Option<RegionRef>,
    availability_window: Option<TimeWindow>,
    interruption_risk: Option<RiskLabel>,
    observed_at: Timestamp,
    expires_at: Timestamp,
    risk_labels: Vec<RiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>,
    evidence_refs: Vec<EvidenceRef>
}
```

Required candidate failure behavior:

```text
missing evidence
  -> reject as not placement-eligible

expired candidate or quote
  -> require requote

unknown, stale, conflicting, or unassessed coverage
  -> cannot execute silently; requires caution state, review, simulation,
     policy exception, or denial

provider cannot satisfy required runtime class or custody posture
  -> reject with named reason and evidence
```

### PlacementDecision

`PlacementDecision` is the selected placement object owned by Hypervisor
provider/environment canon. `decentralized.cloud` can propose candidates and
scoring evidence; Hypervisor admits the selected decision and executes the
environment lifecycle.

When any compared candidate carries source `managed_capacity` or
`contributed_supply`, the decision must record whether that first-party
candidate won or lost, against which named alternatives, and by which evidence
(ADR 0051 §4). A decision that omits this is not placement-eligible.

### CloudSupplyRegistration

`CloudSupplyRegistration` is the registry object for capacity offered behind
the face by an operator other than a direct provider adapter: IOI managed
capacity, a partner provider-of-record, or an independent contributor (a
HypervisorOS node, a small data center, an idle GPU host). It is metadata, not
a provider account and not authority.

```rust
struct CloudSupplyRegistration {
    supply_ref: CloudSupplyRef,
    operator_ref: PrincipalRef,           // server-resolved, never caller-claimed
    supply_kind: SupplyKind,              // managed_capacity | contributed_supply
    affiliation: AffiliationDisclosure,   // first_party | partner | independent
    provider_account_ref: ProviderAccountRef, // owned by the Hypervisor
                                          // provider plane, referenced here
    resource_classes: Vec<ResourceClass>,
    declared_capacity: CapacityDeclaration,
    price_schedule_ref: PriceScheduleRef,
    custody_posture: CustodyPosture,
    reliability_evidence_refs: Vec<EvidenceRef>,
    stake_or_bond_ref: Option<BondRef>,   // per declared settlement profile
    settlement_profile_ref: SettlementProfileRef,
    registered_at: Timestamp,
    expires_at: Timestamp,
    evidence_refs: Vec<EvidenceRef>
}
```

A registration becomes candidates only through the same candidate path as
every other source, with the same evidence and expiry rules. Affiliation is
always disclosed in the candidate and the decision. Reputation for a
registration derives from receipts, never from self-report.

### ResourceLease

`ResourceLease` is a provider or resource reservation candidate. It may describe
provider-native leases such as IP leases, storage leases, GPU capacity windows,
DePIN deployments, or customer-cloud allocations, but it cannot authorize spend
or claim canonical resource truth by itself.

### CustodyPlan

`CustodyPlan` describes how workspace bytes, archive bytes, snapshot material,
state-root checks, cTEE/TEE posture, provider trust, and restore evidence should
be handled. Storage availability does not equal restore validity.

### FailoverPlan

`FailoverPlan` names candidate alternatives, health thresholds, re-placement
policy, data movement assumptions, restore material requirements, expected
downtime, and authority refs required before failover.

### SpendEstimate

`SpendEstimate` describes estimated provider cost, Hypervisor cost, routing fee
eligibility, cost owner, billing path, and uncertainty. It is an estimate, not
spend authority. Under a declared redundancy posture it carries one estimate
per replica and the authorized multiplier, never a blended total.

### RedundancyPosture

`RedundancyPosture` is the caller's declaration of how many places a job must
exist at once (ADR 0051 §8). It is a placement input, not authority, and it is
never inferred.

```rust
struct RedundancyPosture {
    mode: RedundancyMode,                 // none | warm_standby | active_active
    replica_count: u8,                    // 1 for none; ≥2 otherwise
    provider_class_diversity: DiversityRequirement, // distinct provider
                                          // classes (e.g. hyperscaler + DePIN),
                                          // regions, or operators
    budget_multiplier_authorized: Multiplier, // explicit; refuses when the
                                          // discovered budget cannot cover
                                          // replica_count × estimate
    state_class: StateClass,              // stateless | stateful
    switch_policy_ref: Option<PolicyRef>, // health thresholds, DNS/ingress
                                          // switch, promotion of a standby
    evidence_refs: Vec<EvidenceRef>
}
```

### PlacementDecisionReceipt

The user-visible "Placement Receipt" is usually a projection over:

```text
PlacementDecision
ProviderOperationReceipt
SpendReceipt
RoutingDecisionReceipt
```

`RoutingDecisionReceipt` is legitimate only when optimized placement creates
visible routing/procurement/failover/reconciliation/billing value. It may be
minted only when at least two real — non-simulator, evidence-bearing,
unexpired — candidates were compared and the decision names the routing value
created (ADR 0051 §5). A routing fee exists as a minted
`RoutingDecisionReceipt` or it does not exist.

## Redundancy

The face routes every resource class above, not GPU marketplaces alone, and it
may **enact redundancy** when — and only when — the caller declares it
(ADR 0051 §8). Two different things hide in the word:

```text
Reactive failover (exists)
  FailoverPlan: a named failure condition on the running venue triggers a
  wallet-gated re-placement on a DIFFERENT provider class, restore only after
  state-root validation, old exposure closed, new exposure opened, whole chain
  receipted. Available under every posture.

Proactive redundancy (declared)
  warm_standby: a second placement is provisioned and kept ready on a distinct
    provider class; promotion follows the switch policy and is receipted
  active_active: N placements serve concurrently behind network.ingress with
    network.dns / network.tls switching; each replica is its own placement,
    exposure, and receipt
```

Rules:

```text
redundancy multiplies spend; the multiplier is authorized explicitly and
  discovered against the budget before any replica is provisioned
one placement decision, one provider-operation receipt, one spend receipt per
  replica; a blended "redundant job" receipt does not exist
provider_class_diversity is a hard requirement: two replicas on one provider
  class satisfy nothing and refuse by name
stateless workloads (hosting, previews, inference endpoints, workbenches)
  may be active_active once network.dns and network.tls adapters are real
stateful workloads are not made active_active by routing: storage
  availability is not restore validity; state redundancy is a CustodyPlan
  question and stays behind the "later" gate with databases, queues, caches
a posture the caller did not declare is never applied by default, by policy
  inference, or by a fallback
```

## Supply Registry

[ADR 0051](../../../decisions/0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md)
§4 permits the estate to operate supply behind the face. Two forms, two
businesses:

```text
Managed capacity
  IOI or a partner is provider-of-record; bears procurement, operation,
  support, and capacity risk; priced as managed infrastructure (Work Credits,
  reserved capacity, margin) — never as routing
  purpose: the "give me a box now" experience that small, bursty jobs need
  and marketplace venues cannot reliably deliver

Contributed supply
  independent operators register capacity through CloudSupplyRegistration:
  HypervisorOS nodes, small data centers, idle GPU hosts
  reliability stake, reputation from receipts, and contributor settlement
  follow the declared settlement profile; this is where IOI L1 earns its
  keep on the supply side, and only there
```

Ordering rule: **demand first, supply against measured gaps.** The router runs
before either pool exists, and its unmet-request evidence (requested class,
region, price ceiling, latency, no eligible candidate) is the only legitimate
basis for deciding what supply to build. Supply built ahead of evidence is a
guess with a bill.

Neutrality rule: first-party supply is an ordinary candidate. It is scored by
the same evidence as every other venue, it never receives a default, tie-break,
or fallback preference, and every decision that includes it records the win or
loss by name ([`marketplace-neutrality.md`](../marketplace-neutrality.md)
anti-cannibalization rule 13, invariant 16). A router believed to prefer its
own pool is a supplier wearing a router's name, and the venues stop wanting to
be routed to.

## Native routes — implemented contract (candidate plane)

Implementation status: built — candidate plane plus quote sources and
guarded lifecycles for Vast, RunPod, Lambda, Akash, AWS, and GCP ride the
BYO provider plane. Daemon routes: `/v1/hypervisor/cloud-candidates/*`
(`crates/node/src/bin/hypervisor_daemon_routes/decentralized_cloud_routes.rs`);
quote adapters live beside the provider routes
(`*_candidate_source.rs`).

- Intent/candidate/refresh/source/placement-advisory endpoints realize
  the candidate semantics above from LOCAL FACTS ONLY; candidates are
  evidence-bound and expiring; external sources without adapters report
  `candidate_source_unavailable` WITH evidence — no fake prices.
- Candidates and advisories are never authority: provider mutation still
  demands wallet grants on the execution lane; `fee_object_minted` stays
  false and no RoutingDecisionReceipt exists.
- SpendEstimate reconciliation is realized daemon-side: exposures open
  from admitted quote-backed creates, reserve headroom against
  `external_spend`, and close (or warn) on teardown; Hypervisor never
  fakes settlement.

`hypervisor_choose` now moves from advisory to an EXPLICIT PLACEMENT
DECISION when eligible candidates exist: `POST
/v1/hypervisor/placement/decisions` compares candidates deterministically
(the advisory's own scoring), minting a durable
`ioi.hypervisor.placement-decision.v1` citing selected + alternatives +
rejected-with-reason-codes, custody/spend/support posture, and a
`placement-decision-receipt` that is explicitly NOT a RoutingDecisionReceipt
(no fee minted, no charge today; `routing_fee_eligibility: eligible_future`
only when ≥2 real candidates were compared). Decisions are evidence, never
authority. CROSS-PROVIDER FAILOVER rides the same spine
(`/v1/hypervisor/failover/{plans,run,runs}`): a named failure condition
(8 supported, fail-closed without a valid restore root) triggers a
resumable, wallet-gated orchestration that selects a replacement on a
DIFFERENT provider class, creates/starts through the existing per-kind
gates (in-process reuse — no second mutation lane), restores ONLY after
state_root validation (daemon custody first, storage-archive 5-gate ladder
as fallback), closes the old provider (spend exposure closes/warns old,
opens new), and links the whole chain through placement/failover Work
Ledger facets. Done-bar: `verify-hypervisor-cross-provider-failover.mjs`
(27/27 — marker survives a vast → akash class move; corrupt custody heals
via archive; corrupt custody + corrupt archive refuses by name).

The AUTO-FAILOVER POLICY TRIGGER lets operators DECLARE when an armed
`FailoverPlan` may trigger from provider evidence
(`/v1/hypervisor/failover/plans/:id/{arm,disarm}` +
`/v1/hypervisor/failover/evaluate`, plus an opt-in background evaluator,
`IOI_FAILOVER_AUTO_EVALUATE_SECS`). "Automatic" means detection,
preparation, and loud surfacing — NEVER automatic authority: detection is
evidence-mapped from real daemon records (declared detector coverage:
credential_revoked, capacity_eviction, host_unreachable,
storage_unavailable; uncovered conditions stay operator-declared and the
plan says so), every trigger cites the record refs it read, arming
requires valid restore material (fail closed), arming is single-shot
(triggered plans need explicit re-arm — trigger loops are structurally
impossible), and a triggered run advances only through the unattended
phases before PARKING at the same wallet gate an operator-initiated run
crosses. No fee object. Done-bar:
`verify-hypervisor-auto-failover-trigger.mjs` (20/20 — evidence-cited
trigger from a simulated lease revocation, parked at the wallet gate,
no duplicate trigger, granted resume completes akash → vast with the
marker surviving, disarm stops evaluation).

Done-bars: `verify-hypervisor-cloud-candidate-plane.mjs`,
`verify-hypervisor-vast-candidate-adapter.mjs`,
`verify-hypervisor-vast-lifecycle.mjs`; per-adapter done-bars are listed
in [`byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md).
The first-cut implementation narration (source-health ladders, lifecycle
gate details) is archived at
[`../../_archive/implementation-logs/decentralized-cloud-implemented-contract-log.md`](../../_archive/implementation-logs/decentralized-cloud-implemented-contract-log.md).

### Not implemented (typed absence, swept 2026-09-04)

A repository-wide sweep across daemon routes, route modules, the serve lane,
augmentation modules, surface dirs, the RPC adapter, and engine bodies found:

- **No public origin.** Nothing is served at `decentralized.cloud`; the only
  consumer of `/v1/hypervisor/cloud-candidates/*` is the Hypervisor product UI.
  No SDK, explorer, or third-party front door exists.
- **No `CloudJobRequest`.** No composition envelope, tool schema, or console
  surface binds intent + budget + deadline + receipt requirements as one call.
- **No `local_capacity` source and no `contributed_supply` source.** Candidate
  sources are the seven provider quote adapters plus storage-backend facts.
- **No `CloudSupplyRegistration`** and no supply registry at any layer.
- **No `RoutingDecisionReceipt` and no fee object.** `fee_object_minted` is
  `false` on every placement decision; `routing_fee_eligibility:
  eligible_future` is the only fee-adjacent field.
- **Provider control planes are simulated by default.** Every lane's live path
  is env-gated (`IOI_<KIND>_LIVE=1`); only Akash has one bounded,
  owner-authorized live proof with both terminal branches (see the M09 §2
  record in the implementation guide). Simulator candidates are labelled and
  can never satisfy the two-real-candidates fee condition above.
- `network.dns` and `network.tls` have no adapter contract.
- **No `RedundancyPosture`.** Reactive failover exists
  (`/v1/hypervisor/failover/*`, wallet-gated, class-diverse); no warm-standby
  or active-active placement, per-replica exposure, or switch policy exists.

These are the objects ADR 0051 names. Each is `planned`; none may be described
as shipped until its `canon-to-code-delta.md` row records closure.

## Related Canon

- [`cloud/`](./cloud/README.md) — the product specification (adopted 2026-09-08)
- [`cloud/adr/0001`](./cloud/adr/0001-decentralized-cloud-is-a-product.md) — decentralized.cloud is a product; this file is the daemon's native contract

- [ADR 0051](../../../decisions/0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md)
- [`../marketplace-neutrality.md`](../marketplace-neutrality.md)
- [`README.md`](./README.md)
- [`exchange.md`](./exchange.md)
- [`trade.md`](./trade.md)
- [`../../components/hypervisor/providers-and-environments.md`](../../components/hypervisor/providers-and-environments.md)
- [`../../components/hypervisor/byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../components/storage-backends/doctrine.md`](../../components/storage-backends/doctrine.md)
- [`../../foundations/economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md)
