# decentralized.cloud

Status: alpha canon architecture doctrine.
Canonical owner: this file for `decentralized.cloud`, cloud resource
candidate semantics, optimized placement intelligence, resource liquidity
routing, cloud-placement receipts, the public product face and
`CloudJobRequest` composition (ADR 0051), the cloud supply registry, and
cloud-routing anti-patterns.
Supersedes: product prose that treats `decentralized.cloud` as Hypervisor's
cloud control plane, provider account owner, VM lifecycle owner, authority
layer, restore truth layer, mandatory cloud gateway, or storage custody owner.
Superseded by: none.
Last alignment pass: 2026-09-04 (ADR 0051: public face, job primitive,
local capacity as a venue, supply registry, fee binding).
Doctrine status: canonical
Implementation status: mixed (candidate plane + quote sources + guarded lifecycles over the BYO provider plane are built; the public face, `CloudJobRequest`, `local_capacity` source, supply registry, and minted `RoutingDecisionReceipt` are planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/decentralized_cloud_routes.rs`
  - `apps/hypervisor/scripts/verify-hypervisor-cloud-candidate-plane.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-vast-candidate-adapter.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-vast-lifecycle.mjs`
Last implementation audit: 2026-09-04 (route sweep for the public face and fee state; the built candidate-plane claims retain their 2026-07-05 basis)

## Canonical Definition

`decentralized.cloud` is a preferred first-party resource-intelligence engine
for cloud infrastructure capacity.

It answers:

```text
I need infrastructure capacity with these constraints.
Which compute, storage, network, GPU, runtime, or custody candidates are
available across connected, managed, centralized, decentralized, and
customer-owned providers?
```

It is analogous to a cloud DEX or OpenRouter-style meta-router for cloud
resources, but the IOI canon makes it primarily an API/RPC/SDK candidate engine
consumed by Hypervisor, wallet.network, ioi.ai, agents, and third-party
clients. It does not own execution, provider accounts, authority, restore
validity, or storage truth.

```text
decentralized.cloud proposes resource candidates.
wallet.network authorizes spend, provider credentials, grants, and revocation.
Hypervisor provisions, executes, snapshots, restores, supervises, and tears down.
Agentgres records admitted truth, receipts, state roots, and restore validity.
Storage backends hold encrypted bytes.
The system settles locally unless its declared profile selects an external
service such as IOI L1 for triggered public, economic, dispute, registry,
rights, reputation, or cross-domain commitments.
```

In Hypervisor product UX, the user does not choose between Hypervisor and
`decentralized.cloud`. The clean placement choices are:

```text
Run local
Use my infrastructure
Pick a cloud
Let Hypervisor choose
```

`decentralized.cloud` powers two layers without taking away user choice:

```text
Pick a cloud
  show venues, provider posture, regions, GPU/CPU/storage/network options,
  estimated cost, custody posture, reliability, and support boundaries
  the user pins the venue

Let Hypervisor choose
  compare venues, candidates, quotes, failover plans, custody posture,
  provider reliability, and spend estimates
  Hypervisor selects or recommends the placement under policy
```

Hypervisor still executes the selected environment lifecycle. `Pick a cloud`
is therefore compatible with a visible adapter/orchestration fee when Hypervisor
performs provider lifecycle work, and `Let Hypervisor choose` is compatible with
a visible routing/procurement fee when optimized placement creates challengeable
routing value.

## Public Product Face

[ADR 0051](../../../decisions/0051-decentralized-cloud-public-face-job-primitive-and-supply-registry.md)
permits `decentralized.cloud` to be a **standalone public product face** in
addition to the engine Hypervisor consumes internally. The face has two
surfaces:

```text
Candidate API / SDK / explorer
  "what capacity is available now, at what evidence-backed price, until when"
  served at the decentralized.cloud origin; read-only; every response carries
  source, adapter, observed_at, expires_at, and evidence refs; sources without
  adapters answer candidate_source_unavailable — never an invented price

Job API (the branded front for Hypervisor's optimized-placement lane)
  "this much capacity, under this budget, for this long, receipt back"
  one CloudJobRequest; the same primitive for a human or an agent caller;
  tool-callable (MCP and native tool schema) and console/CLI-callable with
  identical semantics and identical receipts
```

Brand is not owner. The face composes four owners and adds none:

```text
decentralized.cloud proposes and normalizes candidates.
wallet.network authorizes: a wallet grant for a human, a scoped
  CapabilityLease draw-down for an agent — the caller never holds provider
  credentials.
Hypervisor places, provisions, supervises, fails over, and tears down.
Agentgres records what ran and what it cost.
```

The face therefore has no private authority store, session plane, credential
vault, provider integration, placement scorer, or receipt format. It is served
by the Hypervisor daemon under the existing auth-gated rollout posture at the
`decentralized.cloud` origin (ADR 0051 §7, owner-reversible). Direct use by a
third party changes the front door, not the owner of authority, execution, or
truth, and it never becomes a requirement for Hypervisor users, who keep the
four placement choices above.

The abstraction earns its weight only when the caller can stop knowing the
venue names. A caller that must choose between named providers is using the
`Pick a cloud` surface, not the job API.

## Owns

`decentralized.cloud` may own or coordinate:

- API/RPC/SDK endpoints for cloud resource candidates;
- provider quote and resource-liquidity discovery;
- centralized cloud, DePIN compute, GPU marketplace, storage, network, and
  customer-cloud candidate adapters;
- candidate normalization across resource classes;
- quote comparison, cost/risk/latency/capacity scoring, and policy hints;
- provider reliability, availability, interruption, region, and custody
  posture projections;
- optimized placement, failover, and re-placement suggestions;
- resource-candidate receipts and route analytics;
- adapter registry metadata for cloud resource sources;
- lightweight explorer or status views over candidate supply;
- the public candidate API/SDK/explorer and the branded job API front at the
  `decentralized.cloud` origin (ADR 0051);
- the `CloudJobRequest` composition envelope and its tool/console schemas;
- cloud supply registry metadata for managed and contributed supply
  (`CloudSupplyRegistration`), never the accounts, credentials, or custody
  behind it.

## Does Not Own

`decentralized.cloud` does not own:

- provider accounts or credentials;
- Wallet authority, spend approval, grants, revocation, or signatures;
- Hypervisor environment lifecycle;
- VM, container, runtime, storage, IP, ingress, or model-server execution;
- Agentgres operation admission, state roots, receipts, or restore validity;
- storage payload bytes or encrypted archive custody;
- private workspace plaintext or custody proof;
- provider infrastructure;
- marketplace settlement;
- IOI L1 settlement truth.

Correct framing:

```text
decentralized.cloud routes cloud resource liquidity.
Hypervisor runs the workload.
wallet.network authorizes it.
Agentgres proves what happened.
```

Incorrect framing:

```text
decentralized.cloud is Hypervisor's cloud control plane.
decentralized.cloud owns provider accounts.
decentralized.cloud approval is enough to spend or deploy.
decentralized.cloud owns VM lifecycle or restore truth.
All Hypervisor cloud placement must route through decentralized.cloud.
```

## Resource Classes

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

## Lifecycle

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

## Minimal Implementation Objects

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

## Implemented Contract (candidate plane)

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

## Product Suite Position

`decentralized.cloud` completes the first `decentralized.*`
candidate-intelligence suite under the IOI / `ioi.ai` public umbrella:

```text
decentralized.exchange  -> route value
decentralized.trade     -> route risk / exposure
decentralized.cloud     -> route infrastructure capacity
```

Short form:

```text
Route value. Route risk. Route infrastructure.
Under authority. With receipts.
```

`decentralized.xyz` may exist as a protocol/docs/redirect namespace, but it is
not the required public umbrella. The public umbrella is IOI / `ioi.ai`; the
`decentralized.*` names are the precise protocol surfaces behind Exchange,
Trade, and Cloud Routing.

Under ADR 0051, `decentralized.cloud` is additionally a standalone public
product face with its own customers and its own front door. That standing is
commercial, not architectural: it changes who calls the engine, not what the
engine owns. The one structural law holds — no surface mints a second spine.

## Anti-Patterns

1. Treating `decentralized.cloud` as a mandatory gateway before Hypervisor can
   use provider integrations.
2. Treating `decentralized.cloud` as the provider account or credential owner.
3. Treating resource candidates as spend authority.
4. Treating provider APIs, CIDs, bucket existence, or leases as Agentgres
   restore truth.
5. Flattening every provider into a fake generic VM lifecycle.
6. Charging a routing fee for direct connected infrastructure with no optimized
   placement value and no Hypervisor-performed provider lifecycle work.
7. Claiming Private or cTEE custody from provider marketing labels without
   matching custody receipts.
8. Letting `decentralized.cloud` own execution, settlement, marketplace rank,
   or provider lifecycle truth.
9. Giving managed capacity or contributed supply a default, tie-break, or
   fallback preference in placement, or omitting the first-party win/loss
   record from a decision that compared it.
10. Letting a job caller — human or agent — hold, see, or forward a provider
    credential; the router is the credential boundary between callers and
    clouds.
11. Minting a `RoutingDecisionReceipt` or charging a routing fee from a
    comparison that included simulator, expired, or evidence-less candidates,
    or from a comparison of fewer than two real candidates.
12. Presenting the public face as a fifth placement choice beside `Pick a
    cloud`; the face is the front door to `Let Hypervisor choose`, and the own
    pool — not the router — is what appears as a venue.
13. Building supply ahead of the router's unmet-request evidence.
14. Applying a redundancy posture the caller did not declare, blending replicas
    into one receipt, or calling two replicas on one provider class redundant.

## Related Canon

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
