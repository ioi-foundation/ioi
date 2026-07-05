# decentralized.cloud

Status: alpha canon architecture doctrine.
Canonical owner: this file for `decentralized.cloud`, cloud resource
candidate semantics, optimized placement intelligence, resource liquidity
routing, cloud-placement receipts, and cloud-routing anti-patterns.
Supersedes: product prose that treats `decentralized.cloud` as Hypervisor's
cloud control plane, provider account owner, VM lifecycle owner, authority
layer, restore truth layer, mandatory cloud gateway, or storage custody owner.
Superseded by: none.
Last alignment pass: 2026-07-04.
Doctrine status: canonical
Implementation status: built (candidate plane + quote sources + guarded lifecycles over the BYO provider plane)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/decentralized_cloud_routes.rs`
Last implementation audit: 2026-07-05

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
IOI L1 settles only triggered public, economic, dispute, registry, rights,
reputation, or cross-domain commitments.
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
- lightweight explorer or status views over candidate supply.

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
runtime.model_server
runtime.browser
runtime.workbench
security.tee
security.ctee
```

Later classes such as databases, queues, caches, DNS, observability, and higher
PaaS surfaces may be added only after adapter contracts, authority semantics,
receipts, custody posture, and restore/failover behavior are real.

## Lifecycle

```text
user, agent, app, automation, or Hypervisor requests infrastructure capacity
  -> Hypervisor creates a placement context from environment/runtime/custody needs
  -> Hypervisor or wallet.network asks resource sources for candidates
  -> decentralized.cloud, direct provider adapters, user-specified providers,
     managed Hypervisor capacity, DePIN markets, storage backends, or
     customer-cloud inventories return candidates
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
  -> IOI L1 receives only selected settlement/dispute/public commitments
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
                                     // customer_inventory | managed_capacity |
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
spend authority.

### PlacementDecisionReceipt

The user-visible "Placement Receipt" is usually a projection over:

```text
PlacementDecision
ProviderOperationReceipt
SpendReceipt
RoutingDecisionReceipt
```

`RoutingDecisionReceipt` is legitimate only when optimized placement creates
visible routing/procurement/failover/reconciliation/billing value.

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

Done-bars: `verify-hypervisor-cloud-candidate-plane.mjs`,
`verify-hypervisor-vast-candidate-adapter.mjs`,
`verify-hypervisor-vast-lifecycle.mjs`; per-adapter done-bars are listed
in [`byo-provider-plane.md`](../../components/hypervisor/byo-provider-plane.md).
The first-cut implementation narration (source-health ladders, lifecycle
gate details) is archived at
[`../../_archive/implementation-logs/decentralized-cloud-implemented-contract-log.md`](../../_archive/implementation-logs/decentralized-cloud-implemented-contract-log.md).

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

## Related Canon

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
