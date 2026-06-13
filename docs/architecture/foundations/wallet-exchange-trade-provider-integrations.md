# Wallet Exchange, Trade, and Provider Integrations

Status: alpha canon architecture doctrine.
Canonical owner: this file for current Wallet-native `decentralized.exchange`
and `decentralized.trade` lanes, Hypervisor direct provider integrations, route
candidate boundaries, and cross-lane ownership doctrine.
Supersedes: product prose that treats `decentralized.exchange`,
`decentralized.trade`, cloud provider catalogs, or cloud routers as mandatory
middlemen, resource owners, custody owners, authority layers, or trust roots.
Superseded by: none.
Last alignment pass: 2026-06-13.

## Canonical Definition

**Wallet owns asset and exposure authority; Hypervisor integrates directly with
the infrastructure providers that run and store autonomous work.**

The present canon has two Wallet-native product lanes and one Hypervisor
infrastructure capability:

The present canon family is:

```text
decentralized.exchange
  route liquidity / convert assets

decentralized.trade
  route exposure / manage positions

Hypervisor direct provider integrations
  cloud compute, storage, GPUs, bandwidth, confidential compute, DePIN,
  hyperscalers, customer cloud, enterprise clusters, local machines,
  decentralized storage networks, and user-specified providers
```

The route or provider candidate is never authority by itself.

```text
Candidates are proposed.
wallet.network authorizes.
Hypervisor deploys or executes.
Venues and providers perform.
Agentgres records admitted truth.
Storage backends hold bytes.
IOI L1 settles only triggered public, economic, dispute, registry,
rights, reputation, or cross-domain commitments.
```

## Owns

`decentralized.exchange` and `decentralized.trade` may own or coordinate:

- source discovery;
- adapter registries;
- candidate normalization;
- route scoring;
- venue/provider metadata;
- cost, latency, availability, and risk comparison;
- route-candidate receipts;
- public comparison surfaces;
- lane-specific analytics;
- proposal metadata that Wallet, Hypervisor, Agentgres, or domain apps may
  reference when a route becomes consequential.

Wallet lane-specific ownership:

```text
decentralized.exchange
  spot route sources, pool/adapter metadata, quote comparison,
  route-candidate receipts, and decentralized-first exchange views

decentralized.trade
  trading venue adapters, order-ticket normalization, market discovery,
  position/risk display, margin calculations, strategy templates,
  venue comparison, and trade-candidate receipts

```

Hypervisor provider integrations may own or coordinate:

- direct provider connectors;
- local inventory;
- customer cloud connectors;
- hyperscaler connectors;
- cloud GPU provider connectors;
- DePIN compute provider connectors;
- decentralized storage network connectors;
- enterprise cluster connectors;
- user-specified provider routes;
- hardware and GPU availability;
- confidential-compute capability metadata;
- attestation descriptors;
- deployment templates;
- price, latency, reliability, health, and region comparison;
- provider reputation projections;
- `CloudRoute`, `CloudCandidate`, and cloud-route receipts.

## Does Not Own

Wallet lanes and Hypervisor provider integrations do not own:

- user authority;
- wallet keys;
- root custody;
- final approvals;
- liquidity;
- market venues;
- exchange execution;
- collateral policy;
- margin policy;
- trading eligibility;
- provider infrastructure;
- canonical workspace state;
- canonical app state;
- Agentgres operation admission;
- storage payload meaning;
- declassification decisions;
- IOI L1 settlement truth.

Correct framing:

```text
decentralized.exchange is not the liquidity.
It is a liquidity route source and comparison surface.

decentralized.trade is not the broker.
It is an exposure route source and trading interface.

Hypervisor provider integrations are not the cloud.
They are direct integration paths to concrete providers.
```

Incorrect framing:

```text
decentralized.exchange is the exchange backend.
decentralized.trade owns user positions.
cloud provider catalog = Hypervisor execution owner.
cloud router = mandatory gateway for cloud or DePIN.
```

## Parked Future: decentralized.cloud

`decentralized.cloud` is not part of the present canon spine or near-term
product architecture.

It is parked as a possible future public cloud layer:

```text
future decentralized.cloud
  provider marketplace
  P2P / PQ-aware cloud routing layer
  compute and storage receipt explorer
  cloud/provider reputation surface
  public provider catalog
  infrastructure marketplace with bonds, SLAs, and disputes
```

Current canon should not require Hypervisor, Fleet, Wallet, or agents to route
through `decentralized.cloud`. Hypervisor must support direct provider mode for
local machines, customer cloud accounts, hyperscalers, cloud GPU providers,
enterprise clusters, DePIN compute providers, decentralized storage networks,
and user-specified routes.

## Lifecycle

### Liquidity Route

```text
user, agent, app, or service requests asset conversion
  -> wallet.network creates an exchange authority context
  -> Wallet or domain app asks route sources for candidates
  -> decentralized.exchange, direct pools, routers, solvers, quote APIs,
     bridge routers, RFQ systems, or user routes return candidates
  -> wallet.network evaluates policy, risk labels, simulation, fees,
     slippage, route dependencies, grant/lease, and revocation epoch
  -> user, org, policy, or agent grant approves an exact ExchangeIntent
  -> wallet.network signs exact TxIntent records or denies execution
  -> venue/chain executes
  -> Wallet emits ExchangeReceipt
  -> Agentgres records receipt/evidence/outcome refs when operational truth
     is affected
  -> IOI L1 receives only selected settlement/dispute/public commitments
```

### Exposure Route

```text
user, agent, app, or service requests market exposure
  -> wallet.network creates a high-risk trade authority context
  -> decentralized.trade or another venue adapter returns trade candidates
  -> Wallet evaluates eligibility, leverage, margin mode, venue risk,
     oracle/mark-price risk, funding, liquidation, collateral, stop-loss,
     max-loss policy, agent authority, and jurisdiction policy
  -> user, org, standing policy, or restricted agent grant approves exact
     TradeIntent records or denies execution
  -> venue executes orders and maintains position state
  -> Wallet/venue adapters monitor position risk and emit receipts
  -> Agentgres records relevant receipts, evidence, and policy state
  -> IOI L1 receives only selected settlement/dispute/public commitments
```

### Execution Route

```text
agent, workflow, service, or operator requests infrastructure
  -> Hypervisor creates a workload/resource intent
  -> direct provider connectors, local inventory, customer cloud connectors,
     DePIN markets, storage networks, or user-specified routes return
     CloudRoute candidates
  -> Fleet compares price, latency, hardware, GPU class, storage locality,
     privacy posture, cTEE posture, attestation, jurisdiction, reliability,
     provider reputation, and budget
  -> wallet.network authorizes spend, admin scopes, secret release,
     declassification policy, or provider account use
  -> Hypervisor Daemon or approved provider connector deploys/runs workload
  -> provider supplies compute/storage/network resources
  -> Agentgres records execution receipts, state refs, artifact refs, and
     restore/replay metadata
  -> IOI L1 receives only selected marketplace, rights, dispute, registry,
     public-proof, or cross-domain commitments
```

## Minimal Implementation Objects

### RouteCandidate

`RouteCandidate` is owned in detail by
[`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md).
It remains a proposal until selected into an approved `ExchangeIntent`.

### TradeIntent

`TradeIntent` is the semantic wallet object above raw venue order or calldata.
Perps, margin, leverage, and position management are high-risk wallet actions,
not ordinary swap routes.

```rust
struct TradeIntent {
    intent_id: Hash,
    initiator_id: PrincipalId,       // user | org | app | agent
    account_id: AccountId,

    venue: VenueRef,
    market: MarketRef,
    side: TradeSide,                 // long | short | buy | sell
    collateral_asset: AssetRef,
    collateral_amount: Amount,
    leverage: Decimal,
    margin_mode: MarginMode,         // isolated | cross
    order_type: OrderType,           // market | limit | stop | tp_sl

    liquidation_price_estimate: Option<Price>,
    funding_rate_snapshot: Option<FundingRate>,
    oracle_source: Option<OracleRef>,
    mark_price_snapshot: Option<Price>,

    max_loss_policy: MaxLossPolicy,
    stop_loss: Option<OrderCondition>,
    take_profit: Option<OrderCondition>,

    policy_hash: Hash,
    grant_id: Option<Hash>,
    lease_id: Option<Hash>,
    revocation_epoch: u64,

    simulation_hash: Hash,
    risk_labels: Vec<RiskLabel>,
    user_disclosures: Vec<DisclosureRef>,
    venue_intents: Vec<VenueIntent>
}
```

### PositionReceipt

```rust
struct PositionReceipt {
    receipt_id: ReceiptId,
    position_id: PositionId,
    venue: VenueRef,
    market: MarketRef,
    side: TradeSide,
    size: Amount,
    collateral: Amount,
    leverage: Decimal,
    margin_mode: MarginMode,
    entry_price: Price,
    mark_price: Price,
    liquidation_price: Option<Price>,
    funding_paid_or_received: Amount,
    pnl: Amount,
    policy_status: PolicyStatus,
    risk_status: RiskStatus,
    close_conditions: Vec<OrderCondition>,
    created_at: Timestamp
}
```

### CloudRoute

`CloudRoute` is the Hypervisor/Fleet object for routing a workload to compute,
storage, GPU, network, or confidential execution infrastructure.

```rust
struct CloudRoute {
    route_id: Hash,
    workload_id: Hash,
    requester: PrincipalId,          // user | org | agent | Hypervisor
    purpose: String,

    resource_requirements: ResourceSpec,
    privacy_requirements: PrivacySpec,
    storage_requirements: StorageSpec,
    budget: BudgetSpec,
    jurisdiction: Vec<RegionPolicy>,

    candidates: Vec<CloudCandidate>,
    selected_candidate: CloudCandidateId,

    provider_trust_model: TrustModel,
    attestation_requirements: Option<AttestationPolicy>,
    secret_release_policy: SecretReleasePolicy,

    wallet_policy_hash: Hash,
    grant_id: Option<Hash>,
    revocation_epoch: u64,

    expected_cost: CostEstimate,
    risk_labels: Vec<CloudRiskLabel>,
    receipt_policy: ReceiptPolicy
}
```

### CloudCandidate

```rust
struct CloudCandidate {
    candidate_id: CloudCandidateId,
    source: CloudRouteSourceRef,
    provider: ProviderRef,           // AWS | GCP | Azure | CoreWeave |
                                     // Lambda | RunPod | Vast | Akash |
                                     // Filecoin | local | customer_cloud |
                                     // enterprise_kubernetes | etc.
    resource_type: ResourceType,     // gpu | cpu | storage | enclave |
                                     // vm | container | k8s | bare_metal
    hardware: Option<String>,        // H100 | A100 | RTX_4090 | etc.
    region: Option<String>,
    price_estimate: CostEstimate,
    availability: Availability,
    privacy_posture: PrivacyPosture,
    attestation: Option<AttestationDescriptor>,
    storage_persistence: Option<StorageDescriptor>,
    network_profile: NetworkProfile,
    reputation_score: Option<Score>,
    risk_labels: Vec<CloudRiskLabel>
}
```

## Risk Labels

### Exchange Risk Labels

Examples:

```text
No Bridge
Bridge Exposure
Admin-Key Risk
Oracle Risk
Legacy EC
PQ-Native
Hybrid / Signature-Agile
Unknown Contract
Unlimited Approval
Route Risk Low / Medium / High
```

### Trade Risk Labels

Examples:

```text
Leverage Risk
Liquidation Risk
Funding Rate Risk
Oracle / Mark Price Risk
Cross-Margin Risk
Venue Risk
Insurance Fund / ADL Risk
Open Interest Risk
Withdrawal / Settlement Risk
Jurisdiction Restricted
Agent Trading Disabled
Agent Trading Limited
Paper Mode Only
```

### Cloud Risk Labels

Examples:

```text
Provider-Trust Route
Confidential Compute
Attestation Available
Attestation Missing
TEE-Limited
GPU Plaintext Risk
cTEE Split Path
Local-Only
Customer Cloud
Decentralized Provider
Storage Retrieval Risk
Region Risk
Cost Spike Risk
No Persistent Storage
Encrypted Archive Required
```

## Admission / Settlement Boundary

Route and provider proposals do not become operational truth by themselves.

```text
route or provider candidate
  -> wallet.network authority/policy evaluation where power, funds, secrets,
     private data, or declassification are involved
  -> Hypervisor Daemon or venue/provider execution boundary where work happens
  -> Agentgres operation, receipt, artifact ref, state root, or projection
  -> optional IOI L1 / compatible L1 commitment by trigger
```

Exchange and trade actions require exact wallet intent binding before signing
or execution. Cloud actions require wallet authorization when they spend funds,
use provider accounts, release secrets, mount private workspace state, change
declassification posture, or affect long-lived infrastructure.

## Events and Receipts

Meaningful route and provider transitions should emit receipts:

```text
RouteCandidateReceipt
ExchangeIntentReceipt
ExchangeReceipt
TradeCandidateReceipt
TradeIntentReceipt
OrderReceipt
PositionReceipt
PositionRiskReceipt
CloudRouteCandidateReceipt
CloudRouteApprovalReceipt
CloudExecutionReceipt
ProviderAttestationReceipt
StoragePlacementReceipt
SecretReleaseReceipt
DeclassificationReceipt
PaymentReceipt
DisputeReceipt
```

Receipts should bind:

- initiator;
- selected candidate or denied candidate;
- policy hash;
- authority refs;
- revocation epoch;
- risk labels;
- simulation or verification hash when relevant;
- provider, venue, route, pool, chain, or storage dependency;
- Agentgres refs when operational truth is affected;
- IOI L1 or compatible L1 commitment refs only when triggered.

## Conformance Checks

- No `decentralized.*` lane can authorize a user, agent, or organization action.
- No route candidate can execute without Wallet or policy approval when funds,
  authority, secrets, private data, or consequential work are involved.
- No lane can claim to own liquidity, venue execution, provider resources, or
  user custody.
- `decentralized.trade` must not be presented as ordinary spot exchange when
  leverage, margin, liquidation, or position lifecycle is involved.
- Agent trading over perps or margin must be disabled by default or constrained
  by explicit paper/sandbox, max collateral, max leverage, isolated-margin,
  stop-loss, max daily loss, market whitelist, expiry, and step-up policies.
- Hypervisor provider integration cannot treat a cheap provider as privacy-safe
  merely because payload bytes are encrypted at rest.
- Provider selection cannot release secrets or protected plaintext without
  wallet.network authority and the declared cTEE, TEE, local, customer-cloud,
  or provider-trust posture.
- Storage availability cannot be treated as payload meaning, artifact truth, or
  restore validity without Agentgres artifact refs, state roots, and receipts.
- IOI L1 cannot become the default settlement sink for every route proposal.

## Anti-Patterns

Reject these:

1. Treating `decentralized.exchange` as the wallet exchange backend.
2. Treating `decentralized.trade` as a broker, custodian, or user-position
   owner.
3. Promoting parked future `decentralized.cloud` into a mandatory gateway.
4. Treating route sources, quote APIs, solvers, venues, or provider catalogs as
   trust roots.
5. Treating spot swaps, perps, margin, and strategy execution as one risk class.
6. Giving agents open-ended perps or leveraged-trading authority.
7. Hiding route, venue, bridge, oracle, admin-key, liquidation, funding, or
   provider dependencies from users.
8. Treating cTEE as ordinary encryption at rest.
9. Treating hardware confidential compute as magic rather than an execution
   lane with attestation, workload, side-channel, key-release, and provider
   assumptions.
10. Treating Akash, Filecoin, AWS, GCP, local nodes, or customer VPCs as
    interchangeable resources without privacy, trust, region, storage,
    persistence, and receipt differences.
11. Creating one separate app with separate truth for every lane instead of
    projecting them through Wallet, Hypervisor, Agentgres, and IOI contracts.

## Related Canon

- [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md)
- [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md)
- [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md)
- [`../components/hypervisor/fleet.md`](../components/hypervisor/fleet.md)
- [`../components/daemon-runtime/private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md)
- [`../components/agentgres/doctrine.md`](../components/agentgres/doctrine.md)
- [`../components/agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md)
- [`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md)
- [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md)
