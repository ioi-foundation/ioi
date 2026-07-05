# decentralized.exchange

Status: alpha canon architecture doctrine.
Canonical owner: this file for `decentralized.exchange`, spot and cross-chain
route-source boundaries, route-candidate semantics, exchange receipts, and
exchange anti-patterns.
Supersedes: product prose that treats `decentralized.exchange` as Wallet's
exchange backend, a liquidity owner, a custody surface, a router monopoly, or
a trust root.
Superseded by: none.
Last alignment pass: 2026-06-14.
Doctrine status: canonical
Implementation status: partial (SDK candidate-source client exists; live route service is a deployment concern)
Implementation refs:
  - `packages/wallet-sdk/`
Last implementation audit: 2026-07-05

## Canonical Definition

`decentralized.exchange` is a preferred first-party route-intelligence engine
for asset conversion.

It answers:

```text
I have asset X.
I need asset Y.
What source-agnostic route candidates are available?
```

It is analogous to a RocketX/Rango/aggregator-style route surface in product
shape, but the IOI canon makes it primarily an API/RPC/SDK service consumed by
Wallet and other clients, with a stricter authority boundary:

```text
decentralized.exchange proposes.
wallet.network authorizes.
Pools, bridges, solvers, venues, and chains execute.
Agentgres records receipts and evidence when operational truth is affected.
```

Wallet is the cockpit. A Wallet user may see Exchange inside wallet.network
while Wallet calls `decentralized.exchange` for route candidates behind the
authority surface. `decentralized.exchange` may still expose docs, a route
explorer, adapter registry, or lightweight standalone swap view, but that is not
the canonical user path.

## Owns

`decentralized.exchange` may own or coordinate:

- API/RPC/SDK endpoints for route candidates;
- spot route-source discovery;
- pool, bridge, router, solver, RFQ, and quote-source adapters;
- pool and route metadata normalization;
- route scoring and comparison;
- route-candidate receipts;
- decentralized-first exchange views;
- route analytics and route-source health projections.

## Does Not Own

`decentralized.exchange` does not own:

- Wallet exchange authority;
- user keys;
- final approvals;
- liquidity;
- pools, bridges, routers, solvers, or quote APIs;
- chain execution or finality;
- exchange truth;
- Agentgres receipts or operational truth;
- IOI L1 settlement.

Correct framing:

```text
Wallet Exchange is the authority cockpit.
decentralized.exchange is a preferred decentralized route-intelligence engine.
```

Incorrect framing:

```text
decentralized.exchange is the exchange backend for Wallet.
decentralized.exchange owns liquidity.
decentralized.exchange approval is enough to swap.
Users must leave Wallet and use decentralized.exchange directly to exchange.
```

## Lifecycle

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

## Minimal Implementation Objects

### RouteCandidate

`RouteCandidate` is a proposed route from `decentralized.exchange`, direct pool
adapters, DEX routers, bridge routers, solvers, quote APIs, RFQ systems, or
user-specified paths.

It is not authority and cannot execute until selected into an approved
`ExchangeIntent`.

Every `RouteCandidate` must carry `CandidateEvidence`. A route candidate without
candidate evidence is an untrusted suggestion, not an approval candidate.

```rust
struct CandidateEvidence {
    candidate_id: Hash,
    source: RouteSourceRef,
    adapter_id: AdapterRef,
    observed_at: Timestamp,
    expires_at: Timestamp,
    coverage_state: RiskCoverageState, // assessed | unknown | unassessed |
                                      // stale | conflicting_sources
    evidence_refs: Vec<EvidenceRef>,
    risk_labels: Vec<RiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>,
    claims: Vec<CandidateClaim>
}
```

Required candidate failure behavior:

```text
missing CandidateEvidence
  -> reject as not approval-eligible

missing adapter_id, observed_at, expires_at, evidence_refs, or coverage_state
  -> reject as malformed

expired candidate
  -> require requote or resimulation

unknown, unassessed, stale, or conflicting_sources coverage_state
  -> cannot execute silently; requires Wallet caution state, simulation,
     policy review, or denial
```

`RouteCandidate` shape:

```rust
struct RouteCandidate {
    route_id: Hash,
    candidate_evidence: CandidateEvidence,
    source: RouteSourceRef,
    adapter_id: AdapterRef,
    source_kind: RouteSourceKind,    // decentralized_exchange | direct_pool |
                                     // dex_router | bridge_router | solver |
                                     // quote_api | user_specified
    path: Vec<RouteHop>,
    expected_amount_out: Amount,
    min_amount_out: Amount,
    calldata_commitment: Hash,
    quote_hash: Hash,
    observed_at: Timestamp,
    expires_at: Timestamp,
    risk_labels: Vec<RiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>,
    economics: ExchangeEconomics,
    evidence_refs: Vec<EvidenceRef>,
    route_receipt_ref: Option<ReceiptRef>
}
```

### ExchangeIntent

`ExchangeIntent` is owned in detail by
[`wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md).
It binds the selected route, calldata commitments, slippage, simulation hash,
policy hash, grant/lease, revocation epoch, economics, risk labels, and exact
`TxIntent` records before exchange execution can be approved or signed.

### Wallet SDK Source Client

The canonical SDK seam for this first-party source is
`createDecentralizedExchangeCandidateSourceClient()` in `@ioi/wallet-sdk`.

That client fixes:

```text
source: decentralized.exchange
adapter_id: adapter:decentralized-exchange
domain: exchange
candidate_kind: route_candidate
trust_boundary: candidate_source_only
evidence_policy: claims_plus_refs_required
```

The helper is a source client, not an approval client. It may fetch executable
`CandidateEvidence` from a decentralized.exchange-compatible endpoint, but
Wallet must still verify, simulate, policy-check, approve or deny, execute, and
receipt the selected `ExchangeIntent`.

## Risk Labels

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

## Events and Receipts

Meaningful exchange transitions should emit receipts:

```text
RouteCandidateReceipt
ExchangeIntentReceipt
ExchangeReceipt
PaymentReceipt
DisputeReceipt
```

Receipts should bind:

- initiator;
- selected route or denied route;
- candidate evidence;
- adapter id;
- observed timestamp;
- expiry;
- coverage state;
- evidence refs;
- policy hash;
- authority refs;
- revocation epoch;
- risk labels;
- simulation hash;
- provider, route, pool, bridge, chain, or quote dependency;
- Agentgres refs when operational truth is affected;
- IOI L1 commitment refs only when triggered.

## Conformance Checks

- A quote is not authority.
- A route candidate is not approval.
- A route source is not a trust root.
- Route candidates must include `CandidateEvidence`.
- Missing, expired, stale, unknown, unassessed, or conflicting candidate
  evidence cannot execute silently.
- Final execution requires wallet.network intent binding.
- Bridge, admin-key, oracle, unlimited-approval, and unknown-contract risks
  must not be hidden behind a "best route" label.

## Anti-Patterns

Reject these:

1. Treating `decentralized.exchange` as the Wallet exchange backend.
2. Treating route sources, quote APIs, solvers, bridges, or pools as authority.
3. Treating bridge routes and same-chain pool routes as the same risk class.
4. Hiding route dependencies from Wallet, users, agents, or receipts.
5. Recording exchange history only in app-local state instead of receipt-backed
   truth when operational state is affected.
6. Requiring the canonical Wallet user to visit `decentralized.exchange` before
   Wallet can review, approve, execute, and receipt an exchange.

## Related Canon

- [`README.md`](./README.md)
- [`trade.md`](./trade.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/api-authority-scopes.md`](../../components/wallet-network/api-authority-scopes.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
