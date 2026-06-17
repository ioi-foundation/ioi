# decentralized.trade

Status: alpha canon architecture doctrine.
Canonical owner: this file for `decentralized.trade`, advanced trading and
exposure route boundaries, perps/position lifecycle doctrine, prediction
markets/event contracts, `TradeIntent`, `PredictionIntent`, `PositionReceipt`,
`PredictionReceipt`, and agent-trading restrictions.
Supersedes: product prose that treats perps, margin, leverage, prediction
markets, event contracts, or strategy execution as ordinary exchange routes.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

`decentralized.trade` is a preferred first-party venue, market, and
exposure-intelligence engine for advanced trade candidates.

It answers:

```text
I want exposure to price movement or an event outcome under defined risk.
What venue actions, orders, positions, prediction markets, event contracts,
or strategy candidates are available?
```

It may feel like an aggregator for perps, spot order venues, prediction
markets, event contracts, and position management, but it is primarily an
API/RPC/SDK service consumed by Wallet and other clients. It is not a broker,
custodian, venue, resolution oracle, or Wallet authority layer.

```text
decentralized.trade proposes exposure candidates.
wallet.network authorizes exact TradeIntent records.
Venues execute orders, maintain venue-native position state, and resolve
event markets under venue or oracle rules.
Wallet and Agentgres make authority, receipts, and risk state accountable.
```

Wallet is the cockpit. A Wallet user may see Trade inside wallet.network while
Wallet calls `decentralized.trade` for venue, market, position, and event
candidates behind the authority surface. `decentralized.trade` may still expose
docs, market explorers, adapter registries, paper venues, or a standalone
terminal later, but that is not the canonical approval path.

## Owns

`decentralized.trade` may own or coordinate:

- API/RPC/SDK endpoints for trade, position, venue, and prediction candidates;
- trading venue adapters;
- order-ticket normalization;
- market discovery;
- prediction-market and event-contract discovery;
- venue comparison;
- position and risk display;
- event market and resolution-rule display;
- margin and liquidation calculations;
- event-market liquidity, spread, and max-loss calculations;
- strategy templates;
- trade-candidate receipts and analytics views.

## Does Not Own

`decentralized.trade` does not own:

- user authority;
- Wallet keys;
- collateral custody;
- trading eligibility;
- final approval;
- venue execution;
- market resolution;
- event outcome truth;
- user positions as canonical Wallet truth;
- policy or compliance decisions;
- Agentgres receipt truth;
- IOI L1 settlement.

Correct framing:

```text
Wallet owns trade authority.
decentralized.trade is a preferred exposure-intelligence engine that proposes
routes, markets, and venue actions.
Venues execute, resolve event markets, and maintain venue-native position state.
```

Incorrect framing:

```text
decentralized.trade owns user positions.
Perps are just another exchange route.
Prediction markets are just swaps.
Agents may trade leveraged products by default.
Agents may place live event bets by default.
Users must leave Wallet and use decentralized.trade directly to trade.
```

## Lifecycle

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

### Event Exposure Route

```text
user, agent, app, or service requests event exposure
  -> wallet.network creates a high-risk prediction authority context
  -> decentralized.trade or another event-market adapter returns market
     candidates
  -> Wallet evaluates event category, venue risk, resolution source,
     market rules, ambiguity, liquidity, spread, manipulation/insider risk,
     max loss, max payout, jurisdiction policy, and agent authority
  -> user, org, standing policy, or restricted agent grant approves exact
     PredictionIntent records or denies execution
  -> venue executes order and maintains venue-native event position state
  -> venue or oracle resolves the market under its rules
  -> Wallet/venue adapters emit prediction, risk, and resolution receipts
  -> Agentgres records relevant receipts, evidence, policy state, and
     resolution refs
  -> IOI L1 receives only selected settlement/dispute/public commitments
```

## Minimal Implementation Objects

### CandidateEvidence

Every trade, venue, position, and prediction candidate must carry
`CandidateEvidence`. A candidate without source, adapter, timestamp, expiry,
coverage state, and evidence refs is not approval-eligible.

```rust
struct CandidateEvidence {
    candidate_id: Hash,
    source: CandidateSourceRef,
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

Failure behavior:

```text
missing CandidateEvidence
  -> reject as not approval-eligible

missing adapter_id, observed_at, expires_at, evidence_refs, or coverage_state
  -> reject as malformed

expired venue, quote, liquidity, funding, or oracle snapshot
  -> require refresh or resimulation

unknown, unassessed, stale, or conflicting_sources coverage_state
  -> cannot execute silently; requires Wallet caution state, policy review,
     step-up, paper mode, or denial
```

### TradeCandidate

`TradeCandidate` is a proposed venue/order/position action from
`decentralized.trade`, a venue adapter, a paper venue, or user-specified route.
It is not authority and cannot execute until selected into an approved
`TradeIntent`.

```rust
struct TradeCandidate {
    trade_candidate_id: Hash,
    candidate_evidence: CandidateEvidence,
    venue_candidate_id: Hash,
    market: MarketRef,
    side: TradeSide,
    collateral: Money,
    leverage: Option<Decimal>,
    margin_mode: Option<MarginMode>,
    order_template: VenueOrderTemplate,
    liquidation_price_estimate: Option<Price>,
    funding_rate_snapshot: Option<FundingRate>,
    oracle_source: Option<OracleRef>,
    observed_at: Timestamp,
    expires_at: Timestamp,
    evidence_refs: Vec<EvidenceRef>,
    risk_labels: Vec<RiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>
}
```

### TradeIntent

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

### PredictionIntent

`PredictionIntent` is the semantic wallet object for event exposure. It is a
specialized trade intent, not a separate authority system.

### PredictionCandidate

`PredictionCandidate` is a proposed event-market action. It is not authority
and cannot execute until selected into an approved `PredictionIntent`.

```rust
struct PredictionCandidate {
    prediction_candidate_id: Hash,
    candidate_evidence: CandidateEvidence,
    venue_candidate_id: Hash,
    market_id: MarketRef,
    question: String,
    outcome: OutcomeRef,
    resolution_source: ResolutionSourceRef,
    market_rules_hash: Hash,
    liquidity_snapshot: LiquiditySnapshot,
    price_snapshot: Price,
    max_loss: Money,
    max_payout: Money,
    observed_at: Timestamp,
    expires_at: Timestamp,
    evidence_refs: Vec<EvidenceRef>,
    risk_labels: Vec<PredictionRiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>
}
```

```rust
struct PredictionIntent {
    intent_id: Hash,
    initiator_id: PrincipalId,
    account_id: AccountId,

    venue_candidate_id: Hash,
    market_id: MarketRef,
    question: String,
    outcome: OutcomeRef,              // yes | no | candidate outcome
    side: TradeSide,                  // buy | sell
    price_limit: Decimal,
    shares: Decimal,
    max_loss: Money,
    max_payout: Money,

    resolution_source: ResolutionSourceRef,
    resolution_time: Timestamp,
    market_rules_hash: Hash,

    liquidity_snapshot: LiquiditySnapshot,
    risk_labels: Vec<PredictionRiskLabel>,

    policy_hash: Hash,
    grant_id: Option<Hash>,
    lease_id: Option<Hash>,
    revocation_epoch: u64,

    simulation_hash: Option<Hash>
}
```

### PredictionReceipt

```rust
struct PredictionReceipt {
    receipt_id: ReceiptId,
    prediction_intent_id: Hash,

    venue: VenueRef,
    market: MarketRef,
    outcome: OutcomeRef,

    side: TradeSide,
    price: Decimal,
    shares: Decimal,
    max_loss: Money,
    max_payout: Money,

    resolution_source: ResolutionSourceRef,
    market_rules_hash: Hash,
    resolution_ref: Option<ResolutionRef>,

    policy_checks: Vec<PolicyCheck>,
    risk_labels: Vec<PredictionRiskLabel>,

    execution_ref: ExecutionRef,
    result: ReceiptResult,

    agentgres_ref: Option<AgentgresRef>
}
```

## Risk Labels

Position and derivatives examples:

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

Event and prediction-market examples:

```text
Resolution Risk
Oracle / Source Risk
Ambiguous Criteria Risk
Manipulation Risk
Insider Information Risk
Low Liquidity
Wide Spread
Event Cancellation Risk
Jurisdiction Restricted
Venue Risk
Settlement Delay Risk
Correlated Outcome Risk
Agent Trading Disabled
Agent Trading Limited
Paper Only
```

## Agent Trading Policy

Agents must not receive open-ended perps, margin, leveraged-trading, or live
prediction-market authority by default.

Allowed agent-trading authority should be constrained by explicit policy:

- paper/sandbox mode by default;
- max collateral;
- max leverage;
- isolated margin only unless explicitly approved;
- required stop loss;
- max daily realized loss;
- market whitelist;
- expiry;
- step-up for new markets, added collateral, cross-margin, or leverage
  increases.

Prediction-market authority should use the same default-deny posture:

```text
default:
  agent may read markets only

paper/sandbox:
  agent may propose or simulate event exposure only

restricted live:
  max loss cap
  market-category allowlist
  no restricted politics, elections, sports, employer-related, or
  insider-risk markets unless policy explicitly allows them
  required resolution-source and market-rules disclosure
  lease expiry
  immediate revocation path
```

## Events and Receipts

Meaningful trade transitions should emit receipts:

```text
TradeCandidateReceipt
PredictionCandidateReceipt
TradeIntentReceipt
OrderReceipt
PositionReceipt
PositionRiskReceipt
PredictionIntentReceipt
PredictionReceipt
PredictionRiskReceipt
EventResolutionReceipt
PaymentReceipt
DisputeReceipt
```

## Conformance Checks

- Perps, margin, leverage, and position lifecycle must not be presented as
  ordinary spot exchange.
- Agent perps/margin authority must be denied by default or explicitly bounded.
- Prediction markets and event contracts must be presented as event exposure,
  not swaps.
- Agent live prediction-market authority must be denied by default or
  explicitly bounded.
- TradeCandidate and PredictionCandidate must include `CandidateEvidence`.
- Missing, expired, stale, unknown, unassessed, or conflicting candidate
  evidence cannot execute silently.
- TradeIntent must bind venue, market, side, collateral, leverage, margin mode,
  liquidation/funding assumptions, simulation, policy, risk labels, grant,
  lease, revocation epoch, and exact venue/order records.
- PredictionIntent must bind venue, market, question, outcome, side,
  price limit, shares, max loss, max payout, resolution source, market rules,
  liquidity snapshot, policy, risk labels, grant, lease, revocation epoch, and
  exact venue/order records.
- Position risk must remain visible after order execution.
- Prediction-market resolution state must remain visible until settlement or
  dispute resolution.

## Anti-Patterns

Reject these:

1. Treating `decentralized.trade` as a broker or custodian.
2. Hiding liquidation, funding, oracle, venue, or margin assumptions.
3. Giving agents unlimited trading authority.
4. Treating venue-native position state as Wallet canonical truth without
   receipts, policy status, and Agentgres refs.
5. Mixing low-risk swaps and high-risk leveraged positions in one approval
   class.
6. Treating prediction markets as swaps instead of event exposure.
7. Hiding resolution source, ambiguous criteria, insider-information, or
   manipulation risk.
8. Letting agents place live event bets without explicit max-loss, category,
   jurisdiction, and market-integrity policy.
9. Requiring the canonical Wallet user to visit `decentralized.trade` before
   Wallet can review, approve, execute, monitor, and receipt exposure.

## Related Canon

- [`README.md`](./README.md)
- [`exchange.md`](./exchange.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/api-authority-scopes.md`](../../components/wallet-network/api-authority-scopes.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
