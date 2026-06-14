# decentralized.trade

Status: alpha canon architecture doctrine.
Canonical owner: this file for `decentralized.trade`, advanced trading and
exposure route boundaries, perps/position lifecycle doctrine, `TradeIntent`,
`PositionReceipt`, and agent-trading restrictions.
Supersedes: product prose that treats perps, margin, leverage, or strategy
execution as ordinary exchange routes.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

`decentralized.trade` is a preferred first-party trading route source and
advanced exposure-management surface.

It answers:

```text
I want exposure to price movement under defined risk.
What venue actions, orders, positions, or strategy candidates are available?
```

It may feel like an aggregator for perps, spot order venues, and position
management, but it is not a broker, custodian, venue, or Wallet authority
layer.

```text
decentralized.trade proposes exposure candidates.
wallet.network authorizes exact TradeIntent records.
Venues execute orders and maintain venue-native position state.
Wallet and Agentgres make authority, receipts, and risk state accountable.
```

## Owns

`decentralized.trade` may own or coordinate:

- trading venue adapters;
- order-ticket normalization;
- market discovery;
- venue comparison;
- position and risk display;
- margin and liquidation calculations;
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
- user positions as canonical Wallet truth;
- policy or compliance decisions;
- Agentgres receipt truth;
- IOI L1 settlement.

Correct framing:

```text
Wallet owns trade authority.
decentralized.trade proposes exposure routes and venue actions.
Venues execute and maintain venue-native position state.
```

Incorrect framing:

```text
decentralized.trade owns user positions.
Perps are just another exchange route.
Agents may trade leveraged products by default.
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

## Minimal Implementation Objects

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

## Risk Labels

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

## Agent Trading Policy

Agents must not receive open-ended perps, margin, or leveraged-trading
authority by default.

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

## Events and Receipts

Meaningful trade transitions should emit receipts:

```text
TradeCandidateReceipt
TradeIntentReceipt
OrderReceipt
PositionReceipt
PositionRiskReceipt
PaymentReceipt
DisputeReceipt
```

## Conformance Checks

- Perps, margin, leverage, and position lifecycle must not be presented as
  ordinary spot exchange.
- Agent perps/margin authority must be denied by default or explicitly bounded.
- TradeIntent must bind venue, market, side, collateral, leverage, margin mode,
  liquidation/funding assumptions, simulation, policy, risk labels, grant,
  lease, revocation epoch, and exact venue/order records.
- Position risk must remain visible after order execution.

## Anti-Patterns

Reject these:

1. Treating `decentralized.trade` as a broker or custodian.
2. Hiding liquidation, funding, oracle, venue, or margin assumptions.
3. Giving agents unlimited trading authority.
4. Treating venue-native position state as Wallet canonical truth without
   receipts, policy status, and Agentgres refs.
5. Mixing low-risk swaps and high-risk leveraged positions in one approval
   class.

## Related Canon

- [`README.md`](./README.md)
- [`exchange.md`](./exchange.md)
- [`../../components/wallet-network/product-exchange-risk.md`](../../components/wallet-network/product-exchange-risk.md)
- [`../../components/wallet-network/api-authority-scopes.md`](../../components/wallet-network/api-authority-scopes.md)
- [`../../components/agentgres/doctrine.md`](../../components/agentgres/doctrine.md)
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md)
