# wallet.network Product, Exchange, and Risk Doctrine

Status: canonical architecture product module.
Canonical owner: this file for wallet.network product doctrine, exchange
authority, route-source boundaries, advanced trade authority, position-risk
boundaries, asset exposure, protection actions, approval inbox, user-facing
wallet receipts, and wallet SDK events.
Supersedes: wallet product, swap, trade, risk-center, and route-authority
language embedded only in prototypes or supporting product notes when it
conflicts with this file.
Superseded by: none.
Last alignment pass: 2026-06-14.

## Canonical Definition

**wallet.network is the user-facing authority wallet and cockpit for autonomous
finance.**

It is not merely a crypto wallet and not merely an IAM service. It lets users
and organizations hold assets, exchange assets, delegate bounded financial
authority, revoke authority, inspect risk, protect assets, manage approved
trading exposure, and verify receipts.

The product grammar is:

```text
Action
-> simulation
-> risk labels
-> policy check
-> approval or denial
-> execution
-> receipt
```

This grammar applies to sends, receives, exchanges, advanced trades, approvals,
delegations, revocations, protection actions, secret brokerage,
declassification, payment authorization, and agent actions.

## Owns

wallet.network owns the authority and user-understanding path for wallet
actions:

- identity and account authority;
- policy evaluation;
- authority risk classification;
- asset, route, and security risk labeling;
- approval, denial, step-up, revocation, and emergency stop;
- exact intent binding for sends, exchanges, advanced trades, position changes,
  delegations, protection actions, capability exits, and agent actions;
- approval-mode selection for one-shot, session, batch, silent-within-policy,
  after-the-fact receipt, and step-up flows;
- reusable authority presentation profiles for embedded apps, Wallet surfaces,
  mobile approvals, CLI approvals, and advanced consoles;
- signing or denial of executable intents;
- user-facing and machine-verifiable wallet receipts;
- asset exposure records and protection recommendations;
- approval inbox state;
- wallet SDK events for authority, risk, route, receipt, and revocation changes.

## Does Not Own

wallet.network does not own:

- liquidity;
- DEX, bridge, or venue execution mechanics;
- trading venue mechanics;
- user positions as venue-native state;
- quote APIs or solver networks;
- `decentralized.exchange` route proposals;
- `decentralized.trade` venue proposals;
- chain execution or finality;
- Agentgres operational truth;
- IOI L1 settlement state;
- app-domain databases;
- the full user interface for every Web3/Web4 app;
- worker/service marketplace state.

## Wallet Product Surface Doctrine

Wallet must expose authority in user-understandable surfaces:

```text
Home
  assets, risk, active authority, recent receipts

Assets
  holdings, custody accounts, security assumptions, exposure

Exchange
  route-visible swaps with simulation, risk labels, fees, approvals, receipts

Trade
  advanced, eligibility-gated exposure management for spot orders, perps,
  prediction markets, event contracts, leverage, collateral, margin,
  liquidation, funding, resolution, and position receipts

Authority
  apps, agents, grants, policies, leases, revocation, emergency stop

Agents
  bounded financial authority for autonomous workers and outcome engines

Activity
  receipt-backed audit trail across sends, swaps, approvals, agent actions,
  revocations, protection actions, and policy changes

Risk
  asset exposure, route exposure, cryptographic posture, recommendations

Settings
  factors, recovery, networks, developer mode, org/team controls
```

Core actions:

```text
hold
send
receive
exchange
trade
delegate
revoke
review
protect
```

The product surface may vary by app, mobile, extension, web, CLI, or enterprise
profile, but the action grammar and receipt semantics must remain stable.

Wallet is the canonical user-facing cockpit for Exchange and Trade. The user
should be able to review, approve, deny, execute, monitor, and receipt exchange
or trade actions inside Wallet without first visiting `decentralized.exchange`
or `decentralized.trade`.

## Wallet Authority UX Model

Wallet's authority model generalizes beyond the Wallet console. The full Wallet
application is the high-trust financial and operator cockpit; it is not the
mandatory UI for every Web3/Web4 application.

Reusable model:

```text
Intent
  -> simulation
  -> risk and eligibility labels
  -> policy explanation
  -> approval mode
  -> execution handoff
  -> typed receipt
  -> revocation path
```

Generic object grammar:

```text
Subject
  user | account | agent | app | org | service

Capability
  what may be done

Object
  asset | credential | data | vote | message | position | workload | secret

Policy
  when, where, how much, by whom, for how long, and under which risk posture

Receipt
  what actually happened, under which policy, with which evidence
```

This keeps Wallet Web4-ready. Some apps have no assets at all; they may request
identity, credentials, posting rights, data-sharing rights, storage, compute,
votes, connector actions, or agent capabilities. Those apps should still use the
same authority grammar without inheriting the full finance console.

### Presentation Profiles

Wallet authority should be presented through three canonical profiles:

```text
Lite Approval Card
  Compact embedded or mobile-first review for games, social apps, consumer
  apps, and low-risk dapp sessions. It exposes approve, deny, revoke, and view
  receipt without pulling in the full Wallet console.

Standard Wallet Review
  The normal Wallet approval surface for sends, receives, swaps, delegations,
  revocations, protection actions, moderate-risk sessions, and agent
  permissions.

Advanced Authority Console
  Dense operator/developer/treasury/infra surface for trading, agents,
  Hypervisor, raw receipts, policy JSON, route candidates, adapter evidence,
  eligibility, traces, and org approvals.
```

Canonical invariant:

> **The Wallet authority pipeline is reusable infrastructure. The Wallet
> console is one presentation of that pipeline, not the universal dapp UI.**

### Approval Modes

Review-per-action does not scale. Wallet must support approval modes that
preserve authority while reducing modal fatigue:

```text
one_shot_review
  Approve or deny exactly one consequential action.

session_envelope
  Allow repeated actions inside explicit caps, resources, TTL, and revocation
  epoch.

batch_review
  Approve or deny many similar actions under one policy result and receipt
  bundle.

silent_within_policy
  Execute low-risk pre-authorized actions without interrupting the user, while
  still producing receipts.

after_the_fact_receipt
  Surface receipt after an action already allowed by an active session envelope.

step_up_review
  Require stronger authentication or human approval when an action exceeds the
  envelope, widens policy, touches secrets, exports data, moves funds, trades,
  or declassifies private workspace state.

denied
  Refuse execution and emit denial reason plus safer alternatives where known.
```

Approval modes must be policy-derived. Apps may request a mode, but
wallet.network decides whether that mode is allowed.

### Risk Coverage and Eligibility

Risk labels, eligibility labels, and authority risk are separate dimensions.

```text
Authority risk
  What kind of power is requested?

Technical / financial / operational risk
  What can go wrong?

Eligibility
  Is this user, account, jurisdiction, venue, app, or agent allowed?

Coverage state
  How well has this risk or eligibility claim been assessed?
```

Coverage states:

```text
Assessed
Unknown
Unassessed
Stale
Partially Covered
Conflicting Sources
```

Canonical invariant:

> **Absence of a risk label is never safety. Unknown, unassessed, stale, and
> conflicting-source states are explicit caution states.**

Every risk or eligibility label should carry:

```text
label
level
source
coverage_state
confidence
as_of
expires_at
evidence_refs
```

### Policy Explanations

Wallet policy must be explainable enough that users and developers know what to
change. Approval, denial, and step-up responses should include:

```text
decision
blocking_reasons
policy_refs
requested_action_summary
affected_assets_or_objects
risk_labels
eligibility_labels
required_changes
safer_alternatives
receipt_or_denial_ref
```

Example:

```text
Blocked because:
  agent live perps disabled
  requested leverage exceeds policy cap
  stop loss missing

To proceed:
  switch to paper mode
  lower leverage
  add stop loss
  request policy change through step-up
```

### Candidate Evidence and Adapter Trust

Route, venue, market, provider, connector, and app adapters are evidence
sources, not trust roots. They may return candidates and claims, but Wallet must
bind final approval to evidence it can inspect, simulate, or reject.

Candidate claims should include:

```text
source
adapter_id
observed_at
expires_at
contracts_or_venues
calldata_or_action_template
simulation_ref
risk_labels
eligibility_labels
coverage_state
evidence_refs
confidence
failure_conditions
```

Canonical evidence envelope:

```rust
struct CandidateEvidence {
    candidate_id: Hash,
    source: CandidateSourceRef,
    adapter_id: AdapterRef,
    observed_at: Timestamp,
    expires_at: Timestamp,
    coverage_state: RiskCoverageState,
    evidence_refs: Vec<EvidenceRef>,
    risk_labels: Vec<RiskLabel>,
    eligibility_labels: Vec<EligibilityLabel>,
    claims: Vec<CandidateClaim>
}
```

Wallet must treat stale, unknown, unassessed, conflicting-source, expired, or
evidence-missing candidates as caution or denial states. They cannot be silently
promoted into `ExchangeIntent`, `TradeIntent`, or `PredictionIntent`.

Canonical invariant:

> **Adapters propose. Wallet verifies, explains, approves or denies, executes
> only through authorized paths, and receipts what happened.**

## Exchange and Route Authority

Exchange is a first-class Wallet action.

wallet.network owns the **exchange authority path**:

- initiator identity;
- account authority;
- policy checks;
- asset, route, and security risk labels;
- step-up and approval;
- signing or denial;
- exchange receipts.

Wallet Exchange is source-agnostic. Route sources produce candidates; they do
not authorize execution.

Route candidates may come from:

- `decentralized.exchange`;
- direct pool adapters;
- DEX protocol routers;
- bridge routers;
- solver networks;
- RFQ systems;
- third-party quote APIs;
- user-specified routes.

No route source is a trust root.

Canonical invariant:

> **A quote is not authority. A route candidate is not approval. A final
> exchange becomes executable only after wallet.network binds route, calldata,
> slippage, simulation, policy, risk labels, grant/lease, revocation epoch, and
> user or agent approval into a receipt-backed intent.**

## Relationship to decentralized.exchange

`decentralized.exchange` is a preferred first-party route-intelligence engine
consumed by Wallet through API/RPC/SDK boundaries. It may own its own route
proposals, adapter registry, pool-metadata normalization, route scoring,
route-candidate receipts, route explorer, and decentralized-first comparison
views.

It does not own:

- Wallet exchange actions;
- user authority;
- liquidity;
- execution;
- exchange truth;
- final settlement.

Correct product framing:

```text
Wallet Exchange is the user-facing authority cockpit.
decentralized.exchange is a preferred decentralized route-intelligence engine.
```

Incorrect product framing:

```text
decentralized.exchange is the exchange backend for Wallet.
Users must leave Wallet and use decentralized.exchange directly to exchange.
```

## Relationship to decentralized.trade

`decentralized.trade` is a source-agnostic venue, market, and
exposure-intelligence engine consumed by Wallet through API/RPC/SDK boundaries.
It may own venue adapters, order-ticket normalization, market discovery,
prediction-market discovery, event-market and resolution-rule display,
position/risk display, margin calculations, strategy templates, venue
comparison, paper venues, and trade-candidate receipts.

It does not own:

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

Correct product framing:

```text
Wallet owns trade authority.
decentralized.trade proposes exposure, event-market, and venue-action
candidates.
Venues execute and maintain venue-native position state.
Wallet and Agentgres make authority, receipts, and risk state accountable.
```

Incorrect product framing:

```text
decentralized.trade owns the user's positions.
Perps are just another exchange route.
Agents may trade leveraged products by default.
Users must leave Wallet and use decentralized.trade directly to trade.
```

## Trade, Prediction, and Position Authority

Trade is a first-class but high-risk Wallet action. It is not the same product
surface as simple exchange.

```text
Exchange
  "I have X and need Y."
  Spot conversion, route risk, slippage, fees, and execution dependency.

Trade
  "I want exposure to price movement under defined risk."
  Venue, market, side, collateral, leverage, margin mode, liquidation,
  funding, stop-loss, take-profit, position lifecycle, and eligibility.

Prediction
  "I want exposure to an event outcome under defined risk."
  Venue, market question, outcome, price, shares, max loss, max payout,
  resolution source, market rules, liquidity, and eligibility.
```

Spot swaps can be ordinary Wallet actions when policy allows. Perps, margin,
leveraged trading, prediction markets, event contracts, strategy execution, and
ongoing position management must be quarantined as advanced actions with
separate risk labels, disclosures, receipts, and policy gates.

Canonical invariant:

> **A position is not a route. Leveraged or margined exposure must be approved
> as an exact TradeIntent with venue, market, collateral, leverage, margin mode,
> liquidation/funding assumptions, risk labels, policy, and receipt binding.**

> **A prediction is not a swap. Event exposure must be approved as an exact
> PredictionIntent with venue, market, outcome, max loss, max payout,
> resolution source, market rules, risk labels, policy, and receipt binding.**

Agent trading over perps, margin, or prediction markets is exceptional:

```text
default:
  agent may not trade perps, margin, or live prediction markets

paper/sandbox:
  agent may propose or simulate only

restricted live:
  max collateral
  max leverage
  isolated margin only unless explicitly approved
  market allowlist
  required stop loss
  max daily realized loss
  no adding collateral without step-up
  no new market without step-up
  no live event market without category allowlist and max-loss cap
  no restricted politics, elections, sports, employer-related, or
  insider-risk event markets unless policy explicitly allows them
  lease expiry
  immediate revocation path
```

## Canonical Exchange Flow

```text
user or agent requests exchange
  -> Wallet asks route sources for candidates
  -> route candidates return from decentralized.exchange, direct pools,
     aggregators, solvers, bridge routers, or user-specified paths
  -> Wallet evaluates price, slippage, fees, bridge exposure, contract risk,
     admin-key risk, oracle risk, cryptographic posture, policy compatibility,
     and simulation result
  -> Wallet selects or presents a route
  -> user, org, standing policy, or agent grant approves ExchangeIntent
  -> Wallet signs exact TxIntent(s)
  -> chain executes
  -> Wallet emits ExchangeReceipt
  -> Agentgres records receipt/evidence/outcome refs
  -> IOI L1 receives only selected public/economic/dispute commitments
```

## Canonical Trade Flow

```text
user or agent requests exposure
  -> Wallet opens a high-risk trade authority context
  -> decentralized.trade, direct venue adapters, order-book venues,
     perp venues, solver venues, or user routes return trade candidates
  -> Wallet evaluates eligibility, collateral, leverage, margin mode,
     liquidation estimate, funding, oracle/mark-price risk, venue risk,
     jurisdiction policy, agent authority, stop-loss, max-loss policy,
     and simulation result
  -> user, org, standing policy, or restricted agent grant approves TradeIntent
  -> Wallet signs exact venue/order/TxIntent records or denies execution
  -> venue executes and maintains venue-native position state
  -> Wallet/venue adapter monitors position risk and emits receipts
  -> Agentgres records receipt/evidence/outcome refs
  -> IOI L1 receives only selected public/economic/dispute commitments
```

## Minimal Implementation Objects

### ExchangeIntent

`ExchangeIntent` is the semantic wallet object above raw transaction calldata.
The user or agent does not approve a vague swap; they approve a specific,
policy-bound exchange intent.

```rust
struct ExchangeIntent {
    intent_id: Hash,
    initiator_id: PrincipalId,       // user | org | app | agent
    account_id: AccountId,

    from_asset: AssetRef,
    to_asset: AssetRef,
    amount_in: Amount,
    min_amount_out: Amount,
    quote_expires_at: Timestamp,

    route: RoutePlan,
    execution_mode: ExchangeMode,    // best_price | lowest_risk |
                                     // most_decentralized | no_bridges |
                                     // pq_preferred | user_specified

    policy_hash: Hash,
    grant_id: Option<Hash>,
    lease_id: Option<Hash>,
    revocation_epoch: u64,

    simulation_hash: Hash,
    risk_labels: Vec<RiskLabel>,
    user_disclosures: Vec<DisclosureRef>,
    economics: ExchangeEconomics,

    tx_intents: Vec<TxIntent>
}
```

### RouteCandidate

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
    evidence_refs: Vec<EvidenceRef>,
    economics: ExchangeEconomics,
    route_receipt_ref: Option<ReceiptRef>
}
```

### TradeIntent

`TradeIntent` is the semantic wallet object above raw order, venue, or calldata
execution. The user or agent does not approve vague market exposure; they
approve an exact, policy-bound trade intent.

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

    venue_intents: Vec<VenueIntent>,
    tx_intents: Vec<TxIntent>
}
```

### PositionReceipt

`PositionReceipt` is the user-facing and machine-verifiable record of position
state, risk, and policy status at a meaningful transition or checkpoint.

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

`PredictionIntent` is the semantic wallet object for prediction markets and
event contracts. It is a specialized trade authority object, not a swap.

```rust
struct PredictionIntent {
    intent_id: Hash,
    initiator_id: PrincipalId,
    account_id: AccountId,

    venue_candidate_id: Hash,
    market_id: MarketRef,
    question: String,
    outcome: OutcomeRef,
    side: TradeSide,              // buy | sell
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

`PredictionReceipt` is the user-facing and machine-verifiable record of an
event-market order, position, or resolution transition.

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

### TxIntent

`TxIntent` remains the low-level chain-execution object. `ExchangeIntent`
contains one or more `TxIntent` records for the final executable route.

Before signing, `TxIntent` must bind chain, account, target, calldata, nonce,
gas, policy hash, grant id, lease id, revocation epoch, slippage bounds, and
simulation hash.

### WalletReceipt

Wallet receipts are human-readable and machine-verifiable.

```rust
struct WalletReceipt {
    receipt_id: ReceiptId,
    receipt_type: ReceiptType,
    initiator_id: PrincipalId,
    account_id: AccountId,
    action_summary: String,

    request_hash: Hash,
    policy_hash: Hash,
    grant_id: Option<Hash>,
    lease_id: Option<Hash>,
    revocation_epoch: u64,

    risk_labels: Vec<RiskLabel>,
    policy_checks: Vec<PolicyCheck>,
    simulation_hash: Option<Hash>,

    execution_refs: Vec<ExecutionRef>,
    agentgres_ref: Option<AgentgresRef>,
    ioi_commitment: Option<L1CommitmentRef>,

    created_at: Timestamp,
    signatures: HybridSignatureBlock
}
```

User-facing receipt types include:

- `SendReceipt`;
- `ReceiveReceipt`;
- `ExchangeReceipt`;
- `TradeIntentReceipt`;
- `OrderReceipt`;
- `PositionReceipt`;
- `PositionRiskReceipt`;
- `PredictionIntentReceipt`;
- `PredictionReceipt`;
- `PredictionRiskReceipt`;
- `EventResolutionReceipt`;
- `ApprovalReceipt`;
- `DelegationReceipt`;
- `RevocationReceipt`;
- `AgentActionReceipt`;
- `StepUpReceipt`;
- `SecretExecutionReceipt`;
- `RiskEventReceipt`;
- `ProtectionReceipt`;
- `PolicyChangeReceipt`.

## Risk Label Taxonomy

wallet.network uses two distinct risk systems.

### Authority Risk Class

Authority risk class describes what kind of power is being requested:

```text
read
draft
local_write
external_message
commerce
funds
policy_widening
secret_export
identity_change
```

Authority risk drives policy, step-up, revocation, and grant requirements.

### Asset / Route / Security Risk Labels

Risk labels describe what assumptions an action, route, asset, account, or
venue depends on:

```text
PQ-Native
Hybrid / Signature-Agile
Legacy EC
Public Key Exposed
Bridge Exposure
Admin-Key Risk
Oracle Risk
Unknown / Unverified
Unlimited Approval
Route Risk Low
Route Risk Medium
Route Risk High
MEV Exposure
Solver Trust
Quote-Only Dependency
External Custody Dependency
```

Quantum and post-quantum labels must be accurate disclosures, not marketing
claims. Legacy-chain custody remains constrained by the legacy chain's own
cryptographic limits.

### Trade / Position Risk Labels

Trade risk labels describe the risk assumptions behind a market exposure,
event exposure, or position lifecycle:

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

Event and prediction-market labels:

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

Trade labels must be actionable. If a user sees liquidation, cross-margin,
funding, resolution, venue, manipulation, insider-information, or jurisdiction
risk, Wallet should also show the policy status and available protection,
reduction, close, revoke, report, or step-up actions.

## Asset Exposure Model

Each asset/account should have an exposure record:

```rust
struct AssetExposureRecord {
    exposure_id: Hash,
    account_id: AccountId,
    asset: AssetRef,
    chain: ChainRef,
    custody_account: AccountRef,

    cryptographic_regime: CryptoRegime,
    public_key_exposure: PublicKeyExposureState,
    bridge_dependencies: Vec<BridgeRef>,
    admin_key_dependencies: Vec<ContractRef>,
    oracle_dependencies: Vec<OracleRef>,
    approval_exposure: Vec<ApprovalExposure>,
    agent_access_exposure: Vec<GrantRef>,

    policy_protection_level: ProtectionLevel,
    risk_labels: Vec<RiskLabel>,
    recommended_actions: Vec<ProtectionActionRef>,
    updated_at: Timestamp
}
```

The user should be able to ask:

```text
What do I hold?
Which assets are legacy EC?
Which accounts have exposed public keys?
Which approvals are unlimited?
Which agents can touch which assets?
Which assets should be moved, protected, or policy-locked?
```

## Protection Actions

Risk labels must lead to action, not merely warnings.

wallet.network should support:

- revoke approval;
- reduce approval amount;
- move asset to fresh account;
- move asset to smart account with stronger policy modules;
- move or wrap into PQ-aware account where possible;
- set transfer threshold;
- require step-up for bridge exposure;
- require step-up for public-key exposure;
- isolate agent execution funds from long-term custody;
- freeze or pause agent grant access;
- require org quorum for higher-risk routes.

Each protection action follows the same action grammar and emits a
`ProtectionReceipt`.

## Approval Inbox

wallet.network should expose a unified inbox for pending authority decisions:

- step-up requests;
- policy-widening requests;
- exchange exceptions;
- trade exceptions;
- margin, leverage, or perps requests;
- position-risk escalation;
- bridge-use requests;
- unknown-contract requests;
- unlimited-approval requests;
- agent delegation requests;
- secret-release requests;
- declassification requests;
- high-value transfer requests;
- org quorum requests.

Each approval item must show:

- initiator;
- requested action;
- authority risk class;
- asset, route, and security risk labels;
- affected assets, accounts, secrets, or protected data;
- budget or amount;
- destination;
- policy diff;
- simulation result;
- liquidation, funding, margin, and position-risk summary when applicable;
- expiry;
- deny, edit, or approve actions.

## Exchange Economics Disclosure

For every exchange, Wallet must disclose:

- expected output;
- minimum output;
- slippage tolerance;
- pool fee;
- protocol fee, if any;
- wallet fee, if any;
- gas estimate;
- price impact;
- route source;
- quote source;
- execution venue;
- bridge fee and bridge finality risk, if any;
- solver/RFQ dependency, if any;
- MEV/protection mode, if any.

If Wallet charges a fee or spread, that fee must be explicit in the
`ExchangeEconomics` object and in the `ExchangeReceipt`.

## Trade Economics and Position Disclosure

For every advanced trade or position-affecting action, Wallet must disclose:

- collateral asset and amount;
- notional exposure;
- leverage;
- margin mode;
- order type;
- entry or trigger price;
- estimated liquidation price, if applicable;
- mark price and oracle source;
- funding rate snapshot, if applicable;
- venue fees;
- protocol or wallet fee, if any;
- withdrawal or settlement constraints;
- stop-loss and take-profit status;
- max-loss policy status;
- agent authority status;
- jurisdiction or eligibility status.

If any field is unavailable, stale, or venue-specific, the receipt and risk
panel must say so rather than pretending the position is fully knowable.

## Organization Authority

wallet.network supports personal, team, and enterprise authority profiles.

Org wallets require:

- members;
- roles;
- quorum rules;
- policy templates;
- approval chains;
- spend limits;
- emergency stop roles;
- audit/export permissions;
- separation between operator, approver, auditor, and agent owner.

Org approvals must bind who approved, which role or quorum satisfied policy,
what changed, and which receipt proves it.

## Compliance and Jurisdictional Policy Hooks

Compliance must be modeled as policy modules, not as Wallet's product identity.

Policy hooks may include:

- blocked assets;
- blocked jurisdictions;
- sanctions screening mode;
- unsupported derivatives, perps, leverage, or margin;
- travel-rule-style metadata where applicable;
- tax export;
- org audit export;
- risk acknowledgement logs.

Compliance outcomes must be recorded as policy checks and risk or denial
receipts where they affect execution.

## SDK Event Protocol

wallet SDKs should expose a stable event protocol for product surfaces, agent
runtimes, Hypervisor, marketplaces, and enterprise apps:

```ts
wallet.on("permission_requested", ...)
wallet.on("approval_required", ...)
wallet.on("exchange_route_ready", ...)
wallet.on("exchange_intent_created", ...)
wallet.on("risk_label_changed", ...)
wallet.on("asset_exposure_changed", ...)
wallet.on("protection_recommended", ...)
wallet.on("receipt_created", ...)
wallet.on("grant_revoked", ...)
wallet.on("step_up_required", ...)
wallet.on("emergency_stop", ...)
```

Events notify surfaces. They do not become authority by themselves.

## Admission / Settlement Boundary

Wallet receipts and authority artifacts become operational truth only when the
appropriate domain records them.

```text
wallet.network authority / receipt
  -> Agentgres operation, receipt index, evidence ref, or projection
  -> optional IOI L1 commitment by trigger
```

IOI L1 settlement is triggered only by public/economic/cross-domain needs such
as escrow, marketplace settlement, dispute, public registry, public proof, or
explicit user/org policy.

## Conformance Checks

A conforming Wallet Exchange path must prove:

- route source is not treated as authority;
- final approval binds an exact `ExchangeIntent`;
- each executable transaction is represented by exact `TxIntent` records;
- policy hash, grant/lease, revocation epoch, simulation hash, risk labels, and
  economics are bound into the receipt;
- route, fee, bridge, oracle, admin-key, and cryptographic risks are disclosed;
- high-risk route or policy changes trigger step-up;
- approval/revocation/emergency-stop invalidates stale executable intents;
- Agentgres receives exchange receipt/evidence refs when the exchange affects
  operational truth;
- IOI L1 receives commitments only when settlement triggers apply.

A conforming Wallet Trade path must prove:

- trade source is not treated as authority;
- final approval binds an exact `TradeIntent`;
- final approval binds an exact `PredictionIntent` for prediction markets or
  event contracts;
- venue, market, side, collateral, leverage, margin mode, order type,
  liquidation/funding assumptions, stop-loss, max-loss policy, and simulation
  are bound into approval and receipts where applicable;
- venue, market question, outcome, price, shares, max loss, max payout,
  resolution source, market rules, liquidity, and simulation are bound into
  prediction approval and receipts where applicable;
- perps, leverage, margin, prediction markets, event contracts, and position
  management are high-risk actions;
- agent live trading is denied by default or constrained by explicit policy;
- position state changes emit `OrderReceipt`, `PositionReceipt`, or
  `PositionRiskReceipt` when they affect user risk;
- prediction-market state changes emit `PredictionReceipt`,
  `PredictionRiskReceipt`, or `EventResolutionReceipt` when they affect user
  risk, settlement, or dispute posture;
- compliance, eligibility, and jurisdiction policy checks are represented as
  policy outcomes, not buried in UI text;
- Agentgres receives trade receipt/evidence refs when the trade affects
  operational truth;
- IOI L1 receives commitments only when settlement triggers apply.

## Anti-Patterns

Do not model wallet.network as:

```text
a centralized exchange
a single liquidity router
a mandatory dependency on decentralized.exchange
a place where route sources become approval
a product that hides route dependencies from users
a quote API trust root
a bridge-risk laundering layer
a perps broker hidden behind "swap"
an event-betting surface hidden behind "swap"
an agent-leverage machine with open-ended authority
an agent-prediction machine with open-ended authority
a blanket post-quantum safety wrapper for legacy chains
a receipt UI without machine-verifiable receipt binding
an app database for exchange history outside Agentgres-backed truth
```

Correct model:

```text
wallet.network owns exchange authority.
Wallet Exchange evaluates route candidates.
decentralized.exchange is a preferred, non-exclusive route source.
Wallet Trade evaluates exposure candidates.
decentralized.trade is a preferred, non-exclusive trading route source.
Liquidity lives in pools and venues.
Positions and execution live in chains or selected venues.
Prediction markets and event contracts live in selected venues and resolution
rules.
Agentgres records receipts and evidence.
IOI L1 anchors only selected public/economic commitments.
```

## Related Canon

- [`../../domains/decentralized/README.md`](../../domains/decentralized/README.md):
  decentralized.exchange and decentralized.trade route/venue-intelligence
  boundaries.
- [`../../domains/decentralized/exchange.md`](../../domains/decentralized/exchange.md):
  route-source and spot/cross-chain exchange doctrine.
- [`../../domains/decentralized/trade.md`](../../domains/decentralized/trade.md):
  advanced trading, exposure, perps, prediction markets, event contracts, and
  position lifecycle doctrine.
- [`doctrine.md`](./doctrine.md): wallet.network authority doctrine.
- [`api-authority-scopes.md`](./api-authority-scopes.md): low-level account,
  scope, approval, payment, exchange, exposure, receipt, and revocation APIs.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  action proposal, gate, execution, and receipt path.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): operational truth.
- [`../agentgres/artifact-ref-plane.md`](../agentgres/artifact-ref-plane.md):
  artifact and payload refs for evidence.
- [`../../foundations/ioi-l1-mainnet.md`](../../foundations/ioi-l1-mainnet.md):
  public/economic settlement triggers.
