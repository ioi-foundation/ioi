# wallet.network Product, Exchange, and Risk Doctrine

Status: canonical architecture product module.
Canonical owner: this file for wallet.network product doctrine, exchange
authority, route-source boundaries, asset exposure, protection actions,
approval inbox, user-facing wallet receipts, and wallet SDK events.
Supersedes: wallet product, swap, risk-center, and route-authority language
embedded only in prototypes or supporting product notes when it conflicts with
this file.
Superseded by: none.
Last alignment pass: 2026-06-12.

## Canonical Definition

**wallet.network is the user-facing authority wallet for autonomous finance.**

It is not merely a crypto wallet and not merely an IAM service. It lets users
and organizations hold assets, exchange assets, delegate bounded financial
authority, revoke authority, inspect risk, protect assets, and verify receipts.

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

This grammar applies to sends, receives, exchanges, approvals, delegations,
revocations, protection actions, secret brokerage, declassification, payment
authorization, and agent actions.

## Owns

wallet.network owns the authority and user-understanding path for wallet
actions:

- identity and account authority;
- policy evaluation;
- authority risk classification;
- asset, route, and security risk labeling;
- approval, denial, step-up, revocation, and emergency stop;
- exact intent binding for sends, exchanges, delegations, protection actions,
  capability exits, and agent actions;
- signing or denial of executable intents;
- user-facing and machine-verifiable wallet receipts;
- asset exposure records and protection recommendations;
- approval inbox state;
- wallet SDK events for authority, risk, route, receipt, and revocation changes.

## Does Not Own

wallet.network does not own:

- liquidity;
- DEX, bridge, or venue execution mechanics;
- quote APIs or solver networks;
- `decentralized.exchange` route proposals;
- chain execution or finality;
- Agentgres operational truth;
- IOI L1 settlement state;
- app-domain databases;
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
delegate
revoke
review
protect
```

The product surface may vary by app, mobile, extension, web, CLI, or enterprise
profile, but the action grammar and receipt semantics must remain stable.

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

`decentralized.exchange` is a preferred first-party route source and public
exchange surface. It may own its own route proposals, adapter registry,
pool-metadata normalization, route scoring, route-candidate receipts, and
decentralized-first comparison views.

It does not own:

- Wallet exchange actions;
- user authority;
- liquidity;
- execution;
- exchange truth;
- final settlement.

Correct product framing:

```text
Wallet Exchange is source-agnostic.
decentralized.exchange is the preferred decentralized route source.
```

Incorrect product framing:

```text
decentralized.exchange is the exchange backend for Wallet.
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
    source: RouteSourceRef,
    source_kind: RouteSourceKind,    // decentralized_exchange | direct_pool |
                                     // dex_router | bridge_router | solver |
                                     // quote_api | user_specified
    path: Vec<RouteHop>,
    expected_amount_out: Amount,
    min_amount_out: Amount,
    calldata_commitment: Hash,
    quote_hash: Hash,
    quote_expires_at: Timestamp,
    risk_labels: Vec<RiskLabel>,
    economics: ExchangeEconomics,
    route_receipt_ref: Option<ReceiptRef>
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
a blanket post-quantum safety wrapper for legacy chains
a receipt UI without machine-verifiable receipt binding
an app database for exchange history outside Agentgres-backed truth
```

Correct model:

```text
wallet.network owns exchange authority.
Wallet Exchange evaluates route candidates.
decentralized.exchange is a preferred, non-exclusive route source.
Liquidity lives in pools and venues.
Execution lives onchain or in the selected venue.
Agentgres records receipts and evidence.
IOI L1 anchors only selected public/economic commitments.
```

## Related Canon

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
