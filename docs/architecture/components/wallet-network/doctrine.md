# wallet.network Authority Layer Specification

Status: canonical architecture authority.
Canonical owner: this file for wallet.network authority doctrine; wallet product, exchange, route-source, exposure, protection, approval-inbox, and receipt doctrine lives in [`product-exchange-risk.md`](./product-exchange-risk.md); low-level scope APIs live in [`wallet-network-api-and-authority-scopes.md`](./api-authority-scopes.md).
Supersedes: older generic capability-grant wording when it conflicts with `scope:*` authority grants.
Superseded by: none.
Last alignment pass: 2026-06-22.

## Canonical Definition

**wallet.network is the canonical Web4 authority layer: the identity, secret,
authority-scope, approval, payment, exchange-authority, training-data
permission, decryption-lease, and revocation control plane for autonomous
software.**

It owns identity, secrets, authority scope grants, session authority, approvals,
payments, revocation, and audit lineage. It is the authority wallet and control
cockpit for autonomous agents. It is not merely a crypto wallet.

Within canonical Web4, wallet.network is the machine-authority issuer and
revocation plane. It converts human, organization, domain, contract, and policy
intent into machine-readable authority requests, leases, denials, challenges,
spend limits, declassification decisions, data-use permissions, payment
authority, and revocation events.

## Core Doctrine

> **The Hypervisor Daemon runs autonomous work. Hypervisor App, Hypervisor Web,
> CLI/headless clients, optional TUI views, and application surfaces let humans
> operate it. Agentgres remembers and settles what changed. wallet.network
> decides what power workers are allowed to use.**

Put more sharply:

> **wallet.network authorizes power. It does not do the work, store the app, or
> become the chain.**

Product doctrine:

> **Agents do not get secrets. They get authority leases.**

Raw secrets, refresh tokens, provider credentials, key shards, decryption keys,
and BYOK provider keys remain brokered by wallet.network or approved authority
clients. Agents, workers, runtimes, connectors, and application surfaces receive
scoped, revocable, policy-bound leases with expiry, purpose, receipts, and
revocation paths.

Machine authority means a worker can prove what power it requested, what power
it received, under which policy, for what purpose, for how long, against which
resources, and with which receipts. It does not mean the worker holds raw
secrets or can widen its own scope.

## Autonomous Work Authority Gateway

For Hypervisor, wallet.network is the authority gateway for autonomous work.
It controls the user-visible and organization-visible decision path for:

```text
agent and worker identity
delegated authority
capability leases
connector and tool authority
approval queues
secret leases
spend limits
data-use permission
declassification
private workspace authority
provider and GPU spend
revocation and panic controls
policy simulation inputs
gateway decisions
risk labels
authority receipts
```

The gateway must be portable, revocable, policy-bound, receipted, and visible
across local, hosted, enterprise, cTEE/private-workspace, DePIN, cloud, model,
connector, marketplace, and domain-application routes.

This is how Web4 moves autonomous-work authority outside provider trust by
default. Model providers, cloud providers, connector providers, venues, and
managed services can perform work or expose capabilities, but wallet.network
keeps the authority lease, secret brokerage, step-up, revocation, and authority
receipt path outside provider custody unless policy explicitly accepts a
provider-trust route.

It may render as a Wallet console, embedded approval panel, mobile/passkey
step-up, CLI signer, enterprise authority service, or Hypervisor authority
panel. The presentation can vary; the authority contract cannot.

## Boundary Statement

wallet.network does not execute work, store app-domain operational truth, or
serve as the marketplace database. It may authenticate the user and release
bounded viewing/decryption authority for private user/app state, but the
state's canonical meaning remains in Agentgres refs and the encrypted bytes
remain in storage backends.

- Hypervisor Daemon executes work as the autonomous-execution hypervisor/control plane.
- Hypervisor App, Hypervisor Web, CLI/headless clients, optional TUI views, and
  Workbench, Automations, Foundry, Applications, Providers / Environments views,
  and domain surfaces request, approve, and inspect work as operator clients,
  application surfaces, and projections.
- Agentgres records operational state, runs, receipts, projections, delivery,
  and contribution accounting.
- IOI L1 settles registry, rights, escrows, bonds, disputes, and public
  commitments.
- wallet.network authorizes scopes, protects secrets, controls payments, and
  issues approval/session grants.

Authority receipts flow through the operational substrate:

```text
wallet.network authority receipt
→ Agentgres domain operation/evidence/delivery bundle
→ optional IOI L1 commitment when economically or security relevant
```

## What wallet.network Owns

wallet.network owns:

- user identity;
- authentication factors and account security posture;
- high-assurance guardian surfaces;
- MPC, threshold, hardware-backed, or organization key shards;
- low-assurance access-point bindings and step-up challenge policy;
- agent/app/domain authority grants;
- root secrets;
- API keys;
- OAuth refresh tokens;
- connector credentials;
- provider credential bindings;
- BYOK model provider keys;
- sealed archive decryption authority;
- cTEE guardian identity, key-share, and declassification authority;
- restore key leases;
- training-data access approvals;
- training artifact decryption leases;
- model-provider and GPU spend authority for training/evaluation jobs;
- Private Workspace node `AutonomyLease` grants;
- authority scope leases;
- approval tokens;
- session grants;
- policy envelopes;
- revocation epochs;
- payment authorization;
- exchange authority and exact exchange-intent approval;
- asset, route, and security risk disclosure for wallet actions;
- protection-action authority such as approval revocation, spend limits,
  account migration, and agent-fund isolation;
- panic/emergency controls;
- capability-exit signing and revocation for protected remote work;
- wallet CLI, MCP, SDK, mobile, web, embedded, and enterprise authority-client
  contracts;
- audit lineage.

## What wallet.network Does Not Own

wallet.network does not own:

- rich application state;
- workflow graphs;
- worker marketplace listings;
- service order operational state;
- full run traces;
- Agentgres projections;
- artifact payload bytes;
- model inference execution;
- training, benchmark, or evaluation execution;
- IOI L1 registry, settlement, or dispute state;
- sealed state archive bytes.
- liquidity, route proposals, quote truth, DEX/bridge execution mechanics, and
  chain finality.

## Worker Training Authority

Worker Training improves capability; it does not grant power. wallet.network
owns the authority path for training inputs and training side effects:

- access to private source documents, traces, examples, and corrections;
- permission to use data for training, evaluation, benchmark, or publication;
- permission to run DataRecipes over PolicyBoundDataViews;
- permission to use connector mappings against source systems and accounts;
- permission to publish or reuse DomainOntologies, ontology packs, canonical
  object models, and evaluation datasets when they contain governed material;
- decryption leases for sealed training datasets and artifacts;
- BYOK model-provider keys used by planner, generator, verifier, or trainer
  jobs;
- approval for remote GPU, hosted, DePIN, TEE, or customer-VPC training
  execution;
- payment approval for benchmark submissions, training compute, and service
  settlement.

Training archives should contain wallet.network secret refs and data-use refs,
not raw long-lived secrets. Reuse of training material must request the
appropriate authority scope again unless the original grant explicitly permits
reuse.

## Availability Profiles

wallet.network is the trusted authority plane. It may be always-on locally,
hosted, mobile-assisted, enterprise-managed, or wakeable depending on profile.

Examples:

- Hypervisor desktop may use a background local wallet authority service.
- Hosted workers may use delegated wallet authority with narrow standing
  grants.
- High-risk actions may require mobile/passkey/security-key step-up before
  sealed secret release, payment authorization, or policy widening.

## Sealed Archive Restore Authority

When Agentgres exports dormant or idle runtime state to a sealed archive,
wallet.network owns the restore authority path:

```text
restore requested
→ wallet.network verifies account/org/device/policy authority
→ scoped decryption key lease or sealed key release is granted
→ daemon/domain kernel decrypts archive in the approved environment
→ Agentgres records restore/import receipts
→ lease expires or is revoked
```

Archives should contain secret refs such as
`wallet.network://secret/openai-key`, not raw long-lived secrets, unless a
separately sealed exceptional policy explicitly permits it.

## Account Abstraction

User-facing onboarding should hide wallet complexity.

A user may create a wallet.network account through:

- Google;
- GitHub;
- passkey;
- Web3 wallet linking;
- email/OIDC provider;
- enterprise SSO.

A frictionless login creates a native wallet.network account with a Level 1 authority profile.

The external login is an authentication factor, not the root identity.

## Account Security and Authority Factor Taxonomy

wallet.network separates account access from authority. A user may enter through
a simple provider login, but consequential agent authority must pass through
policy, step-up, grant issuance, revocation semantics, and receipts.

Canonical terms:

```text
AuthFactor
  A credential or login method that helps authenticate the user or device.
  Examples: Google, GitHub, email/OIDC, enterprise SSO, passkey, Web3 wallet,
  TOTP. An AuthFactor is not an authority grant.

LowAssuranceAccessPoint
  A notification or initiation channel such as SMS, email, chat, voice, or
  webhook. It may carry a challenge pointer, but not grants, raw credentials,
  decryption keys, or durable authority.

GuardianSurface
  A high-assurance surface that can render an exact action, bind the request
  hash, and sign or approve the challenge. Examples: enrolled mobile device,
  passkey device, hardware key, local CLI signer, enterprise approval surface,
  or trusted Hypervisor/wallet app.

KeyShard
  Actual MPC, threshold, hardware-backed, or organization quorum key material.
  "Shard" is reserved for cryptographic or threshold authority, not ordinary
  provider login.

ProviderCredentialBinding
  A brokered OAuth refresh token, API key, wallet credential, model-provider key,
  cloud credential, or connector credential managed by wallet.network.

AuthorityGrant
  The scoped `grant://...` or lease object an agent, app, worker, service, or
  runtime receives. It is the only object that conveys power.
```

Google, GitHub, email, or enterprise SSO can bootstrap a wallet.network account
and satisfy low-risk access. They should not be sufficient by themselves for
funds, secret release, policy widening, persistent agent authority,
declassification, production deploys, high-value compute spend, or organization
administration.

TOTP is a supplemental factor and may raise confidence, but it is phishable and
must not be treated as a sovereign authority shard. Face ID, Touch ID, or other
biometrics are stronger when bound to passkey or secure-enclave assertions and
an enrolled device policy.

Out-of-band guardian approval should be available for high-risk actions. A QR,
push, or CLI challenge is only a transport; the security property comes from the
guardian surface displaying and signing the exact:

```text
subject
action
resources / destination
budget or amount
expiry
risk class
policy hash
request hash
```

The agent never receives provider tokens, OTP values, biometric results,
guardian secrets, raw key shards, or root session material. It receives only a
scoped grant, denial receipt, revocation epoch, or authority receipt.

## Frictionless-to-Fortress Security Ladder

### Level 1: Federated / Frictionless Account

- Google/GitHub/OIDC/Web3/email login;
- native wallet.network identity created automatically;
- low-risk authority scopes;
- managed recovery;
- limited autonomy.

### Level 2: Trusted Device / Passkey

- passkey;
- biometric assertion bound to an enrolled device;
- mobile approver;
- local wallet or Hypervisor app;
- higher risk limits;
- stronger approval flows.

### Level 3: Out-of-Band Guardian

- enrolled external device;
- QR, push, or CLI challenge over exact request hash;
- hardware key;
- local CLI signer;
- enterprise approval surface;
- persistent agent authority;
- funds, secrets, deploys, policy widening, and declassification.

### Level 4: Sovereign / Organization Vault

- MPC or threshold key shards;
- hardware-backed key shares;
- quorum or role-based organization approvals;
- high-value assets;
- high-value compute and production environments;
- policy widening;
- institutional autonomy.

## wallet.network Authority Surfaces

wallet.network may expose web, mobile, desktop, embedded Hypervisor panels, CLI,
SDK, MCP, enterprise authority service, and local signer surfaces. All surfaces
are clients of the same authority pipeline:

```text
intent
-> simulation / evidence
-> risk and eligibility labels
-> policy
-> step-up or denial
-> scoped grant / lease
-> execution handoff
-> receipt
-> revocation path
```

The wallet.network CLI is a local operator and signer surface. It may sign in,
link factors, enroll guardian devices, approve or deny challenges, inspect
grants, revoke leases, broker secret execution, and export receipts. It must not
become a second authority source.

The wallet.network MCP surface is an agent-facing authority request and receipt
surface. It may let agents request authority, check capability posture, create
approval requests, request policy-bound payments, inspect receipts, and request
revocation. It must not export raw secrets, reveal provider tokens, raw-sign
arbitrary payloads, raise limits, disable step-up, enroll guardians, or convert
authentication into authority without policy and receipts.

## Authority Scope Request Flow

```text
agent/runtime requests authority scope
→ wallet.network evaluates policy
→ if allowed, issues scoped authority grant/session/approval token
→ runtime executes operation without raw secret exposure where possible
→ receipt emitted
→ Agentgres records effect state/evidence
```

## Authority Scope Examples

```text
scope:model.openai.chat
scope:model.anthropic.messages
scope:gmail.read
scope:gmail.draft
scope:gmail.send
scope:calendar.create
scope:slack.post
scope:github.comment
scope:instacart.cart_create
scope:instacart.order_submit
scope:wallet.transfer_under_limit
```

## Risk Classes

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

Higher classes require stronger approval or security tier.

## Product, Exchange, and Risk Doctrine

Wallet's product doctrine is canonical, but separate from this authority-layer
doctrine to avoid turning the authority spec into a route router, exchange
backend, or app database.

See [`product-exchange-risk.md`](./product-exchange-risk.md) for:

- Wallet product surface doctrine;
- Exchange and Route Authority;
- relationship to `decentralized.exchange`;
- Trade, Prediction, and Position Authority;
- relationship to `decentralized.trade`;
- `ExchangeIntent`, `RouteCandidate`, `TradeIntent`, `PredictionIntent`,
  `PositionReceipt`, `PredictionReceipt`, `WalletReceipt`, and
  `AssetExposureRecord`;
- authority risk classes versus asset/route/security risk labels;
- protection actions;
- approval inbox;
- exchange economics disclosure;
- organization authority;
- wallet SDK event protocol.

Core invariant:

> **wallet.network owns exchange authority. Route sources produce candidates.
> Liquidity lives in pools and venues. Execution lives onchain or in the chosen
> venue. Agentgres records receipts and evidence. No quote or route source is a
> trust root.**

## Repository and Contract Boundary

The wallet.network product may live in its own application repository. That is
the preferred product boundary for rapid UI, website, design-system, mobile,
extension, and marketing iteration.

The wallet.network authority contracts must remain anchored in the IOI protocol
repository and exported outward. Product repositories consume the contracts;
they do not define authority truth.

```text
IOI protocol monorepo
  owns:
    Rust wallet.network types
    wallet.network service transition logic
    authority scope and receipt API doctrine
    `@ioi/wallet-protocol`
    `@ioi/wallet-sdk`
    OpenAPI / JSON Schema artifacts
    receipt fixtures and conformance tests

wallet-network product repo
  owns:
    Wallet app UI
    website/product surfaces
    design system
    screenshots and product prototypes
    app-specific frontend state
    fixture data only when clearly marked as non-authoritative
```

Current implementation anchors:

```text
crates/types/src/app/wallet_network/
  Rust authority/session/connector/secret/receipt object types.

crates/services/src/wallet_network/
  Native wallet.network service transition logic and validation.

crates/services/src/wallet_network/tests/
  Service-level wallet authority, lease, connector, receipt, and replay tests.

crates/cli/tests/wallet_network_session_channel_e2e/
  End-to-end session channel, lease, approval, secret injection, and mail
  capability tests.

scripts/conformance/hypervisor-conformance.mjs
  Cross-runtime conformance hooks for wallet.network authority boundaries.

packages/wallet-protocol/
  Versioned TypeScript protocol objects, method registry, JSON Schema,
  OpenAPI, fixtures, and package tests tied back to the Rust wallet anchors.

packages/wallet-sdk/
  Typed client helpers over wallet.network authority reviews, capability
  leases, receipts, and protocol method calls. The SDK imports
  `@ioi/wallet-protocol`; it does not author wallet authority semantics.
```

Package artifacts:

```text
@ioi/wallet-protocol
  Versioned protocol objects, method metadata, schemas, OpenAPI/JSON Schema,
  receipt fixtures, and canonical examples tied to IOI-owned contracts.

@ioi/wallet-sdk
  Typed client helpers over wallet.network APIs, receipts, grants, leases,
  exchange/trade intents, capability exits, and revocation.
```

The Rust `ioi_types::app::wallet_network` module and
`WalletNetworkService` remain the lower service/type anchors. The TypeScript
protocol and SDK packages are the distributable app/developer boundary over
those anchors. Product apps may mock Wallet flows, but they must not become the
source of truth for scopes, grants, leases, receipts, exchange/trade intents,
secret-release semantics, or capability-use policy.

## Marketplace Role

wallet.network authorizes:

- worker installation;
- worker authority grants;
- WorkerInvocation escrow;
- ContributionReceipt payment;
- UsageReceipt settlement;
- service escrow funding;
- ServiceOrder escrow;
- SLA bond approval;
- payment release;
- payout authorization;
- refund/dispute authorization;
- recurring worker standing orders;
- BYOK model calls;
- connector OAuth usage;
- policy widening;
- revocation/panic.

## Relationship to IOI L1

wallet.network may interact with IOI L1 for:

- gas payments;
- escrow funding;
- SLA bond posting;
- license/installation rights;
- payout acceptance;
- disputes;
- identity commitments.

wallet.network abstracts gas and payment complexity from the user.

IOI L1 is not the wallet database. IOI L1 stores registry, economic,
settlement, dispute, and sparse public commitments. wallet.network stores
authority state locally or in a secure authority deployment profile, and
Agentgres stores operational receipts and projections.

Private user/app metadata should follow the same boundary:

```text
wallet.network
  authenticates the user and grants viewing/decryption/mutation authority

Agentgres
  stores canonical refs, policy, receipts, state roots, and restore/import truth

storage backends
  store encrypted profile, preference, app-state, workspace, and service bytes

IOI L1
  stores selected public/economic commitments only
```

## Relationship to Agentgres

wallet.network emits authority artifacts:

```text
PolicyEnvelope
RootGrant
SubGrant
AuthorityScopeLease
ApprovalToken
RevocationEvent
SecretExecutionReceipt
StepUpReceipt
```

Agentgres records the effect of these in domain state, but does not own the raw secrets.

## Hypervisor Daemon / Guardian Profile Boundary

Public architecture names the execution boundary as the Hypervisor Daemon. A hardened
Guardian profile may exist inside that boundary for policy gates, attestation,
tool execution, and authority mediation.

```text
wallet.network ↔ Hypervisor Daemon / Guardian execution profile
```

The daemon requests authority scopes and receives bounded grants, approval
tokens, or operation-scoped secret execution. It does not become a key
custodian.

## Low-Assurance Access Points

SMS, email, chat apps, webhooks, voice bridges, and other low-assurance
messaging channels are notification and initiation rails. They are not guardian
surfaces and they are not wallet.network authority grants by themselves.

Low-assurance access points may:

- notify the user about blockers, status changes, candidate outputs, or pending
  approvals;
- wake, pause, resume, or steer an agent inside preconfigured low-risk bounds;
- start preapproved workflows under an existing `AutonomyLease`;
- carry a short-lived, single-use step-up challenge pointer.

They must not:

- decrypt private workspace state;
- declassify protected files, PII, strategy logic, private memory, credentials,
  or sealed outputs;
- receive durable keys, OAuth credentials, broker keys, or wallet secrets;
- approve funds, trades, deploys, secret export, policy widening, private
  workspace viewing, or other high-risk actions without step-up;
- be treated as the cTEE guardian or authority view.

The correct escalation path is:

```text
SMS or low-assurance channel receives blocker/approval notice
  -> user opens short-lived challenge link
  -> wallet.network, Hypervisor, enrolled guardian device, passkey,
     enterprise IdP, local app, or CLI signer authenticates the user
  -> exact action, risk, data, budget, recipient, and expiry are shown
  -> wallet.network issues a scoped grant or denial receipt
  -> daemon/agent continues using only the grant ref and receipt
```

An SMS reply such as `YES` may acknowledge or request a step-up flow, but it is
not sufficient authority for sensitive action unless a prior wallet policy
explicitly bound that exact low-risk command, risk ceiling, budget, expiry, and
recipient. Even then, it must not release protected plaintext or durable
secrets.

Canonical invariant:

> **Low-assurance access points can wake, steer, pause, and notify agents. They
> cannot decrypt, declassify, or authorize high-risk actions without step-up into
> wallet.network, Hypervisor, an enrolled guardian device, enterprise IdP, local
> app, CLI signer, or another high-assurance authority surface.**

## Runtime Privacy Profiles

wallet.network should support authority-release policy by runtime privacy
profile.

### Mutual Blind Profile

- no raw secrets;
- no final effects solely from untrusted execution;
- opaque, narrow, operation-scoped authority only;
- receipts must prove what was requested, released, used, and revoked.

### Private Workspace cTEE Profile

- rented hosted/provider/DePIN GPU nodes may stay online and run the daemon,
  Hypervisor Node shell, public inference, encrypted persistence, and redacted
  workspace work;
- Plaintext-Free Runtime Mounting exposes public/redacted context and private
  handles to the node for tools and models, while wallet-controlled authority
  decides key release, declassification, and capability exits;
- Candidate-Lattice Private Decoding is the default protected-agency path:
  rented nodes generate candidate lattices while wallet-controlled guardian,
  AlphaSeal, or private operators select, deny, declassify, or sign;
- Counterfactual Lattice Execution may spend additional public token volume to
  reduce online private-choice leakage when the wallet policy or leakage budget
  requires it;
- `CustodyProof` binds the custody derivation, mount graph, lattice commitments,
  receipts, leakage budget, and state roots for verifier-facing
  no-plaintext-custody claims;
- model routes that send sensitive plaintext to third-party APIs are
  provider-trust routes, not base cTEE no-plaintext-custody routes;
- wallet policy should require an `ExecutionPrivacyPosture` disclosure when a
  worker, service, or outcome engine may use third-party model APIs over private
  workspace data;
- the Cryptographic Operator Plane routes protected scoring, selection,
  retrieval, and policy checks through FHE/MPC/garbled/ORAM/local/threshold
  paths when public/redacted execution is insufficient;
- the authenticated authority surface is the default second logical party for
  private operators: browser/device session, mobile guardian, CLI signer,
  wallet.network policy/key path, or enterprise key service;
- managed non-colluding committees are optional escalation paths for higher
  assurance or unattended enterprise workflows, not the ordinary user-facing
  topology;
- protected classes such as PII, strategy source, broker keys, live portfolio
  state, private memory, and final action logic are not released as plaintext to
  the provider-rooted node by default;
- `AutonomyLease` grants define what the node may do while the user is offline;
- the cTEE authority view, implemented by wallet.network, authenticated
  browser/device session, local Hypervisor, CLI signer, customer authority
  service, mobile approval path, or threshold committee, participates in key
  release, private-head selection, declassification, and capability exits;
- `ModelMountReceipt`, `PrivateInferenceReceipt`,
  `CounterfactualLatticeReceipt`, `PrivateOperatorReceipt`,
  `DeclassificationReceipt`, capability-exit receipts, and
  deterrence/detection receipts prove what was mounted, computed, privately
  operated, revealed, denied, signed, watermarked, or canary-checked.

### Enterprise Secure Profile

- TEE or equivalent attestation required before sealed secret or authority
  release;
- authority release binds to code identity, request hash, policy hash, expiry,
  and revocation epoch;
- Agentgres records the resulting authority and execution receipts.

## Private Workspace Authority

For Private Workspace backed by cTEE, wallet.network owns the authority
membrane that keeps a persistent rented GPU useful without making it the
plaintext custody workspace.

wallet.network controls:

- authority-view identity and quorum policy;
- key shares, masks, decryption leases, viewing keys, and revoke/panic state;
- `AutonomyLease` creation, renewal, narrowing, and revocation;
- declassification policy for protected outputs;
- action limits for broker, API, payment, message, deploy, or connector exits;
- step-up rules for widening risk, disclosing private material, or exporting
  protected memory.

The default flow is:

```text
Private Workspace node produces protected output commitment
  -> Agentgres records refs and private-inference receipt
  -> wallet.network checks AutonomyLease, policy hash, risk, and revocation
  -> authority view decrypts, reconstructs, selects, or denies if allowed
  -> declassification gate approves, denies, or escalates
  -> capability exit signs only bounded actions
  -> DeclassificationReceipt and capability-exit receipt are recorded
```

wallet.network must not release durable raw broker keys, unrestricted OAuth
tokens, strategy source, live portfolio plaintext, full private memory, or root
secrets to a root-controlled rented node. The node may receive opaque,
operation-scoped capability exits and encrypted or masked state under policy.

## Cryptography Positioning

The target profile is hybrid classical + post-quantum authority, not a blanket
claim that every connected legacy system becomes post-quantum safe.

Appropriate claims:

- hybrid signatures for policy envelopes, grants, and approval records;
- hybrid KEM for control-plane handshakes;
- authenticated encryption such as XChaCha20-Poly1305 for vault storage;
- legacy-chain custody remains constrained by the legacy chain's own
  cryptographic limits.

## Anti-Patterns

Do not model wallet.network as:

```text
the execution runtime
the application database
the worker marketplace
the Agentgres state store
the L1 settlement chain
a place where agents receive raw root secrets
a place that releases plaintext alpha or PII to a rented GPU because the node
passed a boot measurement
a centralized exchange
a single liquidity router
a mandatory dependency on decentralized.exchange
a broker or custodian for decentralized.trade
a place where perps, margin, leveraged positions, prediction markets, or event
contracts are treated as ordinary swaps
a place where agents get open-ended trading authority by default
a place where route candidates become approval
a quote API trust root
a blanket post-quantum safety wrapper for legacy chains
a generic login provider with no autonomous-work semantics
a blanket claim that legacy systems become post-quantum safe
```

Correct model:

```text
wallet.network owns authority, secrets, approvals, payment scopes,
decryption leases, revocation, and audit lineage
daemon executes work
Agentgres records operational truth
IOI L1 settles public/economic commitments
```

## Related Canon

- [`product-exchange-risk.md`](./product-exchange-risk.md): Wallet product,
  exchange, route-source, risk, protection, approval-inbox, and receipt doctrine.
- [`api-authority-scopes.md`](./api-authority-scopes.md): scope API and grant
  shapes.
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md):
  daemon-executed action proposal, gate, and execution path.
- [`../daemon-runtime/private-workspace-ctee.md`](../daemon-runtime/private-workspace-ctee.md):
  Private Workspace backed by cTEE, persistent private nodes, `AutonomyLease`,
  declassification gates, and private strategy execution.
- [`../daemon-runtime/api.md`](../daemon-runtime/api.md): action mediation and
  approval API.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): where authority
  outcomes become operational truth.
- [`../../foundations/security-privacy-policy-invariants.md`](../../foundations/security-privacy-policy-invariants.md):
  broader security and policy invariants.

## Non-Negotiables

1. Agents never receive raw root secrets.
2. Apps and runtimes are authority clients, not key custodians.
3. Policy widening requires step-up.
4. Sensitive actions bind to exact request hash, policy hash, scope, expiry, and revocation epoch.
5. Panic/revocation must kill active grants.
6. BYOK keys live in wallet.network, not workflow node configs.
7. Agent execution accounts are not default for every agent; they are required
   only when the agent needs on-chain execution power.
8. High-risk on-chain actions require wallet.network step-up and/or
   smart-account module enforcement.

## One-Line Doctrine

> **Do not make users create a wallet. Let them create an account that can grow into a vault.**

## wallet.network Product Context Module

The following module carries detailed wallet.network v3.2 product-spec context
from the former `docs/specs/wallet_network.md`. It is supporting context, not a
parallel architecture variant. Where deployment availability, Hypervisor Daemon /
Guardian-profile naming, Agentgres receipt sinks, IOI L1 commitments, runtime
privacy modes, marketplace settlement, or hybrid-cryptography claims differ,
update this module to follow the canonical doctrine above.

---

# 📑 Product Specification: wallet.network (The Sovereign IAM Hub)

**Version:** 3.2 (Frictionless-to-Fortress Architecture, Superset Custody & Zero-Trust Extensibility)
**Target:** Desktop (Primary), Browser Extension (Bridge), Mobile (Notifier / Approver)
**Core Philosophy:** **“Security tolerance is defined by the user. The Vault owns both assets and agency.”**
**Positioning Note:** Treat **`wallet.network`** as a **foundational Identity & Access Management (IAM) control plane and native Web4 Custodian** — not just a wrapped app. Wrapped apps/agents are **clients** of wallet capabilities and are **never key custodians**.

---

## 0. System Model & Boundaries

### 0.1 The IOI Ecosystem (Non-Negotiable Separation)

1.  **`wallet.network` = Foundational Control Plane**
    *   Trusted, stateful, profile-based availability.
    *   Owns root secrets, dual-entropy mnemonic, hybrid asset custody, session authority, policy enforcement, audit lineage, and approvals.
2.  **External Domains & Connectors = Permissionless Capability Clients**
    *   **First-Party Platforms:** `sas.xyz` (Supply/Developers) and `aiagent.xyz` (Demand/Marketplace).
    *   **Third-Party Platforms:** Any external dApp or enterprise dashboard can integrate the `wallet-sdk` to programmatically request Session Keys and agentic authority scopes.
    *   **Extensible Connectors:** Swappable provider adapters (e.g., Stripe, custom local banks). Third-party code runs in strictly isolated WASM sandboxes to preserve Vault invariants.
3.  **Wrapped Apps / Agents = Ephemeral Execution**
    *   Ephemeral/untrusted by design.
    *   Receive **scoped authority tokens**, never raw secrets or custodial keys.

### 0.2 Practical Code Boundary (Recommended Modules)

1.  **`wallet-core`**
    *   Vault database + encryption (`dcrypt`), dual-entropy derivation, MPC shard management, policy engine, sessions, approvals, attestations, audit log.
2.  **`wallet-connector-*`**
    *   Provider OAuth + API adapters; token brokerage; provider-specific schemas.
3.  **`wallet-sdk`**
    *   Client library for external domains, wrapped apps, Hypervisor Workbench / Workflow Compositor surfaces, marketplace clients, and agent harness adapters to request capabilities and handle receipts/errors.
4.  **UI shells**
    *   Desktop/Extension/Mobile — all consume the same core API and policy semantics.

---

## 1. Executive Summary

**`wallet.network`** is the **Web4 Authority Layer** for the decentralized internet. It abandons the rigid "One-Size-Fits-All" Web3 onboarding model. Instead, it scales dynamically from a frictionless Web2-style "Sign in with Google" experience up to an institutional "hybrid classical + post-quantum authority profile," based entirely on the user's risk appetite.

It functions as a secure **Cryptographic Superset** that manages the pillars of agentic operation:

1.  **Native Hybrid Custody:** Natively holds legacy assets (ETH/SOL) and Web4 authority assets such as service licenses, ServiceOrder escrow positions, SLA bonds, work credits, and receipt-backed claims.
2.  **Session Authority:** Issuing bounded, automated permissions so agents can operate without constant human clicks.
3.  **Secret Injection (and Authority-Scope Execution):** Securely storing non-blockchain credentials (API keys, OAuth tokens) and injecting them via policy. The AI model never sees the raw secret.
4.  **Future-Proof Identity:** Establishing a **hybrid classical + post-quantum** root of trust while bridging to legacy EOAs.
5.  **Policy-Locked Autonomy + Recursive Delegation:** Humans approve power (policy); agents spend power (sessions) and may re-delegate downward (sub-grants) without expanding scope.

### 1.1 Value Proposition
*   **For Users:** “The last wallet you’ll ever need. Hybrid classical + post-quantum authority for your assets, and Sovereign IAM for your AI workforce.”
*   **For Developers:** “A unified, extensible interface for secrets, sessions, and safety policies—across all providers.”
*   **For the Network:** “The enforcement point for the IOI Safety Sandwich: deterministic policy + cryptographic audit + safe autonomy.”

---

## 2. Architecture: The Superset Identity Stack

### 2.1 The Hybrid Asset & Agency Custody Stack

`wallet.network` operates as a Cryptographic Superset. Because it implements the **Dual-Entropy Mnemonic** (deriving both classical and lattice-based keys from one master seed), it natively manages both static asset ownership and dynamic autonomous agency.

| Custody Domain | Managed By | Cryptography (via `dcrypt`) | Assets / Artifacts Held |
| :--- | :--- | :--- | :--- |
| **Legacy Web3 Assets** | `wallet.network` (Native) | **Classical:** `secp256k1` / `Ed25519` | ETH, SOL, ERC-20s, standard NFTs. |
| **Web4 Native Assets** | `wallet.network` (Native) | **Hybrid Sigs:** `Ed25519` + `ML-DSA-44` | Service licenses, ServiceOrder escrows, SLA bonds, work credits, receipt-backed claims. |
| **Agentic Authority** | `wallet.network` (Vault) | **Hybrid KEM & Sigs** | Session Keys, ApprovalTokens, Policy Envelopes. |

### 2.2 The "Frictionless-to-Fortress" Authority Tiers

Users configure authority policy based on risk appetite, but the canonical split
above still applies: authentication factors are not authority grants, guardian
surfaces approve exact request hashes, and key shards are actual threshold or
cryptographic authority material.

*   **Level 1: Federated / Frictionless:** Google OIDC, GitHub, email/OIDC, enterprise SSO, Web3 sign-in, or similar providers may bootstrap a native wallet.network account and low-risk authority posture. A provider login is not a shard and cannot authorize high-risk agent power by itself.
*   **Level 2: Trusted Device / Passkey:** Passkeys, enrolled devices, and secure-enclave-backed assertions may satisfy stronger step-up. TOTP is supplemental and phishable. Biometrics count only when bound to an enrolled device/passkey assertion; they are not standalone authority.
*   **Level 3: Out-of-Band Guardian:** Enrolled mobile, hardware key, enterprise approval surface, trusted Hypervisor/wallet app, or local CLI signer displays the exact subject, action, resources, budget, expiry, policy hash, and request hash before approval.
*   **Level 4: Sovereign / Organization Vault:** MPC, threshold key shards, hardware-backed shares, role/quorum approval, and institutional policies secure high-value assets, production authority, high-value compute, policy widening, and persistent agent autonomy.

### 2.3 The "Link and Upgrade" Web3 Bridge

We do not let legacy Web3 wallets (MetaMask) *be* the Web4 identity, to avoid inheriting legacy cryptographic vulnerabilities. Instead, we use them as Onboarding Factors and Liquidity Sources.
1.  **Native Generation:** `wallet.network` *always* generates a native, hybrid classical + post-quantum Web4 identity upon account creation.
2.  **Web3 Sign-In (SIWE):** Users can click "Connect MetaMask" to cryptographically link their legacy `0x...` address to the new Web4 identity as an authentication factor.
3.  **Liquidity Bridging:** Users can grant their native Web4 identity an allowance to trade funds held in their Web3 cold storage via ERC-4337 Smart Accounts (See Appendix A).

### 2.4 The Sovereign Vault (Control Plane Database)

A local, encrypted database that stores what EOAs cannot:
*   **Secrets:** API keys, refresh tokens, connector credentials, private service keys.
*   **Policy Commitments:** Signed, versioned policy envelopes that define the boundaries of autonomy.
*   **Sessions & Grants:** Ephemeral keys/tokens granted to specific agents for specific scopes and durations.
*   **Audit Lineage:** Cryptographically linked log of approvals, grants, interceptions, and authority-scope executions.

### 2.5 Integration with IOI Kernel (Hypervisor Daemon / Guardian Profile Link)

The Vault communicates directly with the local **Hypervisor Daemon / Guardian execution profile** over **mTLS**.
*   **Handshake (App-Layer):** While transport is mTLS, `wallet-core` and Hypervisor Daemon / Guardian profile performs an additional **application-layer hybrid KEM handshake** (X25519 + ML-KEM-768) to derive session secrets. This prevents "harvest-now, decrypt-later" attacks even if the TLS layer is compromised or recorded.
*   **Inbound:** Receives `FirewallInterception` events when an agent hits a policy gate or step-up trigger.
*   **Outbound:** Issues:
    *   `ApprovalTokens` (action-bound, scoped, replay-resistant)
    *   Injected secrets (as ephemeral, operation-scoped releases)
    *   Session grants and sub-grants
    *   Policy updates and revocations

---

## 3. Autonomy Model: Policy-Locked Power, Session-Spent Autonomy

### 3.1 “Humans Approve Power; Agents Spend Power”

The system is designed so autonomy is safe and scalable:
*   **Humans** approve a **Policy Envelope** (capabilities + constraints).
*   **Agents** run autonomously within that envelope using short-lived sessions.
*   **Policy changes** (widening scope, raising limits, adding connectors) require step-up human approval based on the user's configured Auth Tier.
*   **Delegation** is allowed only as **monotonic narrowing** (no privilege inflation).

### 3.2 Grants: Root Grants and Recursive Sub-Grants

**RootGrant**
*   Issued by `wallet-core` after onboarding and step-up approval.
*   Includes: allowed authority scopes, explicit constraints (amount caps, domains, recipients, categories), TTL / renewal policy, and delegation rules (max depth, issuance budget).

**SubGrant (Agent → Agent)**
*   Minted by an agent only if:
    *   `SubGrant.scope ⊆ ParentGrant.scope`
    *   `SubGrant.limits ≤ ParentGrant.limits`
    *   `SubGrant.expiry ≤ ParentGrant.expiry`
    *   Delegation depth/budget is not exceeded.

### 3.3 Step-Up Triggers (First-Class Policy Clauses)

Step-up requirements are explicit, not ad-hoc. Examples:
*   New connector onboarding / new destination domain.
*   Action > configured caps (daily spend, per-tx threshold, volume anomaly).
*   Exporting, revealing, or “raw secret access”.
*   Any **policy envelope widening**.

When triggered:
1.  Hypervisor Daemon / Guardian profile blocks the action.
2.  `wallet.network` notifies Desktop/Mobile.
3.  User approves with their configured authentication threshold (e.g., passkey/biometric/security key).
4.  Vault issues an action-bound `ApprovalToken`.
5.  Hypervisor Daemon / Guardian profile resumes and records the receipt.

### 3.4 Core Data Models (Schema Definition)

To ensure interoperability and security, the following fields are mandatory for Grant and Policy structures:
*   `issuer_id`: Vault Identity (Hybrid Public Key)
*   `subject_id`: Agent / App Identity (or Ephemeral Key)
*   `policy_hash`: Cryptographic commitment to the governing policy logic
*   `policy_version`: Monotonically increasing integer
*   `authority_scope_set`: List of allowed actions (e.g., `['email:send', 'twitter:post']`)
*   `constraints`: Parameter limits (e.g., `{'max_usd': 50, 'allowlist': [...]}`)
*   `delegation_rules`: `{'max_depth': 2, 'can_redelegate': true}`
*   `expiry`: Unix timestamp (Absolute)
*   `revocation_epoch`: Minimum valid epoch (allows bulk revocation)
*   `signatures`: **Hybrid Signature Block** (Must contain both Ed25519 and ML-DSA signatures)

---

## 4. User Experience (UX) Flows

### 4.1 Progressive Onboarding ("Start Simple, Secure Later")

1.  **The Hook:** User clicks "Login" on a Web4 interface (`aiagent.xyz` or `sas.xyz`).
2.  **Auth Choice:**
    *   *Path A (Web2 Native):* "Sign in with Google." A native wallet.network identity is created with low-risk authority posture. Provider login is an auth factor, not a shard or grant.
    *   *Path B (Web3 Native):* "Connect MetaMask." Web4 identity is generated and cryptographically linked to the EOA via SIWE.
3.  **Security Upgrades:** Inside the Vault dashboard, user adds passkeys, enrolled guardian devices, hardware keys, local CLI signer, MPC/key shards, or organization quorum policies to unlock higher limits and institutional autonomy.

### 4.2 Marketplace Flow (Delegating Agency)

1.  **Discovery:** User selects “Hedge Fund Agent” on `aiagent.xyz`.
2.  **Delegation (Handoff):**
    *   Marketplace requests: “Needs 24h session + Twitter authority scope.”
    *   `wallet.network` prompts: *“Authorize ‘Hedge Fund Agent’ to run for 24h under Policy Envelope X?”*
    *   User approves via configured tier (e.g., passkey/phone/biometric).
3.  **Autonomy:** Agent runs continuously without repeated prompts, strictly within policy and spend caps.

### 4.3 Human-in-the-Loop Intercept (Step-Up)

1.  **Trigger:** Agent hits a step-up clause.
2.  **Notification:** `wallet.network` alerts Desktop/Mobile.
3.  **Resolution:** User approves on phone.
4.  **Resume:** Vault issues a one-time, action-bound `ApprovalToken`.

### 4.4 Emergency Controls (Panic + Revocation)

*   **Panic Button:** Instantly revoke all sessions and freeze delegation.
*   **Connector Kill Switch:** Revoke connector tokens and rotate refresh tokens.
*   **Policy Freeze:** Lock envelopes to “deny except allowlisted” mode.

---

## 5. Software Modules

### 5.1 `wallet-core` (The Vault Control Plane)

*   **Role:** Always-on local server for user agency.
*   **Implementation:** Pure Rust, `forbid(unsafe_code)` via `dcrypt` library for high assurance.
*   **Responsibilities:**
    *   Vault encryption, dual-entropy derivation, MPC shard management.
    *   Policy engine and envelope commitments.
    *   Session issuance and delegation verification.
    *   Approvals, step-up gating, revocation.
    *   Attestation verification (Hypervisor Daemon / Guardian profile + sensitive executors).
    *   Audit log: immutable, hash-linked lineage.

### 5.2 `wallet-connector-*` (Provider Adapters)

*   **Role:** Modular OAuth + API adapters (gmail/outlook/stripe/etc).
*   **Responsibilities:** OAuth flows, refresh token storage, access token minting, token brokerage (short-lived access tokens and operation-scoped authority), provider schema normalization.

### 5.3 `wallet-sdk` (Client Capability Interface)

*   **Role:** Used by wrapped apps, Hypervisor Workbench / Workflow Compositor surfaces, marketplace clients, and agent harness adapters.
*   **Responsibilities:** Request capabilities and sessions, handle interception/step-up responses, enforce “no raw secret visibility” in the client API design.

### 5.4 UI Shells

*   **`wallet-desktop` (Primary):** Tauri + React + Rust. Background/tray service, secret management, policy graph, audit feed, local approvals fallback.
*   **`wallet-extension` (Bridge):** Chrome Extension (Manifest V3). **Crypto Role:** Uses `dcrypt` WASM bindings *only* for request integrity, local pairing, and channel encryption to the desktop. **Constraint:** The extension is a relay and UI surface; it **never** holds vault DEKs/KEKs or decrypts secrets directly.
*   **`wallet-mobile` (Notifier / Approver):** React Native / Native. Push notifications for gates, passkey/enrolled-device approval signing, biometrics only when bound to device policy, panic + revocation controls.

### 5.5 Zero-Trust Extensibility Framework (Open Ecosystem)

To ensure `wallet.network` serves as a universal standard, it supports programmatic extensibility bounded by zero-trust architecture.

**5.5.1 Permissionless Domain Integration (The "WalletConnect" of Agency)**
Any third-party platform can integrate `wallet.network` using `wallet-sdk`.
*   **Standardized Handshake:** Domains submit a `CapabilityRequest` specifying requested scopes, limits, and TTL.
*   **Origin Isolation:** The Vault cryptographically verifies the domain's origin to prevent phishing.
*   **No Ambient Authority:** Third-party domains **never** receive root keys or raw secrets; they receive ephemeral `SessionKeys` mapped specifically to their requested task.

**5.5.2 Sandboxed Connector Marketplace (Third-Party API Adapters)**
Developers can publish new API connectors without compromising Vault security.
*   **Declarative Schemas:** Connectors must adhere to the Canonical Connector Manifest (Whitepaper Appendix F).
*   **WASM Isolation (WASI):** Custom connector logic is compiled to WebAssembly. `wallet-core` executes them within a hermetic sandbox.
*   **Data Siloing:** The WASM sandbox is injected *only* with the specific secret required for that connector. It has zero memory access to the rest of the Vault's encrypted database.

---

## 6. Security & Cryptography (Strict Hybrid Model)

### 6.1 Hybrid Security Model (Classical + hybrid classical + post-quantum)

We utilize the `dcrypt` library to implement a "Hybrid" model.

*   **Data Confidentiality at Rest (Symmetric):**
    *   **Algorithm:** **XChaCha20-Poly1305** (Pure Rust).
    *   **PQ Resilience:** Achieved via 256-bit key space (resists Grover's Algorithm) and robust KDFs.
    *   **Note:** We expressly do **not** use PQC (ML-KEM/ML-DSA) for database encryption, as they are asymmetric primitives unsuited for bulk storage.
*   **Control Plane Signaling (Hybrid KEM):**
    *   **Algorithm:** **X25519 + ML-KEM-768**.
    *   **Usage:** Application-layer handshake to establish session keys between Vault, Hypervisor Daemon / Guardian profile, and agents.
    *   **Benefit:** "Harvest now, decrypt later" protection.
*   **Identity & Policy (Hybrid Signatures):**
    *   **Algorithm:** **Ed25519 + ML-DSA-44**.
    *   **Verification:** Default verification requires **both** signatures for high-stakes Web4 artifacts. Compatibility mode may accept either only with explicit policy flag and prominent audit marking.

### 6.2 Threat Model (Practical Guarantees)

**Goal:** Protect secrets against stolen device, offline disk exfiltration, and rollback attacks.
**Non-Goal / Reality:** A fully compromised, active host (root access) can attempt impersonation and memory scraping.
*   **Mitigation:** We mitigate by minimizing plaintext exposure, never exporting raw secrets, enforcing short-lived grants, requiring out-of-band step-up, and executor attestation.
*   **Role of Memory Safety:** Using memory-safe Rust (`dcrypt`) reduces the risk of *bug-class exploits* (buffer overflows) allowing an attacker in, but it is not a substitute for host isolation.

### 6.3 Vault Encryption: Envelope Keys + Multi-Factor Unlock

Use **envelope encryption**:
*   **DEKs** encrypt vault records (secrets/policies) using **XChaCha20-Poly1305**.
*   **KEKs** wrap DEKs; KEKs are derived using **Argon2id** (memory-hard KDF) to resist GPU/ASIC cracking.
*   **Factors:** Device factor (TPM), User factor (Bio/Passphrase), Out-of-band factor (Phone).

### 6.4 Monotonic Counter + Anti-Grinding / Anti-Rollback (IOI-daemon/Guardian-profile-grade)

To resist grinding and rollback:
*   Incorporate a **monotonic counter** stored outside snapshot boundaries (hardware/TEE when available).
*   Enforce attempt limits, exponential backoff, and lockout thresholds.

### 6.5 Out-of-Band Approval Factors

**Default step-up factor:** **Passkey (FIDO2/WebAuthn)**, preferably **phone-as-security-key over Bluetooth**.

### 6.6 ApprovalTokens (Action-Bound, Replay-Resistant)

An `ApprovalToken` is signed using the **Hybrid Signature** scheme and must contain:
*   **action:** (approve tx / widen policy / release authority)
*   **audience:** (Hypervisor Daemon / Guardian profile instance ID / specific executor)
*   **target:** (connector/provider/app/agent identity)
*   **mode:** (`one_shot` vs `lease` with TTL)
*   **grant_linkage:** (`parent_grant_id` for audit lineage)
*   **scope:** (caps, allowlists)
*   **nonce + counter:** (replay protection)

### 6.7 Secret Injection Protocol (Refined to “Authority-Scope Execution”)

1.  **Request:** Agent asks the Hypervisor Daemon / Guardian profile for an authority scope (e.g., `scope:model.openai.chat`), not a raw secret.
2.  **Challenge:** Hypervisor Daemon / Guardian profile proves it is running valid, attested code (remote attestation).
3.  **Policy Check:** Vault evaluates the authority scope against current envelope.
4.  **Release / Execute:**
    *   *Preferred:* Vault/Hypervisor Daemon / Guardian profile executes operation using secret internally (no raw secret to agent).
    *   *Otherwise:* Vault encrypts ephemeral secret material to the Hypervisor Daemon / Guardian profile ephemeral key (Hybrid KEM) with strict TTL.

### 6.8 Connector Token Brokerage (Minimize Long-Lived Exposure)

*   Store refresh tokens in vault.
*   Mint short-lived access tokens per operation.
*   Rotate and revoke rapidly.

### 6.9 Auditing & Lineage (Control Plane Receipts)

Every important event yields a receipt:
*   Policy commitment signed + hash-addressed.
*   Session issuance / sub-grant issuance.
*   Step-up approval token issuance.
*   Secret injection or authority-scope execution receipt.

Receipts are hash-linked for tamper-evidence and can be anchored into IOI’s broader audit substrate.

---

## 7. Adoption Strategy: “Embrace and Extend”

### 7.1 The “Trojan Horse” (DX Wedge)
*   **Pitch:** “Don’t trust your API keys to a browser. Keep them in your Sovereign Vault.”
*   **Wedge:** Developers need secrets + sessions + safe automation; `wallet.network` solves this first as a standalone Secret Manager before they even care about blockchains.

### 7.2 Ecosystem Integration
*   **WalletConnect v2:** Compatibility for legacy Tier 1 ownership wallets.
*   **Passkeys/OIDC:** Eliminates the "seed phrase bounce rate."
*   **Marketplace:** Capability-based integrations that never transfer custody of secrets.

---

## 8. Development Roadmap

### Phase 1: The Local Control Panel (Q3 2025)
*   Desktop App only.
*   Local key management (Hybrid PQ + EC) via `dcrypt` + Dual-Entropy Mnemonic.
*   Vault DB encryption (XChaCha20) + envelope keys (Argon2id).
*   Basic policy engine (Allow/Block) + audit log.
*   Hypervisor Daemon / Guardian Profile Link + basic step-up flow.

### Phase 2: The Web Bridge & Extensibility (Q4 2025)
*   Browser extension bridge (WASM for channel crypto only).
*   “Connect with Vault” protocol via `wallet-sdk`.
*   Capability requests and programmatic domain integration.
*   Connector framework (`wallet-connector-*`) with OAuth + token brokerage.

### Phase 3: The Mobile Approver (Q1 2026)
*   Mobile notifier/approver app.
*   Out-of-band approvals via passkeys, enrolled guardian devices, or hardware-backed assertions; biometrics are valid only when bound to the enrolled device/passkey policy.
*   Panic button + remote revocation.
*   Stronger step-up rules + anomaly triggers.

### Phase 4: Delegation Envelope + Advanced Hardening (Post Q1 2026)
*   RootGrant/SubGrant formalization (depth + issuance budgets).
*   Monotonic counter integration for anti-rollback/grinding where available.
*   Policy commitments + authority receipts recorded into Agentgres and optionally committed to IOI L1.
*   WASM/WASI Connector Marketplace activation.

---

## 9. Success Metrics

1.  **Vault Activations:** Users who stored at least one secret or onboarded one connector.
2.  **Session Density:** Autonomous actions per session (higher = better autonomy).
3.  **Intervention Rate:** High-risk actions intercepted and resolved successfully.
4.  **Policy Stability:** Percentage of actions executed without policy widening (healthy autonomy).
5.  **Delegation Safety:** Number of sub-grants issued that remain monotonic and within budgets.

---

## Appendix A — Web3 Account Control Model (Web4 Vault → Web3 Execution)

**Purpose:** Define how **`wallet.network`** (The Native Web4 Custodian) governs execution endpoints (smart accounts/EOAs) for users and agents, integrating legacy Web3 liquidity with Web4 security.

### A.1 Design Principles

1.  **Unified Sovereignty:** `wallet.network` serves as the ultimate custodian for both the assets (Funds) and the capabilities (Agency). 
2.  **Authority-Scope-First:** Agents receive **authority scope grants** (e.g., "Trade ETH for USDC on Uniswap"), never raw signing keys.
3.  **Approvals by Default Deny:** Token approvals (ERC-20 `approve`) default to **DENY** unless the contract, token, and amount are explicitly allowlisted.
4.  **On-Chain Enforcement:** Security constraints MUST survive a compromised runtime. High-risk actions require on-chain guarantees (Smart Account Modules).
5.  **Unified Audit:** Every action, whether on-chain or off-chain, yields a cryptographic receipt linked to a specific Policy Envelope.

---

### A.2 Account Roles (The Superset Topology)

1.  **The Master Custodian Account (Native `wallet.network`)**
    *   **Type:** Native Web4 Identity (Dual-Entropy Seed).
    *   **Purpose:** Holds the bulk of classical (ETH) and Web4/PQ assets such as service licenses, ServiceOrder escrows, SLA bonds, and receipt-backed claims. Secured by the highest configured threshold (e.g., 3FA/MPC).
    *   **Constraint:** **Never** directly connected to a running agent session.
2.  **The Agent Execution Account (Ops Wallet)**
    *   **Type:** Smart Account (ERC-4337, Safe, Kernel) with Policy Modules.
    *   **Purpose:** Routine autonomous execution.
    *   **Characteristics:** Limited funds (capped exposure), controlled by revocable **Session Keys**, subject to on-chain guards (Spending Limits, Allowlist).
3.  **The Web3 Cold Storage (Optional Linked EOA)**
    *   **Type:** External EOA / Hardware Wallet (MetaMask, Ledger).
    *   **Purpose:** Optional legacy storage. Can be used to deploy and fund the Ops Wallet via Smart Account delegation if the user wishes to keep their life savings out of the `wallet.network` seed.

---

### A.3 Control Mechanisms

`wallet.network` controls execution via three layers:

#### A.3.1 Policy Envelope (The Law)
*   **Definition:** Defined off-chain in the Vault. `PolicyCommitment` defines the `allowlist` (chains, contracts, selectors), `spend_caps`, `approval_limits`, and `step_up_triggers`.
*   **Enforcement:** Verified by the Hypervisor Daemon / Guardian profile before signing any intent.

#### A.3.2 Session Signers (The Keys)
*   **Type:** Ephemeral ECDSA/Ed25519 keys.
*   **Storage Invariant:** Private keys reside **solely** in Hypervisor Daemon / Guardian profile/executor memory (or TEE). They are **NEVER** persisted unencrypted and **NEVER** exposed to client apps/agents.
*   **Lifecycle:** Generated per-session, bounded by TTL, revocable via Epoch.

#### A.3.3 Smart Account Modules (The Enforcer)
*   **Type:** On-chain contracts (Validators/Guards).
*   **Role:** Enforce constraints (Spend Limits, Allowlisted Call Targets) at the blockchain level.
*   **Benefit:** Prevents a compromised Hypervisor Daemon / Guardian profile from draining the wallet beyond the limits.

---

### A.4 Risk Classification & Enforcement Requirements

Actions are classified by risk; enforcement strictness scales accordingly.

#### A.4.1 Low Risk (Autonomous)
*   *Examples:* Read-only calls, claiming rewards, swaps on allowlisted routers under strict slippage caps.
*   **Requirement:** Valid Grant + Valid Session Lease.
*   **Enforcement:** Off-chain Hypervisor Daemon / Guardian profile checks are sufficient. Receipts required.

#### A.4.2 Medium Risk (Restricted Autonomy)
*   *Examples:* Transfers under daily spend cap, interacting with curated contracts.
*   **Requirement:**
    *   **SHOULD** use On-Chain Module enforcement (Spend Limit).
    *   If On-Chain enforcement is unavailable, Hypervisor Daemon / Guardian profile **MUST** perform strict transaction simulation and rate-limiting.
    *   **MUST** block unknown token approvals.

#### A.4.3 High Risk (Step-Up Required)
*   *Examples:* New contract interaction, bridging, transfers > cap, policy widening.
*   **Requirement:**
    *   **MUST** be enforced via On-Chain Module (e.g., Multisig/Guard requiring User signature) **OR** require a direct Master Custodian Signature.
    *   **MUST** trigger Out-of-Band Step-Up (Phone/Passkey).
    *   Pure off-chain Hypervisor Daemon / Guardian profile checks are **insufficient**.

---

### A.5 Canonical Data Model: `TxIntent`

To ensure what the Agent requests is exactly what the User approves (and what the Chain executes), we define a canonical `TxIntent` object.

```rust
struct TxIntent {
    chain_id: u64,
    from: Address,      // Agent Account
    to: Address,        // Target Contract/Recipient
    value: U256,
    data: Bytes,        // Calldata
    nonce: u64,
    gas_limits: GasConfig,
    
    // Policy Bindings
    policy_hash: Hash,
    grant_id: Hash,
    lease_id: Hash,
    revocation_epoch: u64,
    
    // Safety Constraints
    slippage_bounds: Option<u64>, 
    simulation_hash: Hash, // Commitment to expected outcome
}
```
*   **Binding:** The `ApprovalToken` (A.7) signs the hash of `TxIntent`.
*   **Verification:** Smart Account Modules (Phase B) should ideally verify `policy_hash` or `lease_id` if supported.

---

### A.6 Funding & Exposure Controls

#### A.6.1 The "Token Approval" Invariant
*   **Default:** `DENY` all ERC-20 `approve` calls.
*   **Exception:** Allow only if `(Contract, Token, Amount)` is explicitly defined in the Policy Envelope.
*   **Preference:** Use `permit` (EIP-2612) with strict deadlines where possible.

#### A.6.2 Exposure Budget
*   **Rule:** Agent Accounts must be funded only with "Loss Tolerant" capital.
*   **Mechanism:** Master Custodian (or Linked Web3 Wallet) sends funds; Vault tracks "Burn Rate." Re-funding requires Step-Up.

---

### A.7 Step-Up & Approval Tokens

When a High-Risk action triggers a Step-Up:
1.  Hypervisor Daemon / Guardian profile pauses execution.
2.  User receives notification on Mobile/Desktop.
3.  User signs an `ApprovalToken` binding to `Hash(TxIntent)`.

**ApprovalToken Fields:**
*   `intent_hash` (The specific Tx)
*   `audience` (specific executor / Hypervisor Daemon / Guardian profile)
*   `mode` (`one_shot` default)
*   `expiry`
*   `sig_hybrid_user`

---

### A.8 Revocation & Emergency Stop

#### A.8.1 Off-Chain (Immediate)
*   **Action:** Bump `revocation_epoch`.
*   **Effect:** Hypervisor Daemon / Guardian profile rejects all `TxIntents` with old epochs. Immediate cessation of new signing.

#### A.8.2 On-Chain (Durable)
*   **Action:** Call `disableModule` or `rotateKey` on the Smart Account.
*   **Effect:** Invalidates the Session Key on-chain. Even a rogue Guardian cannot sign.

**Panic Button:** Triggers **both** A.8.1 and A.8.2 simultaneously.

---

### A.9 Implementation Roadmap

#### Phase A: The Guarded EOA (Fastest)
*   **Setup:** Master Custodian (or Tier-1 linked wallet) funds a standard EOA (Agent Account).
*   **Control:** Private Key in Hypervisor Daemon / Guardian profile memory (TEE/Secure Enclave).
*   **Enforcement:** Strict Off-Chain Policy checking + Simulation.
*   **Risk:** Relies on Hypervisor Daemon / Guardian profile integrity.

#### Phase B: The Smart Agent (Secure-by-Design)
*   **Setup:** Master Custodian deploys ERC-4337/Safe Account.
*   **Control:** Vault manages ephemeral Session Keys authorized as Module Signers.
*   **Enforcement:** **On-Chain Modules** for Spend Limits and Allowlist.
*   **Benefit:** High-Risk autonomy is now safe; compromised runtime cannot drain funds.

#### Phase C: Enterprise Account Estate
*   **Setup:** Multiple Strategy Sub-Accounts.
*   **Control:** Hierarchical Grants, Aggregate Reporting.
*   **Enforcement:** On-Chain Receipt Anchoring for compliance.
