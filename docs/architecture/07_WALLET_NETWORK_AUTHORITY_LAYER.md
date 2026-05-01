# wallet.network Authority Layer Specification

## Canonical Definition

**wallet.network is the sovereign authority layer for canonical Web4.**

It owns identity, secrets, capability grants, session authority, approvals, payments, revocation, and audit lineage. It is not merely a crypto wallet.

## Core Doctrine

> **Autopilot runs agents. Agentgres remembers and settles what changed. wallet.network decides what power agents are allowed to use.**

## What wallet.network Owns

wallet.network owns:

- user identity;
- agent/app/domain authority grants;
- root secrets;
- API keys;
- OAuth refresh tokens;
- connector credentials;
- BYOK model provider keys;
- capability leases;
- approval tokens;
- session grants;
- policy envelopes;
- revocation epochs;
- payment authorization;
- panic/emergency controls;
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
- model inference execution.

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

## Frictionless-to-Fortress Security Ladder

### Level 1: Frictionless Account

- Google/GitHub/OIDC/Web3 login;
- native wallet.network identity created automatically;
- low-risk capabilities;
- managed recovery;
- limited autonomy.

### Level 2: Trusted Device

- passkey;
- biometric;
- mobile approver;
- higher risk limits;
- stronger approval flows.

### Level 3: Sovereign Vault

- multiple factors;
- hardware key;
- MPC/shards;
- high-value assets;
- policy widening;
- institutional autonomy.

## Capability Request Flow

```text
agent/runtime requests capability
→ wallet.network evaluates policy
→ if allowed, issues scoped capability/session/approval token
→ runtime executes operation without raw secret exposure where possible
→ receipt emitted
→ Agentgres records effect state/evidence
```

## Capability Examples

```text
cap:model.openai.chat
cap:model.anthropic.messages
cap:gmail.read
cap:gmail.draft
cap:gmail.send
cap:calendar.create
cap:slack.post
cap:github.comment
cap:instacart.cart_create
cap:instacart.order_submit
cap:wallet.transfer_under_cap
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

## Marketplace Role

wallet.network authorizes:

- worker installation;
- worker capability grants;
- service escrow funding;
- payment release;
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

## Relationship to Agentgres

wallet.network emits authority artifacts:

```text
PolicyEnvelope
RootGrant
SubGrant
CapabilityLease
ApprovalToken
RevocationEvent
SecretExecutionReceipt
StepUpReceipt
```

Agentgres records the effect of these in domain state, but does not own the raw secrets.

## Non-Negotiables

1. Agents never receive raw root secrets.
2. Apps and runtimes are capability clients, not key custodians.
3. Policy widening requires step-up.
4. Sensitive actions bind to exact request hash, policy hash, scope, expiry, and revocation epoch.
5. Panic/revocation must kill active grants.
6. BYOK keys live in wallet.network, not workflow node configs.

## One-Line Doctrine

> **Do not make users create a wallet. Let them create an account that can grow into a vault.**

