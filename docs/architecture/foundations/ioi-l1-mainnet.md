# IOI L1 Mainnet Specification

Status: canonical architecture authority.
Canonical owner: this file for IOI L1, root contracts, gas boundaries, settlement, and public commitments.
Supersedes: overlapping plan prose when L1 ownership or gas boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Canonical Definition

**IOI L1 is the canonical Web4 registry, rights, settlement, and governance layer.**

It coordinates public trust and economic commitments. It does not run application state, workflow execution, model inference, or Agentgres domains.

## Primary Duties

IOI L1 owns:

1. `ai://` namespace registration.
2. Publisher and provider identity commitments.
3. Application, worker, service, and domain manifest commitments.
4. Smart contracts for rights, licenses, escrows, SLA bonds, payouts, and disputes.
5. Reputation, quality, contribution, and receipt-root commitments where public or economic trust requires them.
6. Protocol governance and HHAI-governed upgrades for canonical specs, contracts, and reference implementations.
7. Public coordination for first-party Web4 applications such as aiagent.xyz, sas.xyz, Autopilot, wallet.network, and ioi.ai.

## What IOI L1 Does Not Own

IOI L1 does not own:

- Agentgres operational state;
- every worker run;
- every workflow event;
- every model invocation;
- every tool call;
- every receipt;
- local memory;
- private artifacts;
- routine app queries;
- subscriptions;
- projection deltas;
- runtime execution.

> **IOI L1 settles rights and trust, not every agent thought.**

## Smart Contract Families

### Registry Contracts

- `AiNamespaceRegistry`
- `PublisherRegistry`
- `DomainRegistry`
- `ManifestRootRegistry`
- `VerificationProfileRegistry`

### aiagent.xyz Contracts

- `WorkerRegistry`
- `WorkerVersionCommitment`
- `WorkerLicenseRight`
- `WorkerInstallRight`
- `UsageSettlement`
- `WorkerDispute`
- `WorkerReputationRoot`
- `ContributionRoot`

### sas.xyz Contracts

- `ServiceRegistry`
- `ServiceOrder`
- `ServiceEscrow`
- `SLABond`
- `DeliveryAcceptance`
- `ProviderPayout`
- `ServiceDispute`
- `ServiceReputationRoot`

### Governance Contracts

- `ProtocolUpgradeProposal`
- `ReferenceImplementationRelease`
- `EmergencySecurityAction`
- `TreasuryGrant`
- `ValidatorOrGuardianSetUpdate`

## Gas Boundary

IOI gas is consumed when applications interact with IOI L1 contracts.

Examples:

```text
register ai:// name
publish worker/service manifest root
mint license/install right
lock escrow
post SLA bond
accept delivery
release payout
open dispute
resolve dispute
commit reputation/contribution root
```

IOI gas is not consumed for:

```text
model thoughts
tool calls
workflow nodes
Agentgres domain writes
runtime events
artifact generation
local cache updates
projection deltas
```

> **The chain prices commitments. The runtime prices work.**

## Mainnet and Application Domains

First-party applications such as aiagent.xyz and sas.xyz use IOI L1 smart contracts for public commitments and economics, while their rich operational state lives in their own Agentgres-backed application domains.

```text
IOI L1
  rights, settlement, contracts, roots

aiagent.xyz domain
  worker marketplace state, runs, quality, installs, projections

sas.xyz domain
  service orders, delivery bundles, provider state, disputes, projections
```

## Independent Sovereign Domains

Independent L1s or sovereign domains may register with IOI L1 for `ai://` discoverability and interoperability. They do not need to anchor all state into IOI L1.

Required registration may include:

- domain ID;
- publisher/operator identity;
- resolver endpoint;
- manifest root;
- runtime profile;
- receipt schema;
- verification profile.

Optional anchoring may include:

- dispute roots;
- bridge roots;
- public checkpoint roots;
- settlement commitments.

Doctrine:

> **IOI mainnet keeps the map. Sovereign domains keep their territory.**

## HHAI Governance Duties

Eventually, IOI L1 governance may govern:

- canonical Web4 protocol specs;
- IOI kernel protocol upgrades;
- `ai://` schemas;
- settlement contract upgrades;
- validator/guardian rules;
- protocol fees;
- treasury grants;
- security emergency actions;
- reference implementation release approvals;
- L0 monorepo release policy.

Governance should not micromanage ordinary application-domain state, every worker package, or private runtime execution.

## Non-Negotiables

1. IOI L1 is not the Agentgres database.
2. IOI L1 is not the execution runtime.
3. IOI L1 should not receive every receipt or projection root.
4. IOI L1 should store commitments and economic state, not operational payloads.
5. IOI L1 smart contracts are the correct starting point; L2s/rollups are only scaling contingencies.

## One-Line Doctrine

> **Put rights, money, registry, and settlement on L1. Put operational truth in Agentgres. Put execution in daemons. Put payloads in Filecoin/CAS.**
