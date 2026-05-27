# IOI L1 Mainnet Specification

Status: canonical architecture authority.
Canonical owner: this file for IOI L1, root contracts, gas boundaries, settlement, and public commitments.
Supersedes: overlapping plan prose when L1 ownership or gas boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-05-25.

## Canonical Definition

**IOI L1 is the canonical Web4 settlement layer for autonomous systems: the public registry, rights, settlement, dispute, sparse-commitment, and governance layer for consequential autonomous work.**

It coordinates public trust and economic commitments. It does not run application state, workflow execution, model inference, or Agentgres domains.

Short form:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

## Primary Duties

IOI L1 owns:

1. `ai://` namespace registration.
2. Publisher, provider, domain, and runtime identity commitments.
3. Application, worker, service, and domain manifest commitments.
4. Smart contracts for rights, licenses, escrows, SLA bonds, payouts, and disputes.
5. Reputation, quality, contribution, ontology, benchmark, routing,
   training-lineage, and receipt-root commitments where public or economic
   trust requires them.
6. Autopilot-node, autonomous-system-chain, policy, module, upgrade, local
   settlement, and receipt roots when public trust, dispute, reputation, or
   economic settlement requires them.
7. Authority lease commitments, settlement claims, routing roots, worker
   eligibility commitments, and cross-system handoff finality for AIIP-powered
   autonomous work.
8. AIIP channel, profile, schema, endpoint, relay/router policy, and capability
   registry commitments when global interoperability requires them.
9. Protocol governance and HHAI-governed upgrades for canonical specs, contracts, and reference implementations.
10. Public coordination for first-party Web4 applications and domains such as aiagent.xyz, sas.xyz, Autopilot, wallet.network, and ioi.ai.

Identity note:

> IOI L1 anchors public identity and registry commitments. wallet.network owns
> identity operations, authority grants, secrets, approvals, key leases,
> revocation, and payment authorization.

## L0 / L1 Boundary

The IOI kernel is the **L0 substrate**: the portable kernel/toolchain used to
instantiate application domains, sovereign execution domains, non-intelligent
chains/state machines, and intelligent blockchains.

IOI L1 is the **public root coordination chain** for that ecosystem. It anchors
identity, rights, registry, settlement, dispute, sparse commitments, and
governance. It can govern canonical L0/kernel releases by hash, proposal, and
upgrade policy, but it does not operate every runtime, run every domain, or
manage ordinary source-control activity.

Canonical release flow should look like:

```text
source/build/manifest candidate roots
  -> governance proposal or release approval
  -> IOI L1 records approval, rejection, deprecation, or emergency action
  -> domains and runtimes decide whether and when to adopt the release
```

This lets IOI L1 govern the public substrate without becoming the day-to-day
manager of the monorepo, private deployments, or application-domain state.

## What IOI L1 Does Not Own

IOI L1 does not own:

- Autopilot-node local settlement state;
- every governed autonomous-system-chain transition;
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

The commercial surface is the buy/sell or invocation record. The trust surface
is the authority, receipt, routing, dispute, reputation, and settlement record.
Both should settle through IOI when consequential.

## Local and Global Settlement

IOI distinguishes local autonomous work settlement from global autonomous-system
settlement.

```text
Governed Autonomous-System Chain
  accepts local module invocations, proposals, receipts, and state transitions

Autopilot Node
  coordinates many autonomous-system chains and settles local interop, authority
  outcomes, receipt bundles, replay, and escalation records

IOI L1
  anchors selected roots and settles public rights, disputes, reputation,
  registry commitments, AIIP handoff finality, and economics
```

Autopilot nodes are local settlement domains. IOI L1 is the global settlement
layer for autonomous systems. IOI L1 should receive sparse commitments from
Autopilot nodes, application domains, and independent AS-L1s only when public
trust, economic finality, dispute resolution, reputation portability,
cross-system handoff finality, or marketplace rights require it.

Canonical line:

> **Sovereignty at the edge. Settlement at the center.**

## Smart Contract Families

### Registry Contracts

- `AiNamespaceRegistry`
- `PublisherRegistry`
- `DomainRegistry`
- `ManifestRootRegistry`
- `VerificationProfileRegistry`
- `AutonomousSystemRegistry`
- `AIIPChannelRegistry`
- `AIIPSchemaRegistry`
- `SettlementAccountRegistry`

### Autonomous-System Settlement Contracts

- `SystemManifestRoot`
- `AuthorityLeaseCommitment`
- `PolicyRootRegistry`
- `ReceiptRootRegistry`
- `HandoffFinalityRegistry`
- `SettlementIntentRegistry`
- `RoutingDecisionRoot`
- `WorkerEligibilityRoot`

### aiagent.xyz Contracts

- `WorkerRegistry`
- `WorkerVersionCommitment`
- `WorkerLicenseRight`
- `WorkerInstallRight`
- `UsageSettlement`
- `WorkerDispute`
- `WorkerReputationRoot`
- `ContributionRoot`
- `SparseWorkerCategoryRegistry`
- `BenchmarkProfileRegistry`
- `TrainingLineageRoot`
- `RoutingDecisionRoot`

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
commit benchmark/category/routing/training-lineage root
commit Autopilot-node receipt/local-settlement root for dispute or settlement
commit autonomous-system-chain policy/module/upgrade root for public trust
commit AIIP channel/schema/profile root
commit authority lease commitment
commit settlement intent
commit cross-system handoff finality
```

IOI gas is not consumed for:

```text
model thoughts
tool calls
workflow nodes
Agentgres domain writes
Autopilot-node local settlement records
autonomous-system-chain module invocations
AIIP local-profile packets
private receipt bodies
runtime events
artifact generation
local cache updates
projection deltas
```

> **The chain prices commitments. The runtime prices work.**

## Mainnet and Application Domains

First-party applications such as aiagent.xyz and sas.xyz use AIIP and IOI L1
smart contracts for public commitments and economics, while their rich
operational state lives in their own Agentgres-backed application domains. They
are first-party protocol clients, not the entire protocol.

```text
IOI L1
  rights, settlement, contracts, roots

aiagent.xyz domain
  worker marketplace state, runs, quality, installs, projections

sas.xyz domain
  service orders, delivery bundles, provider state, disputes, projections

Autopilot node/domain
  local autonomous-system chains, module invocations, proposals, receipts,
  authority outcomes, state roots, replay, local settlement records
```

## Independent Sovereign Domains

Independent L1s or sovereign domains may register with IOI L1 for `ai://`
discoverability, AIIP interoperability, and settlement. They do not need to
anchor all state into IOI L1.

Required registration may include:

- domain ID;
- publisher/operator identity;
- resolver endpoint;
- manifest root;
- runtime profile;
- receipt schema;
- verification profile.
- AIIP profile and channel schema refs;
- settlement account ref.

Optional anchoring may include:

- dispute roots;
- bridge roots;
- public checkpoint roots;
- settlement commitments.
- authority lease commitments;
- handoff finality records;
- routing decision roots;
- reputation event roots.

Doctrine:

> **IOI mainnet keeps the map. Sovereign domains keep their territory.**

Or:

> **Bring your own autonomous system. Settle it on IOI.**

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
- L0/kernel release roots and release policy.

Governance should not micromanage ordinary commits, pull requests,
application-domain state, every worker package, or private runtime execution.

## Non-Negotiables

1. IOI L1 is not the Agentgres database.
2. IOI L1 is not the execution runtime.
3. IOI L1 should not receive every receipt or projection root.
4. IOI L1 should store commitments and economic state, not operational payloads.
5. IOI L1 governance may approve canonical L0/kernel releases; it does not
   operate the L0 substrate or own day-to-day repository management.
6. IOI L1 should not be described as the Autopilot node. Autopilot nodes settle
   autonomous work locally; IOI L1 settles machine labor globally.
7. IOI L1 smart contracts are the correct starting point; L2s/rollups are only scaling contingencies.
8. IOI L1 should not be described as the agent marketplace or outcome
   marketplace. aiagent.xyz and sas.xyz are first-party applications of the
   settlement layer.

## One-Line Doctrine

> **Put public rights, money, registry, settlement, and kernel release commitments on L1. Put operational truth in Agentgres. Put execution in daemons. Put payloads in Filecoin/CAS.**
