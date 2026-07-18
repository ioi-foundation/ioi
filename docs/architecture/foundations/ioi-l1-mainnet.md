# IOI L1 Mainnet Specification

Status: canonical architecture authority.
Canonical owner: this file for IOI L1, explicit network enrollment, shared-trust services, root contracts, gas boundaries, settlement, and public commitments.
Supersedes: overlapping plan prose when L1 ownership or gas boundaries conflict.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: speculative (no L1 deployment; design authority for a future chain)
Last implementation audit: 2026-07-05

## Canonical Definition

**IOI L1 is the optional neutral public-trust utility for IOI-connected and
IOI-secured autonomous systems: a registry, rights, assurance, shared-security,
dispute, sparse-commitment, and economic-finality layer.**

It coordinates public trust and economic commitments. It does not run application state, workflow execution, model inference, or Agentgres domains.

Short form:

> **L0 systems remain sovereign. Explicitly enrolled systems use IOI L1 only
> for the shared trust and economic finality they select.**

Category role:

> **IOI L1 is an opt-in public map and risk-bearing trust market for a Web4
> ecosystem of sovereign autonomous-system domains.**

## Primary Duties

IOI L1 owns:

1. `ai://` namespace registration.
2. Publisher, provider, domain, and runtime identity commitments.
3. Application, worker, service, and domain manifest commitments.
4. Smart contracts for rights, licenses, escrows, SLA bonds, payouts, and disputes.
5. Reputation, quality, contribution, ontology, benchmark, routing,
   training-lineage, and receipt-root commitments where public or economic
   trust requires them and the underlying assurance state distinguishes
   receipt, evidence, verification, acceptance, and adjudication.
6. Hypervisor Node, autonomous-system-chain, policy, module, upgrade, local
   settlement, and receipt roots when public trust, dispute, reputation, or
   economic settlement requires them.
7. Authority lease commitments, settlement claims, routing roots, worker
   eligibility commitments, and cross-system handoff finality for AIIP-powered
   autonomous work.
8. System constitution, recognized release, Standard DAS conformance, network
   enrollment, selected endpoint, and service commitments for connected or
   secured systems.
9. Optional verifier, guardian, availability-witness, relayer, arbitrator,
   ordering, and finality services with explicit terms, bonds/stake, claims,
   slashing, and exit obligations.
10. AIIP channel, profile, schema, endpoint, relay/router policy, and capability
   registry commitments only for systems selecting those registry services.
11. Governance of IOI Network contracts, conformance profiles, recognized
   release roots, public services, and reference implementations—not all Web4
   or all compatible L0 use.
12. Public coordination for first-party Web4 applications and domains such as aiagent.xyz, sas.xyz, Hypervisor, wallet.network, and ioi.ai.

Identity note:

> IOI L1 anchors public identity and registry commitments. wallet.network owns
> identity operations, authority grants, secrets, approvals, key leases,
> revocation, and payment authorization.

## L0 / L1 Boundary

The IOI kernel is the **L0 substrate**: the portable kernel/toolchain used to
instantiate application domains, sovereign execution domains, non-intelligent
chains/state machines, and intelligent blockchains.

IOI L1 is an optional **public root coordination chain** for that ecosystem. It anchors
identity, rights, registry, settlement, dispute, sparse commitments, and
governance. It can recognize IOI Network L0/kernel releases by hash, proposal, and
upgrade policy, but it does not operate every runtime, run every domain, or
manage ordinary source-control activity.

Canonical release flow should look like:

```text
source/build/manifest candidate roots
  -> governance proposal or release approval
  -> IOI L1 records approval, rejection, deprecation, or emergency action
  -> domains and runtimes decide whether and when to adopt the release
```

Approval of a kernel release means that the IOI Network recognizes that release
under a named conformance/security profile. It is not permission to use, fork,
or independently operate the open L0 contracts and reference stack. This lets
IOI L1 govern IOI Network-recognized releases without becoming the day-to-day
manager of the monorepo, compatible deployments, or application-domain state.

As more domains explicitly connect and consume registry, assurance, rights,
security, dispute, or settlement services, IOI L1 can become more useful as
shared trust infrastructure without absorbing their operational state. L0 or
AIIP adoption alone does not create L1 transactions, fees, bonded demand, or
token value.

## Explicit Network Enrollment

The enrollment contract is one stateful `IOINetworkEnrollmentEnvelope`:

| Profile | L1 relationship | Permitted assurance claim |
| --- | --- | --- |
| `ioi_compatible` | None required. Open L0 conformance may be proven locally and AIIP may use any compatible resolver or settlement adapter. | No IOI Network connection or assurance. |
| `ioi_connected` | Commits a named conformance result plus selected system, constitution, release, endpoint, and service refs. | Only the exact registry, rights, reputation, escrow, dispute, or settlement service consumed. |
| `ioi_secured` | Additionally adopts an approved Standard DAS profile and named shared-security/assurance services. | Only the declared verifier, guardian, availability, ordering, finality, arbitration, or other coverage under its terms. |

Enrollment is orthogonal to deployment topology, consensus, contributor scope,
product subscription, and assurance stage. `ioi_secured` is not a blanket claim
that a system is safe, correct, benevolent, legal, available, or economically
sound. Each service names providers, fault assumptions, scope, duration,
evidence, fees/contribution, bond/stake, claims, slashing/dispute rules, renewal,
suspension, and exit.

An IOI-compatible system owes no ambient fee, token, registration, or L1
transaction. A connected system pays only for selected services. A secured
system supplies explicit consideration for scarce neutral trust. Exit preserves
outstanding obligations, disputes, evidence-retention duties, and final
commitments.

### Shared-Security Service Market

IOI L1 may coordinate independently accountable validators, guardians,
verifiers, availability witnesses, relayers, arbitrators, ordering providers,
and finality providers. Their security comes from named responsibility and
capital at risk, not from the label "decentralized." Service agreements bind
conformance roots, membership, performance/SLA, evidence, bond or stake,
slashing/claims, replacement, emergency action, and exit. A system can combine
several services or use external security while remaining compatible.

## What IOI L1 Does Not Own

IOI L1 does not own:

- Hypervisor Node operational state-transition commitments;
- every governed autonomous-system-chain transition;
- Agentgres operational state;
- every worker run;
- every GoalRun, OutcomeRoom, participant lease, work claim, attempt, finding,
  verifier challenge, or OutcomeDelta;
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

> **IOI L1 settles selected rights and shared trust, not every agent thought,
> attempt, receipt, or collaborative-room transition.**

The commercial surface is the buy/sell, service-order, or invocation record.
The trust surface is the authority, evidence, verification, acceptance,
adjudication, contribution, reputation, and settlement record. Selected roots
should settle through IOI only when independent public ordering, rights,
portability, dispute, reputation, or economic finality creates value.

## Local And Optional Public Settlement

IOI distinguishes local autonomous work settlement from optional public
autonomous-system commitments.

```text
Governed Autonomous-System Chain
  accepts local module invocations, proposals, receipts, and state transitions

Hypervisor Node
  coordinates many autonomous-system chains and settles local interop, authority
  outcomes, receipt bundles, replay, and escalation records

IOI L1
  anchors selected roots and settles public rights, disputes, reputation,
  registry commitments, AIIP handoff finality, and economics
```

Hypervisor Nodes are local operational-finality domains. Systems select whether IOI L1,
an external chain, a bilateral contract, or no public layer handles each shared
commitment. IOI L1 receives sparse commitments only from explicitly enrolled
systems and only when the selected public-trust, shared-security, economic,
dispute, reputation, handoff-finality, or marketplace service requires it.

Canonical line:

> **Sovereignty at the edge. Shared trust by explicit enrollment.**

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
- `NetworkEnrollmentRegistry`
- `StandardDASProfileRegistry`
- `SharedSecurityServiceRegistry`
- `ServiceBondRegistry`

### Autonomous-System Settlement Contracts

- `SystemManifestRoot`
- `AuthorityLeaseCommitment`
- `PolicyRootRegistry`
- `ReceiptRootRegistry`
- `HandoffFinalityRegistry`
- `SettlementIntentRegistry`
- `RoutingDecisionRoot`
- `WorkerEligibilityRoot`
- `SystemConstitutionCommitment`
- `RecognizedSystemReleaseRoot`
- `SystemMembershipRoot`
- `LifecycleAndExitCommitment`
- `SharedSecurityAgreement`

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
- `DeliveryRevision`
- `ProviderPayout`
- `EscrowRefund`
- `SLASlash`
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
accept partial delivery
request revision
release payout
release partial payout
refund escrow
slash SLA bond
open dispute
resolve dispute
commit reputation/contribution root
commit benchmark/category/routing/training-lineage root
commit a Hypervisor Node receipt/state-transition root for dispute or settlement
commit autonomous-system-chain policy/module/upgrade root for public trust
commit AIIP channel/schema/profile root
commit authority lease commitment
commit settlement intent
commit cross-system handoff finality
activate or change connected/secured enrollment
register or consume a shared-security service
post, claim, slash, or release a verifier/guardian/availability/relayer/arbitrator bond
commit a recognized constitution, Standard DAS conformance, release, lifecycle, or exit root
```

IOI gas is not consumed for:

```text
model thoughts
tool calls
workflow nodes
Agentgres domain writes
Hypervisor Node state-transition commitment records
autonomous-system-chain module invocations
ioi-compatible system creation, deployment, replication, failover, or lifecycle transitions
AIIP local-profile packets
GoalRuns and GoalGroundingLoop iterations
OutcomeRoom participant/frontier/claim/attempt/finding transitions
verifier challenges and re-verification inside one declared room/domain
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

Hypervisor Node/domain
  local autonomous-system chains, module invocations, proposals, receipts,
  authority outcomes, state roots, replay, state-transition commitment records
```

## Independent Sovereign Domains

Independent L1s or sovereign domains may register with IOI L1 for selected
`ai://` resolution, AIIP endpoint discovery, rights, assurance, dispute, or
settlement services. Registration is not required for AIIP interoperability,
and enrolled systems do not anchor all state into IOI L1.

This is the intended ecosystem shape: teams may bring their own autonomous
systems, appchains, enterprise domains, marketplaces, or intelligent
blockchains, keep local governance and state where it belongs, and use IOI for
the shared trust surfaces that benefit from public coordination.

Connected or secured registration may include:

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

> **Bring your own autonomous system. Connect or secure only what benefits from
> neutral shared trust.**

## HHAI Governance Duties

Eventually, IOI L1 governance may govern:

- IOI Network conformance and Standard DAS profiles;
- IOI Network-recognized kernel release roots and upgrades;
- `ai://` schemas;
- settlement contract upgrades;
- validator/guardian rules;
- protocol fees;
- treasury grants;
- security emergency actions;
- IOI Network-recognized reference-release approvals under named conformance
  profiles.

It does not govern compatible L0 implementations, external AIIP peers, or the
Web4 category merely because they use open contracts or schemas.

Governance should not micromanage ordinary commits, pull requests,
application-domain state, every worker package, or private runtime execution.

## Bootstrap And Native-Asset Gate

The architecture does not require a sovereign L1 at product launch. First prove
real demand for registries, rights, escrow, service bonds, verifier/guardian/
availability services, disputes, and settlement using a devnet or mature
compatible settlement environment. A sovereign IOI L1 becomes justified when
neutral ordering/security, sovereignty, performance, or governance creates
more value than the migration and security burden.

Any eventual native asset is conditional risk-bearing capital and scarce
public-capacity access. Legitimate roles may include gas for public commitments,
validator or consensus security, verifier/guardian/availability/relayer/
arbitrator bonds, slashing/claims, and IOI Network governance. It is not the
currency for every model call, a replacement for stable-value user billing or
Work Credits, or a mandatory token for each bounded DAS. Architecture does not
predict market capitalization; value depends on explicit service demand,
credible security, fees, bonded risk, and governance rights.

## Anti-Patterns

Do not model IOI L1 as:

```text
the Agentgres database
the default execution runtime
the default trace store
the artifact byte store
the Hypervisor Node
the worker marketplace itself
the service marketplace itself
the place where every local run must settle
a chain per agent, GoalRun, attempt, room, tool call, or receipt
```

Correct model:

```text
daemons execute
Agentgres records operational truth
storage backends hold payload bytes
AIIP moves bounded work
explicitly enrolled systems may use IOI L1 for selected public, economic,
registry, assurance, security, rights, dispute, reputation, governance, and
cross-domain commitments
```

## Non-Negotiables

1. IOI L1 is not the Agentgres database.
2. IOI L1 is not the execution runtime.
3. IOI L1 should not receive every receipt or projection root.
4. IOI L1 should store commitments and economic state, not operational payloads.
5. IOI L1 governance may approve IOI Network-recognized L0/kernel releases; it does not
   operate the L0 substrate, grant permission to use compatible L0, or own
   day-to-day repository management.
6. IOI L1 should not be described as the Hypervisor Node. Hypervisor Nodes settle
   autonomous work locally; enrolled systems use IOI L1 only for selected
   shared-trust services.
7. Contract and service demand should be proven before a sovereign mainnet or
   native asset; L2s/rollups and external settlement are options, not dogma.
8. IOI L1 should not be described as the agent marketplace or outcome
   marketplace. aiagent.xyz and sas.xyz are first-party applications of the
   settlement layer.
9. Contribution or reputation commitments must preserve their assurance stage;
   a signed receipt or self-reported score alone is not accepted economic value.
10. GoalRuns, OutcomeRooms, attempts, and local autonomous systems use
    deterministic domain admission, signatures, branches, receipts, and replay
    by default. Consensus appears only at a real independent-trust boundary.
11. Open L0 or AIIP use creates no mandatory enrollment, fee, gas, token, L1
    transaction, assurance claim, or value-accrual promise.
12. A native asset, if launched, is risk-bearing network capital and public
    capacity—not Work Credits, generic inference currency, or a token per DAS.

## One-Line Doctrine

> **Keep L0 systems sovereign. Put operational truth in Agentgres, execution in
> daemons, and payload bytes in storage backends. Put only explicitly selected
> registry, assurance, security, rights, dispute, governance, and economic
> commitments on IOI L1.**
