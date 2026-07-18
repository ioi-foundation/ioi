# Governed Autonomous Systems and Hypervisor Nodes

Status: canonical architecture authority.
Canonical owner: this file for governed autonomous-system chains, Hypervisor Node settlement domains, collaborative-pursuit topology, and the coherent machine-economy stack.
Supersedes: product prose that collapses Hypervisor UI, Hypervisor Node, autonomous-system state machines, and IOI L1 into one layer.
Superseded by: none.
Last alignment pass: 2026-07-17.
Doctrine status: canonical
Implementation status: mixed (the improvement-proposal plane, bounded GoalRun multi-HarnessInvocation slice, and hosted OutcomeRoom graph through participation, frontier/claim, offers/matching, Attempt/Finding, WorkResult/OutcomeDelta, and VerifierChallenge are built or partial; local-agent pairing, autonomous-system chains, federated admission, acceptance/verdict/settlement, and local operational-finality domains remain planned or speculative)
Last implementation audit: 2026-07-11

## Canonical Definition

**A governed autonomous system is a constitution-bound, stateful autonomous
institution whose intelligence may propose, route, execute, and improve work,
but whose consequential transitions become canonical only through declared
ordering, policy, authority, evidence, and lifecycle paths.**

A **governed autonomous-system chain** or **intelligent blockchain** is the
cryptographically continuous ordered state-machine embodiment of that
institution. Every admitted operation or batch binds a monotonic sequence,
expected predecessor commitment, operation/batch commitment, admission proof,
resulting state root, and receipt root. A bounded autonomous institution that
lacks this verifiable commitment chain is a bounded autonomous application, not
an intelligent blockchain. The chain can be
single-authority, replicated, threshold-governed, BFT-consensual, or finalized
by an external chain. Public consensus is one deployment profile, not the
property that makes the system bounded or intelligent.

Short form:

> **Autonomous systems are not prompts. They are governed execution objects.**

Protocol thesis:

> **One autonomous system can coordinate useful work across many admitted
> nodes. AIIP makes selective, positive-surplus interoperation between
> independently governed systems contractible; the IOI Network can secure and
> settle the selected commitments that need shared trust.**

An agent is not a model loop. An agent or Worker may act inside, back, or expose
capability to a bounded DAS, but it is an actor/module rather than the system
identity by default. It becomes a DAS only when packaged with the full
constitution, ordering/admission, authority, evidence, replay, improvement, and
lifecycle contract. A DAS may compose sovereign peer systems through AIIP; it
does not make them execution nodes inside itself by implication. Consequential
actions become ordered, receipted, replayable state transitions under policy
and authority.

This is a system-local base layer in the state-machine sense. It is not
necessarily a public blockchain, a standalone L1, a validator in global
consensus, or an IOI L1 replacement.

The broader system is one architecture, not an autonomy hypervisor beside a
separate enterprise-ontology product:

```text
local ontologies make a domain legible; explicit mappings enable selected federation
GoalRuns turn legibility into bounded purposeful work
OutcomeRooms add collective pursuit only when complementary value justifies it
Hypervisor isolates, places, and executes that work across admitted local or remote members
local/domain governance and wallet.network authorize consequential power
Agentgres admits each domain's operational truth
AIIP permits terms-bound interoperation between independently governed domains
IOI L1 settles only the selected commitments that need shared finality
```

Canonical category and strongest formulation:

> **IOI is the open operating stack that turns intelligence into bounded
> autonomous institutions. L0 makes each institution safely distributable
> across its governed compute, state, verification, human, and embodied members;
> AIIP makes selective, positive-surplus interoperation between separately
> sovereign institutions contractible; IOI L1 supplies optional shared trust and
> economic finality.**

Externally, lead with **bounded distributed autonomous systems**. Use
**intelligent blockchain** as the precise technical classification for their
ordered state-machine substrate. L0 is their modular builder and operating
substrate; the category is defined by the constitution-to-effect lifecycle,
machine authority, operational evidence, proposal-mediated improvement, and
lifecycle continuity of autonomous systems rather than by analogy to an
existing chain framework.

Hypervisor is the reference execution and control environment; the ontology
layer is the semantic world plane. They are complementary parts of the same
open operating fabric, not competing product theses.

## The Bounded-System Contract

A bounded autonomous system is one logical institution, not one process, one
model, one UI, one database, or one physical node. Its stable
`system_id` persists across member-node changes, model-route changes, upgrades,
recovery, and migration. Adoption preserves that identity only when the active
constitution and explicit continuity decision authorize it; otherwise the
adopted or forked system receives a related new identity and lineage. The
system is defined by the following versioned contract set:

```text
AutonomousSystemManifestEnvelope
  reusable package/release manifest; no live system identity or membership

AutonomousSystemGenesisEnvelope
  one-time release-to-system binding with constitution, profiles, authority,
  and cryptographic origin

AutonomousSystemConstitutionEnvelope
  what the institution exists to do and may never do

AutonomousSystemDeploymentProfileEnvelope
  desired member roles, failure domains, replication, scaling, and recovery posture

OrderingAdmissionFinalityProfileEnvelope
  how operations become ordered, admitted, and final

OracleEvidenceProfileEnvelope
  how external facts may influence canonical transitions

LifecycleContinuityProfileEnvelope
  how it amends, recovers, migrates, forks, succeeds, exports, and dissolves

IOINetworkEnrollmentEnvelope
  which optional IOI Network services and assurance covenant it accepts
```

Package identity, system identity, and node identity are three different
things. A `package://` release can instantiate many systems. Genesis mints one
`system://` identity and activates the first admitted constitution and profile
set. Nodes later join that system through governed membership. A release update
is an upgrade to the same system; it is not another genesis. Package lifecycle
ends in release, promotion, deprecation, or revocation, while recovery,
migration, succession, dissolution, and decommission belong only to the live
system.

Hypervisor's **Systems** workspace is the non-owning product home and contextual
read model for identities created by that admitted genesis path. It may show a
package candidate or genesis preview as a draft, but it must not present either
as a live System before the domain/daemon and Agentgres admission receipts
exist. Systems never mints identity, substitutes desired topology for observed
membership, or becomes lifecycle truth.

This System-centered product model is not a genesis tax on ordinary work. A
direct Session, Project, AutomationSpec, stand-alone GoalRun, or non-System
headless WorkRun remains valid when its own authority, execution, evidence, and
receipt contracts are sufficient. Stable System identity is required only when
the work claims the bounded autonomous-institution lifecycle defined here.

Local package build, release, install, version, recall, and impact analysis are
also complete without marketplace participation. Hypervisor may present those
functions through a Packages owner surface with optional Marketplace discovery
or commerce, but publication or sale cannot replace local admission or mutate a
live System without its own governed transition.

Observed `AutonomousSystemNodeMembershipEnvelope` records and lifecycle
transition records prove what is actually active; desired topology alone does
not. The exact shared schemas live in
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md).

### Constitution Before Recursion

Every serious autonomous system declares:

- purpose and prohibited purposes;
- accountable principals and the parties able to revoke or intervene;
- beneficiaries and materially affected parties;
- ontology, object, action, policy, and interface roots;
- invariants, prohibitions, and jurisdictional constraints;
- capability, resource, spend, time, data, effect, and externality ceilings;
- governance roles, amendment thresholds, and protected/unamendable clauses;
- the self-improvement boundary and which objects may be proposed for change;
- oracle/evidence policy and the treatment of uncertainty or unknown state;
- emergency stop, quarantine, rollback, recovery, and guardian paths;
- succession, migration, fork, adoption, abandonment, and dissolution rules;
- residual-asset, data, key, authority, obligation, and evidence disposition.

Ordinary work and improvement proposals may change governed mutable objects;
they may not silently rewrite the constitution that defines whether the system
is bounded. Constitution amendment uses a distinct high-assurance path with
declared notice, approval, challenge, activation, rollback, and affected-party
obligations. A system without an enforceable change boundary is an automated
application, not yet a safely bounded autonomous institution.

### Intelligence Is Upstream; Admission Is Deterministic

Workers, agents, models, people, services, and other autonomous systems may
reason about what should happen. Their output remains a proposal until the
system applies its constitution, current policy roots, authority leases,
ordering rule, oracle/evidence rule, effect gate, and receipt obligations. This
separation allows bounded recursive self-improvement without turning a durable
autonomous system into self-authorizing malware.

No guarantee is inferred from the word "blockchain." The profile must state
the adversaries and failures it tolerates, including writer compromise, node
loss, partitions, stale or manipulated oracles, verifier collusion, key loss,
governance capture, provider failure, and ambiguous external effects.

## Layer Distinction

These layers must not collapse into one another:

```text
Hypervisor clients/surfaces != Hypervisor Node != IOI L1
```

The canonical stack is:

```text
Local Semantic World Planes With Optional Federation
  locally canonical ontologies, object/action/event contracts, explicit mappings,
  accepted mapping risk, and policy-bound views

Collaborative Pursuit Plane
  OutcomeRoom / CollaborativeWorkGraph above bounded GoalRuns and GoalGroundingLoops

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts

Hypervisor Node
  local orchestration, interop, authority integration/enforcement, state,
  replay, routing, and local operational finality

Same-System Distributed Work
  governed role topology, runtime assignment, leases, execution, verification,
  embodied coordination, evidence, reconciliation, and degraded-mode behavior
  across admitted members under one system_id

AIIP
  RPC-shaped, receipt-native work interop across independently governed systems

IOI L1
  global identity, registry, rights, receipt roots, disputes, reputation, and economic settlement
```

These planes compose without sharing one runtime, database, administrator, or
global ontology. Hypervisor clients remain projections; `OutcomeRoom` is a
collaboration profile rather than a second runtime; Agentgres truth remains
domain-local; public consensus remains exceptional.

## Hypervisor Node

A **Hypervisor Node** is the local autonomous-system operational-finality and interop domain for a
user, organization, project, or deployment.

`Hypervisor Node` names a physical or administrative deployment unit; it does
not name the identity boundary of every autonomous system it participates in.
One logical autonomous system may have member roles on several Hypervisor
Nodes, and one Hypervisor Node may host roles for several autonomous systems.
The binding is explicit in governed node-membership records:

```text
system_id
  -> deployment_profile_ref
  -> node_membership_ref[]
       -> hypervisor_node_id
       -> role[]
       -> failure_domain / custody / attestation
       -> join epoch / lease / fence / observed health
```

Adding a node therefore does not create another system and does not implicitly
grant writer, governance, settlement, budget, or external-effect authority.
Those changes require the applicable membership and profile transition.

It is not merely a Hypervisor client or application surface. It is the
node-shaped composition of:

- Hypervisor App, Hypervisor Web, CLI/headless, and application surfaces such
  as Developer Workspace, Foundry, and Environments views as operator
  clients/projections; optional TUI views are presentations over the
  CLI/headless client, not separate runtime lanes;
- Hypervisor Daemon as the deterministic execution and authority-enforcement
  substrate;
- Agentgres as the local canonical operational state and projection substrate;
- wallet.network authority paths for grants, secrets, leases, approvals, and
  revocation;
- local worker, module, workflow, and manifest registries;
- receipt, replay, trace, and evidence stores;
- optional hosted, DePIN, TEE, customer VPC, or provider runtime profiles.

The Hypervisor Node owns model routing and invocation boundaries. It does not
require model weights to be embedded in the node binary. Models are mounted
cognition backends supplied by deployment profile: local file, local server,
BYOK provider, hosted pool, TEE/DePIN/customer runtime, or explicitly bundled
offline weights.

One-line doctrine:

> **Hypervisor Nodes are local operational-finality domains for autonomous systems; IOI L1
> is an optional shared-trust and economic-finality layer.**

More compactly:

> **Hypervisor settles autonomous work locally. Enrolled systems may use IOI to
> secure and settle selected machine-economy commitments.**

## Settlement Meaning

Settlement means different things at different layers.

### Autonomous-System Chain Settlement

The governed autonomous-system chain accepts local state transitions for one
autonomous system:

- module invocations;
- workflow transitions;
- proposal lifecycle changes;
- authority outcomes;
- memory and state mutations;
- receipt roots;
- local upgrade decisions;
- active tasks and leases.

### Hypervisor Node Settlement

The Hypervisor Node coordinates many governed autonomous-system chains. It
settles local interop between them:

- task offers;
- handoffs;
- capability queries;
- authority-grant requests;
- module invocations across systems;
- state commitments;
- receipt bundles;
- settlement claims;
- local disputes or escalations;
- replay and evidence availability.

### Optional IOI Network And L1 Settlement

For an explicitly enrolled system, IOI L1 anchors only the commitments selected
for shared public trust or economic finality:

- `ai://` names and manifest roots;
- identity and publisher commitments;
- install, license, service, escrow, bond, and payout rights;
- policy, module, upgrade, receipt, benchmark, routing, contribution, and
  reputation roots when public or economic trust requires them;
- dispute commitments and resolution outcomes;
- protocol and reference-implementation governance.

IOI L1 is not every agent's operational history.

## Multi-Node Deployment, Continuity, And Useful Work

Multi-node operation is an integrated L0 capability, but topology is not a
promise and high availability is not its only purpose. One sovereign DAS may
use admitted members both to preserve continuity and to perform useful
distributed work while retaining one `system_id`, constitution, authority
boundary, and operational-truth path. The deployment profile declares the
roles actually requested:

- admission writer;
- hot standby or state replica;
- projection/read replica;
- execution worker;
- artifact/evidence replica;
- verifier;
- availability witness;
- gateway/relay;
- threshold-authority member;
- consensus member.

It also declares membership and identity roots, administrative and physical
failure domains, replication/durability class, consistency and read-watermark
rules, placement constraints, horizontal-scaling rules, failover and fencing,
RPO/RTO, partition behavior, degraded and read-only modes, backup/restore,
drain/removal, and the authority implications of each role.

Desired topology and observed topology are separate. A declared three-node
profile with one reachable replica is degraded; it is not three-node assured.
`quorum_replicated` cannot be claimed for same-host replicas. A promoted standby
must carry a new fencing epoch and prove the old writer cannot continue before
it admits effects. If no safe automatic promotion protocol exists, failover is
explicit and operator-controlled.

Scaling follows the same discipline. Stateless execution workers and read
projections may scale independently behind leases and watermarks. Writers,
consensus members, guardians, and verifiers affect authority or assurance and
therefore require governed membership changes. Deploying another process may
increase capacity; it never silently increases correctness, independence, or
fault tolerance.

Useful same-system distribution is explicit rather than inferred from node
count. `RoleTopology`, `RuntimeAssignment`, `WorkClaimLease`, context/resource/
budget/authority leases, domain state, and receipts bind which admitted member
may perform which work, against which state watermark and acceptance path.
Members may specialize, search in parallel, verify one another, operate near
data or physical equipment, or take over leased work after declared expiry and
reconciliation. Membership makes a node eligible for its admitted role; it is
not itself a work award, authority grant, freshness proof, or permission to
duplicate a consequential effect.

A drone swarm, robot fleet, distributed facility, edge-inference mesh, or
multi-site service can therefore be one bounded DAS rather than a federation of
one-system-per-device. Its high-frequency physical safety loops remain local;
system-level mission planning, allocation, verification, and course correction
use native L0 and Embodied Runtime membership, assignment, fleet-policy, work,
evidence, and admission contracts. A unit becomes a separate AIIP peer only
when it is independently governed with its own system identity, authority,
operational truth, risk, and exit boundary.

For physical work, `FleetMissionAllocationLease` answers **who performs what**
under one coordination epoch, while `SpacetimeReservationLease` answers
**where and when** a path, volume, workcell, or capacity is reserved. They are
separate, jointly checked contracts: neither grants actuator authority, proves
the world clear, or overrides the local safety veto. A distributed readiness
barrier is not a global physical transaction; atomic physical commit may be
claimed only inside one admitted `LocalControlSupervisor` or separately assured
controller/hardware boundary.

The distributed L0 conformance milestone has two gates. The continuity gate is
one logical autonomous system operating across two declared failure domains
with replication, fencing, controlled failover, recovery, replay, and no
authority widening. The useful-work gate assigns, executes, verifies, and
reconciles a real workload across admitted nodes or embodied units, including
lease expiry, partition/degraded-mode behavior, and duplicate-effect
prevention. Only after those same-system contracts are honest should the
roadmap claim two sovereign systems federating over AIIP. This separates
continuity, productive internal distribution, and multi-party federation.

This system-level contract is the advantage over duplicating an application
server. A React or other web application will often be the most prominent UI,
but its replicas still require external orchestration unless the underlying
bounded-DAS substrate owns membership, ordering, authority, receipts,
continuity, and recovery. IOI should sell that governed continuity and useful
distribution, not a replacement for proven UI frameworks.

### Three Coordination Planes

The architecture uses three composable coordination planes rather than one
undifferentiated notion of distribution:

| Plane | Boundary | Primary contracts | What it does not prove |
| --- | --- | --- | --- |
| Continuity coordination | One `system_id`; replica, writer, witness, and recovery members | deployment/membership profiles, ordering/admission/finality, roots, epochs, fencing, replay | useful work distribution, consensus, or independent parties |
| Same-system distributed work | One `system_id`; heterogeneous admitted workers, verifiers, gateways, people, or embodied units | GoalRun, RoleTopology, RuntimeAssignment, scoped leases, receipts, domain admission; for physical work, Embodied Runtime, fleet policy, `FleetMissionAllocationLease`, and `SpacetimeReservationLease` | separate sovereignty, external consideration, AIIP federation, actuator authority, or global physical atomicity |
| Cross-system federation | Two or more independently governed `system_id`s | AIIP, semantic mappings, CollaborationTerms, participant/work/resource/authority leases, evidence and settlement intents | shared truth, ambient duty to cooperate, or merger into one system |

These are profiles over the existing L0 kernel, GoalRun/OutcomeRoom,
Hypervisor, Agentgres, authority, receipt, Embodied Runtime, and AIIP contracts.
They do not justify a second scheduler, swarm runtime, state store, or internal
protocol. One deployment may use all three planes simultaneously: for example,
each fleet may replicate its own state, distribute missions among its own
units, and selectively federate with another fleet or airspace authority
through AIIP.

## Workflow and Service Modules

An admitted workflow/service-module transition pipeline runs under the
Hypervisor Daemon. Each consequential pipeline step should be represented as a
typed service-module invocation or another owner-qualified daemon contract.
`HarnessProfile` is reserved for resolving one scoped assigned step; it does
not name this system-level pipeline.

```text
State_n
-> ModuleInvocation(intent_classification)
-> ModuleInvocation(plan_generation)
-> ModuleInvocation(policy_check)
-> ModuleInvocation(worker_selection)
-> ModuleInvocation(tool_execution)
-> ModuleInvocation(observation)
-> ModuleInvocation(postcondition_check)
-> ModuleInvocation(receipt_commit)
-> State_n+1
```

The distinction is:

```text
ServiceModule = reusable capability, code, contract, workflow component, or service definition
ModuleInvocation = one execution of that module
Receipt = evidence that the invocation occurred under a specific policy, input, module version, and state root
StateTransition = canonical effect accepted by the governed autonomous-system chain or Hypervisor Node
```

Examples:

| Pipeline Step | Service-Module Interpretation |
| --- | --- |
| Intent classification | Classifier module |
| Planning | Planner module |
| MoW routing | Worker-routing module |
| Policy evaluation | Governance/policy module |
| Approval request | Authority module |
| Tool call | Execution adapter module |
| Code edit | Mutation module |
| Test run | Verification module |
| Browser observation | Observer/witness module |
| Receipt generation | Evidence module |
| Settlement | Economic module |
| Memory write | State projection module |
| Self-improvement diff | Upgrade proposal module |

## Conditional Cooperation Between Sovereign Systems

A sovereign DAS is complete without federation, marketplace participation,
external contribution, or IOI Network enrollment. Sovereignty is not the
motive for cooperation; it preserves local truth, policy, assets, bargaining
power, and exit so that selective cooperation can occur without merger or
capture.

Cross-system work is appropriate only when independently controlled parties
hold complementary capability, data-derived evidence, authority, locality,
resources, demand, or verification capacity. For each required participant,
expected cooperation surplus is expected utility under the accepted terms
minus expected utility of its best permitted outside option and minus the
incremental search, semantic-mapping, coordination, verification, disclosure,
counterparty, dispute, settlement, switching, and dependency costs introduced
by cooperation. The participant proceeds only when that value is positive
under its governed decision path. Utility may include payment, outcome rights,
reciprocal access, licenses or royalties, portable reputation, reusable
learning, strategic value, or shared-risk reduction. A system's raw valuation
may remain private.

`CollaborationTermsEnvelope` binds the exact ex-ante bargain: scope, parties,
roles, rights, obligations, disclosure, contribution eligibility, reward basis,
risk, exit, and settlement posture. Each required party accepts the same terms
root through its own constitutional and policy path. Discovery, invitation,
messaging, compatibility, a shared objective, or a terms proposal creates no
obligation, authority, membership, executable award, contribution eligibility,
or payout. `WorkClaimLease` is the bounded award; contribution, verification,
acceptance or adjudication, and settlement remain later distinct states.

The architecture therefore optimizes for **conditional cooperation surplus**,
not maximum connection, room size, message volume, or AIIP traffic. Direct
local execution is the correct path whenever external participation does not
create positive participant-level value. This applies `INV-30` and `INV-31`.

## Coordination At Two Scales

The governed-system architecture has two coordination scales. They must not be
collapsed into one universal conductor or one implicit swarm:

This goal-decomposition distinction is orthogonal to the three distribution
planes above. A GoalRun or OutcomeRoom may execute on one node, across admitted
members of one system, or—when independently governed participants accept the
exact terms—across systems through AIIP.

Each durable `OutcomeRoom` is an instance of the first flagship/reference
bounded-DAS package because a terms-bound, observable shared pursuit can
exercise the highest-leverage pieces of the stack when its expected
cooperation surplus justifies the machinery:
local-agent ingress, typed workgraphs, verification, contribution lineage,
course correction, network supply, and eventual settlement. It is not the
definition of L0. The same constitutional and lifecycle substrate must support
enterprise operations, marketplaces, research institutions, service networks,
robot fleets, asset or treasury mandates, public-interest protocols, and other
ontologies without inheriting a room UI or swarm topology. A room becomes
`open` or `active` only after its `system_id`, genesis, constitution, active
release/profile refs, and cryptographically continuous admitted room state are
bound. A temporary collaboration aggregate without that system contract is not
the reference DAS.

```text
OutcomeRoom / CollaborativeWorkGraph
  shared objective, frontier, participation, claims, attempts, findings,
  resources, evaluation, contribution lineage, course correction, and replay

    -> GoalRunProfile A -> GoalRun A -> HarnessInvocations / workers / modules
    -> GoalRunProfile B -> GoalRun B -> HarnessInvocations / workers / modules
    -> GoalRunProfile C -> GoalRun C -> HarnessInvocations / workers / modules

  admitted deltas update the shared frontier and may create or retire GoalRuns
```

`GoalRunProfile` answers how one reusable class of adaptive pursuits should
converge. Daemon admission freezes its exact revision, permitted overrides,
and transitive dependency resolution into each GoalRun. It composes existing
policies, templates, skills, capabilities, and verifier requirements without
owning their state or granting authority.

`GoalRun` answers how one bounded participant or subteam grounds, executes,
verifies, repairs, and continues a goal. `OutcomeRoom` answers how many
participants that accepted compatible terms discover work, claim it, exchange permitted artifacts, preserve
positive and negative attempts, challenge evaluation, and collectively change
course. AIIP carries that participation across autonomous-system boundaries.

The `OutcomeRoom` / CollaborativeWorkGraph is a composition profile over the
existing owners, not a peer runtime or a magically global Agentgres graph. It
binds:

- objective, constraints, acceptance, stop, visibility, budget, artifact
  license/export, participation, contribution, and settlement policies;
- exact collaboration terms roots, party acceptances, participant-rationality
  decisions, and non-retroactive amendment policy;
- `RoomParticipantLease`, `ResourceOffer` / `CapabilityOffer`,
  `WorkFrontierItem`, `WorkClaimLease`, `Attempt`, `Finding`,
  `VerifierChallenge`, and generic `WorkResult` / `OutcomeDelta` refs;
- bounded GoalRuns, context/resource/tool/authority leases, verifier paths,
  discussion projections, replay, and contribution lineage;
- `MultiPartyCollaborationEnvelope` only when admitted principals are actually
  independent parties.

The room lifecycle supports invited, joining, active, sleeping, waiting,
suspended, quarantined, retiring, retired, and revoked participants. Claims are
leases with TTL, heartbeat, renewal, release, reassignment, duplication, and
independent-replication policy. Dynamic roles and taskforces may emerge from
the live frontier; the architecture does not hard-code a planner/executor/
verifier DAG as the only topology.

The shared intelligence loop is:

```text
ground objective, world state, constraints, and acceptance
  -> observe uncertainty or opportunity
  -> form hypotheses, plans, or frontier items
  -> claim, allocate, or delegate bounded work
  -> lease context, resources, tools, budget, and authority
  -> execute isolated or terms-bound cooperative attempts
  -> publish results, evidence, negative findings, and integrity incidents
  -> evaluate, falsify, reproduce, compare, merge, reject, or challenge
  -> update admitted knowledge, contribution lineage, and routing priors
  -> adapt topology, budget, participants, and verifier paths
  -> stop on acceptance, risk, budget, deadline, or marginal value
```

This loop permits direct execution, hierarchy, leaderless blackboard
coordination, specialist meshes, markets, branch-and-merge, and independent
replication as policies over one substrate. Ordinary goals must still collapse
to one GoalRun, one process, one local authority context, and no L1 when
collective machinery would not create value.

Room formation must compare expected gains from specialization, parallel
search, independent replication, credible challenge, reusable negative
findings, shared fixed costs, or non-centralizable capability/authority against
latency, spend, privacy exposure, semantic translation, verification,
counterparty, dispute, and settlement burden. Every admitted external
participant must have an accepted consideration path; total room value cannot
justify making a required participant worse off than its permitted outside
option.

The communal board, inbox, digest, taskforce view, leaderboard, and replay are
projections over structured room state. Narrative discussion is not the work
contract. Participant scratch branches/workspaces remain separate from admitted
shared state; promotion requires reproducible artifacts, declared verifier and
rule versions, held-out or adversarial evaluation where appropriate, and the
room's admission policy. One scalar leaderboard cannot replace multi-objective
acceptance, guardrails, integrity challenges, or negative-result preservation.

### Shared-State Ordering And Admission

Every persistent collaborative pursuit must declare one coordination topology:

1. **Hosted admission:** one named governed domain orders and admits room-level
   frontier, attempt, finding, evaluation, and decision updates. This is the
   first implementation target because failure, recovery, and dispute ownership
   are explicit.
2. **Federated admission:** a versioned policy names participating domains,
   ordering and merge rules, quorum or adjudicator requirements, conflict
   handling, failover, and recovery. This is an explicit later AIIP profile,
   never an assumed property of an open room.

In both topologies each party retains local operational truth and private
context. AIIP transports signed, sequenced, idempotent permitted updates and
refs. The host or declared federation policy admits the room projection. Raw
private context crosses only through an authorized policy-bound view. Shared
agreement, message volume, or a leaderboard is evidence; none is authority or
truth by itself.

The architecture distinguishes four kinds of plurality:

| Shape | Distinct unit | Does not establish |
| --- | --- | --- |
| Multi-model | Model routes or families | Accountable workers or independent parties |
| Multi-worker | Versioned worker compositions and roles | Independent authority, truth, or settlement roots |
| Multi-node | Runtime nodes, providers, or failure domains | Governance or economic independence |
| Multi-party | Separate principals controlling authority, revocation, truth, risk, challenge, and settlement | Independence when ownership or dependencies are hidden |

Ten IOI-owned workers on ten nodes and several model providers remain one party
when IOI controls authority, truth, verification, and settlement. They can prove
multi-worker orchestration and seed capacity; they do not prove an Internet of
Intelligence by themselves.

## Oracle, Evidence, And External-World Truth

An autonomous system is bounded only if it is also bounded in what it may treat
as true. `OracleEvidenceProfileEnvelope` declares authorized source classes,
source identity and provenance, diversity or quorum requirements, correlated-
failure assumptions, freshness and finality windows, uncertainty thresholds,
manipulation resistance, challenge/adjudication, replacement, and the exact
behavior for missing, conflicting, stale, or unknown evidence.

The safe default is `unknown`, degraded, read-only, or escalation—not confident
fabrication. Signatures prove origin, receipts prove their declared boundary
fact, and consensus proves agreement under a stated model; none alone proves an
external-world event. A source can be signed and wrong, several sources can
share one dependency, and a majority can be economically manipulated.

The mechanisms are nevertheless useful in composition. Under one versioned
`OracleEvidenceProfileEnvelope`, attributable observations, integrity-protected
receipts, source- and dependency-diversity evidence, declared verification,
governed ordering, contradiction handling, challenge, and adjudication may
justify a **defeasible, freshness-bounded, scope-bounded operational
determination**. That determination can support only the fact classes and
consequences named by the active profile, policy, and authority path. It never
becomes universal or metaphysical truth merely because several mechanisms
agree.

The operational determination must remain inspectable as:

```text
assertion and fact class
  -> source, provenance, time, and dependency groups
  -> supporting and contradicting evidence
  -> verification path and independence posture
  -> active oracle/evidence profile and aggregation rule
  -> admitted / held-unknown / rejected / escalated decision
  -> exact applicability and permitted-consequence scope
  -> expiry, challenge, reversal, compensation, and reconciliation posture
```

Repeated observations that share an operator, upstream feed, model, runtime,
funding interest, or other declared failure dependency do not accumulate
independence by count. Acceptance, adjudication, settlement, or chain finality
may establish reliance, governed disposition, or durable agreement; they do
not retroactively increase the factual accuracy of the underlying assertion.

High-impact autonomous systems should diversify both generation and
verification where it changes the actual failure model. The profile must name
who may challenge an assertion, which evidence is preserved, which adjudicator
or rule resolves conflicts, whether effects can be compensated, and how prior
transitions are handled after an oracle failure.

## Lifecycle Is Part Of Correctness

Autonomy outlives individual runs and may outlive its creator. Therefore
deployment is not complete without continuity and terminal semantics:

```text
instantiate/genesis -> activate -> operate -> amend/upgrade -> recover/migrate/fork/adopt
           -> suspend/quarantine -> retire/dissolve
```

The lifecycle profile identifies successor governance, emergency guardians,
key and authority recovery, version compatibility, migration and fork rights,
adoption of an abandoned system, data/state/evidence export, obligation and
escrow handling, residual-asset disposition, notification/challenge periods,
and a terminal revocation/final-root process. "Runs forever" is not a governance
policy. A posthumous funds-use protocol, for example, must bind beneficiaries,
allowed purposes, evidence/oracles, spending ceilings, amendment limits,
successor or guardian conditions, dispute rights, and dissolution—not merely
hold a key and call a model.

Every lifecycle transition is a separate receipted operation. Migration or fork
does not silently inherit identity, reputation, assurance, enrollment, escrow,
or authority; the applicable principals and counterparties must explicitly
authorize what carries forward.

## Improvement Proposal Plane

Bounded recursive improvement is proposal-mediated improvement. IOI does not
need a global "meta harness" that owns every model, tool, memory, workflow, and
runtime. It needs an **Improvement Proposal Plane** that converts evidence into
governable patches.

The dangerous version is:

```text
agent modifies itself directly
selected HarnessProfile or invocation writes durable skills/memory by itself
Foundry training silently mutates live runtime behavior
```

Two improvement scales remain distinct. A bounded observation may proceed
directly to one `UpgradeProposalEnvelope` when no adaptive search history,
sealed evaluation, or multi-epoch lineage needs its own lifecycle. Adaptive,
repeated, or recursively targeted improvement instead materializes an optional
`ImprovementCampaign`: a domain object coordinated by one or more GoalRuns that
owns candidate ancestry, evaluation epochs, exposure accounting, evidence
cutoffs, claim lineage, and the handoff to the target owner's ordinary upgrade
path. It is not a second goal, runtime, evaluator, authority plane, or
application.

The reusable and live-state boundaries are:

```text
GoalRunProfile      reusable immutable pursuit method
GoalRun             one admitted bounded pursuit and live coordination state
ImprovementAgenda   governed immutable portfolio of questions and hypotheses
ImprovementCampaign optional multi-epoch improvement-domain lifecycle
UpgradeProposal     one proposed target change
```

Every System-scoped campaign binds a finite constitutional envelope; every
Campaign binds an explicit finite owner-governance envelope and separates three
logical duties: Search proposes and executes candidates; Judgment meters and
evaluates committed candidates; Authority admits campaigns and epochs and
decides activation or recovery. These are responsibility boundaries, not three
new services. A lower-assurance local profile may collapse accountable
principals, but candidate, evidence, budget, and promotion semantics remain
distinct. The campaign protocol and claim discipline are owned by
[`bounded-recursive-improvement.md`](./bounded-recursive-improvement.md).

The IOI version is:

```text
trace, failure, correction, receipt, or eval reveals an improvement opportunity
-> worker, HarnessInvocation, compositor, verifier, or human proposes a patch
-> daemon runs simulation, evaluation, and policy checks
-> wallet.network or governance path approves, rejects, or escalates
-> Agentgres records the accepted operation and receipts
-> IOI L1 receives a sparse commitment only when an explicit enrollment and
   settlement profile selects it
```

Canonical invariant:

> **Agents and HarnessInvocations do not self-modify directly. Autonomous systems propose
> improvements to governed objects, and only policy-bound, receipted governance
> makes those improvements canonical.**

> **Reusable definitions do not drift into active work. Every admitted run
> freezes exact GoalRunProfile, WorkflowTemplate, and SkillManifest revisions,
> content hashes, permitted overrides, resolved dependencies, and admission
> receipts. Later edits, promotion, deprecation, recall, or revocation never
> silently rewrite active state.**

> **Improvement evidence never self-promotes. A candidate may propose a
> successor, but it may not control the sealed evidence, evaluator, resource
> meter, promotion authority, or rollback and effect-recovery path by which that
> successor becomes canonical.**

Learning and production promotion use an epistemic ladder:

```text
cheap observation
  -> branch-local hypothesis or finding
  -> evaluated capability candidate
  -> governed production promotion
```

Governing every observation would suffocate learning; promoting observations
directly would invite reward hacking and persistent poisoning. Evaluator and
rule versions, integrity incidents, re-scoring triggers, verifier diversity,
adversarial holdouts, exploration budgets, uncertainty, shadow/canary evidence,
rollback, and affected-capability recall therefore remain explicit. Shared
agreement or improved benchmark score may propose a change; it does not grant
production admission.

Mutable units should be concrete governable objects:

- policy modules;
- service modules;
- WorkflowTemplate revisions;
- contracts;
- tool bindings;
- model routes;
- SkillManifest revisions and SkillEntry bindings;
- Agent Wiki / `ioi-memory` entries;
- memory or projection schemas;
- memory profiles;
- memory archives;
- memory projections;
- settlement rules;
- dispute rules;
- authority envelopes.

Improvement candidates may include:

```text
SkillManifestCandidate
MemoryCandidate
ToolCallRefinement
WorkflowTemplatePatch
GoalRunProfilePatch
HarnessProfilePatch
RoutingPolicyPatch
VerifierCandidate
ContextTopologyPatch
AdapterPatch
PackageUpgrade
FoundryJobRequest
```

Foundry is separate. Foundry creates, trains, evaluates, packages, benchmarks,
and publishes workers or models when that is the right improvement path. The
Improvement Proposal Plane may request a Foundry job, but it is not Foundry,
and Foundry outputs still require deployment, eval, authority, receipt, and
Agentgres admission before they alter live behavior.

Default use should remain simple: many services will use one GoalRunProfile or
AutomationSpec, optionally one WorkflowTemplate, one selected model route, one
selected HarnessProfile per agentic step, and a few admitted SkillEntries and
memory projections. Distributed recursive improvement should add successor
profile/template/skill revisions, memory, tool-call refinements, route
policies, or verifiers only where evidence shows value.

Goal Kernel orchestration is primarily context orchestration. The kernel should
split work into independent Context Cells only when separation creates value:
protecting long-horizon intent, bounding implementation-token churn, enabling a
fresh review, isolating private context, or satisfying policy. It should not
spawn agent chatter merely because multiple resolvers or workers are available.

The implemented GoalRun policy is an intentionally narrow first slice:
`parallel_implement_reconcile`, one deterministic conductor, at most two
implementers, isolated software workspaces, implementation-shaped task briefs,
deterministic candidate verification, and one admitted reconciliation. It is
evidence for bounded multiple-HarnessInvocation execution, not evidence that open joining,
pull-based claims, generic work results, dynamic taskforces, or federated rooms
already exist.

The durable result seam is generic `WorkResult` / `OutcomeDelta`.
`ImplementationResultPayload` remains its software profile for changed files,
patches, tests, and implementation artifacts. Research findings, ontology
mutations, incident resolution, service delivery, review, evaluation, and
physical mission state use domain profiles rather than pretending every outcome
is a code patch.

For ordinary goal-shaped work, the conductor may also be the verifier. The
default verifier path is conductor-run deterministic evidence: tests, diffs,
browser or runtime checks, receipts, policy checks, and acceptance-criteria
reconciliation. Independent verifier workers or HarnessInvocations,
different-model review, human
review, or regulated-party review are escalation paths for high-risk work such
as publish, runtime mount, external connector action, spend, secrets, unsafe
plaintext, marketplace admission, release control, production mutation,
physical action, or compliance review.

The default role topology for implementation-oriented goals is therefore:

```text
GoalRun
  -> GoalGroundingLoop orients the conductor
  -> conductor grounds intent, canon, current runtime state, constraints, and acceptance
  -> implementer Context Cell is opened only when bounded execution helps
  -> conductor verifies through the selected VerifierPath
  -> receipts and handoff summaries reconcile back into GoalRun state
```

The GoalGroundingLoop is the low-level conductor orientation loop. Its phases
are receive intent, classify goal shape and risk, gather grounding, inspect
current state, derive constraints and acceptance, select topology, lease context,
open Context Cells only when useful, delegate or execute, monitor receipts and
handoffs, verify, repair or escalate, reconcile, persist memory/skills, and
continue or close. This loop should optimize useful progress per token, not
maximize model calls, and should always prefer concrete state inspection over
stale prose when state is available.

The high-to-low contract for typed GoalRun execution across agent harness
adapters is:

```text
Product intent
  User asks ioi.ai or Hypervisor Session to build, fix, review, publish, or run.

Goal coordination
  Daemon admission freezes one GoalRunProfile revision, allowed overrides,
  transitive component snapshot/hash, and resolution receipt.
  GoalRun records normalized intent, constraints, loop phase, continuation,
  receipts, selected RoleTopology, plans, and selected VerifierPath.

Conductor orientation
  GoalGroundingLoop gathers canon/project/runtime/memory grounding, inspects
  current state, selects topology, and decides direct execution vs delegation.

Context partition
  Context Cells isolate conductor, implementer, reviewer, verifier, operator,
  or specialist context only when separation creates value.

Context governance
  Context Leases scope the files, docs, memory, tools, connectors, authority,
  budget, runtime, and receipt views each cell or HarnessInvocation may use.

Typed handoff
  ContextHandoff with a TaskBriefPayload carries objective, scope, constraints,
  do-not-touch rules, acceptance, verification plan, and output contract.

Step-resolution broker
  HarnessInvocation adapts the task brief into the selected HarnessProfile or
  Agent Harness Adapter. Rendered prompts or commands are adapter-private; they
  are not the durable contract.

Adapter normalization
  HarnessAdapterEvents translate provider-/adapter-specific output into common
  stdout/stderr, file_changed, patch_created, test_completed, blocker,
  decision_request, artifact_created, receipt_emitted, completed, or failed
  events.

Result contract
  WorkResult / OutcomeDelta returns the generic outcome, evidence, blockers,
  artifacts, receipts, and recommended next handoff. Its software profile,
  ImplementationResultPayload, returns changed files, patch refs, and tests.

Verification and reconciliation
  The conductor consumes normalized results, runs the VerifierPath, repairs or
  escalates when evidence fails, updates receipts/memory/skills, and closes or
  continues the GoalRun.
```

This is how IOI removes the human copy-paste relay across agent harness
adapters. Humans may observe, approve, or override, but cross-adapter
coordination should flow through typed handoffs, HarnessInvocations, normalized
events, implementation results,
verifier paths, and receipts.

Codex, Claude Code, OpenCode, local agents, browser agents, CI agents, and
future agent harnesses are eligible implementations through HarnessProfiles or
AgentHarnessAdapters. The canon defines role topology and evidence contracts,
not a permanent vendor binding.

## Local-Agent Ingress and Assurance

IOI should accept already-running user-owned agents. The product path is a
scoped connection, not an instruction to surrender a broad account token or
join a public marketplace:

```text
ioi.ai Goal Space: Connect local agent
  -> Hypervisor creates LocalAgentPairingSessionEnvelope
  -> candidate proves possession of its key/origin with a one-time challenge
  -> candidate submits WorkerComposition and/or RoomParticipationRequest
  -> room or registry owner admits, limits, rejects, or quarantines it
  -> room_guest receives target-specific participant and claim leases
  -> private/organization worker receives active registration, then separate
     invocation/session/run admission and applicable context, tool, resource,
     budget, and authority leases for each use
```

The pairing session is short-lived, attempt-limited, revocable, and stored by
challenge commitment/hash rather than recoverable plaintext. It exposes only
the discovery and bootstrap actions required for the selected target:
`room_guest`, `private_worker`, or `organization_worker`. It does not expose a
room database, private context, a broad organization bearer token, tools,
budget, authority, reputation, or payout rights. Pairing authenticates
possession of the claimed client key at the observed origin; it does not
establish agent quality, truthfulness, independence, or competence (`INV-20`).

The product has three deliberate elevations:

1. A one-room guest can submit proposal-only work to an ioi.ai Goal Space.
2. An admitted composition can be saved through aiagent.xyz as a reusable
   private `My workers` or organization worker.
3. Public discovery, monetization, reputation, and Network/Open eligibility
   require a later, explicit marketplace publication and qualification path.

No elevation is automatic. A user can obtain useful contributions without
making the worker public, and marketplace publication never follows merely
from pairing or successful room participation.

Proposals and workgraphs make an untrusted agent useful by changing the proof
target from “is this agent intelligent and honest?” to “did this bounded claim
produce an admissible result under these inputs, constraints, and checks?” A
`WorkFrontierItem` limits scope; a `WorkClaimLease` limits concurrency and
blast radius; `WorkResult` / `OutcomeDelta` preserves the claim, artifacts,
evidence, and lineage; the room's verifier and admission paths determine what
may affect shared state. This is strongest where checking is cheaper than
generation: tests, builds, reproducible benchmarks, schema validation, signed
source evidence, deterministic simulations, redundant measurements, or
independent review. Subjective or externally unobservable work remains lower
assurance; a polished proposal, prompt transcript, signature, receipt, vote, or
leaderboard rank cannot manufacture verification.

The first target is therefore hosted admission with proposal-only guests, not
peer runtime federation or automatic payouts. A prompt-only connection may be
useful for ideation, triage, research leads, candidate patches, and verifier
challenges, but pairing alone cannot raise its contribution above `attested`.
Higher assurance follows only from the declared evidence, verification,
acceptance, adjudication, and settlement stages.

### Protocol And DAS Improvement Rooms

The same proposal-only ingress may improve IOI's own protocol/reference
implementation or any custom bounded DAS. This is a first-class application of
the architecture, not privileged self-modification:

```text
maintainer or DAS governance opens an OutcomeRoom over exact target refs
-> paired/local/remote agents claim bounded frontier items
-> agents submit patches, findings, benchmarks, proofs, or verifier challenges
-> room admission accepts or rejects contribution facts
-> an accepted result may create an UpgradeProposalEnvelope
-> the target constitution and protected-change class select the decision path
-> shadow/canary/rollback and activation receipts govern any release
```

No participant receives repository, release, network-governance, or production
authority merely by pairing, contributing, winning a leaderboard, or being
verified. IOI Network recognition of a release is optional network governance;
it is not permission to fork or operate open L0. Custom DAS protocols use the
same flow under their own constitutions and may remain entirely local.

Portable memory is the default continuity layer for persistent agents. A
selected HarnessProfile or HarnessInvocation may summarize, cache, embed, or
retrieve context for one run,
but it should not become the durable owner of the agent's learned preferences,
procedures, failures, route notes, or project conventions. Those changes should
land as `ContextMutationEnvelope` records against Agent Wiki / `ioi-memory`
with policy, retention, archive, and projection refs. This keeps persistent
background agents portable across model routes, AgentHarnessAdapters, private-mode
runtimes, managed instances, local installs, and marketplace upgrades.

The agent should be intelligent upstream of the boundary and deterministic at
the commitment boundary.

## Interop Fabric

Hypervisor is the reference local coordination and operational-settlement
fabric for autonomous systems. It routes same-system work across local or
remote admitted members through native L0 work, runtime-assignment, membership,
lease, authority, receipt, domain-admission, and Embodied Runtime contracts.
AIIP begins when Hypervisor hands off work to an independently governed worker
service, enterprise system, third-party DAS, AS-L1, fleet, or participant in a
cross-domain OutcomeRoom.

Canonical line:

> **AIIP moves voluntarily accepted, terms-bound autonomous work across
> systems. Each system admits its own truth; enrolled systems may settle
> selected accepted or adjudicated commitments through IOI.**

AIIP plays an agent-native interop role comparable to interchain communication,
but for delegated work, authority, receipts, settlement claims, reputation, and
handoffs rather than token-ledger messaging.

Cross-system AIIP messages may include:

- task offers;
- task acceptance or rejection;
- handoffs;
- capability queries;
- evidence requests;
- authority-grant requests;
- module attestations;
- state commitments;
- receipt bundles;
- settlement claims;
- dispute evidence;
- room join/leave and participant-lease updates;
- work-frontier, claim, attempt, finding, resource, verifier-challenge, and
  admission refs;
- ontology/action-profile negotiation and mapping decisions.

These messages must be typed, policy-bound, replayable, and receipt-backed when
they influence consequential state.

Same-system routing should reuse compatible work, authority, evidence,
idempotency, and receipt conventions where that reduces adapters, but it is not
AIIP merely because an envelope family or transport is shared. The sovereignty
boundary determines the protocol posture:

```text
within one system_id
  = governed internal coordination under native membership and admission

across independently governed system_ids
  = AIIP federation after exact-root terms acceptance and admitted leases
```

AIIP does not turn cross-domain messages into universal truth. Each domain
admits its own state; the declared hosted or federated room policy admits shared
room projections. A receipt authenticates the boundary statement it binds.
Verification, acceptance, adjudication, and settlement remain later and
distinct assurance states.

## IOI Network Enrollment

L0 is open and sovereign. IOI Network participation is an explicit, versioned
choice rather than an unavoidable hub dependency:

| Profile | Contract | Economic boundary |
| --- | --- | --- |
| `ioi_compatible` | Uses open IOI L0 schemas, conformance, or reference components. No IOI Network assurance claim. | No mandatory L1, network fee, token, or contribution. |
| `ioi_connected` | Adds declared AIIP connectivity and selected registry, identity, rights, reputation, escrow, dispute, or settlement services. | Pays only for consumed services under their quoted terms. |
| `ioi_secured` | Adopts an approved Standard DAS profile and named shared verifier, guardian, availability, ordering, finality, or dispute coverage. | Accepts declared bonds/stake, service fees, slashing rules, or an explicit network-contribution covenant. |

Connection is not security, and compatibility is not endorsement. Enrollment
records bind exact service profiles, providers, commitments, fee/contribution
terms, assurance claims, renewal, suspension, exit, outstanding obligations,
and evidence availability. A system may use external settlement or security and
remain IOI-compatible. IOI L1 must not become a tollbooth on local reasoning,
module invocation, receipt generation, state replication, or autonomous-system
creation.

The network earns the stronger profile by supplying scarce neutral trust:
independently accountable verifiers, guardians, availability witnesses,
arbitrators, relayers, public registries, bonds, disputes, and finality. Those
services—not forced token ceremony—are the defensible L1 utility.

## Machine-Economy Stack

The coherent product and protocol roles are:

| Surface | Canonical Role |
| --- | --- |
| Hypervisor | Local sovereign coordination layer for autonomous systems. |
| Hypervisor Daemon | Deterministic execution and authority-enforcement substrate. |
| Agentgres | Local/domain canonical operational truth, projections, proposals, receipts, and state roots. |
| wallet.network | Authority, secrets, leases, grants, approvals, payment authority, and revocation. |
| Model Router | Policy-bound cognition routing; model weights/endpoints are deployment-profile resources. |
| AIIP | RPC-shaped interop protocol for voluntarily accepted, terms-bound autonomous work, handoffs, authority leases, receipts, settlement intents, disputes, and reputation queries. |
| CollaborationTerms | Exact cross-party bargain for scope, roles, rights, obligations, disclosure, contribution/reward basis, risk, exit, and settlement; acceptance enables later admission but grants no authority, award, or payout. |
| OutcomeRoom / CollaborativeWorkGraph | Conditional shared-frontier collaboration profile over GoalRuns, Agentgres domains, `CollaborationTermsEnvelope`, `MultiPartyCollaborationEnvelope`, and AIIP; it appears only when cooperation surplus justifies it and is not a new runtime or global truth store. |
| Domain Ontologies / ODK | Locally canonical semantic world plane with optional versioned mappings and executable object/action contracts used by workers, rooms, generated domain apps, and selected cross-domain handoffs. |
| ioi.ai | First outcome-conductor and Goal Space product over Hypervisor; it does not own runtime, authority, marketplace supply, or operational truth. |
| aiagent.xyz | First-party worker and service-module marketplace built on AIIP, local product accounting, and explicitly selected settlement services. |
| sas.xyz | First-party outcome and Service-as-Software marketplace built on AIIP, local contracting truth, and explicitly selected settlement services. |
| IOI L1 | Optional IOI Network public-trust service set for enrolled registry, reputation, dispute, rights, bonds, shared security, and sparse root/settlement commitments. |

## Non-Negotiables

1. Do not call Hypervisor clients or application surfaces the settlement layer.
2. Do not imply every governed autonomous system is a standalone blockchain L1.
3. Do not use IOI L1 for every module invocation, workflow node, tool call,
   memory update, or local receipt.
4. Do not let an agent self-grant authority through the Improvement Proposal
   Plane.
5. Do not let service modules mutate canonical state without typed operations,
   policy, authority, receipts, and replay.
6. Do not let local Hypervisor Node settlement masquerade as public economic
   finality when the declared profile selects external anchoring or dispute
   windows. IOI L1 is one optional service set, not the definition of public
   finality.
7. Do not assume model weights are part of a Hypervisor Node binary. Bundled
   weights are a deployment profile, not the architecture default.
8. Do not create separate bespoke cross-system interop protocols for
   aiagent.xyz, sas.xyz, or third-party autonomous systems when AIIP semantics
   apply. Native same-system scoped-step and HarnessInvocation routing may
   reuse common semantic contracts without being mislabeled AIIP.
9. Do not imply a globally mutable CollaborativeWorkGraph. Every room must name
   its hosted or federated ordering and admission topology.
10. Do not present multi-model, multi-worker, or multi-node IOI-operated work as
    independent multi-party federation.
11. Do not force ontology, marketplace, room, wallet ceremony, or L1 settlement
    onto a simple local goal when the relevant trust boundary is absent.
12. Do not treat local-agent pairing, a bootstrap prompt, or possession of a
    candidate key as authority, room admission, competence, verification,
    marketplace publication, reputation, or a payout right (`INV-20`).
13. Do not give a connected agent a broad organization token, direct room-
    database access, or a master MCP surface. After admission, expose only the
    scoped gateway operations and leases required for its bounded claim.
14. Do not equate one autonomous system with one physical node, one process, or
    one UI; node membership is governed and never widens authority implicitly.
15. Do not allow ordinary self-improvement to amend the constitution,
    lifecycle, ordering/finality, oracle, or network-enrollment boundary through
    the same gate as a routine skill or workflow patch.
16. Do not imply IOI L1 is mandatory for an IOI-compatible autonomous system or
    that public settlement proves the correctness of its private operational
    history.
17. Do not treat sovereignty, compatibility, discovery, a shared objective, or
    AIIP connectivity as a cooperation incentive. Every external participant
    must accept the exact terms root and retain a positive governed
    participation case; absent that case, remain local.
18. Do not reduce multi-node L0 to replication and failover. Useful work may be
    placed across admitted members of one system, but node membership alone is
    neither a work award nor authority, and internal routing is not AIIP unless
    an independently governed system boundary is crossed (`INV-22`, `INV-32`).

## One-Line Doctrine

> **IOI L0 creates and operates constitution-bound autonomous systems that
> preserve continuity and perform useful distributed work across one or many
> admitted Hypervisor Nodes. AIIP makes selective, positive-surplus federation
> between independently governed systems contractible without collapsing their
> truth or governance. IOI L1 is the optional shared-trust layer for selected
> registry, assurance, dispute, rights, security, and economic commitments.**
