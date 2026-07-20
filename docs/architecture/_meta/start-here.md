# Start Here

Status: canonical reader entry point.
Canonical owner: this file for first-read architecture orientation and role-based reading paths.
Supersedes: ad hoc onboarding paths across architecture docs.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: mixed (reader entry point over built, partial, planned, and speculative subjects)
Last implementation audit: 2026-07-11

## Five-Minute Mental Model

IOI is the open operating stack for bounded distributed autonomous systems and
the Internet of Intelligence:

> **IOI turns intelligence into bounded autonomous institutions. L0 makes one
> institution safely distributable across governed compute, state,
> verification, human, and embodied nodes; AIIP makes selective,
> positive-surplus interoperation between separately sovereign institutions
> contractible; IOI L1 supplies optional shared trust and economic finality.**

It combines two complementary directions:

1. a Hypervisor substrate that mounts models, workers, tools, services,
   runtimes, infrastructure, memory, and embodied systems behind one governed
   effect boundary; and
2. a local-first semantic and coordination fabric in which member nodes,
   workers, people, services, and embodied units can pursue one system's goals,
   while separately sovereign domains may optionally collaborate without
   surrendering local truth or authority to one global database.

The first direction makes intelligence executable and governable. The second
makes independently owned intelligence composable. Neither replaces the other.

Local-first is an operating contract, not only a semantic preference: within a
declared standalone capability, durability, custody, and assurance envelope, a
compatible local or customer-controlled deployment remains independently
operable without an `ioi.ai` account or another first-party managed
dependency. Managed attachment adds separately admitted capabilities and never
silently transfers truth, authority, custody, or writer ownership.

For an enterprise, their clearest joint value is a governed learning loop:
models remain replaceable cognition suppliers while the institution retains the
ontology, admitted memory, corrections, private evals, policies, workflows,
datasets, lineage, and rights-eligible derived capability that compound into
institutional intelligence. The
[`InstitutionalLearningBoundaryProfile`](../foundations/institutional-learning-boundary.md)
compiles this boundary across Hypervisor, Agentgres, Foundry, Private Workspace,
Ontology/Data, and the model router; it does not create another subsystem.

```text
Goal Space (ioi.ai)
  durable goals, subscriptions, budgets, collaboration, replay, outcome UX
  -> OutcomeRoom / CollaborativeWorkGraph when shared pursuit is useful
     -> one or more bounded GoalRuns
        -> one immutable GoalRunProfile resolution per GoalRun
        -> Goal Kernel interprets it through GoalGroundingLoop and RoleTopology
           -> ContextCells, claims, leases, typed handoffs, attempts
              -> HarnessInvocations, Workers, tools, and services

Hypervisor
  one control plane across Type 1 bare-metal, Type 2 workstation, and
  Type 3 governed-autonomy postures
  -> Hypervisor Daemon admits and mediates effects
  -> Agentgres records admitted operational truth
  -> artifact/storage planes hold governed payloads
  -> wallet.network and local/domain policy supply authority

One bounded DAS across admitted nodes
  one system_id / constitution / operational truth
  -> RuntimeAssignments bind GoalRuns and roles to governed node memberships
  -> execution, state, verification, gateway, and embodied roles coordinate
  -> partitions, reassignment, failover, replay, and duplicate effects follow policy

Local semantic world planes with optional federation
  local Domain Ontologies, assertions, overlays, and action contracts
  <-> explicit crosswalks and challengeable mapping decisions after accepted terms
  <-> optional AIIP signed handoffs between bounded execution domains

Sparse public coordination
  local work stays local by default
  -> explicit ioi_compatible / ioi_connected / ioi_secured enrollment
  -> IOI L1 only for selected rights, registry, assurance, security, economic,
     dispute, governance, or cross-domain commitments
```

This is not a choice between a “hypervisor app” and a decentralized enterprise
ontology. Hypervisor is the execution and operating substrate; Goal Space and
the semantic/collaboration planes are how many intelligences and domains use
that substrate to converge on open or private outcomes.

## Bounded DAS In One Minute

An intelligent blockchain is the ordered state-machine substrate of a bounded
autonomous institution. It can use one authority/PoA-1, replicated authority,
threshold authority, BFT consensus, or external-chain finality. Consensus is a
deployment profile, not what makes the system intelligent or bounded.

Every durable system declares a constitution, executable manifest, desired
deployment, observed member nodes and roles, ordering/finality, external-fact
oracle/evidence policy, lifecycle continuity, and optional network enrollment.
One stable logical identity may span several nodes. Joining a node never
silently grants authority or changes finality. A promoted/replacement
single-writer requires catch-up, root verification, a new writer epoch, and
fencing; a deliberately single-node system may fail closed or restore under its
declared proof contract; threshold, BFT, and external-finality systems use their
profile-native recovery proofs instead.

The roadmap proves this in order:

```text
one hosted durable OutcomeRoom instance (one room system)
  -> the same logical DAS across two failure domains with controlled failover
     and useful distributed work across active member nodes or embodied units
  -> two sovereign DASs interoperating over AIIP
  -> productized Goal Space and open challenge network
  -> optional shared-trust and public-economic commitments
```

The reusable OutcomeRoom package and each durable room-system instance are the
flagship reference DAS, not the definition of L0. A React or
other generated domain app will often be the leading user interface; it remains
a projection over the system's constitution, authority, state, deployment, and
receipts.

## The Core Product Shape

### Goal Space

ioi.ai should sell one coherent Goal Space subscription rather than a bundle of
pooled model seats. The subscription includes persistent conductor state,
portable memory, private and organization goals, governance, collaboration,
receipts, replay, and a bounded grant of non-transferable Work Credits.

Managed model and runtime supply is a portfolio:

- direct provider APIs, dedicated capacity, and negotiated inference;
- replaceable aggregators such as OpenRouter for breadth and discovery;
- customer BYOK or provider-approved user-scoped BYOA;
- open-weight, local, customer-boundary, and self-hosted routes.

Every route resolves a versioned commercial and technical rights contract.
Named-human ChatGPT, Claude, or similar subscriptions are not pooled production
worker capacity. Missing automation, downstream, OEM/reseller, data, region,
credential-principal, provider-use, retention, or customer-output-use rights fail
closed.

The user controls independent axes:

- execution/custody: `Standard` or `Private`;
- goal routing: `Auto`, `Pinned`, or `Compare`;
- contributors: `My workers`, `Organization`, or `Network / Open`;
- placement: local, customer infrastructure, selected cloud, or Hypervisor
  choice.

Network/Open contribution uses a separate funded goal budget, bounty,
procurement cap, or sas.xyz service order. It must not silently burn an
ordinary seat allowance.

### OutcomeRoom And GoalRun

An `OutcomeRoom` is the durable shared-pursuit bounded-DAS instance created from
the reusable room package through genesis. Its
`CollaborativeWorkGraph` records admitted participants, offers, frontier items,
leased claims, attempts, findings, verifier challenges, contribution lineage,
discussion projections, and replay. Goal Space workstreams and Hypervisor Work /
Rooms are projections over this same graph.

A `GoalRun` is a bounded execution unit below an optional OutcomeRoom. Its
generic loop is:

```text
orient -> plan -> implement/act -> observe -> verify -> course-correct
       -> continue, escalate, hand off, reconcile, or close
```

The kernel should be generic and loop-native. It should not be a global swarm,
a hard-coded coding loop, or a chat transcript. Simple work collapses to one
direct path. Hard or uncertain work may fan out across models, workers,
verifiers, sessions, or parties when expected value justifies the added cost.

`WorkResult` and `OutcomeDelta` are the generic result seam.
`ImplementationResultPayload` is only the software-implementation profile.

### Hypervisor

Hypervisor is one operating fabric with three complementary postures:

- Type 1: HypervisorOS bare-metal, appliance, and cluster substrate;
- Type 2: desktop/workstation hosting of local environments, models, tools,
  VMs, containers, microVMs, and sandboxes;
- Type 3: the autonomy plane for sessions, workers, goals, authority, receipts,
  replay, outcomes, and governed improvement.

Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK, the
core workspaces (Home, Systems, Projects, Applications, and Work), the
shell-placed Automations owner application, owner applications (Studio,
Automations, Ontology, Data, Governance,
Provenance, Evaluations, Improvement, Foundry, Packages, Developer Workspace,
and Developer Console), the Environments and Operations substrate applications,
extension applications and tools, and the conditional Embodied Systems
`owner_application` registration with `surface_availability: planned` are
clients, builder surfaces, or projections over the
same Core. ODK is the developer kit beneath Ontology and Data; Workbench is a
compatibility alias for Developer Workspace; the former Work Ledger card
converges in Provenance. None creates private runtime truth beside the daemon.

The target shell opens new work through a keyboard-first `+ New` menu with
System, Session, Goal, Project, and Automation; New Session remains a one-click
and keyboard-first path. Systems is a stable context/read model for one admitted
`system_id`, not the owner of System identity, membership, or lifecycle. Direct
Sessions, Projects, AutomationSpecs, and stand-alone GoalRuns do not require a
System. Work is a policy-filtered projection over typed work subjects with
Active, Goals, Sessions, Rooms, Queues, Reviews, Incidents, and History views;
it never becomes a universal work state machine or authority owner.

Keep the work object spine literal: GoalRun is durable pursuit; OutcomeRoom is
collective pursuit; AutomationSpec is reusable standing behavior;
AutomationInstallationBinding is successor-versioned scope enablement and
narrowing; AutomationRun is one activation freezing the exact spec, binding,
and WorkflowTemplate; Session is a bounded
interactive/headless/supervisory context; and WorkRun is one execution
attempt. `background` is a mode. The generic `HypervisorMission` object is
retired; optional Mission presentation profiles may wrap exactly one GoalRun
or OutcomeRoom without independent identity, lifecycle, budget, authority,
evidence, or receipts. Typed physical mission and allocation contracts remain
valid.

Packages owns local and organization package lifecycle. Marketplace is an
optional discovery, distribution, and commerce mode over that truth. Every
product surface uses the independent surface class, publisher origin, creation
method, distribution, availability, admission, installation, package
disposition, enablement, capability depth, and operational state axes in
[`canonical-enums.md`](../foundations/canonical-enums.md), and one
policy-filtered compiler serves shell, Applications, command-palette,
contextual-launch, and API projections. A generated surface splits package,
immutable release, surface descriptor, installation binding, enablement,
serving runtime, System binding, and System identity; reference-product
captures and parity evidence grant none of them.

### Local Ontology And Optional Federation

There is no universal enterprise graph. Each domain owns local ontology
versions, overlays, assertions, valid time, transaction time, provenance,
uncertainty, contradictions, supersession, and disputes. Cross-domain work, when
selected under accepted terms, uses explicit `OntologyCrosswalk` and
`SemanticMappingDecision` objects.

Semantic meaning never grants power. A consequential ontology action becomes
executable only through an `OntologyActionContract` binding typed IO,
preconditions, postconditions, state transition, capability, runtime, policy,
authority, risk, idempotency, ambiguous-effect recovery, compensation,
verification, evidence, receipts, and physical safety where applicable.

### Internet Of Intelligence

IOI facilitates an Internet of Intelligence when it preserves all four forms
of plurality instead of conflating them:

| Plurality | What changes | What it does not prove |
| --- | --- | --- |
| Multi-model | cognition routes | independent workers or parties |
| Multi-worker | accountable labor actors | independent infrastructure or governance |
| Multi-node | placement, custody, and failure domains | independent contributors |
| Multi-party | ownership, policy, authority, attribution, dispute, economics | automatically trustworthy results |

Multi-node work is not merely replication. One bounded DAS may distribute
useful GoalRun roles, verification, gateway/edge work, and typed embodied
mission/action allocations across admitted members through native L0
`RuntimeAssignment`, scoped leases, state/evidence watermarks, and domain
admission. AIIP begins only where a separate constitution, operational truth,
authority, risk, and credible exit create an independently governed system
boundary.

Hugging Face-style open-agent experiments demonstrate one high-fit pattern for
goals where parallel attempts, negative results, independent challenges, and
shared resources create positive expected value. IOI supports that pattern
alongside direct local work, private rooms, bilateral handoffs, enterprise
workflows, and embodied systems; it does not presume open participation. A
sovereign system remains local unless accepted terms make every required
party's participation rational after coordination, disclosure, verification,
and counterparty costs.

## Core Effect Boundary

```text
intent or room claim
  -> worker/model/harness proposes
  -> semantic and capability checks
  -> policy and authority providers authorize
  -> Hypervisor Daemon admits, schedules, executes or mediates
  -> environment/provider/actuator performs
  -> observations, receipts, artifacts, and state deltas return
  -> verifier and acceptance paths classify assurance
  -> Agentgres admits local operational truth
  -> AIIP handoff or L1 commitment only when policy triggers it
```

The daemon does not invent authority. Policy and authority providers authorize;
the daemon admits, enforces, executes or mediates, receipts, and fails closed.

Receipt assurance is staged:

```text
attested -> evidenced -> verified -> accepted -> adjudicated -> settled
```

A receipt proves only its bound event or claim. It is not automatically proof
of correctness, truth, acceptance, or settlement.

External-effect recovery is also explicit:

```text
replayable | checkpointable | compensatable |
reconciliation_required | non_retryable
```

A timeout after a possible external effect is ambiguous, not safely retryable.
Environment restore and outcome reconciliation are separate operations.

## Enterprise Learning, Persistent Intelligence, Privacy, And Embodiment

- `MemorySpace` is portable vault truth; `MemoryProjection` is the filtered
  harness/model/worker view. Adapter-local memory is cache, not the durable
  brain.
- **Enterprise Learning Boundary** is the product-facing projection of an
  admitted `InstitutionalLearningBoundaryProfile`. It narrows organization and
  project defaults into a sovereign system revision and run/job snapshots. The
  effective decision intersects source rights, consent, data-view policy,
  model-route rights, custody, training eligibility, retention/export, and
  jurisdiction; missing rights fail closed.
- Provider learning, cross-customer aggregation, and seller access to a buyer's
  managed-instance learning are denied by default. Standard may use a disclosed
  provider-trust route; Private requires custody-proven containment for protected
  plaintext. A receipt proves an IOI-admitted crossing or an attempt blocked
  before egress, not a provider's hidden internal behavior.
- Improvement is proposal-driven. A bounded one-shot change may move directly
  from eligible evidence and evaluation to an `UpgradeProposal`; adaptive,
  repeated, sealed-evaluation, multi-epoch, or higher-order work uses an
  optional `ImprovementCampaign`. Search proposes, Judgment evaluates under a
  frozen `EvaluationEpoch`, and Authority alone admits promotion. Traces and
  failures may yield skill, memory, workflow, verifier, harness, routing, or
  Foundry candidates, but `LearningEvidenceEligibility`, evaluation, policy,
  authority, receipts, and Agentgres admission gate their use and promotion.
  A Campaign never activates itself or turns its claim artifact into authority.
- Institutional capability portability spans more than memory: rights-eligible
  ontology and recipes, Agentgres archive/state roots, evals, policies, workers,
  workflows, datasets, adapters, packages, and lineage can form an
  `InstitutionalIntelligenceExportBundle`. Import re-runs admission. A model-swap
  continuity test must remove the incumbent provider and rerun declared evals
  using institution-controlled, rights-eligible state; model neutrality never
  promises identical models.
- Private Workspace backed by cTEE keeps protected plaintext, secrets,
  strategy, and unrestricted authority off untrusted rented nodes by default.
  Provider-trust API routes remain explicitly labeled provider-trust.
- Embodied execution retains a two-speed system boundary: the slower
  mission/governance plane proposes plans, semantic actions, and typed physical
  envelopes, while the fast local side isolates on-unit autonomy, deterministic
  motion, and independent runtime-assurance/safety strata. The native
  `LocalControlSupervisor` or a separately assured local controller holds the
  final veto; model output is never an actuator command, safety heartbeat, or
  emergency-stop authority.

## Route By Problem

Use [`current-canon-defaults.md`](./current-canon-defaults.md) for the current
cross-owner digest, [`source-of-truth-map.md`](./source-of-truth-map.md) before
editing doctrine, and [`implementation-matrix.md`](./implementation-matrix.md)
before claiming that a target object is built.

| Problem | Start here | Then read |
| --- | --- | --- |
| Bounded DAS/intelligent blockchain constitution, deployment, membership, failover, lifecycle | [`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md) | [`domain-kernels.md`](../foundations/domain-kernels.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`execution-horizons.md`](./execution-horizons.md) |
| Goal Space, open agent collaboration, room/workstream UX | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md), [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) |
| GoalRunProfile, GoalRun, Goal Kernel, topology, context cells, and typed step/result seams | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md) | [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`api.md`](../components/daemon-runtime/api.md) |
| Goal Space pricing, Work Credits, Network/Open budgets | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) | [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md), [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md) |
| Foundation-model supply, OpenRouter, BYOK/BYOA, route rights | [`model-router/doctrine.md`](../components/model-router/doctrine.md) | [`api-byok-mounting.md`](../components/model-router/api-byok-mounting.md), [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) |
| Hypervisor shell, Systems/Work, applications, packages, clients, sessions, adapters | [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md) | [`canonical-enums.md`](../foundations/canonical-enums.md), [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`doctrine.md`](../components/daemon-runtime/doctrine.md) |
| Type 1/2/3 substrate and HypervisorOS | [`hypervisoros.md`](../components/daemon-runtime/hypervisoros.md) | [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md), [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md) |
| Enterprise ontology, semantic federation, ODK | [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md) | [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md), [`foundry.md`](../components/hypervisor/foundry.md) |
| Enterprise-owned learning, provider exposure, capability portability, and model-swap continuity | [`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md) | [`model-router/doctrine.md`](../components/model-router/doctrine.md), [`foundry.md`](../components/hypervisor/foundry.md), [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) |
| Cross-domain collaboration, standards bindings, or autonomous-system interop | [`aiip.md`](../foundations/aiip.md) | [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md), [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) |
| Authority, secrets, approvals, revocation | [`wallet-network/doctrine.md`](../components/wallet-network/doctrine.md) | [`wallet-network/api-authority-scopes.md`](../components/wallet-network/api-authority-scopes.md), [`security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md) |
| Operational truth, object heads, projections | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md) | [`agentgres/api-object-model.md`](../components/agentgres/api-object-model.md), [`agentgres/projection-system-reference.md`](../components/agentgres/projection-system-reference.md) |
| Portable memory and model/harness projections | [`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md) | [`agentgres/doctrine.md`](../components/agentgres/doctrine.md), [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md) |
| Artifact refs, archives, restore, missing payloads | [`agentgres/artifact-ref-plane.md`](../components/agentgres/artifact-ref-plane.md) | [`storage-backends/doctrine.md`](../components/storage-backends/doctrine.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Private rented/cloud compute | [`private-workspace-ctee.md`](../components/daemon-runtime/private-workspace-ctee.md) | [`runtime-nodes-tee-depin.md`](../components/daemon-runtime/runtime-nodes-tee-depin.md), [`model-router/doctrine.md`](../components/model-router/doctrine.md) |
| Worker marketplace and managed instances | [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) | [`aiagent/digital-worker-ontology.md`](../domains/aiagent/digital-worker-ontology.md), [`aiagent/managed-worker-instance-lifecycle.md`](../domains/aiagent/managed-worker-instance-lifecycle.md) |
| Service procurement and delivery | [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md) | [`sas/service-endpoints.md`](../domains/sas/service-endpoints.md), [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md) |
| Governed improvement, bounded campaigns, evaluation epochs, and promotion | [`bounded-recursive-improvement.md`](../foundations/bounded-recursive-improvement.md) | [`improvement.md`](../components/hypervisor/improvement.md), [`evaluations.md`](../components/hypervisor/evaluations.md), [`improvement-governance-gates.md`](../components/daemon-runtime/improvement-governance-gates.md), [`foundry.md`](../components/hypervisor/foundry.md) |
| Native embodied execution, runtime graphs, units, fleets, and swarms | [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md) | [`physical-action-safety.md`](../foundations/physical-action-safety.md), [`foundry.md`](../components/hypervisor/foundry.md), [`aiip.md`](../foundations/aiip.md) |
| Physical actuation authority, local safety, supervision, and emergency stop | [`physical-action-safety.md`](../foundations/physical-action-safety.md) | [`embodied-runtime.md`](../components/daemon-runtime/embodied-runtime.md), [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) |
| Assurance, certification, liability, audit | [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) | [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md), [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md) |
| Network enrollment, Standard DAS, L1, token/BME, and sparse public settlement | [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md) | [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md), [`ecosystem-assurance-certification-liability.md`](../foundations/ecosystem-assurance-certification-liability.md) |

## Reader Paths

### Runtime implementer

Read, in order:

1. [`default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md)
2. [`doctrine.md`](../components/daemon-runtime/doctrine.md)
3. [`api.md`](../components/daemon-runtime/api.md)
4. [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md)
5. [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
6. [`implementation-matrix.md`](./implementation-matrix.md)

### Product implementer

Read Goal Space and Hypervisor as two views over one fabric:

1. [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
2. [`institutional-learning-boundary.md`](../foundations/institutional-learning-boundary.md)
3. [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
4. [`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md)
5. [`identity-access-and-metering.md`](../components/hypervisor/identity-access-and-metering.md)
6. [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)

### Semantic and interop implementer

1. [`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md)
2. [`aiip.md`](../foundations/aiip.md)
3. [`common-objects-and-envelopes.md`](../foundations/common-objects-and-envelopes.md)
4. [`agentgres/doctrine.md`](../components/agentgres/doctrine.md)
5. [`security-privacy-policy-invariants.md`](../foundations/security-privacy-policy-invariants.md)

### Economics and marketplace implementer

1. [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)
2. [`mixture-of-workers.md`](../foundations/mixture-of-workers.md)
3. [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md)
4. [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md)
5. [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md)
6. [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md)

## North-Star Internet-of-Intelligence Test

An independently operated external Worker must be able to discover an eligible
OutcomeRoom through a policy-bound projection, negotiate semantic/action
profiles, request admission, receive bounded leases, claim work, return a
verifiable contribution, retain credit/dispute lineage, and exit with a
portable policy-filtered participant-state bundle. Passing the test cannot
require one runtime, operational database, administrator, or continued access
to an IOI-hosted room. This is the minimum network proof; same-owner worker or
model multiplicity alone does not satisfy it.

## Most Common Boundary Mistakes

Reject these models:

```text
Goal Space = pooled frontier-model subscriptions
OutcomeRoom = global database, chat room, or leaderboard
Goal Kernel = one global swarm or coding-only loop
GoalRunProfile = executable, authority, live run state, or workflow graph
WorkflowTemplate = AutomationSpec, trigger, run history, or canvas state
SkillManifest = executable tool, hook, authority, or marketplace listing
multi-model = multi-worker = multi-node = multi-party
same-system member routing = AIIP federation
ImplementationResult = universal work result
ontology name = executable capability or authority
receipt = verified truth, acceptance, or settlement
daemon = authority provider
provider fallback = harmless endpoint substitution
provider-trust API = Private/no-provider-trust execution
enterprise operation = ownership or training rights over every trace
receipt or ZDR contract = proof of hidden provider non-learning
model-neutral routing = equivalent replacement quality without retained state/evals
OpenRouter = the product moat or sole inference boundary
Agentgres = one global enterprise graph or all payload bytes
memory projection = portable vault truth
environment restore = external-effect reconciliation
model output = physical safety heartbeat
IOI L1 = per-step execution database
Work Credit = pooled provider token, cash, or protocol token
```

Use this model instead:

```text
Goal Space sells governed outcome pursuit.
OutcomeRoom coordinates shared pursuit above bounded GoalRuns.
GoalRun loops, verifies, course-corrects, and collapses to direct when simple.
Same-system distributed work uses native L0 membership, RuntimeAssignment,
leases, state/evidence, and Embodied Runtime contracts.
Cross-plane operation readiness is evaluated per operation through the
[`Platform Operability`](../components/daemon-runtime/platform-operability.md)
contract; one green process or dashboard never substitutes for current truth,
authority, clock, billing, attestation, storage, provider, fleet, or settlement
evidence.
AIIP begins only across independently governed system boundaries.
Workers compose models, harnesses, tools, services, and runtime placements.
Domains own local semantic and operational truth.
InstitutionalLearningBoundaryProfile compiles the institution's learning rules;
source rights and per-subject eligibility still decide what may be learned.
AIIP moves typed, permitted work and refs between domains.
Policy and authority providers authorize.
The daemon admits, enforces, executes or mediates, and receipts.
Agentgres admits local truth; storage holds payload bytes.
Receipts feed explicit assurance stages.
Hypervisor spans infrastructure and governed autonomy.
Goal Space, Hypervisor, marketplaces, and services monetize product value.
Substrate layers meter, attest, authorize, record, and settle.
IOI L1 receives selected public commitments only for explicitly enrolled
systems.
```

## Maintaining The Canon

- Edit the subject owner named in
  [`source-of-truth-map.md`](./source-of-truth-map.md) first.
- Reconcile cross-owner defaults in
  [`current-canon-defaults.md`](./current-canon-defaults.md).
- Put shared enum values in
  [`canonical-enums.md`](../foundations/canonical-enums.md).
- Put shared names in [`vocabulary.md`](./vocabulary.md).
- Record built/partial/planned truth in
  [`implementation-matrix.md`](./implementation-matrix.md).
- Do not use the whitepaper, an archive, an ignored internal guide, or a UI
  projection as a competing architecture owner.
