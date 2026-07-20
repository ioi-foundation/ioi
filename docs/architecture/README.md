# IOI Canonical Architecture Spec Pack

Status: canonical navigation and source-of-authority index.
Canonical owner: this file for architecture navigation; see [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) for subject ownership.
Supersedes: ad hoc architecture navigation in plans/specs when links or ownership disagree.
Superseded by: none.
Last alignment pass: 2026-07-20.
Doctrine status: canonical
Implementation status: mixed (navigation index over built, partial, planned, and speculative subjects)
Last implementation audit: 2026-07-19

## Purpose

This directory is the tracked architecture and product-doctrine authority for
IOI. It separates owner documents by subject so implementation, product copy,
protocol schemas, and the whitepaper can converge on one target without turning
any synthesis or UI into a competing source of truth.

Start with [`START_HERE.md`](./START_HERE.md). Then use:

- [`current-canon-defaults.md`](./_meta/current-canon-defaults.md) for the
  cross-owner target-state digest;
- [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) before changing a
  subject;
- [`implementation-matrix.md`](./_meta/implementation-matrix.md) before making
  a built/partial/planned claim;
- [`execution-horizons.md`](./_meta/execution-horizons.md) to distinguish the
  convergence target from later gated horizons;
- [`vocabulary.md`](./_meta/vocabulary.md) and
  [`canonical-enums.md`](./foundations/canonical-enums.md) for shared names and
  values;
- [`architecture-contract-registry.v1.json`](./_meta/schemas/architecture-contract-registry.v1.json)
  for the machine-readable shared-contract pilot and its generated Rust and
  TypeScript projections.

[`whitepaper.tex`](./whitepaper.tex) is the publishing synthesis. It is not the
owner of component doctrine. Ignored guides, prompt packs, reverse-engineering
notes, captures, and archived specs are evidence or workbench material, not
parallel canon.

## Category And Target End State

IOI is the open operating stack for bounded distributed autonomous systems and
the Internet of Intelligence:

> **IOI turns intelligence into bounded autonomous institutions. L0 makes one
> institution safely distributable across governed compute, state,
> verification, human, and embodied nodes; AIIP makes selective,
> positive-surplus interoperation between separately sovereign institutions
> contractible; IOI L1 supplies optional shared trust and economic finality.**

> Intelligence may reason and execute anywhere; consequential effects cross a
> constitution-bound governed boundary; domains retain local truth; typed
> intelligence and work move between domains; only explicitly selected
> commitments use public shared trust.

The target joins two complementary architecture directions:

- Hypervisor is the open operating substrate for infrastructure and governed
  autonomy: models, workers, harnesses, tools, services, connectors, memory,
  VMs, containers, GPUs, remote nodes, and embodied systems share one control,
  authority, receipt, replay, and state fabric.
- Goal Space plus the optional semantic-interoperation and collaboration plane is
  the open operating environment for distributed intelligence where a positive
  cooperation case exists: participants accept exact terms and coordinate
  around shared outcomes, explicit ontologies, leased work, findings,
  verification, contribution lineage, and cross-domain handoffs without one
  global centralized semantic database owning every domain. Local systems remain
  complete when that case does not exist.

The architecture is edge-in. Work begins near users, data, tools, providers,
and physical systems; Agentgres admits operational truth inside bounded
domains; AIIP carries only voluntarily accepted, terms-bound interoperation
when every required party expects net benefit; IOI L1 receives sparse public commitments when
rights, settlement, registry, dispute, governance, security, or cross-domain
trust creates value for an explicitly enrolled system.

For enterprises, the clearest composition thesis is **enterprise-owned
learning**: foundation models are replaceable cognition suppliers, while the
organization or sovereign system retains the ontology, admitted memory,
corrections, evals, policies, workflows, datasets, lineage, and rights-eligible
derived capability that make its intelligence particular. The canonical
[`InstitutionalLearningBoundaryProfile`](./foundations/institutional-learning-boundary.md)
compiles the applicable source rights, data views, model-route rights, custody,
training eligibility, retention, export, and revocation contracts into one
fail-closed boundary. It is a cross-cutting profile, not a new runtime, truth
store, authority plane, privacy tier, or application.

## Canonical Stack

```text
Product and collaboration
  ioi.ai Goal Space
  Hypervisor App / Web / CLI-headless / optional TUI
  shell: Home / Systems / Projects / Automations / Applications / Work
  owner applications: Studio / Automations / Ontology / Data / Governance /
    Provenance / Evaluations / Improvement / Foundry / Packages /
    Developer Workspace / Developer Console
  substrate applications: Environments / Operations
  extension applications and tools; conditional planned Embodied Systems owner application
  aiagent.xyz / sas.xyz / wallet.network

Shared pursuit
  OutcomeRoom / CollaborativeWorkGraph
  participants / resource and capability offers / frontier / claims
  attempts / findings / verifier challenges / contribution lineage / replay

Bounded execution
  GoalRunProfile -> admitted GoalRun / GoalGroundingLoop / RoleTopology
  optional WorkflowTemplate / SkillManifest and exact ActiveSkillSetSnapshot
  ContextCells / leases / typed handoffs / HarnessInvocations
  WorkResult / OutcomeDelta

Operating substrate
  Hypervisor Core and Hypervisor Daemon
  Type 1 HypervisorOS / Type 2 workstation / Type 3 autonomy plane
  model router / connectors / runtimes / provider and environment plane
  immutable MCPGatewayRequirement -> admitted subject-scoped gateway profile

Policy composition, authority, truth, memory, and evidence
  InstitutionalLearningBoundaryProfile and LearningEgressReceipt
  wallet.network plus local/domain policy and authority providers
  Agentgres operations, object heads, projections, and state roots
  MemorySpace and policy-filtered MemoryProjections
  receipts, evidence bundles, verification, acceptance, replay, artifacts

Federation and settlement
  Domain Ontologies / overlays / crosswalks / semantic mapping decisions
  OntologyActionContracts
  AIIP between bounded execution domains
  IOI L1 for selected public commitments
```

Stable product taxonomy:

```text
IOI daemon = hypervisor/control plane for autonomous execution
Hypervisor App/Web/CLI-headless = first-class clients over Hypervisor Core
Systems = stable context/read model for one admitted system_id, not system truth
Work = policy-filtered projection over typed work objects, not work truth
Developer Workspace / Automations / Foundry = owner applications over Hypervisor Core
Packages = local package lifecycle owner; Marketplace = optional distribution mode
IOI Authority Gateway = compatibility adapter profile
```

The core work spine keeps identity and lifecycle explicit:

```text
GoalRunProfile = reusable immutable pursuit definition
GoalRun = durable state of one admitted pursuit
GoalKernel = interpreter/operator of the pursue-verify-course-correct loop
ImprovementGovernanceProfile = immutable owner-scoped Campaign admission policy
ImprovementAgenda = immutable-by-revision, non-executable investigation portfolio
ImprovementCampaign = optional multi-epoch improvement domain lifecycle
OutcomeRoom = collective pursuit
WorkflowTemplate = reusable immutable directed-work graph
AutomationSpec = standing activation over one exact WorkflowTemplate revision
AutomationInstallationBinding = successor-versioned scope enablement and narrowing
AutomationRun = one activation freezing the exact template, spec, and binding
SkillManifest = immutable procedure and support material
SkillEntry = revisioned owner-scope binding to one exact SkillManifest revision
ActiveSkillSetSnapshot = exact run-scoped skill selection
HarnessProfile = resolver for one assigned scoped step
HarnessInvocation = one daemon-mediated step resolution
RuntimeToolContract = typed callable capability and effect boundary
Session = bounded interactive, headless, or supervisory context
WorkRun = one execution attempt
Package = distribution/lifecycle composition without ownership transfer
Domain object = owner of the actual artifact, campaign, fleet, business, or system state
```

The environment-composition spine is equally explicit:

```text
source snapshot + detector revision
  -> HypervisorProjectDiscoveryProposal
  -> explicit candidate and override acceptance
  -> HypervisorProject + HypervisorDevelopmentEnvironmentRecipe
  -> recipe resolution + HypervisorEnvironmentStartupPlan
  -> environment lifecycle, route bindings, backups, restore ChangePlans,
     and cleanup obligations
```

Discovery never executes source, grants authority, installs dependencies, or
starts an environment. Ports, route bindings, backups, restore activation, and
provider cleanup remain independently typed so convenience cannot erase their
different authority, evidence, or recovery boundaries.

“Recipe” is product/package language over one of the owner-qualified reusable
objects: DataRecipe, HypervisorDevelopmentEnvironmentRecipe,
HypervisorSessionLaunchRecipe, WorkflowTemplate, AutomationSpec, or
GoalRunProfile. There is no generic executable RecipeEnvelope.

`background` is a mode, not a separate kind of work. The generic
`HypervisorMission` object is retired. A product may render `Mission` as an
optional profile over exactly one GoalRun or OutcomeRoom, with the backing ref
visible and no independent identity, state, budget, authority, evidence, or
receipts. Typed physical mission and allocation contracts remain valid domain
objects.

## Decisions That Define The Target

[ADR 0015](../decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md)
records the durable decision below and supersedes the earlier node-equals-local-
domain/global-L1 framing in ADRs 0011 and 0012.
[ADR 0017](../decisions/0017-goal-pursuit-workflow-skill-and-harness-taxonomy.md)
records the pursuit/workflow/skill/step-resolution taxonomy above.

### A bounded DAS is one logical institution across admitted nodes

An intelligent blockchain is a constitution-bound autonomous-system state
machine, not necessarily a public chain. `single_authority`, replicated,
threshold, BFT, and external-finality deployments are all valid declared
profiles. One stable system identity may span multiple Hypervisor Nodes;
membership, roles, catch-up, roots, degraded state, and declared recovery are
governed and observed separately from desired topology. Writer epochs/fencing
apply to single-writer restore or promotion; threshold/BFT/external-finality
profiles use their native recovery proofs. Adding a node never silently widens
authority or finality.

The first distributed milestone is one logical DAS across two failure domains
with both controlled continuity and useful distributed work: active placement,
leases, reassignment, partition behavior, distributed verification, replay, and
duplicate-effect prevention under unchanged authority. The next is two
sovereign bounded DASs over AIIP. The reusable `OutcomeRoom` package and each durable
room-system instance are the flagship reference DAS, not the definition
of L0. Generated React or other domain apps remain first-class system UIs and
projections over the underlying contracts.

Same-system distribution and cross-system federation are distinct. Nodes,
workers, people, and embodied units sharing one `system_id`, constitution,
canonical admission path, lifecycle, and authority coordinate through governed
membership, placement, work, resource, and authority leases. Separately
governed systems with their own truth, risk, assets, and credible exit use AIIP
only after accepting exact collaboration terms. Internal routing may reuse typed
handoff and receipt vocabulary without being represented as federation.

### IOI Network participation is explicit

`ioi_compatible` systems use open L0 without mandatory L1, fees, tokens, or IOI
assurance. `ioi_connected` systems select and pay for named registry, rights,
reputation, escrow, dispute, or settlement services. `ioi_secured` systems also
adopt a Standard DAS profile and named shared-security/assurance services with
explicit terms and bonds where applicable. L0 product, network, and L1 value
are separate; adoption alone is not token demand.

### AIIP composes with existing standards

AIIP owns the cross-system work, authority, semantic-action, evidence, recovery,
dispute, and settlement envelope. Versioned A2A, MCP, directory/schema,
HTTP/RPC, and chain/escrow bindings reuse external standards for remote tasks,
tools/context, discovery, and settlement without treating their completion or
registry state as IOI verification or authority.

### The standalone core must be independently operable

The target contract requires a compatible local or customer-controlled IOI
deployment, within its declared standalone capability, durability, custody,
and assurance envelope, to bootstrap, create and govern a bounded System,
execute local or BYO work, preserve and replay Agentgres truth, and back up,
restore, export, and verify evidence without an `ioi.ai` account or another
first-party managed dependency. Unavailable connected capabilities remain
typed unavailable rather than becoming hidden prerequisites or simulated
local parity. The conformance contract is defined; no current end-to-end
standalone product pass is claimed.

The product-level proof is one non-object zero-to-operable journey shared by
App and CLI/headless: verify the selected release and supply-chain evidence;
preview paths, endpoints, custody, supervision, egress, and effects; install;
bootstrap deployment-local identity and authority; start the client, daemon,
and declared Agentgres posture; pass bounded readiness; open the product;
inspect status, doctor findings, and logs; update or roll back through an
admitted `HypervisorChangePlan`; stop or uninstall without implicit data wipe;
and export, back up, or restore through the owning contracts. This journey is
distinct from zero-to-idle posture and from an environment StartupPlan. It is
a target conformance claim, not a statement that the current estate has
shipped it.

Managed attachment may extend placement, collaboration, backup, support, model
supply, routing, and assurance, but it never silently uploads, owns, meters,
authorizes, or completes locally governed Systems. Primary managed product
does not mean required control plane.

### Goal Space is the primary managed product

ioi.ai should provide one Goal Space subscription: persistent conductor and
goal state, portable memory, policy, receipts, replay, collaboration, support,
and a bounded grant of non-transferable Work Credits. Additional managed work
uses top-ups, overage, or committed spend. Network/Open contributors use a
separate goal budget, bounty, procurement cap, or service order.

IOI must not pool or resell named-human foundation-model workspace
subscriptions as production worker capacity. Supply is a plural portfolio of
direct and dedicated provider routes, replaceable provider aggregators,
customer BYOK/BYOA when permitted, and open/self-hosted weights.
Every candidate route must resolve an explicit versioned rights contract.

### Enterprise learning remains inside a compiled boundary

The product-facing **Enterprise Learning Boundary** compiles into each deployed
system and snapshots into its sessions, GoalRuns, model invocations, data
transformations, and Foundry jobs. Organization and project policies may supply
defaults, but they cannot silently mutate a live sovereign system; an admitted
system revision is authoritative, and narrower run-specific policy may not widen
it without explicit authority and a new decision.

The effective permission is the most restrictive intersection of source rights,
consent, policy-bound data views, the boundary profile, custody posture,
model-route rights, `LearningEvidenceEligibility`, retention/export policy, and
jurisdictional obligations. Cross-tenant and provider secondary learning are
denied by default. Private Workspace can supply custody-proven containment;
disclosed provider APIs remain provider trust. Agentgres records admitted
profiles, lineage, and impact without granting rights; Foundry improves only
from individually eligible evidence; model-neutral routing is credible only when
institutional state and evals survive provider removal.

`TrainingEvidenceEligibility` remains the model/worker-training compatibility
profile of the broader decision. Permission to use evidence for inference or
training does not silently grant permission to improve a policy, evaluator,
Agenda, workflow, cross-tenant service, or other owner-qualified target.

### Bounded improvement separates search, judgment, and authority

The direct `UpgradeProposal` path remains the default for one-shot bounded
change. Adaptive search, repeated protected evaluation, multiple epochs,
candidate archives, or qualified higher-order claims use an optional
`ImprovementCampaign` under the doctrine in
[`bounded-recursive-improvement.md`](./foundations/bounded-recursive-improvement.md).
The Campaign coordinates GoalRuns and evidence; it does not become a runtime,
truth store, evaluator, or promoter. Search cannot redefine the active epoch,
Judgment cannot mutate or activate the candidate, and Authority cannot fabricate
evidence. Selection creates proposal eligibility only; the target owner's normal
governance, activation, monitoring, and recovery path remains decisive.

### OutcomeRoom is above GoalRun

`OutcomeRoom` is the durable shared-pursuit bounded-DAS instance created from a
reusable package through genesis;
`CollaborativeWorkGraph` is its admitted participant/frontier/claim/attempt/
finding/evaluation graph. A room may coordinate many bounded `GoalRun` objects.
It is not a runtime, global graph, marketplace, or authority plane.

`GoalRun` remains a generic, loop-native kernel that orients, plans, acts,
observes, verifies, course-corrects, and closes or escalates. Simple work
collapses to direct execution. `WorkResult` and `OutcomeDelta` are generic;
`ImplementationResultPayload` is the software profile.

### Plurality dimensions stay distinct

Multi-model, multi-worker, multi-node, and multi-party are different claims.
Only multi-party collaboration implies independently governed principals, and
even that does not imply a trustworthy result without evidence, verification,
acceptance, and dispute semantics.

### The semantic plane is local-first and selectively interoperable

No ontology or Agentgres database is presumed globally canonical. Domains own
local ontology versions, overlays, assertions, provenance, valid and
transaction time, uncertainty, contradictions, and disputes. Cross-domain work
uses explicit crosswalks and receipted, challengeable mapping decisions only
after the participating domains accept the relevant terms and mapping risk.

Semantic meaning does not grant authority. Consequential actions compile to an
`OntologyActionContract` and then pass capability, policy, authority, daemon,
evidence, and verification gates.

### Authority and execution are separate

Policy and authority providers authorize. The Hypervisor Daemon admits,
enforces, schedules, executes or mediates, receipts, and fails closed.
wallet.network is mandatory for portable delegated authority and the high-risk
external actions assigned to it; local/domain governance may own local
authority where canon permits.

### Receipts are not the final assurance claim

Assurance remains explicit across `attested`, `evidenced`, `verified`,
`accepted`, `adjudicated`, and `settled`. The Verified Work Graph is the
cross-domain provenance and economic memory over those stages, including
negative, inconclusive, invalid, superseded, disputed, and exploit-finding work.

### Physical and external effects require recovery semantics

Actions declare replayable, checkpointable, compensatable,
reconciliation-required, or non-retryable recovery posture. A timeout after a
possible external effect is ambiguous. Environment restore is not outcome
reconciliation.

Embodied systems use a two-speed system boundary with three explicitly isolated
local strata. The slower mission/governance plane proposes plans and typed
physical envelopes; on-unit autonomy proposes bounded action, deterministic
motion owns admitted execution, and independent runtime assurance may deny,
clip, replace, recover, or stop. The native `LocalControlSupervisor` or a
separately assured local controller holds the final veto. Models do not become
actuator commands, safety heartbeats, or emergency-stop authorities.

## Navigation And Ownership

### Meta canon

| File | Owns |
| --- | --- |
| [`start-here.md`](./_meta/start-here.md) | reader orientation and reading paths |
| [`source-of-truth-map.md`](./_meta/source-of-truth-map.md) | edit-first subject ownership |
| [`current-canon-defaults.md`](./_meta/current-canon-defaults.md) | cross-owner defaults |
| [`vocabulary.md`](./_meta/vocabulary.md) | shared names and boundary terms |
| [`implementation-matrix.md`](./_meta/implementation-matrix.md) | durable forms, status, code anchors, conformance hooks |
| [`execution-horizons.md`](./_meta/execution-horizons.md) | convergence target and gated later horizons |
| [`doc-classes.md`](./_meta/doc-classes.md) | document classes and authority order |
| [`decisions/README.md`](../decisions/README.md) | accepted architecture decision records |

### Foundation owners

| Area | Canonical owners |
| --- | --- |
| stack and category | [`web4-and-ioi-stack.md`](./foundations/web4-and-ioi-stack.md), [`verifiable-bounded-agency.md`](./foundations/verifiable-bounded-agency.md) |
| invariants and security | [`invariants.md`](./foundations/invariants.md), [`security-privacy-policy-invariants.md`](./foundations/security-privacy-policy-invariants.md) |
| shared objects and values | [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md), [`canonical-enums.md`](./foundations/canonical-enums.md) |
| domains and autonomous systems | [`domain-kernels.md`](./foundations/domain-kernels.md), [`governed-autonomous-systems.md`](./foundations/governed-autonomous-systems.md) |
| bounded recursive improvement | [`bounded-recursive-improvement.md`](./foundations/bounded-recursive-improvement.md) |
| semantic world plane | [`domain-ontologies-and-data-recipes.md`](./foundations/domain-ontologies-and-data-recipes.md) |
| institutional learning boundary | [`institutional-learning-boundary.md`](./foundations/institutional-learning-boundary.md) |
| worker routing and training | [`mixture-of-workers.md`](./foundations/mixture-of-workers.md), [`worker-training-lifecycle.md`](./foundations/worker-training-lifecycle.md) |
| interop | [`aiip.md`](./foundations/aiip.md) |
| physical safety | [`physical-action-safety.md`](./foundations/physical-action-safety.md) |
| economics | [`economic-flywheel-and-pricing-boundaries.md`](./foundations/economic-flywheel-and-pricing-boundaries.md) |
| ecosystem assurance | [`ecosystem-assurance-certification-liability.md`](./foundations/ecosystem-assurance-certification-liability.md) |
| public settlement | [`ioi-l1-mainnet.md`](./foundations/ioi-l1-mainnet.md), [`ioi-l1-contract-interfaces.md`](./foundations/ioi-l1-contract-interfaces.md) |

### Component owners

| Area | Canonical owners |
| --- | --- |
| daemon runtime and cross-plane operability | [`doctrine.md`](./components/daemon-runtime/doctrine.md), [`api.md`](./components/daemon-runtime/api.md), [`events-receipts-delivery-bundles.md`](./components/daemon-runtime/events-receipts-delivery-bundles.md), [`task-capsule-protocol.md`](./components/daemon-runtime/task-capsule-protocol.md), [`platform-operability.md`](./components/daemon-runtime/platform-operability.md) |
| GoalRunProfile, GoalRun, Goal Kernel, topology, and context/handoff objects | [`common-objects-and-envelopes.md`](./foundations/common-objects-and-envelopes.md) |
| HarnessProfile and AgentHarnessAdapter step-resolution contracts | [`default-harness-profile.md`](./components/daemon-runtime/default-harness-profile.md) |
| portable memory | [`portable-memory-vault.md`](./components/daemon-runtime/portable-memory-vault.md) |
| improvement gates | [`improvement-governance-gates.md`](./components/daemon-runtime/improvement-governance-gates.md) |
| privacy and nodes | [`private-workspace-ctee.md`](./components/daemon-runtime/private-workspace-ctee.md), [`runtime-nodes-tee-depin.md`](./components/daemon-runtime/runtime-nodes-tee-depin.md), [`hypervisoros.md`](./components/daemon-runtime/hypervisoros.md) |
| embodied runtime | [`embodied-runtime.md`](./components/daemon-runtime/embodied-runtime.md) |
| Hypervisor product | [`core-clients-surfaces.md`](./components/hypervisor/core-clients-surfaces.md), [`providers-and-environments.md`](./components/hypervisor/providers-and-environments.md), [`improvement.md`](./components/hypervisor/improvement.md), [`evaluations.md`](./components/hypervisor/evaluations.md), [`foundry.md`](./components/hypervisor/foundry.md) |
| Hypervisor identity and supply | [`identity-access-and-metering.md`](./components/hypervisor/identity-access-and-metering.md), [`byo-provider-plane.md`](./components/hypervisor/byo-provider-plane.md) |
| model routing | [`doctrine.md`](./components/model-router/doctrine.md), [`api-byok-mounting.md`](./components/model-router/api-byok-mounting.md) |
| Agentgres | [`doctrine.md`](./components/agentgres/doctrine.md), [`api-object-model.md`](./components/agentgres/api-object-model.md), [`artifact-ref-plane.md`](./components/agentgres/artifact-ref-plane.md), [`projection-system-reference.md`](./components/agentgres/projection-system-reference.md), [`postgres-bridge-and-readiness-contract.md`](./components/agentgres/postgres-bridge-and-readiness-contract.md) |
| wallet authority | [`doctrine.md`](./components/wallet-network/doctrine.md), [`api-authority-scopes.md`](./components/wallet-network/api-authority-scopes.md), [`product-exchange-risk.md`](./components/wallet-network/product-exchange-risk.md) |
| connectors and tools | [`doctrine.md`](./components/connectors-tools/doctrine.md), [`contracts.md`](./components/connectors-tools/contracts.md) |
| storage | [`doctrine.md`](./components/storage-backends/doctrine.md), [`filecoin-cas.md`](./components/storage-backends/filecoin-cas.md) |

Some link labels repeat because the owner path, not the basename, carries the
namespace.

### Product and application-domain owners

| Domain | Canonical owners |
| --- | --- |
| ioi.ai Goal Space | [`collaborative-outcome-pattern.md`](./domains/ioi-ai/collaborative-outcome-pattern.md), [`control-plane.md`](./domains/ioi-ai/control-plane.md) |
| aiagent.xyz ontology-bound digital and embodied workers | [`worker-marketplace.md`](./domains/aiagent/worker-marketplace.md), [`digital-worker-ontology.md`](./domains/aiagent/digital-worker-ontology.md), [`vertical-ontology-packs.md`](./domains/aiagent/vertical-ontology-packs.md), [`integration-surface-taxonomy.md`](./domains/aiagent/integration-surface-taxonomy.md), [`managed-worker-instance-lifecycle.md`](./domains/aiagent/managed-worker-instance-lifecycle.md), [`managed-agent-console-contract.md`](./domains/aiagent/managed-agent-console-contract.md), [`worker-endpoints.md`](./domains/aiagent/worker-endpoints.md) |
| sas.xyz | [`service-marketplace.md`](./domains/sas/service-marketplace.md), [`service-endpoints.md`](./domains/sas/service-endpoints.md) |
| marketplace neutrality | [`marketplace-neutrality.md`](./domains/marketplace-neutrality.md) |
| decentralized route intelligence | [`README.md`](./domains/decentralized/README.md), [`exchange.md`](./domains/decentralized/exchange.md), [`trade.md`](./domains/decentralized/trade.md), [`cloud.md`](./domains/decentralized/cloud.md) |

## Runtime And Product Boundaries

| Layer or product | Owns | Does not own |
| --- | --- | --- |
| ioi.ai Goal Space | pre-admission intent drafts; read projections over GoalRun, OrchestrationPlan, and optional OutcomeRoom; room/workstream UX; subscription/budget controls; synthesis | admitted goal lifecycle, plan selection, execution effects, wallet authority, or global truth |
| OutcomeRoom | shared-pursuit policy and graph | runtime, marketplace, authority, global database |
| GoalRunProfile | reusable adaptive convergence composition | execution, authority, live run state, workflow graph, or domain state |
| GoalRun | bounded loop and typed orchestration | global collaboration or permanent memory |
| WorkflowTemplate | reusable directed-work graph shape | triggers, standing activation, adaptive pursuit, or run history |
| SkillManifest / SkillEntry / ActiveSkillSetSnapshot | immutable procedure / successor-versioned owner-scoped binding / exact admitted run selection | executable tool, authority, hook, or marketplace listing |
| Systems workspace | policy-filtered context/read model for one admitted `system_id` | System identity, membership, lifecycle, or admission truth |
| Work workspace | typed projections over GoalRuns, AutomationRuns, OutcomeRooms, Sessions, WorkRuns, queues, reviews, incidents, and history | a universal work lifecycle, authority, budget, evidence, or runtime truth |
| Session | bounded interactive, headless, or supervisory context | durable pursuit, standing behavior, collective pursuit, or execution-attempt truth |
| AutomationSpec / AutomationInstallationBinding / AutomationRun | reusable standing behavior / successor-versioned scope enablement and narrowing overlay / one activation freezing the exact template, spec, and binding | a generic background mission or daemon execution truth |
| WorkRun | one execution attempt bound to a typed work subject | its parent GoalRun, AutomationRun, OutcomeRoom, or queue lifecycle |
| Packages / Marketplace mode | package lifecycle / optional discovery, distribution, and commerce | System identity, surface origin, installation by discovery alone, or runtime truth |
| Hypervisor Core | shared client/control substrate | independent authority or truth beside daemon/Agentgres |
| Hypervisor Daemon | admission, scheduling, mediation/execution, receipts, fail-closed runtime boundary | inventing authority or universal truth |
| HypervisorOS | daemon-rooted bare-metal profile and node integrity | confidential-compute claim by itself |
| wallet.network | portable delegated and designated high-risk authority | runtime execution or operational truth |
| Agentgres | admitted domain-local operations, object heads, projections, roots | all memory, payload bytes, or one global graph |
| MemorySpace | portable governed memory truth | runtime admission or public settlement |
| storage backends | payload bytes and availability | semantic meaning or authority |
| model router | eligible cognition route selection and invocation | accountable labor actor or provider-seat resale |
| AIIP | typed inter-domain work, evidence, authority refs, disputes, settlement intents | remote database access or global sequence |
| IOI L1 | selected public registry, rights, economics, disputes, governance, roots | per-step runtime or operational notebook |

## North-Star Network Proof

IOI has demonstrated an Internet of Intelligence only when an independently
operated external Worker can discover eligible work through a policy-bound
projection, negotiate semantic/action profiles, submit a typed participation
request, receive bounded context/resource/authority/budget leases, claim work,
return a verifiable contribution, preserve credit and dispute lineage, and exit
with portable permitted state. The proof must not require participants to share
one runtime, operational database, administrator, or continued trust/access to
an IOI-hosted room. Same-owner multi-model, multi-worker, or multi-node
orchestration is a primary same-system L0 capability and proof target, but it is
not this cross-system network proof.

## Non-Negotiables

1. There is one governed operating fabric, not a daemon plus competing hidden
   runtimes in apps, harnesses, SDKs, editors, or provider adapters.
2. Hypervisor Type 1, Type 2, and Type 3 are deployment/control postures of one
   product, not three disconnected products.
3. OutcomeRoom is above GoalRun. Neither is one global graph or ambient swarm.
4. GoalRun is generic and loop-native; coding-specific files/diffs/tests live in
   the ImplementationResult profile, not the universal WorkResult contract.
5. Simple work collapses to a direct path. Parallelism and collaboration must
   earn their cost through uncertainty, expected value, independence, or
   verification need.
6. Multi-model, multi-worker, multi-node, and multi-party claims remain
   separate in schemas, UI, receipts, and economics. Useful multi-node work
   inside one `system_id` is native L0 coordination, not AIIP federation.
7. Participants and claims are explicit leases with scope, TTL, heartbeat,
   policy, visibility, authority, resource, and budget bounds.
8. Domain Ontologies and Agentgres truth are locally canonical. Cross-domain
   semantics require explicit versions, crosswalks, mapping decisions, and
   challenges.
9. Ontology semantics do not grant capability or authority.
10. Policy and authority providers authorize; the daemon admits, enforces,
    executes or mediates, receipts, and fails closed.
11. Workers receive declared `prim:*` capabilities and bounded `scope:*`
    authority grants, not ambient raw secrets or unlimited credentials.
12. Worker is the accountable labor actor; model is cognition; GoalRunProfile
    is reusable pursuit method; WorkflowTemplate is directed graph shape;
    HarnessProfile resolves one scoped step; RuntimeToolContract is callable
    capability; runtime node is placement; party is an independently governed
    principal.
13. MCP is a replaceable compatibility transport: tools normalize to
    RuntimeToolContract, resources to leased policy-bound projections, prompts
    to untrusted inputs, elicitation to typed input, tasks to external
    invocation handles, and Apps to sandboxed extension surfaces. Packages
    carry gateway requirements, never concrete live gateway profiles.
14. Named-human foundation-model subscriptions are not pooled, automated, or
    resold as production worker capacity unless an explicit provider agreement
    authorizes the exact use.
15. Every managed model route has a versioned rights contract. Missing rights
    fail closed; provider fallback is a semantic substitution.
16. A provider aggregator is a replaceable supply adapter, not the
    product moat, sole trust boundary, or excuse to ignore underlying terms.
17. Provider permission to perform inference does not imply logging, secondary
    use, training, or cross-customer aggregation of customer material; customer
    receipt of an output does not imply retention, replay, evaluation,
    RAG/memory, tuning, distillation, competing-model training, package reuse,
    publication, resale, or OEM rights.
18. Work Credits are bounded non-transferable product budget, not cash, provider
    tokens, pooled seats, worker payout, or the IOI protocol token.
19. Network/Open work uses explicit separate funding and preserves marketplace,
    service, verifier, attribution, dispute, and settlement owner boundaries.
20. A receipt is attributable evidence, not automatic correctness, truth,
    verification, acceptance, adjudication, settlement, or payout.
21. Assurance stages remain explicit from attested through settled and preserve
    negative, inconclusive, invalid, exploit, superseded, disputed, and no-fault
    information.
22. Effect recovery is typed. Ambiguous external effects reconcile before
    retry; restore is not reconciliation.
23. Persistent intelligence belongs to governed MemorySpace and Agentgres
    admission, not the selected model, harness, or local cache.
24. Improvement remains proposal-driven and gated by evidence eligibility,
    evaluation, policy, authority, receipts, effect recovery, and Agentgres
    admission. Campaign selection and improvement claims never self-promote.
25. Private/no-provider-trust claims require a custody-proven route. Contractual
    provider privacy is useful but is not cTEE no-plaintext custody.
26. Embodied action uses a slower mission/governance plane over isolated local
    autonomy, deterministic-motion, and runtime-assurance/safety strata. The
    final local veto and emergency stop cannot depend on a model, cloud, chain,
    remote wallet, or stale telemetry.
27. Storage backends hold bytes; Agentgres refs define meaning, lifecycle,
    integrity, policy/authority linkage, and restore validity.
28. AIIP transports bounded signed handoffs and refs only across independently
    governed system boundaries while each domain keeps local truth. Member-node,
    worker, or embodied-unit coordination inside one `system_id` uses native L0
    and Embodied Runtime contracts, not AIIP.
29. IOI L1 is sparse settlement and coordination, not the per-thought or
    per-tool execution database.
30. Product surfaces monetize real product value. Substrates meter, attest,
    authorize, record, or settle; token economics activate only with real
    verified network demand.
30. UI boards, chat, leaderboards, replays, and admin consoles are projections.
    They never become authority or canonical runtime truth by convenience.
31. Direct Sessions, Projects, AutomationSpecs, and stand-alone GoalRuns do not
    require creation of a System. Systems is the coherent read/context surface
    for work that is actually bound to an admitted `system_id`.
32. Work always exposes typed subject refs and applies policy before search,
    counts, caching, or recents. It does not flatten distinct work objects into
    one universal state machine.
33. The generic `HypervisorMission` is retired; optional Mission presentation
    profiles have exactly one GoalRun or OutcomeRoom backing and no independent
    lifecycle. Typed physical mission contracts remain canonical.
34. Packages owns package lifecycle even when Marketplace is absent.
    Marketplace is an optional distribution/commerce mode, not an application
    origin, install state, or separate truth owner.
35. One registered product-surface compiler serves shell, catalog, command
    palette, contextual, and API projections using independent surface class,
    publisher origin, creation method, distribution, availability, admission,
    installation, package disposition, enablement, capability depth, and
    operational state axes from `canonical-enums.md`.
36. Reference-product captures, parity matrices, and copied interaction
    patterns are evidence only. They cannot register a product surface, assign
    an owner, or grant operational maturity.

## Implementation Discipline

The target architecture is not a claim that every target object is built.
Consult [`implementation-matrix.md`](./_meta/implementation-matrix.md) for the
current durable form and code anchors. In particular, the existing narrow
software GoalRun is partial implementation; OutcomeRoom federation,
collaborative AIIP, full route-right enforcement, invoice-grade Work Credits,
the complete semantic action plane, and cross-domain assurance remain target
work unless the matrix is updated with current proof. The target Hypervisor
shell taxonomy, shared product-surface compiler, and registration axes likewise
remain target architecture where the matrix still records hard-coded catalogs,
routes, or parity-derived UI classifications.

When implementing:

```text
owner doc -> shared objects/enums -> API/envelope -> daemon/domain admission
          -> receipt/evidence -> Agentgres truth/projection -> conformance
```

Run the architecture documentation checks before claiming alignment:

```bash
npm run check:architecture-docs
git diff --check -- docs/architecture
```
