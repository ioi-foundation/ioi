# Governed Autonomous Systems and Hypervisor Nodes

Status: canonical architecture authority.
Canonical owner: this file for governed autonomous-system chains, Hypervisor Node settlement domains, collaborative-pursuit topology, and the coherent machine-economy stack.
Supersedes: product prose that collapses Hypervisor UI, Hypervisor Node, autonomous-system state machines, and IOI L1 into one layer.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (improvement-proposal plane and a narrow GoalRun multi-harness slice built; generalized OutcomeRoom / CollaborativeWorkGraph, autonomous-system chains, federated admission, and local settlement domains planned or speculative)
Last implementation audit: 2026-07-11

## Canonical Definition

**A governed autonomous-system chain is a policy-bound, stateful autonomous
execution object whose harness invokes typed service modules, emits receipts,
and commits consequential transitions only through deterministic authority and
governance paths.**

Short form:

> **Autonomous systems are not prompts. They are governed execution objects.**

Protocol thesis:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

An agent is not a model loop. In IOI canon, a serious agent or worker-backed
autonomous system is an intelligent execution node inside a governed
autonomous-system chain. It can reason, plan, diagnose, route work, and propose
upgrades, but its consequential actions become ordered, receipted, replayable
state transitions under policy and authority.

This is a system-local base layer in the state-machine sense. It is not
necessarily a public blockchain, a standalone L1, a validator in global
consensus, or an IOI L1 replacement.

The broader system is one architecture, not an autonomy hypervisor beside a
separate enterprise-ontology product:

```text
federated ontologies make a domain legible
GoalRun and collaborative pursuit turn legibility into purposeful work
Hypervisor isolates and executes that work
local/domain governance and wallet.network authorize consequential power
Agentgres admits each domain's operational truth
AIIP connects independently governed domains
IOI L1 settles only the selected commitments that need shared finality
```

Canonical category:

> **IOI is an open, edge-sovereign operating fabric for governed autonomous
> systems. Hypervisor is its reference execution and control environment; the
> ontology layer is its semantic world plane, not a competing platform.**

## Layer Distinction

These layers must not collapse into one another:

```text
Hypervisor clients/surfaces != Hypervisor Node != IOI L1
```

The canonical stack is:

```text
Federated Semantic World Plane
  namespaced ontologies, object/action/event contracts, mappings, and policy-bound views

Collaborative Pursuit Plane
  OutcomeRoom / CollaborativeWorkGraph above bounded GoalRuns and GoalGroundingLoops

Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts

Hypervisor Node
  local orchestration, interop, authority integration/enforcement, state,
  replay, routing, and local settlement

AIIP
  RPC-shaped, receipt-native work interop across bounded execution domains

IOI L1
  global identity, registry, rights, receipt roots, disputes, reputation, and economic settlement
```

These planes compose without sharing one runtime, database, administrator, or
global ontology. Hypervisor clients remain projections; `OutcomeRoom` is a
collaboration profile rather than a second runtime; Agentgres truth remains
domain-local; public consensus remains exceptional.

## Hypervisor Node

A **Hypervisor Node** is the local autonomous-system settlement domain for a
user, organization, project, or deployment.

It is not merely a Hypervisor client or application surface. It is the
node-shaped composition of:

- Hypervisor App, Hypervisor Web, CLI/headless, and application surfaces such
  as Workbench, Foundry, and Environments views as operator
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

> **Hypervisor Nodes are local settlement domains for autonomous systems; IOI L1
> is the global settlement layer for the machine economy.**

More compactly:

> **Hypervisor settles autonomous work locally. IOI settles machine labor globally.**

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

### IOI L1 Settlement

IOI L1 anchors only the commitments that need public trust or economic finality:

- `ai://` names and manifest roots;
- identity and publisher commitments;
- install, license, service, escrow, bond, and payout rights;
- policy, module, upgrade, receipt, benchmark, routing, contribution, and
  reputation roots when public or economic trust requires them;
- dispute commitments and resolution outcomes;
- protocol and reference-implementation governance.

IOI L1 is not every agent's operational history.

## Harness and Service Modules

An autonomous-system harness is the modular state-transition pipeline running
under the Hypervisor Daemon. Each consequential harness step should be represented as a
typed service-module invocation.

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

| Harness Step | Service-Module Interpretation |
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

## Coordination At Two Scales

The governed-system architecture has two coordination scales. They must not be
collapsed into one universal conductor or one implicit swarm:

```text
OutcomeRoom / CollaborativeWorkGraph
  shared objective, frontier, participation, claims, attempts, findings,
  resources, evaluation, contribution lineage, course correction, and replay

    -> GoalRun A -> GoalGroundingLoop -> bounded harnesses / workers
    -> GoalRun B -> GoalGroundingLoop -> bounded harnesses / workers
    -> GoalRun C -> GoalGroundingLoop -> bounded harnesses / workers

  admitted deltas update the shared frontier and may create or retire GoalRuns
```

`GoalRun` answers how one bounded participant or subteam grounds, executes,
verifies, repairs, and continues a goal. `OutcomeRoom` answers how many
participants discover work, claim it, exchange permitted artifacts, preserve
positive and negative attempts, challenge evaluation, and collectively change
course. AIIP carries that participation across autonomous-system boundaries.

The `OutcomeRoom` / CollaborativeWorkGraph is a composition profile over the
existing owners, not a peer runtime or a magically global Agentgres graph. It
binds:

- objective, constraints, acceptance, stop, visibility, budget, artifact
  license/export, participation, contribution, and settlement policies;
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
  -> execute isolated or cooperative attempts
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

## Improvement Proposal Plane

Bounded recursive improvement is proposal-mediated improvement. IOI does not
need a global "meta harness" that owns every model, tool, memory, workflow, and
runtime. It needs an **Improvement Proposal Plane** that converts evidence into
governable patches.

The dangerous version is:

```text
agent modifies itself directly
selected harness writes durable skills/memory by itself
Foundry training silently mutates live runtime behavior
```

The IOI version is:

```text
trace, failure, correction, receipt, or eval reveals an improvement opportunity
-> worker, harness, compositor, verifier, or human proposes a patch
-> daemon runs simulation, evaluation, and policy checks
-> wallet.network or governance path approves, rejects, or escalates
-> Agentgres records the accepted operation and receipts
-> IOI L1 receives a sparse commitment only when public trust or settlement requires it
```

Canonical invariant:

> **Agents and harnesses do not self-modify directly. Autonomous systems propose
> improvements to governed objects, and only policy-bound, receipted governance
> makes those improvements canonical.**

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
- workflow graphs;
- contracts;
- tool bindings;
- model routes;
- skills;
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
SkillCandidate
MemoryCandidate
ToolCallRefinement
WorkflowPatch
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

Default use should remain simple: many services will run one workflow, one
selected model route, one selected HarnessProfile, and a few skills/memory
projections. Distributed recursive improvement should add skills, memory,
tool-call refinements, route policies, verifiers, or workflow patches only
where evidence shows value.

Harness orchestration is primarily context orchestration. The goal kernel should
split work into independent Context Cells only when separation creates value:
protecting long-horizon intent, bounding implementation-token churn, enabling a
fresh review, isolating private context, or satisfying policy. It should not
spawn agent chatter merely because multiple harnesses are available.

The implemented GoalRun policy is an intentionally narrow first slice:
`parallel_implement_reconcile`, one deterministic conductor, at most two
implementers, isolated software workspaces, implementation-shaped task briefs,
deterministic candidate verification, and one admitted reconciliation. It is
evidence for bounded multi-harness execution, not evidence that open joining,
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
reconciliation. Independent verifier harnesses, different-model review, human
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

The high-to-low contract for a harness-of-harnesses implementation is:

```text
Product intent
  User asks ioi.ai or Hypervisor Session to build, fix, review, publish, or run.

Goal coordination
  GoalRun records normalized intent, constraints, loop phase, continuation,
  receipts, selected RoleTopology, and selected VerifierPath.

Conductor orientation
  GoalGroundingLoop gathers canon/project/runtime/memory grounding, inspects
  current state, selects topology, and decides direct execution vs delegation.

Context partition
  Context Cells isolate conductor, implementer, reviewer, verifier, operator,
  or specialist context only when separation creates value.

Context governance
  Context Leases scope the files, docs, memory, tools, connectors, authority,
  budget, runtime, and receipt views each cell or harness may use.

Typed handoff
  ContextHandoff with a TaskBriefPayload carries objective, scope, constraints,
  do-not-touch rules, acceptance, verification plan, and output contract.

Harness broker
  HarnessInvocation adapts the task brief into the selected HarnessProfile or
  Agent Harness Adapter. Rendered prompts or commands are adapter-private; they
  are not the durable contract.

Adapter normalization
  HarnessAdapterEvents translate provider/harness-specific output into common
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

This is how IOI removes the human copy-paste relay between harnesses. Humans may
observe, approve, or override, but cross-harness coordination should flow through
typed handoffs, harness invocations, normalized events, implementation results,
verifier paths, and receipts.

Codex, Claude Code, OpenCode, local agents, browser agents, CI agents, and
future harnesses are eligible implementations of these roles through
HarnessProfiles. The canon defines the role topology and evidence contracts, not
a permanent vendor binding.

Portable memory is the default continuity layer for persistent agents. A
selected harness may summarize, cache, embed, or retrieve context for one run,
but it should not become the durable owner of the agent's learned preferences,
procedures, failures, route notes, or project conventions. Those changes should
land as `ContextMutationEnvelope` records against Agent Wiki / `ioi-memory`
with policy, retention, archive, and projection refs. This keeps persistent
background agents portable across model routes, harness adapters, private-mode
runtimes, managed instances, local installs, and marketplace upgrades.

The agent should be intelligent upstream of the boundary and deterministic at
the commitment boundary.

## Interop Fabric

Hypervisor is the reference local interop and settlement fabric for autonomous
systems. AIIP is the shared semantic protocol that lets Hypervisor route local
microharness work and hand off external work to workers, services, enterprises,
third-party autonomous systems, independent AS-L1s, and participants in a
cross-domain OutcomeRoom.

Canonical line:

> **AIIP moves autonomous work across systems. IOI settles what happened.**

AIIP plays an agent-native interop role comparable to interchain communication,
but for delegated work, authority, receipts, settlement claims, reputation, and
handoffs rather than token-ledger messaging.

Hypervisor Node interop messages may include:

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

Local interop and external interop should use the same AIIP semantics. The
difference is transport, trust boundary, privacy posture, and settlement depth.

```text
same semantic protocol
different transport and settlement mode
```

AIIP does not turn cross-domain messages into universal truth. Each domain
admits its own state; the declared hosted or federated room policy admits shared
room projections. A receipt authenticates the boundary statement it binds.
Verification, acceptance, adjudication, and settlement remain later and
distinct assurance states.

## Machine-Economy Stack

The coherent product and protocol roles are:

| Surface | Canonical Role |
| --- | --- |
| Hypervisor | Local sovereign coordination layer for autonomous systems. |
| Hypervisor Daemon | Deterministic execution and authority-enforcement substrate. |
| Agentgres | Local/domain canonical operational truth, projections, proposals, receipts, and state roots. |
| wallet.network | Authority, secrets, leases, grants, approvals, payment authority, and revocation. |
| Model Router | Policy-bound cognition routing; model weights/endpoints are deployment-profile resources. |
| AIIP | RPC-shaped interop protocol for bounded autonomous work, handoffs, authority leases, receipts, settlement intents, disputes, and reputation queries. |
| OutcomeRoom / CollaborativeWorkGraph | Shared-frontier collaboration profile over GoalRuns, Agentgres domains, `MultiPartyCollaborationEnvelope`, and AIIP; not a new runtime or global truth store. |
| Domain Ontologies / ODK | Federated semantic world plane and executable object/action contracts used by workers, rooms, generated domain apps, and cross-domain handoffs. |
| ioi.ai | First outcome-conductor and Goal Space product over Hypervisor; it does not own runtime, authority, marketplace supply, or operational truth. |
| aiagent.xyz | First-party worker and service-module marketplace built on AIIP and IOI settlement. |
| sas.xyz | First-party outcome and Service-as-Software marketplace built on AIIP and IOI settlement. |
| IOI L1 | Global autonomous-system settlement, registry, reputation, dispute, rights, and root-anchoring layer. |

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
   finality when IOI L1 anchoring or dispute windows are required.
7. Do not assume model weights are part of a Hypervisor Node binary. Bundled
   weights are a deployment profile, not the architecture default.
8. Do not create separate bespoke interop protocols for local microharnesses,
   aiagent.xyz, sas.xyz, and third-party autonomous systems when AIIP semantics
   apply.
9. Do not imply a globally mutable CollaborativeWorkGraph. Every room must name
   its hosted or federated ordering and admission topology.
10. Do not present multi-model, multi-worker, or multi-node IOI-operated work as
    independent multi-party federation.
11. Do not force ontology, marketplace, room, wallet ceremony, or L1 settlement
    onto a simple local goal when the relevant trust boundary is absent.

## One-Line Doctrine

> **Each Hypervisor Node is a local autonomous-system settlement domain. It hosts
> governed chains and bounded GoalRuns, may participate in declared hosted or
> federated OutcomeRooms, routes work through AIIP, manages portable authority
> through wallet.network, stores admitted state and receipts through Agentgres,
> and anchors only selected commitments to IOI L1 for shared registry, dispute,
> reputation, rights, or economic settlement.**
