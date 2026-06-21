# Governed Autonomous Systems and Hypervisor Nodes

Status: canonical architecture authority.
Canonical owner: this file for governed autonomous-system chains, Hypervisor Node settlement domains, and the coherent machine-economy stack.
Supersedes: product prose that collapses Hypervisor UI, Hypervisor Node, autonomous-system state machines, and IOI L1 into one layer.
Superseded by: none.
Last alignment pass: 2026-05-25.

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

## Layer Distinction

These layers must not collapse into one another:

```text
Hypervisor clients/surfaces != Hypervisor Node != IOI L1
```

The canonical stack is:

```text
Governed Autonomous-System Chains
  local agents, workers, workflows, policies, modules, proposals, receipts

Hypervisor Node
  local orchestration, interop, authority, state, replay, routing, and local settlement

AIIP
  RPC-shaped, receipt-native work interop across bounded execution domains

IOI L1
  global identity, registry, rights, receipt roots, disputes, reputation, and economic settlement
```

## Hypervisor Node

An **Hypervisor Node** is the local autonomous-system settlement domain for a
user, organization, project, or deployment.

It is not merely a Hypervisor client or application surface. It is the
node-shaped composition of:

- Hypervisor App, Hypervisor Web, CLI/headless, and application surfaces such
  as Workbench, Foundry, and Providers / Environments views as operator
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

The agent should be intelligent upstream of the boundary and deterministic at
the commitment boundary.

## Interop Fabric

Hypervisor is the reference local interop and settlement fabric for autonomous
systems. AIIP is the shared semantic protocol that lets Hypervisor route local
microharness work and hand off external work to workers, services, enterprises,
third-party autonomous systems, and independent AS-L1s.

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
- dispute evidence.

These messages must be typed, policy-bound, replayable, and receipt-backed when
they influence consequential state.

Local interop and external interop should use the same AIIP semantics. The
difference is transport, trust boundary, privacy posture, and settlement depth.

```text
same semantic protocol
different transport and settlement mode
```

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

## One-Line Doctrine

> **Each Hypervisor Node is a local autonomous-system settlement domain. It hosts
> many governed autonomous-system chains, routes work between them, manages
> authority through wallet.network, stores state and receipts through Agentgres,
> and anchors selected commitments to IOI L1 for global registry, dispute,
> reputation, and economic settlement.**
