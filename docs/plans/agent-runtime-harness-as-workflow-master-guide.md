# Agent Runtime Harness-As-Workflow Master Guide

Last updated: 2026-05-08
Owner: agent runtime / workflow substrate / Autopilot GUI
Status: next-leg master guide

Companion documents:

- `docs/roadmap.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`
- `docs/plans/meta-harness-master-guide.md`
- `docs/specs/runtime/cursor-sdk-harness-parity-plus-master-guide.md`
- `docs/specs/runtime/harness-change-workflow.md`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-07T12-03-49-923Z/result.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-29-56-082Z/result.json`
- `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-36-18-437Z/dashboard-index.json`
- `docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`

## Executive Verdict

The next leg should be the transition from "the runtime harness is projected
into workflow-shaped components" to "the default live agent runtime is actually
driven by those workflow-addressable components."

Chronologically, this means:

1. Finish componentizing the runtime harness around explicit action frames,
   schemas, policies, receipt bindings, replay envelopes, and UI surfaces.
2. Run the workflow projection in shadow against the live `RuntimeAgentService`
   path until every major runtime decision can be correlated to a graph node.
3. Promote the blessed `Default Agent Harness` workflow from inspectable
   projection to the default runtime orchestration surface.
4. Let users fork the harness only after activation gates prove bindings,
   replay fixtures, tests, slots, policy posture, and receipt mapping are safe.

The focus is not just architectural neatness. The focus is proving one unified
substrate by dogfooding the real agent harness through the same workflow graph
model that users can inspect, test, package, propose changes to, and eventually
fork.

## Strategic Thesis

The roadmap already says the workflow canvas has strong bones and the agent
runtime is the part that must be componentized next. The key line is the
roadmap's current architecture read:

> `RuntimeAgentService` owns session lifecycle, step/resume, pending action
> state, approvals, PII, execution queue, transcript continuity, worker
> templates, and playbooks.

The implication is correct: componentize the harness before expanding
persistent agents, the model router, markets, or long-lived worker autonomy.

The product reason is equally important. A workflow-backed harness gives users
an inspectable mental model for why an agent planned, routed, asked approval,
called a tool, retried, repaired, verified, or stopped. It also creates a real
dogfood loop: the default agent that edits workflows should itself be running
through a workflow-backed harness.

## Latest Validated Checkpoint

As of 2026-05-08, the default live harness activation-id gate and default
runtime dispatch proof have a green end-to-end checkpoint:

- Full retained Autopilot GUI harness run:
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-29-56-082Z/result.json`
- Runtime P3 validation with required GUI evidence:
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-36-18-437Z/dashboard-index.json`

This checkpoint proves the GUI promotion flow can show the activation-id gate,
the fork activation click proof, the default runtime dispatch binding, live
handoff, route-stateful deep links, activation audit links, rollback restore
actions, and runtime evidence in one retained-query evidence bundle. It also
proves the blessed default dispatch is bound to
`activation:default-agent-harness:blessed-readonly` while the fork activation
wizard remains its own evidence object.

### 2026-05-08 Cognition Live Adapter Slice

The current implementation has started the first true component-promotion
slice inside the default dispatch path:

- Rust now treats `planner`, `prompt_assembler`, and `task_state` as
  `live_ready` canonical harness components.
- The shared adapter can invoke those components in `live` mode and still
  blocks later clusters that remain `shadow_ready`.
- The Autopilot default runtime dispatch proof now records
  `cognitionExecutionAdapterMode: workflow_component_adapter_live`,
  canonical adapter results, action frame ids, live-ready component kinds, and
  live node attempts for the cognition triplet.
- The TypeScript harness projection mirrors that readiness split so the GUI
  workbench and runtime proof cannot drift from Rust.
- Focused validation is green for the Rust harness contract, service adapter,
  Autopilot default dispatch store test, TS type check, harness contract
  consistency, shell wiring, and `test:autopilot-gui-harness`.
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-12-40-928Z/`,
  with the copied workflow proof showing three live cognition adapter results
  and `planner`, `prompt_assembler`, and `task_state` as live-ready.

This is not the full target end state yet. It is the first production-shaped
promotion wedge: the cognition envelope still uses the existing workflow node
executor for the actual envelope execution, but its authority proof now flows
through the canonical harness adapter result instead of only hand-assembled
attempt ids.

### 2026-05-08 Cognition Gate Adapter Slice

The second cognition slice extends the same proof pattern across the remaining
cognition cluster without prematurely promoting those gates to live authority:

- `uncertainty_gate`, `budget_gate`, and `capability_sequencer` now execute as
  staged workflow envelopes during default dispatch proof generation.
- Their canonical adapter invocations run in `gated` mode, keep
  `shadow_ready` readiness, emit node attempts, action frames, receipt refs,
  replay fixture refs, and divergence classifications.
- The default dispatch proof now distinguishes live cognition authority
  (`planner`, `prompt_assembler`, `task_state`) from staged cognition gates
  (`uncertainty_gate`, `budget_gate`, `capability_sequencer`).
- Full retained GUI validation is green in
  `docs/evidence/autopilot-gui-harness-validation/2026-05-08T09-29-56-082Z/`;
  the copied workflow proof shows three live adapter results, three gated
  adapter results, and `gateDivergenceClasses: ["none"]`.
- Runtime P3 with required GUI evidence is green at
  `docs/evidence/agent-runtime-p3-validation/2026-05-08T09-36-18-437Z/dashboard-index.json`.

This completes the cognition cluster proof shape while preserving the staged
promotion discipline: only the cognition authority triplet is live-ready; the
uncertainty, budget, and capability gates are proven through gated adapter
records until shadow/gated divergence criteria justify live promotion.

## Current State

### Roadmap State

`docs/roadmap.md` defines the relevant sequence:

- Phase 1: workflow runtime parity.
- Phase 2: harness componentization.
- Phase 3: harness-as-workflow.

The phrasing is already directionally right, but the next implementation leg
should treat Phase 2 and Phase 3 as one continuous migration:

- first make every live harness kernel an executable component contract;
- then bind those contracts into a blessed workflow graph;
- then dogfood live turns through that graph;
- then allow forked harness activation.

### Code State

The repository already has more than a sketch:

- `packages/agent-ide/src/runtime/harness-workflow.ts` defines
  `DEFAULT_AGENT_HARNESS_COMPONENTS`, `HARNESS_FLOW`,
  `runtimeBindingFor`, `makeDefaultAgentHarnessWorkflow`, and
  `forkDefaultAgentHarnessWorkflow`.
- `crates/types/src/app/harness.rs` defines typed Rust harness component,
  slot, action frame, retry, timeout, approval, receipt, and worker binding
  contracts.
- `crates/services/src/agentic/runtime/harness.rs` explicitly states that the
  current projection does not replace the live executor yet. It lifts existing
  runtime kernels into stable workflow-addressable frames.
- `apps/autopilot/src-tauri/src/project/runtime.rs` executes many workflow node
  kinds through an action vocabulary, including task state, uncertainty,
  probes, budget gates, capability sequences, dry run, semantic impact,
  postconditions, verifiers, drift detection, quality ledgers, handoff, GUI
  validation, model calls, tools, approval gates, and outputs.
- `apps/autopilot/src-tauri/src/kernel/data/commands/local_engine_support.rs`
  already exposes worker workflow records with a default harness workflow id,
  activation id, and harness hash.

That means the missing work is not "invent a harness graph." The missing work
is making the harness graph the live orchestration authority and proving it
with receipts, tests, replay, GUI inspection, and activation gates.

### Autopilot GUI Pass

I ran the Autopilot GUI locally and exercised the Chat and Workflows surfaces.
The GUI launched with:

```bash
AUTOPILOT_LOCAL_GPU_DEV=0 AUTOPILOT_RESET_DATA_ON_BOOT=0 AUTOPILOT_DEV_CLEAN_INSTANCE=0 AUTOPILOT_TAURI_WATCH=0 npm run dev:desktop
```

The Vite surface came up at `http://127.0.0.1:1428`, the native shell opened,
and the Workflows surface was reachable from the left activity bar.

I also ran:

```bash
npm run validate:autopilot-gui-harness
```

That generated:

```text
docs/evidence/autopilot-gui-harness-validation/2026-05-07T12-03-49-923Z/result.json
```

The retained-query validation passed with all 8 retained queries and runtime
evidence.

GUI observations:

- The shell has a clear Workflows entry point.
- The Workflows surface already presents the graph as a real workbench with
  Create, Bind, Run, and Ship control clusters.
- A `Harness` header action opens the read-only `Default Agent Harness` graph.
- The default harness graph shows component nodes and action-kind counts.
- The header exposes a harness binding badge, lifecycle state, read-only state,
  validation status, and blocked activation state.
- The right rail already has Settings, Readiness, Data, Search, graph,
  waveform/run, and validation-style panels.
- The bottom shelf already has Selection Preview, Data Preview, Suggestions,
  Warnings, Fixtures, Checkpoints, Proposal Diff, Test Output, and Run Output.
- Forking is intentionally gated through a `Fork harness` action and readiness
  blockers.

GUI gap:

The GUI has the right surface area for harness orchestration, but live agent
turns are not yet experienced as node-by-node harness executions. The next UX
work should turn node execution, receipts, policy decisions, replay fixtures,
and fork activation into first-class operator affordances rather than hidden
side effects.

## Target End State

The target end state is:

- the blessed default live agent runtime is backed by a workflow activation;
- every important runtime decision maps to a harness component node;
- every component has typed input, output, error, timeout, cancellation, retry,
  policy, approval, capability, receipt, and replay contracts;
- the Autopilot GUI can inspect live harness execution at node level;
- default harness changes happen through bounded workflow proposals;
- forked harnesses are packageable but blocked from activation until tests,
  fixtures, slots, policy, and receipt checks pass;
- persistent workers can declare which harness workflow id, activation id, and
  hash they are using;
- the agent runtime dogfoods the same substrate exposed to users.

This is the proof of unified substrate: the default agent runtime, user-created
workflows, workflow-as-tool calls, worker package manifests, tests, proposals,
receipts, and GUI inspection all speak one graph/action-frame language.

### Workflow-As-Code Source Control End State

The harness workflow should not grow a parallel fake source-control system. It
should be a typed domain control plane over real workflow-as-code artifacts and
the existing editor/source-control substrate.

Right end state:

- Workflow graphs, tests, fixtures, proposals, manifests, package metadata, and
  harness metadata are versioned files.
- Every activation is bound to a workflow path, repo root, branch, proposal id,
  activation id, content hash, worker binding, and rollback target.
- When the workflow is inside a Git repository, the activation also records the
  base commit, activated commit or tree hash, and any branch or compare target.
- Push/activation is a validated workflow-code promotion, not just a metadata
  mutation.
- Rollback restores a prior activation binding and can point back to the
  corresponding workflow revision, commit, or tree.
- VS Code/OpenVSCode-derived substrate owns generic authoring affordances:
  explorer, file search, source control, branch compare, text editing, and
  diff review.
- Autopilot owns workflow-domain affordances: readiness gates, receipts,
  canaries, policy posture, slots, activation ledger, worker binding, runtime
  mode, rollback proof, and fork activation.

This split matters. Git is the right substrate for versioning, diffs, branches,
reviews, and file rollback. The workflow runtime still needs a typed activation
ledger because policy gates, secret slots, worker bindings, receipts, canaries,
and live runtime authority are domain objects that raw Git does not model
safely by itself.

The core binding object should be explicit:

```text
WorkflowRevisionBinding
- workflow_path
- repo_root
- branch
- base_revision
- activated_revision
- workflow_content_hash
- proposal_id
- activation_id
- worker_binding
- rollback_activation_id
- rollback_revision
```

The GUI should make this feel like one coherent flow: edit workflow-as-code,
review a typed proposal diff, validate gates, activate the worker binding, and
retain a one-operation rollback target that is tied to the previous workflow
revision.

## Non-Goals

This leg should not become:

- a broad persistent-agent dashboard expansion;
- a marketplace or worker-store effort;
- a new model registry/router project beyond the harness-facing binding
  contract;
- a prompt-only harness rewrite;
- a GUI redesign detached from runtime contracts;
- unrestricted self-modifying agents;
- user-editable live harness activation without policy, tests, replay, and
  bounded proposal review.

## Non-Negotiable Invariants

### 1. The live runtime remains trustworthy during migration

The workflow-backed harness should start in projection and shadow modes before
it becomes the default executor. Live agent correctness must not depend on a
half-ported graph path.

### 2. No visible node may fake execution

If a node is visible and runnable, runtime validation must either execute it
honestly or block with a concrete reason. "Looks runnable but skips" behavior
is not acceptable for the default harness.

### 3. Runtime decisions need receipt correlation

Planner choices, model routing, tool routing, approval decisions, policy
blocks, retries, repairs, verification results, output writes, and completion
states must be mapped to workflow node ids.

### 4. Forks are packages, not live authority by default

Forking the harness should create an editable package with lineage, tests,
fixtures, slots, proposals, and activation blockers. It must not silently
replace the blessed runtime.

### 5. AI mutation remains proposal-only

The default harness may be analyzed and proposed against by agents, but
AI-authored changes must go through bounded workflow proposals and human or
policy-defined acceptance gates.

### 6. Policy and wallet authority are not graph decorations

Approval rules, wallet capability grants, connector permissions, BYOK key
brokerage, and policy constraints must remain enforced by runtime authority.
The graph exposes and parameterizes them; it does not bypass them.

### 7. Replay captures must be deliberate

Replay fixtures need redaction posture, deterministic envelope flags, input and
output capture semantics, and policy-decision capture semantics. The graph must
not accidentally persist sensitive transcript or connector data.

### 8. Workflow source control is substrate, not decoration

Workflow save, proposal, push, activation, and rollback paths must be able to
bind to workflow-as-code revision state. If a workflow lives in Git, the
activation ledger should preserve the relevant revision identity instead of
only storing a UI-local metadata mutation.

## Component Contract

Every harness component must declare the same minimum contract:

| Field | Requirement |
| --- | --- |
| Component id | Stable id used by TS workflow nodes and Rust action frames. |
| Kind | Typed harness component kind, mapped to a workflow node type. |
| Version | Component version for compatibility and activation checks. |
| Kernel ref | Runtime implementation reference or adapter boundary. |
| Input schema | JSON schema or Rust/TS generated schema for accepted input. |
| Output schema | JSON schema or Rust/TS generated schema for produced output. |
| Error schema | Typed error classes and retryability semantics. |
| Timeout | Default timeout, override policy, and cancellation behavior. |
| Retry | Retry class, max attempts, backoff, idempotency posture. |
| Capability scope | Model, tool, wallet, connector, memory, policy, or evidence scopes. |
| Approval semantics | Whether approval is never, conditional, required, or resumable. |
| Receipt binding | Event and evidence kinds mapped to workflow node ids. |
| Replay envelope | Input/output/policy capture, determinism, redaction, fixture support. |
| UI representation | Node title, group, icon, inspector summary, logs, warnings, and actions. |
| Activation checks | Slot requirements and validation blockers before live use. |

No component should be considered complete until it has the TS graph contract,
Rust action-frame contract, runtime adapter, receipt mapping, replay behavior,
tests, and UI affordance.

## Component Inventory

The default harness should be decomposed into these live-capable components.
The names below are intentionally close to the current projection so the
migration can be incremental.

| Component | Purpose | Priority |
| --- | --- | --- |
| Planner | Produce next plan step from session state, user request, and capability context. | P0 |
| Task state | Maintain objective, facts, uncertainty, stale facts, blockers, and evidence refs. | P0 |
| Uncertainty gate | Decide ask/retrieve/probe/dry-run/execute/verify/escalate/stop. | P0 |
| Budget gate | Bound reasoning, tool calls, retries, wall time, and verification spend. | P0 |
| Capability sequencer | Discover, select, sequence, and retire capabilities. | P0 |
| Model router | Select model binding under model policy and deployment profile. | P0 |
| Model call | Invoke selected model with request/response capture and streaming events. | P0 |
| Tool router | Select tool, connector, MCP, workflow-tool, or dry-run path. | P0 |
| Policy gate | Enforce runtime, approval, trust, data, and side-effect policy. | P0 |
| Approval gate | Interrupt, present decision, resume, reject, or edit action. | P0 |
| Wallet capability | Request, check, lease, revoke, and receipt wallet-backed authority. | P1 |
| MCP provider | Resolve MCP server, scope, availability, and containment. | P1 |
| MCP tool call | Invoke MCP tool with containment, request/response hashes, and receipts. | P1 |
| Plugin tool call | Invoke local/plugin tool through governed binding. | P1 |
| Connector call | Invoke external connector with auth, policy memory, and idempotency. | P1 |
| Workflow tool call | Execute child workflow as a typed tool with lineage. | P1 |
| Probe runner | Run cheap bounded validation for a hypothesis. | P1 |
| Dry-run simulator | Preview side effects and compare mutation risk before execution. | P1 |
| Memory read | Retrieve scoped memory with provenance and staleness posture. | P1 |
| Memory write | Persist memory with policy, summarization, and provenance. | P1 |
| Semantic impact analyzer | Estimate behavioral or code impact before applying changes. | P2 |
| Postcondition synthesizer | Generate concrete verification conditions from task intent. | P2 |
| Verifier | Run tests, checks, assertions, or semantic verification. | P0 |
| Drift detector | Detect state, context, dependency, or output drift. | P2 |
| Retry policy | Bound retries and classify retryable failures. | P0 |
| Repair loop | Produce fix-up attempts from typed failure state. | P1 |
| Merge judge | Decide accept/merge/retry/escalate for competing outputs. | P2 |
| Quality ledger | Record score, risks, unresolved issues, and confidence. | P1 |
| Handoff bridge | Package state for another worker or human handoff. | P2 |
| GUI harness validator | Validate GUI surfaces against retained harness scenarios. | P2 |
| Completion gate | Decide done/continue/escalate with stop-condition evidence. | P0 |
| Receipt writer | Persist receipts and node correlations. | P0 |
| Output writer | Materialize final response, artifact, patch, or external delivery. | P0 |

P0 components must exist before the default live agent runtime can be driven
by the workflow graph. P1 components are needed for serious dogfood. P2
components can mature after shadow mode starts but before broad fork activation.

## Runtime Architecture

### Layer 1: Live Runtime Kernel

The existing runtime kernel remains the source of actual authority for:

- session lifecycle;
- transcript continuity;
- execution queue;
- approvals and resumability;
- policy enforcement;
- tool and connector execution;
- wallet capability checks;
- PII and redaction;
- receipts;
- output materialization.

During the migration, this layer exports component kernels and event hooks
instead of being replaced wholesale.

### Layer 2: Harness Component Adapter

Each runtime kernel gets a harness adapter that knows how to:

- build a `HarnessActionFrame`;
- validate input and bound slots;
- call the live kernel or simulator;
- emit typed events;
- map receipts to workflow node ids;
- provide replay input/output captures;
- expose activation blockers.

This layer is the bridge between `RuntimeAgentService` and the workflow graph.

### Layer 3: Workflow Activation

A harness workflow activation compiles:

- workflow id;
- activation id;
- harness hash;
- workflow revision binding;
- component versions;
- slot bindings;
- model/tool/approval/memory/output policy;
- tests and replay fixtures;
- production profile;
- activation blockers and warnings.

The default activation is read-only and blessed. Fork activations are blocked
until validation mints a new activation id.

### Layer 4: Runtime Orchestrator

The orchestrator executes the active harness activation. It should support:

- projection mode: render the graph and metadata only;
- shadow mode: run live runtime and graph action frames side by side;
- gated mode: graph drives selected components while live runtime remains
  fallback authority;
- live mode: graph activation is the default runtime control plane.

### Layer 5: GUI and Package Surface

The GUI and package layer expose:

- graph topology;
- node config and slots;
- runtime mode;
- read-only vs fork state;
- activation readiness;
- run timeline;
- node IO;
- receipts;
- replay fixtures;
- proposal diffs;
- export/import packages;
- worker harness bindings.

## Chronological Plan

### Phase 0: Lock The Existing Projection

Goal: preserve the useful existing harness projection while preventing it from
being mistaken for full live orchestration.

Build:

- a short doc string in the GUI that distinguishes projection, shadow, gated,
  and live modes;
- a visible mode badge on harness workflows;
- a runtime capability check that reports which components are projection-only,
  simulated, shadow-ready, or live-ready;
- a generated component inventory diff between TS and Rust contracts;
- a no-regression test for default harness graph rendering, slot binding,
  worker binding, and fork lineage.

Exit criteria:

- The `Default Agent Harness` graph opens as read-only.
- The GUI reports activation state truthfully.
- Component inventory is generated or validated from shared contract data.
- Forking remains blocked from live use.

### Phase 1: Normalize The Action-Frame Contract

Goal: make TS node definitions, Rust validation, Rust execution, SDK events,
and receipt bindings share one action-frame vocabulary.

Build:

- a canonical `HarnessActionFrame` schema with id, kind, labels, ports,
  schemas, slots, policy, approval, timeout, retry, and receipts;
- generated TS types from Rust or generated Rust types from a shared schema;
- validation that every harness component has a node type and every node type
  maps to a valid action kind;
- stable error classes for blocked, unsupported, simulated, policy-blocked,
  approval-required, timeout, retry-exhausted, and receipt-missing cases;
- a fixture format for component-level input/output replay.

Exit criteria:

- No harness component can exist only in TS or only in Rust.
- Runtime validation explains unsupported components before execution.
- Component tests can run without a full chat/session path.

### Phase 2: Extract Live Runtime Kernels Into Components

Goal: convert `RuntimeAgentService` from a monolithic owner of all harness
behavior into an orchestrator over component kernels.

Build:

- planner component adapter;
- task-state component adapter;
- uncertainty gate adapter;
- budget gate adapter;
- model router and model call adapters;
- tool router adapter;
- policy and approval gate adapters;
- verifier adapter;
- retry, repair, completion, receipt, and output adapters;
- basic component registry in Rust with explicit capability scopes;
- component-level unit tests over retained fixtures.

Exit criteria:

- P0 component kernels can be invoked independently.
- Chat/session runtime still behaves the same through the existing path.
- Every P0 component emits a node-correlatable event.

### Phase 3: Receipt Correlation And Replay

Goal: make every live runtime turn inspectable through harness graph nodes.

Build:

- receipt binding from plan/routing/workload/execution/policy events to
  workflow node ids;
- per-node run attempt records with input, output, error, duration, and event
  refs;
- redacted replay fixture capture for P0 and P1 components;
- replay comparison between previous and current component versions;
- GUI node inspector sections for latest input, output, policy decision,
  receipt refs, replay envelope, and warnings.

Exit criteria:

- A live agent turn produces a harness-node timeline.
- Selecting a harness node shows the latest relevant decision and receipt refs.
- Replay fixtures can reproduce component outputs or explain nondeterminism.

### Phase 4: Shadow Harness Execution

Goal: run the workflow activation beside the live runtime until behavior and
events line up.

Build:

- shadow runner that consumes the same session state and proposed actions;
- diffing of live vs graph-selected decisions;
- stop reason, approval, routing, tool, verification, and output comparison;
- shadow evidence bundle written under `docs/evidence` or runtime trace
  storage;
- GUI compare panel for live vs shadow node results;
- failure classification for harmless divergence, policy divergence, missing
  receipt, and behavioral regression.

Exit criteria:

- Retained chat/workflow dogfood runs produce shadow reports.
- The default harness graph explains live runtime decisions without driving
  them yet.
- P0 divergence rate is low enough to begin gated execution.

### Phase 5: Gated Default Harness Execution

Goal: let the workflow activation drive selected low-risk components while the
legacy runtime path remains fallback authority.

Build:

- feature flag for component-by-component graph authority;
- live execution for planner/task-state/uncertainty/budget first;
- then model routing/model call;
- then verifier/retry/completion/output;
- finally policy/approval/tool/router paths after receipts are stable;
- automatic fallback and incident receipts for graph execution failures;
- GUI mode controls for default, shadow, and gated diagnostics.

Exit criteria:

- The default agent runtime can run through graph authority for P0
  non-side-effect components.
- Fallbacks are explicit, receipted, and visible.
- No hidden bypass path is presented as graph success.

### Phase 6: Full Default Live Harness

Goal: promote the blessed default harness workflow activation to the default
runtime control plane.

Build:

- default worker binding to harness workflow id, activation id, and hash;
- workflow revision binding on the blessed activation, including workflow path,
  content hash, and revision identity when Git is available;
- live orchestration through the compiled harness graph;
- node-level streaming events in the GUI;
- durable run records linked to harness node attempts;
- activation hash included in SDK, CLI, GUI, and worker records;
- conformance test proving a standard live chat turn maps to graph nodes.

Exit criteria:

- The default live agent runtime is driven by the blessed harness activation.
- Users can inspect why the harness planned, routed, asked, executed, verified,
  retried, repaired, or stopped.
- Runtime, SDK, CLI, and GUI all report the same harness binding.

### Phase 7: Forkable Harness Activation

Goal: allow advanced users to fork the harness and activate forks safely.

Build:

- fork package export/import with component versions and slot manifests;
- source-control-backed proposal diffs for workflow graph, tests, fixtures,
  manifests, package metadata, and harness metadata;
- activation wizard for tests, fixtures, live bindings, policy, wallet grants,
  replay samples, output contracts, and production profile;
- proposal review for graph/config/metadata/sidecar diffs;
- compatibility checks against the blessed harness version;
- canary and rollback controls;
- worker-level selection of a validated harness activation.

Exit criteria:

- Forking produces an editable package with lineage.
- Activation is blocked until validation passes.
- A persistent worker can point to a forked harness activation by id.
- Rollback to the blessed default harness is one operation and fully receipted.
- Rollback can identify the workflow revision, commit, or tree that produced
  the prior activation.

## GUI Requirements

The current GUI has the foundation. The next leg should add or harden the
following operator affordances.

### Already Present

- Workflows left-nav entry.
- Graph/proposals/executions tabs.
- Create, Bind, Run, Ship header clusters.
- `Harness` button to open the default graph.
- `Fork harness` action.
- Read-only harness badge.
- Harness worker binding badge.
- Harness settings summary with template, activation, components, and slots.
- Fork lineage and activation blocker summaries.
- Readiness checklist.
- Node selection preview.
- Node IO workbench.
- Bottom shelf for suggestions, warnings, fixtures, checkpoints, proposal diff,
  tests, and run output.
- Stable selectors for dogfood automation.

### Required Next

- Runtime mode badge: projection, shadow, gated, live.
- Component readiness badge: projection-only, simulated, shadow-ready,
  live-ready.
- Node execution timeline for live harness turns.
- Node decision explainer for planner, uncertainty, budget, router, policy,
  approval, verifier, retry, and completion gates.
- Receipt refs and replay envelope visible on every harness component node.
- Live vs shadow comparison panel.
- Collapsible and expandable node groups for complex harness phases, with
  typed boundary ports and warning/receipt/status rollups.
- Harness activation wizard for forked graphs.
- Slot binding editor specialized for model, tool, memory, approval, wallet,
  verifier, output, retry, and handoff policies.
- Component diff view between blessed and forked harnesses.
- Canary, rollback, and fallback visibility.
- Worker binding picker that shows workflow id, activation id, hash, mode, and
  validation age.
- Source-control posture that shows workflow path, branch, dirty state,
  proposal id, activation revision, compare target, and rollback revision.
- Dogfood launcher for retained chat queries, workflow scratch probe, and
  harness shadow suites.

### Workflow-As-Code UI Boundary

Use the VS Code/OpenVSCode substrate for generic code-workflow mechanics:

- file explorer for workflow bundle files and sidecars;
- Monaco/source editor for workflow JSON, tests, fixtures, manifests, and
  generated package files;
- source-control view for dirty files, branch state, staging, commit posture,
  and compare target;
- diff editor for proposal review, fork comparison, activation changes, and
  rollback preview;
- search across workflow files, proposals, receipts, fixtures, and manifests.

Keep Autopilot-specific workflow controls in the workflow GUI:

- graph canvas and grouped harness topology;
- activation wizard and readiness gates;
- slot binding, policy posture, canary status, and receipt coverage;
- worker binding picker and activation ledger;
- rollback drill, rollback execution, and rollback proof;
- live/shadow/gated runtime timeline and node-level receipt/replay inspectors.

The design goal is not to turn the workflow GUI into a raw code editor. The
goal is to make workflow-as-code feel native: the generic authoring substrate
handles files and diffs, while the workflow workbench handles runtime meaning.

### UI Primitive Decision Gate

When adding a new workflow GUI element for advanced harness orchestration, use a
short design-context gate before choosing or inventing the component. The goal
is a broad shared interaction vocabulary, not imitation of another product.

Required decision sequence:

1. Check existing IOI/Autopilot primitives first.
2. Review the AIP reference evidence for comparable graph/workbench mechanics:
   `docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`.
3. Prefer the shared vocabulary when it fits: rails, mini maps, tabs, split
   panes, bottom shelves, inspectors, workbench panels, tables, status chips,
   cards, legends, expand/collapse groups, focused-node workbenches, and
   branch/compare banners.
4. State why the chosen primitive fits the operator task: inspection,
   navigation, comparison, activation, rollback, receipt tracing, replay,
   policy review, or output control.
5. Avoid bespoke UI when a familiar primitive already covers the interaction.
6. Preserve IOI semantics and visual language: receipts, activation state,
   policy posture, slots, worker bindings, replay, rollback, runtime modes,
   workflow revision binding, and proposal-only mutation.

This gate should run before implementation decisions for right rails, mini
maps, tabs, split panes, cards, expand/collapse controls, status chips, tables,
workbench panels, activation surfaces, and rollback surfaces.

### Collapsible Harness Groups

Complex harness workflows need a screen-real-estate model that lets users move
between operational altitude and component detail without losing trust. The
default harness should support visual grouping where a cluster can collapse
into one node and expand back into its internal graph.

Recommended default groups:

| Group | Components |
| --- | --- |
| Cognition | Planner, task state, uncertainty gate, budget gate, probe runner. |
| Routing | Capability sequencer, model router, tool router. |
| Authority | Policy gate, approval gate, wallet capability. |
| Execution | Model call, MCP provider, MCP tool call, plugin tool call, connector call, workflow tool call, dry-run simulator. |
| State | Memory read, memory write, drift detector. |
| Verification | Semantic impact analyzer, postcondition synthesizer, verifier, quality ledger. |
| Recovery | Retry policy, repair loop, merge judge. |
| Output | Completion gate, receipt writer, output writer, handoff bridge. |

Rules:

- Collapse is a visual abstraction, not semantic hiding.
- A collapsed group must expose typed boundary ports, schema summaries, slot
  requirements, and activation state.
- Warnings, blockers, failed tests, approval requirements, side effects,
  receipt gaps, replay gaps, and live/shadow divergence must roll up to the
  collapsed node.
- Clicking a rollup issue should expand the group and focus the exact inner
  node.
- Search, validation, run timelines, proposal diffs, and receipt links must be
  able to address inner nodes even when the group is collapsed.
- Package export should preserve expanded internals, group metadata, and the
  user's preferred collapse state separately from runtime semantics.

This gives the Palantir-style benefit of compact graph altitude while keeping
IOI's stronger runtime guarantees visible.

### Reference Mechanics From AIP Browser Pass

The Palantir AIP pipeline pass is useful because it shows a mature pattern for
managing dense operational graphs without making the canvas carry every
interaction. These are product mechanics to consider for the harness leg, not
visual requirements. The user-provided screenshot evidence is indexed in
`docs/evidence/harness-as-workflow-aip-reference/2026-05-06/README.md`.
The browser-control workflow used to inspect that app is captured separately in
`docs/plans/browser-use-master-guide.md`.

Useful mechanics:

- Right rail as output/control inventory: show produced outputs, deployment or
  mapping status, and output settings without forcing users to open every node.
- Right rail mode strip: keep narrow icon tabs for output inventory, graph
  search, branch/change comparison, deployment posture, runtime/build settings,
  schedules, file tree, tests, and sources.
- Mini graph in the rail: provide a compressed graph overview that stays useful
  when the main canvas is zoomed into an expanded group or detailed workbench.
- Bottom workbench that changes with selection: use the bottom area for
  selection preview, input/output data, transformations, warnings, fixtures,
  checkpoints, proposal diff, tests, and run output.
- Focused node workbench: allow a selected or expanded node/group to take over
  the main work area with a toolbar, `Expand all`, close/apply controls, and
  row-level step inspection.
- Deep-linkable expanded state: the browser URL can represent a focused
  cluster/node path. Harness groups should likewise support durable links to a
  selected component, expanded group, selected replay fixture, or run attempt.
- Expand-all and close controls: make it easy to descend into detail and return
  to the compact graph without losing context.
- Legend with visibility toggles: expose categories, counts, and eye/open
  toggles so large graphs can be filtered by component family or runtime state.
- Read-only and branch posture banners: make permission, fork, branch, compare,
  proposal, saved, and deploy posture visible at the top of the workbench.
- Status rollups on output cards: show mapping completeness, deployment
  posture, validation status, or receipt health in compact cards.
- File-tree navigation beside the graph: expose a dense list of graph objects
  or components so users can navigate by name without panning the canvas.
- Empty-state panels with local actions: schedules, tests, sources, and search
  panels should show clear empty states and relevant local actions instead of
  generic blank rails.
- Row-level status in expanded workbenches: inner steps should show applied,
  previewable, deprecated, warning, blocked, disabled, or upgrade-needed states
  directly on the row.
- Input/output table affordances: previews should expose row count, column
  count, schema/column search, column stats, input sampling, and row-count
  calculation in the same workbench as the selected step.

How this maps to the harness leg:

- The default harness graph needs a right rail that can show worker binding,
  activation, outputs, receipt health, policy posture, and selected-node
  details as separate modes.
- Harness rail modes should include at least: receipts/outputs, search,
  live-vs-shadow changes, activation/deploy posture, runtime settings,
  schedules/triggers, component tree, tests, sources/inputs, policy, and
  capabilities.
- Collapsed harness groups should pair with a mini graph so users can navigate
  the whole runtime while one group is expanded.
- Expanded groups should get a focused workbench with inner-node steps,
  boundary IO, replay fixtures, live/shadow comparison, warnings, and policy
  decisions.
- Expanded harness groups should be URL-addressable by group id, component id,
  run id, replay fixture id, and selected panel so links can jump directly to a
  failing receipt or activation blocker.
- The top bar should make read-only blessed mode, fork lineage, proposal mode,
  activation state, and live/shadow/gated/live runtime mode impossible to miss.
- Output and receipt cards should behave like first-class operational objects,
  not only terminal nodes on the canvas.
- A component tree panel should provide dense navigation over all harness
  components, slots, tests, policy gates, outputs, and receipt writers.
- Tests and schedules/triggers panels should keep their own empty states,
  create actions, and readiness warnings instead of hiding inside global
  settings.
- `Expand all` should exist at group, phase, and selected-node levels, but
  expanded state must remain UI state rather than runtime semantics.
- Graph filters should support component kind, policy side-effect class,
  approval requirement, readiness state, run status, failed receipts, and
  live/shadow divergence.
- The bottom shelf should remain selection-sensitive and should not become a
  generic log dump. It should promote the exact workbench needed for the
  selected graph altitude.
- Component rows in expanded harness workbenches should show run status,
  replay status, deprecation/version warnings, policy blockers, preview/dry-run
  availability, and upgrade/proposal affordances.
- Harness input/output previews should mirror the table mechanics for runtime
  payloads: schema fields, redaction status, sampled fixtures, event counts,
  receipt refs, and replay row/attempt counts.

### UX Principle

The harness graph should feel like an execution workbench, not a diagram. A
user should be able to select a node and answer:

- What input did this component see?
- What policy and slots constrained it?
- What decision did it make?
- What evidence or receipts support that decision?
- What changed from the blessed default?
- Can this node be replayed?
- Did the shadow graph agree with live runtime?
- Is this fork safe to activate?
- If this is a collapsed group, which inner node owns the current status,
  warning, receipt, or blocker?

## Dogfood Plan

### Lane 1: Retained Chat Queries

Run the existing retained GUI harness queries through projection and shadow
mode. Capture:

- harness graph opened;
- active harness binding;
- live turn receipt mapping;
- shadow comparison;
- GUI cleanliness.

### Lane 2: Workflow Scratch Probe

Continue using the workflow scratch GUI dogfood that manually builds primitive
workflows instead of loading hidden templates. Add harness-specific assertions:

- open default harness;
- inspect component counts;
- select P0 components;
- capture node input/output after a run;
- fork harness;
- observe activation blockers;
- export package only after readiness checks.

### Lane 3: Default Agent Runtime Dogfood

Use the normal agent runtime to edit workflow and harness code while it is
itself shadowed by the harness graph. This is the real substrate proof.

Capture:

- agent prompt;
- live runtime events;
- graph action frames;
- divergence summary;
- node-level receipts;
- final response and verification.

### Lane 4: Forked Harness Canary

Create a harmless fork that changes a low-risk policy, such as a verifier
threshold or retry bound. Run retained scenarios in canary mode. Require:

- component diff;
- replay fixture pass;
- no policy regressions;
- canary rollback proof;
- explicit activation id.

### Lane 5: Worker Binding Proof

Bind a persistent worker record to a validated harness activation. The GUI,
runtime, SDK, and CLI should all agree on:

- harness workflow id;
- activation id;
- harness hash;
- validation status;
- component version set;
- policy profile.

## Validation Matrix

| Gate | Command or evidence | Purpose |
| --- | --- | --- |
| GUI harness retained queries | `npm run validate:autopilot-gui-harness` | Proves retained GUI preflight and clean harness contract. |
| Workflow wiring | `npm run test -- apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts` or existing package script | Proves GUI selectors, harness controls, and workflow surface wiring. |
| Runtime P3 contract | `npm run validate:agent-runtime-p3` | Proves smarter runtime and harness contract lanes. |
| Runtime tests | `npm run test:agent-runtime-p3` | Exercises agent runtime P3 test surface. |
| Rust harness tests | targeted `cargo test` for `agentic::runtime::harness` and `ioi_types::app::harness` | Proves component contracts and receipt mapping. |
| Workflow execution tests | targeted Tauri/project runtime tests | Proves visible node kinds execute or block honestly. |
| Shadow comparison | new harness shadow evidence bundle | Proves graph/action-frame decisions match live runtime. |
| Fork activation | new activation readiness tests | Proves forked harness cannot activate without slots, fixtures, policy, tests, and receipts. |
| Worker binding | local engine worker support tests | Proves worker records expose harness id, activation id, and hash. |

## Acceptance Criteria

This leg is complete when all of the following are true:

- The default harness graph is generated from shared TS/Rust component
  contracts, not duplicated ad hoc lists.
- Every P0 harness component has typed input, output, error, timeout, retry,
  capability, approval, receipt, replay, and UI contracts.
- A normal live agent turn produces a node-level harness timeline.
- Live runtime receipts map to workflow node ids.
- The GUI can show node input, output, policy decision, receipts, and replay
  status for the harness turn.
- Shadow mode compares live runtime decisions against graph action frames.
- Gated mode can safely let selected components be graph-driven.
- Full live mode uses the blessed default harness activation as the default
  runtime control plane.
- Forking the harness creates an editable, packageable workflow with lineage.
- Forked harness activation is blocked until validation, tests, fixtures,
  slots, policy, and receipt mapping pass.
- Persistent workers can declare harness workflow id, activation id, and hash.
- SDK, CLI, GUI, worker records, and runtime traces expose the same harness
  binding.

## Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Graph path diverges from live runtime semantics. | Shadow mode with decision diffing before promotion. |
| Component contracts duplicate between TS and Rust. | Generate one side or validate both from a shared manifest. |
| GUI implies forked harnesses are live-ready too early. | Explicit projection/shadow/gated/live badges and activation blockers. |
| Replay captures sensitive data. | Redaction policy, fixture scopes, deterministic envelope metadata, and opt-in captures. |
| Policy is weakened by graph editability. | Runtime authority remains final; graph slots parameterize policy but do not bypass it. |
| Half-supported nodes create false confidence. | Unsupported/simulated/live readiness states and validation blockers. |
| Migration regresses normal chat. | Component-by-component gated rollout with fallback receipts. |
| Fork activation becomes too hard to understand. | Activation wizard, actionable blockers, component diff, and canary/rollback controls. |

## Immediate Work Queue

1. Add a harness execution mode model shared by TS workflow metadata and Rust
   activation records: `projection`, `shadow`, `gated`, `live`.
2. Add a component readiness status model:
   `projection_only`, `simulated`, `shadow_ready`, `live_ready`.
3. Create a shared harness component manifest test that compares TS
   `DEFAULT_AGENT_HARNESS_COMPONENTS` with Rust `default_agent_harness_components`.
4. Add component-level fixtures for P0 components.
5. Add receipt correlation coverage for planner, routing, workload, approval,
   policy, verifier, completion, and output events.
6. Add a shadow runner that consumes live turn state and emits graph decision
   diffs.
7. Extend the GUI node inspector with harness node receipts, live/shadow
   comparison, replay status, and activation blockers.
8. Add collapsible harness groups with typed boundary ports, rollup badges,
   inner-node search/focus, and preserved group metadata.
9. Add deep-linkable expanded harness state for group id, component id, run id,
   replay fixture id, and selected rail/bottom panel.
10. Add harness-specific right rail modes for receipts/outputs, search,
   live-vs-shadow changes, activation posture, runtime settings,
   schedules/triggers, component tree, tests, sources/inputs, policy, and
   capabilities.
11. Add row-level expanded workbench status for component run state, replay
   state, deprecation/version warnings, policy blockers, preview/dry-run
   availability, and upgrade/proposal affordances.
12. Add a fork activation wizard and block live worker binding until activation
   id minting succeeds.
13. Add a retained dogfood run where the default agent edits workflow code while
   the harness graph shadows the turn.
14. Promote gated graph authority one P0 component cluster at a time.

## Recommended First PR Slice

The first implementation slice should be deliberately small:

- introduce `harnessExecutionMode` and `componentRuntimeStatus` fields;
- surface them in the default harness workflow metadata and GUI badges;
- add validation that default harness components exist in both TS and Rust;
- add a read-only GUI note explaining projection vs shadow vs gated vs live;
- extend `validate:autopilot-gui-harness` expectations to capture the mode
  badge.

That slice will not make the harness live-driven yet, but it creates the
language the rest of the migration needs and prevents the current projection
from being over-claimed.

## Open Questions

- Should the canonical component manifest be Rust-first, JSON-schema-first, or
  generated from a small language-neutral manifest?
- Should shadow mode run synchronously inside the live turn, asynchronously
  after the turn, or both depending on latency profile?
- What is the minimum divergence threshold before promoting a component from
  shadow-ready to gated?
- Which policy decisions are allowed to be parameterized by a forked harness,
  and which must remain fixed by the runtime or wallet authority?
- Should forked harness activations be user-local only at first, or can they be
  bound to persistent workers after canary proof?

## Final North Star

The default live agent should be able to say, in the GUI and in receipts:

```text
I ran under harness workflow default-agent-harness,
activation default-agent-harness@v1,
hash <hash>.

Planner chose this step.
Uncertainty gate chose this action.
Budget gate allowed it.
Policy gate constrained it.
Tool/model router selected this binding.
Verifier accepted or rejected it.
Completion gate stopped for this reason.

Every decision is visible as a workflow node.
Every node can be tested, replayed, proposed against, and safely forked.
```

That is the end state: not a workflow skin over an agent, but the agent runtime
proving the workflow substrate by living inside it.
