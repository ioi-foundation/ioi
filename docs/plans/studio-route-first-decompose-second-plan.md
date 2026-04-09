# Studio Route-First Decompose-Second Plan

Last updated: 2026-04-09
Owner: Studio / execution fabric / Autopilot shell / Agent IDE
Status: in progress

Companion documents:

- `docs/specs/CIRC.md`
- `docs/specs/CEC.md`
- `docs/plans/adaptive-scoped-swarm-execution-plan.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`

## Purpose

This document defines the concrete migration from the current Studio
artifact-execution baseline to the desired control architecture:

- route first
- decompose second
- execute only the justified work graph

The immediate goal is to stop treating swarm as an eager or default path for
artifact work.

The longer-term goal is to make swarm a planner-governed mutable work graph
that is:

- generic rather than artifact-specific
- budgeted rather than open-ended
- adaptive rather than predetermined
- truthful in the UI rather than represented as a canned ten-step workflow

## Implementation status

The repo now partially implements this plan.

### Shipped in code

- the execution ladder is now explicitly `single_pass`, `plan_execute`,
  `micro_swarm`, and `adaptive_work_graph`
- legacy `swarm` remains a compatibility alias for
  `adaptive_work_graph`
- artifact outcome selection no longer implies swarm by default
- a cheap execution-mode gate now runs after outcome routing and before graph
  execution
- execution-mode decisions, budget envelopes, and completion invariants now
  serialize through the shared execution envelope
- `micro_swarm` is a real bounded mode with a distinct budget profile and
  product-surface label
- Studio pipeline surfaces now render direct, planned, micro, and adaptive
  paths more truthfully instead of always projecting a canned artifact ceremony
- safe dispatch planning now treats already-terminal work items correctly when
  building frontier batches

### Still broader follow-on work

- deeper cross-domain execution-fabric maturity beyond the current Studio-heavy
  lane
- richer planner-driven graph mutation beyond the current bounded artifact
  adapters
- more generic semantic-conflict handling across non-artifact domains
- additional rollout tuning once the broader branch-level Studio HTML fixture
  suite is stabilized

## Core doctrine

The governing rule for this plan is:

> Do not decompose because a swarm exists; decompose only when the planner can
> justify that a bounded work graph has higher expected value than direct
> execution within the assigned budget.

That doctrine implies four non-negotiable boundaries:

- CIRC resolves intent and outcome shape without heuristic shortcuts.
- An execution-mode gate decides whether one bounded execution unit is enough.
- A planner only decomposes work after escalation is justified.
- CEC governs deterministic execution, verification, and completion after the
  mode is selected.

## Problem summary

The current system has improved, but it is still architecturally misaligned
with the target shape.

### What is wrong today

- Artifact work has historically over-escalated into swarm-like execution.
- Strategy selection and decomposition are still too tightly coupled.
- The existing artifact swarm path still starts from a largely predetermined
  plan template rather than a discovered work graph.
- The system lacks a middle tier between one-shot and full swarm.
- Product surfaces still risk showing static orchestration phases that do not
  correspond to the real execution shape.

### Why that is wrong

- It violates CIRC by letting coarse product class influence execution policy
  too early.
- It violates the intended CEC discipline by doing expensive decomposition
  before proving that decomposition is required.
- It makes coordination tax look free even when latency, merge cost, and repair
  loops dominate the run.
- It models swarm as "many workers exist" instead of "a mutable work graph is
  required to satisfy the run-level completion invariant."

## Desired end state

The desired system should behave like this:

1. Resolve the user request into an outcome and a cheap execution-mode
   decision.
2. Use direct execution when the request is satisfiable as one bounded unit.
3. Use planning without swarm when structure helps but parallelism does not.
4. Use a small bounded graph when the work naturally splits into a few nodes.
5. Use a full adaptive work graph only when the request implies multiple
   obligations, hidden dependencies, or likely graph mutation during
   execution.
6. Terminate when the run-level completion invariant is satisfied, not when a
   canned workflow finishes.

## CIRC and CEC alignment

This plan should be implemented as an explicit bridge between the repo's two
governing contracts.

### CIRC responsibility

CIRC should remain responsible for:

- intent resolution
- typed outcome selection
- capability-feasibility discipline
- eliminating ad hoc keyword and artifact-class routing hacks

### CEC responsibility

CEC should remain responsible for:

- discovery and synthesis discipline
- single-shot or bounded execution semantics once a node is chosen
- verification and completion gating
- receipt-driven final adjudication

### New control layer between them

This plan introduces an execution control layer between CIRC and the node-level
CEC execution phases.

That layer owns:

- execution-mode selection
- budget-envelope assignment
- graph planning when required
- frontier dispatch
- graph mutation
- graph pruning
- completion-invariant evaluation

## Execution mode ladder

Studio should explicitly support four execution modes.

### 1. `single_pass`

Use when:

- the request is well-specified
- the output is bounded
- no meaningful decomposition is justified
- revision cost is low or moderate
- one-shot sufficiency confidence is high

Properties:

- one worker
- no replan
- no merge
- no repair unless policy explicitly allows one narrow post-pass

### 2. `plan_execute`

Use when:

- the request benefits from planning or structuring
- execution is still best represented as one bounded work unit
- parallel workers do not materially increase expected value

Properties:

- planner may create structure
- execution still lands as one bounded synthesis unit
- verification remains mandatory
- no swarm frontier exists

### 3. `micro_swarm`

Use when:

- the request implies a small known graph
- there are only two or three meaningful work nodes
- critique, evidence, packaging, or assembly would help
- a full adaptive swarm would be latency overkill

Properties:

- maximum three workers
- one merge pass
- one replan maximum
- one repair loop maximum
- strict wall-clock and token caps

This is the highest-leverage new tier because it closes the gap between
one-shot and full swarm.

### 4. `adaptive_work_graph`

Use when:

- the request cannot be cleanly satisfied as one bounded execution unit
- the request implies multiple obligations
- hidden prerequisites or dependencies are likely
- the work graph is only partially knowable at the start
- expected value from decomposition exceeds coordination cost

Properties:

- rolling-wave planning
- frontier-based execution
- node spawning and pruning
- budget-aware expansion
- deterministic assembly and verification

During migration, the current wire-level `swarm` label may remain as a
compatibility alias, but the architecture should treat it as
`adaptive_work_graph`, not as "artifact mode."

## Execution-mode gate

Before any decomposition prompt runs, the system should perform a cheap
execution-mode decision.

That gate should score at least these dimensions:

- one-shot sufficiency confidence
- ambiguity level
- work-graph size estimate
- hidden-dependency likelihood
- verification pressure
- revision cost
- evidence breadth
- merge burden
- expected payoff from decomposition

The gate should emit a typed `ExecutionModeDecision` object with fields like:

- `outcome_kind`
- `execution_mode`
- `mode_confidence`
- `one_shot_sufficiency`
- `work_graph_required`
- `decomposition_reason`
- `budget_envelope`
- `escalation_receipt`

The gate must be cheap, fast, and auditable. It must not emit a full graph.

## Planner model

If and only if the mode requires decomposition, the planner should produce an
initial work-graph hypothesis.

The planner should not emit "workers first." It should emit required work
first.

The planner output should include:

- top-level objective
- decomposition hypothesis
- decomposition type
- mandatory nodes
- speculative nodes
- dependency assumptions
- first executable frontier
- spawn conditions
- prune conditions
- merge strategy
- verification strategy
- fallback collapse strategy
- run-level completion invariant

This planner may be probabilistic.

Its outputs must still be normalized into deterministic node contracts before
execution begins.

## Node contract

Every executable node should carry a deterministic contract.

Minimum node fields:

- `node_id`
- `objective`
- `allowed_capabilities`
- `tool or runtime lane`
- `read_scope`
- `write_scope`
- `budget`
- `success_criteria`
- `required_evidence`
- `output_schema`
- `merge_contract`

This preserves the current strongest invariant in the repo:

- one canonical state
- scoped mutation
- receipted execution
- merge before verification

## Decomposition styles

The planner should choose a decomposition style rather than filling in one
fixed template.

Supported styles should include:

- functional decomposition
- content decomposition
- evidence decomposition
- perspective decomposition
- candidate decomposition
- repair decomposition

The planner must also be allowed to emit:

- no decomposition
- two-node decomposition only
- serial decomposition because write scopes overlap
- speculative side branches with pruning conditions

## Rolling-wave execution

The adaptive runtime should execute the graph through repeated frontiers rather
than through a fully predetermined DAG.

The loop should be:

1. Load the current graph state and budget envelope.
2. Dispatch the currently unblocked frontier.
3. Collect node receipts, evidence, and merge outcomes.
4. Verify partial state against the completion invariant.
5. Ask the planner whether to expand, prune, fuse, collapse, or stop.
6. Emit the next frontier or terminate.

The graph should be discovered, not merely instantiated.

## Completion and pruning

This system should not use candidate-answer early exit as its primary stopping
logic.

The correct early-exit model is work-graph pruning plus run-level completion
checks.

The runtime should support:

- pre-planning early exit
- mid-planning collapse to direct execution
- in-graph pruning of now-unnecessary nodes
- node fusion when earlier outputs reduce downstream obligations
- terminal completion once the completion invariant is satisfied

The key stopping object is the run-level completion invariant.

That invariant should answer:

- which obligations are mandatory
- which nodes are still unresolved
- which required sections or deliverables must exist
- which verification conditions must pass before completion

## Budget envelopes

Every execution-mode decision should assign a budget envelope before work
begins.

Minimum envelope fields:

- `max_workers`
- `max_parallel_depth`
- `max_replans`
- `max_wall_clock_ms`
- `max_tokens`
- `max_tool_calls`
- `max_repairs`
- `expansion_policy`

Suggested defaults:

- `single_pass`: one worker, zero replans, zero merge
- `plan_execute`: one worker, one planning pass, zero graph expansion
- `micro_swarm`: up to three workers, one replan, one merge, one repair
- `adaptive_work_graph`: policy-sized envelope with revocable branches

Expansion should be earned through confidence deficits rather than assumed up
front.

## Product-surface truthfulness

The UI should render execution truth, not workflow theater.

That means:

- a direct or `plan_execute` run should not show planner/swarm/merge phases
  unless they actually happened
- `micro_swarm` should look like a small graph, not like a shrunk version of a
  fixed ten-step artifact ceremony
- `adaptive_work_graph` should show frontiers, graph mutations, pruning, and
  completion-invariant progress
- the route decision should expose why escalation happened and what budget was
  assigned

## Current implementation map

The current repo already contains most of the scaffolding needed for this
migration.

### Routing and strategy

Primary touch points:

- `crates/api/src/studio/planning.rs`
- `crates/api/src/execution.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/content_session.rs`

These paths should own:

- typed execution-mode decisions
- escalation receipts
- budget envelopes
- compatibility mapping from current `swarm` handling to the new ladder

### Planning and graph execution

Primary touch points:

- `crates/api/src/studio/generation.rs`
- `crates/api/src/studio/generation/swarm.rs`
- `crates/api/src/studio/types.rs`
- `crates/api/src/execution.rs`

These paths should evolve from:

- static upfront artifact swarm plans

to:

- initial graph hypotheses
- frontier dispatch
- graph mutation receipts
- pruning and completion-invariant checks

### Kernel materialization and session state

Primary touch points:

- `apps/autopilot/src-tauri/src/kernel/studio/materialization.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/prepare.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/proof.rs`

These paths should preserve:

- execution-mode decisions
- budget envelopes
- graph state
- completion-invariant status
- truthful terminal receipts

### Pipeline and UI presentation

Primary touch points:

- `apps/autopilot/src-tauri/src/kernel/studio/pipeline.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/tests.rs`
- the Studio/Spotlight renderer surfaces in `apps/autopilot/src`

These paths should stop assuming:

- artifact implies swarm
- swarm implies a fixed workflow

and instead project:

- actual execution mode
- actual frontier history
- actual graph mutations
- actual verification and completion state

## Implementation phases

### Phase 0: Contract and type cleanup

Deliverables:

- define the four execution modes
- add a typed budget envelope
- add a typed execution-mode decision receipt
- add a typed completion-invariant object
- add compatibility rules for existing `swarm` receipts and session state

Exit criteria:

- no code path infers full swarm from artifact type alone
- strategy selection is receipt-backed and serializable

Current status:

- shipped

### Phase 1: Cheap escalation gate

Deliverables:

- split route selection from decomposition
- add a fast execution-mode gate after outcome routing
- keep the gate local-runtime friendly
- store escalation rationale and budgets in the execution envelope

Exit criteria:

- the router decides between `single_pass`, `plan_execute`,
  `micro_swarm`, and `adaptive_work_graph`
- no full graph planning happens before escalation is justified

Current status:

- shipped for the shared Studio routing path with typed decision receipts and
  budget envelopes

### Phase 2: Planner and decomposer split

Deliverables:

- introduce a planner prompt and schema for initial graph hypotheses
- remove the assumption that the planner must emit a full worker graph up front
- add decomposition-style selection
- require a run-level completion invariant for graph modes

Exit criteria:

- decomposition is represented as required work nodes, not canned worker roles
- the planner can emit no decomposition or a small graph without penalty

Current status:

- partially shipped; the planner prompt and graph metadata now distinguish
  decomposition from routing, but deeper graph mutation remains follow-on work

### Phase 3: Ship `micro_swarm`

Deliverables:

- implement the bounded three-worker tier
- support small known graphs
- bound merge and repair counts
- expose a distinct `micro_swarm` surface in receipts and UI

Exit criteria:

- medium-complexity artifact work no longer escalates directly to full swarm
- local HTML and similar artifact requests can use a small graph path

Current status:

- shipped

### Phase 4: Frontier runtime

Deliverables:

- add frontier-based dispatch
- add graph mutation and pruning operations
- add planner-directed replan hooks
- make dispatch batches a first-class rolling-wave object

Exit criteria:

- the graph can expand, shrink, or collapse during execution
- the runtime is no longer dependent on a full upfront DAG

Current status:

- partially shipped; frontier dispatch, graph receipts, and bounded replans are
  real, but broader domain-generic graph mutation remains follow-on work

### Phase 5: Completion-invariant gating

Deliverables:

- define invariant evaluation for each execution mode
- gate termination on the run-level invariant, not workflow exhaustion
- support in-graph pruning and node fusion
- keep merge and verification deterministic

Exit criteria:

- runs stop because the obligations are satisfied
- unnecessary branches are pruned before they consume full budget

Current status:

- partially shipped; completion invariants now flow through the execution
  envelope and pipeline, while deeper pruning/fusion policies remain follow-on

### Phase 6: Product-surface alignment

Deliverables:

- update pipeline rendering to reflect actual mode and frontier history
- expose escalation rationale and budget use
- expose graph mutations and pruned nodes when relevant
- remove static step assumptions from artifact surfaces

Exit criteria:

- a user can tell why the system escalated
- a user can tell whether they are on a direct, planned, micro, or adaptive
  path
- a user never sees a fake planner/swarm story for a direct run

Current status:

- shipped for the Studio pipeline and execution chrome surfaces touched by this
  migration

### Phase 7: Rollout and policy tuning

Deliverables:

- ship dark-launch evaluation counters
- compare latency, first-render time, repair frequency, and completion quality
- tune thresholds for the escalation gate and micro-swarm admission

Exit criteria:

- full adaptive swarm is used only when its value exceeds its coordination tax
- pathological long-running artifact cases fall materially without hurting
  complex-task quality

Current status:

- not complete; requires branch-level stabilization and live telemetry after
  the control-plane rollout

## Required tests

The migration should add or update tests at four levels.

### Resolver and gate tests

- artifact type alone does not force swarm
- direct, planned, micro, and adaptive routing are all reachable
- route decisions are stable under paraphrase where CIRC expects stability

### Planner tests

- the planner can emit zero-node decomposition beyond direct execution
- the planner can emit a small known graph
- the planner can emit a mutable graph hypothesis with speculative nodes
- the planner always emits a completion invariant for graph modes

### Runtime tests

- frontier dispatch respects dependencies and scopes
- graph mutation can add and prune nodes
- completion-invariant checks stop the run without exhausting every speculative
  node
- budget envelopes block unbounded expansion

### Product-surface tests

- the pipeline reflects the chosen mode truthfully
- non-swarm runs do not show swarm phases
- micro-swarm and adaptive-work-graph runs display different orchestration
  evidence

## Success criteria

This plan succeeds when all of the following are true:

- Studio no longer uses artifact type as a proxy for swarm.
- The system has a real middle tier between one-shot and full swarm.
- Decomposition is justified before it happens.
- Graph execution is frontier-based rather than locked to a canned workflow.
- Completion is governed by run-level obligations and verification, not by
  finishing a fixed sequence of steps.
- The UI tells the truth about what the runtime actually did.

## Final north-star sentence

Studio swarm should become a planner-governed mutable work graph, not a
parallel answer generator and not a default artifact ceremony.
