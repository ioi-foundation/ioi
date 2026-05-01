# Adaptive Scoped Swarm Execution Plan

Last updated: 2026-04-09
Owner: execution fabric / Studio / Autopilot shell / Agent IDE
Status: in progress

Companion documents:

- `docs/plans/meta-harness-master-guide.md`
- `docs/plans/autopilot-canvas-runtime-unification-plan.md`
- `docs/plans/autopilot-desktop-ux-visibility-scratchboard.md`

## Purpose

This document defines the implementation path from the current scoped swarm
baseline to the north star:

- preserve the current shared-state patch swarm as the base species
- lift it into a domain-generic execution fabric
- grow it into `adaptive_scoped_swarm`
- only call it `full_execution_swarm` once dynamic replanning, safe parallel
  dispatch, leases, semantic conflict handling, and budget-aware coordination
  are real

The intent is not to replace the current swarm with a looser autonomous system.

The intent is to keep the strongest invariants already present:

- one canonical state
- planner-defined work items
- bounded write scopes
- change, merge, and verification receipts
- narrow repair after merge

and then add orchestration intelligence on top.

## Canonical framing

The system should be described with these boundaries:

- `swarm` is an execution strategy, not a product surface
- `artifact` is an execution domain, not the parent abstraction
- the parent abstraction is a generic execution envelope with typed domain
  children

The long-term target is:

- a policy-driven, domain-generic execution fabric
- whose strongest strategy is `adaptive_scoped_swarm`

## Current baseline

The repo now has a real shared-state swarm foundation:

- a generic execution stage model
- a shared execution envelope
- a canonical artifact state
- scoped work items
- change receipts
- merge receipts
- verification receipts
- narrow repair on the merged state

This corresponds to:

- `single_pass`
- `plan_execute`
- `scoped_patch_swarm`

What does not yet exist in a fully mature form:

- dynamic work graph evolution during execution
- lease-based concurrency control
- semantic conflict detection
- adaptive replanning
- safe parallel dispatch as a normal capability
- budget-aware strategy selection and throttling
- cross-domain maturity at the same level as the artifact lane

## North star

The north star is not "every query uses swarm."

The north star is:

- a generic execution envelope
- multiple execution strategies under that envelope
- policy- and budget-aware strategy selection
- domain adapters that define decomposition, merge, and verification behavior
- product surfaces that expose execution truth without turning orchestration
  into the main UI

The target maturity ladder is:

1. `single_pass`
2. `plan_execute`
3. `micro_swarm`
4. `adaptive_work_graph`
5. `full_execution_swarm`

## Current status snapshot

The repo now ships a route-first execution ladder on the Studio path:

- `single_pass`
- `plan_execute`
- `micro_swarm`
- `adaptive_work_graph`

The active chat execution strategy now serializes the generic
`adaptive_work_graph` label. Persisted historical records may still mention
`swarm`, but new runtime contracts should not accept or introduce it as a wire
alias.

What is now real:

- policy-aware execution-mode selection on the Studio route
- typed budget envelopes
- typed execution-mode decisions in the shared execution envelope
- completion invariants flowing through kernel and pipeline surfaces
- truthful `micro_swarm` versus `adaptive_work_graph` labels in the product
  surface
- safer rolling frontier dispatch for already-terminal nodes

What remains broader follow-on work for this plan:

- deeper generic execution-module extraction
- wider cross-domain substrate maturity for reply, research, workflow, and code
- semantic conflict handling beyond the current artifact-heavy lane
- the full north-star exit criteria below

## Non-goals

This plan does not aim to create:

- a freeform multi-agent system with disconnected candidate universes
- a default swarm route for every query
- a hidden whole-world regeneration loop marketed as repair
- a UI where users primarily stare at orchestration internals
- a concurrency-first system without ownership and semantic conflict controls

## Invariants to preserve

These should remain true through every phase of the migration:

### 1. Canonical shared state

Workers operate against one canonical state, not separate artifact or reply
universes.

### 2. Scoped mutation

Workers return bounded changes, not wholesale rewrites of the world.

### 3. Receipted execution

Planning, dispatch, work, changes, merges, verification, and repair must remain
observable.

### 4. Merge then verify

Local worker success is insufficient. Acceptance is based on the merged state.

### 5. Narrow repair preference

Repair must stay bounded to cited failures unless the adapter explicitly marks
the state unrecoverable.

## Architecture layers

The target architecture has four layers.

### Layer 1: Execution substrate

This should become the stable foundation shared by all domains.

It owns:

- canonical state
- generic execution envelope
- work graph
- work-item status
- ownership and lease state
- change receipts
- merge receipts
- verification receipts
- repair receipts
- execution summary
- budget and timing accounting

Target end-state modules:

- `crates/api/src/execution/types.rs`
- `crates/api/src/execution/graph.rs`
- `crates/api/src/execution/leases.rs`
- `crates/api/src/execution/merge.rs`
- `crates/api/src/execution/verification.rs`
- `crates/api/src/execution/budget.rs`

This layer should not know how HTML, conversation, research, or code work in
detail.

### Layer 2: Coordination intelligence

This is where the system becomes a real adaptive swarm.

It owns:

- strategy selection
- planner
- dispatcher
- dependency tracker
- replan engine
- conflict detector
- repair coordinator
- budget controller

Target end-state modules:

- `crates/api/src/execution/strategy.rs`
- `crates/api/src/execution/planner.rs`
- `crates/api/src/execution/dispatch.rs`
- `crates/api/src/execution/dependencies.rs`
- `crates/api/src/execution/replan.rs`
- `crates/api/src/execution/conflicts.rs`
- `crates/api/src/execution/repair.rs`

### Layer 3: Domain adapters

Each domain plugs into the generic execution fabric through typed adapter
contracts.

Initial domains:

- artifact
- reply
- workflow
- research
- code

Each adapter defines:

- decomposition rules
- validity rules
- semantic conflict signals
- merge policies
- verification suites
- repair heuristics
- budget defaults

### Layer 4: Product surfaces

Product surfaces expose execution truth, but do not become the parent
abstraction.

They own:

- compact status
- receipts and inspector
- repair and rerun controls
- developer observability
- policy controls

The default experience should remain outcome-first, not orchestration-first.

## Execution envelope target

The generic execution envelope should converge on this shape:

- `strategy`
- `plan`
- `execution_summary`
- `work_graph`
- `worker_receipts`
- `change_receipts`
- `merge_receipts`
- `verification_receipts`
- `repair_receipts`
- `budget_summary`
- `domain_details`

The `domain_details` child should carry adapter-specific evidence such as:

- artifact render findings
- research source evaluations
- workflow command receipts
- code build or test outputs
- reply-specific provenance or truthfulness evidence

## Work graph target

Each work item should eventually support:

- `id`
- `role`
- `domain`
- `owned_surfaces`
- `dependency_ids`
- `lease_requirements`
- `status`
- `spawned_from`
- `retry_policy`
- `escalation_policy`
- `verification_policy`
- `budget_allocation`

Worker results should be able to report:

- completed change
- no-op
- blocked
- conflict
- dependency discovered
- subtask request
- replan request
- verification concern
- repair suggestion

## Swarm maturity definitions

### `scoped_patch_swarm`

This is the current base species.

It includes:

- shared canonical state
- planner-defined work items
- bounded mutation
- deterministic merge
- integration-time verification
- narrow repair

### `adaptive_scoped_swarm`

This is the next major target.

It adds:

- dynamic work graph evolution
- worker-discovered dependencies
- explicit block, conflict, and replan signals
- lease-aware execution
- semantic conflict detection
- adaptive verification intensity
- repair coordination on the merged state

### `full_execution_swarm`

This label should only be used once all of the following are real:

- dynamic graph evolution
- safe parallel dispatch
- lease and ownership machinery
- semantic conflict handling
- replanning
- budget-aware coordination
- cross-domain maturity

## Risks a mature swarm must explicitly manage

These are not incidental bugs. They are the coordination tax of the north-star
system and must be first-class in the design.

- task graph mistakes
- hidden dependencies
- patch collisions
- merge instability
- semantic conflicts that survive text merge
- coordination latency overhead
- debugging complexity across many work items
- unclear ownership for cross-cutting seams
- verification blind spots after integration

The plan below exists partly to introduce explicit machinery for these failure
classes.

## Implementation phases

### Phase 0: Freeze the current base species

Goal:

- preserve the current scoped-patch swarm as the stable baseline

Deliverables:

- keep the current generic execution envelope compiling and tested
- keep the artifact lane as the canonical reference implementation
- keep the current stage model generic: `plan`, `dispatch`, `work`, `mutate`,
  `merge`, `verify`, `finalize`

Acceptance bar:

- artifact swarm path remains green
- no regression to candidate-lottery behavior

### Phase 1: Lift the substrate out of `studio`

Goal:

- make the execution substrate truly parent-level rather than Studio-local

Deliverables:

- move shared execution types out of `crates/api/src/studio/types`
- create a shared execution module tree
- move shared stage, summary, receipt, and graph types into the new execution
  namespace
- keep artifact-specific evidence as a typed child payload

Repo targets:

- `crates/api/src/execution/*`
- `apps/autopilot/src/types/execution.ts`
- `apps/autopilot/src-tauri/src/models.rs`
- `apps/autopilot/src-tauri/src/kernel/studio/*` consumers

Acceptance bar:

- no parent abstraction types remain artifact-named
- all current consumers compile against the shared execution namespace

### Phase 2: Introduce explicit strategy selection

Goal:

- let the system choose among multiple execution strategies without conflating
  strategy and domain

Deliverables:

- strategy selector with at least:
  - `single_pass`
  - `plan_execute`
  - `scoped_patch_swarm`
  - `adaptive_scoped_swarm` as a gated preview mode
- typed strategy selection receipts
- policy hooks for forcing or forbidding certain strategies per domain

Acceptance bar:

- the same execution envelope can carry different strategies cleanly
- non-artifact domains can use non-swarm strategies without artifact leakage

### Phase 3: Add dynamic work graph evolution

Goal:

- move from fixed upfront decomposition to provisional plans that can evolve

Deliverables:

- work-item outcomes that can request:
  - subtask spawn
  - task split
  - dependency discovery
  - replan
  - verification escalation or downgrade
- graph mutation receipts
- graph versioning so the work graph is auditable over time

Acceptance bar:

- workers and verifiers can change the graph without breaking auditability
- graph changes are visible in receipts and replay

### Phase 4: Add ownership and lease semantics

Goal:

- make parallelism safe by construction rather than conservative by default

Deliverables:

- file lease
- region lease
- semantic surface lease
- shared-read and exclusive-write phases
- lease acquisition, release, and denial receipts

Acceptance bar:

- overlapping write attempts are prevented or explicitly arbitrated
- the system can explain why parallel work was or was not allowed

### Phase 5: Add semantic conflict detection

Goal:

- detect conflicts that a line-level merge cannot see

Deliverables:

- adapter-defined semantic conflict checkers

Initial artifact conflict classes:

- DOM structure and selector coupling
- component API mismatch
- design token contradiction
- contradictory content claims
- broken interaction contract

Initial reply or research conflict classes:

- contradictory claims
- duplicated or incompatible evidence use
- response shape mismatch relative to the route contract

Acceptance bar:

- the system can reject semantically unsafe merges even when the textual merge
  is clean

### Phase 6: Add adaptive replanning

Goal:

- allow the planner to correct bad decompositions using real execution evidence

Deliverables:

- replan triggers from:
  - repeated block status
  - semantic conflicts
  - verification failure clusters
  - budget pressure
- planner support for:
  - task merge
  - task split
  - strategy downgrade or upgrade
  - verification intensity changes

Acceptance bar:

- the system can recover from planner mistakes without restarting from scratch

### Phase 7: Add safe parallel dispatch

Goal:

- use concurrency where independence is real

Deliverables:

- dependency-aware dispatch scheduler
- lease-aware parallel dispatch
- budget-aware concurrency ceiling
- queue and wait receipts for blocked work

Acceptance bar:

- independent work can run concurrently
- coupled work remains serialized
- latency improves on suitable workloads without raising merge failures

### Phase 8: Add budget-aware orchestration

Goal:

- keep the swarm commercially sane and user-sensitive

Deliverables:

- per-request budget summary
- work-item budget allocation
- planner visibility into:
  - latency
  - inference cost
  - verification burden
  - repair burden
- strategy downgrade rules when orchestration overhead is not worth it

Acceptance bar:

- the system can explain why it chose a simpler strategy
- orchestration overhead is measured, not guessed

### Phase 9: Expand cross-domain maturity

Goal:

- prove the execution fabric is real beyond artifacts

Order of rollout:

1. reply or conversation
2. research
3. workflow
4. code

Deliverables per domain:

- adapter decomposition rules
- domain conflict signals
- verification suite
- repair policy
- budget defaults

Acceptance bar:

- at least three domains can use the generic execution envelope truthfully
- artifact-specific concepts are not required to understand non-artifact runs

## Product-surface changes

The UI should evolve with the execution fabric, but stay outcome-first.

### Main surface

Show only compact execution truth:

- active strategy
- generic execution stage
- active work-item or worker role
- progress count
- verification status

### Receipts or inspector

Show the rich execution trail:

- plan
- work graph
- worker receipts
- change receipts
- merge receipts
- verification receipts
- repair receipts
- budget summary

### Developer controls

Add explicit controls for:

- strategy override
- verification intensity override
- replay
- repair retry
- graph inspection

## Validation plan

### Unit tests

- work graph generation
- graph mutation and versioning
- lease acquisition and denial
- scope enforcement
- semantic conflict detection
- merge stability
- budget allocation

### Integration tests

- artifact scoped swarm with repair
- non-artifact route through shared execution envelope
- replan after dependency discovery
- blocked merge followed by repair
- parallel safe dispatch when leases are disjoint

### Stress tests

- patch collision scenarios
- hidden dependency scenarios
- semantic conflict scenarios
- budget exhaustion scenarios
- repeated replan loops

### Native acceptance

For at least one artifact and one non-artifact flow:

- submit from the real Studio shell
- observe compact execution truth
- inspect receipts
- verify the merged final state is the authority

## Metrics

The north-star implementation should be judged on:

- merged-state success rate
- repair success rate
- semantic conflict catch rate
- hidden dependency discovery rate
- unnecessary parallelization rate
- orchestration latency overhead
- verification cost per accepted outcome
- percentage of requests where strategy choice improved cost or latency

## Immediate tactical sequence

The next concrete implementation order should be:

1. move shared execution substrate out of `studio`
2. add strategy selection receipts and policy hooks
3. add dynamic work graph mutation primitives
4. add leases before broad parallelism
5. add adapter-defined semantic conflict checkers
6. add adaptive replanning
7. enable safe parallel dispatch
8. add budget-aware throttling
9. bring reply and research onto the fabric before code

## Canonical terminology

Use these terms consistently:

- `execution envelope`: parent abstraction
- `execution strategy`: single-pass, plan-execute, swarm variants
- `execution domain`: artifact, reply, research, workflow, code
- `micro_swarm`: current bounded graph tier
- `adaptive_work_graph`: current mutable graph tier
- `adaptive_scoped_swarm`: historical design name for the stronger adaptive
  graph mode
- `full_execution_swarm`: reserved for the mature system only

Avoid:

- treating `swarm` as the parent abstraction
- treating `artifact` as the parent abstraction
- using `full swarm` for the current system

## Exit criteria for the north star

This plan can be considered complete only when:

- the generic execution substrate is fully shared
- strategy selection is real and policy-aware
- the work graph can evolve during execution
- leases make safe parallel dispatch possible
- semantic conflict detection exists in multiple domains
- replanning is real
- budget-aware coordination is real
- artifact, reply, and research all operate on the shared execution fabric
- product surfaces remain outcome-first while exposing truthful execution traces
