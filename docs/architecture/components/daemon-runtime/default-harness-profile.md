# Default Harness Profile

Status: canonical reference harness profile.
Canonical owner: this file for HarnessProfile semantics, the Default Harness
Profile reference scaffold/fallback, bounded Goal Kernel loop-native step
resolution, context topology, generic result normalization, output ownership,
and implementation-stage object boundaries.
Supersedes: standalone harness-profile wording that implies a peer runtime beside the Hypervisor Daemon.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: partial (harness-profile registry and default profile built; wider adapter contracts in progress)
Last implementation audit: 2026-07-05

## Canonical Definition

The **Default Harness Profile** is IOI's built-in reference
`HarnessProfile` for scoped autonomous step resolution.

It is not a separate runtime beside the daemon. The Hypervisor Daemon owns execution
semantics. The Workflow Compositor owns high-level workflow/service shape.
Harness profiles configure how scoped steps are resolved under authority,
receipts, Agentgres state, artifact refs, and verification.

Use this doctrine:

> **Workflow Compositor shapes work. HarnessProfiles resolve steps. The Default
> Harness Profile is IOI's reference scaffold and fallback profile, not a
> meta-harness and not the only admissible harness.**

The Goal Kernel is deliberately bounded. It grounds, implements, observes,
verifies, repairs, course-corrects, and completes one GoalRun or claimed subgoal.
It is not the whole collaborative system. When many participants share a
frontier, an `OutcomeRoom` / `CollaborativeWorkGraph` sits above multiple
GoalRuns and owns dynamic participation, work discovery, claim leases,
attempt/finding exchange, verifier challenges, resource allocation, and
shared-frontier admission. HarnessProfiles still resolve only scoped steps.

It is not:

```text
a fixed swarm
a communal message board or shared-work-frontier owner
a separate execution daemon
a meta-harness above other harnesses
the owner of high-level workflow composition
the owner of persistent skills or memory
the only admissible agent harness
a chatbot loop
a blockchain-first execution model
a CAS/Filecoin blob runtime
a marketplace
a deterministic workflow with a model bolted on
```

The default stack relation is:

```text
Hypervisor clients and surfaces
  Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK,
  Workbench/Automations/Foundry surfaces, other application surfaces,
  Canvas views, Environments views, Authority Gateway adapters

Hypervisor Daemon
  execution owner and authorization-admission, enforcement, and effect-execution
  boundary under applicable policy and authority

Workflow Compositor
  high-level service/workflow graph, dependencies, review points, acceptance
  criteria, delivery contract, and harness selection hints

Hypervisor Automations
  durable workflow, trigger, schedule, API/service, approval-flow, queue, and
  background-mission product surface over Workflow Compositor contracts

ioi.ai collaborative outcome pattern
  ioi.ai's Goal Space and optional OutcomeRoom/CollaborativeWorkGraph over
  Hypervisor; many bounded GoalRuns and harnesses may participate, but no
  harness owns room coordination, execution, authority, or truth

Harness Profiles
  daemon-executed or daemon-mediated step-resolution profiles and adapters,
  including Default Harness Profile as the reference scaffold/fallback

Private Workspace backed by cTEE
  optional daemon workspace/execution profile for persistent rented GPU nodes
  where protected plaintext must not enter provider-rooted memory; CLPD is the
  default protected-agency strategy

Runtime services and guest workloads
  workers, service engines, models, tools, connectors, browsers, shells

wallet.network
  authority grants, approvals, secrets, payment and decryption scopes

Agentgres
  accepted operations, object heads, run/task state, receipts, artifact refs,
  archive refs, projections, delivery state, replay/restore authority

Agentgres artifact/ref plane
  ArtifactRef, PayloadRef, EvidenceBundle, AgentStateArchive refs

Storage backends
  local disk, S3, Filecoin, CAS/IPFS, object stores, provider/customer blobs

IOI L1 / compatible L1s
  optional public settlement, registries, rights, disputes, interop roots
```

## Central Thesis

IOI scales autonomous labor by decomposing work across context-resolution
boundaries, executing each scoped task through model/tool/result/model loops,
delegating authority monotonically, routing context selectively, recording
operational truth in Agentgres, storing payload bytes behind Agentgres-governed
artifact refs, and verifying claims according to risk.

Harness profiles exist to make scoped step resolution portable across many
models, tools, workers, service engines, and external agent harnesses. The
Default Harness Profile is the built-in reference implementation and scaffold
for that contract. It is useful as a fallback and as a template for custom
profiles, but it does not own high-level workflow composition and should not
make IOI hostile to other credible harnesses.

The generic bounded loop is:

```text
ground objective, state, constraints, and acceptance
  -> observe uncertainty or opportunity
  -> form a bounded plan or hypothesis
  -> lease context, resources, tools, and authority
  -> execute or delegate
  -> normalize WorkResult / OutcomeDelta
  -> verify, falsify, reproduce, compare, accept, reject, or challenge
  -> repair, escalate, update admitted learning, continue, or close
```

The live first implementation is intentionally narrower than this target. It
admits only `parallel_implement_reconcile`, uses one deterministic conductor,
at most two implementers, software-shaped task briefs/results, isolated
candidate workspaces, deterministic candidate verification, and one admitted
reconciliation. That is a valid bounded software profile, not evidence that
open participation, dynamic topology, generic results, or cross-domain room
coordination is already implemented.

Persistent workspace intelligence is separate from any selected model or
harness. Skills, memory, wiki state, learned tool affordances, and durable
behavior-affecting context belong to the workspace/project/domain through
Agent Wiki / `ioi-memory`, Agentgres-admitted mutations, receipts, provenance,
and policy. Swapping from one model or harness to another should not discard
that intelligence when workspace identity, compatibility, and authority remain
valid.

## Profile Record

Implementations should expose the active `HarnessProfile` through runtime
manifest, event, trace, receipt, or Agentgres projection metadata.

```yaml
HarnessProfile:
  profile_id: harness_profile:...
  profile_family:
    default_ioi | hermes | deepseek_tui | openhands |
    codex_adapter | claude_code_adapter | service_engine |
    deterministic_only | custom
  profile_version: string
  daemon_executed_or_mediated: true
  step_resolution_contract_required: true
  produces_boundary_objects:
    - ActionProposal
    - GateResult
    - ExecutionResult
    - NormalizedObservation
    - WorkResult
    - OutcomeDelta
    - Receipt
    - ArtifactRef
    - PayloadRef
    - AgentgresOperationRef
  authority_model: wallet.network
  state_substrate: Agentgres
  persistent_workspace_intelligence:
    reads_agent_wiki: policy_selected
    writes_memory_via_agentgres_admission: required_for_durable_changes
  workflow_compositor_role:
    consumes_step_contracts: true
    owns_high_level_graph: false

DefaultHarnessProfile:
  profile_id: default-harness-profile
  profile_version: 2026.05.default-harness-profile.v1
  daemon_executed: true
  reference_profile: true
  scaffold_profile: true
  fallback_profile: true
  daemon_runtime_api_required: true
  execution_modes:
    - projection
    - shadow
    - gated
    - live
  loop_native: true
  final_output_ownership_required: true
  generic_work_result_required: true
  context_topology_planning_required: best_effort
  authority_model: wallet.network
  state_substrate: Agentgres
  artifact_ref_owner: Agentgres
  storage_backend_policy: policy_selected
  sensitive_compute_profiles:
    - local_only
    - redacted_remote
    - private_workspace_ctee
    - tee
    - customer_vpc
  l1_settlement: trigger_based
  conformance_refs:
    - CIRC
    - CEC
```

A harness profile may be implemented by a lower-level runtime service, external
agent harness, deterministic service module, or Rust/WASM workload substrate,
but the public ownership boundary stays with the daemon.

## Agent Operating Contract

Hypervisor may expose an `Agent` selector in composer controls, launch forms,
Automations nodes, Workbench panels, and Applications surfaces. That selector is
product-facing. Under the runtime contract, a configured agent compiles into:

```text
AgentRecord
  metadata, owner, install/package refs, project/environment/code context

Mode
  Agent | Plan | Goal

ModelConfiguration
  model, reasoning effort, speed/service tier, fallback policy, custody policy

HarnessSelection
  selected HarnessProfile or Agent Harness Adapter

ToolAndConnectorBindings
  RuntimeToolContracts, MCP servers, connector mappings, authority scopes

MemoryAndWorkspaceIntelligence
  Agent Wiki / ioi-memory reads, Agentgres-admitted durable memory mutations

AuthorityAndBudget
  wallet.network grants, approval gates, spend limits, context/token budgets

ReceiptsAndReplay
  receipt policy, artifact refs, transcript refs, state roots, replay refs
```

The product may show a compact control such as:

```text
Agent -> Mode -> Model -> Reasoning -> Speed
```

`Harness` is an advanced configuration child of Agent. It should appear only
when the selected agent supports multiple execution topologies or when the user
is editing the agent definition. Do not expose "Execution Profile" as ordinary
composer language; reserve deployment/execution profile wording for provider
and runtime-posture docs.

## Turn Coordination

A selected harness resolves bounded turns under daemon control. The daemon owns
turn admission, active-turn state, stale-turn reconciliation, failure breaker
state, model/MCP configuration for the turn, and terminal-state emission.
Clients may render turn state or request controls, but they do not own a hidden
loop.

Canonical control inputs:

```text
compact
goal.pause
goal.resume
goal.complete
goal.clear
goal.set(objective, status)
delete_queued_message(user_input_id)
interrupt
steer
```

Canonical turn options:

```text
modes: Agent | Plan | Goal
model configuration: model, reasoning effort, speed/service tier
tool/MCP availability
authority and budget posture
receipt/replay policy
```

LLM/provider failures are run facts, not only client errors. A harness profile
must report repeated model failures, fallback route use, waiting-for-input
states, stale active turns, and human-handoff conditions through daemon events,
Agentgres operation refs, and receipts when they affect accepted work.

## Subagent And Delegated Work Boundary

Subagents are delegated work items or child work runs, not hidden private
threads. Parent and child work must share explicit authority, budget,
conversation, cancellation, receipt, and output contracts.

Inside an OutcomeRoom, a background agent additionally binds a
`RoomParticipantLease` and usually a `WorkClaimLease`. The room owns join,
sleep/wake, heartbeat, replacement, retirement, quarantine, resource offers,
and frontier state; the child GoalRun owns the bounded pursuit. Spawning another
process or model context does not by itself create an independent participant
or party.

Subagent message flow should use explicit boundary objects:

```text
UserInputBlock
AgentMessage
WakeEvent
AgentResponseBlock
WorkRunConversationProjection
```

Avoid a generic untyped event bag as the canonical subagent interface. Generic
event envelopes may transport records, but the durable agent contract should
distinguish user input, parent/child agent messages, wake events, text output,
action started/completed, file modifications, host-auth-required, todo items,
thoughts, mode changes, and available commands.

Subagent wait conditions should be represented as runtime interests:

```text
timer
subagent result
user message
environment readiness
devcontainer or workspace rebuild
```

The parent harness may wait, cancel, resume, assign, or send input to a
subagent, but the daemon remains the admission, cancellation, event ordering,
receipt, and state-root owner.

Client projections must expose a background participant's claim, lease expiry,
heartbeat or wake condition, spend, last contribution, blockers, evidence,
verification state, and cancellation/quarantine controls. A token stream or
opaque process count is not an adequate background-agent contract.

## Compositor And Harness Boundary

The clean architecture is:

```text
Workflow Compositor
  owns high-level directed work:
    service graph
    dependencies
    typed steps
    step contracts
    acceptance criteria
    review points
    delivery contract
    reusable workflow/service templates
    harness/model/provider selection hints

Hypervisor Automations
  owns durable product projections:
    automation specs
    triggers and schedules
    API/service entrypoints
    approval flows
    background missions
    run-history and replay views
    Canvas editor state where useful

ioi.ai collaborative outcomes
  conduct one Goal Space and optionally coordinate an
  OutcomeRoom/CollaborativeWorkGraph over Hypervisor and Automations:
    dynamic participant leases and affiliations
    shared work frontier and claim leases
    isolated GoalRuns, sessions, branches, and attempts
    positive, negative, inconclusive, invalid, and superseded results
    findings, verifier challenges, scorecards, and evaluation rule versions
    hosted or federated shared-state admission
    contribution lineage, failure mining, and replay

Selected HarnessProfile
  resolves one scoped step:
    local loop policy
    model/tool/worker/service call planning
    context cell usage
    action proposal production
    observation normalization
    stop/blocker/final-output conditions

Hypervisor Daemon
  owns gates and effects:
    policy
    authority
    execution boundary
    receipts
    Agentgres admission
    artifact refs
    replay/restore

Workspace Intelligence
  persists across harness/model swaps:
    skills
    memory
    wiki facts
    tool affordances
    correction patterns
    routing preferences
    provenance
```

The compositor may choose the Default Harness Profile for ordinary steps, but
it may also choose another harness profile or a deterministic service module
when that is a better fit. The selected profile is a step-resolution adapter,
not the owner of the workflow graph.

Setup flows such as downloading models, configuring providers, selecting local
versus remote compute, creating capability leases, or initializing a private
workspace should be represented as **Workspace Bootstrap Recipes** or
**Hypervisor Setup Profiles** executed through the Workflow Compositor and
daemon gates. They are not the Default Harness Profile.

## Normative Lifecycle

Every serious run using a harness profile follows this lifecycle. Small local
tasks may collapse steps, but they must not bypass policy, authority, receipts,
verification, or terminal-state gates when those gates apply.

```text
1. Capture intent.
2. Build or derive an IntentContract.
3. Resolve intent through CIRC-style deterministic selection.
4. Estimate context pressure and risk.
5. Build a ContextTopology when useful or required.
6. Choose fulfillment mode.
7. Forecast authority, resources, artifacts, and receipts.
8. Request preflight grants or approval when needed.
9. Compile or select an initial WorkGraph, service graph, or single Task
   through the Workflow Compositor when the work is multi-step.
10. Select a HarnessProfile, deterministic service module, worker, tool, model,
   or service engine for each executable step.
11. Convert cross-context delegation into a ContextHandoff and
   TaskBriefPayload, then open a HarnessInvocation when a HarnessProfile or
   Agent Harness Adapter must perform the step.
12. Normalize raw results into generic `WorkResult` / `OutcomeDelta` plus
    observations. Software implementation may use
    `ImplementationResultPayload` as a profile of that seam.
13. Record receipts, traces, Agentgres operations, and artifact refs.
14. Re-enter model loop when more action or synthesis is needed.
15. Verify claims according to risk.
16. Repartition context topology when telemetry proves the plan wrong.
17. Run an OutputOwnershipPass unless deterministic-only profile applies.
18. Commit delivery state and local/domain settlement in Agentgres.
19. Store payload bytes in selected storage backends behind ArtifactRefs.
20. Trigger L1/app-chain settlement only when policy or contract requires it.
```

When a GoalRun is fulfilling a room claim, its admitted result returns to the
room admission owner. The room may update the frontier, create follow-on
claims, request independent replication, change verifier policy, or stop on
acceptance, risk, budget, deadline, or marginal-value grounds. The harness does
not mutate shared-room truth directly.

## Loop-Native Execution

The fundamental execution unit is a grounded cognitive loop:

```text
ContextCell
  task, constraints, authority, evidence refs, receipts, observations,
  loop history summary, uncertainty, acceptance criteria

→ ModelPass
→ ActionProposal
→ Authority/Policy Gate
→ Execution
→ ResultNormalization
→ Receipts / traces / Agentgres operation or rejection / context update
→ Model re-entry
```

## Harness Broker Boundary

The daemon-mediated harness broker is the boundary between Goal Kernel
coordination and provider-/tool-specific harness execution. It prevents the
manual copy-paste workflow from becoming canon.

```text
ContextHandoff(task_brief)
  -> TaskBriefPayload
  -> ContextLease set
  -> HarnessInvocation(selected HarnessProfile or Agent Harness Adapter)
  -> HarnessAdapterEvents
  -> WorkResult / OutcomeDelta
       (ImplementationResultPayload for the software profile)
  -> ContextHandoff(work_result)
  -> conductor VerifierPath
```

Harness adapters may render a prompt, command, JSON request, terminal script, or
provider-specific session internally. That rendering is adapter-private
evidence. The durable contract is the task brief, leases, invocation,
normalized events, generic result/outcome delta, domain profile, receipts, and
verifier path.

The deterministic substrate owns:

```text
policy checks
authority gates
approval binding
tool execution boundaries
schema validation
receipt emission
trace emission
Agentgres operation admission
artifact-ref creation
payload hash/CID checks
budget accounting
lease enforcement
revocation
verification gates
retry and recovery mechanics
optional settlement triggers
```

The model loop owns:

```text
interpreting task context
choosing or proposing next action
asking for evidence
adapting plans before effect boundaries
interpreting normalized observations
handling uncertainty
requesting verification
synthesizing final output
```

Raw model output is never authority. A model may propose an effect; the daemon
admits and enforces execution only when applicable policy and authority
providers authorize the crossing.

## Minimal Implementation Objects

The profile is implementation-grade, but it should not force every concept into
a new canonical Agentgres object on day one. Start with the minimum durable
form and promote only when query, replay, conflict, lifecycle, or projection
needs justify object heads.

| Concept | Minimum durable form | Promote to object when |
| --- | --- | --- |
| `IntentContract` | run request, resolver receipt, or Agentgres operation payload | multiple components query or rebase it |
| `Run` / `Task` / `TaskState` | Agentgres runtime objects | always for serious runs |
| `ContextTopology` | planner projection plus receipts | repartition, replay, or cross-cell routing requires it |
| `ContextCell` | scoped runtime state plus context events | context cells outlive one turn or are shared across actors |
| `LoopIteration` | event/receipt/trace segment | loop-level replay or verification becomes first-class |
| `ModelPass` | model invocation receipt plus redacted trace | model-pass lineage is queried or evaluated |
| `ActionProposal` | action request / runtime item / event | approval, replay, or policy review requires durable identity |
| `GateResult` | policy/authority decision receipt | always for consequential actions |
| `ExecutionResult` | tool/worker/service receipt | always for effectful or externally observed actions |
| `NormalizedObservation` | typed event or projection payload | observations are reused by verifiers or downstream tasks |
| `WorkResult` / `OutcomeDelta` | normalized harness result payload plus receipts and domain-profile refs | cross-run, cross-room, cross-domain, contribution, challenge, or replay consumers require stable identity |
| `ImplementationResultPayload` | software profile of `WorkResult` with changed-file/diff/test refs | software implementation needs typed review and reconciliation |
| `OutputOwnershipPass` | completion/output receipt plus terminal event | delivery claims need replay, dispute, or marketplace settlement |
| `ArtifactRef` / `PayloadRef` | Agentgres object/ref | always when payload bytes matter |
| `PrivateWorkspaceCapsule` | daemon profile payload plus Agentgres artifact/receipt refs | rented or provider GPU work touches protected classes |
| `AutonomyLease` | wallet.network grant plus receipt | remote persistent work continues while the user is offline |
| `DeclassificationReceipt` | wallet.network + Agentgres receipt | protected output becomes visible, exportable, or actionable |
| `PhysicalActionIntent` / `SafetyEnvelope` / `ActuatorCommandReceipt` | safety refs plus receipt-backed physical action record | embodied work can affect actuators or safety-relevant devices |
| `Blocker` | event plus task state | user/operator action or long-lived wait is needed |

## Core Schemas

These schemas are intentionally small. Implementations may extend them, but
must preserve the fields needed for policy, replay, receipts, and Agentgres
projection.

### IntentContract

```yaml
IntentContract:
  intent_id: intent:...
  origin:
    type: user | hypervisor | cli | sdk | service | worker | schedule | webhook | aiip
    ref: string
  goal: string
  constraints: [string]
  acceptance_criteria: [string]
  risk_class:
    read | draft | local_write | write_reversible | external_message |
    commerce | funds | credential_access | policy_widening | secret_export |
    identity_change | system_destructive | physical_action
  privacy_profile:
    local_only | redacted_remote | confidential_remote | managed
  execution_profile:
    local | workstation | hosted | tee | vpc | depin | private_workspace_ctee | hybrid
  budget:
    compute: string | null
    money: string | null
    time: string | null
    context: string | null
    tool_calls: integer | null
    loop_iterations: integer | null
    artifact_storage: string | null
  authority_forecast_required: boolean
  loop_policy:
    loop_native_required: true
    model_reentry_required_after:
      - tool_result
      - worker_result
      - service_result
      - verifier_result
      - user_approval
      - blocker_resolution
    final_output_requires_ownership_pass: true
  agentgres_policy:
    domain_ref: agentgres://domain/...
    operation_backed_truth_required: true
    artifact_refs_required_for_large_payloads: true
  settlement_profile:
    local_agentgres: true
    receipt_required: true
    l1_required_triggers:
      - marketplace
      - escrow
      - public_registry
      - dispute
      - interop
```

### RuntimePlan

```yaml
RuntimePlan:
  plan_id: plan:...
  run_id: run:...
  intent_id: intent:...
  fulfillment_mode:
    single_worker | worker_graph | workflow_graph |
    service_package | configured_engine | hybrid
  context_topology_ref: context_topology:... | null
  work_graph_ref: graph:... | null
  outcome_room_ref: outcome-room://... | null
  work_claim_lease_ref: work-claim://... | null
  selected_units:
    - type: worker | service_engine | workflow | model_backend | tool
      ref: string
  authority_forecast_refs:
    - grant_request:...
  expected_artifact_roles:
    - evidence | trace | checkpoint | delivery_bundle | package | sealed_state_archive
  required_receipts:
    - policy_decision
    - execution
    - verification
    - completion_gate
  reason:
    - context_fit
    - capability_match
    - privacy
    - authority
    - cost
    - service_contract
```

`OutcomeRoom` refs are absent for ordinary direct work. When present, the plan
must not infer broader authority, context, budget, or shared-state write access
from room membership; the participant and claim leases remain controlling.

### ContextTopology

`ContextTopology` is a planning and repair surface. It may start as a
projection, but it must be visible enough for replay and operator inspection
when work is split across actors.

```yaml
ContextTopology:
  topology_id: context_topology:...
  run_id: run:...
  estimated_total_context_pressure: number | null
  root_resolution: coarse | medium | fine | forensic
  context_cells:
    - context_cell://...
  boundaries:
    - boundary_id: boundary:...
      split_reason:
        - context_volume
        - semantic_domain
        - authority_boundary
        - privacy_boundary
        - verification_boundary
        - service_step_boundary
        - loop_depth_boundary
        - agentgres_domain_boundary
      parent_context_cell: context_cell://... | null
      child_context_cells:
        - context_cell://...
  compaction_strategy:
    preserve_provenance: true
    preserve_agentgres_refs: true
    preserve_artifact_refs: true
    preserve_receipt_refs: true
    preserve_uncertainty: true
  repartition_policy:
    enabled: true
    triggers:
      - unexpected_context_growth
      - verifier_detected_omission
      - dependency_fanout_growth
      - repeated_prior_context_requests
      - loop_depth_exceeded
      - missing_artifact_ref_for_claim
```

Context pressure estimates are planning heuristics, not protocol law. They may
use a Context Fit Ratio, but thresholds are policy defaults rather than
universal invariants.

### Default Harness ContextCell Profile

[`ContextCellEnvelope`](../../foundations/common-objects-and-envelopes.md#contextcellenvelope)
owns the shared cell identity, role, room/participant binding, harness/model
route, leases, authority scopes, wake condition, and lifecycle. The Default
Harness Profile extends that envelope with the following loop-local execution
state; it does not define a second `ContextCell` object.

```yaml
DefaultHarnessContextCellProfile:
  context_cell_ref: context_cell://...
  run_ref: run://...
  task_ref: task://...
  resolution: coarse | medium | fine | forensic
  goal: string
  constraints: [string]
  acceptance_criteria: [string]
  authority_ref: grant://... | null
  agentgres_refs:
    - agentgres://operation/...
    - agentgres://object/...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  prior_observation_refs:
    - observation://...
  open_uncertainties:
    - string
  loop_policy:
    current_iteration: integer
    max_iterations: integer | null
    model_reentry_required: boolean
  memory_policy:
    private_scratch_allowed: boolean
    agent_wiki_retrieval_allowed: boolean
    agentgres_memory_mutation_allowed: boolean
  output_policy:
    return_claims: true
    return_uncertainty: true
    return_state_patch: true
```

Harness hot state and private scratch stay local unless admitted. Durable
behavior-affecting memory goes through Agent Wiki / `ioi-memory` and crosses
into Agentgres only as authorized operations such as `ContextMutation`.

### LoopStep

```yaml
LoopStep:
  loop_step_id: loop_step:...
  run_id: run:...
  task_id: task:...
  context_cell_id: context_cell://...
  actor_id: worker:... | service_engine:... | runtime:...
  model_pass_ref: model_pass:... | receipt://... | null
  action_proposal_ref: action:... | null
  gate_result_ref: gate:... | receipt://... | null
  execution_result_ref: result:... | receipt://... | null
  normalized_observation_ref: observation:... | null
  agentgres_operation_refs:
    - agentgres://operation/...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  trace_refs:
    - trace://...
  status:
    continued | blocked | verified | failed | completed | escalated
```

### WorkResult And OutcomeDelta

Harness completion normalizes into the generic result seam owned by the shared
object canon. Every domain profile preserves:

```text
claim and GoalRun identity
worker/harness/model/runtime identity and versions
method and derived-from lineage
outcome class and summary
typed state or knowledge delta
claims, uncertainty, supporting and contradicting evidence
artifact, receipt, trace, cost, authority, and verifier refs
license, disclosure, retention, and export posture
reproduction, acceptance, challenge, and supersession state
```

Software adds changed-file, diff, patch, test, branch/worktree, and merge refs
through `ImplementationResultPayload`. Research, ontology, incident, service,
physical-mission, review, and evaluation profiles must not be forced through
software-only fields.

### ActionProposal

```yaml
ActionProposal:
  action_id: action:...
  actor_id: worker:... | service_engine:... | runtime:...
  task_id: task:...
  action_type:
    model.invoke | tool.invoke | worker.invoke | service.invoke |
    browser.use | computer.use | shell.exec | file.patch |
    connector.call | workflow.compose | agentgres.operation.propose |
    aiip.send | request_context | request_verification |
    request_authority | final_output
  requested_primitives:
    - prim:...
  requested_scopes:
    - scope:...
  risk_class:
    read | draft | local_write | write_reversible | external_message |
    commerce | funds | credential_access | policy_widening | secret_export |
    identity_change | system_destructive | physical_action
  expected_result_schema: schema:... | null
  reason_summary: string
  input_refs:
    - ctx:...
    - artifact://...
    - receipt://...
```

Use `prim:*` for primitive execution capabilities and `scope:*` for authority
scopes. Do not introduce a third generic authority vocabulary.

A `physical_action` proposal that can affect actuators, robots, vehicles,
drones, facilities, access control, machines, or safety-relevant devices is not
a generic tool call. The proposal must carry refs to `PhysicalActionPolicy`,
`SafetyEnvelope`, `EmergencyStopAuthority`, and any required
`HumanSupervisionPolicy`, plus expected `SensorEvidenceReceipt` and
`ActuatorCommandReceipt` schemas. The daemon must block the proposal when those
refs are missing or stale. The canonical owner for that object family is
[`physical-action-safety.md`](../../foundations/physical-action-safety.md).

### GateResult

```yaml
GateResult:
  gate_id: gate:...
  action_id: action:...
  result:
    approved | denied | blocked | requires_step_up |
    requires_user | requires_policy_review
  authority_ref: grant:... | null
  policy_hash: sha256:...
  reason: string
  safe_alternatives:
    - action:...
  blocker_ref: blocker:... | null
  receipt_ref: receipt://...
```

The deterministic layer owns gate results. The model does not.

### NormalizedObservation

```yaml
NormalizedObservation:
  observation_id: observation:...
  result_ref: result:... | receipt://...
  task_id: task:...
  observation_type:
    tool_output | browser_state | file_diff | test_result |
    api_response | verifier_result | user_approval |
    blocker | state_patch | delivery_update
  summary: string
  structured_data: object
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  confidence: number | null
  uncertainty:
    - string
  suggested_next_actions:
    - string
```

Models should re-enter on normalized reality, not raw noise.

### OutputOwnershipPass

```yaml
OutputOwnershipPass:
  output_pass_id: output_pass:...
  actor_id: worker:... | service_engine:... | runtime:...
  task_id: task:...
  accepted_claims:
    - claim:...
  rejected_claims:
    - claim:...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  verification_refs:
    - receipt://...
  unresolved_uncertainties:
    - string
  final_artifacts:
    - artifact://...
  final_answer_ref: artifact://... | null
  confidence: number
  caveats:
    - string
  agentgres_operation_ref: agentgres://operation/... | null
  receipt_ref: receipt://...
```

The output ownership pass may be represented initially as completion receipts
plus a terminal event. It should become a first-class object when delivery,
dispute, replay, marketplace settlement, or downstream reuse needs stable
queryable output ownership.

## Agentgres Admission Rules

For serious runs, the profile admits these transitions into Agentgres or an
Agentgres-compatible operation log:

```text
RunCreated
TaskStateUpdated
PolicyDecisionRecorded
AuthorityDecisionRecorded
WorkerInvocationCreated
ServiceEngineInvocationCreated
RuntimeAssignmentRecorded
ReceiptRecorded
ArtifactRecorded
BlockerOpened
VerificationRecorded
OutputOwnershipRecorded
DeliveryRecorded
LocalSettlementRecorded
AgentStateArchiveCreated
StateImported
RunTerminalStateRecorded
```

Do not admit every private thought or scratch update. Admit durable facts,
effects, decisions, refs, policy outcomes, verification outcomes, terminal
states, and state mutations that must be replayable, portable, shared,
auditable, or settlement-relevant.

## Artifact And Storage Rule

Agentgres owns:

```text
artifact identity
artifact refs
payload refs
archive refs
lifecycle status
policy hash
schema version
authority context
state roots
receipt linkage
trace linkage
replay/import metadata
restore validity
local/domain settlement records
```

Storage backends own:

```text
payload bytes
encrypted archive bytes
large evidence bytes
raw logs
large traces
screenshots
datasets
packages
delivery bundles
```

Use `artifact.put`, `artifact.get`, `artifact.verify`, `artifact.archive`, and
`artifact.restore` through Agentgres-governed refs. Do not model `cas.put` or
`filecoin.put` as authority-bearing runtime primitives.

## Verification And Completion

Verification depth scales with risk:

```text
low       deterministic local check or no separate verifier
medium    independent verifier or test gate
high      deterministic tests + independent verifier + policy verifier
critical  adversarial verifier + independent check + human/org approval
```

Terminal success requires:

```text
required receipts present
required postconditions present
verification completed or explicitly marked partial/unverified
pending blockers resolved or surfaced
artifact refs attached for durable evidence
completion gate passed
output ownership pass completed unless deterministic-only
```

Final answer text is not the authority for pass/fail. It is an output surface
over receipts, observations, claims, artifacts, verification, and accepted
state.

## Context Topology Rules

The scaling artifact is context-resolution management, not raw actor count.

Split work when:

```text
expected context pressure exceeds reliable capacity
privacy or authority boundaries require isolation
verification requires independent context
semantic domains are separable
loop depth is likely to outgrow one context cell
artifact/evidence volume would drown the parent actor
service contract or delivery shape requires a step boundary
Agentgres domain boundary requires separation
```

Parent actors carry:

```text
goal
status
authority scope
risk
confidence
claims
uncertainty
receipt refs
artifact refs
Agentgres operation refs
blockers
loop summary
recommended next action
```

Child actors receive:

```text
local goal
relevant constraints
acceptance criteria
required evidence
authority scope
budget
privacy policy
tool permissions
expected output schema
loop policy
Agentgres domain/ref policy
artifact policy
escalation path
```

Compaction is allowed inside context cells, but compaction drift is telemetry that
the topology may be wrong. It is not the primary topology discovery mechanism.

## Service And Worker Fulfillment

The profile may fulfill an intent through:

```text
one worker
a worker graph
a Hypervisor workflow
a configured service engine
a service package
a marketplace worker
a marketplace service
a private enterprise package
a remote AIIP-compatible domain
a hybrid combination
```

`aiagent.xyz` packages capability. `sas.xyz` packages outcomes. Worker packages
can exist without aiagent.xyz. Service packages can exist without sas.xyz. A
service package may use marketplace workers, private workers, proprietary
models, deterministic tools, configured workflows, nested service packages, or
no worker marketplace at all.

## L1 Settlement Triggers

Most runs end with Agentgres state, receipts, trace refs, artifact refs,
payload bytes, and local/domain settlement.

Promote to IOI L1 or a compatible L1 only when a policy, contract, or operator
requires:

```text
marketplace listing or transaction
worker/service registry mutation
service contract, escrow, payment, SLA, dispute, or remediation
rights/licensing
benchmark or reputation publication
public registry mutation
cross-domain proof
developer-built L1 interop
explicit public commitment
```

## Anti-Patterns

Do not model the Default Harness Profile as:

```text
a peer runtime beside the Hypervisor Daemon
a meta-harness that owns or supervises all other harnesses
the high-level Workflow Compositor
the only admissible harness for autonomous work
the owner of workspace skills, memory, wiki state, or learned tool affordances
a Foundry training/distillation/post-training pipeline
a setup assistant for model downloads and provider configuration
a chatbot loop with receipts added afterward
a fixed swarm topology
a shared-frontier or OutcomeRoom owner
a reason to force every goal into collective pursuit
a software-only ImplementationResultPayload as the universal result contract
a hidden background-agent process tree without participant/claim projections
a deterministic workflow that calls a model only at the end
a CAS/Filecoin blob runtime
a marketplace router that silently prefers itself
a way to bypass wallet.network authority
a place to canonicalize every private thought or scratch update
a place to send protected plaintext to a rented GPU node by default
```

Correct model:

```text
daemon executes
Workflow Compositor shapes high-level workflows and services
selected HarnessProfiles resolve scoped steps
Default Harness Profile is the reference scaffold/fallback HarnessProfile
Agent Wiki / ioi-memory and skills persist at workspace/project/domain level
wallet.network authorizes
Agentgres admits serious truth
artifact refs bind payload meaning
storage backends hold bytes
receipts bind accountable transition facts; verification and acceptance stay explicit
Private Workspace backed by cTEE keeps protected plaintext off untrusted persistent nodes
Plaintext-Free Runtime Mounting keeps tool/model context to public/redacted refs and private handles
Candidate-Lattice Private Decoding lets rented GPUs generate candidates while private heads select
Counterfactual Lattice Execution may spend additional public token volume to reduce online private-choice leakage
Cryptographic Operator Plane routes protected scoring/retrieval/policy checks to FHE/MPC/local/threshold paths
External Model API Boundary labels private-native, redacted-API, provider-trust, and unsafe model paths
L1 settlement happens only by trigger
```

Protected subcomputations MUST route to guardian, local, FHE, MPC, garbled,
ORAM, or threshold private-operator paths unless the protected state has been
explicitly declassified. The authenticated authority surface is the default
second logical party for private operators; managed committees are escalation
paths, not ordinary user-facing infrastructure.

The profile MUST distinguish ordinary GPU kernel speed from same-token-budget
private inference. Public/redacted proposal generation can run at normal GPU
speed; counterfactual lattices, padding, decoys, and private-operator paths may
increase token volume, latency, or private computation.

The profile MUST NOT treat third-party model APIs over sensitive plaintext as
base cTEE no-plaintext-custody. Such routes are provider-trust unless the API
receives only public/redacted/declassified inputs or exposes a separately
verifiable private-compute guarantee accepted by policy.

## Conformance Profiles

Implementation tests should be organized around these profile checks:

```text
HP-1 Daemon ownership
  Clients, adapters, harnesses, and benchmarks cannot own private effect truth.

HP-2 Proposal-gate-execute
  Consequential actions are proposed, policy/authority gated, then executed.

HP-3 Receipt-backed terminal
  Terminal success requires typed receipts, observations, postconditions,
  verification state, and completion gate success.

HP-4 Context topology
  Work splits across context, authority, privacy, risk, service, or
  verification boundaries without dumping global context.

HP-5 Artifact refs
  Large payloads are stored behind Agentgres-governed ArtifactRefs/PayloadRefs.

HP-6 Output ownership
  Final cognitive output is produced after evidence, receipts, observations,
  verification, and uncertainty have been ingested.

HP-7 Local-first settlement
  Ordinary runs settle in Agentgres/receipts; L1 commitment happens only by
  trigger.

HP-8 Marketplace neutrality
  Harness profiles do not silently absorb worker/service internals or privilege
  themselves over routed workers by platform fiat.

HP-9 Harness interoperability
  Any selected harness profile must produce the common boundary objects:
  ActionProposal, GateResult, ExecutionResult, NormalizedObservation,
  WorkResult/OutcomeDelta, Receipt, ArtifactRef/PayloadRef, Agentgres refs, and
  terminal/blocker state.

HP-10 Workspace intelligence portability
  Persistent skills and memory survive model/harness swaps when workspace
  identity, compatibility, provenance, policy, and authority remain valid.

HP-11 Bounded Goal Kernel
  One GoalRun owns one bounded pursue/verify/course-correct loop; room-level
  participation, frontier, claims, and shared admission remain outside it.

HP-12 Generic result seam
  Harnesses return WorkResult/OutcomeDelta; software may use the
  ImplementationResultPayload profile without imposing file/test fields on
  other domains.

HP-13 Observable background work
  Background participants expose participant/claim leases, heartbeats or wake
  conditions, spend, evidence, blockers, verification, and controls.
```

CEC remains the post-resolution execution-collapse contract. CIRC remains the
intent-resolution contract. Harness profiles compose those contracts into
step-resolution behavior under the daemon. The Workflow Compositor composes
steps into service and workflow graphs.

## Implementation Phases

Phase 0: project the existing runtime into profile-shaped events and receipts.

```text
map workload receipts to harness components
map routing receipts to policy/approval gates
emit completion-gate receipts
bind terminal output to postcondition receipts
surface harness profile metadata in runtime manifests
```

Phase 1: formalize action/gate/observation records.

```text
ActionProposal events or action-request records
GateResult receipts
ExecutionResult receipts
NormalizedObservation events/projections
ArtifactRef creation for large payloads
```

Phase 2: add context topology planning.

```text
ContextTopology projection
ContextCell runtime state
context pressure estimates
repartition blockers
compaction lineage and provenance preservation
```

Phase 3: settle serious run truth through Agentgres.

```text
Run, Task, TaskState, PolicyDecision, AuthorityDecision
ReceiptRecorded, ArtifactRecorded, Blocker, Verification
OutputOwnershipRecorded, DeliveryRecorded, LocalSettlementRecorded
archive/restore operation chain
```

Phase 4: generalize fulfillment.

```text
service engines
service packages
worker graphs
AIIP remote domains
MoW routed workers
marketplace-neutral package invocation
optional L1 settlement hooks
```

## Related Canon

- [`doctrine.md`](./doctrine.md): daemon/runtime ownership boundary.
- [`api.md`](./api.md): public runtime API and action mediation.
- [`events-receipts-delivery-bundles.md`](./events-receipts-delivery-bundles.md):
  event, receipt, trace, and delivery bundle shapes.
- [`private-workspace-ctee.md`](./private-workspace-ctee.md): Private Workspace
  backed by cTEE, persistent private Hypervisor Nodes, `AlphaSeal`,
  `AutonomyLease`, and declassification receipts.
- [`../agentgres/api-object-model.md`](../agentgres/api-object-model.md):
  Agentgres runtime objects, operations, artifact refs, and archives.
- [`../../foundations/aiip.md`](../../foundations/aiip.md): interop profile for
  bounded autonomous work.
- [`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md):
  GoalRun, OutcomeRoom, participant/claim, generic result, and collaboration
  envelopes.
- [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md):
  Goal Space and collaborative work graph product behavior above GoalRuns.
- [`../../_meta/implementation-matrix.md`](../../_meta/implementation-matrix.md):
  concept-to-durable-form implementation index.

## Non-Negotiables

1. The Hypervisor Daemon owns execution semantics.
2. Harness profiles are daemon-executed or daemon-mediated; they are not peer
   runtimes.
3. The Default Harness Profile is the reference scaffold/fallback
   HarnessProfile; it is not the only admissible harness and not a meta-harness.
4. The Workflow Compositor owns high-level workflow/service shape; selected
   harness profiles resolve scoped steps.
5. The reference profile is loop-native by default.
6. Tool calls, worker calls, service calls, file changes, browser actions,
   connector calls, payments, deploys, and Agentgres writes are proposals until
   policy and authority admit them.
7. Raw model output is never authority.
8. Deterministic infrastructure gates, executes, records, normalizes, verifies,
   and settles. It does not replace iterative cognition.
9. Cognitive final output requires an output ownership pass after evidence and
   verification have returned, unless the package is explicitly
   deterministic-only.
10. Authority is monotonic top-down.
11. Context may move bottom-up and laterally, but cannot grant authority.
12. Context topology is planned where possible and repaired when telemetry
    proves it wrong.
13. Compaction preserves provenance, refs, uncertainty, and loop state.
14. Agentgres owns canonical operational truth.
15. Agentgres owns artifact identity, refs, lifecycle, policy linkage, receipt
    linkage, restore validity, and state-root validity.
16. Storage backends hold bytes; they do not define runtime truth.
17. Persistent skills, memory, wiki state, and durable behavior-affecting
    context are workspace/project/domain intelligence, not private property of
    the selected harness or model.
18. Most local/domain runs do not require L1 settlement.
19. Verification depth scales with risk.
20. No actor needs global knowledge.
21. Harness profiles are marketplace-neutral.
22. Worker packages and service packages remain portable outside their first
    party marketplace surfaces.
23. Restore and import are operation-backed through Agentgres, not silent local
    mutation.
24. Goal Kernel is the bounded loop for one GoalRun or claim; it is not the
    OutcomeRoom, collaborative work graph, or universal conductor.
25. `WorkResult` / `OutcomeDelta` is the generic result seam.
    `ImplementationResultPayload` remains the software implementation profile.
26. Dynamic room participation, claim leasing, resource allocation, shared
    frontier admission, and verifier challenges belong to the collaborative
    work graph, not private harness state.
27. Background agents are durable delegated work with visible leases, spend,
    evidence, blockers, verification, and cancellation/quarantine controls.

## One-Line Doctrine

> **Workflow Compositor shapes work; HarnessProfiles resolve steps; the Default
> Harness Profile is IOI's reference bounded-loop scaffold; OutcomeRooms
> coordinate many GoalRuns; generic results cross the seam; workspace
> intelligence persists through skills, memory, receipts, provenance, and
> policy.**
