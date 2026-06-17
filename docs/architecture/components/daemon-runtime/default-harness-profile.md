# Default Harness Profile

Status: canonical reference harness profile.
Canonical owner: this file for HarnessProfile semantics, the Default Harness Profile reference scaffold/fallback, loop-native step resolution, context topology, output ownership, and implementation-stage object boundaries.
Supersedes: standalone "Default Harness Runtime" wording when that wording implies a peer runtime beside the Hypervisor Daemon.
Superseded by: none.
Last alignment pass: 2026-06-01.

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

It is not:

```text
a fixed swarm
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
  Workbench/Automations/Foundry surfaces, Canvas views, provider/environment
  views, Authority Gateway adapters

Hypervisor Daemon
  execution owner and policy/authority/effect boundary

Workflow Compositor
  high-level service/workflow graph, dependencies, review points, acceptance
  criteria, delivery contract, and harness selection hints

Hypervisor Automations
  durable workflow, trigger, schedule, API/service, approval-flow, queue, and
  background-mission product surface over Workflow Compositor contracts

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

Selected HarnessProfile
  resolves one scoped step:
    local loop policy
    model/tool/worker/service call planning
    context chamber usage
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
11. Resolve scoped steps through the selected HarnessProfile or module path.
12. Normalize raw results into observations.
13. Record receipts, traces, Agentgres operations, and artifact refs.
14. Re-enter model loop when more action or synthesis is needed.
15. Verify claims according to risk.
16. Repartition context topology when telemetry proves the plan wrong.
17. Run an OutputOwnershipPass unless deterministic-only profile applies.
18. Commit delivery state and local/domain settlement in Agentgres.
19. Store payload bytes in selected storage backends behind ArtifactRefs.
20. Trigger L1/app-chain settlement only when policy or contract requires it.
```

## Loop-Native Execution

The fundamental execution unit is a grounded cognitive loop:

```text
ContextChamber
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
decides whether that effect can cross the deterministic boundary.

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
| `ContextChamber` | scoped runtime state plus context events | chambers outlive one turn or are shared across actors |
| `LoopIteration` | event/receipt/trace segment | loop-level replay or verification becomes first-class |
| `ModelPass` | model invocation receipt plus redacted trace | model-pass lineage is queried or evaluated |
| `ActionProposal` | action request / runtime item / event | approval, replay, or policy review requires durable identity |
| `GateResult` | policy/authority decision receipt | always for consequential actions |
| `ExecutionResult` | tool/worker/service receipt | always for effectful or externally observed actions |
| `NormalizedObservation` | typed event or projection payload | observations are reused by verifiers or downstream tasks |
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
    read | draft | local_write | external_message |
    commerce | funds | deploy | secret_export | physical_action
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
  chambers:
    - chamber:...
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
      parent_chamber: chamber:... | null
      child_chambers:
        - chamber:...
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

### ContextChamber

```yaml
ContextChamber:
  chamber_id: chamber:...
  run_id: run:...
  task_id: task:...
  resolution: coarse | medium | fine | forensic
  goal: string
  constraints: [string]
  acceptance_criteria: [string]
  authority_ref: grant:... | null
  agentgres_refs:
    - agentgres://operation/...
    - agentgres://object/...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  prior_observation_refs:
    - observation:...
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
  chamber_id: chamber:...
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
    read | draft | local_write | external_message |
    commerce | funds | deploy | secret_export | physical_action
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
loop depth is likely to outgrow one chamber
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

Compaction is allowed inside chambers, but compaction drift is telemetry that
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
receipts prove accountable transitions
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
  Receipt, ArtifactRef/PayloadRef, Agentgres refs, and terminal/blocker state.

HP-10 Workspace intelligence portability
  Persistent skills and memory survive model/harness swaps when workspace
  identity, compatibility, provenance, policy, and authority remain valid.
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
ContextChamber runtime state
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

## One-Line Doctrine

> **Workflow Compositor shapes work; HarnessProfiles resolve steps; the Default
> Harness Profile is IOI's reference scaffold; workspace intelligence persists
> through skills, memory, receipts, provenance, and policy.**
