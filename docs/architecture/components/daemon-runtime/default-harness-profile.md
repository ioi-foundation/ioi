# Default Harness Profile

Status: canonical implementation profile.
Canonical owner: this file for the default daemon-executed harness profile, loop-native orchestration, context topology, output ownership, and implementation-stage object boundaries.
Supersedes: standalone "Default Harness Runtime" wording when that wording implies a peer runtime beside the IOI daemon.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

The **Default Harness Profile** is the standard daemon-executed orchestration
profile for bounded autonomous work.

It is not a separate runtime beside the daemon. The IOI daemon owns execution
semantics; the Default Harness Profile configures how intent becomes
loop-native work under authority, receipts, Agentgres state, artifact refs, and
verification.

Use this doctrine:

> **The Default Harness Profile is a daemon-executed, wallet-authorized, Agentgres-backed, AIIP-speaking, loop-native orchestration profile for bounded autonomous work.**

It is not:

```text
a fixed swarm
a separate execution daemon
a chatbot loop
a blockchain-first execution model
a CAS/Filecoin blob runtime
a marketplace
a deterministic workflow with a model bolted on
```

The default stack relation is:

```text
Operator surfaces
  Autopilot Workbench, CLI/TUI, SDK, ADK, Authority Gateway adapters

IOI daemon
  execution owner and policy/authority/effect boundary

Default Harness Profile
  loop-native orchestration profile executed by the daemon

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

The harness profile exists to make that thesis implementable without requiring
every worker, service, app, or marketplace to invent a private loop.

## Profile Record

Implementations should expose the active harness profile through runtime
manifest, event, trace, or Agentgres projection metadata.

```yaml
DefaultHarnessProfile:
  profile_id: default-harness-profile
  profile_version: 2026.05.default-harness-profile.v1
  daemon_executed: true
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
  l1_settlement: trigger_based
  conformance_refs:
    - CIRC
    - CEC
```

The profile may be implemented by a lower-level runtime service, but the public
ownership boundary stays with the daemon.

## Normative Lifecycle

Every serious run under the profile follows this lifecycle. Small local tasks
may collapse steps, but they must not bypass policy, authority, receipts,
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
9. Compile an initial WorkGraph or single Task.
10. Route workers, tools, models, service engines, or packages.
11. Execute loop-native actors.
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
    type: user | autopilot | cli | sdk | service | worker | schedule | webhook | aiip
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
    local | workstation | hosted | tee | vpc | depin | hybrid
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
an Autopilot workflow
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
a peer runtime beside the IOI daemon
a chatbot loop with receipts added afterward
a fixed swarm topology
a deterministic workflow that calls a model only at the end
a CAS/Filecoin blob runtime
a marketplace router that silently prefers itself
a way to bypass wallet.network authority
a place to canonicalize every private thought or scratch update
```

Correct model:

```text
daemon executes
harness profile orchestrates
wallet.network authorizes
Agentgres admits serious truth
artifact refs bind payload meaning
storage backends hold bytes
receipts prove accountable transitions
L1 settlement happens only by trigger
```

## Conformance Profiles

Implementation tests should be organized around these profile checks:

```text
DHP-1 Daemon ownership
  Clients, adapters, harnesses, and benchmarks cannot own private effect truth.

DHP-2 Proposal-gate-execute
  Consequential actions are proposed, policy/authority gated, then executed.

DHP-3 Receipt-backed terminal
  Terminal success requires typed receipts, observations, postconditions,
  verification state, and completion gate success.

DHP-4 Context topology
  Work splits across context, authority, privacy, risk, service, or
  verification boundaries without dumping global context.

DHP-5 Artifact refs
  Large payloads are stored behind Agentgres-governed ArtifactRefs/PayloadRefs.

DHP-6 Output ownership
  Final cognitive output is produced after evidence, receipts, observations,
  verification, and uncertainty have been ingested.

DHP-7 Local-first settlement
  Ordinary runs settle in Agentgres/receipts; L1 commitment happens only by
  trigger.

DHP-8 Marketplace neutrality
  The default profile does not silently absorb worker/service internals or
  privilege itself over routed workers by platform fiat.
```

CEC remains the post-resolution execution-collapse contract. CIRC remains the
intent-resolution contract. The Default Harness Profile composes those
contracts into an end-to-end daemon orchestration profile.

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
- [`../agentgres/api-object-model.md`](../agentgres/api-object-model.md):
  Agentgres runtime objects, operations, artifact refs, and archives.
- [`../../foundations/aiip.md`](../../foundations/aiip.md): interop profile for
  bounded autonomous work.
- [`../../_meta/implementation-matrix.md`](../../_meta/implementation-matrix.md):
  concept-to-durable-form implementation index.

## Non-Negotiables

1. The IOI daemon owns execution semantics.
2. The Default Harness Profile is daemon-executed; it is not a peer runtime.
3. The profile is loop-native by default.
4. Tool calls, worker calls, service calls, file changes, browser actions,
   connector calls, payments, deploys, and Agentgres writes are proposals until
   policy and authority admit them.
5. Raw model output is never authority.
6. Deterministic infrastructure gates, executes, records, normalizes, verifies,
   and settles. It does not replace iterative cognition.
7. Cognitive final output requires an output ownership pass after evidence and
   verification have returned, unless the package is explicitly
   deterministic-only.
8. Authority is monotonic top-down.
9. Context may move bottom-up and laterally, but cannot grant authority.
10. Context topology is planned where possible and repaired when telemetry
    proves it wrong.
11. Compaction preserves provenance, refs, uncertainty, and loop state.
12. Agentgres owns canonical operational truth.
13. Agentgres owns artifact identity, refs, lifecycle, policy linkage, receipt
    linkage, restore validity, and state-root validity.
14. Storage backends hold bytes; they do not define runtime truth.
15. Most local/domain runs do not require L1 settlement.
16. Verification depth scales with risk.
17. No actor needs global knowledge.
18. The profile is marketplace-neutral.
19. Worker packages and service packages remain portable outside their first
    party marketplace surfaces.
20. Restore and import are operation-backed through Agentgres, not silent local
    mutation.

## One-Line Doctrine

> **The Default Harness Profile thinks through loops, acts through daemon gates, remembers through admitted state, proves through receipts, stores bytes through artifact refs, and settles only what matters.**
