# GoalRun Execution, Context, and Step-Resolution Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of GoalRuns, goal grounding loops, role topologies, information-flow labels and declassification approvals, context cells, context leases, context handoffs, task briefs, harness invocations, harness adapter events, implementation result payloads, verifier paths, orchestration decision receipt registration, benchmarks, and routing decisions.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (`InformationFlowLabel` v1 and `DeclassificationApproval` v1 have registered schemas, invariants, fixtures, and generated projections; a narrow software GoalRun and the harness-profile registry exist; production information-flow enforcement, ContextCell leasing, typed handoff, and the GoalRun admission bindings for activation, source context, retained state root, and typed receipt obligations remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md);
this module does not restate them.

## GoalRunEnvelope

Durable state for goal-shaped work. `ioi.ai` and Hypervisor Sessions may expose
different product surfaces, but they should converge on the same GoalRun
primitive when intent must survive compaction, delegation, verification, or
long-session continuation.

The GoalRun is not a chat transcript and not a harness-specific memory file. It
is the bounded coordination record for one participant or subteam's Goal Kernel
loop: intent, constraints, role topology, context cells, leases, handoffs,
runtime assignments, attempts, generic results, verifier path, receipts, and
continuation state. A
GoalRun may stand alone or participate in an `OutcomeRoomEnvelope`; it does not
own the shared room frontier or cross-party admission policy.

```yaml
GoalRunEnvelope:
  goal_run_id: goal://...
  owner_ref: system://... | user://... | org://... | project://... | domain://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_content_hash: hash
  admitted_override_set_ref: artifact://... | null
  admitted_override_set_hash: hash | null
  resolved_component_set_snapshot_ref: artifact://...
  resolved_component_set_hash: hash
  active_skill_set_snapshot_ref: active-skill-set://...
  active_skill_set_hash: hash
  goal_run_profile_resolution_receipt_ref: receipt://...
  initial_role_topology_revision_ref: role_topology://.../revision/... | null
  initial_role_topology_content_hash: hash | null
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  origin_surface:
    ioi_goal_chat | hypervisor_new_session | hypervisor_session |
    automation | marketplace_instance | api
  activation_ref: goal-run-activation://... | null
  source_context_binding:
    target_session_ref: session://... | null
    project_ref: project://... | null
  user_intent_ref: intent://... | prompt://...
  normalized_goal: string
  outcome_room_ref: outcome-room://... | null
  room_participant_lease_ref: participant-lease://... | null
  frontier_item_refs:
    - frontier://...
  work_claim_refs:
    - work-claim://...
  constraint_refs:
    - constraint://... | policy://... | budget://...
  role_topology_ref: role_topology://.../revision/... | null
  grounding_loop_ref: goal_loop://... | null
  active_loop_phase:
    receive_intent | classify_goal | gather_grounding | inspect_state |
    derive_constraints | observe_frontier | form_hypotheses |
    select_or_adapt_topology | claim_allocate_or_delegate | lease_context |
    open_context_cells | execute_attempt | monitor_progress |
    publish_result | verify_compare_or_challenge | repair_or_escalate |
    reconcile | update_frontier_and_memory | continue_or_close | null
  context_cell_refs:
    - context_cell://...
  context_lease_refs:
    - context_lease://... | lease://... | memory_projection://...
  runtime_assignment_refs:
    - runtime-assignment://...
  orchestration_plan_revision_refs:
    - orchestration_plan://.../revision/...
  selected_orchestration_plan_revision_ref: orchestration_plan://.../revision/... | null
  selected_orchestration_plan_content_hash: hash | null
  orchestration_decision_receipt_ref: receipt://... | null
  topology_revision_refs:
    - role_topology://.../revision/...
  attempt_refs:
    - attempt://...
  work_result_refs:
    - work-result://...
  finding_refs:
    - finding://...
  verifier_path_ref: verifier_path://... | null
  verifier_challenge_refs:
    - verifier-challenge://...
  receipt_refs:
    - receipt://... | ledger://...
  receipt_obligations:
    - boundary_event:
        admission | activation | invocation | reconciliation |
        cancellation | close_or_escalate
      receipt_type: string
      receipt_profile_ref: schema://... | receipt://profile/...
  admitted_state_root_ref: agentgres://state-root/goal-run/... | null
  authority_scope_refs:
    - scope:...
  continuation_state:
    open | waiting_on_user | waiting_on_frontier | sleeping | delegated |
    verifying | course_correcting | complete | blocked | superseded
  status: draft | active | paused | complete | superseded | revoked
```

When `outcome_room_ref` is non-null, `room_participant_lease_ref` is required,
must name a current lease for that same room, and every `work_claim_ref` must be
issued to that lease. A GoalRun cannot attach itself to shared room state by
setting a room ref alone.

Every newly admitted GoalRun binds exactly one profile revision. Direct ad hoc
work uses the versioned generic-adaptive profile plus explicit run constraints;
null profile fields are accepted only by a versioned legacy migration adapter
and must be resolved before activation. The resolved-component snapshot,
hash, and resolution receipt are required before the GoalRun becomes `active`.
When an override set is present, both its ref and hash are required; when it is
absent, both are null. The receipt binds the admitted override set and the
transitive versions/hashes actually resolved for this run. Profile revocation
or recall follows its declared policy and may pause, quarantine, migrate, or
allow bounded completion; it never silently rewrites an active run to a newer
revision.

The `initial_role_topology_*` tuple is the immutable admission-time selection
bound by the profile-resolution receipt; both fields are null or both are
non-null. `role_topology_ref` is the current topology pointer and
`topology_revision_refs` preserves its immutable evolution. Initial selection
after grounding and every later adaptation require their own decision/receipt;
they never rewrite the admission tuple.

The selected OrchestrationPlan revision ref/hash and decision receipt are all
null before selection or all non-null after selection. Course correction appends
a successor revision and decision receipt; it never mutates the selected plan
body or makes a product `outcome-plan://` projection authoritative.

Four admission bindings the record must retain, each fixing a defect this canon
observed in its own runtime:

- **Activation.** `origin_surface` is a provenance tag, never the crossing.
  A GoalRun claiming an originating Session, WorkRun, work item, room claim,
  automation step, gateway adapter context, or ioi.ai draft binds the admitted
  `GoalRunActivationEnvelope` through `activation_ref`
  (see [`goal-pursuit.md`](./goal-pursuit.md)); only the direct
  `api | hypervisor_new_session` creation lane may leave it null.
- **Source context.** When the run targets a workspace, `source_context_binding`
  names the daemon-verified target Session and Project. Verifying that the
  Session exists, is admitted, and has a provisioned workspace is part of the
  admission contract itself, not a route convenience (INV-37 in
  [`../invariants.md`](../invariants.md)).
- **State commitment.** `admitted_state_root_ref` names the Agentgres state
  root under which the run's truth is admitted, and the durable record retains
  it. A prefix-shaped string with no admitted root behind it discharges
  nothing (INV-8); replay verifies the record against the admitted root, and
  restore-style claims follow INV-12.
- **Receipt obligations.** `receipt_obligations` is the typed set of boundary
  events this run must receipt and the exact receipt type/profile for each,
  using the `ReceiptObligation` element owned by
  [`evidence-and-delivery.md`](./evidence-and-delivery.md). A bare
  `receipt_required: true` boolean is a claim, not a contract; it cannot say
  which receipt binds which boundary, so it satisfies nothing on its own.

## GoalGroundingLoopEnvelope

Low-level orientation and course-correction loop for bounded goal-shaped work.
This is the concrete loop behind the Goal Kernel: it prevents "goal mode" from
becoming unbounded chat, and prevents multi-worker orchestration from becoming
token-maxing. The loop may run in one harness, across multiple Context Cells,
or as one participant in an OutcomeRoom, but every phase has a purpose, an
admission boundary, and an exit condition.

```yaml
GoalGroundingLoopEnvelope:
  goal_loop_id: goal_loop://...
  goal_ref: goal://...
  conductor_context_cell_ref: context_cell://...
  loop_iteration: integer
  phase:
    receive_intent | classify_goal | gather_grounding | inspect_state |
    derive_constraints | observe_frontier | form_hypotheses |
    select_or_adapt_topology | claim_allocate_or_delegate | lease_context |
    open_context_cells | execute_attempt | monitor_progress |
    publish_result | verify_compare_or_challenge | repair_or_escalate |
    reconcile | update_frontier_and_memory | continue_or_close
  outcome_room_ref: outcome-room://... | null
  frontier_and_claim_refs:
    - frontier://... | work-claim://...
  grounding_source_refs:
    - canon://... | doc://... | route://... | runtime://... |
      project://... | receipt://... | ledger://... | memory_projection://...
  state_inspection_refs:
    - environment://... | session://... | run://... | artifact://... |
      worktree://... | surface://... | endpoint://...
  decision_refs:
    - orchestration_decision://... | routing-decision://... |
      approval-request://... | release-control://...
  context_cell_refs:
    - context_cell://...
  handoff_refs:
    - handoff://...
  attempt_result_and_finding_refs:
    - attempt://... | work-result://... |
      finding://... | outcome-delta://...
  verifier_path_ref: verifier_path://... | null
  evidence_refs:
    - receipt://... | test://... | artifact://... | screenshot://... |
      ledger://...
  productivity_budget_ref: budget://... | null
  topology_participant_and_verifier_change_refs:
    - role_topology://... | participant-lease://... |
      verifier_path://... | decision://...
  marginal_value_stop_policy_ref: policy://... | null
  escalation_state:
    none | ask_user | open_implementer_cell | open_reviewer_cell |
    require_independent_verifier | require_governance_control |
    stop_blocked
  exit_condition:
    continue | delegated | waiting_on_frontier | verified_complete |
    accepted | risk_stop | budget_stop | deadline_stop |
    marginal_value_stop | blocked | superseded |
    user_input_required | governance_required
  status: active | waiting | satisfied | blocked | superseded | revoked
```

Canonical conductor loop:

```text
receive intent
  -> classify goal shape and risk
  -> gather canon, project, runtime, memory, and surface grounding
  -> inspect current state instead of relying on prose
  -> derive constraints, acceptance, and verification path
  -> observe uncertainty, opportunity, and any shared work frontier
  -> form hypotheses, candidate plans, or frontier items
  -> select or adapt topology; claim, allocate, or delegate bounded work
  -> lease context, tools, memory, resources, budget, and authority
  -> execute isolated or cooperative attempts
  -> publish positive, negative, inconclusive, and integrity results
  -> evaluate, falsify, reproduce, compare, merge, reject, or challenge
  -> reconcile receipts, findings, contribution lineage, and memory
  -> update the shared frontier and routing priors when admitted
  -> adapt topology, participants, budget, and verifier paths
  -> continue until acceptance, risk, budget, deadline, or marginal-value stop
```

The conductor may be the verifier for ordinary work. Independent verifier cells
are policy-triggered escalation paths, not the default. A "sea of agents" is a
participation and allocation policy over this loop and the OutcomeRoom frontier,
not a separate runtime or hard-coded topology.

## RoleTopologyEnvelope

Selected role shape for one admitted work subject. The topology is provider-
neutral but never actor-neutral: every role names an accountable actor or
participant separately from its step resolver, model route, and runtime
placement. The durable contract is the role, handoff shape, verifier path, and
authority posture, not a vendor or reusable resolver definition. A topology
may be fixed for a small run or revised under policy as the frontier,
participants, evidence, risk, or resource bottlenecks change.

```yaml
RoleTopologyEnvelope:
  topology_id: role_topology://...
  revision_ref: role_topology://.../revision/...
  content_hash: hash
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  topology_version: integer | semver_or_hash
  topology_kind:
    direct | goal_conductor | delegated_build | governed_release |
    multi_context_review | specialist_mesh | leaderless_blackboard |
    market_allocated | independent_replication | federated_pursuit
  mutation_policy:
    fixed | conductor_mutable | participant_proposed |
    frontier_driven | governance_required
  conductor_role_id: string
  role_bindings:
    - role_id: string
      role_kind:
        conductor | implementer | reviewer | verifier | operator |
        researcher | specialist | synthesizer | resource_provider |
        integrity_challenger | memory_curator
      accountable_actor_ref:
        participant-lease://... | system://... | worker://... | agent://... |
        service://... | org://... | user://... | domain://...
      resolver_requirement_ref: schema://... | capability://... | null
      selected_resolver_kind: harness_profile | agent_harness_adapter | none
      selected_resolver_revision_ref:
        harness-profile://.../revision/... |
        agent-harness-adapter://.../revision/... | null
      selected_resolver_content_hash: hash | null
      model_route_requirement_ref: schema://... | capability://... | null
      selected_model_route_ref: model_route://... | null
      runtime_assignment_ref: runtime-assignment://... | null
      context_cell_ref: context_cell://... | null
  resource_offer_refs:
    - resource-offer://... | capability-offer://...
  verifier_path_ref: verifier_path://... | null
  conductor_verifies_by_default: boolean
  escalation_triggers:
    - publish | runtime_mount | external_connector_action | spend |
      secret_access | unsafe_plaintext | marketplace_admission |
      release_control | production_mutation | physical_action |
      compliance_review
  predecessor_revision_ref: role_topology://.../revision/... | null
  mutation_decision_ref: decision://... | receipt://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: draft | active | adapting | satisfied | superseded | revoked
```

Each topology revision is immutable and content-addressed. Adapting topology
creates a successor revision whose `content_hash` commits the topology body and
predecessor. `mutation_decision_ref` and registry lifecycle/status are excluded;
the decision/receipt binds the already-computed revision/hash and lifecycle may
change eligibility without rewriting a revision. A GoalRun may be admitted
with `role_topology_ref: null` when its profile permits topology to be selected
after grounding. The first selection and every successor are receipted plan/run
updates, never an unversioned in-place graph mutation.

`selected_resolver_kind` discriminates the resolver ref/hash pair; `none`
requires both null. A HarnessProfile, AgentHarnessAdapter, model route, or
RuntimeAssignment can never occupy `accountable_actor_ref`. Room roles use the
current `participant-lease://` as their accountable actor; non-room roles name
the Worker, agent, service, System, organization, user, or domain that remains
responsible for the work and receipts.

## InformationFlowLabel and DeclassificationApproval

`InformationFlowLabel` is the versioned, multi-axis information-flow contract
carried by context, connector/tool outputs, memory imports, model outputs, and
their derivatives. Its registered v1 wire shape owns origin, integrity,
confidentiality, instruction authority, destination/data-class egress policy,
purpose, retention, and the transitive derivation-parent closure. Missing or
`unknown` axes fail closed at consequential-effect admission. Summarization,
model substitution, memory import, and tool-output transformation create a new
label by deterministic restrictive join; they never erase or weaken a parent
label.

Boundary production also cannot mint trust. Raw model-provider results are
`model_output + untrusted + none`; browser observations are
`external_untrusted + untrusted + none`; live MCP results are
`tool_output + untrusted + none`; and durable imported/summarized memory is
content-only while preserving the worst parent integrity and authority. A
separately admitted verifier may later create a successor label; the producing
boundary cannot do so implicitly.

`DeclassificationApproval` is the separate wallet/policy authority object for
one protected egress. It binds the exact RuntimeToolContract revision, label ref
and content hash, canonical effect hash, canonical request hash, exact reviewed-
representation hash, destination, purpose, declassification target, expiry,
grant, and approval receipt. Changing effect bytes, request content, destination,
reviewed representation, label, tool revision, purpose, status, or expiry makes
the approval unusable. Declassification changes neither provenance nor
instruction authority; it cannot make an untrusted instruction authoritative.

The canonical JSON Schema 2020-12 wire contracts, invariant profiles, and
cross-language fixtures are registered in
[`architecture-contract-registry.v1.json`](../../_meta/schemas/architecture-contract-registry.v1.json).
The Hypervisor Daemon owns pre-effect evaluation. `ContextCell`, memory,
connector/tool, and model owners carry refs to these labels rather than defining
parallel taint or privacy objects.

## ContextCellEnvelope

Independent working context for one role. Context cells exist to protect
long-horizon intent from implementation-token churn, to keep implementation
details out of high-level state until summarized, and to allow review with a
fresh bounded context. Agent-to-agent conversation is allowed only when it is a
typed handoff between cells.

```yaml
ContextCellEnvelope:
  context_cell_id: context_cell://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  role_topology_revision_ref: role_topology://.../revision/... | null
  role_binding_id: string
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  role:
    conductor | implementer | reviewer | verifier | operator |
    researcher | specialist | synthesizer | resource_provider |
    integrity_challenger | memory_curator
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  model_route_ref: model_route://... | null
  memory_projection_refs:
    - memory_projection://... | wiki://...
  context_lease_refs:
    - context_lease://... | lease://...
  information_flow_label_refs:
    - ifc-label://...
  active_runtime_assignment_ref: runtime-assignment://... | null
  authority_scope_refs:
    - authority://... | policy://...
  compression_policy_ref: policy://... | null
  current_claim_ref: work-claim://... | null
  next_wake_condition_ref: policy://... | event://... | null
  status:
    open | active | sleeping | waiting | handed_off | summarized |
    quarantined | closed | revoked
```

The runtime-assignment refs above are projections of separately admitted
placement decisions. A RoleTopology declares logical responsibility and a
Context Cell owns bounded working context; neither object may infer node
membership, locality, authority, or cross-system participation from a worker or
harness ref. Reassignment creates a new assignment epoch and preserves the
predecessor and reconciliation lineage.

When `role_topology_revision_ref` is non-null, `role_binding_id`, accountable
actor, resolver ref/hash, model route, runtime assignment, and participant
lease must equal that exact topology role. Changing any of those role-binding
axes requires a successor RoleTopology revision plus the owning routing,
placement, or admission decision/receipt and an updated cell pointer. They are
convenience projections, not independent selection truth.
A topology-less direct-work cell leaves the topology ref null and must still
name its standalone accountable actor; HarnessInvocation owns the resolver
actually invoked.

## ContextLeaseEnvelope

Scoped lease that lets a Context Cell or harness invocation use only the context,
tools, memory, files, runtime, authority, and budget required for its bounded
role. Context leases make context a governed resource instead of dumping the
entire conversation, wiki, repo, connector estate, or authority envelope into
every harness.

```yaml
ContextLeaseEnvelope:
  context_lease_id: context_lease://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  context_cell_ref: context_cell://... | null
  issued_to_ref: context_cell://... | harness_invocation://...
  lease_kind:
    canon | repo_slice | worktree | memory_projection | tool |
    connector | runtime | authority | budget | surface | receipt_view |
    mixed
  allowed_ref_patterns:
    - docs/architecture/... | apps/... | crate://... | memory_projection://... |
      tool://... | connector://... | authority://... | receipt://...
  denied_ref_patterns:
    - secret://... | unrelated_path://... | unsafe_plaintext://...
  authority_scope_refs:
    - authority://... | policy://...
  budget_ref: budget://... | null
  ttl_seconds: integer | null
  receipt_required: boolean
  status: draft | active | expired | revoked | consumed
```

`issued_to_ref` names only a concrete ContextCell or HarnessInvocation. A
reusable HarnessProfile, AgentHarnessAdapter, Worker definition, or service
definition is never a lease subject. The lease and its subject must bind the
same `work_subject_ref`; when a cell ref is present it must be that subject or
the cell that owns the invocation.

## ContextHandoffEnvelope

Typed packet between context cells. Handoffs are the durable substrate for
conductor/implementer/reviewer workflows; they should contain enough state for
the receiving cell to act without inheriting the sender's entire context window.

```yaml
ContextHandoffEnvelope:
  handoff_id: handoff://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  from_context_cell_ref: context_cell://...
  to_context_cell_ref: context_cell://...
  handoff_kind:
    task_brief | implementation_result | blocker | diff_summary |
    test_result | review_request | verification_result |
    attempt_result | finding | resource_request | capability_offer |
    frontier_update | verifier_challenge | decision_request |
    continuation_summary
  payload_ref:
    task_brief://... | implementation_result://... | artifact://... |
    work-result://... | finding://... | resource-offer://... |
    capability-offer://... | verifier-challenge://... | message://... | null
  context_lease_refs:
    - context_lease://...
  acceptance_refs:
    - rubric://... | gate://... | test://...
  receipt_refs:
    - receipt://... | ledger://...
  status: draft | sent | accepted | rejected | superseded
```

## TaskBriefPayloadEnvelope

Normalized payload for bounded implementation, research, review, repair,
specialist, resource, synthesis, or verification work. The conductor may
render this as a prompt for a specific harness, but the durable contract is
this task brief, not the rendered prompt. Software-specific fields are one
output profile rather than the generic result contract.

```yaml
TaskBriefPayloadEnvelope:
  task_brief_id: task_brief://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  handoff_ref: handoff://... | null
  objective: string
  objective_class:
    implement | repair | review | verify | inspect | research |
    reproduce | synthesize | curate | challenge | provide_resource |
    ontology_change | incident_response | service_delivery |
    physical_mission | refactor | ui_check | release_check | custom
  scope_refs:
    - project://... | file://... | route://... | surface://... |
      artifact://... | receipt://...
  canon_refs:
    - canon://... | doc://...
  constraints:
    - string
  do_not_touch_refs:
    - file://... | module://... | policy://...
  acceptance_refs:
    - rubric://... | test://... | gate://...
  verification_plan_refs:
    - verifier_path://... | test://... | script://...
  context_lease_refs:
    - context_lease://...
  output_contract:
    result_profile:
      software_implementation | research | ontology_mutation |
      incident_resolution | service_delivery | physical_mission |
      review | evaluation | custom
    work_result_required: boolean
    outcome_delta_required: boolean
    finding_refs_required: boolean
    changed_files_required: boolean
    diff_summary_required: boolean
    tests_required: boolean
    blocker_report_required: boolean
    receipt_refs_required: boolean
  status: draft | issued | superseded | revoked
```

## HarnessInvocationEnvelope

Daemon-mediated invocation of a selected HarnessProfile or Agent Harness
Adapter. This is the object that removes the human copy-paste relay: a
ContextHandoff becomes a HarnessInvocation, the adapter renders the harness
native prompt or command privately, and the daemon records normalized events,
artifacts, receipts, and final result.

```yaml
HarnessInvocationEnvelope:
  harness_invocation_id: harness_invocation://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  goal_run_ref: goal://... | null
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  handoff_ref: handoff://... | null
  context_cell_ref: context_cell://... | null
  task_brief_ref: task_brief://...
  resolver_kind: harness_profile | agent_harness_adapter
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/...
  resolver_content_hash: hash
  model_route_ref: model_route://... | null
  runtime_ref: runtime://... | environment://... | session://... | null
  external_invocation_bindings:
    - external_protocol_binding_ref: aiip-binding://... | mcp://... | schema://...
      protocol_version_or_extension_ref: string
      opaque_handle_commitment: hash
      encrypted_or_redacted_handle_ref: artifact://... | null
      status_projection_ref: event://... | artifact://... | null
  context_lease_refs:
    - context_lease://...
  adapter_rendering_ref: artifact://... | null
  event_refs:
    - harness_event://...
  work_result_ref: work-result://... | null
  profile_result_ref: implementation_result://... | artifact://... | null
  receipt_refs:
    - receipt://... | ledger://...
  status:
    queued | running | waiting_on_harness | waiting_on_conductor |
    completed | failed | cancelled | superseded
```

An MCP Task or another protocol-native asynchronous task remains an opaque
external invocation handle bound to this invocation and its exact
protocol/version adapter. IOI records its commitment and protected handle
reference; it does not mint an IOI identity that pretends to own the external
task. The handle never becomes the `GoalRun` identity or authoritative GoalRun
status. Completion is normalized into `WorkResult` / `OutcomeDelta` and remains
subject to the conductor's `VerifierPath`.

`resolver_kind` discriminates the exact resolver revision/hash. The invocation
also binds the accountable actor that owns the work and receipts; neither a
HarnessProfile, adapter, model route, nor runtime can stand in for that actor.
GoalRun/context-cell execution binds `goal_run_ref`, `handoff_ref`, and
`context_cell_ref` as applicable. A direct AutomationRun, WorkRun, module run,
claim, or attempt invocation may leave those goal-specific refs null, but still
requires an exact `work_subject_ref`, accountable actor, TaskBrief, resolver,
leases, and result/receipt path. Every event and result emitted by the
invocation must carry the same work subject.

A completed invocation requires `work_result_ref`. `profile_result_ref` is an
optional domain/profile payload and cannot replace the canonical WorkResult.
For software work it names an `ImplementationResultPayloadEnvelope`, which
must point back to the same WorkResult and be the WorkResult's
`result_payload_ref` (or its content-addressed payload). Failed or cancelled
invocations may leave both result refs null only when their terminal receipt
and failure/blocker evidence are present.

## HarnessAdapterEventEnvelope

Normalized event emitted by a harness adapter during a HarnessInvocation.
Harnesses may stream text, tool calls, terminal output, file writes, browser
events, or provider-specific state; the adapter must translate them into common
events before they become durable coordination evidence.

```yaml
HarnessAdapterEventEnvelope:
  harness_event_id: harness_event://...
  harness_invocation_ref: harness_invocation://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  event_kind:
    started | stdout | stderr | thought_summary | tool_proposed |
    tool_started | tool_completed | file_changed | patch_created |
    test_started | test_completed | blocker | decision_request |
    artifact_created | attempt_updated | finding_proposed |
    outcome_delta_proposed | verifier_challenge_proposed |
    resource_requested | frontier_update_proposed |
    receipt_emitted | completed | failed
  payload_ref: artifact://... | message://... | null
  normalized_observation_ref: observation://... | null
  receipt_refs:
    - receipt://...
  redaction_policy_ref: policy://... | null
  timestamp: iso8601
```

## ImplementationResultPayloadEnvelope

Software-implementation profile of `WorkResultEnvelope` returned from a
HarnessInvocation. The conductor consumes this object, not a copied chat
response. It is intentionally bounded: enough evidence to verify, repair,
continue, or close; not the implementer's full context. Research, ontology,
incident, service, physical-mission, review, and evaluation results use the
generic WorkResult/OutcomeDelta seam rather than overloading changed files.

```yaml
ImplementationResultPayloadEnvelope:
  implementation_result_id: implementation_result://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  harness_invocation_ref: harness_invocation://...
  handoff_ref: handoff://... | null
  work_result_ref: work-result://...
  attempt_ref: attempt://... | null
  status: completed | failed | blocked | partial | superseded
  changed_file_refs:
    - file://... | artifact://...
  patch_refs:
    - artifact://... | diff://...
  test_result_refs:
    - test://... | receipt://...
  blocker_refs:
    - blocker://... | handoff://...
  decision_request_refs:
    - handoff://...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://... | ledger://...
  summary_ref: message://... | artifact://... | null
  next_recommended_handoff_kind:
    none | repair | review | verify | ask_user | escalate
```

## VerifierPathEnvelope

Defines the selected verification shape for a plan, run, worker, route, or
package. Verifier paths are evidence contracts; model judges are allowed, but
they are not truth by themselves.

The default verifier path for ordinary goal work may be conductor-run
deterministic verification: tests, diffs, browser evidence, source checks,
receipt inspection, and acceptance-criteria reconciliation. Independent verifier
harnesses are escalation paths, not the default requirement.

```yaml
VerifierPathEnvelope:
  verifier_path_id: verifier_path://...
  owner_ref: org://... | system://... | domain://... | null
  applies_to:
    - goal://... | run://... | worker://... | model_route://... |
      package://... | orchestration_plan://... | outcome-room://... |
      attempt://... | finding://... | ontology-assertion://... |
      evidence://...
  verifier_rule_version_ref: rubric://... | policy://... | gate://...
  verification_kind:
    deterministic | test | static_analysis | browser_evidence |
    model_judge | verifier_worker | human_review | benchmark |
    regulated_review | physical_safety | hybrid
  required_evidence_refs:
    - artifact://... | receipt://... | gate://... | benchmark://...
  verifier_refs:
    - principal://... | worker://... | model://... | gate://... | org://... |
      system://... | domain://...
  acceptance_threshold_ref: rubric://... | gate://... | policy://...
  independence:
    minimum_independent_principals: nonnegative_integer
    subject_owner_may_self_verify: boolean
    required_distinct_independence_groups: nonnegative_integer
    affiliation_and_dependency_evidence_refs:
      - evidence://... | artifact://... | receipt://...
    correlated_failure_policy_ref: policy://... | null
  replay_required: boolean
  challenge_refs:
    - verifier-challenge://...
  status:
    draft | active | challenged | reverifying | satisfied |
    failed | superseded | revoked
```

For an independence requirement greater than zero, a verifier counts only when
its accountable principal, affiliations, upstream evidence dependencies, and
declared independence group satisfy the selected correlation policy. Missing
affiliation or dependency evidence is unknown and never counts as independence.

## Orchestration Decision Receipt Registration

The shared object canon owns `OrchestrationConstraintEnvelope`,
`OrchestrationPolicyEnvelope`, and `OrchestrationPlanEnvelope`. The canonical
`OrchestrationDecisionReceipt` field schema and receipt-type registration are
owned solely by
[`events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md).
That receipt records why a coordinator selected a plan under declared
constraints, policy, candidates, evidence, fallback, and verifier posture. It
is distinct from `RoutingDecisionEnvelope`, which records Worker/domain/route
selection, and it does not prove that either decision was globally optimal or
correct.

## BenchmarkEnvelope

```yaml
BenchmarkEnvelope:
  benchmark_run_id: benchmark://...
  worker_id: worker://...
  worker_composition_ref: package://... | ai://... | null
  model_route_ref: model_route://... | null
  resolver_kind: harness_profile | agent_harness_adapter | none
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  semantic_harness_profile_revision_ref:
    harness-profile://.../revision/... | null
  semantic_harness_profile_content_hash: hash | null
  runtime_profile_ref: runtime://... | profile://... | null
  privacy_posture_ref: privacy_posture://... | policy://... | null
  verifier_path_ref: verifier_path://... | null
  sparse_worker_category: string
  benchmark_profile_ref: benchmark://...
  environment_hash: hash
  manifest_hash: hash
  policy_hash: hash
  score_commitment: hash
  evaluator_id: worker://... | verifier://...
  evaluation_receipt_root: hash
  routing_eligibility_result: eligible | ineligible | suspended
```

The benchmark resolver discriminator follows the pairing rule above. An
adapter benchmark may additionally bind the exact HarnessProfile it realizes;
the score never treats an adapter family ref or semantic profile as proof of
the other. `none` requires all resolver/profile fields to be null unless the
benchmark profile explicitly names a non-harness deterministic path.

## RoutingDecisionEnvelope

`RoutingDecisionEnvelope` is the neutral, replayable selection record. It
commits not only to the candidate set but also to affiliations, first-party or
subsidized seed supply, the selected Worker composition and its mounted
dependencies, every admitted route attempt, fallback/escalation, and verifier
posture. A selection receipt can attest this decision boundary; it cannot prove
that the chosen route was globally optimal or independent without the declared
evidence.

```yaml
RoutingDecisionEnvelope:
  routing_decision_id: routing-decision://...
  task_id: task://...
  goal_and_room_refs:
    - goal://... | outcome-room://...
  router_id: worker://... | runtime://... | system://... | domain://...
  task_offer_ref: packet://... | null
  task_acceptance_refs:
    - packet://...
  selected_task_acceptance_ref: packet://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
  intent_hash: hash
  candidate_set_commitment: hash
  candidate_affiliation_commitment: hash
  candidate_affiliation_and_ownership_evidence_refs:
    - evidence://... | receipt://... | org://... | provider://...
  routing_policy_hash: hash
  selected_domain_or_worker: system://... | domain://... | worker://... | service://... | runtime://...
  selected_worker_composition_ref: package://... | ai://... | worker://... | null
  selected_model_provider_runtime_refs:
    - model://... | model_route://... | provider://... | runtime://... |
      node://... | model-route-contract://...
  attempted_route_refs:
    - route-attempt://... | route-chain://...
  actual_attempt_refs:
    - route-attempt://... | attempt://... | work-result://... | receipt://...
  authority_scope: []
  cost_bound_ref: cost://... | budget://... | quote://... | null
  reason_codes:
    - quality | cost | privacy | latency | locality | installed_status |
      benchmark_result | authority_fit | user_preference | safety |
      independence | affiliation | seed_supply | fallback_availability
  fallback_policy_ref: policy://... | null
  fallback_or_escalation_refs:
    - route-chain://... | route-attempt://... | decision://... | receipt://...
  verifier_escalation_refs:
    - verifier_path://... | verifier-challenge://... | worker://... |
      decision://... | receipt://...
  contributor_scope: my_workers | organization | network_open
  contribution_policy_ref: policy://...
  seed_supply_and_independence_evidence_refs:
    - evidence://... | receipt://... | benchmark://... | certification_claim://...
  receipt_obligations: []
  routing_decision_receipt_ref: receipt://... | null
  signature: optional
```

For an external solicitation, the decision binds every admitted response and
the selected response under one terms root. It explains selection but is not
an authority grant, executable award, accepted result, contribution allocation,
or payout right. The corresponding `WorkClaimLeaseEnvelope` is the bounded
award that must still satisfy participant, context, resource, budget, and
authority admission.

The `selected_task_acceptance_ref` must be a member of
`task_acceptance_refs`. For an external solicitation it is non-null, has
`status: accepted`, names `selected_domain_or_worker` as its accountable
responder, and binds the same collaboration terms root. The selected quote and
budget reservation must match the routing decision. Internal local routing may
leave offer/response refs null, but it cannot claim an external award.
