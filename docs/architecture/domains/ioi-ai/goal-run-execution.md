# GoalRun Execution, Context, and Step-Resolution Objects

Status: canonical low-level reference.
Canonical owner: this file for the object shapes of GoalRuns, GoalRun execution ceilings, goal grounding loops, role topologies, context cells, context leases, context handoffs, and orchestration decision receipt registration.
Supersedes: none.
Superseded by: none.
Last alignment pass: 2026-08-07.
Doctrine status: canonical
Implementation status: see [`../../_meta/canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md)

## Purpose

This module owns the object shapes above. They are domain objects of the **ioi.ai
orchestration application**, an openly packaged domain application on Hypervisor.
The daemon admits, executes, and receipts them as it does any application domain.

Whenever a GoalRun executes work, its execution composes the daemon-owned thread,
fork, managed-session, launch-recipe, and harness-binding primitives owned by
[`../../components/daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md).
GoalRun state stores typed refs and derived status. The objects here select,
constrain, and project work; they do not own execution truth, and an
application-owned context object mints no thread, fork, managed-session, launch,
or harness record.

Registered contracts in this family carry `schema://ioi/applications/ioi-ai/*`.
Envelope base types, ID conventions, and capability/authority tiers come from
[`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md).
Doctrine and lifecycle semantics are owned by
[`control-plane.md`](./control-plane.md).

## GoalRunEnvelope

Durable state for goal-shaped work. `ioi.ai` and Hypervisor Sessions may expose
different product surfaces, but they should converge on the same GoalRun
application object when intent must survive compaction, delegation, verification, or
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
  goal_run_execution_ceiling_revision_ref: goal-run-execution-ceiling://.../revision/sha256:...
  goal_run_execution_ceiling_content_hash: sha256:...
  declared_invocation_budget:
    max_total_invocations: integer
    max_parallel_invocations: integer
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
    - obligation_id: receipt-obligation://...
      boundary_event:
        admission | activation | invocation | reconciliation |
        cancellation | close_or_escalate
      receipt_type: string
      receipt_profile_ref: schema://... | receipt://profile/...
      bound_fact_requirement_refs:
        - goal://... | receipt://... | artifact://... | decision://...
      required: boolean
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
The run also binds one exact immutable `GoalRunExecutionCeilingEnvelope`
revision and content hash plus a closed `declared_invocation_budget`; omission
never means an implementation default. The declaration may be narrower than
the ceiling but cannot widen either count.
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
  [`../invariants.md`](../../foundations/invariants.md)).
- **State commitment.** `admitted_state_root_ref` names the Agentgres state
  root under which the run's truth is admitted, and the durable record retains
  it. A prefix-shaped string with no admitted root behind it discharges
  nothing (INV-8); replay verifies the record against the admitted root, and
  restore-style claims follow INV-12.
- **Receipt obligations.** `receipt_obligations` is the typed set of boundary
  events this run must receipt and the exact receipt type/profile for each,
  using the `ReceiptObligation` element owned by
  [`evidence-and-delivery.md`](../../foundations/objects/evidence-and-delivery.md). A bare
  `receipt_required: true` boolean is a claim, not a contract; it cannot say
  which receipt binds which boundary, so it satisfies nothing on its own.

For an activation-backed admission, `admitted_state_root_ref` resolves an
immutable `GoalRunAdmittedState` record whose registered v1 contract retains
the exact `goal_run_ref`, activation and source commitments, requesting
principal, authority/admission decisions and receipts, profile revision/hash,
execution-ceiling revision/hash, declared invocation budget, admitted override
tuple,
resolved-component snapshot/hash, profile-resolution receipt, typed receipt
obligations, admission instant, and non-grants. Its `state_root` is SHA-256 over
JCS of that complete record with `state_root` and `state_root_ref` null; the
coordinate is
`agentgres://state-root/goal-run/<goal-id>/<state-root>`. A file alone is not
admission: the daemon must admit the identical record through Agentgres and
must reconstruct and verify both owners on replay.

## GoalRunExecutionCeilingEnvelope

Immutable, source-neutral bounds admitted with a GoalRun. A ceiling constrains
execution; it does not authorize execution, mint a budget, choose a harness, or
infer a default.

```yaml
GoalRunExecutionCeilingEnvelope:
  schema_version: ioi.goal-run-execution-ceiling.v1
  goal_run_execution_ceiling_id: goal-run-execution-ceiling://...
  revision_ref: goal-run-execution-ceiling://.../revision/sha256:...
  content_hash: sha256:...
  owner_ref: system://... | org://... | project://... | user://...
  max_total_invocations: integer
  max_parallel_invocations: integer
  registry_status: released
```

The revision is the content-addressed identity of the complete immutable body.
`max_parallel_invocations` cannot exceed `max_total_invocations`. A GoalRun
admits a separate `declared_invocation_budget` with the same two fields and
both values less than or equal to the selected ceiling. The ceiling and the
declaration are required facts: a missing, malformed, unresolved, substituted,
tampered, or widened value refuses admission instead of receiving a fallback.

For the M4 `ioi_goal_draft` activation lane, the selected ceiling and the
declared budget are both exactly `{max_total_invocations: 0,
max_parallel_invocations: 0}`. This lane admits durable Goal Space identity,
authority state, receipts, and replayable truth but performs no harness,
worker, model, tool, or service invocation and produces no WorkResult. Its
`active` status means the durable GoalRun identity is admitted and may
participate in bounded room truth; it does not mean execution capacity exists.
An attempted start or invocation must refuse before reservation or effect.
The registered GoalRun v1 contract makes these fields mandatory when the
GoalRun has `origin_surface: ioi_goal_chat`; the corresponding M4 activation
crossing has `source_kind: ioi_goal_draft`. Other already-admitted GoalRun lanes
remain explicitly partial until their own owner-approved ceiling-adoption cut;
their omission is not interpreted as a zero, nonzero, or otherwise inferred
budget, and this M4 ruling does not recertify or broaden M3.

### The admission contract

This is the goal-orchestration application's admission contract (ADR 0020;
placement per
[ADR 0022](../../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md)).
The daemon executes and enforces it under the substrate's admission-evidence
discipline (INV-37); the application owns its content. The M4
`create` + `ioi_goal_draft` slice implements all seven requirements for that
one source lane; this remains the target contract for every other source and
for `join_existing`, whose current runtime paths enforce narrower subsets
([`canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md)).

Admitting a GoalRun requires all of the following, together, before the run
may become `active`:

1. **Profile resolution.** Exactly one immutable `GoalRunProfile` revision and
   content hash; the admitted override set (ref and hash together, or both
   null); the resolved-component snapshot and hash; and the
   `GoalRunProfileResolutionReceipt` committing the admission-time dependency
   closure.
2. **Activation.** The activation binding above, when any originating context
   is claimed.
3. **Source-context verification.** The source-context binding above,
   daemon-verified.
4. **Authority.** The requesting principal's authority decision covering the
   goal-orchestration scope, resolved by the daemon against current grant,
   revocation, and expiry state; room-participating runs additionally satisfy
   the room-lease rule above.
5. **State commitment.** The retained `admitted_state_root_ref` above.
6. **Receipt obligations.** The typed `ReceiptObligation` set above.
7. **Bounds.** The declared invocation/parallelism budget and any
   profile-declared ceilings, admitted as exact revision/hash bindings, never
   widened by defaults. The profile-resolution closure, admitted state, and
   GoalRun retain the identical ceiling and declared budget.

Every precondition is discharged by evidence the admission core resolves or
independently verifies — never by route-supplied constants (INV-37).

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
