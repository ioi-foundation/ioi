# Work Request, WorkRun, and Runtime Binding Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of worker instances, runtime subscriptions, typed work-subject bindings, runtime assignments, work requests, WorkRuns, and resource-allocation decisions.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: partial (worker-instance, runtime-assignment, and run-lifecycle shapes back existing daemon run routes; typed work-subject binding, resource-allocation decision, and runtime-subscription shapes remain planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../../components/daemon-runtime/doctrine.md`](../../components/daemon-runtime/doctrine.md);
this module does not restate them.

## WorkerInstanceEnvelope

```yaml
WorkerInstanceEnvelope:
  worker_instance_id: agent://...
  worker_id: worker://...
  worker_manifest_ref: ai://...
  install_id: install://...
  owner_id: wallet://... | org://... | project://...
  runtime_assignment_id: optional
  runtime_id: optional
  execution_profile: local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc
  persistence_profile: ephemeral | session | zero_to_idle | persistent
  interaction_surfaces:
    - chat
    - task
    - api
    - workflow_node
    - scheduler
  status: starting | running | idle | recovering | suspended | archived | failed
  memory_policy:
    mode: none | session | agentgres_refs | sealed_archive
    archive_on_idle: boolean
  authority_grant_refs:
    - grant://...
  subscription_ref: optional
  latest_run_id: optional
  latest_state_root: optional
  archive_ref: optional
  created_at: timestamp
  updated_at: timestamp
```

## RuntimeSubscriptionEnvelope

```yaml
RuntimeSubscriptionEnvelope:
  subscription_id: subscription://...
  owner_id: wallet://... | org://...
  worker_instance_id: optional
  runtime_assignment_id: optional
  mode: per_invocation | warm_runtime | managed_monthly
  compute_profile: hosted | provider | depin | tee | customer_vpc | local
  budget_policy_ref: optional
  entitlement_ref: optional
  billing_ref: optional
  status: trial | active | past_due | paused | cancelled
  renews_at: optional
  expires_at: optional
```

## TypedWorkSubjectBinding

`TypedWorkSubjectBinding` is a non-owning discriminated value used when a
domain contract must point at the work that authorized or contextualized an
effect without inventing a universal work wrapper. `kind` and `ref` must agree,
and the referenced owner remains authoritative for lifecycle, budget,
acceptance, evidence, and status:

```yaml
TypedWorkSubjectBinding:
  kind:
    goal_run | automation_run | work_item | work_claim |
    service_order | physical_action_intent
  ref:
    goal://... | automation-run://... | work_item://... | work-claim://... |
    order://... | intent://...
```

The legacy `mission://...` namespace may survive only as a compatibility alias
that resolves to exactly one `goal://...` or `outcome-room://...` backing
subject. It cannot be written as canonical identity or carry independent
authority, budget, lifecycle, evidence, receipts, or status.
An `automation_run` binding always uses `automation-run://...`; the reusable
AutomationSpec remains `automation://...`. A discriminator may not rescue an
intrinsically ambiguous identity namespace.

## RuntimeAssignmentEnvelope

`RuntimeAssignmentEnvelope` is the governed bridge from logical work to an
actual execution placement. It binds a GoalRun, claimed work, role, Context
Cell, or embodied unit to one runtime and, when the work executes for a bounded
DAS, to one currently admitted node membership of that same `system_id`. It is
a placement and reconciliation decision, not a node-membership record,
authority grant, actuator-authority grant, or cross-system delegation packet.

```yaml
RuntimeAssignmentEnvelope:
  schema_version: ioi.runtime-assignment.v1
  runtime_assignment_id: runtime-assignment://...
  assignment_epoch: nonnegative_integer
  predecessor_runtime_assignment_ref: runtime-assignment://... | null
  work_binding:
    goal_run_ref: goal://... | null
    task_ref: task://... | null
    run_ref: run://... | null
    frontier_item_ref: frontier://... | null
    work_claim_ref: work-claim://... | null
    role_topology_ref: role_topology://... | null
    role_name: string | null
    context_cell_ref: context_cell://... | null
    harness_invocation_ref: harness_invocation://... | null
    worker_instance_ref: agent://... | null
    embodied_unit_ref:
      robot://... | drone://... | device://... | facility-system://... | null
    controller_binding_ref: controller-binding://... | null
    fleet_mission_allocation_lease_ref:
      fleet-mission-allocation-lease://... | null
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: hash
  system_id: system://... | null
  system_placement:
    deployment_profile_ref: deployment-profile://... | null
    node_membership_ref: node-membership://... | null
    node_id: node://... | null
    node_membership_epoch: nonnegative_integer | null
    node_role: autonomous_system_node_role | null
    node_role_lease_ref: lease://... | null
    writer_epoch_transition_ref: writer-transition://... | null
    writer_epoch_transition_hash: hash | null
    writer_epoch: nonnegative_integer | null
  runtime_placement:
    runtime_node_ref: runtime://...
    daemon_profile_ref: profile://...
    compute_session_ref: compute://... | null
    placement_policy_ref: policy://...
    required_locality_refs:
      - region://... | failure-domain://... | custody://... | policy://...
    prohibited_locality_refs:
      - region://... | failure-domain://... | custody://... | policy://...
  embodied_runtime_binding:
    execution_target: native | external | null
    native_runtime_profile:
      micro | edge | site | null
    runtime_graph_manifest_ref: embodied-runtime-graph-manifest://... | null
    runtime_graph_manifest_hash: hash | null
    graph_partition_bindings:
      - partition_key: string
        resolved_partition_hash: hash
    graph_activation_ref: graph-activation-transaction://... | null
  state_and_partition:
    required_state_watermark_ref:
      agentgres://... | checkpoint://... | commitment://... | state://... | null
    minimum_operation_offset: nonnegative_integer | null
    required_state_root: hash | null
    minimum_read_consistency:
      cached_projection | projection_consistent | snapshot_consistent |
      state_root_consistent | linearized_domain | serializable_domain
    required_read_watermark: string | null
    state_freshness_policy_ref: policy://...
    state_sync_before_start: required | policy_conditional | not_required
    temporal_verification_profile_ref: policy://... | null
    temporal_verification_profile_hash: hash | null
    temporal_validity_evaluation_ref: evidence://... | receipt://... | null
    temporal_validity_evaluation_hash: hash | null
    partition_mode:
      fail_closed | read_only | bounded_local_execution | disconnected_autonomy
    partition_and_degraded_mode_policy_ref: policy://...
    rejoin_and_state_merge_policy_ref: policy://...
  lease_and_reassignment:
    assignment_lease_ref: lease://...
    valid_from: timestamp
    expires_at: timestamp | null
    reassignment_policy_ref: policy://...
    predecessor_drain_or_fencing_receipt_ref: receipt://... | null
    handoff_checkpoint_ref: checkpoint://... | artifact://... | null
  duplicate_effect_control:
    effect_recovery_class:
      replayable | checkpointable | compensatable |
      reconciliation_required | non_retryable | null
    idempotency_key: string | null
    idempotency_scope_ref: policy://... | state://... | null
    duplicate_effect_prevention_policy_ref: policy://...
    ambiguous_effect_reconciliation_policy_ref: policy://...
    compensation_policy_ref: policy://... | null
  reconciliation:
    required_before_activation: boolean
    predecessor_outcome_state:
      not_applicable | known_not_committed | known_committed | ambiguous
    reconciliation_policy_ref: policy://...
    unresolved_effect_refs:
      - effect://... | invocation://... | receipt://...
    reconciliation_receipt_ref: receipt://... | null
    status: not_required | pending | satisfied | failed_closed
  authority_and_assurance:
    assigned_by_ref: system://... | domain://... | policy://... | worker://...
    assignment_decision_ref: decision://... | routing-decision://...
    authority_grant_refs:
      - grant://...
    authority_scope_refs:
      - authority://... | policy://...
    verification_profile_refs:
      - verifier_path://... | policy://... | schema://...
    admission_evidence_refs:
      - evidence://... | receipt://... | attestation://...
    receipt_obligations: []
  economics:
    subscription_ref: subscription://... | null
    quote_ref: quote://... | null
    budget_reservation_ref: budget://... | allocation://... | null
  assignment_hash: hash
  signature: required
  admission_receipt_ref: receipt://... | null
  execution_receipt_refs:
    - receipt://...
  status:
    proposed | admitted | active | draining | completed | superseded |
    revoked | failed_closed
```

At least one of `goal_run_ref`, `task_ref`, `run_ref`, `work_claim_ref`,
`harness_invocation_ref`, or `embodied_unit_ref` is required. An embodied unit
may therefore be the required work subject for placement. A Context Cell, role,
controller binding, fleet-allocation binding, or exact embodied-resource-group
revision narrows that work subject; it cannot create work, room participation,
node membership, actuator authority, or any other authority by itself.

When a system-owned GoalRun is the work subject, assignment `system_id` must
match the GoalRun owner. For room-scoped participant work, it must resolve
through the GoalRun's current participant lease and work claim; the room's own
system identity does not silently become the participant's execution identity.

When `embodied_unit_ref` is non-null, assignment `system_id` is required and
must match the unit's owning `system_id`. An admitted or active embodied
assignment must bind `controller_binding_ref`; that controller binding must name
the same unit and `system_id`, and its admitted execution-node membership must
match `system_placement.node_membership_ref`. When
`fleet_mission_allocation_lease_ref` is present, the lease must name the same
unit, controller binding, `system_id`, and execution-node membership as the
assignment.

Every `resource_group_bindings` entry must name one admitted immutable group
revision and its exact `membership_closure_hash`. The group must resolve to the
same `system_id` and `system_placement.deployment_profile_ref` as the assignment
and to one embodied domain admitted by that system. It is never sufficient as
the only work subject. When `embodied_unit_ref` or `controller_binding_ref` is
present, the group's resolved closure must contain that unit or controller plus
at least one sensor or actuator reachable through the bound controller; the
binding then narrows placement to that assignment's slice of the group.

An actuator-bearing assignment requires non-null `embodied_unit_ref` and
`controller_binding_ref`, and every actuator in its effective group slice must
be reachable through that controller. An `observe_only` group containing only
passive work may instead narrow a GoalRun, task, run, work claim, or harness
invocation without fabricating an embodied unit, provided every selected sensor
resolves through the assignment's admitted source-node membership or another
explicitly admitted read/evidence route. This exception never admits
actuation. One assignment never stands in for every unit or controller in a
multi-unit group, and a changed revision or closure hash requires a new
assignment admission rather than late-bound expansion.

A physical work subject that distributes or reconciles work across multiple
embodied units or execution-node memberships requires a distinct, current
`FleetMissionAllocationLease` for each affected assignment. A
`RobotFleetRecord` with one unit does not require a coordination record or fleet
allocation lease merely because it is represented as a fleet; those contracts
become required only when the physical work actually crosses unit or execution-member
boundaries. Naming a multi-unit resource group does not collapse those
assignments, allocation leases, controller boundaries, or reconciliation
obligations into one placement.

An admitted embodied execution assignment binds one exact
`EmbodiedRuntimeGraphManifestEnvelope` revision and hash plus the exact hashes
of graph partitions placed by that assignment. `native_runtime_profile` is required
exactly when `execution_target` is `native`; it selects the `micro`, `edge`, or
`site` deployment footprint
without implying that all three profiles share one binary or operating system.
An active assignment also binds the current successful
`EmbodiedGraphActivationTransaction`. A proposed or admitted-but-not-active assignment
may leave `graph_activation_ref` null. The activation must name the same graph
hash, assignment, partitions, controller/resource bindings, runtime node, and
system membership; otherwise activation fails closed. External compatibility
execution still binds the compiled graph, but leaves `native_runtime_profile`
null and resolves the admitted external adapter through that graph.

No `SpacetimeReservationLease` is embedded in the assignment. Assignment and
`FleetMissionAllocationLease` determine placement and who owns which work;
spacetime reservations separately constrain where and when a unit may attempt
physical occupancy. Neither object expands the other's scope or authorizes an
actuator.

An embodied unit may have no current assignment while it is inventory-only,
commissioning, unplaced idle, detached, under maintenance, offline, retired, or
otherwise outside an admitted execution placement. Historical and superseded
assignment refs remain lineage only. Neither an embodied identity,
resource-group binding, controller binding, fleet allocation lease, nor
`RuntimeAssignmentEnvelope` authorizes actuation; Physical Action Safety and
the admitted physical-mission/action authority envelopes remain mandatory.

For an ordinary non-system local assignment, `system_id` and every
`system_placement` field may be null. Once `system_id` is non-null, an admitted
or active assignment must bind the system's active deployment profile, the
selected node's current membership and membership epoch, and the declared node
role. `node_id` must match that membership. A role lease is additionally
required whenever the selected membership or deployment policy requires one.
Membership, role, and assignment leases must all remain current before an
effect is admitted. The assignment never widens the authority already carried
by those records and grants.

`required_state_watermark_ref`, `required_state_root`, assignment epoch, and
predecessor drain/fencing evidence prevent a replacement or partitioned worker
from proceeding on silently stale state. `bounded_local_execution` and
`disconnected_autonomy` are valid only under the referenced system partition
policy and an exact `TemporalVerificationProfile`. That profile must bind the
admitted elapsed-duration/boot-continuity basis, maximum holdover and
revocation exposure, allowed operation classes, call/effect budget, and
reconnect/revalidation rule. Reboot, restore, continuity loss, or bound
exhaustion makes the stronger claim indeterminate or unavailable until
re-anchored; a signed lease or rolled-back wall clock cannot preserve it.
These modes do not permit undeclared external effects or override the
independently enforceable local safety boundary. An ambiguous predecessor
effect requires satisfied reconciliation
before activation. A `non_retryable` or `reconciliation_required` effect cannot
be reassigned as a fresh attempt merely because its runtime disappeared.

One logical GoalRun may therefore have several assignments for parallel roles,
independent replication, failover, or fleet/swarm execution while remaining
inside one system's constitution and operational truth. Same-system placement
and coordination are native L0 operations and do not use AIIP semantics.
Cross-system work does not share this placement object: each sovereign
participant admits its own local `RuntimeAssignmentEnvelope`, and AIIP carries
the accepted handoff, terms, permitted evidence, and result between those
systems. No AIIP packet, remote GoalRun, or foreign role topology grants
placement or node authority inside another system.

## TaskEnvelope

```yaml
TaskEnvelope:
  task_id: task://...
  requester_id: wallet://... | agent://... | service://...
  outcome_room_ref: outcome-room://... | null
  frontier_item_ref: frontier://... | null
  work_claim_ref: work-claim://... | null
  objective: string
  task_class: coding | research | workflow | commerce | render | connector | service_delivery | managed_agent | other
  privacy_class: public | internal | confidential | restricted | regulated | safety_critical
  execution_profile: local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc
  input_refs:
    - artifact://...
    - agentgres://object/...
  output_contract:
    type:
      report | patch | artifact | work_result | outcome_delta | finding |
      delivery_bundle | service_result | worker_result
    required_receipts:
      - execution
      - validation
  constraints:
    deadline: optional
    max_budget: optional
    human_approval: optional
  training_spec_ref: optional
  domain_ontology_ref: optional
  data_recipe_refs: []
  policy_bound_data_view_refs: []
  evaluation_dataset_refs: []
  benchmark_profile_ref: optional
  sparse_worker_category: optional
  evaluation_rubric_ref: optional
  contribution_policy_ref: optional
  primitive_capabilities_required:
    - prim:model.invoke
  authority_scopes_required:
    - scope:model.invoke.external
  created_at: timestamp
```

## RunEnvelope

```yaml
RunEnvelope:
  run_id: run://...
  task_id: task://...
  institutional_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  goal_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  participant_lease_ref: participant-lease://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: hash | null
  task_offer_and_acceptance_refs:
    - packet://...
  work_claim_ref: work-claim://... | null
  room_admission: RoomAdmittedObjectBase | null
  attempt_ref: attempt://... | null
  runtime_id: runtime://...
  worker_id: optional
  worker_instance_id: optional
  service_id: optional
  subscription_ref: optional
  state: queued | assigned | starting | running | sleeping | waiting | throttled | degraded | preempted | awaiting_approval | paused | quarantined | completed | failed | cancelled
  assignment:
    node_id: node://...
    placement_reason: string
    privacy_mode: mutual_blind | enterprise_secure | local | hosted
  event_stream: /v1/runs/{run_id}/events
  artifacts_endpoint: /v1/runs/{run_id}/artifacts
  receipts_endpoint: /v1/runs/{run_id}/receipts
  trace_endpoint: /v1/runs/{run_id}/trace
  inspect_endpoint: /v1/runs/{run_id}/inspect
  scorecard_endpoint: /v1/runs/{run_id}/scorecard
  stop_condition: optional
  resource_allocation_refs:
    - allocation://...
  budget_refs:
    - budget://...
  task_state_ref: optional
  agentgres_projection_watermark: optional
```

## ResourceAllocationDecisionEnvelope

```yaml
ResourceAllocationDecisionEnvelope:
  allocation_decision_id: allocation://...
  allocation_request_ref: allocation://...
  workload_kind:
    session | work_run | automation | scheduled_job | training_pipeline |
    eval | managed_worker | model_route | outcome_room | frontier_claim |
    verification | replication | release_job | connector_job
  workload_refs:
    - session://... | work_run://... | trainpipe://... | worker://... |
      outcome-room://... | frontier://... | work-claim://... | attempt://...
  resource_offer_refs:
    - resource-offer://... | capability-offer://...
  resource_pool_refs:
    - resource_pool://...
  budget_refs:
    - budget://...
  quota_refs:
    - quota://...
  fairness_and_backpressure_policy_refs:
    - policy://...
  priority_class:
    safety_critical | user_blocking | deadline | interactive |
    production | standard | background | speculative
  decision:
    admit | queue | throttle | degrade | preempt | pause | defer |
    cancel | shift_provider | request_budget | fail_closed
  reason_code:
    capacity_available | capacity_exhausted | budget_warning |
    budget_exhausted | quota_exhausted | rate_limited |
    deadline_priority | safety_priority | policy_denied |
    privacy_or_residency_block | provider_unhealthy |
    verified_work_low_value | duplicate_catchup | unfair_share |
    verification_bottleneck | marginal_value_stop
  affected_workload_refs:
    - work_run://... | trainpipe://... | worker://...
  preempted_workload_refs:
    - work_run://...
  preserved_checkpoint_refs:
    - artifact://... | receipt://...
  lost_or_discarded_refs:
    - artifact://...
  retry_or_resume_policy_ref: optional policy://...
  catchup_policy_ref: optional schedule://...
  authority_requirement_refs:
    - authority://... | policy://...
  authority_grant_refs:
    - grant://... | lease://... | authority://...
  cost_delta_ref: optional ledger://...
  expected_verified_work_delta_ref: optional artifact://... | receipt://...
  receipt_refs:
    - receipt://...
  status: proposed | admitted | blocked | executed | superseded | failed
```
