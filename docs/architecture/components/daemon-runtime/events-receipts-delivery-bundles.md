# Events, Receipts, and Delivery Bundles

Status: canonical low-level reference.
Canonical owner: this file for runtime events, receipts, delivery bundles, trace bundles, and quality records.
Supersedes: overlapping event/receipt examples in plans/specs when event, trace, or receipt fields conflict.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (receipts/events live across built planes; OutcomeRoom/collective-pursuit receipt families, physical segment commitments, and delivery-bundle settlement planned)
Last implementation audit: 2026-07-05

## Purpose

Events enable observation; receipts bind attributable boundary facts; replay
enables inspection; evidence, verification, acceptance, adjudication, and
settlement add progressively stronger claims. Delivery bundles carry the
evidence required for marketplace acceptance and settlement. These objects
must be consistent across Hypervisor clients/application surfaces, Hypervisor
Daemon, Agentgres, ioi.ai, aiagent.xyz, sas.xyz, and wallet.network.

## Assurance Ladder

The phrase "receipts prove" is valid only for the boundary fact a receipt
actually binds. A receipt may establish that a request was admitted, a policy
hash was evaluated, a named signer emitted an observation, a runtime reported
an effect, or an artifact hash was produced. It does not by itself establish
that an external-world effect occurred, an output is correct, one contribution
caused the outcome, or the work is economically valuable.

All product, reputation, contribution, and settlement projections must preserve
this ladder rather than collapsing it into one `verified` boolean:

```text
receipt / attestation
  authenticated statement about one declared boundary fact

evidence bundle
  provenance-bearing support for a claim

verification
  a declared verifier evaluated the claim under a named rule and version

acceptance
  a user, customer, domain, or counterparty accepted the outcome

adjudication
  a challenge or dispute was resolved under a declared policy

settlement
  rights or value moved under an accepted or adjudicated claim
```

Cryptography makes work claims attributable and challengeable. Correctness,
causality, demand, scarcity, quality, and economic value still require evidence,
evaluation, acceptance, and—when contested—adjudication.

## Receipt Registry And Schema Ownership

This file governs the common `ReceiptEnvelope` base and owns the receipt-type
registry, cross-component receipt schemas, lifecycle, and assurance semantics (INV-9,
[`../../foundations/invariants.md`](../../foundations/invariants.md)). Every new
receipt type registers here before another owner relies on it.

A component or domain owner may define a named specialized receipt profile only
when its subject ownership is explicit in the source-of-truth map. Such a
profile extends the shared envelope; it may add domain facts but must not
redefine receipt identity, assurance stages, policy/authority binding,
Agentgres admission, or the meaning of proof. When an excerpt elsewhere
disagrees with a schema defined here, this file wins and the excerpt must be
replaced by a link. New cross-component profiles belong here rather than in
multiple domain docs.

Work analytics, tool analytics, feedback annotations, and rollout observations
are observation/improvement signals. They may inform Foundry evals, routing,
release controls, support queues, and capability-improvement proposals, but they
do not replace receipts, state roots, policy decisions, or wallet authority.
When promoted into training or evaluation material, they must pass through
policy-bound data views, Data Recipes, and Agentgres refs.

Trace bundles are the inspection projection over events, logs, receipts,
artifacts, authority decisions, and proof refs. A trace bundle should support
grouping by user turn, run segment, workflow node, workrun, or automation step;
waterfall-style spans for model, tool, connector, MCP, browser, terminal,
environment, authority, eval, package, and settlement activity; detail views for
event, request, response, graph, logs, authority, receipts, proof, settlement,
and artifacts; and redacted export for private work.

Trace inspection is not settlement truth. Raw transaction hashes, contract refs,
chain IDs, bridge refs, gas details, or public commitment metadata belong in
proof/settlement drilldowns, developer views, dispute/governance views, or
exported evidence bundles. Normal run inspection should lead with work events,
human-readable proof state, receipts, and replay availability.

Product surfaces should preserve a clear distinction:

```text
Run Replay
  temporal inspection of what happened: turns, spans, tools, models,
  connectors, browser/computer-use actions, logs, artifacts, approvals,
  errors, retries, and replayable context

Proof / Settlement Explorer
  evidence inspection of what can be verified: receipts, state roots,
  commitment refs, transaction hashes, contract refs, dispute refs,
  governance refs, bridge refs, delivery bundles, contribution receipts,
  and exported proof packages
```

Run Replay may link into proof/settlement drilldowns, but it should not force
normal operators to read raw chain or settlement details to understand whether a
run succeeded. Proof / Settlement Explorer may expose low-level commitments, but
it should not become the only way to inspect ordinary runtime behavior.

The Hypervisor Daemon emits these objects as the autonomous-execution
hypervisor/control plane. Hypervisor App, Hypervisor Web, CLI/headless,
optional TUI, SDK, ADK, Workbench/Foundry surfaces, other Applications
surfaces, Environments views, harnesses, benchmarks, and
extension-host code may project or inspect them, but they must not mint private
runtime truth for consequential work.

## Runtime Events

Required event kinds:

```text
session.started
thread.created
thread.resumed
thread.forked
thread.mode_changed
thread.model_route_changed
thread.reasoning_changed
turn.started
turn.interrupted
turn.steered
context.prepared
context.compacted
context.budget_updated
context.pressure_delta
context.pressure_alert
task_state.updated
uncertainty.assessed
probe.started
probe.completed
postconditions.synthesized
semantic_impact.analyzed
model.requested
model.token
model.completed
tool.proposed
tool.validated
policy.decided
authority.decided
approval.requested
tool.started
tool.progress
tool.completed
artifact.created
memory.retrieved
memory.validated
memory.updated
mcp.server_validated
mcp.server_imported
mcp.tool_invoked
mcp.gateway_profile_registered
mcp.gateway_profile_used
mcp.gateway_profile_quarantined
mcp.gateway_profile_revoked
authority_client.registered
authority_client.used
authority_client.denied
authority_client.revoked
authority_client.rotated
authority_client.quarantined
revocation.epoch_advanced
revocation.blast_radius_reported
tool.missing_capability_requested
tool.analytics_recorded
delegation.started
delegation.completed
subagent.spawned
subagent.input_sent
subagent.assigned
subagent.cancelled
subagent.completed
handoff.recorded
aiip.channel.opened
aiip.channel.closed
aiip.channel.disputed
aiip.packet.sent
aiip.packet.received
aiip.packet.rejected
aiip.delivery_update.recorded
aiip.acceptance_decision.recorded
aiip.dispute.opened
aiip.dispute.resolved
aiip.settlement_intent.recorded
stop_condition.recorded
scorecard.updated
feedback.recorded
annotation.recorded
rollout.exposure_recorded
rollout.adjudicated
capability.lifecycle_proposed
capability.lifecycle_gate_evaluated
capability.lifecycle_transitioned
capability.rollback_requested
capability.recall_issued
capability.regression_detected
capability.regression_adjudicated
usage.delta
usage.final
resource.allocation_requested
resource.allocation_decided
resource.budget_warning
resource.budget_exhausted
resource.preemption_decided
resource.degradation_applied
scheduler.catchup_planned
scheduler.catchup_executed
assurance.policy_pack.applied
assurance.policy_pack.blocked
assurance.audit_export.requested
assurance.audit_export.generated
assurance.audit_export.delivered
assurance.audit_export.revoked
collaboration.context_created
collaboration.party_joined
collaboration.party_removed
collaboration.view_granted
collaboration.view_revoked
collaboration.proof_bundle_generated
outcome_room.created
outcome_room.opened
outcome_room.paused
outcome_room.closed
outcome_room.discovery_published
outcome_room.discovery_paused
outcome_room.discovery_withdrawn
outcome_room.coordination_policy_changed
outcome_room.frontier_item_created
outcome_room.frontier_item_updated
outcome_room.participant_join_requested
outcome_room.participant_admitted
outcome_room.participant_rejected
outcome_room.participant_request_withdrawn
outcome_room.participant_sleeping
outcome_room.participant_quarantined
outcome_room.participant_retired
outcome_room.participant_state_prepared
outcome_room.participant_state_exported
outcome_room.participant_state_acknowledged
outcome_room.participant_state_superseded
outcome_room.participant_state_revoked
outcome_room.work_claim_issued
outcome_room.work_claim_released
outcome_room.work_claim_expired
outcome_room.resource_offered
outcome_room.resource_allocated
outcome_room.attempt_submitted
outcome_room.attempt_admitted
outcome_room.finding_proposed
outcome_room.finding_admitted
outcome_room.verifier_challenge_opened
outcome_room.verifier_rule_changed
outcome_room.reverification_started
outcome_room.outcome_delta_admitted
outcome_room.frontier_course_corrected
workspace_trust.warning
workspace_trust.acknowledged
workspace_snapshot.created
workspace_restore.previewed
workspace_restore.applied
environment.failure_detected
environment.recovery_planned
environment.recovery_started
environment.recovery_completed
environment.recovery_failed
workrun.recovery_reconciled
diagnostics.injected
diagnostics.repair_decision_recorded
diagnostics.repair_executed
job.queued
job.started
job.completed
job.failed
job.cancelled
module.invocation_proposed
module.invocation_started
module.invocation_completed
module.invocation_committed
upgrade.proposal_submitted
upgrade.proposal_approved
upgrade.proposal_rejected
upgrade.proposal_committed
local_settlement.committed
ontology.bound
ontology_projection.updated
data_recipe.run_started
data_recipe.run_completed
transformation.receipt_emitted
evaluation_dataset.bound
training.spec_bound
training.evidence_eligibility_recorded
training.dataset_factory_started
training.dataset_factory_completed
training.batch_planned
training.generation_batch_archived
training.quality_gates_reported
training.cost_ledger_updated
training.dataset_curated
training.context_mutated
training.pipeline_started
training.pipeline_stage_advanced
training.pipeline_suspended
training.pipeline_resumed
training.pipeline_completed
training.pipeline_failed
training.experiment_trial_started
training.experiment_trial_completed
training.experiment_trial_accepted
training.experiment_trial_rejected
training.artifact_conversion_started
training.artifact_conversion_validated
training.model_registered
training.conductor_advisor_candidate_created
training.conductor_advisor_shadow_started
training.conductor_advisor_promoted
training.post_training_cycle_started
training.post_training_cycle_promoted
training.post_training_cycle_rejected
training.post_training_cycle_rolled_back
training.run_started
training.run_completed
evaluation.started
evaluation.completed
benchmark.started
benchmark.completed
routing.candidate_set_committed
routing.decision_recorded
hypervisoros.boot.started
hypervisoros.boot.measured
hypervisoros.boot.failed
hypervisoros.node.ready
hypervisoros.node.quarantined
hypervisoros.workload.blocked
hypervisoros.egress.blocked
embodied.domain.registered
embodied.fleet.registered
embodied.unit.bound
embodied.controller.bound
embodied.heartbeat.recorded
embodied.failsafe.triggered
embodied.sensor.registered
embodied.actuator.registered
embodied.world_model.updated
embodied.environment_state.updated
embodied.command.proposed
embodied.command.queued
embodied.command.started
embodied.command.paused
embodied.command.cancelled
embodied.command.retried
embodied.command.interrupted
embodied.command.completed
embodied.command.failed
embodied.telemetry.frame_recorded
embodied.replay.bundle_created
embodied.operator_handoff.requested
embodied.operator_handoff.accepted
embodied.operator_handoff.declined
embodied.operator_handoff.timed_out
embodied.operator_handoff.completed
embodied.incident.opened
embodied.incident.contained
embodied.incident.closed
embodied.recovery.started
embodied.recovery.completed
sim_to_real.gate_created
sim_to_real.shadow_started
sim_to_real.limited_live_started
sim_to_real.promoted
sim_to_real.rolled_back
receipt.emitted
run.completed
run.failed
run.cancelled
```

## Event Shape

```json
{
  "event_id": "evt_123",
  "parent_event_id": "evt_122",
  "run_id": "run_123",
  "task_id": "task_123",
  "kind": "tool.completed",
  "timestamp": "2026-05-01T00:00:00Z",
  "cursor": 42,
  "actor_id": "runtime://node_abc",
  "privacy_class": "internal",
  "redaction_status": "redacted",
  "payload": {},
  "receipt_ref": "receipt://tool_123",
  "terminal": false
}
```

## Receipt Types

```text
PolicyDecisionReceipt
ApprovalReceipt
ModelInvocationReceipt
ToolExecutionReceipt
ModuleInvocationReceipt
ArtifactReceipt
ArtifactAvailabilityReceipt
ArtifactRepairReceipt
ValidationReceipt
MergeReceipt
SettlementReceipt
LocalSettlementReceipt
DeliveryReceipt
AIIPPacketReceipt
AIIPDeliveryUpdateReceipt
AIIPAcceptanceDecisionReceipt
AIIPDisputeResolutionReceipt
AIIPSettlementIntentReceipt
CrossDomainDeliveryBundleReceipt
ContributionReceipt
QualityReceipt
DataRecipeRunReceipt
TransformationReceipt
DatasetDistillationReceipt
OntologyProjectionReceipt
TrainingEvidenceEligibilityReceipt
UpgradeProposalReceipt
UpgradeDecisionReceipt
FoundrySpecReceipt
DatasetSnapshotReceipt
FoundryRunPlanReceipt
DatasetFactoryRunReceipt
TrainingPipelineRunReceipt
TrainingTraceReceipt
TrainingBatchPlanReceipt
GenerationBatchReceipt
TeacherSessionReceipt
CandidateTrainingSignalReceipt
OnPolicyCorrectionReceipt
QualityGateReportReceipt
TrainingCostLedgerReceipt
TrainingTrialReceipt
TrainingCheckpointReceipt
DatasetCurationReceipt
ExperimentOptimizationCycleReceipt
ArtifactConversionReceipt
ModelArtifactReceipt
PackageArtifactReceipt
ModelRegistrationReceipt
RegistryVersionReceipt
RouteBindingReceipt
FoundryPromotionBundleReceipt
ConductorAdvisorCandidateReceipt
ContextMutationReceipt
PostTrainingCycleReceipt
PromotionDecisionReceipt
CapabilityRegressionReceipt
CapabilityLifecycleTransitionReceipt
EnvironmentFailureReceipt
EnvironmentRecoveryReceipt
WorkRunRecoveryReceipt
ResourceAllocationReceipt
BudgetExhaustionReceipt
PreemptionReceipt
SchedulerCatchupReceipt
JurisdictionPolicyDecisionReceipt
AssuranceEvidenceBundleReceipt
ComplianceAuditExportBundleReceipt
CommercialAssuranceExportReceipt
MultiPartyCollaborationReceipt
OutcomeRoomAdmissionReceipt
OutcomeRoomDiscoveryPublicationReceipt
RoomParticipationDecisionReceipt
ParticipantStateExportReceipt
RoomParticipantLeaseReceipt
WorkFrontierMutationReceipt
WorkClaimLeaseReceipt
ResourceOfferAllocationReceipt
AttemptAdmissionReceipt
FindingAdmissionReceipt
VerifierChallengeReceipt
WorkResultReceipt
OutcomeDeltaAdmissionReceipt
BenchmarkRunReceipt
EvaluationVerdictReceipt
OrchestrationDecisionReceipt
RoutingDecisionReceipt
AuthorityClientRegistrationReceipt
AuthorityClientUseReceipt
AuthorityClientDenialReceipt
AuthorityClientRevocationReceipt
AuthorityClientRotationReceipt
AuthorityClientQuarantineReceipt
McpGatewayProfileQuarantineReceipt
BlastRadiusReportReceipt
RuntimeAttestationReceipt
RuntimeBridgeReceipt
RuntimeUsageReceipt
HypervisorOSBootReceipt
NodeMeasurementReceipt
EmbodiedRuntimeDomainReceipt
RobotFleetRegistrationReceipt
ControllerBindingReceipt
HeartbeatReceipt
FailsafeReceipt
WorldModelReceipt
CalibrationReceipt
PhysicalCommandQueueReceipt
PhysicalCommandReceipt
PhysicalActionPreflightReceipt
PhysicalActionSegmentCommitmentReceipt
SensorEvidenceReceipt
ActuatorCommandReceipt
EmergencyStopReceipt
PhysicalActionExecutionReceipt
PhysicalActionIncidentReceipt
PhysicalActionRemediationReceipt
PhysicalTelemetryReceipt
PhysicalReplayReceipt
SimToRealPromotionReceipt
OperatorHandoffReceipt
EmbodiedIncidentReceipt
EmbodiedRecoveryReceipt
LiabilityClaimRouteReceipt
QuarantineAdvisoryReceipt
ModelMountReceipt
PrivateInferenceReceipt
CounterfactualLatticeReceipt
PrivateOperatorReceipt
DeclassificationReceipt
CapabilityExitReceipt
DeterrenceDetectionReceipt
CanaryTripReceipt
ContextBudgetReceipt
MemoryMutationReceipt
McpInvocationReceipt
SubagentReceipt
WorkspaceTrustReceipt
WorkspaceSnapshotReceipt
WorkspaceRestoreReceipt
DiagnosticsRepairReceipt
JobReceipt
```

## AIIP And Cross-Domain Service Receipts

AIIP receipts bind cross-domain service handoffs without copying remote domain
state into local Agentgres as truth. `AIIPPacketReceipt` records an admitted
packet and its envelope hash. `AIIPDeliveryUpdateReceipt` records milestone,
partial, final, revision, or cancellation updates with artifact, evidence, and
receipt roots. `AIIPAcceptanceDecisionReceipt` records accept, partial accept,
reject, revision request, or dispute-open decisions. `AIIPDisputeResolutionReceipt`
records refund, partial refund, payout, partial payout, slash, retry, revision,
escalation, or no-fault outcomes. `AIIPSettlementIntentReceipt` records the
conditions proposed for IOI L1 or local settlement. `CrossDomainDeliveryBundleReceipt`
binds local and remote receipt roots, evidence refs, delivery updates,
acceptance decisions, dispute refs, and settlement intent refs into an
exportable proof bundle.

## Model Invocation And Invoice-Reconciled Usage Receipts

Managed model and runtime charging must be reconstructable from route-attempt
receipts and reconciled supplier statements. A flat charge per model-backed
receipt is a development projection, not invoice-grade Work Credit truth.

```json
{
  "receipt_id": "receipt://model_invocation_123",
  "receipt_type": "model_invocation | runtime_usage",
  "invocation_ref": "invocation://123",
  "goal_ref": "goal://123",
  "outcome_room_ref": "outcome-room://123 | null",
  "attempt_ref": "attempt://123 | null",
  "worker_ref": "worker://planner",
  "harness_ref": "harness_profile:default | null",
  "runtime_node_ref": "node://123",
  "route_attempt_id": "route-attempt://123",
  "fallback_chain_ref": "route-chain://123",
  "route_contract_ref": "model-route-contract://123",
  "goal_execution_policy": "auto | pinned | compare",
  "endpoint_ref": "endpoint://123",
  "provider_ref": "provider://123",
  "model_ref": "model://123",
  "model_version_ref": "registry-version-or-provider-hash",
  "commercial_posture": "direct | aggregator | customer_byok | customer_byoa | self_hosted",
  "price_schedule_ref": "price-schedule://provider/model/2026-07-11",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "privacy_class": "public | internal | confidential | restricted | regulated | safety_critical",
  "policy_hash": "sha256:...",
  "usage": {
    "uncached_input_tokens": 0,
    "cache_write_tokens": 0,
    "cache_read_tokens": 0,
    "visible_output_tokens": 0,
    "reasoning_tokens": 0,
    "tool_result_tokens": 0,
    "image_units": 0,
    "audio_units": 0,
    "accelerator_seconds": 0,
    "runtime_seconds": 0,
    "storage_byte_seconds": 0
  },
  "route_result": "succeeded | failed | cancelled | timed_out | rate_limited | privacy_blocked | policy_blocked",
  "supplier_billing_state": "not_billable | estimated | billed | credited | disputed",
  "estimated_supplier_cost_ref": "cost://estimate-123",
  "finalized_supplier_cost_ref": "cost://invoice-line-123 | null",
  "external_broker_fee_ref": "fee://broker-123 | null",
  "ioi_fee_basis_ref": "fee-basis://managed-execution-v1 | null",
  "ioi_fee_amount_ref": "fee://ioi-123 | null",
  "work_credit_reservation_ref": "work-credit://reservation-123 | null",
  "work_credit_final_debit_ref": "work-credit://debit-123 | null",
  "adjustment_or_refund_refs": [],
  "fallback_or_escalation_reason": "quality_gate_failed | provider_unavailable | price_cap | privacy_policy | user_policy | none",
  "latency_ms": 0,
  "policy_and_authority_refs": [],
  "agentgres_operation_refs": [],
  "assurance_stage": "attested | evidenced | verified | accepted | adjudicated | settled",
  "status": "estimated | finalized | reconciled | adjusted | disputed"
}
```

The receipt ledger must preserve each attempt even when a supplier does not
bill it. Fallbacks require a total cost ceiling, maximum attempt count, privacy
and commercial-rights equivalence, and an explicit reason. A fallback that
changes provider, model, custody, behavior, or supported parameters is a
semantic substitution and must run the applicable verifier/acceptance path.

Direct BYOK, BYOA, local, customer-cloud, and self-hosted routes must not debit
a model-provider cost already borne by the customer. They may still carry
explicit conductor, governed-runtime, connector, storage, assurance, or support
charges when those services were actually supplied.

## Orchestration Decision Receipts

An orchestration receipt records why a conductor selected a plan shape. It is
distinct from `RoutingDecisionReceipt`, which binds Worker/domain/route
selection. It binds the declared policy, constraints, candidates, selected
materialization, evidence basis, and reason codes; it does not prove optimality
or correctness.

```yaml
OrchestrationDecisionReceipt:
  receipt_id: receipt://...
  receipt_type: orchestration_decision
  goal_ref: goal://... | task://...
  conductor_ref: system://... | agent://... | worker://...
  orchestration_policy_ref: orchestration_policy://...
  constraint_envelope_ref: constraint://...
  candidate_plan_refs:
    - orchestration_plan://...
  selected_plan_ref: orchestration_plan://...
  selected_materialization:
    single_path | verifier_backed_single_path | multi_model_answer |
    multi_harness_attempt | cross_session_branch_and_merge |
    collaborative_frontier | independent_replication |
    dynamic_specialist_mesh | open_challenge |
    marketplace_worker_delegation | foundry_job
  selected_model_route_refs:
    - model_route://...
  selected_harness_refs:
    - harness_profile:... | agent_harness_adapter:...
  selected_worker_refs:
    - worker://... | agent://...
  selected_verifier_path_refs:
    - verifier_path://...
  expected_cost_ref: budget://... | null
  expected_latency_class: interactive | batch | background | deadline_bound
  evidence_basis_refs:
    - benchmark://... | receipt://... | ledger://... | gate://...
  fallback_policy_ref: policy://... | null
  reason_codes:
    - quality | cost | privacy | latency | locality | installed_status |
      benchmark_result | authority_fit | user_preference | safety
  agentgres_operation_refs: []
  assurance_stage:
    attested | evidenced | verified | accepted | adjudicated | settled
  receipt_root: hash
  signature: optional
```

## Routing Decision Receipts

`RoutingDecisionEnvelope` owns the candidate and selection record. A
`RoutingDecisionReceipt` binds the declared decision facts when selection can
affect cost, trust, privacy, attribution, reputation, settlement, or dispute.

```yaml
RoutingDecisionReceipt:
  receipt_id: receipt://...
  receipt_type: routing_decision
  routing_decision_ref: routing-decision://...
  routing_decision_hash: sha256:...
  goal_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  task_ref: task://... | null
  router_ref: worker://... | runtime://... | system://... | domain://...
  intent_hash: sha256:...
  candidate_set_commitment: sha256:...
  candidate_affiliation_commitment: sha256:...
  candidate_affiliation_and_ownership_evidence_refs:
    - evidence://... | receipt://... | org://... | provider://...
  routing_policy_hash: sha256:...
  selected_domain_or_worker_ref:
    system://... | domain://... | worker://... | service://... | runtime://...
  selected_worker_composition_ref: package://... | ai://... | worker://... | null
  selected_model_provider_runtime_refs:
    - model://... | model_route://... | provider://... | runtime://... |
      node://... | model-route-contract://...
  authority_scope_refs: []
  cost_bound_ref: cost://... | budget://... | quote://... | null
  reason_codes:
    - quality | cost | privacy | latency | locality | installed_status |
      benchmark_result | authority_fit | user_preference | safety |
      independence | affiliation | seed_supply | fallback_availability
  attempted_route_refs:
    - route-attempt://... | route-chain://...
  actual_attempt_refs:
    - route-attempt://... | attempt://... | work-result://... | receipt://...
  fallback_or_escalation_refs:
    - route-chain://... | route-attempt://... | decision://... | receipt://...
  verifier_escalation_refs:
    - verifier_path://... | verifier-challenge://... | worker://... |
      decision://... | receipt://...
  contributor_scope: my_workers | organization | network_open
  contribution_policy_ref: policy://... | null
  seed_supply_and_independence_evidence_refs:
    - evidence://... | receipt://... | benchmark://... | certification_claim://...
  receipt_obligations: []
  agentgres_operation_refs: []
  assurance_stage:
    attested | evidenced | verified | accepted | adjudicated | settled
```

The affiliation commitment must make first-party control, shared operators,
shared verifiers, and material provider dependencies inspectable. A receipt
does not make candidate independence, route quality, or neutrality true by
assertion; those remain evidence and verification claims.

## Contribution Receipts

`ContributionEnvelope` owns the durable contribution record. The receipt binds
the contributor, work lineage, evidence, assurance, and proposed economic
effect without turning attribution into automatic correctness or payout.

```yaml
ContributionReceipt:
  receipt_id: receipt://...
  receipt_type: contribution
  contribution_ref: contrib_...
  contributor_ref:
    worker://... | service://... | publisher://... | tool://... |
    org://... | domain://...
  contributor_role:
    worker | service | publisher | tool | verifier | reviewer |
    resource_provider | semantic_mapper | organization
  operator_ref: org://... | user://... | domain://... | null
  affiliation_refs: []
  contributor_version_ref: registry_version://... | package://... | null
  model_and_route_attribution_refs:
    - model://... | model_route://... | provider://... | runtime://...
  goal_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  task_ref: task://... | null
  run_ref: run://... | null
  attempt_refs:
    - attempt://...
  work_result_refs:
    - work-result://...
  outcome_delta_refs:
    - outcome-delta://...
  contribution_kind:
    planning | execution | generation | worker_invocation | service_delivery |
    tool_use | model_use | dataset_use | workflow_use | resource_provision |
    debugging | review | verification | replication | negative_result |
    integrity_report | semantic_mapping | verifier_hardening | curation |
    synthesis | training_data | distilled_training_data | training_service |
    benchmark_submission | routing_selection | verifier_signal
  routing_decision_ref: routing-decision://... | null
  sparse_worker_category_ref: category://... | null
  benchmark_profile_ref: benchmark://... | null
  downstream_outcome_ref: outcome://... | null
  parent_contribution_refs: []
  evidence_bundle_refs: []
  verifier_refs: []
  verifier_rule_version_refs: []
  acceptance_ref: acceptance://... | null
  adjudication_ref: decision://... | null
  assurance_stage:
    attested | evidenced | verified | accepted | adjudicated | settled
  dispute_status: none | pending | upheld | rejected | no_fault
  input_refs: []
  output_refs: []
  quality_delta_claim: number | null
  uncertainty: number | string | null
  applicability: string | null
  license_policy_refs: []
  reward_basis_ref: order://... | budget://... | policy://... | null
  settlement_ref: settlement-intent://... | settlement://... | null
  agentgres_operation_refs: []
  receipt_hash: sha256:...
```

Model use may be attributed through `model_and_route_attribution_refs`, but a
model endpoint is not the accountable contributor actor. Negative,
inconclusive, reproduction, debugging, review, resource, and integrity work can
be creditable when its marginal value is bound to durable lineage. Settlement
must consume the required assurance stage rather than raw activity or tokens.

## Private Workspace cTEE Receipts

Private Workspace cTEE nodes and private-strategy flows use ordinary receipt
semantics with stricter privacy fields. These receipts bind declared facts
about what was measured, mounted, computed, revealed, denied, detected, or
signed without making the
protected workspace payload public. Candidate-Lattice Private Decoding is the default
protected-agency execution strategy: receipts bind the candidate lattice,
private-head decision, leakage profile, and declassification/action outcome.

`ModelMountReceipt` is emitted before private workspace model invocation. It
binds the plaintext-free model mount view: public/redacted context hashes,
encrypted refs, private handles, forbidden plaintext classes, and the
deterrence/detection profile.

```json
{
  "receipt_id": "receipt://model_mount_123",
  "receipt_type": "model_mount",
  "mount_id": "model_mount://123",
  "view_id": "model_mount_view://123",
  "run_id": "run_123",
  "node_id": "runtime_node_3090",
  "model_route_ref": "model_route://...",
  "visible_context_hash": "sha256:...",
  "redacted_projection_refs": ["projection://..."],
  "encrypted_ref_commitments": ["commitment://..."],
  "private_handle_refs": ["alpha_seal://...", "capability_exit://..."],
  "forbidden_plaintext_classes": ["pii", "strategy_source", "broker_credentials"],
  "plaintext_sensitive_classes_on_node": ["none"],
  "deterrence_detection_profile_ref": "deterrence://...",
  "policy_hash": "sha256:...",
  "status": "accepted | rejected"
}
```

```json
{
  "receipt_id": "receipt://private_inference_123",
  "receipt_type": "private_inference",
  "run_id": "run_123",
  "node_id": "runtime_node_3090",
  "capsule_id": "shielded_capsule://123",
  "alpha_seal_ref": "alpha_seal://123",
  "input_commitment": "sha256:...",
  "output_commitment": "sha256:...",
  "leakage_profile_ref": "leakage://...",
  "operator_hash": "sha256:...",
  "execution_strategy": "candidate_lattice_private_decoding",
  "candidate_lattice_commitment": "commitment://...",
  "selection_policy": "selected_one | top_m | denial_only | masked_score",
  "selection_bits_bound": 0,
  "timing_bucket_bits_bound": 0,
  "size_bucket_bits_bound": 0,
  "cumulative_leakage_budget_after": 0,
  "mitigation_refs": ["padding_policy://...", "decoy_policy://..."],
  "plaintext_sensitive_classes_on_node": ["none"],
  "model_mount_receipt_ref": "receipt://model_mount_123",
  "artifact_refs": ["artifact://protected-output"],
  "status": "success | failure | blocked | invalid"
}
```

`PrivateOperatorReceipt` is emitted when a protected subcomputation is routed
through the cTEE Cryptographic Operator Plane. It binds the operator family,
protected input commitments, second logical party, leakage profile, and proof
that no protected plaintext class was materialized on the provider-rooted node.

`CounterfactualLatticeReceipt` is emitted when the node expands a committed
candidate lattice before private selection feedback. It supports claims that
online branch-selection leakage was suppressed for that lattice round, while
still accounting for public token volume, lattice metadata, timing, size, and
schedule leakage.

```json
{
  "receipt_id": "receipt://counterfactual_lattice_123",
  "receipt_type": "counterfactual_lattice",
  "capsule_id": "private_workspace_capsule://123",
  "lattice_commitment": "commitment://...",
  "model_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "width_budget_k": 8,
  "depth_budget_d": 4,
  "public_token_budget": 4096,
  "generation_rule_hash": "sha256:...",
  "dedupe_rule_hash": "sha256:...",
  "padding_rule_hash": "sha256:...",
  "node_ref": "runtime_node_3090",
  "state_root": "sha256:..."
}
```

```json
{
  "receipt_id": "receipt://private_operator_123",
  "receipt_type": "private_operator",
  "policy_ref": "crypto_op_policy://123",
  "run_id": "run_123",
  "capsule_id": "shielded_capsule://123",
  "operator_family": "fhe_linear | fhe_approx | mpc_nonlinear | garbled_boolean | oram_lookup | local_guardian | threshold_guardian",
  "node_ref": "runtime_node_3090",
  "second_party_ref": "browser_session://... | mobile_guardian://... | cli_signer://... | wallet.network://... | threshold_guardian://...",
  "protected_input_commitments": ["commitment://..."],
  "public_input_refs": ["artifact://..."],
  "output_commitment": "commitment://...",
  "leakage_profile_ref": "leakage://...",
  "policy_hash": "sha256:...",
  "plaintext_sensitive_classes_on_node": ["none"],
  "status": "success | failure | denied | escalated"
}
```

```json
{
  "receipt_id": "receipt://declassification_123",
  "receipt_type": "declassification",
  "protected_output_ref": "artifact://protected-output",
  "authority_grant_id": "grant_123",
  "guardian_ref": "guardian://...",
  "policy_hash": "sha256:...",
  "decision": "reveal_to_user | reveal_to_third_party | execute_capability | deny | escalate",
  "disclosed_classes": ["redacted | pii | strategy_summary | order_intent | none"],
  "capability_exit_ref": "capability_exit://...",
  "status": "success | denied | escalated"
}
```

## Artifact Availability And Repair Receipts

`ArtifactAvailabilityReceipt` records the detection or observation that an
artifact payload, payload ref, archive payload, replica, storage lease, or
decryptability check no longer satisfies the Agentgres artifact lifecycle
policy. `ArtifactRepairReceipt` records an attempted or completed repair. These
receipts do not make storage backends authoritative; they bind backend evidence
to Agentgres operations.

```json
{
  "receipt_id": "receipt://artifact_availability_123",
  "receipt_type": "artifact_availability",
  "incident_id": "artifact_incident://123",
  "artifact_ref": "artifact://123",
  "payload_ref": "payload://123",
  "archive_ref": "archive://123",
  "failure_kind": "missing | unavailable | invalid_hash | invalid_cid | decrypt_failed | stale_replica | backend_timeout | retention_expired | lease_expired | policy_violation",
  "expected_commitment": "sha256:...",
  "observed_commitment": "sha256:... | null",
  "backend_refs": ["storage://filecoin/..."],
  "policy_hash": "sha256:...",
  "agentgres_operation_ref": "agentgres://operation/...",
  "status": "open | quarantined | escalated"
}
```

```json
{
  "receipt_id": "receipt://artifact_repair_123",
  "receipt_type": "artifact_repair",
  "incident_id": "artifact_incident://123",
  "artifact_ref": "artifact://123",
  "repair_action": "replica_fetch | backend_fallback | deal_renewal | rehydrate_from_archive | replacement_payload | mark_unrecoverable",
  "source_backend_refs": ["storage://..."],
  "replacement_payload_refs": ["artifact://..."],
  "verified_commitments": ["sha256:...", "bafy..."],
  "decryptability_checked": true,
  "restore_validity_checked": true,
  "policy_hash": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "repair_attempted | repaired | unrecoverable | denied"
}
```

`NodeMeasurementReceipt` is integrity/accounting evidence. It is not, by
itself, a consumer-GPU plaintext privacy guarantee.

`HypervisorOSBootReceipt` binds boot epoch, boot profile, image hash, daemon
binary hash, package/driver manifest hashes, measurement method, and declared
privacy claim. It proves node integrity posture, not protected plaintext
privacy by itself.

## Environment Failure And Recovery Receipts

`EnvironmentFailureReceipt` records the provider/runtime failure boundary for a
session or WorkRun. `EnvironmentRecoveryReceipt` records the attempted recovery
path, including restore/failover/rebuild material, authority context, WorkRun
reconciliation, and final state. These receipts do not make provider logs,
snapshots, backups, or encrypted archive blobs authoritative by themselves;
they bind provider evidence and recovery execution to Agentgres operations.

```json
{
  "receipt_id": "receipt://environment_failure_123",
  "receipt_type": "environment_failure",
  "incident_ref": "incident://provider-failure/123",
  "session_ref": "session://123",
  "environment_ref": "environment://123",
  "provider_ref": "provider://us-east-gpu-a",
  "work_run_refs": ["work_run://123"],
  "effect_recovery_classes_by_work_run": {
    "work_run://123": "replayable | checkpointable | compensatable | reconciliation_required | non_retryable"
  },
  "failure_kind": "provider_outage | vm_lost | host_unreachable | control_plane_unavailable | storage_unavailable | archive_invalid | snapshot_invalid | backup_invalid | port_unavailable | log_stream_lost | terminal_stream_lost | runner_split_brain | capacity_eviction | credential_revoked | ctee_attestation_regression",
  "provider_evidence_refs": ["provider_event://..."],
  "lifecycle_observation_refs": ["observation://..."],
  "last_admitted_state_root_ref": "state_root://...",
  "latest_receipt_refs": ["receipt://..."],
  "policy_hash": "sha256:...",
  "agentgres_operation_ref": "agentgres://operation/...",
  "status": "open | recovering | failed_closed | recovered | abandoned | escalated"
}
```

```json
{
  "receipt_id": "receipt://environment_recovery_123",
  "receipt_type": "environment_recovery | work_run_recovery",
  "recovery_attempt_ref": "recovery://environment/123",
  "incident_ref": "incident://provider-failure/123",
  "selected_candidate_ref": "recovery://candidate/123",
  "recovery_mode": "restore_snapshot | restore_backup | restore_archive | failover_provider | rebuild_from_recipe | retry_workrun | reconcile_external_effect | compensate_effect | abandon_fail_closed",
  "target_provider_ref": "provider://us-east-gpu-b",
  "restore_material_refs": ["snapshot://...", "archive://..."],
  "restore_validation_refs": ["receipt://restore-validity"],
  "authority_grant_refs": ["grant://..."],
  "cost_estimate_ref": "ledger://...",
  "work_run_reconciliation": {
    "git_worktree_refs": ["git://..."],
    "agentgres_patch_branch_refs": ["patch_branch://..."],
    "preserved_output_refs": ["artifact://..."],
    "lost_material_refs": ["artifact://lost"],
    "retry_work_item_refs": ["work_item://..."],
    "ambiguous_effect_refs": ["effect://..."],
    "external_reconciliation_refs": ["receipt://external-reconciliation"],
    "compensation_refs": ["receipt://compensation"]
  },
  "effect_reconciliation_receipt_refs": ["receipt://external-reconciliation"],
  "compensation_receipt_refs": ["receipt://compensation"],
  "state_root_before_ref": "state_root://before",
  "state_root_after_ref": "state_root://after",
  "policy_hash": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "outcome": "recovered | partially_recovered | failed_closed | abandoned | escalated"
}
```

## Embodied Runtime Receipts

Embodied runtime receipts bind physical-domain runtime state. They complement,
but do not replace, physical-action safety receipts such as
`SensorEvidenceReceipt`, `ActuatorCommandReceipt`, and
`PhysicalActionExecutionReceipt`.

```yaml
SensorEvidenceReceipt:
  receipt_id: receipt://...
  receipt_type: sensor_evidence
  mission_or_intent_ref: mission://... | intent://...
  sensor_refs:
    - sensor://...
  observation_hashes:
    - sha256:...
  artifact_refs:
    - artifact://...
  captured_at: timestamp
  confidence: number | null
  redaction_policy_ref: policy://... | null
  retention_policy_ref: policy://... | null
  agentgres_operation_refs: []
  assurance_stage: attested | evidenced | verified | accepted | adjudicated | settled

ActuatorCommandReceipt:
  receipt_id: receipt://...
  receipt_type: actuator_command
  mission_or_intent_ref: mission://... | intent://...
  command_ref: physical_command://...
  actuator_ref: actuator://...
  command_hash: sha256:...
  issued_by_ref: runtime://... | controller://...
  authority_refs:
    - authority://... | grant://... | scope:*
  safety_envelope_ref: safety://...
  sensor_evidence_receipt_refs:
    - receipt://...
  result: accepted | rejected | executed | stopped | failed | unknown
  result_observation_ref: observation://... | null
  issued_at: timestamp
  agentgres_operation_refs: []

PhysicalActionExecutionReceipt:
  receipt_id: receipt://...
  receipt_type: physical_action_execution
  mission_or_intent_ref: mission://... | intent://...
  segment_commitment_receipt_refs:
    - receipt://...
  preflight_receipt_refs:
    - receipt://...
  sensor_evidence_receipt_refs:
    - receipt://...
  incident_refs:
    - incident://...
  reconciliation_state:
    confirmed | partially_confirmed | ambiguous_effect |
    compensation_required | non_retryable | failed
  acceptance_ref: acceptance://... | null
  adjudication_ref: decision://... | null
  agentgres_operation_refs: []
  assurance_stage: attested | evidenced | verified | accepted | adjudicated | settled
```

```json
{
  "receipt_id": "receipt://embodied_command_123",
  "receipt_type": "physical_command_queue | physical_command | physical_telemetry | physical_replay | controller_binding | heartbeat | failsafe | sim_to_real_promotion | operator_handoff | embodied_incident | embodied_recovery",
  "embodied_domain_ref": "embodied_domain://...",
  "fleet_ref": "robot_fleet://...",
  "unit_ref": "robot://...",
  "controller_binding_ref": "controller-binding://...",
  "command_ref": "physical_command://...",
  "queue_ref": "physical_command_queue://...",
  "world_model_ref": "world_model://...",
  "environment_state_ref": "environment_state://...",
  "telemetry_stream_refs": ["telemetry_stream://..."],
  "sensor_evidence_receipt_refs": ["receipt://..."],
  "actuator_command_receipt_refs": ["receipt://..."],
  "safety_envelope_ref": "safety://...",
  "authority_ref": "grant://...",
  "operator_handoff_ref": "operator_handoff://...",
  "incident_ref": "incident://...",
  "liability_claim_route_ref": "liability_claim_route://...",
  "status": "recorded | admitted | blocked | degraded | stopped | failed"
}
```

High-frequency local control may aggregate routine commands into a
`PhysicalActionSegmentCommitmentReceipt` while exception, emergency-stop, and
incident receipts remain immediate:

```json
{
  "receipt_id": "receipt://physical_segment_123",
  "receipt_type": "physical_action_segment_commitment",
  "local_control_segment_ref": "control-segment://segment-123",
  "mission_or_intent_ref": "mission://mission-7",
  "controller_binding_ref": "controller-binding://robot-a",
  "controller_version_ref": "registry_version://controller/v4",
  "physical_action_policy_ref": "policy://physical-action/v2",
  "safety_envelope_ref": "safety://mission-7",
  "authority_refs": ["authority://...", "grant://..."],
  "started_at": "timestamp",
  "ended_at": "timestamp",
  "command_sequence_root": "sha256:...",
  "sensor_sequence_root": "sha256:...",
  "initial_state_ref": "state://initial",
  "final_state_ref": "state://final",
  "actuator_command_receipt_refs": [],
  "exception_receipt_refs": [],
  "emergency_stop_receipt_ref": null,
  "agentgres_operation_refs": [],
  "result": "completed | clipped | stopped | failed | unknown"
}
```

A segment commitment proves the bound controller, interval, command/sensor
roots, state refs, and reported result. It does not prove physical correctness
or erase ambiguous-effect state; mission acceptance, external reconciliation,
adjudication, and compensation remain separate.

Physical telemetry receipts should commit to stream refs, frame hashes, sequence
windows, redaction status, retention policy, and replay bundle refs. They should
not require raw video, point clouds, or controller logs to be embedded in the
receipt. Payload bytes remain in storage backends; Agentgres records refs,
hashes, projections, replay indexes, and state roots.

`DeterrenceDetectionReceipt` and `CanaryTripReceipt` are attribution and
dispute evidence. They do not make plaintext safe and must not justify unsafe
mounting.

```json
{
  "receipt_id": "receipt://deterrence_123",
  "receipt_type": "deterrence_detection",
  "workspace_id": "workspace://123",
  "node_id": "runtime_node_3090",
  "profile_ref": "deterrence://...",
  "event_type": "canary_planted | watermark_bound | honeytoken_bound | canary_checked | canary_tripped | suspicious_replay_detected | leak_scan_completed",
  "bound_refs": ["model_mount://123", "shielded_capsule://123"],
  "public_evidence_refs": ["artifact://evidence-capture"],
  "private_evidence_commitments": ["commitment://..."],
  "action": "none | warn_user | revoke_node | rotate_keys | open_dispute | slash_provider | quarantine_workspace",
  "policy_hash": "sha256:...",
  "status": "recorded | escalated | disputed"
}
```

## ToolExecutionReceipt

```json
{
  "receipt_id": "receipt://tool_123",
  "receipt_type": "tool_execution",
  "run_id": "run_123",
  "tool_id": "tool://gmail.create_draft",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "authority_grant_id": "grant_123",
  "primitive_capabilities": ["prim:net.request"],
  "authority_scopes": ["scope:gmail.create_draft"],
  "status": "success | failure",
  "started_at": "...",
  "completed_at": "...",
  "artifact_refs": []
}
```

## Authority Client And Gateway Receipts

Authority-client and gateway receipts bind client registration, use, denial,
revocation, rotation, quarantine, and blast-radius decisions without exposing raw
secrets, provider tokens, or private payloads.

```json
{
  "receipt_id": "receipt://authority_client_123",
  "receipt_type": "authority_client_registration | authority_client_use | authority_client_denial | authority_client_revocation | authority_client_rotation | authority_client_quarantine | mcp_gateway_profile_quarantine | blast_radius_report",
  "authority_client_ref": "wallet_client://...",
  "gateway_profile_ref": "mcp_gateway://... | null",
  "origin_binding_ref": "origin://... | null",
  "grant_refs": ["grant://..."],
  "lease_refs": ["lease://..."],
  "connector_refs": ["connector://..."],
  "session_refs": ["session://..."],
  "work_run_refs": ["work_run://..."],
  "policy_hash": "sha256:...",
  "request_hash": "sha256:... | null",
  "revocation_epoch": 8,
  "anomaly_state": "clean | watch | origin_mismatch | expired_use | scope_excess | suspicious_frequency | policy_denied | leaked | compromised",
  "action": "allow | deny | revoke | rotate | quarantine | release",
  "quarantine_advisory_ref": "quarantine_advisory://... | null",
  "replacement_client_ref": "wallet_client://... | null",
  "status": "recorded | blocked | rotated | revoked | quarantined"
}
```

Blast-radius reports must be built from admitted authority-client, gateway,
session, WorkRun, connector, approval, and receipt refs. Untrusted logs may
support investigation, but they are not blast-radius truth by themselves.

## Resource Allocation And Budget Receipts

Resource allocation receipts bind how Hypervisor handled scarce capacity,
budget exhaustion, provider quota, rate limits, and scheduler catch-up. They
make queue and preemption decisions inspectable without treating raw compute
seconds as product success.

```json
{
  "receipt_id": "receipt://resource_allocation_123",
  "receipt_type": "resource_allocation | budget_exhaustion | preemption | scheduler_catchup",
  "allocation_decision_ref": "allocation://decision/123",
  "allocation_request_ref": "allocation://request/123",
  "workload_kind": "session | work_run | automation | scheduled_job | training_pipeline | eval | managed_worker | model_route | outcome_room | frontier_claim | verification | replication | release_job | connector_job",
  "workload_refs": ["work_run://123", "outcome-room://room-1", "work-claim://claim-2", "attempt://attempt-4"],
  "resource_offer_refs": ["resource-offer://gpu-capacity", "capability-offer://verification"],
  "resource_pool_refs": ["resource_pool://gpu/us-east"],
  "budget_refs": ["budget://org/monthly-gpu"],
  "quota_refs": ["quota://provider/gpu"],
  "fairness_and_backpressure_policy_refs": ["policy://room-resource-fairness"],
  "rate_limit_refs": ["rate_limit://model-provider/tpm"],
  "priority_class": "safety_critical | user_blocking | deadline | interactive | production | standard | background | speculative",
  "decision": "admit | queue | throttle | degrade | preempt | pause | defer | cancel | shift_provider | request_budget | fail_closed",
  "reason_code": "capacity_available | capacity_exhausted | budget_warning | budget_exhausted | quota_exhausted | rate_limited | deadline_priority | safety_priority | policy_denied | privacy_or_residency_block | provider_unhealthy | verified_work_low_value | duplicate_catchup | unfair_share | verification_bottleneck | marginal_value_stop",
  "affected_workload_refs": ["work_run://123"],
  "preempted_workload_refs": ["work_run://background-7"],
  "preserved_checkpoint_refs": ["artifact://checkpoint"],
  "lost_or_discarded_refs": ["artifact://discarded-cache"],
  "retry_or_resume_policy_ref": "policy://retry-after-capacity",
  "catchup_policy_ref": "schedule://nightly-coalesce",
  "authority_requirement_refs": ["policy://gpu-spend-limit"],
  "authority_grant_refs": ["grant://gpu-spend"],
  "cost_delta_ref": "ledger://cost-delta",
  "expected_verified_work_delta_ref": "receipt://quality-delta",
  "policy_hash": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "admitted | blocked | executed | superseded | failed"
}
```

Budget exhaustion receipts must be emitted before new external spend or
provider mutation. Scheduler catch-up receipts must name whether missed work was
skipped, coalesced, backfilled, run-latest, gated for approval, or failed
closed. Preemption receipts must name the preserved checkpoint, retry/resume
policy, and user-visible reason.

## Multi-Party Collaboration Receipts

Multi-party collaboration receipts bind the declared parties, roles, authority
refs, restricted views, coordination topology, AIIP handoffs, evidence refs,
delivery refs, contribution refs, settlement refs, and export profiles used for
shared autonomous work. They prove those bound facts, not that all parties were
independent, the outcome was correct, or one party gained authority over
another party's connector, wallet, or protected payload.

```json
{
  "receipt_id": "receipt://multi_party_collaboration_123",
  "receipt_type": "multi_party_collaboration",
  "collaboration_ref": "collaboration://joint-service-outcome-001",
  "outcome_room_ref": "outcome-room://joint-service-outcome-001",
  "goal_ref": "order://123",
  "coordinator_ref": "domain://service-coordinator",
  "coordination_topology": "hosted_admission | federated_admission",
  "coordination_and_ordering_policy_ref": "policy://room-ordering-v1",
  "shared_state_admission_owner_ref": "domain://service-coordinator",
  "party_refs": [
    {
      "party_ref": "org://customer-a",
      "role": "data_owner",
      "domain_ref": "agentgres://domain/customer-a",
      "authority_refs": ["grant://customer-data-read"],
      "status": "active"
    },
    {
      "party_ref": "org://provider-b",
      "role": "worker_provider",
      "domain_ref": "agentgres://domain/provider-b",
      "authority_refs": ["grant://worker-execute"],
      "status": "active"
    },
    {
      "party_ref": "org://auditor",
      "role": "auditor",
      "domain_ref": null,
      "authority_refs": ["policy://auditor-readonly"],
      "status": "observer_only"
    }
  ],
  "allowed_shared_refs": [
    "receipt://execution",
    "restricted_view://auditor-safe",
    "redacted_summary://run-summary",
    "delivery://final"
  ],
  "blocked_context_classes": [
    "raw_secret",
    "protected_plaintext",
    "unauthorized_connector_payload",
    "unrelated_private_memory",
    "non_opted_in_training_trace"
  ],
  "policy_bound_data_view_refs": ["view://customer-a-service-view"],
  "restricted_view_refs": ["restricted_view://auditor-safe"],
  "aiip_channel_refs": ["aiip://channel/customer-provider"],
  "handoff_refs": ["packet://handoff-001"],
  "evidence_bundle_refs": ["evidence://collaboration-proof"],
  "delivery_bundle_refs": ["delivery://final"],
  "contribution_refs": ["receipt://contribution-provider-b"],
  "settlement_intent_refs": ["settlement-intent://payout-provider-b"],
  "audit_export_profile_refs": ["audit_export://auditor-review"],
  "revocation_refs": ["revocation://collaboration/auditor"],
  "history_policy": {
    "party_removal_effect": "no_new_access | revoke_live_access | tombstone_view | rotate_views",
    "historical_receipts": "immutable | sealed | export_limited"
  },
  "l1_anchor_policy": "local_only | optional_anchor | dispute_only | reputation_only | settlement_required | required_public_root",
  "policy_hash": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "created | party_joined | party_removed | view_granted | view_revoked | proof_bundle_generated | archived"
}
```

Several models, workers, nodes, clouds, or provider keys controlled by one
operator remain one party. Receipts must preserve operator, organization,
model-route, runtime-node, infrastructure-provider, verifier, and settlement
affiliations separately so a first-party seed fleet cannot be presented as
independent multi-party verification.

## OutcomeRoom And Collective-Pursuit Receipts

OutcomeRoom receipts make a persistent shared work frontier inspectable without
turning board messages, self-reported results, or participant consensus into
truth. Every participant message, artifact, finding, ontology mapping, verifier
suggestion, and executable result remains untrusted input until the named room
host or federated admission policy admits the relevant state change.

```json
{
  "receipt_id": "receipt://outcome_room_123",
  "receipt_type": "outcome_room_admission | outcome_room_discovery_publication | room_participation_decision | participant_state_export | room_participant_lease | work_frontier_mutation | work_claim_lease | resource_offer_allocation | attempt_admission | finding_admission | verifier_challenge | work_result | outcome_delta_admission",
  "outcome_room_ref": "outcome-room://research-123",
  "coordination_topology": "hosted_admission | federated_admission",
  "admission_owner_or_policy_ref": "domain://room-host | policy://federated-admission-v1",
  "subject_refs": [
    "room-discovery://research-123",
    "participation-request://worker-a",
    "participant-state://worker-a/export-1",
    "participant-lease://worker-a",
    "frontier://question-7",
    "work-claim://claim-9",
    "attempt://attempt-12",
    "finding://finding-4",
    "verifier-challenge://challenge-2",
    "work-result://result-12",
    "outcome-delta://delta-8"
  ],
  "actor_and_affiliation_refs": [
    "worker://worker-a",
    "org://operator-a",
    "domain://operator-a",
    "model_route://route-3",
    "runtime://node-8"
  ],
  "policy_refs": [
    "policy://participation-v1",
    "policy://privacy-v2",
    "policy://contribution-v1",
    "policy://artifact-export-v1"
  ],
  "context_resource_authority_and_budget_lease_refs": [
    "context_lease://lease-3",
    "resource-lease://gpu-2",
    "grant://bounded-tools",
    "budget://goal-123"
  ],
  "evidence_and_artifact_refs": [
    "evidence://bundle-12",
    "artifact://candidate-12"
  ],
  "verifier_rule_version_ref": "rubric://research-v3",
  "predecessor_room_state_root": "sha256:...",
  "resulting_room_state_root": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "proposed | admitted | challenged | superseded | rejected | revoked"
}
```

Receipt-specific obligations:

- `OutcomeRoomAdmissionReceipt` binds room mode, objective, acceptance/stop
  policies, coordination topology, shared-state admission owner, ontology
  profiles, privacy, contribution, artifact/export, verifier, budget, and
  settlement policies.
- `OutcomeRoomDiscoveryPublicationReceipt` binds the public or permissioned
  discovery projection, objective/category, semantic profiles, eligibility,
  privacy/visibility, budget/quote, verifier/settlement posture, publication
  version, expiry, and publish/pause/withdraw decision without exposing private
  room context.
- `RoomParticipationDecisionReceipt` binds the participation request, applicant
  identity/affiliations, eligibility evidence, requested role/capabilities,
  policy/version, admitted/rejected/withdrawn decision, participant lease when
  admitted, and denial reason without transferring ambient authority.
- `ParticipantStateExportReceipt` binds claim release/reassignment, access
  revocation, the policy-filtered portable participant-state bundle, included
  contribution/evidence/receipt/dispute refs, exclusions/redactions, export and
  acknowledgement state, and supersession/revocation. The bundle must remain
  usable without continued access to the hosted room database. Revocation is
  append-only: it may revoke future access or restricted-view keys, or
  supersede an erroneous export, but cannot erase already permitted historical
  contribution, receipt, acceptance, settlement, or dispute lineage.
- `RoomParticipantLeaseReceipt` binds identity/eligibility evidence,
  affiliation and dependency disclosure, visibility, context, resource,
  authority and budget leases, TTL, heartbeat, wake condition, quarantine, and
  revocation.
- `WorkFrontierMutationReceipt` binds the predecessor and resulting frontier,
  dependencies, priority/uncertainty, duplication policy, admission decision,
  and reason for course correction.
- `WorkClaimLeaseReceipt` binds bounded scope, claimant, concurrency,
  independent-replication policy, TTL, heartbeat, release, expiry,
  reassignment, and quarantine.
- `ResourceOfferAllocationReceipt` binds the offered capacity or capability,
  locality/custody, trust, price, eligibility, queue/preemption/fairness policy,
  allocation, spend, and contribution refs.
- `AttemptAdmissionReceipt` preserves method, lineage, environment and version
  refs, outcome class—including negative, inconclusive, invalid, exploit-found,
  or superseded—cost, artifacts, evidence, reproduction, license/export, and
  contribution refs.
- `FindingAdmissionReceipt` preserves proposition, uncertainty, time, source,
  applicability, supporting and contradicting evidence, supersession, dispute,
  and any proposed frontier, ontology, policy, capability, or routing effect.
- `VerifierChallengeReceipt` binds the challenged metric, rule, verifier,
  evidence, eligibility, result, independence, or mapping decision; rule
  versions; adjudicator; affected attempts; and required re-verification.
- `WorkResultReceipt` binds the generic result profile and outcome class. A
  software implementation may additionally bind changed files and tests, but
  research, ontology, incident, service, physical mission, review, and
  evaluation results do not need to masquerade as patches.
- `OutcomeDeltaAdmissionReceipt` binds preconditions, invariants, expected
  effect, verifier/acceptance refs, and the admitted, rejected, superseded, or
  rolled-back change to frontier, finding, ontology, state, capability, policy,
  route prior, or service outcome.

Room replay must reconstruct who joined, what each participant could see and
do, which work was open or claimed, why resources were allocated, all positive
and negative attempts, which findings were admitted or contradicted, verifier
rule changes, affected re-verification, spend, authority, contribution lineage,
and why the room changed direction.

## Compliance Audit Export Receipts

Compliance audit export receipts attest that a customer, auditor, regulator,
counterparty, procurement, tax, SLA, or internal-control export was generated
from admitted refs under a declared policy-pack, retention, restricted-view,
redaction, and authority posture. They are not raw log dumps, screenshot
bundles, or replay bypasses.

```json
{
  "receipt_id": "receipt://compliance_audit_export_123",
  "receipt_type": "jurisdiction_policy_decision | assurance_evidence_bundle | compliance_audit_export_bundle | commercial_assurance_export",
  "audit_export_ref": "audit_export://customer-q2-2026",
  "export_type": "customer_audit | auditor_review | regulator_request | counterparty_dispute | procurement_review | internal_control | tax_report | sla_report | incident_review",
  "audience": "customer | external_auditor | regulator | counterparty | insurer | procurement | internal_auditor | public",
  "subject_refs": ["order://123", "run://456", "service://789"],
  "jurisdiction_policy_pack_refs": ["jurisdiction_policy_pack://us-finance-v1"],
  "policy_decision_refs": ["receipt://policy_decision"],
  "approval_receipt_refs": ["receipt://approval"],
  "denial_receipt_refs": ["receipt://denial"],
  "authority_refs": ["authority://export-grant"],
  "evidence_bundle_refs": ["assurance_evidence://bundle", "evidence://agentgres-bundle"],
  "receipt_refs": ["receipt://execution", "receipt://delivery"],
  "replay_refs": ["replay://redacted-run"],
  "retention_lock_refs": ["retention_lock://legal-hold"],
  "restricted_view_refs": ["restricted_view://auditor-safe"],
  "redaction_profile_ref": "policy://redaction/customer-audit",
  "export_policy_ref": "policy://export/customer-audit",
  "declassification_refs": ["receipt://declassification"],
  "export_manifest_hash": "sha256:...",
  "included_refs": ["receipt://execution"],
  "redacted_refs": ["trace://private-span"],
  "protected_payload_refs": ["artifact://protected-output"],
  "excluded_refs": ["artifact://unrelated-secret"],
  "exclusion_reasons": ["retention_locked | restricted_view | no_export_authority | protected_plaintext | unrelated | expired | policy_blocked"],
  "commercial_refs": {
    "invoice_refs": ["invoice://..."],
    "cost_center_refs": ["cost_center://..."],
    "sla_report_refs": ["sla://..."],
    "tax_export_refs": ["tax://..."],
    "purchase_order_refs": ["procurement://..."]
  },
  "l1_anchor_policy": "local_only | optional_anchor | dispute_only | required_public_root",
  "l1_anchor_refs": ["l1://..."],
  "policy_hash": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "requested | generated | delivered | revoked | superseded | expired"
}
```

Export receipts must make protected payload posture explicit. If an export
cannot include a private artifact, trace span, replay fragment, approval body,
or connector output, the receipt names the excluded ref and reason rather than
pretending the export is complete.

## Worker Training Receipts

Data recipe, transformation, training evidence eligibility, Worker Training,
benchmark, evaluation, ontology projection, and MoW routing receipts are
specialized receipts. They are not new artifact classes and they do not bypass
the normal receipt semantics: canonical input, policy hash, actor identity,
artifact refs, timestamps, and signatures still apply.

```json
{
  "receipt_id": "receipt://recipe_123",
  "receipt_type": "data_recipe_run | transformation | ontology_projection",
  "data_recipe_ref": "recipe://construction/estimate-normalization/v1",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "transformation_run_id": "transform://123",
  "policy_bound_data_view_refs": ["view://customer-estimate-training"],
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "authority_grant_id": "grant://...",
  "artifact_refs": ["artifact://transformation-output"],
  "policy_hash": "sha256:...",
  "status": "accepted | rejected | redacted"
}
```

```json
{
  "receipt_id": "receipt://training_eligibility_123",
  "receipt_type": "training_evidence_eligibility",
  "eligibility_id": "eligibility://...",
  "governance_owner_ref": "project://... | org://... | agentgres://domain/...",
  "subject_refs": ["artifact://...", "receipt://...", "view://..."],
  "intended_use": "conductor_training | worker_training | eval_generation | dataset_distillation | benchmark | simulation | analytics_only",
  "training_data_posture": "never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy",
  "policy_bound_data_view_refs": ["view://..."],
  "data_recipe_refs": ["recipe://..."],
  "local_policy_refs": ["policy://..."],
  "consent_refs": ["grant://...", "policy://..."],
  "wallet_authority_refs": ["grant://...", "lease://..."],
  "authority_requirement_kinds": ["decryption | connector_access | model_provider_key | gpu_spend | provider_trust | publication | export | cross_domain_reuse | none"],
  "provider_trust_posture": "no_provider_plaintext | redacted_api | provider_trust_accepted | private_compute_required | blocked",
  "exclusion_reason": "optional",
  "policy_hash": "sha256:...",
  "admitted_by_ref": "agentgres://operation/...",
  "status": "eligible | excluded | revoked | expired"
}
```

```json
{
  "receipt_id": "receipt://training_123",
  "receipt_type": "dataset_factory_run | training_pipeline_run | training_batch_plan | generation_batch | quality_gate_report | training_cost_ledger | training_trace | dataset_curation | experiment_optimization_cycle | artifact_conversion | model_registration | conductor_advisor_candidate | context_mutation | post_training_cycle | promotion_decision",
  "training_id": "train_123",
  "target_worker_id": "worker://...",
  "run_id": "run_123",
  "dataset_factory_run_id": "run://dataset_factory/...",
  "training_pipeline_run_id": "trainpipe://...",
  "training_evidence_eligibility_refs": ["eligibility://..."],
  "training_data_posture": "synthetic_only | redacted_opt_in | full_private_opt_in | org_policy",
  "optimization_cycle_id": "optcycle://...",
  "conversion_run_id": "conversion://...",
  "registered_model_ref": "model://...",
  "conductor_advisor_candidate_ref": "conductor://...",
  "stage": "optional",
  "pipeline_status": "optional",
  "batch_plan_ref": "batch://...",
  "generation_batch_ref": "batch://...",
  "quality_gate_report_ref": "gate://...",
  "training_cost_ledger_ref": "ledger://...",
  "spend_forecast_ref": "ledger://...",
  "current_burn_ref": "ledger://...",
  "continuation_policy_ref": "policy://...",
  "stop_resume_policy_ref": "policy://...",
  "ontology_refs": ["ontology://..."],
  "data_recipe_refs": ["recipe://..."],
  "evaluation_dataset_refs": ["dataset://..."],
  "dataset_commitment": "sha256:...",
  "privacy_policy_ref": "policy://...",
  "policy_hash": "sha256:...",
  "artifact_refs": ["artifact://dataset"],
  "status": "accepted | rejected | redacted"
}
```

```json
{
  "receipt_id": "receipt://promotion_123",
  "receipt_type": "promotion_decision | capability_lifecycle_transition",
  "cycle_id": "ptc_123",
  "capability_kind": "worker | model_route | agent_harness | tool | mcp_server | connector | automation | service | environment_image | package | domain_app | fleet_policy",
  "worker_id": "worker://...",
  "capability_ref": "worker://...",
  "candidate_ref": "cid://...",
  "baseline_version": "worker://...@1.0.1",
  "candidate_version": "worker://...@1.0.2-candidate",
  "eval_profile_ref": "benchmark://...",
  "regression_receipt_refs": ["receipt://eval_123"],
  "release_target_refs": ["release://..."],
  "gate_receipt_refs": ["receipt://..."],
  "authority_grant_refs": ["grant://..."],
  "decision": "promoted | rejected | rolled_back | paused | recalled | retired",
  "rollback_ref": "optional",
  "recall_ref": "optional",
  "policy_hash": "sha256:..."
}
```

```json
{
  "receipt_id": "receipt://capability_regression_123",
  "receipt_type": "capability_regression",
  "regression_id": "regression://support-worker-canary-001",
  "capability_kind": "worker | model_route | agent_harness | tool | mcp_server | connector | automation | service | environment_image | package | domain_app | fleet_policy",
  "capability_ref": "worker://support-triage@1.0.2",
  "baseline_version_ref": "worker://support-triage@1.0.1",
  "candidate_or_active_version_ref": "worker://support-triage@1.0.2",
  "detected_phase": "offline_eval | shadow | canary | rollout | production | recall_review",
  "regression_class": "quality | safety | privacy | cost | latency | authority | reliability | policy | security | compliance | marketplace_reputation",
  "severity": "info | warning | blocking | critical",
  "evidence_refs": ["receipt://eval_123", "artifact://failure-cluster"],
  "scorecard_refs": ["gate://support-scorecard"],
  "affected_scope_refs": ["project://support", "release://support-tier1-canary"],
  "recommended_action": "reject | hold | shadow_more | pause | rollback | recall | constrain | patch_and_retry | require_human_review",
  "adjudication_ref": "receipt://adjudication_123",
  "promotion_decision_ref": "receipt://promotion_123",
  "training_evidence_eligibility_ref": "eligibility://support-regression-001",
  "future_eval_candidate_refs": ["dataset://support-regression-holdout-candidate"],
  "policy_hash": "sha256:...",
  "status": "detected | adjudicating | blocked | rejected | shadowing | paused | rolled_back | recalled | constrained | converted_to_eval | closed"
}
```

```json
{
  "receipt_id": "receipt://benchmark_123",
  "receipt_type": "benchmark_run | evaluation_verdict",
  "benchmark_run_id": "bench_123",
  "worker_id": "worker://...",
  "sparse_worker_category": "std:code:runtime_audit.v1",
  "benchmark_profile_ref": "benchmark://ioi/categories/runtime_audit/v1",
  "evaluation_rubric_ref": "rubric://ioi/runtime_audit/v1",
  "environment_hash": "sha256:...",
  "manifest_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "score_commitment": "sha256:...",
  "routing_eligibility_result": "eligible | ineligible | suspended"
}
```

```json
{
  "receipt_id": "receipt://route_123",
  "receipt_type": "routing_decision",
  "routing_decision_id": "route_123",
  "task_id": "task://...",
  "router_id": "runtime://... | system://... | domain://...",
  "intent_hash": "sha256:...",
  "candidate_set_commitment": "sha256:...",
  "routing_policy_hash": "sha256:...",
  "selected_domain_or_worker": "worker://...",
  "authority_scope": ["scope:..."],
  "cost_bound": "optional",
  "reason_code": "policy_compatible_benchmark_leading_within_budget",
  "fallback_policy": "optional",
  "contribution_policy_ref": "license://...",
  "receipt_obligations": ["receipt://contribution_required"]
}
```

Training receipts bind declared training-lineage and dataset/evaluation
commitments. Context mutation receipts bind versioned supersession rather than
silent memory overwrite. Promotion receipts bind whether a context, adapter,
route-policy, evaluation, or package update passed or failed declared gates.
Benchmark receipts bind the run, profile, evaluator, and reported performance.
Routing receipts bind selection under a declared candidate set and policy.
None of these receipts alone proves capability quality, external correctness,
acceptance, economic value, or universal worker superiority.

## Autonomous-System Module and Local Settlement Receipts

Governed autonomous-system chains use service-module invocations as typed
transition boundaries. The receipt binds the specific invocation; Agentgres
records the accepted operation and state roots; IOI L1 anchors only selected
roots when public trust, dispute, reputation, or economic settlement requires
them.

```json
{
  "receipt_id": "receipt://module_123",
  "receipt_type": "module_invocation",
  "module_id": "module://policy.evaluate.spend_limit.v3",
  "invocation_id": "invocation://123",
  "autonomous_system_chain_id": "system://customer-ops",
  "hypervisor_node_id": "node://local-hypervisor",
  "input_hash": "sha256:...",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "policy_hash": "sha256:...",
  "authority_grant_refs": ["grant://..."],
  "decision": "accepted | rejected | escalated",
  "artifact_refs": [],
  "signature": "optional"
}
```

```json
{
  "receipt_id": "receipt://upgrade_123",
  "receipt_type": "upgrade_proposal | upgrade_decision",
  "proposal_id": "proposal://...",
  "target_kind": "service_module | workflow_graph | policy_module | model_route | tool_binding | settlement_rule",
  "target_ref": "module://...",
  "diff_ref": "artifact://...",
  "simulation_receipt_refs": ["receipt://..."],
  "benchmark_receipt_refs": ["receipt://..."],
  "decision": "approved | rejected | escalated | rolled_back",
  "policy_hash": "sha256:...",
  "l1_commitment": "optional"
}
```

```json
{
  "receipt_id": "receipt://local_settlement_123",
  "receipt_type": "local_settlement",
  "hypervisor_node_id": "node://...",
  "autonomous_system_chain_id": "system://...",
  "settlement_kind": "module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation",
  "operation_ref": "agentgres://operation/...",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "receipt_root": "sha256:...",
  "l1_anchor_ref": "optional"
}
```

## ServiceCompositionReceiptBundle

`ServiceCompositionReceiptBundle` is the default evidence profile for
service-order deliveries that route through nested workers, service modules,
external providers, verifiers, private workspaces, or MoW compositions. It is
not a new authority layer and it is not a replacement for `DeliveryBundle`.
It is the receipt graph that lets a marketplace, buyer, provider, verifier, or
dispute process understand who contributed, what was verified, what private
data posture applied, and which evidence refs support settlement.

```json
{
  "service_composition_receipt_bundle_id": "service_comp_bundle_123",
  "delivery_bundle_ref": "delivery://delivery_123",
  "service_order_ref": "order://order_123",
  "outcome_workspace_ref": "agentgres://sas/outcome-workspaces/order_123",
  "service_package_ref": "service://sas/runtime-audit-weekly@1.0.0",
  "composition_graph_ref": "workflow://graph_123",
  "routing_receipt_refs": ["receipt://route_123"],
  "contribution_receipt_refs": ["receipt://contribution_worker_1"],
  "verifier_receipt_refs": ["receipt://validation_1", "receipt://quality_1"],
  "policy_receipt_refs": ["receipt://policy_1", "receipt://approval_1"],
  "private_data_posture": {
    "posture": "none | public_only | redacted_projection | ctee_private_workspace | tee_or_customer_cloud | customer_vpc | unsafe_plaintext_exception",
    "custody_proof_refs": ["receipt://model_mount_1"],
    "declassification_receipt_refs": ["receipt://declassification_1"],
    "plaintext_sensitive_classes_on_provider": ["none"]
  },
  "artifact_refs": ["artifact://report"],
  "evidence_bundle_refs": ["evidence://bundle_123"],
  "dispute_evidence_refs": ["evidence://dispute_ready_123"],
  "acceptance_criteria_refs": ["criteria://runtime-audit/v1"],
  "settlement_refs": ["settlement://order_123"],
  "agentgres_operation_refs": ["agentgres://operation/op_789"],
  "state_root": "sha256:...",
  "status": "draft | submitted | accepted | rejected | disputed | remediated"
}
```

`ContributionReceipt` entries should name the contributing worker, service
module, package, provider, harness adapter, or verifier role; bind the claimed
contribution to receipts and artifacts; and state whether the contribution is
relevant to payout, royalty, reputation, warranty, or dispute handling. Raw
token usage, popularity, opaque provider logs, or hidden platform preference
must not be treated as contribution truth.

Contribution is not limited to the winning execution. Receipts may attribute
negative information, independent reproduction, debugging, review, curation,
verifier hardening, integrity reports, resource provision, and synthesis when
their marginal value is bound to durable attempt/finding/result lineage. The
receipt must carry its canonical assurance state—`attested`, `evidenced`,
`verified`, `accepted`, `adjudicated`, or `settled`—rather than implying that a
claimed quality delta is already payable truth.

`private_data_posture` is evidence about custody and execution posture, not a
privacy authority by itself. wallet.network owns secret/declassification
authority, Private Workspace cTEE owns no-plaintext-custody execution posture,
the Hypervisor Daemon emits runtime receipts, and Agentgres admits the delivery
truth. An `unsafe_plaintext_exception` must be explicit, policy-approved, and
dispute-visible.

Anti-patterns:

```text
delivery bundle as a raw ZIP without contribution and verifier refs
token usage as contribution truth
provider logs as dispute truth
privacy posture implied by marketing copy instead of receipts
disputes opened without durable dispute evidence refs
L1 settlement for every nested service step by default
```

## DeliveryBundle

```json
{
  "delivery_id": "delivery_123",
  "delivery_type": "service_order | worker_invocation | workflow_run",
  "order_id": "optional",
  "worker_invocation_id": "optional",
  "run_ids": ["run_123"],
  "output_artifacts": ["artifact://report"],
  "artifact_refs": [
    {
      "cid": "bafy...",
      "sha256": "...",
      "media_type": "application/pdf",
      "privacy_class": "confidential"
    }
  ],
  "evidence_bundle": ["receipt://execution", "receipt://validation"],
  "receipt_bundle_ref": {
    "cid": "bafy...",
    "sha256": "..."
  },
  "state_commitment": {
    "agentgres_domain": "agentgres://domain/sas.xyz",
    "operation_id": "op_789",
    "state_root": "sha256:..."
  },
  "quality_summary": {
    "score": 0.91,
    "checks_passed": true,
    "warnings": []
  },
  "policy_summary": {
    "approvals_used": ["approval_123"],
    "denied_actions": []
  },
  "routing_refs": ["receipt://route_123"],
  "contribution_refs": ["receipt://contribution_worker_1"],
  "service_composition_receipt_bundle_ref": "service_comp_bundle_123",
  "verifier_receipt_refs": ["receipt://validation_1", "receipt://quality_1"],
  "private_data_posture": "public_only | redacted_projection | ctee_private_workspace | tee_or_customer_cloud | customer_vpc | unsafe_plaintext_exception",
  "dispute_evidence_refs": ["evidence://dispute_ready_123"],
  "settlement": {
    "l1_contract": "0x...",
    "status": "pending_acceptance"
  }
}
```

Agentgres owns the delivery state: whether the delivery happened, what state
changed, which receipts are required, which artifacts exist, which
quality/contribution ledgers update, and which projections/subscriptions should
advance. Storage backends hold the heavy immutable payloads: artifact bytes,
receipt/evidence bundles, trace bundles, screenshots/videos, reports, and
archival checkpoint files.

## SessionTraceBundle

```json
{
  "trace_bundle_id": "trace_123",
  "run_id": "run_123",
  "outcome_room_ref": "outcome-room://room-123 | null",
  "room_coordination_topology": "hosted_admission | federated_admission | null",
  "timeline_segments": [],
  "span_waterfall": [],
  "event_refs": [],
  "log_refs": [],
  "graph_edges": [],
  "proof_links": [],
  "settlement_links": [],
  "config_snapshot": {},
  "prompt_section_hashes": [],
  "model_invocations": [],
  "tool_proposals": [],
  "policy_decisions": [],
  "authority_decisions": [],
  "task_state_updates": [],
  "uncertainty_assessments": [],
  "probes": [],
  "postcondition_syntheses": [],
  "semantic_impact_records": [],
  "approvals": [],
  "execution_receipts": [],
  "memory_retrieval_receipts": [],
  "runtime_bridge_receipts": [],
  "usage_receipts": [],
  "memory_mutation_receipts": [],
  "mcp_invocation_receipts": [],
  "subagent_receipts": [],
  "participant_lease_refs": [],
  "frontier_item_refs": [],
  "work_claim_refs": [],
  "resource_offer_and_allocation_refs": [],
  "attempt_refs": [],
  "finding_refs": [],
  "verifier_challenge_refs": [],
  "work_result_and_outcome_delta_refs": [],
  "contribution_lineage_refs": [],
  "workspace_snapshot_receipts": [],
  "workspace_restore_receipts": [],
  "diagnostics_repair_receipts": [],
  "artifact_refs": [],
  "final_outcome": {},
  "stop_condition": {},
  "scorecard": {},
  "redaction_manifest": {},
  "verification_result": {}
}
```

## QualityRecord

```json
{
  "quality_record_id": "quality_123",
  "target_type": "worker | service | runtime | model | tool",
  "target_id": "ai://workers.runtime-auditor.ioi",
  "task_class": "coding_audit",
  "score": 0.91,
  "metrics": {
    "success": true,
    "latency_ms": 120000,
    "cost_usd": 1.23,
    "human_override": false,
    "postcondition_pass": true
  },
  "evidence_refs": ["receipt://validation_123"],
  "epoch": 44
}
```

## Non-Negotiables

1. Event streams are not authoritative over persisted settlement state.
2. Receipts must be reconstructable from trace bundles.
3. Delivery requires outputs plus evidence, not just files.
4. Quality/reputation roots should be aggregated before L1 commitment.
5. Private traces must support redacted export.
6. Optional TUI, SDK, ADK, Workflow Compositor, Workbench, and Hypervisor
   controls must leave the same event and receipt trail when they mutate
   runtime state.
7. Private Workspace cTEE receipts must never reveal protected plaintext merely
   to prove that private work occurred.
8. Trace detail panels must not substitute raw logs, prompts, provider output,
   or transaction hashes for receipts, state roots, authority decisions, and
   settlement records.
9. A receipt proves only the boundary fact it binds; verification, acceptance,
   adjudication, and settlement remain distinct states.
10. Room messages, self-reported scores, participant consensus, and
    leaderboards are projections and evidence inputs, never shared-state
    admission or authority by themselves.
11. Positive, negative, inconclusive, invalid, exploit-finding, and superseded
    attempts remain durable when policy admits their informational or audit
    value.
12. Verifier rule changes must version the rule, identify affected attempts,
    and trigger declared re-verification rather than silently rewriting history.
