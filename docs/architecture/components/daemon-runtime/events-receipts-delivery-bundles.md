# Events, Receipts, and Delivery Bundles

Status: canonical low-level reference.
Canonical owner: this file for runtime events, receipts, delivery bundles, trace bundles, and quality records.
Supersedes: overlapping event/receipt examples in plans/specs when event, trace, or receipt fields conflict.
Superseded by: none.
Last alignment pass: 2026-07-17.
Doctrine status: canonical
Implementation status: mixed (receipts/events live across existing owner planes; `ReceiptCheckpoint` v1, `ReceiptProofBundle` v1, managed-work billing ledger-bundle, dispute-rail-bundle, and `PhysicalActionExecutionReceipt` v1 have registered schemas, invariants, fixtures, and generated projections; portable cryptographic proof verification/CLI support, managed-work billing and dispute kernels, physical execution production, daemon/Agentgres production billing/dispute/physical/checkpoint emission, supplier-statement resolution, evidence adjudication, remedy/bond execution receipts, cross-plane information-flow events, OutcomeRoom/collective-pursuit receipt families, full bounded-improvement Campaign receipts, embodied graph activation and action-chunk lineage, spacetime reservation, physical segment commitments, and delivery-bundle settlement remain planned)
Last implementation audit: 2026-07-18

## Purpose

Events enable observation; receipts bind attributable boundary facts; replay
enables inspection; evidence, verification, acceptance, adjudication, and
settlement add distinct claim and disposition stages. Delivery bundles carry the
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

The ladder orders claim handling and institutional disposition, not certainty
about an underlying proposition. Verification evaluates evidence under a named
rule; acceptance records reliance or agreement; adjudication resolves a
governed contest; settlement moves rights or value. A wrong claim can be
accepted, adjudicated, finalized, or paid. Later stages therefore do not erase
contradiction or convert a scoped operational determination into universal
truth.

## Receipt Registry And Schema Ownership

[`../../foundations/common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md#receiptenvelope)
owns the portable `ReceiptEnvelope` base and shared identity/ref contract. This
file owns the exhaustive receipt-type registry, cross-component specialized
schemas, lifecycle, and assurance semantics (INV-9,
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

## Oracle Evidence Admission Receipt

`OracleEvidenceAdmissionReceipt` closes the external-assertion decision boundary
between `OracleEvidenceProfileEnvelope`, provenance-bearing evidence,
`OntologyAssertionEnvelope`, verification, and a permitted consequence. It
extends the shared `ReceiptEnvelope`:

```yaml
OracleEvidenceAdmissionReceipt:
  receipt_type: oracle_evidence_admission
  assertion_ref: ontology-assertion://...
  assertion_commitment: sha256:...
  fact_class_ref: ontology://...#fact-class
  oracle_evidence_profile_ref: oracle-evidence-profile://...
  oracle_evidence_profile_version: semver_or_hash
  oracle_evidence_profile_body_hash: sha256:...
  evidence_bundle_refs:
    - evidence://...
  evidence_root: sha256:...
  evidence_dependency_graph_ref: evidence://... | artifact://...
  evidence_dependency_graph_root: sha256:...
  source_independence_evidence_refs:
    - evidence://... | artifact://... | receipt://...
  verifier_path_refs:
    - verifier_path://...
  verification_receipt_refs:
    - receipt://...
  freshness_and_uncertainty_assessment_ref: evidence://...
  contradiction_and_challenge_refs:
    - ontology-assertion://... | verifier-challenge://... | dispute://...
  decision: admitted_for_scope | held_unknown | rejected | escalated
  applicability_scope_ref: policy://... | system://... | domain://... | null
  permitted_consequence_scope_refs:
    - policy://...
  effective_at: timestamp
  valid_until: timestamp | null
  policy_ref: policy://...
  required_authority_refs:
    - grant://... | lease://...
  expected_predecessor_admission_receipt_ref: receipt://... | null
  expected_predecessor_admission_head_hash: sha256:... | null
  resulting_admission_head_hash: sha256:...
  agentgres_operation_ref: agentgres://operation/...
```

This receipt proves that the named boundary reached the declared decision under
the bound profile, inputs, and time window. It neither proves the external
proposition nor conveys effect authority. A consequential effect separately
requires the active policy and authority path, fresh oracle-evidence and domain
assertion-admission decisions, and the normal effect receipt.

For `decision: admitted_for_scope`, `valid_until` and at least one member of
`permitted_consequence_scope_refs` are mandatory, `valid_until` cannot exceed
the profile maximum, and the receipt's fact class, applicability scope, and
consequence scopes must match the assertion and be permitted by the active
profile. `held_unknown`, `rejected`, and `escalated` convey no permitted
consequence.

Agentgres admits each assertion's oracle-decision chain through exact-head
compare-and-swap over the expected predecessor ref/hash and resulting head.
Concurrent successors from one predecessor cannot both become current. Every
consequential effect binds both the active `OracleEvidenceAdmissionReceipt`
ref/head and the current `OntologyAssertionAdmissionReceipt` ref/resulting
assertion head. Immediately before invocation it revalidates the oracle
decision, validity, active profile, source/verifier revocation posture,
applicability, and permitted consequence scope, plus a current domain decision
of `admitted` whose oracle receipt, assertion commitment, fact class,
applicability, and consequence scopes match exactly. A current rejected or
superseded domain-admission head blocks the effect even while the oracle
decision remains active. Late contradiction, source or verifier revocation,
profile replacement, domain rejection or supersession, or expiry stops future
reliance according to policy while preserving immutable history and invoking
declared reversal, compensation, or reconciliation.

## Ontology Assertion Admission Receipt

`OntologyAssertionAdmissionReceipt` records the separate Agentgres/domain
decision to admit an assertion as operational semantic truth after any required
oracle/evidence determination:

```yaml
OntologyAssertionAdmissionReceipt:
  receipt_type: ontology_assertion_admission
  assertion_ref: ontology-assertion://...
  assertion_commitment: sha256:...
  fact_class_ref: ontology://...#fact-class | null
  oracle_evidence_profile_ref: oracle-evidence-profile://... | null
  oracle_evidence_admission_receipt_ref: receipt://... | null
  applicability_scope_ref: policy://... | system://... | domain://... | null
  permitted_consequence_scope_refs:
    - policy://...
  decision: admitted | rejected
  expected_predecessor_assertion_head_ref: ontology-assertion://... | null
  expected_predecessor_assertion_head_hash: sha256:... | null
  resulting_assertion_head_hash: sha256:...
  policy_ref: policy://...
  authority_refs:
    - grant://... | lease://...
  agentgres_operation_ref: agentgres://operation/...
```

When an oracle/evidence profile governs the assertion, admission requires the
active unexpired `OracleEvidenceAdmissionReceipt`; its assertion commitment,
fact class, profile revision, applicability, and consequence-scope set must
match exactly. Domain admission cannot widen those scopes or revive a held,
rejected, expired, superseded, or revoked oracle decision. The receipt proves
the domain admitted the exact semantic assertion through exact-head CAS. It
does not prove the proposition, replace the oracle evaluator, or convey effect
authority.

## Receipt Checkpoints And Offline Proofs

`ReceiptCheckpoint` v1 and `ReceiptProofBundle` v1 are the portable export
profile over the existing `ReceiptEnvelope`; neither replaces a receipt,
`EvidenceBundle`, `DeliveryBundle`, or Agentgres operational truth. The machine
contracts and fixtures are registered by
[`architecture-contract-registry.v1.json`](../../_meta/schemas/architecture-contract-registry.v1.json).

The v1 accumulator is named
`ioi.receipt-hash-chain-jcs-sha256.v1`. It is a deterministic, append-only,
domain-separated linear hash chain—not a Merkle tree and not an RFC 6962
transparency-log proof. It uses:

```text
receipt_body_hash = SHA256(JCS(exact closed ReceiptEnvelope v1))
leaf[i] = SHA256("IOI-RECEIPT-ACCUMULATOR-LEAF-V1\0" ||
                 JCS(receipt contract/schema, body hash, domain, index i))
root[0] = SHA256("IOI-RECEIPT-ACCUMULATOR-EMPTY-V1\0")
root[i+1] = SHA256("IOI-RECEIPT-ACCUMULATOR-STEP-V1\0" ||
                   JCS(previous root, leaf[i]))
```

An inclusion witness carries the root immediately before the selected leaf and
every later leaf hash through the signed checkpoint. A consistency witness
carries every leaf appended after the signed predecessor checkpoint. Both are
linear-size v1 witnesses: that cost is explicit and is not mislabeled as
Merkle/MMR compactness. A future compact accumulator requires a new versioned
algorithm identity and cross-runtime vectors rather than silent wire mutation.

`ReceiptCheckpoint` binds the receipt-log identity, algorithm and body-hash
profiles, receipt and checkpoint schema hashes, size/root, exact predecessor
checkpoint hash/size/root, issuer key-set identity/version, build identity,
policy posture, and issuance time. The Ed25519 signature preimage is
`IOI-RECEIPT-CHECKPOINT-V1\0` followed by JCS of the checkpoint body hash,
schema hash, signing domain, algorithm, size, and root. The checkpoint body
hash excludes only its signature block.

`ReceiptProofBundle` contains the exact receipt, its body/leaf hashes, inclusion
material, current and optional predecessor checkpoints, consistency material,
trusted key-set/revocation-snapshot refs, and human-readable offline
verification steps. Its manifest hashes every field except the manifest hash
and signature block, and the checkpoint signer authenticates that hash under
the separate `IOI-RECEIPT-PROOF-BUNDLE-MANIFEST-V1\0` domain. Recomputing a
self-hash therefore cannot rewrite verification instructions or trusted-input
refs without invalidating the manifest signature.

Offline verification fails closed unless it can:

1. validate every registered closed schema and schema hash;
2. reproduce the exact receipt body and indexed leaf hashes;
3. reproduce the signed accumulator root from the inclusion witness;
4. verify current and predecessor checkpoint signatures against a locally
   trusted, current key set and signed bounded-freshness revocation snapshot;
5. reproduce the current root from the predecessor root and all extension
   leaves;
6. bind the manifest to those trusted inputs and verify its signature.

The registered schemas, invariants, and adversarial fixtures encode refusal
cases for receipt, type, domain, version, leaf, index, root, predecessor,
manifest, signer, key, revocation, and staleness substitution. They are not a
cryptographic inclusion/consistency verifier or an offline CLI. Those
verifiers, public transparency, network key discovery, gossip/witness-based
split-view detection, and live daemon/Agentgres emission remain separate
planned work. Consequential runtime receipts do not acquire signed-checkpoint
coverage until a production emitter records them in an implemented
accumulator.

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
optional TUI, SDK, ADK, Developer Workspace/Foundry surfaces, other Applications
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
information_flow.labeled
information_flow.effect_admitted
information_flow.effect_denied
information_flow.declassification_applied
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
improvement.agenda_revision_released
improvement.campaign_proposed
improvement.campaign_admitted
improvement.campaign_started
improvement.campaign_paused
improvement.campaign_stopped
improvement.candidate_admitted
improvement.epoch_frozen
improvement.epoch_activated
improvement.epoch_challenged
improvement.epoch_invalidated
improvement.exposure_reserved
improvement.exposure_spent
improvement.exposure_released
improvement.order_cutoff_recorded
improvement.evidence_claim_recorded
improvement.evidence_claim_challenged
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
state_transition_commitment.committed
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
embodied.runtime_graph.compiled
embodied.runtime_graph.admitted
embodied.physical_stream_contract.admitted
embodied.physical_stream_contract.rejected
embodied.physical_stream_contract.violated
embodied.graph_activation.proposed
embodied.graph_activation.staging
embodied.graph_activation.prepared
embodied.graph_activation.validated
embodied.graph_activation.committed
embodied.graph_activation.aborted
embodied.graph_activation.deactivated
embodied.graph_activation.rolled_back
embodied.graph_activation.failed_closed
embodied.local_supervisor.ready
embodied.local_supervisor.vetoed
embodied.local_supervisor.recovery_entered
embodied.world_model.updated
embodied.environment_state.updated
embodied.action_chunk.proposed
embodied.action_chunk.selected
embodied.action_chunk.admitted_to_queue
embodied.action_chunk.executed_under_segment
embodied.action_chunk.clipped
embodied.action_chunk.replaced
embodied.action_chunk.rejected
embodied.action_chunk.expired
embodied.action_chunk.superseded
embodied.fleet_allocation.proposed
embodied.fleet_allocation.active
embodied.fleet_allocation.completed
embodied.fleet_allocation.fenced
embodied.fleet_allocation.expired
embodied.fleet_allocation.revoked
embodied.fleet_allocation.ambiguous
embodied.fleet_allocation.reassigned
embodied.fleet_allocation.reconciliation_required
embodied.spacetime_reservation.proposed
embodied.spacetime_reservation.activated
embodied.spacetime_reservation.consumed
embodied.spacetime_reservation.fenced
embodied.spacetime_reservation.preempted
embodied.spacetime_reservation.revoked
embodied.spacetime_reservation.expired
embodied.spacetime_reservation.conflict
embodied.spacetime_reservation.released
embodied.spacetime_reservation.failed_closed
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
  "event_id": "event://123",
  "parent_event_id": "event://122",
  "run_id": "run://123",
  "task_id": "task://123",
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
LearningEgressReceipt
InformationFlowDecisionReceipt
DeclassificationReceipt
ToolExecutionReceipt
ModuleInvocationReceipt
ArtifactReceipt
ArtifactAvailabilityReceipt
ArtifactRepairReceipt
ValidationReceipt
MergeReceipt
SettlementReceipt
StateTransitionCommitmentReceipt
DeliveryReceipt
AIIPPacketReceipt
AIIPDeliveryUpdateReceipt
AIIPAcceptanceDecisionReceipt
DisputeResolutionReceipt
BondDistributionReceipt
DisputeRemedyExecutionReceipt
AIIPDisputeResolutionReceipt
AIIPSettlementIntentReceipt
CrossDomainDeliveryBundleReceipt
ContributionReceipt
ContributionAdmissionReceipt
QualityReceipt
DataRecipeRunReceipt
TransformationReceipt
DatasetDistillationReceipt
OntologyProjectionReceipt
OracleEvidenceAdmissionReceipt
OntologyAssertionAdmissionReceipt
TrainingEvidenceEligibilityReceipt
LearningEvidenceEligibilityReceipt
UpgradeProposalReceipt
UpgradeDecisionReceipt
ImprovementAgendaRevisionReceipt
ImprovementCampaignAdmissionReceipt
ImprovementCampaignLifecycleReceipt
EvaluationEpochReceipt
EvaluationExposureReceipt
ImprovementOrderCutoffReceipt
ImprovementEvidenceClaimReceipt
ConstitutionProposalReceipt
ConstitutionDecisionReceipt
ConstitutionActivationReceipt
AutonomousSystemGenesisReceipt
AutonomousSystemActivationReceipt
NodeMembershipAdmissionReceipt
NodeMembershipTransitionReceipt
StateCatchupReceipt
StateRootVerificationReceipt
WriterPromotionReceipt
WriterFencingReceipt
DeploymentConformanceReceipt
FailoverEvaluationReceipt
SingleWriterRestoreReceipt
OrderingFinalityRecoveryReceipt
LifecycleTransitionReceipt
MigrationReceipt
SuccessionReceipt
DissolutionReceipt
NetworkEnrollmentTransitionReceipt
NetworkServiceActivationReceipt
NetworkServiceInvocationReceipt
NetworkExitReceipt
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
CollaborationTermsAcceptanceReceipt
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
GoalRunProfileResolutionReceipt
AutomationRunResolutionReceipt
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
EmbodiedGraphActivationReceipt
EmbodiedActionChunkLineageReceipt
SpacetimeReservationReceipt
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

## Information-Flow Decision Receipts

`InformationFlowDecisionReceipt` is the receipt profile for the daemon's
pre-effect IFC boundary. It binds the exact label and RuntimeToolContract
revision, destination, decision/reason, and—when canonicalization reached that
stage—the exact effect, request, and reviewed-representation hashes. A denied
decision may assert `blocked_before_egress` only when its enforcement evidence
binds the pre-network boundary and proves the external invoker was not called.
It never includes protected effect bytes or the reviewed plaintext.

```yaml
InformationFlowDecisionReceipt:
  receipt_profile_ref: schema://ioi/receipt/information-flow-decision/v1
  information_flow_label_ref: ifc-label://... | null
  information_flow_label_content_hash: hash | null
  runtime_tool_contract_revision_ref: tool://.../revision/... | null
  destination: string | null
  effect_hash: hash | null
  request_hash: hash | null
  reviewed_representation_hash: hash | null
  decision: admitted | denied
  reason: canonical_ifc_reason
  blocked_before_egress: boolean
  enforcement_boundary_ref: runtime://... | policy://... | null
  declassification_approval_ref: approval://... | null
  declassification_receipt_ref: receipt://... | null
```

`DeclassificationReceipt` separately records validation or consumption of the
exact `DeclassificationApproval`. It binds the approval ref, label/tool refs,
effect/request/review hashes, destination, resulting data class, authority
grant, and status at use. It does not rewrite the label, erase derivation
parents, upgrade instruction authority, or prove anything about provider-side
retention after a permitted transfer.

`WorkResultReceipt` and `OutcomeDeltaAdmissionReceipt` bind the exact
`information_flow_label_refs` present at admission. Delta admission unions the
bound proposer's refs with any additional declared refs before hashing and
receipting the record; a caller cannot use a delta to erase upstream
provenance. These receipts prove preservation of refs at that boundary, not
that every referenced label is independently verified or that any content was
declassified.

## AIIP And Cross-Domain Service Receipts

AIIP receipts bind cross-domain service handoffs without copying remote domain
state into local Agentgres as truth. `AIIPPacketReceipt` records an admitted
packet and its envelope hash. `AIIPDeliveryUpdateReceipt` records milestone,
partial, final, revision, or cancellation updates with artifact, evidence, and
receipt roots. `AIIPAcceptanceDecisionReceipt` records accept, partial accept,
reject, revision request, or dispute-open decisions.
`DisputeResolutionReceipt` records admission or execution evidence for the
shared dispute object family; AIIP may carry it as an
`AIIPDisputeResolutionReceipt` profile without redefining the body.
`AIIPSettlementIntentReceipt` records the
conditions proposed under the declared local, bilateral, invoice, escrow,
external-chain, or enrolled IOI L1 settlement mode/profile.
`CrossDomainDeliveryBundleReceipt`
binds local and remote receipt roots, evidence refs, delivery updates,
acceptance decisions, dispute refs, and settlement intent refs into an
exportable proof bundle.

### Dispute decision and execution receipts

The canonical `DisputeResolutionEnvelope` is the decision/allocation object,
not a receipt and not proof of execution. Receipt profiles bind stages around
it:

```yaml
DisputeResolutionReceipt:
  receipt_profile_ref: schema://ioi/receipt/dispute-resolution/v1
  dispute_ref: dispute://...
  dispute_resolution_ref: dispute-resolution://...
  dispute_rail_profile_ref: policy://dispute/...
  dispute_rail_profile_version: positive_integer
  dispute_rail_profile_body_hash: sha256:...
  case_head_hash: sha256:...
  resolution_request_hash: sha256:...
  value_unit_ref: denomination://...
  value_unit_body_hash: sha256:...
  outcome: challenger_upheld | respondent_upheld | partial | no_fault | escalated
  remedy: none | refund | partial_refund | payout | partial_payout | slash | retry | revise | escalate
  remedy_units: nonnegative_integer
  bond_pool_units: nonnegative_integer
  bond_allocation_hash: sha256:...
  decision_admission_ref: decision://...
  execution_receipt_refs: []
  appeal_of_resolution_ref: dispute-resolution://... | null
  assurance_stage: attested | evidenced | verified | accepted | adjudicated | settled
  status: admitted | execution_pending | executed | execution_failed | appealed | superseded
```

The profile/case/resolution contract requires one exact asset-unit binding
across disputed value, remedy, bonds, and allocation. The receipt repeats the
unit ref/hash and exact resolution/case/profile hashes; it cannot relabel or
convert them. A decision-stage receipt proves only that the deterministic
admission boundary produced the bound decision. `bond_distribution`,
`dispute_remedy_execution`, and `dispute_escalation` receipts remain separate
required evidence when applicable. Only the owning escrow/payment/settlement
adapter can attest that value moved, and only the applicable appeal/finality
owner can attest finality.

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
  "harness_ref": "harness-profile://default | null",
  "runtime_node_ref": "node://123",
  "route_attempt_id": "route-attempt://123",
  "fallback_chain_ref": "route-chain://123",
  "route_contract_ref": "model-route-contract://123",
  "institutional_learning_boundary_profile_ref": "learning-boundary://org/default/v1 | null",
  "effective_learning_policy_hash": "sha256:... | null",
  "effective_customer_output_rights_hash": "sha256:... | null",
  "learning_egress_receipt_refs": ["receipt://learning_egress_123"],
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

### Managed-work billing ledger linkage

Runtime and model receipts are evidence inputs to billing; they are not
themselves mutable balances or debit authority. The common-object
[`Managed Work Billing Object Family`](../../foundations/common-objects-and-envelopes.md#managed-work-billing-object-family)
owns the exact accounting records:

```text
RateCard + Plan -> WorkQuote -> CreditHold
runtime receipt(s) -> append-only UsageRecord
projected overrun -> OverrunDecision -> exact additional hold or block
complete usage head -> FinalDebit -> Adjustment / Refund / Writeoff
```

Each `UsageRecord` binds the immutable quote, current prior-usage hash,
owner-resolved runtime receipt refs, meter class and integer quantity, frozen
integer rate, commercial posture, separate provider/broker/participant/verifier
/IOI-fee fields, excluded customer-borne provider cost, and any exact supplier
statement refs. The billing record's canonical hash and usage-head link make
reordering, deletion, and changed-body replay detectable.

The event/receipt plane may emit or project these records only after resolving
the owning runtime evidence and billing authority. A public caller cannot
submit an arbitrary supplier-usage body and thereby mint billable usage. A
supplier-cost field marked estimated remains internal-event-log assurance; only
an applicable supplier statement can elevate that cost to
supplier-reconciled. Coarse OCU is zero-rate telemetry outside this chain and
must never be presented as invoice-grade usage.

## Learning Egress Receipt

`LearningEgressReceipt` extends the common `ReceiptEnvelope` and binds one
attempted or actual crossing of an institutional learning boundary. It does not
duplicate route-rights, training-eligibility, custody, authority, export, or
declassification truth; it references their admitted owner objects and the
underlying operation receipts.

```yaml
LearningEgressReceipt:
  receipt_id: receipt://...
  receipt_type: learning_egress
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: sha256:...
  boundary_compilation_or_policy_decision_ref:
    receipt://... | decision://...
  source_scope_ref:
    system://... | org://... | project://... | domain://... |
    agentgres://domain/... | workspace://...
  material_classes:
    - source_data
    - prompts_and_completions
    - connector_and_tool_io
    - work_graphs_traces_and_receipts
    - corrections_and_reviewer_judgments
    - evaluations_rubrics_holdouts_and_canaries
    - memory_context_procedures_workflows_and_skills
    - datasets_embeddings_and_indexes
    - adapters_checkpoints_weights_and_packages
    - router_verifier_authority_and_governance_policy
    - analytics_crash_support_and_security_telemetry
    - embodied_sensor_actuator_mission_and_operator_telemetry
  material_commitment: sha256:...
  learning_source_rights_claim_refs:
    - learning-source-rights://...
  policy_bound_projection_refs:
    - view://... | memory_projection://... | artifact://...
  recipient_class:
    model_provider | external_processor | cross_organization |
    public_export | support_operator
  recipient_ref:
    provider://... | service://... | org://... | domain://... | user://... |
    endpoint://... | null
  purpose:
    inference_service_delivery | hosted_training | hosted_evaluation |
    support | audit_export | publication | cross_domain_reuse
  representation:
    public | redacted | synthetic | declassified | sealed_ciphertext |
    protected_plaintext
  execution_privacy_posture_ref: privacy_posture://... | null
  model_route_contract_ref: model-route-contract://... | null
  intended_customer_output_uses: []
  effective_customer_output_rights_hash: sha256:... | null
  applicable_terms_and_license_refs:
    - terms://... | license://... | contract://...
  provider_use_of_customer_material:
    request_or_prompt_logging:
      prohibited | contract_limited | explicitly_permitted | not_applicable
    human_review:
      prohibited | security_incident_only | contract_limited |
      explicitly_permitted | not_applicable
    abuse_and_security_processing:
      prohibited | transient_only | contract_limited |
      explicitly_permitted | not_applicable
    service_improvement:
      prohibited | contract_limited | explicitly_permitted | not_applicable
    provider_model_training:
      prohibited | contract_limited | explicitly_permitted | not_applicable
    cross_customer_aggregation:
      prohibited | contract_limited | explicitly_permitted | not_applicable
  retention_posture:
    zero_retention | transient_processing | contract_bounded |
    provider_default | not_applicable
  retention_policy_ref: policy://... | null
  local_policy_and_consent_refs:
    - policy://... | terms://... | license://...
  authority_refs:
    - grant://... | lease://... | authority://...
  redaction_or_declassification_receipt_refs:
    - receipt://...
  underlying_operation_receipt_refs:
    - receipt://...
  revocation_impact_ref: policy://... | artifact://... | null
  decision: blocked_before_egress | admitted
  reason_codes:
    - LearningEgressDenied | ProviderSecondaryUseDenied |
      RouteRightsUnsatisfied | CustodyPostureUnsatisfied |
      LearningSourceRightsMissing | InstitutionalExportDenied |
      policy_defined
  transfer_status:
    not_sent | prevented_before_network_write | sent | delivery_confirmed |
    failed | unknown
  network_or_gateway_evidence_refs:
    - receipt://... | artifact://...
  agentgres_operation_refs:
    - agentgres://operation/...
  assurance_stage:
    attested | evidenced | verified | accepted | adjudicated | settled
```

The receipt carries commitments and classifications, not protected plaintext.
Its provider-use and retention fields are an immutable snapshot of the rights
resolved for that crossing; `ModelRouteRightsContract`, source-rights claims,
and the applicable policies remain the semantic owners. The snapshot cannot
widen or reinterpret them.
`admitted` proves only that the declared policies and rights allowed the
crossing; it does not prove delivery, provider compliance, deletion, lack of
training, or lack of cross-customer aggregation. Provider promises remain
provider trust unless separately supported by an accepted confidential-compute
or cryptographic proof.

`blocked_before_egress` is verified only when gateway, network, sandbox, or
equivalent enforcement evidence binds the request commitment and proves that no
network write occurred. Without that evidence the receipt is an attested policy
decision and `transfer_status` must not claim
`prevented_before_network_write`. A later revocation cannot rewrite an earlier
receipt; it links forward through the applicable impact, recall, deletion, or
access-rotation record.

## GoalRun Profile Resolution Receipts

A `GoalRunProfileResolutionReceipt` proves which immutable pursuit definition,
overrides, and transitive component set daemon admission froze before a
GoalRun became active. It proves resolution and admission, not that the profile
is good, that later work is correct, or that any effect was authorized.

```yaml
GoalRunProfileResolutionReceipt:
  receipt_id: receipt://...
  receipt_type: goal_run_profile_resolution
  goal_ref: goal://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_content_hash: hash
  admitted_override_set_ref: artifact://... | null
  admitted_override_set_hash: hash | null
  effective_constraint_envelope_ref: constraint://...
  effective_constraint_envelope_hash: hash
  orchestration_policy_ref: orchestration_policy://...
  orchestration_policy_version_or_hash: semver_or_hash
  workflow_template_resolutions:
    - revision_ref: workflow-template://.../revision/...
      content_hash: hash
  resolved_skill_bindings:
    - skill_entry_ref: skill-entry://...
      skill_entry_binding_revision_ref: skill-entry://.../revision/...
      skill_entry_binding_hash: hash
      skill_manifest_revision_ref: skill://.../revision/...
      skill_manifest_content_hash: hash
  active_skill_set_snapshot_ref: active-skill-set://...
  active_skill_set_hash: hash
  resolved_harness_profile_revisions:
    - revision_ref: harness-profile://.../revision/...
      content_hash: hash
  resolved_runtime_tool_contracts:
    - revision_ref: tool://.../revision/...
      content_hash: hash
  role_topology_requirement_refs: []
  worker_model_service_and_verifier_requirement_refs: []
  primitive_capability_requirement_refs: []
  initial_role_topology_revision_ref: role_topology://.../revision/... | null
  initial_role_topology_content_hash: hash | null
  initial_role_topology_decision_ref: decision://... | receipt://... | null
  unresolved_late_binding_requirement_refs: []
  effective_learning_boundary_profile_ref: learning-boundary://... | null
  effective_learning_policy_hash: hash | null
  compatibility_revocation_and_admission_decision_refs: []
  resolved_component_set_snapshot_ref: artifact://...
  resolved_component_set_hash: hash
  agentgres_operation_refs: []
  assurance_stage: attested
  receipt_root: hash
  signature: optional
```

When the override ref is null its hash is null; otherwise both are required.
Late-binding predicates may remain unresolved at run admission only when the
profile permits them. Each actual worker, model, HarnessProfile, tool, runtime,
context, and authority selection is then frozen by its owning
`OrchestrationPlan`, `HarnessInvocation`, lease, decision, and receipt.

## AutomationRun Resolution Receipts

An `AutomationRunResolutionReceipt` proves which standing activation,
WorkflowTemplate revision, permitted inputs, and dependency closure were frozen
when one AutomationRun was admitted. It is emitted atomically with final run
admission, never by a nonbinding preview or proposal.

```yaml
AutomationRunResolutionReceipt:
  receipt_id: receipt://...
  receipt_type: automation_run_resolution
  automation_run_ref: automation-run://...
  automation_spec_revision_ref: automation://.../revision/...
  automation_spec_content_hash: hash
  automation_installation_binding_revision_ref: install://automation/.../revision/...
  automation_installation_binding_hash: hash
  automation_installation_admission_receipt_ref: receipt://...
  workflow_template_revision_ref: workflow-template://.../revision/...
  workflow_template_content_hash: hash
  activation_kind: manual | schedule | webhook | event | monitor | service | queue
  activation_event_ref: event://...
  admitted_parameter_set_ref: artifact://... | null
  admitted_parameter_set_hash: hash | null
  admitted_activation_override_set_ref: artifact://... | null
  admitted_activation_override_set_hash: hash | null
  goal_run_activation_resolutions:
    - activation_contract_ref: action://goal-run/activate/...
      activation_mode: create | join_existing
      goal_run_profile_revision_ref: goal-run-profile://.../revision/...
      goal_run_profile_content_hash: hash
      goal_run_ref: goal://...
      goal_run_profile_resolution_receipt_ref: receipt://...
  resolved_component_set_snapshot_ref: artifact://...
  resolved_component_set_hash: hash
  compatibility_revocation_and_admission_decision_refs: []
  authority_requirement_refs: []
  agentgres_operation_refs: []
  assurance_stage: attested
  receipt_root: hash
  signature: optional
```

Routine automations leave `goal_run_activation_resolutions` empty. A
goal-shaped step may create or join a GoalRun only through a declared
GoalRunActivationContract; that child GoalRun performs its own profile
resolution and retains its own resolution receipt. The Automation receipt
binds the bridge without collapsing the two run identities.

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
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_resolution_receipt_ref: receipt://...
  orchestration_policy_ref: orchestration_policy://...
  orchestration_policy_version_or_hash: semver_or_hash
  constraint_envelope_ref: constraint://...
  candidate_plan_revisions:
    - revision_ref: orchestration_plan://.../revision/...
      content_hash: hash
  selected_orchestration_plan_revision_ref: orchestration_plan://.../revision/...
  selected_orchestration_plan_content_hash: hash
  selected_materialization:
    single_path | verifier_backed_single_path | multi_model_answer |
    multi_harness_attempt | cross_session_branch_and_merge |
    collaborative_frontier | independent_replication |
    dynamic_specialist_mesh | open_challenge |
    marketplace_worker_delegation | foundry_job
  selected_role_topology_revision_ref: role_topology://.../revision/... | null
  selected_role_topology_content_hash: hash | null
  routing_decision_refs: []
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

The selected plan tuple attests one immutable OrchestrationPlan revision. Its
optional topology tuple attests the exact RoleTopology that owns role, actor,
resolver, model-route, runtime-assignment, and verifier bindings. Routing
receipts own route/worker selection, and HarnessInvocation owns the resolver
actually invoked; this receipt does not duplicate those owners as parallel
selected-harness or selected-worker arrays.

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
  task_offer_ref: packet://... | null
  task_acceptance_refs:
    - packet://...
  selected_task_acceptance_ref: packet://... | null
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: sha256:... | null
  budget_reservation_ref: budget://... | spend://... | allocation://... | null
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
  contribution_ref: contribution://...
  contributor_ref:
    system://... | participant-lease://... | worker://... | service://... |
    ioi://publisher/... | tool://... |
    org://... | domain://...
  contributor_role:
    autonomous_system | worker | service | publisher | tool | verifier | reviewer |
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
  collaboration_terms_ref: terms://... | null
  collaboration_terms_root: sha256:... | null
  task_offer_and_acceptance_refs:
    - packet://...
  work_claim_ref: work-claim://... | null
  reward_basis_ref:
    policy://... | rate-card://... | quote://... | order://... |
    budget://... | null
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
  "run_id": "run://123",
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
  "run_id": "run://123",
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
  "run_id": "run://123",
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
  work_subject:
    kind:
      goal_run | automation_run | work_item | work_claim |
      service_order | physical_action_intent
    ref:
      goal://... | automation-run://... | work_item://... | work-claim://... |
      order://... | intent://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
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
  work_subject:
    kind:
      goal_run | automation_run | work_item | work_claim |
      service_order | physical_action_intent
    ref:
      goal://... | automation-run://... | work_item://... | work-claim://... |
      order://... | intent://...
  command_ref: physical_command://...
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
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
  schema_version: ioi.physical-action-execution-receipt.v1
  receipt_envelope:
    receipt_id: receipt://...
    receipt_type: physical_action_execution
    receipt_profile_ref: schema://ioi/foundations/physical-action-execution-receipt/v1
    attested_boundary_fact_refs: []
    claim_scope_ref: policy://... | schema://... | null
    run_id: run://... | null
    task_id: task://... | null
    actor_id: worker://... | service://... | runtime://...
    input_hash: sha256:...
    output_hash: sha256:...
    policy_hash: sha256:...
    authority_grant_id: grant://... | null
    primitive_capabilities: [prim:physical.actuate]
    authority_scopes: [scope:physical.actuate]
    artifact_refs: []
    evidence_bundle_refs: [evidence://...]
    verification_ref: verification://... | null
    acceptance_ref: acceptance://... | null
    adjudication_ref: decision://... | null
    settlement_ref: settlement://... | null
    timestamp: timestamp
    signature: string | null
    public_commitment_ref: commitment://... | settlement://... | tx://... | null
  body:
    idempotency_key: string
    execution_request_hash: sha256:...
    admission_id: physical-action-admission:...
    admission_record_hash: sha256:...
    work_subject:
      kind:
        goal_run | automation_run | work_item | work_claim |
        service_order | physical_action_intent
      ref:
        goal://... | automation-run://... | work_item://... | work-claim://... |
        order://... | intent://...
    target_system_ref:
      robot://... | facility://... | vehicle://... | device://... |
      drone://... | actuator://...
    resource_group_bindings:
      - group_revision_ref: embodied-resource-group-revision://...
        membership_closure_hash: sha256:...
        unit_refs:
          - robot://... | drone://... | device://...
        controller_binding_refs: [controller-binding://...]
        sensor_refs: [sensor://...]
        actuator_refs: [actuator://...]
        physical_zone_refs: [zone://...]
        emergency_stop_authority_refs: [estop://...]
    emergency_stop_authority_ref: estop://...
    controller_binding_ref: controller-binding://...
    runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
    runtime_graph_manifest_hash: sha256:...
    safety_envelope_ref: safety://...
    safety_envelope_hash: sha256:...
    assurance_evidence_bundle_ref: assurance-evidence://...
    assurance_evidence_bundle_hash: sha256:...
    active_writer_lease_ref: resource-lease://...
    active_writer_fencing_epoch: nonnegative_integer
    active_writer_fencing_token_hash: sha256:...
    graph_timing_chain_ref: artifact://...
    graph_timing_chain_hash: sha256:...
    command_schema_ref: action-schema://...
    command_payload_hash: sha256:...
    segment_commitment_receipt_refs: [receipt://...]
    preflight_receipt_refs: [receipt://...]
    sensor_evidence_receipt_refs: [receipt://...]
    controller_operation_ref: effect://...
    dispatch_posture:
      not_dispatched_proven | dispatched_observed | dispatch_ambiguous
    dispatch_evidence_receipt_refs: [receipt://...]
    controller_receipt_refs: [receipt://...]
    outcome_normalization_error_codes: []
    effect_status: committed | rejected | unknown
    state_root_before: state_root://... | string
    state_root_after: state_root://... | string | null
    previous_execution_receipt_hash: sha256:... | null
    executed_at: timestamp
    incident_refs: [incident://...]
    reconciliation_state:
      confirmed | partially_confirmed | ambiguous_effect |
      compensation_required | non_retryable | failed
    agentgres_operation_refs: []
    assurance_stage:
      attested | evidenced | verified | accepted | adjudicated | settled
  body_hash: sha256:...
  receipt_hash: sha256:...

EmbodiedGraphActivationReceipt:
  receipt_id: receipt://...
  receipt_type: embodied_graph_activation
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  activation_transaction_ref: graph-activation-transaction://...
  native_runtime_profiles:
    - micro | edge | site
  partition_results:
    - partition_key: string
      runtime_profile: micro | edge | site
      local_control_supervisor_ref: local_control_supervisor://... | null
      local_prepare_receipt_ref: receipt://...
      local_activation_receipt_ref: receipt://... | null
      result: active_unarmed | aborted | failed_closed
  atomicity_scope:
    one_supervisor_hardware_boundary | coordinated_multi_partition
  resolved_component_implementations:
    - implementation_ref: package_artifact://... | artifact://... | module://...
      implementation_hash: hash
  resolved_transport_bindings:
    - binding_ref: schema://... | artifact://... | connector://...
      binding_hash: hash
  safety_and_assurance_prerequisite_refs:
    - policy://... | safety://... | conformance_profile://... | evidence://...
  assurance_evidence_bundle_ref: assurance-evidence://...
  prepared_at: timestamp
  committed_at: timestamp | null
  result:
    active_unarmed | aborted | deactivated | rolled_back | failed_closed |
    quarantined
  agentgres_operation_refs: []

EmbodiedActionChunkLineageReceipt:
  receipt_id: receipt://...
  receipt_type: embodied_action_chunk_lineage
  work_subject: TypedWorkSubjectBinding
  embodied_action_chunk_ref: embodied-action-chunk://...
  physical_mission_envelope_ref: physical_mission_envelope://...
  action_policy_contract_ref: embodied-action-policy-contract://...
  action_policy_contract_hash: hash
  source_observation_window_ref: state://... | artifact://...
  world_state_watermark: string
  policy_and_model_hashes: [hash]
  embodiment_adapter_ref: embodiment_adapter://...
  embodiment_adapter_hash: hash
  runtime_graph_manifest_ref: embodied-runtime-graph-manifest://...
  runtime_graph_manifest_hash: hash
  resource_group_bindings:
    - group_revision_ref: embodied-resource-group-revision://...
      membership_closure_hash: hash
  expires_at: timestamp
  exclusive_actuator_writer_lease_ref: resource-lease://... | null
  fencing_epoch: nonnegative_integer | null
  fencing_token_hash: hash | null
  proposed_action_sequence_root: hash
  executed_action_sequence_root: hash | null
  supersedes_or_replaces_ref: embodied-action-chunk://... | null
  local_supervisor_decision:
    admitted_to_queue | clipped | replaced | rejected | expired
  command_and_segment_refs: [physical_command://... | control-segment://...]
  agentgres_operation_refs: []

SpacetimeReservationReceipt:
  receipt_id: receipt://...
  receipt_type: spacetime_reservation
  work_subject: TypedWorkSubjectBinding
  spacetime_reservation_ref: spacetime-reservation-lease://...
  fleet_mission_coordination_ref: fleet-mission-coordination://... | null
  allocation_lease_ref: fleet-mission-allocation-lease://... | null
  coordination_epoch: nonnegative_integer | null
  geometry_and_time_window_hash: hash
  uncertainty_margin_ref: policy://...
  status:
    proposed | active | consumed | expired | preempted | revoked | released |
    failed_closed
  transition_reason:
    admitted | completed | conflict | preemption | revoke | expiry |
    local_safety_override | partition | policy | other
  local_safety_override_refs: [receipt://...]
  agentgres_operation_refs: []
```

Resource-group bindings are optional provenance on embodied receipt families
that are not scoped to a resource group. When present, each entry must match the
exact admitted group revision, membership-closure hash, and expanded unit,
controller-binding, sensor, actuator, physical-zone, and emergency-stop leaf
refs used by the intent, envelope, command, or segment. In
`PhysicalActionExecutionReceipt` the binding and every expanded leaf array are
mandatory: the selected target, controller binding, and emergency-stop
authority must resolve inside that exact closure. Bindings never replace
`SensorEvidenceReceipt.sensor_refs`, `ActuatorCommandReceipt.actuator_ref`, or
per-leaf evidence and result refs. A later group revision cannot rewrite a
prior receipt.

Every embodied work/effect receipt carries the common
`TypedWorkSubjectBinding`. It must match the subject on the admitted
`PhysicalMissionControlEnvelope` and any fleet coordination/allocation records.
A configuration/lifecycle receipt such as graph activation may omit the field
only when it is not performed for an admitted work subject; if present, it uses
the same type. The binding never creates a generic Mission identity or inherits
authority, budget, lifecycle, acceptance, or status.

The registered v1 physical execution contract is the exact closed
`{ schema_version, receipt_envelope, body, body_hash, receipt_hash }` object
above, not the legacy flat receipt. A conforming producer must set
`receipt_envelope.input_hash` to `body.execution_request_hash`,
`receipt_envelope.output_hash` to the JCS SHA-256 of the exact physical body,
and `receipt_envelope.policy_hash` to `body.safety_envelope_hash`. `body_hash`
is the JCS SHA-256 of `{ receipt_envelope, body }`; `receipt_hash` is the
domain-separated hash over the schema version and that same canonical bundle.
Verification recomputes all four cross-bindings and the predecessor chain.

A conforming v1 execution path requires the request's `state_root_before` to
exactly equal the fresh admission state root and requires the invoker's typed
`controller_binding_ref` to exactly equal the admitted binding before
invocation. That is typed adapter identity, not cryptographic hardware identity.
Its ledger must record `Prepared` immediately before the sole controller call and
`Completed` only after normalization and bundle verification. Same key plus the
same canonical request replays a completed receipt without reinvocation; a
changed body conflicts. A restored `Prepared` entry freezes the chain and
requires reconciliation rather than retry.

Current master contains the registered contract substrate and the older
physical-action-intent admission path, but no `PhysicalActionExecutionCore`,
final controller invoker, or execution ledger implementing the behavior above.

`committed` requires `dispatched_observed`, non-empty dispatch evidence,
non-empty controller receipts, and a known after-state root. `rejected`
requires `not_dispatched_proven`, dispatch evidence, and a null after-state
root. A timeout, contradictory dispatch proof, or malformed post-invocation
outcome normalizes to `unknown` plus `dispatch_ambiguous` and remains pending
reconciliation. Agentgres admission, incident/reconciliation enrichment,
acceptance, adjudication, settlement, and signature promotion are later owner
actions; an empty `agentgres_operation_refs` list cannot be read as durable
admission. A future reference ledger may be serializable, but this contract
substrate does not provide a durable Agentgres-owned crash boundary and does not
prove native actuator mounting, cryptographic controller identity,
controller-side idempotency, or estate-wide CPAS coverage.

```json
{
  "receipt_id": "receipt://embodied_command_123",
  "receipt_type": "embodied_graph_activation | embodied_action_chunk_lineage | spacetime_reservation | physical_command_queue | physical_command | physical_telemetry | physical_replay | controller_binding | heartbeat | failsafe | sim_to_real_promotion | operator_handoff | embodied_incident | embodied_recovery",
  "work_subject": {
    "kind": "goal_run | automation_run | work_item | work_claim | service_order | physical_action_intent",
    "ref": "goal://... | automation-run://... | work_item://... | work-claim://... | order://... | intent://..."
  },
  "embodied_domain_ref": "embodied_domain://...",
  "fleet_ref": "robot_fleet://...",
  "unit_ref": "robot://...",
  "controller_binding_ref": "controller-binding://...",
  "resource_group_bindings": [
    {
      "group_revision_ref": "embodied-resource-group-revision://...",
      "membership_closure_hash": "sha256:..."
    }
  ],
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
  "work_subject": {
    "kind": "goal_run",
    "ref": "goal://physical-work-7"
  },
  "controller_binding_ref": "controller-binding://robot-a",
  "resource_group_bindings": [
    {
      "group_revision_ref": "embodied-resource-group-revision://left-arm/v3",
      "membership_closure_hash": "sha256:..."
    }
  ],
  "controller_version_ref": "registry_version://controller/v4",
  "physical_action_policy_ref": "policy://physical-action/v2",
  "safety_envelope_ref": "safety://physical-work-7",
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
or erase ambiguous-effect state; work-subject acceptance, external reconciliation,
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
  "run_id": "run://123",
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

`CollaborationTermsAcceptanceReceipt` binds a party's acceptance of one exact
terms root. It proves the declared party, signature/decision, scope, time, and
supersession posture; it does not prove objective surplus, disclose private
valuation, grant authority, award work, accept a result, or authorize payout.

```yaml
CollaborationTermsAcceptanceReceipt:
  receipt_id: receipt://...
  receipt_type: collaboration_terms_acceptance
  collaboration_terms_ref: terms://...
  collaboration_terms_root: sha256:...
  collaboration_ref: collaboration://... | null
  outcome_room_ref: outcome-room://... | null
  task_and_frontier_refs:
    - task://... | frontier://...
  order_service_and_channel_refs:
    - order://... | service://... | aiip://channel/...
  accepting_party_ref:
    system://... | domain://... | org://... | wallet://... |
    service://... | provider://...
  party_role:
    data_owner | worker_provider | compute_provider | coordinator |
    customer | auditor | regulator | insurer | verifier |
    settlement_counterparty
  participation_decision_ref: decision://... | null
  accepted_scope_root: sha256:...
  acceptance_signature_ref: signature_or_embedded
  accepted_at: timestamp
  effective_until: timestamp | null
  predecessor_acceptance_ref: receipt://... | null
  replacement_terms_ref: terms://... | null
  acceptance_status: accepted | withdrawn | superseded | revoked
  policy_hash: sha256:...
  agentgres_operation_refs: []
  assurance_stage: attested
```

Every required acceptance binds the same `terms_body_root`. A terms amendment
requires a new receipt; it cannot carry forward acceptance or retroactively
rewrite a contribution, claim, reward basis, dispute, or settlement record.
`accepted_scope_root` is the canonical hash of the referenced
`CollaborationTermsEnvelope.scope` object under
`ioi.collaboration-terms-body.v1`; the explicit collaboration, room,
task/frontier, order/service, and channel refs must match that scope. The
receipt's `effective_until` cannot exceed the accepted terms expiry unless the
terms' already accepted renewal or outstanding-obligation policy permits it.

Acceptance receipts are immutable. Withdrawal, revocation, or supersession
mints a new receipt pointing backward through `predecessor_acceptance_ref`;
the prior receipt is never updated. `replacement_terms_ref` is valid only on
the new supersession receipt and names the replacement whose root receives its
own acceptance.

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
  "active_collaboration_terms_ref": "terms://joint-service-outcome/v1",
  "active_collaboration_terms_root": "sha256:...",
  "party_terms_acceptance_refs": [
    "receipt://terms/customer-a",
    "receipt://terms/provider-b"
  ],
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
  "settlement_policy": {
    "default_settlement_mode": "local_domain",
    "allowed_settlement_modes": ["local_domain", "invoice", "external_escrow"],
    "settlement_profile_refs": ["policy://..."],
    "party_network_enrollment_refs": [],
    "public_commitment_policy_ref": "policy://... | null"
  },
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
  "receipt_type": "outcome_room_admission | outcome_room_discovery_publication | room_participation_decision | participant_state_export | room_participant_lease | work_frontier_mutation | work_claim_lease | resource_offer_allocation | attempt_admission | finding_admission | verifier_challenge | work_result | outcome_delta_admission | contribution_admission",
  "system_id": "system://outcome-room/research-123",
  "outcome_room_ref": "outcome-room://research-123",
  "package_id": "package://ioi/outcome-room",
  "manifest_ref": "package://ioi/outcome-room/release/1.0.0",
  "genesis_ref": "genesis://outcome-room/research-123",
  "constitution_ref": "constitution://outcome-room/research-123/v1",
  "active_profile_refs": {
    "deployment": "deployment-profile://...",
    "ordering_admission_finality": "ordering-profile://...",
    "oracle_evidence": ["oracle-evidence-profile://..."],
    "lifecycle_continuity": "lifecycle-profile://...",
    "network_enrollment": null
  },
  "coordination_topology": "hosted_admission | federated_admission",
  "admission_owner_or_policy_ref": "system://room-host | domain://room-host | policy://federated-admission-v1",
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
    "outcome-delta://delta-8",
    "contribution://contribution-12"
  ],
  "actor_and_affiliation_refs": [
    "participant-lease://worker-a",
    "system://operator-a",
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
  "expected_room_revision": 41,
  "resulting_room_revision": 42,
  "sequence": 42,
  "expected_predecessor_commitment_ref": "commitment://outcome-room/research-123/41",
  "operation_or_batch_commitment": "sha256:...",
  "admission_decision_ref": "decision://room-admission/42",
  "admission_proof_ref": "evidence://... | receipt://...",
  "resulting_transition_commitment_ref": "commitment://outcome-room/research-123/42",
  "predecessor_room_state_root": "sha256:...",
  "resulting_room_state_root": "sha256:...",
  "resulting_receipt_root": "sha256:...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "status": "proposed | admitted | challenged | superseded | rejected | revoked"
}
```

Receipt-specific obligations:

- `OutcomeRoomAdmissionReceipt` binds the package/release root, genesis ref,
  stable system identity, constitution root, active deployment/ordering/oracle/
  lifecycle/enrollment refs, authority decision, sequence-zero origin
  commitment, initial state and receipt roots, room mode, objective,
  acceptance/stop policies, coordination topology, shared-state admission
  owner, ontology profiles, privacy, contribution, artifact/export, verifier,
  budget, and settlement policies.
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
  affiliation and dependency disclosure, exact collaboration terms root and
  terms-acceptance receipt, visibility, context, resource, authority and budget
  leases, TTL, heartbeat, wake condition, quarantine, and revocation.
- `WorkFrontierMutationReceipt` binds the predecessor and resulting frontier,
  dependencies, priority/uncertainty, duplication policy, admission decision,
  and reason for course correction.
- `WorkClaimLeaseReceipt` binds bounded scope, claimant, exact collaboration
  terms root and acceptance receipt, task offer/response and routing decision
  when selected, quote, budget reservation, settlement profile, concurrency,
  independent-replication policy, TTL, heartbeat, release, expiry,
  reassignment, and quarantine. The claim receipt cannot outlive the accepted
  terms or acceptance receipt unless their already accepted continuation policy
  permits it.
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
- `ContributionAdmissionReceipt` binds the exact participant lease, accountable
  contributor/operator/affiliation, attempt/finding/result lineage, assurance
  stage, and room admission spine before a contribution enters shared room
  attribution, reputation, or reward projections.

Room replay must reconstruct who joined, what each participant could see and
do, which work was open or claimed, why resources were allocated, all positive
and negative attempts, which findings were admitted or contradicted, verifier
rule changes, affected re-verification, spend, authority, contribution lineage,
and why the room changed direction.

Every room-child receipt implements the `RoomAdmittedObjectBase` proof spine:
exact participant lease or room-system issuer, expected room revision and
predecessor transition commitment, payload/operation commitment, admission
policy and decision, monotonic sequence, admission proof, resulting room
revision, transition commitment, state root, and receipt root. Dependency refs
to a worker, model, runtime, organization, or provider never replace the
participant lease that accepted the room obligation.

## Direct Improvement Gate Receipts

The current daemon emits two application-specific receipt records for the
implemented direct-proposal precursor. They are evidence of the recorded gate
path, not proof that a candidate is correct and not substitutes for the planned
Campaign receipt family below.

Saving a simulation emits `receipt://hypervisor/simulation/{simulation_id}`
with kind `hypervisor.simulation-report`. It binds the simulation and proposal
refs, deterministic report hash, scenario summary, and high-impact result. The
saved simulation report separately binds the exact proposal fingerprint,
target-base ref and hash, versioned impact assessment, and its receipt ref.

Applying a proposal emits `receipt://hypervisor/improvement/{improvement_id}`
with kind `hypervisor.improvement-applied` and retains this chain:

```yaml
DirectImprovementApplicationReceipt:
  proposal_ref: improvement-proposal://...
  proposal_kind: skill_improvement | launch_policy_suggestion | automation_readiness
  signal: string
  applied_ref: string
  evidence_refs: []
  simulation_ref: simulation-report://... | null
  report_hash: sha256:... | null
  simulation_waiver_ref: approval-request://... | null
  approval_request_ref: approval-request://... | null
  release_control_ref: release-control://... | null
  at: timestamp
```

An unsimulated application outside local development is attributable only when
`simulation_waiver_ref` resolves live to an approved ApprovalRequest whose exact
subject, proposal kind, current proposal fingerprint, `saved_simulation`
requirement, and approval-transition `receipt_refs` satisfy the gate. The
application receipt retains that waiver ref; it does not copy the ApprovalRequest
or transition receipt into a second authority record. Saved-simulation paths
retain `simulation_ref` and `report_hash`; high-impact paths additionally retain
their approval and release refs. Provenance joins those owner records rather
than inferring governance from non-null strings.

These current records must converge on the portable `ReceiptEnvelope` identity,
assurance, issuer, policy, and Agentgres admission contract before they are
advertised as portable verified receipts. Their present implementation proves
daemon-attributable chain retention only.

## Bounded Improvement Campaign Receipts

Campaign receipts make adaptive improvement reconstructable without turning a
score, statistical decision, or receipt into promotion authority. The schemas
below are profiles over the canonical objects in
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md);
they do not duplicate campaign state.

```json
{
  "receipt_id": "receipt://improvement/...",
  "receipt_type": "improvement_agenda_revision | improvement_campaign_admission | improvement_campaign_lifecycle | evaluation_epoch | evaluation_exposure | improvement_order_cutoff | improvement_evidence_claim",
  "improvement_agenda_revision_ref": "improvement-agenda://.../revision/... | null",
  "improvement_campaign_ref": "improvement-campaign://... | null",
  "campaign_contract_root": "sha256:... | null",
  "coordinating_goal_run_ref": "goal://... | null",
  "goal_run_profile_revision_ref": "goal-run-profile://.../revision/... | null",
  "resolved_component_set_hash": "sha256:... | null",
  "evaluation_epoch_ref": "evaluation-epoch://... | null",
  "evaluation_epoch_root": "sha256:... | null",
  "target_ref": "string | null",
  "target_base_root": "sha256:... | null",
  "candidate_ref": "attempt://... | artifact://... | package://... | null",
  "candidate_root": "sha256:... | null",
  "target_improvement_order": "nonnegative_integer | null",
  "pursuit_method_order": "positive_integer | null",
  "resource_statistical_risk_and_exposure_reservation_refs": [],
  "learning_evidence_eligibility_refs": [],
  "learning_egress_receipt_refs": [],
  "denied_or_quarantined_information_class_refs": [],
  "evaluator_and_custodian_refs": [],
  "previous_head_or_cutoff_root": "sha256:... | null",
  "resulting_head_or_cutoff_root": "sha256:... | null",
  "policy_and_decision_refs": [],
  "agentgres_operation_refs": [],
  "status": "proposed | admitted | active | paused | stopped | closed | challenged | invalidated | rejected"
}
```

Receipt-specific obligations:

- `ImprovementAgendaRevisionReceipt` binds the immutable released agenda root,
  owner, target graph, portfolio-allocation policy, release decision, and
  predecessor revision. It grants no campaign or target authority.
- `ImprovementCampaignAdmissionReceipt` binds the exact campaign contract,
  owner-scope improvement-governance snapshot and, when System-scoped,
  constitution, target/incumbent roots, selected GoalRunProfile resolution,
  target-order path and ceilings, learning boundary, accountable roles, and
  disjoint ancestor reservations.
- `ImprovementCampaignLifecycleReceipt` binds start, pause, stop, close, or
  supersession against the expected operation head. It cannot rewrite the
  campaign contract or erase attempts and findings.
- `EvaluationEpochReceipt` binds freeze, activation, challenge, close,
  invalidation, or rotation to the immutable target, incumbent, component,
  evaluator, metric, hard-constraint, test, budget, and leakage-policy root.
- `EvaluationExposureReceipt` binds candidate-family commitment, drawn-suite
  commitment, information-return class, access/execution evidence,
  contamination posture, reserved or spent exposure, and the previous ledger
  head without disclosing sealed material to Search.
- `ImprovementOrderCutoffReceipt` binds one source campaign/epoch/archive root,
  one adjacent target-order edge, target-generation cutoff, destination base
  root, eligible and denied evidence, learning eligibility, conditional egress,
  custody/access evidence, sync-wave ID, and previous cutoff root. It says only
  what was eligible at that cutoff; later evaluation, activation, or production
  success requires separate receipts.
- `ImprovementEvidenceClaimReceipt` binds an immutable claim artifact, its claim
  class, target lineage, budget and environment, transfer scope, evaluator
  validity, statistical analysis, reproduction, limitations, and supporting or
  disputing lifecycle refs. It is evidence, never authority.

Candidate attempts, Findings, WorkResults, VerifierChallenges,
UpgradeProposals, UpgradeDecisions, release activation, regression, rollback,
recall, containment, compensation, and residual irreversible-effect records
retain their existing owners and receipt types. Provenance joins those refs into
the complete campaign view; no aggregate campaign receipt may claim facts those
owners have not recorded.

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
  "evidence_bundle_refs": ["assurance-evidence://bundle", "evidence://agentgres-bundle"],
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
  "settlement_mode": "local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1",
  "settlement_profile_ref": "policy://...",
  "network_enrollment_ref": "network-enrollment://... | null",
  "public_commitment_policy_ref": "policy://... | null",
  "public_commitment_refs": ["commitment://... | settlement://... | tx://..."],
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
  "data_recipe_revision_ref": "data-recipe://construction/estimate-normalization/revision/v1",
  "data_recipe_content_hash": "sha256:...",
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
  "data_recipe_refs": ["data-recipe://.../revision/..."],
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
  "run_id": "run://123",
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
  "data_recipe_refs": ["data-recipe://.../revision/..."],
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
  "cycle_id": "post-training-cycle://123",
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

Routing decision receipts are declared once in
[`Routing Decision Receipts`](#routing-decision-receipts). This legacy receipt
catalog does not redeclare or override that canonical schema/registry owner.

Training receipts bind declared training-lineage and dataset/evaluation
commitments. Context mutation receipts bind versioned supersession rather than
silent memory overwrite. Promotion receipts bind whether a context, adapter,
route-policy, evaluation, or package update passed or failed declared gates.
Benchmark receipts bind the run, profile, evaluator, and reported performance.
Routing receipts bind selection under a declared candidate set and policy.
None of these receipts alone proves capability quality, external correctness,
acceptance, economic value, or universal worker superiority.

## Autonomous-System Module And State-Transition Commitment Receipts

Governed autonomous-system chains use service-module invocations as typed
transition boundaries. The receipt binds the specific invocation; Agentgres
records the accepted operation and state roots; an explicitly selected service
such as IOI L1 anchors only the roots named by the system's enrollment and
settlement profiles.

```json
{
  "receipt_id": "receipt://module_123",
  "receipt_type": "module_invocation",
  "module_id": "module://policy.evaluate.spend_limit.v3",
  "invocation_id": "invocation://123",
  "system_id": "system://customer-ops",
  "hypervisor_node_id": "node://local-hypervisor",
  "acting_node_membership_ref": "node-membership://customer-ops/local",
  "ordering_admission_finality_profile_ref": "ordering-profile://customer-ops/single-writer-v1",
  "writer_epoch": 1,
  "ordering_or_finality_proof_ref": null,
  "sequence": 42,
  "expected_predecessor_commitment_ref": "commitment://customer-ops/transition/41",
  "operation_or_batch_commitment": "sha256:...",
  "resulting_transition_commitment_ref": "commitment://customer-ops/transition/42",
  "admission_proof_ref": "receipt://admission_42",
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
  "change_class": "release_upgrade | ordinary_upgrade | constitutional_amendment | deployment_change | membership_change | lifecycle_transition | network_enrollment_change",
  "target_kind": "package_release | service_module | workflow_graph | policy_module | model_route | tool_binding | settlement_rule | constitution | deployment_profile | node_membership | failover_profile | ordering_admission_finality_profile | oracle_evidence_profile | lifecycle_continuity_profile | network_enrollment",
  "target_ref": "module://...",
  "diff_ref": "artifact://...",
  "simulation_receipt_refs": ["receipt://..."],
  "benchmark_receipt_refs": ["receipt://..."],
  "decision": "approved | rejected | escalated | rolled_back",
  "policy_hash": "sha256:...",
  "public_commitment_ref": "commitment://... | settlement://... | tx://... | null"
}
```

```json
{
  "receipt_id": "receipt://state_transition_commitment_123",
  "receipt_type": "state_transition_commitment",
  "system_id": "system://...",
  "hypervisor_node_id": "node://...",
  "acting_node_membership_ref": "node-membership://...",
  "ordering_admission_finality_profile_ref": "ordering-profile://...",
  "writer_epoch": "nonnegative_integer | null",
  "ordering_or_finality_proof_ref": "evidence://... | null",
  "sequence": 43,
  "expected_predecessor_commitment_ref": "commitment://...",
  "operation_or_batch_commitment": "sha256:...",
  "resulting_transition_commitment_ref": "commitment://...",
  "admission_proof_ref": "evidence://... | receipt://...",
  "transition_kind": "module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation",
  "operation_ref": "agentgres://operation/...",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "receipt_root": "sha256:...",
  "external_settlement_ref": "settlement://... | null"
}
```

The state-transition commitment receipt binds a writer epoch only when the active profile
requires one. Threshold/BFT/external-finality records bind their declared
ordering or finality proof instead.

### Autonomous-System Control And Continuity Receipts

Constitution, deployment, membership, failover, ordering/finality, oracle,
lifecycle, and network-enrollment changes use the common receipt base plus the
following binding fields:

```yaml
autonomous_system_control_receipt:
  receipt_type:
    constitution_proposal | constitution_decision | constitution_activation |
    autonomous_system_genesis | autonomous_system_activation |
    node_membership_admission | node_membership_transition | state_catchup |
    state_root_verification | writer_promotion | writer_fencing |
    deployment_conformance | failover_evaluation | single_writer_restore |
    ordering_finality_recovery |
    lifecycle_transition |
    migration | succession | dissolution | network_enrollment_transition |
    network_service_activation | network_exit
  system_id: system://...
  genesis_ref: genesis://... | null
  package_id: package://... | null
  manifest_ref: package://.../release/... | null
  admitted_manifest_root: hash | null
  constitution_root: hash
  acting_hypervisor_node_id: node://... | null
  acting_node_membership_ref: node-membership://... | null
  membership_epoch: nonnegative_integer | null
  writer_epoch: nonnegative_integer | null
  ordering_or_finality_proof_ref: evidence://... | null
  ordering_recovery_ref: ordering-recovery://... | null
  sequence: nonnegative_integer | null
  expected_predecessor_commitment_ref: commitment://... | null
  operation_or_batch_commitment: hash | null
  resulting_transition_commitment_ref: commitment://... | null
  admission_proof_ref: evidence://... | receipt://... | null
  target_profile_or_membership_ref: string
  predecessor_target_root: hash | null
  resulting_target_root: hash | null
  predecessor_system_state_root: hash | null
  resulting_system_state_root: hash | null
  resulting_receipt_root: hash | null
  proposal_ref: proposal://... | null
  decision_ref: decision://... | null
  authority_grant_refs: []
  evidence_refs: []
  challenge_or_dispute_refs: []
  observed_topology_ref: agentgres://... | null
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
```

Each named profile adds only its subject facts. Membership admission binds the
node identity, roles, failure-domain evidence, and membership epoch. State
catch-up binds checkpoint, log offsets, and verified root. Single-writer
promotion binds the old and new writer, incremented epoch, catch-up receipt,
and fencing evidence. Threshold/BFT/external-finality recovery uses a typed
`OrderingFinalityRecoveryEnvelope` and receipt binding the active profile,
expected predecessor commitment/root, view/round or membership transition,
decision/authority, recovery proof, and resulting commitment/root/finality
proof; it does not invent a writer epoch. Lifecycle receipts bind disposition of active work, authority,
data, assets, and obligations. Network receipts bind exact services, terms,
assurance, bond/stake or fee basis, and exit obligations. A proposed topology
or a successful API call is not an observed-readiness, failover, or assurance
receipt.

`SingleWriterRestoreReceipt` binds same-admitted-node restart versus governed
replacement, checkpoint/log continuity proof, predecessor and resulting state/
transition roots, node incarnation, governing decision/authority, work-lease
reconciliation, and—when replacement or the restore policy requires it—the new
writer epoch and displaced-writer fencing evidence. A fail-closed unavailable
profile emits no restore success receipt.

`AutonomousSystemGenesisReceipt` and `AutonomousSystemActivationReceipt` bind
the reusable package/release root, one new stable `system_id`, constitution
root, initial deployment/ordering/oracle/lifecycle/enrollment refs, governing
decision and authority, sequence zero, genesis operation/transition commitment,
initial state root, and initial receipt root. They are the receipt sources for
the Genesis status projection and the `initialize`/`activate` lifecycle
transitions; package publication or a successful create call is not activation.

```yaml
network_service_invocation_receipt:
  receipt_type: network_service_invocation
  network_service_invocation_ref: network-service-invocation://...
  system_id: system://... | null
  subject_ref: string
  service_kind: registry | rights | reputation | finality
  service_subprofile: worker_license | artifact_license | dataset_license | handoff_finality | null
  operation: register | publish | commit | issue | transfer | revoke | finalize | challenge
  service_ref: service://...
  network_or_domain_ref: network://... | domain://...
  network_enrollment_ref: network-enrollment://... | null
  request_root: hash
  expected_predecessor_commitment_ref: commitment://... | null
  resulting_commitment_ref: commitment://... | tx://... | null
  decision_ref: decision://... | null
  authority_grant_refs: []
  public_commitment_policy_ref: policy://... | null
```

This receipt proves only the selected service operation. It does not prove that
the subject is correct, accepted, economically settled, or covered by services
that were not selected. Fees for the invocation retain their independent
`SettlementEnvelope` and rail.

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
  "delivery_id": "delivery://123",
  "delivery_type": "service_order | worker_invocation | workflow_run",
  "order_id": "optional",
  "worker_invocation_id": "optional",
  "run_ids": ["run://123"],
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
    "operation_ref": "agentgres://operation/789",
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
  "run_id": "run://123",
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
6. Optional TUI, SDK, ADK, Workflow Compositor, Developer Workspace, and Hypervisor
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
13. Autonomous-system receipts bind the stable logical system and the acting
    node membership separately; a `hypervisor_node_id` alone is insufficient.
14. Writer-promotion evidence is invalid without catch-up/root verification, a
    higher writer epoch, and old-writer fencing. Ambiguous partition fails closed.
15. Network connection, payment, or registration receipts prove only their
    selected service facts; they do not imply Standard DAS conformance or shared
    security.
16. A learning-egress receipt proves only its declared admission and transfer
    boundary facts; it never proves provider-internal deletion, non-training,
    non-aggregation, or confidential processing by implication.
17. `blocked_before_egress` reaches verified assurance only with enforcement
    evidence binding the request commitment and absence of a network write.
18. Information-flow receipts bind label and tool-contract revisions plus exact
    hashes; they never copy protected effect bytes or reviewed plaintext.
19. A declassification receipt cannot upgrade origin, integrity, provenance, or
    instruction authority and cannot override private-plus-untrusted refusal.
20. Planned propagation through HTTP connectors, MCP tools, hosted models,
    guarded browser navigation, memory write/edit, and OutcomeRoom does not
    create an estate-wide receipt family by declaration. Each implemented
    boundary needs its own emitted decision/derivation evidence before making
    receipt-level assurance; current contract substrate supplies neither
    production propagation nor receipt coverage by implication.
