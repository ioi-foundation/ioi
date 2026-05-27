# Events, Receipts, and Delivery Bundles

Status: canonical low-level reference.
Canonical owner: this file for runtime events, receipts, delivery bundles, trace bundles, and quality records.
Supersedes: overlapping event/receipt examples in plans/specs when event, trace, or receipt fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-25.

## Purpose

Events enable observation; receipts enable proof; replay enables inspection;
delivery bundles enable marketplace settlement. These objects must be consistent
across Autopilot Workbench, IOI daemon, Agentgres, aiagent.xyz, sas.xyz, and
wallet.network.

The IOI daemon emits these objects as the autonomous-execution
hypervisor/control plane. Autopilot Workbench, CLI/TUI, SDK, ADK, harnesses,
benchmarks, and extension-host code may project or inspect them, but they must
not mint private runtime truth for consequential work.

## Runtime Events

Required event kinds:

```text
session.started
thread.created
thread.resumed
thread.forked
thread.mode_changed
thread.model_route_changed
thread.thinking_changed
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
delegation.started
delegation.completed
subagent.spawned
subagent.input_sent
subagent.assigned
subagent.cancelled
subagent.completed
handoff.recorded
stop_condition.recorded
scorecard.updated
usage.delta
usage.final
workspace_trust.warning
workspace_trust.acknowledged
workspace_snapshot.created
workspace_restore.previewed
workspace_restore.applied
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
training.batch_planned
training.generation_batch_archived
training.quality_gates_reported
training.cost_ledger_updated
training.dataset_curated
training.context_mutated
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
ValidationReceipt
MergeReceipt
SettlementReceipt
LocalSettlementReceipt
DeliveryReceipt
ContributionReceipt
QualityReceipt
DataRecipeRunReceipt
TransformationReceipt
OntologyProjectionReceipt
UpgradeProposalReceipt
UpgradeDecisionReceipt
TrainingTraceReceipt
TrainingBatchPlanReceipt
GenerationBatchReceipt
QualityGateReportReceipt
TrainingCostLedgerReceipt
DatasetCurationReceipt
ContextMutationReceipt
PostTrainingCycleReceipt
PromotionDecisionReceipt
BenchmarkRunReceipt
EvaluationVerdictReceipt
RoutingDecisionReceipt
RuntimeAttestationReceipt
RuntimeBridgeReceipt
RuntimeUsageReceipt
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

## ToolExecutionReceipt

```json
{
  "receipt_id": "receipt_tool_123",
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

## Worker Training Receipts

Data recipe, transformation, Worker Training, benchmark, evaluation, ontology
projection, and MoW routing receipts are specialized receipts. They are not new
artifact classes and they do not bypass the normal receipt semantics: canonical
input, policy hash, actor identity, artifact refs, timestamps, and signatures
still apply.

```json
{
  "receipt_id": "receipt_recipe_123",
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
  "receipt_id": "receipt_training_123",
  "receipt_type": "training_batch_plan | generation_batch | quality_gate_report | training_cost_ledger | training_trace | dataset_curation | context_mutation | post_training_cycle | promotion_decision",
  "training_id": "train_123",
  "target_worker_id": "worker://...",
  "run_id": "run_123",
  "batch_plan_ref": "batch://...",
  "generation_batch_ref": "batch://...",
  "quality_gate_report_ref": "gate://...",
  "training_cost_ledger_ref": "ledger://...",
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
  "receipt_id": "receipt_promotion_123",
  "receipt_type": "promotion_decision",
  "cycle_id": "ptc_123",
  "worker_id": "worker://...",
  "candidate_ref": "cid://...",
  "baseline_version": "worker://...@1.0.1",
  "candidate_version": "worker://...@1.0.2-candidate",
  "eval_profile_ref": "benchmark://...",
  "regression_receipt_refs": ["receipt://eval_123"],
  "decision": "promoted | rejected | rolled_back",
  "rollback_ref": "optional",
  "policy_hash": "sha256:..."
}
```

```json
{
  "receipt_id": "receipt_benchmark_123",
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
  "receipt_id": "receipt_route_123",
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

Training receipts prove training lineage and dataset/evaluation commitments.
Context mutation receipts prove versioned supersession rather than silent memory
overwrite. Promotion receipts prove that a context, adapter, route-policy,
evaluation, or package update passed or failed declared gates. Benchmark
receipts prove performance under declared profiles. Routing receipts prove
legible selection under a declared candidate set and policy. None of these
receipts prove universal worker superiority.

## Autonomous-System Module and Local Settlement Receipts

Governed autonomous-system chains use service-module invocations as typed
transition boundaries. The receipt proves the specific invocation; Agentgres
records the accepted operation and state roots; IOI L1 anchors only selected
roots when public trust, dispute, reputation, or economic settlement requires
them.

```json
{
  "receipt_id": "receipt_module_123",
  "receipt_type": "module_invocation",
  "module_id": "module://policy.evaluate.spend_limit.v3",
  "invocation_id": "invocation://123",
  "autonomous_system_chain_id": "system://customer-ops",
  "autopilot_node_id": "node://local-workbench",
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
  "receipt_id": "receipt_upgrade_123",
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
  "receipt_id": "receipt_local_settlement_123",
  "receipt_type": "local_settlement",
  "autopilot_node_id": "node://...",
  "autonomous_system_chain_id": "system://...",
  "settlement_kind": "module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation",
  "operation_ref": "agentgres://operation/...",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "receipt_root": "sha256:...",
  "l1_anchor_ref": "optional"
}
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
      "privacy_class": "shared_encrypted"
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
  "contribution_refs": ["contrib_123"],
  "settlement": {
    "l1_contract": "0x...",
    "status": "pending_acceptance"
  }
}
```

Agentgres owns the delivery state: whether the delivery happened, what state
changed, which receipts are required, which artifacts exist, which
quality/contribution ledgers update, and which projections/subscriptions should
advance. Filecoin/CAS owns the heavy immutable payloads: artifact bytes,
receipt/evidence bundles, trace bundles, screenshots/videos, reports, and
archival checkpoint files.

## SessionTraceBundle

```json
{
  "trace_bundle_id": "trace_123",
  "run_id": "run_123",
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
6. TUI, SDK, ADK, agent-ide, and Autopilot controls must leave the same event
   and receipt trail when they mutate runtime state.
