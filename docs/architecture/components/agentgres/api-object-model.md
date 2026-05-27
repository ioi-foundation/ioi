# Agentgres API and Object Model

Status: canonical low-level reference.
Canonical owner: this file for Agentgres APIs, canonical object classes, runtime v0 state, operation logs, projection watermarks, and replay/export authority; bridge/readiness semantics live in [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).
Supersedes: older Agentgres-as-generic-store wording when runtime truth ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-25.

## Purpose

Agentgres is the per-domain state substrate. It stores operational truth, not IOI L1 economic settlement. Each serious Web4 application domain runs its own kernel/runtime deployment with its own Agentgres domain.

Agentgres is also not a thin index over Filecoin/CAS blobs. Its operation log,
object heads, constraints, indexes, projections, subscriptions, receipt
metadata, delivery state, and quality/contribution ledgers are canonical
Agentgres state. Filecoin/CAS stores immutable payload bytes, sealed archive
bytes, and large evidence objects that Agentgres references by hash/CID.

For governed autonomous-system chains and Autopilot nodes, Agentgres records
the local/domain operational truth: proposals, service-module invocations,
local settlement records, state roots, receipt roots, upgrade decisions, and
replayable projections.

## Core API

```http
GET  /v1/domain/manifest
GET  /v1/domain/status
POST /v1/operations
GET  /v1/operations/{operation_id}
GET  /v1/objects/{object_class}/{object_id}
GET  /v1/objects/{object_class}/{object_id}/history
POST /v1/query
POST /v1/subscriptions
GET  /v1/projections
GET  /v1/projections/{projection_id}
POST /v1/projections/{projection_id}/rebuild
GET  /v1/indexes
GET  /v1/constraints
POST /v1/schema/migrations
GET  /v1/schema/migrations/{migration_id}
POST /v1/schema/migrations/{migration_id}/validate
POST /v1/schema/migrations/{migration_id}/commit
POST /v1/schema/migrations/{migration_id}/rollback
POST /v1/sql/query
GET  /v1/receipts/{receipt_id}
GET  /v1/artifacts/{artifact_id}
GET  /v1/domain-ontologies
POST /v1/domain-ontologies
GET  /v1/domain-ontologies/{ontology_id}
POST /v1/canonical-object-models
POST /v1/data-recipes
POST /v1/data-recipes/{recipe_id}/run
GET  /v1/data-recipes/{recipe_id}/runs
POST /v1/connector-mappings
POST /v1/policy-bound-data-views
POST /v1/distilled-ontology-datasets
POST /v1/evaluation-datasets
POST /v1/ontology-projections
POST /v1/ontology-to-worker-plans
POST /v1/autopilot-nodes
POST /v1/autonomous-system-chains
POST /v1/service-modules
POST /v1/module-invocations
POST /v1/upgrade-proposals
POST /v1/upgrade-proposals/{proposal_id}/decisions
POST /v1/local-settlements
POST /v1/worker-training
POST /v1/worker-training/{training_id}/batch-plans
POST /v1/worker-training/{training_id}/generation-batches
POST /v1/worker-training/{training_id}/quality-gate-reports
POST /v1/worker-training/{training_id}/cost-ledgers
```

## Archive/Restore API

```http
POST /v1/sealed-state-archives
GET  /v1/sealed-state-archives/{archive_id}
POST /v1/sealed-state-archives/{archive_id}/verify
POST /v1/sealed-state-archives/{archive_id}/restore
```

Sealed state archives are cold-state artifacts, not canonical live state. Hot
Agentgres keeps the authoritative archive refs, lifecycle status, roots, policy,
schema, authority, and receipt metadata. Filecoin/CAS, S3, local disk, or other
durable stores hold the encrypted bytes by CID/hash.

## Patch/Change API

```http
POST /v1/intents
POST /v1/scope-leases
POST /v1/workspace-snapshots
GET  /v1/workspace-snapshots/{snapshot_id}
POST /v1/patches
GET  /v1/patches/{patch_id}
POST /v1/patches/{patch_id}/validate
POST /v1/patches/{patch_id}/rebase
POST /v1/patches/{patch_id}/merge
POST /v1/patches/{patch_id}/settle
POST /v1/patches/{patch_id}/reject
POST /v1/revert-operations
```

Patch lifecycle:

```text
Intent → ScopeLease → Patch → Validate → Merge → Settle → Project → Query → Retain
```

Patch branches are isolated draft spaces. Workers do not mutate canonical
file/object heads directly. A patch merge binds the base snapshot, expected
heads, resulting heads, validation receipts, policy hash, scope lease refs, and
merge decision.

```json
{
  "patch_id": "patch_A",
  "branch_id": "branch_agent_7_task_12",
  "base_state_root": "sha256:R1",
  "expected_heads": {
    "file://src/parser.ts": "sha256:P1"
  },
  "resulting_heads": {
    "file://src/parser.ts": "sha256:P2A"
  },
  "changed_artifact_refs": ["artifact://patch_A/parser.ts"],
  "validation_receipt_refs": ["receipt_validate_A"],
  "scope_lease_refs": ["lease_symbol_parse_expression"]
}
```

Validation receipts must identify the frozen target they checked:

```json
{
  "validation_target": "patch_branch",
  "base_state_root": "sha256:R1",
  "patch_id": "patch_A",
  "dependency_state": "pinned"
}
```

If canonical heads have advanced since the patch base, Agentgres must rebase,
auto-merge, repair, revalidate, reject, or route the merge to a planner/reviewer
before settlement.

## Canonical Object Classes

```text
Tenant
User
Role
Policy
PolicyDecision
AuthorityGrantRef
AutopilotNode
AutonomousSystemChain
ServiceModuleManifest
ModuleInvocation
UpgradeProposal
UpgradeDecision
LocalSettlementRecord
SchemaDefinition
SchemaMigration
ConstraintDefinition
InvariantDefinition
InvariantCheck
ConstraintViolationReceipt
IndexDefinition
ProjectionQuery
Task
Run
TaskState
WorkerInstall
ManagedWorkerInstance
WorkerInvocation
DomainOntology
CanonicalObjectModel
DataRecipe
ConnectorMapping
PolicyBoundDataView
TransformationRun
TransformationReceipt
DistilledOntologyDataset
EvaluationDataset
OntologyProjection
OntologyToWorkerPlan
ModelCapacityProfile
TrainingBatchPlan
GenerationBatch
RawBatchArchive
QualityGateReport
TrainingCostLedger
WorkerTraining
DatasetCommitment
TrainingLineage
ContextMutation
PostTrainingCycle
PromotionDecision
BenchmarkSubmission
BenchmarkRun
EvaluationVerdict
MoWRoutingDecision
ServiceOrder
OutcomeWorkspace
RuntimeAssignment
ComputeSession
RuntimeSubscription
DeliveryBundle
Approval
ScopeLease
FileObject
FileVersion
WorkspaceSnapshot
PatchBranch
TaskBranch
Patch
ValidationReceipt
BuildReceipt
MergeDecision
RevertOperation
RollbackReceipt
ExecutionReceipt
ArtifactRef
EvidenceBundle
QualityRecord
Scorecard
StopCondition
OperationLogEntry
AgentStateArchive
ArchiveReceipt
RestoreReceipt
AccountRuntimeProfile
DeviceRegistration
RestoreLifecycleRecord
ComputeEntitlementRef
ContributionReceipt
UsageReceipt
ReputationRecord
ProjectionDefinition
ProjectionEngineAdapter
ProjectionEngineCheckpoint
ProjectionEngineHealth
ProjectionFreshnessSLO
ProjectionRebuildPlan
ProjectionCheckpoint
CommitLogSegment
DomainSequenceCheckpoint
DisputeRecord
SettlementMirror
```

## Domain Manifest

```json
{
  "domain_id": "agentgres://domain/aiagent.xyz",
  "domain_type": "marketplace | service | control_plane | local | enterprise | app",
  "kernel_id": "kernel://aiagent.xyz/main",
  "schema_version": 12,
  "state_root": "sha256:...",
  "watermark": "domain_seq:99182",
  "l1_contracts": {
    "worker_registry": "0x...",
    "license_registry": "0x..."
  },
  "projections": ["worker_search", "quality_rankings", "install_state", "managed_instances"]
}
```

## Autopilot Node and Autonomous-System Chain Shapes

```json
{
  "object_class": "AutopilotNode",
  "autopilot_node_id": "node://local-workbench",
  "owner_id": "wallet://user_123",
  "daemon_runtime_ref": "runtime://local",
  "agentgres_domain_ref": "agentgres://domain/autopilot/local",
  "wallet_authority_ref": "wallet://user_123",
  "autonomous_system_chain_refs": ["system://customer-ops"],
  "local_registry_refs": ["agentgres://registry/modules"],
  "receipt_root": "sha256:...",
  "latest_local_settlement_id": "transition://...",
  "status": "local | hosted | hybrid | enterprise | archived"
}
```

```json
{
  "object_class": "AutonomousSystemChain",
  "autonomous_system_chain_id": "system://customer-ops",
  "autopilot_node_id": "node://local-workbench",
  "manifest_ref": "ai://systems/customer-ops",
  "policy_root": "sha256:...",
  "module_registry_root": "sha256:...",
  "proposal_queue_root": "sha256:...",
  "latest_state_root": "sha256:...",
  "latest_receipt_root": "sha256:...",
  "latest_transition_id": "transition://...",
  "upgrade_policy_ref": "policy://...",
  "status": "draft | active | paused | archived | revoked"
}
```

```json
{
  "object_class": "ModuleInvocation",
  "module_invocation_id": "invocation://123",
  "module_id": "module://policy.evaluate.spend_limit.v3",
  "autonomous_system_chain_id": "system://customer-ops",
  "autopilot_node_id": "node://local-workbench",
  "input_hash": "sha256:...",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "policy_hash": "sha256:...",
  "authority_grant_refs": ["grant://..."],
  "receipt_refs": ["receipt://..."],
  "status": "proposed | admitted | executed | verified | committed | rejected | failed"
}
```

```json
{
  "object_class": "LocalSettlementRecord",
  "local_settlement_id": "transition://123",
  "autopilot_node_id": "node://local-workbench",
  "autonomous_system_chain_id": "system://customer-ops",
  "settlement_kind": "module_invocation | workflow_transition | authority_outcome | task_handoff | upgrade_decision | receipt_root | dispute_escalation",
  "operation_ref": "agentgres://operation/op_123",
  "predecessor_state_root": "sha256:...",
  "resulting_state_root": "sha256:...",
  "receipt_root": "sha256:...",
  "l1_anchor_ref": "optional"
}
```

## Operation Shape

```json
{
  "operation_id": "op_123",
  "domain_id": "agentgres://domain/aiagent.xyz",
  "actor_id": "agent://... | wallet://... | runtime://...",
  "operation_type": "WorkerInvocationCreated",
  "object_class": "WorkerInvocation",
  "object_id": "invocation_123",
  "expected_head": "optional",
  "expected_heads": {"file://src/foo.ts": "sha256:..."},
  "base_state_root": "optional",
  "patch_id": "optional",
  "schema_version": 12,
  "policy_hash": "sha256:...",
  "authority_grant_refs": ["grant_..."],
  "payload": {},
  "payload_refs": [
    {
      "cid": "bafy...",
      "sha256": "...",
      "media_type": "application/json",
      "role": "large_payload | evidence | trace | checkpoint | sealed_state_archive"
    }
  ],
  "resulting_head": "sha256:...",
  "state_root": "sha256:...",
  "receipt_refs": []
}
```

## Database Readiness Shapes

Agentgres exposes database-like behavior through operation-backed objects,
projection queries, indexes, constraints, and migrations. The canonical
semantics live in [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).

Named consistency levels:

```text
cached_projection
projection_consistent
snapshot_consistent
state_root_consistent
linearized_domain
serializable_domain
```

Constraint and invariant objects separate ordinary object validity from Web4
action validity.

```json
{
  "object_class": "ConstraintDefinition",
  "constraint_id": "constraint://unique_worker_listing_slug",
  "constraint_type": "required_field | schema_type | unique_key | foreign_ref | check | exclusion_rule | cardinality | temporal_range",
  "object_class_scope": "WorkerListing",
  "field_refs": ["slug"],
  "deferred": false,
  "status": "active | deprecated",
  "schema_version": 12
}
```

```json
{
  "object_class": "InvariantDefinition",
  "invariant_id": "invariant://authority-before-tool-exec",
  "invariant_type": "authority | receipt | settlement | policy | temporal | projection | state_root | artifact_integrity | policy_monotonicity",
  "object_class_scope": "Run",
  "policy_hash": "sha256:...",
  "violation_receipt_required": true,
  "status": "active | deprecated"
}
```

Index definitions are replay-verifiable serving structures, not canonical truth
by themselves.

```json
{
  "object_class": "IndexDefinition",
  "index_id": "index://worker_search_v1",
  "index_family": "object_head | relation | temporal | graph_edge | authority | receipt | artifact_ref | state_root | full_text | vector_ref | projection_watermark | settlement_mirror",
  "projection_id": "worker_search",
  "field_refs": ["category", "quality_score", "routing_eligibility"],
  "checkpoint_ref": "projection_checkpoint://...",
  "status": "building | active | stale | rebuilding | deprecated"
}
```

Schema changes are operations. They should not be out-of-band DDL that mutates
canonical truth without replay evidence.

```json
{
  "object_class": "SchemaMigration",
  "migration_id": "migration://agentgres/12_to_13",
  "old_schema_version": 12,
  "new_schema_version": 13,
  "affected_object_classes": ["ManagedWorkerInstance", "RuntimeSubscription"],
  "affected_projection_ids": ["managed_instances"],
  "constraint_diff_refs": ["constraint://..."],
  "backfill_plan_ref": "artifact://...",
  "verification_receipt_refs": ["receipt://..."],
  "status": "proposed | validated | backfilling | committed | rolled_back | rejected"
}
```

SQL bridge queries are read-first over named projections. Any write-capable SQL
bridge must compile into ordinary Agentgres operations with authority, policy,
and constraint checks.

```json
{
  "object_class": "ProjectionQuery",
  "query_id": "query://...",
  "projection_id": "worker_search",
  "query_language": "agentgres_projection | sql_read_bridge",
  "consistency": "projection_consistent",
  "projection_watermark": "projection_seq:1234",
  "explain": true
}
```

## Runtime Assignment and Compute Session Shape

Domain routers use runtime assignments to bind work to execution venues.
Agentgres records the decision and lifecycle metadata; the daemon/runtime node
executes the work.

```json
{
  "runtime_assignment_id": "assign_123",
  "domain_id": "agentgres://domain/sas.xyz",
  "run_id": "run_123",
  "order_id": "order_123",
  "outcome_workspace_id": "outcome_workspace_123",
  "compute_session_id": "compute_session_123",
  "daemon_profile": "local | hosted_ioi | provider | depin | tee | customer_vpc",
  "runtime_node_id": "runtime://node_abc",
  "worker_manifest_ref": "ai://workers/runtime-auditor",
  "task_capsule_ref": "agentgres://task_capsules/cap_123",
  "authority_grant_refs": ["grant://..."],
  "verification_requirements": ["execution_receipt", "artifact_hash", "policy_hash"],
  "payment_quote_ref": "quote_123",
  "status": "planned | accepted | running | completed | failed | cancelled"
}
```

The SDK can observe or submit this record through client APIs. It is not the
runtime owner.

## Managed Worker Instance Shape

aiagent.xyz may initialize a worker as an ephemeral invocation, zero-to-idle
agent, or warm persistent instance. Agentgres records the instance lifecycle;
the IOI daemon/runtime node executes it.

```json
{
  "object_class": "ManagedWorkerInstance",
  "worker_instance_id": "agent://runtime-auditor/heath/default",
  "worker_manifest_ref": "ai://workers/runtime-auditor@1.0.0",
  "install_id": "install://install_123",
  "owner_id": "wallet://user_123",
  "runtime_assignment_id": "assign_123",
  "execution_profile": "hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc | local",
  "persistence_profile": "ephemeral | session | zero_to_idle | persistent",
  "interaction_surfaces": ["chat", "task", "api", "scheduler"],
  "subscription_ref": "subscription://sub_123",
  "memory_policy": {
    "mode": "none | session | agentgres_refs | sealed_archive",
    "archive_on_idle": true
  },
  "latest_state_root": "sha256:...",
  "latest_archive_ref": "archive://...",
  "status": "starting | running | idle | suspended | archived | failed"
}
```

Subscriptions are entitlement/accounting records. They do not make Agentgres the
compute provider.

## Domain Ontology and Data Recipe Object Shapes

Agentgres records ontology and data recipe state as canonical operational
truth. Source bytes and large transformed payloads remain in Filecoin/CAS or
another blob store by hash/CID.

```json
{
  "object_class": "DomainOntology",
  "ontology_id": "ontology://construction-estimating/v1",
  "domain_id": "agentgres://domain/sas.xyz",
  "entity_types": ["Project", "PlanSheet", "Room", "Material", "Estimate", "Quote", "ChangeOrder"],
  "relationship_types": ["contains", "priced_by", "derived_from", "approved_by"],
  "event_types": ["quote_requested", "estimate_generated", "change_order_approved"],
  "invariant_refs": ["invariant://estimate-line-items-have-source"],
  "policy_hash": "sha256:...",
  "status": "draft | active | deprecated | revoked"
}
```

```json
{
  "object_class": "DataRecipe",
  "data_recipe_id": "recipe://construction/estimate-normalization/v1",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "connector_mapping_refs": ["mapping://drive-plan-sheets", "mapping://gmail-quote-thread"],
  "output_object_model_refs": ["object-model://Estimate", "object-model://LineItem"],
  "output_distilled_dataset_refs": ["dataset://construction-estimate-distilled-v1"],
  "transformation_steps": ["extract", "redact", "normalize", "dedupe", "validate", "map", "link"],
  "policy_bound_data_view_refs": ["view://customer-estimate-training"],
  "receipt_obligations": ["data_recipe_run", "transformation"],
  "status": "draft | active | deprecated"
}
```

```json
{
  "object_class": "PolicyBoundDataView",
  "view_id": "view://customer-estimate-training",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "object_model_refs": ["object-model://Estimate", "object-model://Quote"],
  "allowed_uses": ["read", "transform", "distill", "train", "evaluate"],
  "authority_grant_refs": ["grant://..."],
  "privacy_class": "confidential",
  "policy_hash": "sha256:...",
  "expires_at": "2026-06-01T00:00:00Z"
}
```

```json
{
  "object_class": "TransformationRun",
  "transformation_run_id": "transform://123",
  "data_recipe_ref": "recipe://construction/estimate-normalization/v1",
  "input_refs": ["artifact://plans_pdf", "connector://gmail/thread_123"],
  "output_object_refs": ["agentgres://object/Estimate/est_123"],
  "output_dataset_refs": ["dataset://construction-estimate-holdout-v1"],
  "output_distilled_dataset_refs": ["dataset://construction-estimate-distilled-v1"],
  "output_artifact_refs": ["artifact://transformed_estimates"],
  "authority_grant_refs": ["grant://..."],
  "receipt_refs": ["receipt://transform_123"],
  "status": "queued | running | completed | failed | rejected"
}
```

```json
{
  "object_class": "DistilledOntologyDataset",
  "distilled_dataset_id": "dataset://construction-estimate-distilled-v1",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "data_recipe_refs": ["recipe://construction/estimate-normalization/v1"],
  "source_commitments": ["sha256:..."],
  "policy_bound_data_view_refs": ["view://customer-estimate-training"],
  "transformation_receipt_refs": ["receipt://transform_123"],
  "distillation_methods": ["teacher_distillation", "verifier_filtering", "schema_canonicalization", "failure_regression"],
  "teacher_refs": ["worker://planner-teacher"],
  "verifier_refs": ["worker://estimate-verifier"],
  "output_artifact_refs": ["artifact://distilled_estimate_examples"],
  "evaluation_dataset_refs": ["dataset://construction-estimate-holdout-v1"],
  "receipt_root": "sha256:...",
  "status": "draft | active | deprecated | revoked"
}
```

```json
{
  "object_class": "EvaluationDataset",
  "evaluation_dataset_id": "dataset://construction-estimate-holdout-v1",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "data_recipe_refs": ["recipe://construction/estimate-normalization/v1"],
  "dataset_type": "golden | holdout | adversarial | regression | benchmark | synthetic | distilled",
  "rubric_ref": "rubric://construction-estimate/v1",
  "benchmark_profile_ref": "benchmark://ioi/categories/construction_estimate/v1",
  "source_commitment": "sha256:...",
  "receipt_root": "sha256:...",
  "status": "draft | active | deprecated | revoked"
}
```

```json
{
  "object_class": "OntologyToWorkerPlan",
  "plan_id": "plan://123",
  "ontology_refs": ["ontology://construction-estimating/v1"],
  "canonical_object_model_refs": ["object-model://Estimate", "object-model://LineItem"],
  "data_recipe_refs": ["recipe://construction/estimate-normalization/v1"],
  "policy_bound_data_view_refs": ["view://customer-estimate-training"],
  "distilled_dataset_refs": ["dataset://construction-estimate-distilled-v1"],
  "evaluation_dataset_refs": ["dataset://construction-estimate-holdout-v1"],
  "benchmark_profile_refs": ["benchmark://ioi/categories/construction_estimate/v1"],
  "proposed_worker_manifest_ref": "ai://workers/construction-estimator",
  "status": "draft | proposed | training | evaluated | bound | rejected"
}
```

## Worker Training and MoW Object Shapes

Agentgres records the operational truth for Worker Training, benchmark, and
MoW routing objects. Payload bytes remain in Filecoin/CAS or another blob store
and are referenced by hash/CID.

```json
{
  "training_id": "train_123",
  "object_class": "WorkerTraining",
  "target_worker_id": "worker://...",
  "requester_id": "wallet://...",
  "provider_id": "service://...",
  "training_objective": "Train a construction estimating worker",
  "training_profile": "dense_transformer | moe | subquadratic | hybrid_attention_state | retrieval_augmented | mutable_context | adapter_trained | distillation_trained | deterministic_verifier | custom",
  "training_methods": ["workflow_trace", "retrieval_curation", "context_update", "route_policy_training", "adapter_training", "model_finetune", "distillation"],
  "dataset_commitment": "sha256:...",
  "domain_ontology_ref": "ontology://construction-estimating/v1",
  "canonical_object_model_refs": ["object-model://Estimate", "object-model://LineItem"],
  "data_recipe_refs": ["recipe://construction/estimate-normalization/v1"],
  "policy_bound_data_view_refs": ["view://customer-estimate-training"],
  "distilled_dataset_refs": ["dataset://construction-estimate-distilled-v1"],
  "evaluation_dataset_refs": ["dataset://construction-estimate-holdout-v1"],
  "model_capacity_profile_ref": "profile://construction-estimator-small-v1",
  "training_batch_plan_refs": ["batch://estimate-scope-001"],
  "raw_batch_archive_refs": ["artifact://raw-estimate-batch-001"],
  "quality_gate_report_refs": ["gate://estimate-batch-001"],
  "training_cost_ledger_ref": "ledger://train_123",
  "ontology_to_worker_plan_ref": "plan://123",
  "privacy_policy_ref": "policy://...",
  "evaluation_rubric_ref": "rubric://...",
  "context_graph_ref": "optional",
  "promotion_gate_ref": "optional",
  "output_manifest_ref": "ai://workers/...",
  "receipt_root": "sha256:...",
  "status": "proposed | running | evaluated | accepted | rejected | disputed"
}
```

```json
{
  "object_class": "ModelCapacityProfile",
  "model_capacity_profile_id": "profile://construction-estimator-small-v1",
  "training_id": "train_123",
  "target_class": "small_local | balanced_local | specialist_local | hosted_frontier | hybrid_worker | deterministic_worker | custom",
  "context_budget_tokens": 8192,
  "system_prompt_budget_tokens": 1200,
  "tool_batch_limit": 4,
  "row_structure": "structured | ontology_bound | tool_trace | mixed",
  "recommendations": [
    "structured_rows",
    "shorter_system_prompt",
    "tighter_label_set",
    "smaller_tool_batches",
    "stronger_gold_reasons"
  ],
  "status": "draft | active | superseded"
}
```

```json
{
  "object_class": "TrainingBatchPlan",
  "batch_plan_id": "batch://estimate-scope-001",
  "training_id": "train_123",
  "orchestrator_ref": "worker://training-orchestrator",
  "target_scope": "change-order estimate line items",
  "target_family": "construction-estimating",
  "label_boundary_ref": "artifact://estimate-label-boundary",
  "hard_eval_pattern_ref": "dataset://construction-estimate-hard-cases",
  "quota": {
    "target_rows": 5000,
    "target_tokens": 20000000,
    "max_cost": "optional"
  },
  "split_policy": {
    "train": 80,
    "holdout": 10,
    "golden": 5,
    "adversarial": 3,
    "regression": 2
  },
  "model_capacity_profile_ref": "profile://construction-estimator-small-v1",
  "executor_worker_refs": ["worker://generator-a", "worker://generator-b"],
  "status": "draft | running | completed | rejected | superseded"
}
```

```json
{
  "object_class": "GenerationBatch",
  "generation_batch_id": "batch://estimate-generation-001",
  "batch_plan_ref": "batch://estimate-scope-001",
  "training_id": "train_123",
  "executor_ref": "worker://generator-a",
  "input_prompt_ref": "artifact://estimate-generation-prompt",
  "raw_batch_archive_ref": "artifact://raw-estimate-batch-001",
  "row_count": 1200,
  "token_count": 1500000,
  "provider_call_count": 120,
  "cost_estimate": "optional",
  "status": "queued | running | archived | gated | rejected | failed"
}
```

```json
{
  "object_class": "RawBatchArchive",
  "raw_batch_archive_id": "artifact://raw-estimate-batch-001",
  "training_id": "train_123",
  "generation_batch_refs": ["batch://estimate-generation-001"],
  "raw_artifact_refs": ["artifact://estimate-raw-jsonl"],
  "cache_artifact_refs": ["artifact://estimate-generation-cache"],
  "provider_metadata_hash": "sha256:...",
  "prompt_hash": "sha256:...",
  "token_count": 1500000,
  "cost_estimate": "optional",
  "policy_hash": "sha256:...",
  "status": "archived | redacted | rejected | promoted_to_curation"
}
```

```json
{
  "object_class": "QualityGateReport",
  "gate_report_id": "gate://estimate-batch-001",
  "training_id": "train_123",
  "batch_plan_ref": "batch://estimate-scope-001",
  "generation_batch_ref": "batch://estimate-generation-001",
  "gate_policy_hash": "sha256:...",
  "accepted_count": 740,
  "rejected_count": 460,
  "rejection_reason_counts": {
    "schema_validity": 20,
    "duplicate_prompt": 44,
    "leakage_risk": 7,
    "low_quality_or_synthetic_pattern": 91,
    "weak_gold_reason": 58
  },
  "accepted_dataset_refs": ["dataset://construction-estimate-curated-v1"],
  "receipt_refs": ["receipt://gate_report_001"],
  "status": "draft | completed | disputed | superseded"
}
```

```json
{
  "object_class": "TrainingCostLedger",
  "training_cost_ledger_id": "ledger://train_123",
  "training_id": "train_123",
  "batch_plan_refs": ["batch://estimate-scope-001"],
  "provider_call_count": 120,
  "token_count": 1500000,
  "accepted_row_count": 740,
  "rejected_row_count": 460,
  "cost_per_accepted_row": "optional",
  "dataset_yield_summary_ref": "artifact://yield-summary",
  "status": "open | closed | disputed"
}
```

```json
{
  "cycle_id": "ptc_123",
  "object_class": "PostTrainingCycle",
  "worker_id": "worker://...",
  "trigger": "user_correction | failed_eval | benchmark_submission | teacher_distillation | scheduled_retrain",
  "allowed_training_methods": ["context_update", "adapter_training", "route_policy_training", "distillation", "eval_generation", "package_revision"],
  "source_trace_refs": ["artifact://..."],
  "candidate_artifact_ref": "cid://...",
  "eval_profile_ref": "benchmark://...",
  "promotion_gate_ref": "gate://...",
  "rollback_required": true,
  "status": "proposed | training | evaluating | promoted | rejected | rolled_back"
}
```

```json
{
  "mutation_id": "ctxmut_123",
  "object_class": "ContextMutation",
  "worker_id": "worker://...",
  "mutation_type": "fact | preference | doctrine | route | procedure | eval | failure",
  "operation": "add | supersede | contradict | deprecate | activate | archive",
  "prior_claim_refs": [],
  "evidence_refs": ["receipt://..."],
  "policy_hash": "sha256:...",
  "receipt_ref": "receipt://context_mutation_123"
}
```

```json
{
  "promotion_id": "promote_123",
  "object_class": "PromotionDecision",
  "cycle_id": "ptc_123",
  "candidate_ref": "cid://...",
  "baseline_version": "worker://...@1.0.1",
  "candidate_version": "worker://...@1.0.2-candidate",
  "eval_profile_ref": "benchmark://...",
  "regression_receipt_refs": ["receipt://eval_123"],
  "decision": "promoted | rejected | rolled_back",
  "rollback_ref": "optional",
  "receipt_ref": "receipt://promotion_123"
}
```

```json
{
  "benchmark_run_id": "bench_123",
  "object_class": "BenchmarkRun",
  "worker_id": "worker://...",
  "sparse_worker_category": "std:code:runtime_audit.v1",
  "benchmark_profile_ref": "benchmark://ioi/categories/runtime_audit/v1",
  "environment_hash": "sha256:...",
  "manifest_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "score_commitment": "sha256:...",
  "evaluation_receipt_root": "sha256:...",
  "routing_eligibility_result": "eligible | ineligible | suspended"
}
```

```json
{
  "routing_decision_id": "route_123",
  "object_class": "MoWRoutingDecision",
  "task_id": "task://...",
  "router_id": "runtime://... | system://... | domain://...",
  "intent_hash": "sha256:...",
  "candidate_set_commitment": "sha256:...",
  "routing_policy_hash": "sha256:...",
  "selected_domain_or_worker": "worker://...",
  "authority_scope": ["scope:..."],
  "cost_bound": "optional",
  "reason_code": "benchmark_leading_within_policy_and_budget",
  "fallback_policy": "optional",
  "contribution_policy_ref": "license://...",
  "receipt_obligations": ["contribution_receipt"]
}
```

## Worker Runtime v0 Canonical Objects

For serious worker/agent runs, Agentgres is the canonical runtime state store.
SDK JSON checkpoints, GUI local stores, CLI session files, harness fixtures,
and workflow caches are projections, exports, or test artifacts only.

```text
Run
Task
TaskState
ArtifactRef
ReceiptRef
PolicyDecision
AuthorityDecision
StopCondition
QualityRecord
Scorecard
OperationLogEntry
ProjectionCheckpoint
AgentStateArchive
```

Minimum runtime operation log entries:

```text
RunCreated
RunEventAppended
TaskStateUpdated
PolicyDecisionRecorded
AuthorityDecisionRecorded
ReceiptRecorded
ArtifactRecorded
StopConditionRecorded
ScorecardRecorded
QualityRecordRecorded
WorkerTrainingSpecCreated
ModelCapacityProfileRecorded
TrainingBatchPlanRecorded
GenerationBatchArchived
QualityGateReportRecorded
TrainingCostLedgerUpdated
DatasetCommitmentRecorded
TrainingLineageUpdated
BenchmarkSubmissionCreated
BenchmarkRunRecorded
EvaluationVerdictRecorded
MoWRoutingDecisionRecorded
AgentStateArchiveCreated
AgentStateRestoreRequested
ArchiveHashVerified
StateImported
RestoreReceiptRecorded
RunTerminalStateRecorded
```

Runtime projections must expose:

```json
{
  "run_id": "run_123",
  "source": "agentgres",
  "projection_id": "runtime_run_view",
  "watermark": "domain_seq:99182",
  "freshness": "projection_consistent",
  "trace_ref": "trace://run_123",
  "scorecard_ref": "agentgres://scorecards/run_123"
}
```

Trace and replay exports must be reconstructable from the operation log plus artifact/receipt references. A local SDK checkpoint may accelerate resume or offline inspection, but deleting it must not delete canonical run truth.

## Sealed State Archive Shape

Agentgres supports cold-state export and hot-state rehydration through
encrypted, content-addressed state bundles.

These bundles are first-class portable state artifacts. They are not canonical
live state by themselves. Agentgres remains the authority for the operation that
created the archive, the state root it represents, the object heads it binds,
the policy and schema under which it was produced, the authority context for
decryption, and the restore/import receipt chain.

```json
{
  "object_class": "AgentStateArchive",
  "archive_id": "archive_123",
  "run_id": "run_123",
  "agent_id": "agent_abc",
  "base_state_root": "sha256:...",
  "object_heads": {
    "Run:run_123": "sha256:...",
    "TaskState:task_456": "sha256:..."
  },
  "archive_cid": "bafy...",
  "archive_sha256": "sha256:...",
  "storage_plane": "filecoin | cas | s3 | local_disk",
  "archive_role": "portable_state | zero_to_idle_checkpoint | evidence_bundle | migration_bundle",
  "encryption": {
    "scheme": "hybrid-pq",
    "recipient": "wallet://user_or_org",
    "key_ref": "wallet.network://sealed-key/..."
  },
  "contents": [
    "task_state",
    "working_memory",
    "patch_branches",
    "tool_trace",
    "artifact_refs",
    "projection_checkpoint",
    "replay_metadata"
  ],
  "policy_hash": "sha256:...",
  "authority_context_ref": "wallet://...",
  "receipt_refs": ["receipt://..."],
  "replay_import_metadata_ref": "artifact://...",
  "schema_version": 12,
  "created_at": "2026-05-13T00:00:00Z"
}
```

Restore/import must be operation-backed:

```text
AgentStateRestoreRequested
ArchiveFetched
ArchiveHashVerified
ArchiveDecrypted
StateImported
ProjectionRebuilt
RestoreReceiptRecorded
```

Archives may contain secret refs, but should not contain raw secret material.
On restore, the runtime reacquires scoped leases from wallet.network.

## Relation Query API

```http
POST /v1/query
```

```json
{
  "relation": "worker_listings",
  "where": {"publisher_id": "ioi://publisher/ioi"},
  "order_by": [{"field": "quality_score", "direction": "desc"}],
  "limit": 50,
  "consistency": "local_cached | projection_consistent | state_root_consistent | linearized_domain"
}
```

Response includes metadata:

```json
{
  "rows": [],
  "metadata": {
    "consistency": "projection_consistent",
    "projection_id": "worker_search",
    "watermark": "domain_seq:99182",
    "state_root": "sha256:...",
    "schema_version": 12
  }
}
```

## Projection Definitions

```json
{
  "projection_id": "quality_rankings",
  "source_objects": ["WorkerInvocation", "QualityRecord", "ContributionReceipt"],
  "output_relation": "worker_quality_rankings",
  "refresh_mode": "nearline_incremental",
  "freshness_slo_ms": 500,
  "checkpoint_interval_ops": 10000
}
```

## Projection Engine Adapter Shapes

Projection engine adapters describe how a named Agentgres projection is served
by a particular external or embedded engine. These adapters are serving planes,
not sources of truth.

```json
{
  "object_class": "ProjectionEngineAdapter",
  "adapter_id": "adapter://worker-search/typesense-primary",
  "projection_id": "worker_search",
  "engine_family": "relational | local_sync | search | vector | olap | stream | cache_lookup | time_series | ledger | graph",
  "engine_name": "postgres | sqlite | typesense | meilisearch | qdrant | lancedb | clickhouse | duckdb | nats_jetstream | redpanda | valkey | dragonfly | questdb | tigerbeetle | custom",
  "serving_role": "read_model | search_index | retrieval_index | analytics_table | stream_tail | materialized_lookup | accounting_projection | local_replica",
  "write_policy": "read_only_projection | append_transport_only | write_to_operation_compiler",
  "canonical_write_allowed": false,
  "projection_definition_hash": "sha256:...",
  "schema_version": 12,
  "policy_hash": "sha256:...",
  "status": "planned | building | active | degraded | stale | rebuilding | disabled"
}
```

```json
{
  "object_class": "ProjectionEngineCheckpoint",
  "checkpoint_id": "projection_checkpoint://worker-search/typesense/99182",
  "adapter_id": "adapter://worker-search/typesense-primary",
  "projection_id": "worker_search",
  "engine_family": "search",
  "source_operation_range": {
    "from_domain_sequence": "domain_seq:98100",
    "to_domain_sequence": "domain_seq:99182"
  },
  "domain_sequence_watermark": "domain_seq:99182",
  "projection_watermark": "projection_seq:1234",
  "schema_version": 12,
  "policy_hash": "sha256:...",
  "projection_definition_hash": "sha256:...",
  "index_definition_hash": "sha256:...",
  "freshness_slo_ref": "projection_slo://worker_search/search_default",
  "verification_receipt_refs": ["receipt://projection_rebuild_123"],
  "status": "active | stale | invalidated | rebuilding | failed"
}
```

```json
{
  "object_class": "ProjectionEngineHealth",
  "health_id": "projection_health://worker-search/typesense-primary",
  "adapter_id": "adapter://worker-search/typesense-primary",
  "projection_id": "worker_search",
  "domain_sequence_watermark": "domain_seq:99182",
  "freshness_lag_ms": 42,
  "freshness_slo_ms": 500,
  "rebuild_required": false,
  "last_rebuild_plan_ref": "projection_rebuild://worker-search/2026-05-22",
  "status": "healthy | degraded | stale | rebuilding | offline"
}
```

```json
{
  "object_class": "ProjectionFreshnessSLO",
  "freshness_slo_id": "projection_slo://worker_search/search_default",
  "projection_id": "worker_search",
  "engine_family": "search",
  "target_freshness_ms": 500,
  "max_stale_ms": 5000,
  "consistency_floor": "cached_projection | projection_consistent | state_root_consistent",
  "alert_policy_ref": "policy://projection-lag-alerts",
  "status": "active | deprecated"
}
```

```json
{
  "object_class": "ProjectionRebuildPlan",
  "rebuild_plan_id": "projection_rebuild://worker-search/2026-05-22",
  "projection_id": "worker_search",
  "adapter_id": "adapter://worker-search/typesense-primary",
  "reason": "schema_changed | policy_changed | index_definition_changed | checkpoint_missing | engine_recovery | operator_requested",
  "source_operation_range": {
    "from_domain_sequence": "domain_seq:0",
    "to_domain_sequence": "domain_seq:99182"
  },
  "rebuild_mode": "full_rebuild | checkpoint_restore_plus_delta | delta_catchup | shadow_rebuild_then_swap",
  "verification_receipt_refs": ["receipt://projection_rebuild_123"],
  "status": "planned | running | verified | swapped | failed | cancelled"
}
```

## Settlement Mirror

Agentgres mirrors L1 contract state but does not replace it.

```json
{
  "object_class": "SettlementMirror",
  "object_id": "settle_123",
  "contract": "ServiceOrderEscrow",
  "tx_hash": "0x...",
  "status": "locked | released | disputed",
  "related_object": "ServiceOrder:order_123"
}
```

## Non-Negotiables

1. Agentgres state is domain-local by default, not IOI L1 state.
2. Agentgres stores rich operational state and sparse L1 mirrors.
3. SQL-like reads may exist, but writes compile into patch/operation settlement.
4. Every consequential operation must bind to actor, policy, schema, and receipts when required.
5. Projections must be rebuildable and checkpointable.
6. Worker runtime truth lives in Agentgres operation logs; client checkpoints are non-authoritative caches or exports.
7. Filecoin/CAS payloads, checkpoints, snapshots, and evidence bundles are refs from Agentgres state, not replacements for Agentgres state.
8. Agents draft in isolated patch branches over pinned workspace snapshots; canonical heads advance only through expected-head merge and settlement.
9. Rollback after settlement is represented as a new canonical revert operation with receipts, not deletion or mutation of previous truth.
10. Sealed state archives are encrypted portable state artifacts; Agentgres retains
    hot canonical refs, lifecycle metadata, roots, policy, and receipts.
11. Restore rehydrates state through Agentgres operations after authority, hash,
    decryption, schema, policy, and state-root checks.
12. External projection engines are serving planes only; they must be disposable,
    invalidatable, checkpointed, and rebuildable from Agentgres truth.
13. Local-first working state is pre-canonical until admitted through Agentgres
    operation settlement.
