# Agentgres API and Object Model

Status: canonical low-level reference.
Canonical owner: this file for Agentgres APIs, canonical object classes, runtime v0 state, operation logs, projection watermarks, and replay/export validity; artifact-ref meaning and restore/import validity live in [`artifact-ref-plane.md`](./artifact-ref-plane.md), and bridge/readiness semantics live in [`postgres-bridge-and-readiness-contract.md`](./postgres-bridge-and-readiness-contract.md).
Supersedes: older Agentgres-as-generic-store wording when runtime truth ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: reference
Implementation status: partial (object catalog; families land with their planes — Agent Execution Branch is planned over existing fork/replay/snapshot substrate, and OutcomeRoom discovery/participation/portable-exit/frontier/claim/attempt/finding/WorkResult/OutcomeDelta plus NetworkGoalBudget persistence and admission are planned)
Last implementation audit: 2026-07-05

## Purpose

Agentgres is the per-domain state substrate. It stores operational truth, not IOI L1 economic settlement. Each serious Web4 application domain runs its own kernel/runtime deployment with its own Agentgres domain.

Agentgres is also not a thin index over Filecoin/CAS blobs. Its operation log,
object heads, constraints, indexes, projections, subscriptions, receipt
metadata, delivery state, and quality/contribution ledgers are canonical
Agentgres state. Storage backends such as Filecoin/CAS store immutable payload
bytes, sealed archive bytes, and large evidence objects that Agentgres
references through Agentgres-governed artifact refs.

For governed autonomous-system chains and Hypervisor Nodes, Agentgres records
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
POST /v1/hypervisor-nodes
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
Agentgres keeps the canonical archive refs, lifecycle status, roots, policy,
schema, authority, and receipt metadata. Storage backends such as Filecoin/CAS,
S3, local disk, or other durable stores hold the encrypted bytes by CID/hash.

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
  "validation_receipt_refs": ["receipt://validate/A"],
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
HypervisorNode
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
OntologyVersion
OntologyOverlay
OntologyAssertion
ProvenanceAssertion
OntologyMapping
OntologyCrosswalk
SemanticMappingDecision
OntologyActionContract
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
DatasetFactoryRun
TrainingPipelineRun
ExperimentOptimizationCycle
ArtifactConversionRun
ConductorAdvisorCandidate
DatasetCommitment
TrainingLineage
ContextMutation
PostTrainingCycle
PromotionDecision
CapabilityRegressionRecord
BenchmarkSubmission
BenchmarkRun
EvaluationVerdict
MoWRoutingDecision
ServiceOrder
OutcomeWorkspace
RuntimeAssignment
ComputeSession
RuntimeSubscription
ResourceAllocationDecision
NetworkGoalBudget
ComplianceAuditExportBundle
MultiPartyCollaborationContext
OutcomeRoom
OutcomeRoomDiscovery
RoomParticipationRequest
ParticipantStateBundle
RoomParticipantLease
ResourceOffer
CapabilityOffer
WorkFrontierItem
WorkClaimLease
Attempt
Finding
VerifierChallenge
WorkResult
OutcomeDelta
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

Ontology profile registration is exact and does not introduce parallel storage
schemas:

| Registered semantic object/profile | Persisted class and canonical wire shape |
| --- | --- |
| `OntologyVersion` | `DomainOntology` using `DomainOntologyEnvelope` with `ontology_record_profile: ontology_version`. |
| `OntologyOverlay` | `DomainOntology` using `DomainOntologyEnvelope` with `ontology_record_profile: ontology_overlay` and base-version refs. |
| `ProvenanceAssertion` | `OntologyAssertion` using `OntologyAssertionEnvelope` with `assertion_profile: provenance_assertion`. |
| `OntologyCrosswalk` | `OntologyMapping` using `OntologyMappingEnvelope` with `mapping_record_profile: ontology_crosswalk`. |
| `SemanticMappingDecision` | `OntologyMapping` using `OntologyMappingEnvelope` with `mapping_record_profile: semantic_mapping_decision`, application targets, challenge refs, and a decision receipt. |

The semantic profile name remains queryable and receipted, but the mapped base
class owns object heads, operation semantics, and migrations.

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

## Hypervisor Node and Autonomous-System Chain Shapes

```json
{
  "object_class": "HypervisorNode",
  "hypervisor_node_id": "node://local-hypervisor",
  "owner_id": "wallet://user_123",
  "daemon_runtime_ref": "runtime://local",
  "agentgres_domain_ref": "agentgres://domain/hypervisor/local",
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
  "hypervisor_node_id": "node://local-hypervisor",
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
  "hypervisor_node_id": "node://local-hypervisor",
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
  "hypervisor_node_id": "node://local-hypervisor",
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
the Hypervisor Daemon runtime node executes it.

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
truth. Source bytes and large transformed payloads remain in storage backends
such as Filecoin/CAS by hash/CID.

`OntologyVersion`, `OntologyOverlay`, `ProvenanceAssertion`,
`OntologyCrosswalk`, and `SemanticMappingDecision` are the registered profiles
listed above. Their authoritative field schemas are the corresponding
`DomainOntologyEnvelope`, `OntologyAssertionEnvelope`, and
`OntologyMappingEnvelope` in the shared object canon; Agentgres operations store
the profile discriminator rather than inventing profile-local shapes.

```json
{
  "object_class": "DomainOntology",
  "ontology_record_profile": "ontology_version | ontology_overlay",
  "ontology_id": "ontology://construction-estimating/v1",
  "ontology_family_ref": "ontology://construction-estimating",
  "base_ontology_version_refs": [],
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
MoW routing objects. Payload bytes remain in storage backends such as
Filecoin/CAS and are referenced by hash/CID.

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
  "object_class": "DatasetFactoryRun",
  "dataset_factory_run_id": "run://dataset_factory_123",
  "foundry_job_ref": "foundry_job://dataset_factory_123",
  "objective": "Create instruction/eval data for support triage model",
  "source_refs": ["artifact://idea", "view://policy_bound_support_tickets"],
  "data_recipe_refs": ["recipe://support-triage-v1"],
  "ontology_refs": ["ontology://support"],
  "policy_bound_data_view_refs": ["view://support-redacted"],
  "stage": "define | research | ground | generate | audit | export | runbook",
  "output_dataset_refs": ["dataset://support-triage-train-v1"],
  "holdout_dataset_refs": ["dataset://support-triage-holdout-v1"],
  "adversarial_dataset_refs": ["dataset://support-triage-regression-v1"],
  "quality_gate_refs": ["gate://dataset-audit"],
  "cost_ledger_ref": "ledger://dataset_factory_123",
  "receipt_root": "sha256:...",
  "status": "draft | running | gated | exported | failed | rejected"
}
```

```json
{
  "object_class": "TrainingPipelineRun",
  "training_pipeline_run_id": "trainpipe://persistent_training_123",
  "foundry_job_ref": "foundry_job://persistent_training_123",
  "objective": "Train and register a 9B support model",
  "stage": "idea | data_binding | dataset_factory | notebook_prep | training | eval | validation | conversion | registration | endpoint_candidate | promotion_review | completed | failed",
  "workspace_ref": "notebook://persistent_training_123",
  "compute_session_refs": ["compute://gpu_job_123"],
  "checkpoint_refs": ["artifact://checkpoint_001", "receipt://checkpoint_001"],
  "resume_ref": "artifact://resume-token",
  "last_heartbeat_ref": "receipt://training-heartbeat",
  "authority_grant_refs": ["grant://training_data", "grant://gpu_spend"],
  "training_evidence_eligibility_refs": ["eligibility://support-triage-traces"],
  "training_data_posture": "synthetic_only | redacted_opt_in | full_private_opt_in | org_policy",
  "model_base_refs": ["model://base-9b"],
  "input_dataset_refs": ["dataset://support-triage-train-v1"],
  "training_config_ref": "artifact://training-config",
  "training_batch_plan_refs": ["batch://train-batch-plan"],
  "eval_suite_refs": ["benchmark://support-eval"],
  "validation_report_refs": ["artifact://validation-report"],
  "optimization_cycle_refs": ["optcycle://persistent_training_123"],
  "artifact_conversion_refs": ["conversion://persistent_training_123"],
  "registered_model_candidate_ref": "model://support-9b-v1",
  "endpoint_candidate_ref": "model_route://support-9b-v1",
  "conductor_advisor_candidate_ref": "optional conductor://ioi-conductor-v1",
  "scorecard_ref": "gate://support-model-scorecard",
  "spend_forecast_ref": "ledger://persistent_training_forecast",
  "current_burn_ref": "ledger://persistent_training_current",
  "continuation_policy_ref": "policy://continue-if-quality-lift-justifies-burn",
  "stop_resume_policy_ref": "policy://persistent-training-stop-resume",
  "cost_ledger_ref": "ledger://persistent_training_123",
  "promotion_proposal_ref": "proposal://promote-support-9b-v1",
  "receipt_root": "sha256:...",
  "status": "planned | running | suspended | resuming | gated | registered | promoted | rejected | failed"
}
```

```json
{
  "object_class": "ExperimentOptimizationCycle",
  "optimization_cycle_id": "optcycle://persistent_training_123",
  "target_training_pipeline_ref": "trainpipe://persistent_training_123",
  "optimizer_ref": "worker://training-recipe-optimizer",
  "objective_metric": {
    "name": "validation_bpb",
    "direction": "minimize"
  },
  "baseline_recipe_ref": "artifact://recipe-baseline",
  "best_candidate_ref": "artifact://recipe-best",
  "trial_refs": ["run://trial_001", "run://trial_002"],
  "accepted_change_refs": ["artifact://recipe-delta-accepted"],
  "rejected_change_refs": ["artifact://recipe-delta-rejected"],
  "seed_policy_ref": "policy://experiment-seeds",
  "budget_policy_ref": "policy://persistent-training-budget",
  "stop_policy_ref": "policy://stop-on-budget-or-no-lift",
  "receipt_root": "sha256:...",
  "status": "planned | running | stopped | promoted_to_review | failed | rejected"
}
```

```json
{
  "object_class": "ArtifactConversionRun",
  "conversion_run_id": "conversion://persistent_training_123",
  "training_pipeline_ref": "trainpipe://persistent_training_123",
  "source_model_artifact_ref": "artifact://trained-model",
  "conversion_targets": ["adapter_merge", "quantization", "gguf", "mlx", "onnx", "model_card", "endpoint_package"],
  "output_artifact_refs": ["artifact://model-gguf", "artifact://model-mlx", "artifact://model-card"],
  "validation_refs": ["gate://conversion-validation", "receipt://conversion_123"],
  "registered_model_candidate_ref": "model://support-9b-v1",
  "receipt_root": "sha256:...",
  "status": "planned | running | validated | registered | failed | rejected"
}
```

```json
{
  "object_class": "ConductorAdvisorCandidate",
  "conductor_advisor_candidate_id": "conductor://ioi-conductor-v1",
  "foundry_job_ref": "foundry_job://conductor_advisor_123",
  "intended_consumer": "ioi_ai | hypervisor_operator_plane | custom_coordinator",
  "training_data_posture": "synthetic_only | redacted_opt_in | full_private_opt_in | org_policy",
  "training_consent_refs": ["grant://training_consent", "policy://training_data_use"],
  "training_evidence_eligibility_refs": ["eligibility://conductor-training-traces"],
  "input_refs": ["dataset://conductor-training", "receipt://work-evidence"],
  "eval_suite_refs": ["benchmark://cross-session-routing"],
  "scorecard_refs": ["gate://conductor-scorecard"],
  "shadow_mode_refs": ["run://shadow_123"],
  "shadow_mode_receipt_refs": ["receipt://shadow_123"],
  "shadow_mode_summary": {
    "quality_delta": "optional",
    "cost_delta": "optional",
    "latency_delta": "optional",
    "privacy_incidents": 0,
    "policy_denials": 0,
    "authority_escalations": 0
  },
  "promotion_status": "draft | training | shadow | gated | promoted | rejected | paused | rolled_back | recalled"
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
  "wiki_ref": "wiki://user-or-project-memory",
  "worker_id": "worker://...",
  "project_ref": "agentgres://project/...",
  "mutation_type": "fact | preference | doctrine | route | procedure | eval | failure",
  "operation": "add | supersede | contradict | deprecate | activate | archive | forget",
  "scope": "user | org | project | worker | service | domain",
  "visibility": "private | shared | org | public",
  "validity_window": "optional",
  "claim_ref": "artifact://... | hash://...",
  "prior_claim_refs": [],
  "evidence_refs": ["receipt://..."],
  "policy_hash": "sha256:...",
  "receipt_ref": "receipt://context_mutation_123"
}
```

`ContextMutation` is the Agentgres admission object for durable Agent Wiki /
`ioi-memory` changes. Draft, task-local, speculative, and fuzzy memory may stay
in the context-memory plane. A memory change should become a `ContextMutation`
when it affects durable behavior, policy, routing, training, sharing,
portability, restore, retention, export, or user-visible doctrine.

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
  "regression_id": "regression://support-worker-canary-001",
  "object_class": "CapabilityRegressionRecord",
  "capability_ref": "worker://support-triage@1.0.2",
  "capability_kind": "worker | model_route | agent_harness | tool | mcp_server | connector | automation | service | environment_image | package | domain_app | fleet_policy",
  "baseline_version_ref": "worker://support-triage@1.0.1",
  "candidate_or_active_version_ref": "worker://support-triage@1.0.2",
  "detected_in": {
    "phase": "offline_eval | shadow | canary | rollout | production | recall_review",
    "run_refs": ["run://shadow_123"],
    "release_target_refs": ["release://support-tier1-canary"]
  },
  "regression_class": "quality | safety | privacy | cost | latency | authority | reliability | policy | security | compliance | marketplace_reputation",
  "severity": "info | warning | blocking | critical",
  "evidence_refs": ["receipt://eval_123", "artifact://failure-cluster"],
  "scorecard_refs": ["gate://support-scorecard"],
  "affected_scope_refs": ["project://support", "release://support-tier1-canary"],
  "recommended_action": "reject | hold | shadow_more | pause | rollback | recall | constrain | patch_and_retry | require_human_review",
  "adjudication_ref": "receipt://adjudication_123",
  "training_evidence_eligibility_ref": "eligibility://support-regression-001",
  "future_eval_candidate_refs": ["dataset://support-regression-holdout-candidate"],
  "receipt_ref": "receipt://capability_regression_123",
  "status": "detected | adjudicating | blocked | rejected | shadowing | paused | rolled_back | recalled | constrained | converted_to_eval | closed"
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

```json
{
  "allocation_decision_id": "allocation://decision/123",
  "object_class": "ResourceAllocationDecision",
  "allocation_request_ref": "allocation://request/123",
  "workload_kind": "session | work_run | automation | scheduled_job | training_pipeline | eval | managed_worker | model_route | release_job | connector_job",
  "workload_refs": ["work_run://123"],
  "resource_pool_refs": ["resource_pool://gpu/us-east"],
  "budget_refs": ["budget://org/monthly-gpu"],
  "quota_refs": ["quota://provider/gpu"],
  "priority_class": "safety_critical | user_blocking | deadline | interactive | production | standard | background | speculative",
  "decision": "admit | queue | throttle | degrade | preempt | pause | defer | cancel | shift_provider | request_budget | fail_closed",
  "reason_code": "capacity_available | capacity_exhausted | budget_warning | budget_exhausted | quota_exhausted | rate_limited | deadline_priority | safety_priority | policy_denied | privacy_or_residency_block | provider_unhealthy | verified_work_low_value | duplicate_catchup",
  "affected_workload_refs": ["work_run://123"],
  "preempted_workload_refs": ["work_run://background-7"],
  "preserved_checkpoint_refs": ["artifact://checkpoint"],
  "lost_or_discarded_refs": [],
  "retry_or_resume_policy_ref": "policy://retry-after-capacity",
  "catchup_policy_ref": "schedule://nightly-coalesce",
  "authority_requirement_refs": ["policy://gpu-spend-limit"],
  "authority_grant_refs": ["grant://gpu-spend"],
  "cost_delta_ref": "ledger://cost-delta",
  "expected_verified_work_delta_ref": "receipt://quality-delta",
  "receipt_refs": ["receipt://resource_allocation_123"],
  "status": "proposed | admitted | blocked | executed | superseded | failed"
}
```

```json
{
  "audit_export_id": "audit_export://customer-q2-2026",
  "object_class": "ComplianceAuditExportBundle",
  "export_type": "customer_audit | auditor_review | regulator_request | counterparty_dispute | procurement_review | internal_control | tax_report | sla_report | incident_review",
  "audience": "customer | external_auditor | regulator | counterparty | insurer | procurement | internal_auditor | public",
  "subject_refs": ["order://123", "run://456", "service://789"],
  "jurisdiction_policy_pack_refs": ["jurisdiction_policy_pack://us-finance-v1"],
  "regulated_action_refs": ["receipt://regulated-action"],
  "policy_decision_refs": ["receipt://policy_decision"],
  "approval_receipt_refs": ["receipt://approval"],
  "denial_receipt_refs": ["receipt://denial"],
  "authority_refs": ["authority://export-grant"],
  "evidence_bundle_refs": ["assurance_evidence://bundle", "evidence://agentgres-bundle"],
  "receipt_refs": ["receipt://execution"],
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
  "export_receipt_refs": ["receipt://compliance_audit_export_bundle"],
  "status": "requested | generated | delivered | revoked | superseded | expired"
}
```

```json
{
  "collaboration_id": "collaboration://joint-service-outcome-001",
  "object_class": "MultiPartyCollaborationContext",
  "goal_ref": "order://123",
  "outcome_room_ref": "outcome-room://joint-service-outcome-001",
  "coordinator_ref": "domain://service-coordinator",
  "coordination_topology": "hosted_admission | federated_admission",
  "coordination_and_ordering_policy_ref": "policy://room-ordering-v1",
  "shared_state_admission_owner_ref": "domain://service-coordinator | policy://federated-admission-v1",
  "conflict_failover_and_adjudication_policy_refs": ["policy://room-conflicts-v1"],
  "party_refs": [
    {
      "party_ref": "org://customer-a",
      "role": "data_owner",
      "domain_ref": "agentgres://domain/customer-a",
      "operator_and_affiliation_refs": ["org://customer-a"],
      "model_runtime_and_infrastructure_dependency_refs": [],
      "authority_provider_refs": ["authority://customer-a-policy"],
      "revocation_ref": "revocation://collaboration/customer-a",
      "status": "active"
    },
    {
      "party_ref": "org://provider-b",
      "role": "worker_provider",
      "domain_ref": "agentgres://domain/provider-b",
      "operator_and_affiliation_refs": ["org://provider-b"],
      "model_runtime_and_infrastructure_dependency_refs": ["model_route://provider-b/default", "runtime://provider-b/node-1"],
      "authority_provider_refs": ["wallet://provider-b"],
      "revocation_ref": null,
      "status": "active"
    },
    {
      "party_ref": "org://auditor",
      "role": "auditor",
      "domain_ref": null,
      "authority_provider_refs": ["policy://auditor-readonly"],
      "revocation_ref": "revocation://collaboration/auditor",
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
  "authority_refs_by_party": [
    {
      "party_ref": "org://customer-a",
      "authority_refs": ["grant://customer-data-read"]
    },
    {
      "party_ref": "org://provider-b",
      "authority_refs": ["grant://worker-execute"]
    }
  ],
  "evidence_bundle_refs": ["evidence://collaboration-proof"],
  "delivery_bundle_refs": ["delivery://final"],
  "contribution_refs": ["receipt://contribution-provider-b"],
  "settlement_intent_refs": ["settlement-intent://payout-provider-b"],
  "audit_export_profile_refs": ["audit_export://auditor-review"],
  "l1_anchor_policy": "local_only | optional_anchor | dispute_only | reputation_only | settlement_required | required_public_root",
  "history_policy": {
    "party_removal_effect": "no_new_access | revoke_live_access | tombstone_view | rotate_views",
    "historical_receipts": "immutable | sealed | export_limited"
  },
  "receipt_refs": ["receipt://multi_party_collaboration"],
  "status": "proposed | active | blocked | delivery_submitted | accepted | revision_requested | disputed | settled | revoked | archived"
}
```

## OutcomeRoom And Collaborative Work Graph Shapes

Agentgres persists the objects defined by
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md)
inside the domain that owns each operation. It does not create one global room
database. A room declares one of two admission shapes:

```text
hosted_admission
  one named Agentgres domain owns room ordering and admission

federated_admission
  each domain retains local truth; a versioned federation policy owns
  signed update ordering, merge, quorum/adjudication, conflicts, and failover
```

Minimum persisted room graph:

```json
{
  "outcome_room_id": "outcome-room://research-123",
  "object_class": "OutcomeRoom",
  "goal_ref": "goal://research-123",
  "room_mode": "private_goal | permissioned_team | cross_org | open_challenge",
  "coordination_topology": "hosted_admission | federated_admission",
  "host_domain_ref": "agentgres://domain/ioi-ai | null",
  "coordination_policy_ref": "policy://room-admission-v1",
  "multi_party_collaboration_ref": "collaboration://research-123 | null",
  "ontology_profile_refs": [],
  "acceptance_stop_privacy_participation_contribution_and_export_policy_refs": [],
  "scorecard_guardrail_verifier_resource_budget_and_settlement_refs": [],
  "network_goal_budget_ref": "goal-budget://research-123 | order://... | null",
  "participant_lease_refs": [],
  "frontier_item_refs": [],
  "attempt_refs": [],
  "finding_refs": [],
  "verifier_challenge_refs": [],
  "contribution_refs": [],
  "room_state_root": "sha256:...",
  "status": "proposed | open | active | paused | blocked | verifying | accepted | disputed | settled | closed | revoked | archived"
}
```

The room relation graph must preserve:

```text
OutcomeRoom
  -> OutcomeRoomDiscovery
       -> policy-filtered objective / category / semantic profile / eligibility
       -> privacy / visibility / budget / verifier / settlement posture
  -> RoomParticipationRequest
       -> applicant / operator / home domain / affiliations / eligibility
       -> requested role / capabilities / leases / accepted policy versions
  -> RoomParticipantLease
       -> identity / operator / home domain / affiliations
       -> worker / model route / harness / runtime dependencies
       -> context / resource / budget / authority leases
       -> current WorkClaimLease / heartbeat / wake condition / quarantine
       -> ParticipantStateBundle
            -> released claims / included lineage / exclusions / redactions
            -> export / acknowledgement / supersession / revocation
  -> WorkFrontierItem
       -> dependencies / related attempts and findings
       -> required capabilities / context / resources / authority / evidence
       -> expected value / uncertainty / priority / duplication policy
       -> WorkClaimLease
  -> ResourceOffer / CapabilityOffer
       -> ResourceAllocationDecision / spend / contribution refs
  -> NetworkGoalBudget
       -> separate funding / cap / allocation / contribution / settlement refs
       -> never an implicit draw on ordinary Goal Space Work Credits
  -> Attempt
       -> declared method / lineage / environment and version refs
       -> positive / negative / inconclusive / invalid / exploit / superseded
       -> WorkResult / OutcomeDelta / artifacts / evidence / costs
       -> reproduction / verifier / license / export / contribution refs
  -> Finding
       -> uncertainty / time / provenance / applicability
       -> supporting and contradicting evidence / supersession / dispute
  -> VerifierChallenge
       -> rule versions / adjudication / affected attempts / re-verification
```

Room messages, boards, inboxes, digests, feeds, taskforce lists, leaderboards,
and replay timelines are projection definitions over those objects. They are
not canonical state classes. Participant inputs remain tainted until the
declared room admission path accepts an object or delta. Admission records the
predecessor room root, resulting root, policy/version refs, operation refs, and
receipt refs without rewriting rejected or superseded history.

For a federated room, a local domain stores its own object heads plus signed
remote refs and the last admitted federation watermark. It must not import a
remote private context, raw operational database, or message stream as local
truth merely because it arrived over AIIP.

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
AgentExecutionTrace
AgentExecutionBranch
StagedEffect
BranchCheckpoint
BranchMergePlan
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
ResourceAllocationDecisionRecorded
ComplianceAuditExportBundleGenerated
ComplianceAuditExportBundleRevoked
MultiPartyCollaborationContextCreated
MultiPartyCollaborationPartyJoined
MultiPartyCollaborationPartyRemoved
MultiPartyCollaborationViewGranted
MultiPartyCollaborationViewRevoked
MultiPartyCollaborationProofBundleGenerated
CapabilityRegressionRecorded
CapabilityRegressionAdjudicated
AgentStateArchiveCreated
AgentStateRestoreRequested
ArchiveHashVerified
StateImported
RestoreReceiptRecorded
RunTerminalStateRecorded
AgentExecutionTraceCreated
AgentExecutionBranchCreated
StagedEffectRecorded
BranchCheckpointCreated
BranchReplayRecorded
BranchMergePlanCreated
BranchMergeAdmitted
BranchDiscardRecorded
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

## Agent Execution Branches

Implementation status (this family): planned durable objects over existing
substrate (`thread.forked` events, run replay, counterfactual what-if replay,
workspace snapshot/restore custody). Shapes below are the committed design
surface, not shipped objects.

Agentgres execution branches are the canonical branch/replay primitive for
autonomous work. Git branches may be one input, but Agentgres branches cover the
coupled state of the run: workspace, trace, model route, harness, memory,
authority, artifacts, receipts, and settlement posture.

This is the difference:

```text
Git branch
  code and file history

Agentgres execution branch
  autonomous-work history, staged effects, authority, memory projection,
  receipts, replay, and merge/admission truth
```

Execution branches are useful for multi-harness comparison, self-correction,
review-before-commit, recoverable long-horizon runs, Foundry training evidence,
Work Ledger proof, and user-visible rollback. They must not allow an agent to
write canonical truth by naming a branch. Canonical heads advance only through
expected-head merge/admission with the required policy, authority, and receipts.

```json
{
  "object_class": "AgentExecutionTrace",
  "trace_id": "trace://run_123",
  "run_id": "run_123",
  "session_ref": "session://...",
  "goal_ref": "goal://...",
  "origin_branch_ref": "execution_branch://main",
  "event_stream_ref": "event://...",
  "operation_range": {
    "from_domain_sequence": "domain_seq:98100",
    "to_domain_sequence": "domain_seq:99182"
  },
  "staged_effect_refs": ["staged_effect://..."],
  "receipt_refs": ["receipt://..."],
  "state_root": "sha256:...",
  "replay_policy_ref": "policy://...",
  "status": "active | sealed | superseded | revoked"
}
```

```json
{
  "object_class": "AgentExecutionBranch",
  "execution_branch_ref": "execution_branch://run_123/branch-a",
  "run_id": "run_123",
  "parent_branch_ref": "execution_branch://run_123/main",
  "git_ref": "patch_branch://repo/branch-a | optional",
  "workspace_snapshot_ref": "snapshot://...",
  "worktree_ref": "worktree://...",
  "memory_projection_refs": ["memory_projection://..."],
  "harness_invocation_refs": ["harness_invocation://..."],
  "model_route_refs": ["model_route://..."],
  "context_lease_refs": ["context_lease://..."],
  "authority_refs": ["authority://...", "lease://..."],
  "trace_ref": "trace://run_123",
  "head_checkpoint_ref": "branch_checkpoint://...",
  "staged_effect_refs": ["staged_effect://..."],
  "receipt_root": "sha256:...",
  "branch_purpose": "main | candidate | research_attempt | ontology_attempt | incident_attempt | service_attempt | physical_mission_attempt | repair | verifier | reproduction | replay | self_correction | comparison",
  "status": "open | staged | admitted | discarded | superseded | archived | revoked"
}
```

```json
{
  "object_class": "StagedEffect",
  "staged_effect_ref": "staged_effect://...",
  "execution_branch_ref": "execution_branch://run_123/branch-a",
  "trace_ref": "trace://run_123",
  "effect_kind": "model_call | tool_call | file_mutation | connector_action | memory_mutation | policy_mutation | spend | provisioning | package_change | custom",
  "intent_ref": "artifact://... | message://... | tool://...",
  "policy_decision_ref": "policy_decision://... | optional",
  "authority_decision_ref": "authority://... | lease://... | optional",
  "outcome_ref": "artifact://... | receipt://... | diff://... | optional",
  "affected_ref_patterns": ["file://...", "memory://...", "connector://..."],
  "pre_state_root": "sha256:...",
  "post_state_root": "sha256:... | optional",
  "receipt_refs": ["receipt://..."],
  "settlement_status": "proposed | authorized | materialized | denied | reverted | admitted | discarded"
}
```

```json
{
  "object_class": "BranchCheckpoint",
  "branch_checkpoint_ref": "branch_checkpoint://...",
  "execution_branch_ref": "execution_branch://run_123/branch-a",
  "trace_ref": "trace://run_123",
  "workspace_snapshot_ref": "snapshot://...",
  "object_heads": {
    "Run:run_123": "sha256:...",
    "TaskState:task_456": "sha256:..."
  },
  "memory_projection_heads": ["memory_projection://..."],
  "lease_heads": ["lease://..."],
  "artifact_refs": ["artifact://..."],
  "receipt_root": "sha256:...",
  "created_for": "manual | before_risky_effect | retry | verifier | scheduled | restore",
  "status": "active | restored | superseded | revoked"
}
```

```json
{
  "object_class": "BranchMergePlan",
  "branch_merge_ref": "branch_merge://...",
  "target_branch_ref": "execution_branch://run_123/main",
  "candidate_branch_refs": ["execution_branch://run_123/branch-a"],
  "diff_refs": ["diff://..."],
  "memory_diff_refs": ["memory_projection://..."],
  "authority_diff_refs": ["authority://...", "lease://..."],
  "receipt_diff_refs": ["receipt://..."],
  "verification_refs": ["test://...", "gate://...", "receipt://..."],
  "admission_policy_ref": "policy://...",
  "expected_head_ref": "branch_checkpoint://...",
  "authority_revalidation": {
    "revocation_epoch_checked": "epoch:...",
    "revalidated_at": "2026-07-05T00:00:00Z",
    "stale_or_revoked_effects": ["staged_effect://..."]
  },
  "decision": "pending | admit | discard | needs_review | conflict | superseded",
  "decision_receipt_ref": "receipt://... | optional",
  "status": "draft | ready | admitted | discarded | blocked | revoked"
}
```

Admission freshness is mandatory: a `BranchMergePlan` cannot reach
`decision: admit` without `authority_revalidation` re-checking every staged
effect's grant against the current revocation epoch, expiry, and policy hash
at merge time; effects listed in `stale_or_revoked_effects` require
re-authorization before materialization, and the decision receipt binds the
epoch checked. Replayed effects execute under fresh authority and mint new
receipts (rule owner: [`doctrine.md`](./doctrine.md) Agent execution branch
doctrine; INV-1/INV-5).

Merge resolution classifies each touched object head as `exclusive_owner`
(single writer since fork — admit on expected-head check alone),
`declared_commutative` (class-declared commutative semantics — auto-merge),
or `adjudicated` (default — policy/verification/human decision). The class
taxonomy and the no-text-merge rule are owned by
[`doctrine.md`](./doctrine.md) (Merge strategy classes).

Execution branches must expose at least these projections:

```text
branch tree
staged-effect diff
trace timeline
authority diff
memory diff
artifact diff
receipt diff
replay bundle
merge/admission plan
```

## Sealed State Archive Shape

Agentgres supports cold-state export and hot-state rehydration through
encrypted, content-addressed state bundles.

These bundles are first-class portable state artifacts. They are not canonical
live state by themselves. Agentgres remains the canonical record owner for the
operation that created the archive, the state root it represents, the object
heads it binds, the policy and schema under which it was produced, the
authority context required for decryption, and the restore/import receipt chain.

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
7. Storage backend payloads, checkpoints, snapshots, and evidence bundles are refs from Agentgres state, not replacements for Agentgres state.
8. Participants draft software, research, ontology, incident, service,
   evaluation, and physical-mission attempts in bounded execution branches;
   canonical heads advance only through declared admission and expected-head
   checks.
9. Agent execution branches bind code/workspace diffs to trace, authority,
   memory projection, artifact, receipt, and replay state; they are not merely
   Git refs.
10. Staged effects do not become canonical truth until admitted through policy,
    authority, expected-head, and receipt checks.
11. Rejected branches and discarded effects remain evidence until retention
    policy says otherwise; they may feed review, training, eval, or audit, but
    not runtime truth.
12. Rollback after settlement is represented as a new canonical revert operation with receipts, not deletion or mutation of previous truth.
13. Sealed state archives are encrypted portable state artifacts; Agentgres retains
    hot canonical refs, lifecycle metadata, roots, policy, and receipts.
14. Restore rehydrates state through Agentgres operations after authority, hash,
    decryption, schema, policy, and state-root checks.
15. External projection engines are serving planes only; they must be disposable,
    invalidatable, checkpointed, and rebuildable from Agentgres truth.
16. Local-first working state is pre-canonical until admitted through Agentgres
    operation settlement.
17. An OutcomeRoom must declare hosted or federated admission; no global mutable
    room graph, message stream, board, or leaderboard is canonical by default.
18. A remote signed statement proves attribution to its signer, not local
    acceptance or universal correctness; cross-domain findings and deltas remain
    refs or proposals until local/federated admission.
19. Discoverable room projections are versioned, policy-filtered objects; they
    never expose private room context or grant participation by publication.
20. Participant exit releases/reassigns live claims and preserves a portable,
    policy-bound state bundle that does not depend on continued hosted-room
    database access.
