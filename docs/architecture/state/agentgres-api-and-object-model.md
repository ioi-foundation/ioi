# Agentgres API and Object Model

Status: canonical low-level reference.
Canonical owner: this file for Agentgres APIs, canonical object classes, runtime v0 state, operation logs, projection watermarks, and replay/export authority.
Supersedes: older Agentgres-as-generic-store wording when runtime truth ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

Agentgres is the per-domain state substrate. It stores operational truth, not IOI L1 economic settlement. Each serious Web4 application domain runs its own kernel/runtime deployment with its own Agentgres domain.

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
GET  /v1/receipts/{receipt_id}
GET  /v1/artifacts/{artifact_id}
```

## Patch/Change API

```http
POST /v1/intents
POST /v1/scope-leases
POST /v1/patches
GET  /v1/patches/{patch_id}
POST /v1/patches/{patch_id}/validate
POST /v1/patches/{patch_id}/merge
POST /v1/patches/{patch_id}/settle
POST /v1/patches/{patch_id}/reject
```

Patch lifecycle:

```text
Intent → ScopeLease → Patch → Validate → Merge → Settle → Project → Query → Retain
```

## Canonical Object Classes

```text
Tenant
User
Role
Policy
PolicyDecision
AuthorityGrantRef
Task
Run
TaskState
WorkerInvocation
ServiceOrder
DeliveryBundle
Approval
Patch
MergeDecision
ExecutionReceipt
ArtifactRef
EvidenceBundle
QualityRecord
Scorecard
StopCondition
OperationLogEntry
ContributionReceipt
UsageReceipt
ReputationRecord
ProjectionDefinition
ProjectionCheckpoint
DisputeRecord
SettlementMirror
```

## Domain Manifest

```json
{
  "domain_id": "agentgres://domain/aiagent.xyz",
  "domain_type": "marketplace | service | local | enterprise | app",
  "kernel_id": "kernel://aiagent.xyz/main",
  "schema_version": 12,
  "state_root": "sha256:...",
  "watermark": "domain_seq:99182",
  "l1_contracts": {
    "worker_registry": "0x...",
    "license_registry": "0x..."
  },
  "projections": ["worker_search", "quality_rankings", "install_state"]
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
  "patch_id": "optional",
  "schema_version": 12,
  "policy_hash": "sha256:...",
  "authority_grant_refs": ["grant_..."],
  "payload": {},
  "resulting_head": "sha256:...",
  "state_root": "sha256:...",
  "receipt_refs": []
}
```

## Agent Runtime v0 Canonical Objects

For serious agent runs, Agentgres is the canonical runtime state store. SDK JSON checkpoints, GUI local stores, CLI session files, harness fixtures, and workflow caches are projections, exports, or test artifacts only.

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
6. Agent runtime truth lives in Agentgres operation logs; client checkpoints are non-authoritative caches or exports.
