# Events, Receipts, and Delivery Bundles

Status: canonical low-level reference.
Canonical owner: this file for runtime events, receipts, delivery bundles, trace bundles, and quality records.
Supersedes: overlapping event/receipt examples in plans/specs when event, trace, or receipt fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

Events enable observation; receipts enable proof; delivery bundles enable marketplace settlement. These objects must be consistent across Autopilot, IOI daemon, Agentgres, aiagent.xyz, sas.xyz, and wallet.network.

## Runtime Events

Required event kinds:

```text
session.started
turn.started
context.prepared
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
delegation.started
delegation.completed
handoff.recorded
stop_condition.recorded
scorecard.updated
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
ArtifactReceipt
ValidationReceipt
MergeReceipt
SettlementReceipt
DeliveryReceipt
ContributionReceipt
QualityReceipt
RuntimeAttestationReceipt
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

## DeliveryBundle

```json
{
  "delivery_id": "delivery_123",
  "delivery_type": "service_order | worker_invocation | workflow_run",
  "order_id": "optional",
  "worker_invocation_id": "optional",
  "run_ids": ["run_123"],
  "output_artifacts": ["artifact://report"],
  "evidence_bundle": ["receipt://execution", "receipt://validation"],
  "quality_summary": {
    "score": 0.91,
    "checks_passed": true,
    "warnings": []
  },
  "policy_summary": {
    "approvals_used": ["approval_123"],
    "denied_actions": []
  },
  "contribution_refs": ["contrib_123"],
  "settlement": {
    "l1_contract": "0x...",
    "status": "pending_acceptance"
  }
}
```

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
