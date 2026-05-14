# sas.xyz Service Endpoints

Status: canonical low-level reference.
Canonical owner: this file for sas.xyz service order, delivery, provider, escrow mirror, and dispute endpoints.
Supersedes: overlapping sas.xyz endpoint examples in plans/specs when endpoint fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-14.

## Purpose

sas.xyz is the canonical Web4 Service-as-Software marketplace. It sells outcomes, not chat sessions or raw model checkpoints. This file defines service listing, Worker Training orders, delivery, escrow, provider, and dispute endpoints.

## Public Service Discovery

```http
GET /v1/services
GET /v1/services/{service_id}
GET /v1/services/{service_id}/versions
GET /v1/services/{service_id}/quality
GET /v1/services/{service_id}/sla
GET /v1/services/{service_id}/pricing
```

### Service Listing Shape

```json
{
  "service_id": "service://sas/runtime-audit-weekly",
  "name": "Weekly Runtime Audit",
  "publisher_id": "ioi://publisher/ioi",
  "manifest_root": "sha256:...",
  "outcome_contract": {
    "deliverables": ["audit_report", "risk_updates", "task_requests"],
    "acceptance_criteria": ["report_contains_evidence_refs", "critical_findings_ranked"],
    "required_receipts": ["execution", "validation", "delivery"]
  },
  "worker_training": {
    "enabled": false,
    "benchmark_profile_refs": [],
    "evaluation_rubric_ref": "optional",
    "sparse_worker_category": "optional"
  },
  "pricing": {
    "type": "fixed | metered | subscription | quote",
    "amount": "50",
    "currency": "IOI"
  },
  "execution_profiles": ["hosted", "depin_mutual_blind", "tee_enterprise", "customer_vpc"],
  "sla": {
    "deadline_hours": 24,
    "bond_required": true,
    "dispute_window_hours": 72
  }
}
```

Worker Training listings set `worker_training.enabled` to true and describe
the trained capability delivered, domain ontology, data recipes, connector
mappings, policy-bound data views, training-data handling policy, evaluation
datasets, evaluation rubric, benchmark profile, deployment target,
ownership/licensing terms, and acceptance receipts.

## Order API

```http
POST /v1/orders
GET  /v1/orders/{order_id}
GET  /v1/orders/{order_id}/events
GET  /v1/orders/{order_id}/runs
GET  /v1/orders/{order_id}/runtime-assignment
GET  /v1/orders/{order_id}/compute-sessions
GET  /v1/orders/{order_id}/delivery
GET  /v1/orders/{order_id}/receipts
POST /v1/orders/{order_id}/cancel
POST /v1/orders/{order_id}/accept-delivery
POST /v1/orders/{order_id}/request-revision
POST /v1/orders/{order_id}/open-dispute
```

### Create Order

```json
{
  "service_id": "service://sas/runtime-audit-weekly",
  "customer_id": "wallet://user_123",
  "objective": "Audit this week's runtime regressions and propose hardening tasks.",
  "context_refs": ["agentgres://project/autopilot", "git://repo/ioi"],
  "privacy_class": "internal",
  "execution_profile": "hosted | depin_mutual_blind | tee_enterprise | customer_vpc",
  "payment": {
    "mode": "escrow",
    "token": "IOI",
    "max_amount": "50"
  },
  "authority_policy": {
    "primitive_capabilities_required": ["prim:model.invoke", "prim:fs.read"],
    "authority_scopes_required": ["scope:repo.read"],
    "approval_required_for": ["code_write", "external_message"],
    "forbidden": ["funds_transfer"]
  }
}
```

Worker Training orders may additionally include:

```json
{
  "training_spec": {
    "target_worker_name": "Construction Estimating Specialist",
    "input_schema_ref": "cid://...",
    "output_schema_ref": "cid://...",
    "domain_ontology_ref": "ontology://construction-estimating/v1",
    "canonical_object_model_refs": ["object-model://Estimate"],
    "data_recipe_refs": ["recipe://construction/estimate-normalization/v1"],
    "policy_bound_data_view_refs": ["view://customer-estimate-training"],
    "evaluation_dataset_refs": ["dataset://construction-estimate-holdout-v1"],
    "source_refs": ["artifact://plans", "artifact://prior_quotes"],
    "training_methods_allowed": ["workflow_trace", "retrieval_curation", "model_finetune"],
    "evaluation_rubric_ref": "rubric://...",
    "benchmark_profile_ref": "benchmark://...",
    "deployment_target": "autopilot_local | aiagent_listing | sas_outcome",
    "acceptance_criteria": ["evaluation_receipts_present", "benchmark_min_score_met"]
  }
}
```

Response:

```json
{
  "order_id": "order_123",
  "service_order_contract": "0x...",
  "escrow_status": "pending_lock | locked",
  "outcome_workspace_ref": "agentgres://sas/outcome-workspaces/order_123",
  "runtime_assignment_ref": "agentgres://sas/runtime-assignments/assign_123",
  "compute_session": {
    "compute_session_id": "compute_session_123",
    "daemon_profile": "hosted_ioi | provider | depin | tee | customer_vpc | local",
    "substrate": "container | vm | browser_sandbox | gpu_job | tee_enclave | process",
    "status": "pending | warming | running | idle | archived"
  },
  "agentgres_ref": "agentgres://sas/orders/order_123",
  "status": "created"
}
```

The compute session boots an IOI daemon/runtime-node profile. SDK clients may
observe or control the order through APIs, but they are not the execution
substrate.

## Delivery API

```http
POST /v1/orders/{order_id}/deliveries
GET  /v1/deliveries/{delivery_id}
GET  /v1/deliveries/{delivery_id}/artifacts
GET  /v1/deliveries/{delivery_id}/evidence
GET  /v1/deliveries/{delivery_id}/quality
POST /v1/deliveries/{delivery_id}/accept
POST /v1/deliveries/{delivery_id}/reject
```

### Delivery Bundle

```json
{
  "delivery_id": "delivery_123",
  "order_id": "order_123",
  "provider_id": "ioi://publisher/provider",
  "run_ids": ["run_1", "run_2"],
  "output_artifacts": [
    {
      "artifact_id": "artifact_report",
      "cid": "bafy...",
      "sha256": "...",
      "media_type": "application/pdf"
    }
  ],
  "evidence_bundle": ["receipt://execution_1", "receipt://validation_1"],
  "training_delivery": {
    "output_manifest_ref": "optional",
    "training_receipts": ["receipt://training_1"],
    "benchmark_receipts": ["receipt://benchmark_1"],
    "evaluation_report_ref": "optional"
  },
  "quality_summary": {
    "checks_passed": true,
    "score": 0.91,
    "warnings": []
  },
  "settlement": {
    "status": "pending_acceptance",
    "acceptance_deadline": "2026-05-04T00:00:00Z"
  }
}
```

## Provider API

```http
POST /v1/provider/services
PATCH /v1/provider/services/{service_id}
POST /v1/provider/services/{service_id}/versions
POST /v1/provider/services/{service_id}/deprecate
GET  /v1/provider/orders
POST /v1/provider/orders/{order_id}/claim
POST /v1/provider/orders/{order_id}/decline
POST /v1/provider/orders/{order_id}/submit-delivery
GET  /v1/provider/payouts
```

## Escrow / Contract Mirror API

sas.xyz Agentgres mirrors contract state. The chain is authoritative for money; Agentgres is authoritative for operational detail.

```http
GET /v1/orders/{order_id}/escrow
GET /v1/orders/{order_id}/settlement
GET /v1/contracts/service-orders/{contract_id}
```

Mirror shape:

```json
{
  "order_id": "order_123",
  "contract_address": "0x...",
  "escrow_amount": "50",
  "token": "IOI",
  "status": "locked | released | disputed | refunded",
  "last_chain_event": "ServiceOrderEscrowLocked",
  "last_tx_hash": "0x..."
}
```

## Dispute API

```http
POST /v1/disputes
GET  /v1/disputes/{dispute_id}
POST /v1/disputes/{dispute_id}/submit-evidence
POST /v1/disputes/{dispute_id}/propose-resolution
POST /v1/disputes/{dispute_id}/accept-resolution
```

## Non-Negotiables

1. sas.xyz sells outcome contracts, not just agent prompts.
2. Every service order must have an explicit output contract and acceptance criteria.
3. Escrow/payout lives on IOI L1 contracts; operational order state lives in sas.xyz Agentgres.
4. Delivery must include artifacts, evidence, receipts, and settlement state.
5. Managed services may run without user-local Autopilot, through hosted/provider/DePIN/TEE IOI daemon nodes.
6. A service order that spawns remote work must bind the order to an
   OutcomeWorkspace, RuntimeAssignment, ComputeSession, daemon profile,
   authority posture, and verification path.
7. Worker Training orders must deliver manifest, policy, lineage, evaluation,
   benchmark, and receipt evidence rather than raw model artifacts alone.
