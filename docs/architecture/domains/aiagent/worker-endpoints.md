# aiagent.xyz Worker and Inter-Agent Endpoints

Status: canonical low-level reference.
Canonical owner: this file for aiagent.xyz worker endpoint shapes and inter-agent endpoint contracts.
Supersedes: overlapping worker endpoint examples in plans/specs when endpoint fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-14.

## Purpose

aiagent.xyz is the canonical Web4 worker marketplace. It must support
discovery, installation, direct worker invocation, hosted worker execution,
managed worker/agent instances, web-mounted consoles, runtime subscriptions,
Sparse Worker Categories, benchmark submissions, routing eligibility, and
inter-agent calls.

Endpoint metadata should reference
[`digital-worker-ontology.md`](./digital-worker-ontology.md),
[`vertical-ontology-packs.md`](./vertical-ontology-packs.md),
[`integration-surface-taxonomy.md`](./integration-surface-taxonomy.md), and
[`managed-worker-instance-lifecycle.md`](./managed-worker-instance-lifecycle.md)
when behavior depends on ontology, vertical, integration, or lifecycle state.

These surfaces are opt-in. A worker publisher declares which invocation modes a
worker supports, and a user chooses whether to run once, route through MoW,
initialize a managed instance, install locally, call by API, or compose into a
workflow. ioi.ai may coordinate account entitlement, restore, and runtime
discovery for those choices, but aiagent.xyz owns the marketplace endpoint
records and the selected Hypervisor Daemon runtime node executes the work.

## Worker Endpoint Classes

```text
Discovery / Manifest
Sparse Worker Categories / Benchmarks
Compatibility inference
Task execution
Managed worker instance management
Web console and subscription controls
Inter-agent protocol
Artifacts and receipts
Admin/observability
```

A worker may implement these directly, or a compatible Hypervisor Daemon may
expose them on the worker's behalf.

When a worker runs on hosted, provider, DePIN, TEE, customer, or local compute,
the execution venue should be modeled as a Hypervisor Daemon runtime node. SDK
helpers may wrap the endpoint contract, but they do not replace daemon
ownership of runtime execution.

## Discovery and Manifest

```http
GET /.well-known/ai-agent.json
GET /v1/agent/manifest
GET /v1/agent/profile
GET /v1/agent/requirements
GET /v1/agent/pricing
GET /v1/agent/quality
```

### `GET /.well-known/ai-agent.json`

```json
{
  "agent_id": "ai://workers.runtime-auditor.ioi",
  "name": "Runtime Auditor",
  "version": "1.0.0",
  "publisher_id": "ioi://publisher/ioi",
  "worker_type": "persistent_worker",
  "manifest_root": "sha256:...",
  "interfaces": {
    "task": "/v1/agent/tasks",
    "worker": "/v1/worker",
    "interagent": "/v1/interagent",
    "chat_completions": "/v1/chat/completions",
    "threads": "/v1/threads",
    "managed_instance": "/v1/worker/instance",
    "artifacts": "/v1/artifacts",
    "receipts": "/v1/receipts"
  },
  "runtime_requirements": {
    "ioi_daemon": ">=0.8.0",
    "agentgres": ">=0.2.0",
    "daemon_profile": "local | hosted_ioi | provider | depin | tee | customer_vpc"
  },
  "primitive_capabilities_required": ["prim:fs.read", "prim:sys.exec", "prim:model.invoke"],
  "authority_scopes_required": ["scope:repo.read"],
  "privacy_profiles": ["local", "hosted", "depin_mutual_blind", "tee_enterprise"],
  "interaction_surfaces": ["chat", "task", "api", "workflow_node", "scheduler"],
  "persistence_profiles": ["ephemeral", "session", "zero_to_idle", "persistent"],
  "subscription_profiles": ["per_invocation", "warm_runtime", "managed_monthly"],
  "mow": {
    "sparse_worker_category": "std:code:runtime_audit.v1",
    "benchmark_profile_refs": ["benchmark://ioi/categories/runtime_audit/v1"],
    "evaluation_rubric_ref": "rubric://ioi/runtime_audit/v1",
    "routing_eligibility_status": "eligible",
    "training_lineage_ref": "agentgres://training/train_123"
  },
  "ontology": {
    "base_ontology_ref": "ontology:aiagent.base.v1",
    "vertical_pack_refs": ["vertical_pack:coding.review.v1"],
    "integration_surface_refs": ["integration_surface:developer_code"],
    "lifecycle_profile_ref": "lifecycle:managed-worker/default"
  }
}
```

## Sparse Worker Category and Benchmark Endpoints

```http
GET  /v1/categories
GET  /v1/categories/{category_id}
GET  /v1/categories/{category_id}/benchmark-profile
POST /v1/categories/{category_id}/submissions
GET  /v1/categories/{category_id}/submissions/{submission_id}
GET  /v1/categories/{category_id}/leaderboard
GET  /v1/workers/{worker_id}/benchmark-runs
GET  /v1/workers/{worker_id}/routing-eligibility
```

Category and benchmark endpoints expose relative labor-market claims. They do
not prove universal intelligence or permanent superiority.

## Compatibility Inference Endpoints

These are optional. They exist for compatibility with common model clients, but they do not define the worker's primary value.

```http
POST /v1/chat/completions
POST /v1/responses
POST /v1/embeddings
```

Rule:

> Models expose completions. Workers expose responsibilities.

Compatibility calls must specify whether persistence is allowed.

```json
{
  "messages": [],
  "persistence": "none | session | worker_memory",
  "worker_session_id": "optional",
  "worker_instance_id": "optional"
}
```

## Task Execution API

```http
POST /v1/agent/tasks
GET  /v1/agent/tasks/{task_id}
GET  /v1/agent/tasks/{task_id}/events
GET  /v1/agent/tasks/{task_id}/artifacts
GET  /v1/agent/tasks/{task_id}/receipts
POST /v1/agent/tasks/{task_id}/pause
POST /v1/agent/tasks/{task_id}/resume
POST /v1/agent/tasks/{task_id}/cancel
POST /v1/agent/tasks/{task_id}/approve
POST /v1/agent/tasks/{task_id}/deny
```

### `POST /v1/agent/tasks`

```json
{
  "objective": "Audit the Git overlay adapter for stale write risks.",
  "context_refs": ["agentgres://project/hypervisor", "git://repo/ioi"],
  "constraints": {
    "deadline": "2026-05-01T12:00:00Z",
    "max_budget_usd": 10,
    "requires_human_approval_for": ["file_write", "external_message"]
  },
  "output_contract": {
    "type": "audit_report_plus_task_requests",
    "required_artifacts": ["summary", "evidence_bundle", "proposed_tasks"],
    "required_receipts": ["execution", "validation"]
  },
  "authority_grants": ["grant_..."],
  "execution_profile": "local | hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc"
}
```

Response:

```json
{
  "task_id": "task_abc",
  "run_id": "run_123",
  "status": "accepted",
  "events": "/v1/agent/tasks/task_abc/events",
  "run_room": "agentgres://runroom/run_123"
}
```

## Managed Worker/Agent Instance API

For digital employees, cron agents, long-duration planner agents, and
web-native user-facing instances. Product UX may call these "agents," but the
protocol object remains a managed worker instance backed by an IOI
daemon/runtime-node profile.

```http
GET  /v1/worker/instance
PATCH /v1/worker/instance
GET  /v1/worker/profile
GET  /v1/worker/status
POST /v1/worker/suspend
POST /v1/worker/resume
POST /v1/worker/archive
GET  /v1/worker/objectives
POST /v1/worker/objectives
GET  /v1/worker/standing-orders
POST /v1/worker/standing-orders
PATCH /v1/worker/standing-orders/{id}
DELETE /v1/worker/standing-orders/{id}
GET  /v1/worker/inbox
POST /v1/worker/inbox/{item_id}/respond
GET  /v1/worker/runs
GET  /v1/worker/memory/summary
GET  /v1/worker/digests
POST /v1/worker/schedules
GET  /v1/worker/subscription
PATCH /v1/worker/subscription
GET  /v1/worker/threads
POST /v1/worker/threads
```

### Managed Instance

```json
{
  "worker_instance_id": "agent://runtime-auditor/heath/default",
  "worker_id": "worker://runtime-auditor.ioi",
  "install_id": "install_123",
  "owner_id": "wallet://user_123",
  "runtime_assignment_id": "assign_456",
  "execution_profile": "hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc | local",
  "persistence_profile": "ephemeral | session | zero_to_idle | persistent",
  "interaction_surfaces": ["chat", "task", "api", "scheduler"],
  "status": "starting | running | idle | suspended | archived | failed",
  "thread_endpoint": "/v1/threads",
  "subscription": {
    "mode": "per_invocation | warm_runtime | managed_monthly",
    "entitlement_ref": "ioi.ai://entitlement/...",
    "budget_policy_ref": "policy://..."
  }
}
```

### Standing Order

```json
{
  "title": "Weekly runtime hardening audit",
  "cadence": "weekly",
  "scope": {
    "project": "agentgres://project/hypervisor",
    "repos": ["git://repo/ioi"]
  },
  "instructions": "Review recent runtime failures and propose hardening tasks.",
  "outputs": ["digest", "risk_updates", "task_requests"],
  "approval_required_for": ["code_write", "external_message"]
}
```

## Inter-Agent Protocol

```http
POST /v1/interagent/message
POST /v1/interagent/authority-query
POST /v1/interagent/task-offer
POST /v1/interagent/task-accept
POST /v1/interagent/task-reject
POST /v1/interagent/handoff
POST /v1/interagent/evidence-request
POST /v1/interagent/decision-request
POST /v1/interagent/patch-proposal
POST /v1/interagent/status-request
```

### Authority Query

```json
{
  "requester": "agent://planner",
  "need": "audit Rust storage engine risks",
  "primitive_capabilities_needed": ["prim:fs.read", "prim:model.invoke"],
  "authority_scopes_needed": ["scope:repo.read"],
  "constraints": {
    "requires_code_read": true,
    "requires_receipts": true,
    "max_budget_usd": 20,
    "deadline": "2026-05-02"
  }
}
```

### Handoff

```json
{
  "type": "handoff",
  "from": "agent://planner",
  "to": "agent://runtime-auditor",
  "project_ref": "agentgres://project/hypervisor",
  "reason": "Need targeted audit of Agentgres write-path invariants.",
  "context_refs": ["agentgres://decision/agentgres-storage-profile"],
  "expected_output": {
    "type": "audit_report",
    "deadline": "2026-05-02T12:00:00Z"
  }
}
```

## Artifact and Receipt API

```http
GET /v1/artifacts/{artifact_id}
GET /v1/artifact-bundles/{bundle_id}
GET /v1/receipts/{receipt_id}
GET /v1/runs/{run_id}/delivery-bundle
```

## Marketplace Install API

These endpoints are usually exposed by aiagent.xyz, not each worker.

```http
GET  /v1/marketplace/workers
GET  /v1/marketplace/workers/{worker_id}
GET  /v1/marketplace/workers/{worker_id}/versions
POST /v1/marketplace/workers/{worker_id}/install
POST /v1/marketplace/workers/{worker_id}/invoke
POST /v1/marketplace/workers/{worker_id}/instances
GET  /v1/marketplace/installs/{install_id}
GET  /v1/marketplace/instances/{worker_instance_id}
POST /v1/marketplace/instances/{worker_instance_id}/suspend
POST /v1/marketplace/instances/{worker_instance_id}/resume
POST /v1/marketplace/instances/{worker_instance_id}/archive
GET  /v1/marketplace/instances/{worker_instance_id}/subscription
PATCH /v1/marketplace/instances/{worker_instance_id}/subscription
```

Install response:

```json
{
  "install_id": "install_123",
  "license_right_id": "l1_license_456",
  "package_ref": "cid://bafy...",
  "manifest_root": "sha256:...",
  "primitive_capabilities_required": ["prim:fs.read", "prim:model.invoke"],
  "authority_scopes_required": ["scope:repo.read"],
  "target_runtime_options": ["local_hypervisor", "hosted_ioi", "provider", "depin_mutual_blind", "tee_enterprise"],
  "interaction_surfaces": ["chat", "task", "api", "workflow_node"],
  "persistence_profiles": ["ephemeral", "zero_to_idle", "persistent"]
}
```

Instance creation response:

```json
{
  "worker_instance_id": "agent://runtime-auditor/heath/default",
  "install_id": "install_123",
  "runtime_assignment_id": "assign_456",
  "status": "starting",
  "console_url": "https://aiagent.xyz/instances/agent_...",
  "thread_endpoint": "/v1/threads",
  "events": "/v1/runs/run_123/events",
  "receipts": "/v1/runs/run_123/receipts"
}
```

## Non-Negotiables

1. A worker endpoint must never require raw user secrets.
2. Every effectful worker invocation must bind to an authority grant or approval.
3. Every marketplace invocation must emit a `WorkerInvocation` record and `ContributionReceipt` when materially used.
4. Hosted workers must expose status, events, artifacts, and receipts.
5. Managed instances must expose status, thread/run controls, subscription
   state, standing orders, inbox, schedules, and memory summary.
6. Web consoles are clients over daemon/domain APIs; they must not hide a
   separate execution loop inside aiagent.xyz.
