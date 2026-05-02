# IOI Daemon Runtime API

Status: canonical low-level reference.
Canonical owner: this file for public daemon/runtime API endpoints, event streaming, run lifecycle, structured errors, and client-vs-runtime ownership.
Supersedes: older daemon/SDK/CLI endpoint lists when endpoint shape conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

The IOI daemon is the universal execution endpoint for canonical Web4. The IOI CLI/TUI, `@ioi/agent-sdk`, agent-ide, Autopilot, workflow compositor, harnesses, and benchmarks are clients over this public runtime API. They must not own separate execution semantics. Local Autopilot, hosted providers, DePIN nodes, TEE nodes, and customer VPC nodes run daemon-compatible runtime nodes to execute workers, workflows, model calls, tools, connectors, and artifact production.

## Runtime Identity and Health

```http
GET /v1/runtime/manifest
GET /v1/runtime/health
GET /v1/runtime/primitive-capabilities
GET /v1/runtime/resources
GET /v1/runtime/attestation
GET /v1/runtime/policy
GET /v1/runtime/nodes
```

### Runtime Manifest

```json
{
  "runtime_id": "runtime://node_abc",
  "runtime_type": "local_autopilot | hosted_ioi | provider | depin | tee | customer_vpc",
  "daemon_version": "0.8.0",
  "agentgres_version": "0.2.0",
  "supported_execution_profiles": ["local", "hosted", "depin_mutual_blind", "tee_enterprise"],
  "supported_interfaces": ["agents", "runs", "workers", "tools", "models", "connectors", "artifacts", "receipts", "trace", "replay", "scorecards"],
  "primitive_capabilities": ["prim:fs.read", "prim:fs.write", "prim:sys.exec", "prim:net.request", "prim:model.invoke"],
  "attestation": {
    "required": false,
    "provider": null
  }
}
```

## Worker Install and Inventory

```http
GET  /v1/workers
POST /v1/workers/install
GET  /v1/workers/{worker_id}
DELETE /v1/workers/{worker_id}
POST /v1/workers/{worker_id}/upgrade
GET  /v1/workers/{worker_id}/manifest
```

### Install Worker

```json
{
  "worker_manifest_ref": "ai://workers.runtime-auditor.ioi@1.0.0",
  "package_ref": "cid://bafy...",
  "manifest_root": "sha256:...",
  "license_right_id": "license_123",
  "install_scope": "user | project | org | runtime",
  "authority_policy": {
    "primitive_capabilities_required": ["prim:fs.read", "prim:sys.exec"],
    "authority_scopes_required": ["scope:repo.read"],
    "approval_required_for": ["file.write"]
  }
}
```

## Agent and Run Lifecycle

```http
POST /v1/agents
GET  /v1/agents
GET  /v1/agents/{agent_id}
DELETE /v1/agents/{agent_id}
POST /v1/agents/{agent_id}/archive
POST /v1/agents/{agent_id}/unarchive
GET  /v1/agents/{agent_id}/messages
POST /v1/agents/{agent_id}/runs
GET  /v1/agents/{agent_id}/runs
GET  /v1/runs/{run_id}
GET  /v1/runs/{run_id}/events
GET  /v1/runs/{run_id}/events?after={cursor}&mode=replay|tail|replay-and-tail
GET  /v1/runs/{run_id}/artifacts
GET  /v1/runs/{run_id}/artifacts/{artifact_id}
GET  /v1/runs/{run_id}/receipts
GET  /v1/runs/{run_id}/conversation
GET  /v1/runs/{run_id}/status
GET  /v1/runs/{run_id}/wait
POST /v1/runs/{run_id}/pause
POST /v1/runs/{run_id}/resume
POST /v1/runs/{run_id}/cancel
POST /v1/runs/{run_id}/approve
POST /v1/runs/{run_id}/deny
POST /v1/runs/{run_id}/replay
GET  /v1/runs/{run_id}/trace
GET  /v1/runs/{run_id}/inspect
GET  /v1/runs/{run_id}/scorecard
GET  /v1/runs/{run_id}/export
GET  /v1/runs/{run_id}/verify
GET  /v1/models
GET  /v1/repositories
GET  /v1/account
```

### Start Run

```json
{
  "task": {
    "objective": "Generate a workflow that audits runtime traces.",
    "task_class": "workflow",
    "privacy_class": "internal"
  },
  "worker_id": "optional",
  "workflow_ref": "optional",
  "execution_profile": "local | hosted | depin_mutual_blind | tee_enterprise",
  "input_refs": ["artifact://..."],
  "authority_grants": ["grant_..."],
  "primitive_capabilities_required": ["prim:model.invoke"],
  "authority_scopes_required": ["scope:repo.read"],
  "output_contract": {
    "type": "delivery_bundle",
    "required_receipts": ["execution", "validation"]
  }
}
```

## Event Stream

The event endpoint may use SSE, WebSocket, or newline-delimited JSON. Events must conform to `RuntimeEventEnvelope`.

```http
GET /v1/runs/{run_id}/events?format=sse|ndjson|websocket&after={cursor}&mode=replay|tail|replay-and-tail
```

Ordering rule:

> A tool execution event must never appear before a policy decision event that permits it.

Cursor rule:

> Event cursors must be monotonic, terminal events must be emitted exactly once, and reconnecting after a terminal cursor must not duplicate the terminal event.

## Approval Handling

```http
GET  /v1/approvals
GET  /v1/approvals/{approval_id}
POST /v1/approvals/{approval_id}/approve
POST /v1/approvals/{approval_id}/deny
POST /v1/approvals/{approval_id}/edit-and-approve
```

Approval request shape:

```json
{
  "approval_id": "approval_123",
  "run_id": "run_123",
  "request_hash": "sha256:...",
  "policy_hash": "sha256:...",
  "action": "gmail.send",
  "risk_class": "external_message",
  "preview": "redacted preview",
  "expires_at": "2026-05-01T00:00:00Z"
}
```

## Tool API

```http
GET  /v1/tools
GET  /v1/tools/{tool_id}
POST /v1/tools/{tool_id}/dry-run
POST /v1/tools/{tool_id}/call
GET  /v1/tools/{tool_id}/policy
```

Effectful tools must be called through a run, not ad hoc, unless operator mode explicitly allows and records a run.

## Model API

```http
GET  /v1/models
GET  /v1/models/routes
POST /v1/models/mount
POST /v1/models/unmount
POST /v1/models/invoke
GET  /v1/models/invocations/{id}
```

## Connector API

```http
GET  /v1/connectors
GET  /v1/connectors/{connector_id}
POST /v1/connectors/{connector_id}/auth/start
POST /v1/connectors/{connector_id}/auth/callback
GET  /v1/connectors/{connector_id}/tools
POST /v1/connectors/{connector_id}/subscriptions
```

## Artifact and Receipt API

```http
POST /v1/artifacts
GET  /v1/artifacts/{artifact_id}
GET  /v1/artifact-bundles/{bundle_id}
GET  /v1/receipts/{receipt_id}
GET  /v1/trace-bundles/{run_id}
```

## Structured Error Shape

Every public daemon error uses the same redacted shape:

```json
{
  "error": {
    "code": "policy_denied | not_found | invalid_request | unavailable | conflict | internal",
    "message": "safe operator-facing message",
    "request_id": "req_...",
    "retryable": false,
    "status": 403,
    "redaction_status": "redacted"
  }
}
```

## Agentgres Sync

```http
GET  /v1/agentgres/status
POST /v1/agentgres/sync
GET  /v1/agentgres/projections
GET  /v1/agentgres/watermark
```

## Node Placement and Assignment

```http
POST /v1/runtime/assignments
GET  /v1/runtime/assignments/{assignment_id}
POST /v1/runtime/assignments/{assignment_id}/accept
POST /v1/runtime/assignments/{assignment_id}/reject
```

## Non-Negotiables

1. The daemon is the execution target; it is not the public marketplace or app database.
2. Every run must produce events, receipts, artifacts when applicable, and trace export.
3. The daemon cannot receive raw secrets unless it is local/customer-controlled or Enterprise Secure mode with attestation.
4. All effectful actions require policy decision persistence.
5. Every exposed API must support redacted diagnostic export.
6. SDK, CLI, GUI, workflow compositor, harness, and benchmark clients must observe the same run contracts rather than owning separate runtimes.
