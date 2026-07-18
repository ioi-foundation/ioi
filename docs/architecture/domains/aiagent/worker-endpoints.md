# aiagent.xyz Worker and Inter-Agent Endpoints

Status: canonical low-level reference.
Canonical owner: this file for aiagent.xyz worker endpoint shapes and inter-agent endpoint contracts.
Supersedes: overlapping worker endpoint examples in plans/specs when endpoint fields conflict.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: reference
Implementation status: planned (endpoint spec; draft plane implements a small
listing/candidate/review/offer subset; private registration, local-agent
pairing, promotion, benchmark, install, invocation, and managed-instance routes
below are not live unless separately audited)
Last implementation audit: 2026-07-05

## Purpose

aiagent.xyz is the canonical Web4 worker marketplace. It must support
discovery, installation, direct worker invocation, hosted worker execution,
managed worker/agent instances, web-mounted consoles, runtime subscriptions,
Sparse Worker Categories, benchmark submissions, routing eligibility, and
inter-agent calls. It must also support a private **My workers** registry for
reusable local Worker compositions without forcing those workers into public
listing, benchmarking, or Network/Open routing.

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

A user may instead connect an existing local agent as a one-room ioi.ai guest,
save the exact composition as an owner- or organization-private reusable
worker, or explicitly promote it through aiagent.xyz admission. Those are
separate states. A room guest needs no aiagent.xyz record; a private
registration has no public listing; and promotion, benchmark admission,
publication, and MoW routing eligibility remain separate explicit actions.

## Worker Endpoint Classes

```text
Discovery / Manifest
Private worker registration / local-agent pairing / promotion
Sparse Worker Categories / Benchmarks
Marketplace admission
Compatibility inference
Task execution
Managed worker instance management
Web console and subscription controls
Integration export bundle
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
    "responses": "/v1/responses",
    "mcp": "/v1/mcp",
    "threads": "/v1/threads",
    "managed_instance": "/v1/worker/instance",
    "artifacts": "/v1/artifacts",
    "receipts": "/v1/receipts",
    "contact_channels": "/v1/worker/contact-channels"
  },
  "runtime_requirements": {
    "ioi_daemon": ">=0.8.0",
    "agentgres": ">=0.2.0",
    "daemon_profile": "local | hosted_ioi | provider | depin | tee | customer_vpc"
  },
  "composition": {
    "composition_id": "composition://runtime-auditor/1.0.0/qwen-coder/local",
    "source_provenance_refs": ["git://github.com/example/runtime-auditor#v1.0.0"],
    "license_ref": "license://apache-2.0",
    "maintainer_refs": ["ioi://publisher/example"],
    "harness_profile_revision_ref": "harness-profile://coding/step-resolution/revision/1",
    "harness_profile_content_hash": "sha256:...",
    "agent_harness_adapter_revision_ref": "agent-harness-adapter://coding/loop/revision/1",
    "agent_harness_adapter_content_hash": "sha256:...",
    "model_route_options": [
      {
        "route_id": "model_route://qwen-coder-local",
        "model_ref": "model://qwen/coder",
        "selection_policy": "user_selected | package_default | router_selected",
        "privacy_profiles": ["local", "private_workspace_ctee"]
      }
    ],
    "build_recipe_ref": "build://runtime-auditor/v1",
    "sbom_ref": "artifact://sbom/runtime-auditor/v1",
    "security_scan_refs": ["scan://runtime-auditor/v1"]
  },
  "primitive_capabilities_required": ["prim:fs.read", "prim:sys.exec", "prim:model.invoke"],
  "authority_scopes_required": ["scope:repo.read"],
  "privacy_profiles": ["local", "hosted", "depin_mutual_blind", "tee_enterprise"],
  "interaction_surfaces": ["chat", "task", "api", "workflow_node", "scheduler", "background_service"],
  "contact_delivery_channels": ["web_console", "email", "slack", "webhook", "mcp_callback"],
  "persistence_profiles": ["ephemeral", "session", "zero_to_idle", "persistent"],
  "subscription_profiles": ["per_invocation", "warm_runtime", "managed_monthly"],
  "mow": {
    "sparse_worker_category": "std:code:runtime_audit.v1",
    "benchmark_profile_refs": ["benchmark://ioi/categories/runtime_audit/v1"],
    "evaluation_rubric_ref": "rubric://ioi/runtime_audit/v1",
    "listing_status": "routing_eligible",
    "benchmark_status": "passed",
    "latest_benchmark_run_ref": "benchmark_run://bench_123",
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

## Private Worker Registration, Pairing, And Promotion

The private-registry and promotion endpoints below back the **My workers**
supply surface. They are planned. Local pairing compiles to the shared
Hypervisor routes owned by the daemon API; listing those routes here is a
cross-domain product-flow reference, not duplicate endpoint ownership or
evidence of a live remote-agent runtime.

```http
POST /v1/hypervisor/local-agent-pairings
GET  /v1/hypervisor/local-agent-pairings/{pairing_ref}
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/claim
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/complete
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/cancel
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/revoke

GET    /v1/worker-registrations
POST   /v1/worker-registrations
GET    /v1/worker-registrations/{registration_ref}
PATCH  /v1/worker-registrations/{registration_ref}
DELETE /v1/worker-registrations/{registration_ref}
POST   /v1/worker-registrations/{registration_ref}/re-pair
POST   /v1/worker-registrations/{registration_ref}/preflight
POST   /v1/worker-registrations/{registration_ref}/revoke

POST /v1/worker-registrations/{registration_ref}/promotion-proposals
GET  /v1/worker-registrations/{registration_ref}/promotion-proposals
GET  /v1/worker-registrations/{registration_ref}/promotion-proposals/{promotion_ref}
POST /v1/worker-registrations/{registration_ref}/promotion-proposals/{promotion_ref}/submit
POST /v1/worker-registrations/{registration_ref}/promotion-proposals/{promotion_ref}/cancel
```

### Pairing Session Projection

`LocalAgentPairingSessionEnvelope` is the canonical shared object. The create
route accepts only one declared target:

```json
{
  "target_kind": "room_guest | private_worker | organization_worker",
  "target_scope_ref": "outcome-room://... | user://... | org://...",
  "room_discovery_ref": "room-discovery://... | null",
  "claimed_local_agent": {
    "display_name": "Runtime Auditor",
    "resolver_kind": "harness_profile | agent_harness_adapter | none",
    "resolver_revision_ref": "harness-profile://.../revision/... | agent-harness-adapter://.../revision/... | null",
    "resolver_content_hash": "sha256:... | null",
    "semantic_harness_profile_revision_ref": "harness-profile://.../revision/... | null",
    "semantic_harness_profile_content_hash": "sha256:... | null",
    "execution_posture": "instrumented_adapter | prompt_only"
  },
  "pairing_transport": "loopback | device_code | copy_command",
  "expires_in_seconds": 600
}
```

`room_guest` is initiated from the ioi.ai/OutcomeRoom flow and does not create a
private registration. `private_worker` and `organization_worker` completion
records the submitted composition; a separate aiagent.xyz registration
admission may then create the private record. The returned projection contains
an expiring challenge, a loopback/device-code/copy-command bootstrap
instruction, and only these bootstrap actions:

```text
read_discovery
submit_worker_composition
submit_room_participation_request
```

The copyable instruction is setup convenience, not identity or authority. It
must not contain a durable organization credential, broad bucket permission,
room-database token, raw connector secret, ambient MCP access, or permission to
execute effects. The local agent proves control of its generated key and origin
binding through the selected pairing transport. Ordinary AIIP participation
begins only after `bootstrap_bound`.

The product returns the exact shared lifecycle:

```text
created | challenge_issued | agent_proof_received | bootstrap_bound |
composition_submitted | participation_submitted | completed | expired |
rejected | cancelled | revoked | failed_closed
```

Completion refs may include `composition://...` and, for a room guest,
`participation-request://...`. `completed` proves only the declared pairing
boundary; it grants no room membership, private context, database access,
budget, tool capability, effect authority, benchmark standing, listing, or
task success. The session fails closed on expiry, replay, principal/origin
mismatch, unsupported adapter, invalid composition, or revoked target using the
shared failure codes: `challenge_expired`, `challenge_replayed`,
`invalid_proof`, `key_mismatch`, `origin_mismatch`, `attempt_exhausted`,
`rate_limited`, `scope_escalation`, `malformed_submission`, `policy_denied`, or
`target_unavailable`. Product-specific explanations must map to one of those
codes rather than extending the envelope locally.

The private-registration preflight route uses
`execution_posture: prompt_only` and `contribution_lane: proposal_only` by
default. It checks adapter reachability, typed request/result support, evidence
delivery, revocation, and bounded failure behavior without granting an
effectful tool surface. A `prompt_only` agent remains at an `attested`
assurance ceiling until its bounded contribution is independently evaluated;
copied instructions and self-reported runtime or model metadata are not proof.

### Private Registration Projection

`POST /v1/worker-registrations` adopts a completed private/organization pairing
or an otherwise policy-admitted exact Worker composition:

```json
{
  "pairing_session_ref": "local-agent-pairing://... | null",
  "worker_composition_ref": "composition://...",
  "visibility": "owner_private | organization_private",
  "owner_ref": "user://... | org://...",
  "display_profile": {
    "name": "Runtime Auditor",
    "description": "Reviews bounded repository changes.",
    "persona": "optional descriptive metadata only"
  },
  "invocation_policy_ref": "policy://...",
  "eligible_goal_space_policy_ref": "policy://..."
}
```

Response:

```json
{
  "registration_ref": "worker-registration://...",
  "worker_composition_ref": "composition://...",
  "visibility": "owner_private | organization_private",
  "status": "pending_preflight | ready | offline | incompatible | expired | revoked | re_pair_required",
  "public_listing_ref": null,
  "benchmark_status": "unbenchmarked",
  "routing_eligibility_status": "private_only",
  "last_preflight_receipt_ref": "receipt://... | null"
}
```

Private visibility is fail-closed. Registration does not create a publisher
profile, public artifact, category submission, benchmark run, public reputation
entry, settlement offer, or training permission. `PATCH` may change descriptive
metadata or policy within the owner's authority; a material composition,
principal, adapter, model-route, tool, privacy, or runtime change creates a new
version and may require re-pairing or preflight. Delete/revoke ends future use
while preserving only the receipt, dispute, audit, and contribution lineage
required by policy.

### Promotion Projection

A promotion proposal selects the exact public disclosure rather than flipping
the private registration's visibility:

```json
{
  "worker_composition_ref": "composition://...",
  "public_manifest_field_allowlist": [
    "name",
    "task_classes",
    "output_contracts",
    "dependencies",
    "benchmark_profile_refs",
    "license_ref"
  ],
  "public_artifact_refs": ["artifact://package/..."],
  "sparse_worker_category": "std:code:runtime_audit.v1",
  "benchmark_profile_refs": ["benchmark://ioi/categories/runtime_audit/v1"],
  "license_ref": "license://...",
  "pricing_ref": "pricing://... | null",
  "contribution_history_export_policy_ref": "policy://... | null"
}
```

Submitting the proposal creates or binds the existing marketplace admission
record. It does not publish automatically. The seller must still satisfy the
quote/waiver, benchmark and admission gates, then invoke the separate
`POST /v1/marketplace/submissions/{submission_id}/publish` action. Public
listing still does not imply MoW routing eligibility. Cancelling or rejecting a
promotion leaves the private registration intact and unexposed.

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

## Marketplace Admission Endpoints

```http
POST /v1/marketplace/workers/submissions
GET  /v1/marketplace/submissions/{submission_id}
GET  /v1/marketplace/submissions/{submission_id}/quote
POST /v1/marketplace/submissions/{submission_id}/pay
POST /v1/marketplace/submissions/{submission_id}/benchmark
GET  /v1/marketplace/submissions/{submission_id}/benchmark-runs
POST /v1/marketplace/submissions/{submission_id}/publish
POST /v1/marketplace/submissions/{submission_id}/appeal
```

Submission creates an admission record for a specific worker composition. The
quote covers benchmark compute, queueing, and review overhead. Payment,
staking, waiver, or sponsorship may satisfy the quote, but it must not purchase
ranking or routing eligibility.

```json
{
  "submission_id": "submission://runtime-auditor/1.0.0",
  "worker_package_ref": "package://runtime-auditor/1.0.0",
  "composition_id": "composition://runtime-auditor/1.0.0/qwen-coder/local",
  "sparse_worker_category": "std:code:runtime_audit.v1",
  "benchmark_profile_refs": ["benchmark://ioi/categories/runtime_audit/v1"],
  "submission_quote_ref": "quote://benchmark/runtime-auditor/1.0.0",
  "admission_payment_ref": "payment://...",
  "status": "submitted | quote_pending | awaiting_payment | benchmarking | listed | rejected | appealed",
  "spam_risk": "low | medium | high",
  "waiver_policy_ref": "optional"
}
```

Benchmark, listing, and routing eligibility metadata must bind to the manifest
hash, composition version, model route policy, harness adapter, runtime
profile, privacy posture, policy hash, and benchmark environment that produced
the score.

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

When a managed instance advertises model-compatible use, the model identifier
should resolve to the worker package or managed instance, not to an unbound raw
model checkpoint. Compatibility requests still flow through daemon execution,
authority-approved scopes, Agentgres state, and receipts when the invocation is
effectful or materially contributes to an outcome.

## Integration Export Bundle

aiagent.xyz should expose a copyable integration bundle for each package or
managed instance that supports external use. The bundle is a projection over
existing endpoints; it does not create a separate runtime or authority system.

```http
GET /v1/worker/integration-exports
GET /v1/marketplace/instances/{worker_instance_id}/integration-exports
```

Example:

```json
{
  "worker_instance_id": "agent://runtime-auditor/heath/default",
  "web_console": {
    "url": "https://aiagent.xyz/instances/agent_..."
  },
  "worker_api": {
    "task_endpoint": "/v1/agent/tasks",
    "thread_endpoint": "/v1/threads",
    "events_endpoint": "/v1/agent/tasks/{task_id}/events",
    "receipts_endpoint": "/v1/agent/tasks/{task_id}/receipts"
  },
  "model_compatible_api": {
    "base_url": "https://api.aiagent.xyz/v1",
    "wire_apis": ["responses", "chat_completions"],
    "model": "agent://runtime-auditor/heath/default",
    "persistence": "none | session | worker_memory"
  },
  "mcp": {
    "server_url": "https://api.aiagent.xyz/v1/mcp/agent/...",
    "tool_namespace": "aiagent.runtime_auditor"
  },
  "workflow_node": {
    "endpoint": "/v1/agent/tasks",
    "output_contract_ref": "contract://..."
  },
  "local_hypervisor_install": {
    "package_ref": "cid://bafy...",
    "manifest_root": "sha256:..."
  },
  "authority_client": {
    "client_ref": "wallet_client://...",
    "scopes": ["scope:repo.read"],
    "expires_at": "2026-05-02T12:00:00Z",
    "revoke_endpoint": "/v1/authority/clients/{client_id}/revoke"
  },
  "contact_delivery_channels": {
    "configured": [
      {
        "channel_ref": "contact_channel://slack/product-analytics",
        "kind": "slack",
        "posture": "summary_delivery",
        "redaction_policy_ref": "policy://redacted-weekly-digest",
        "test_endpoint": "/v1/worker/contact-channels/contact_channel.../test",
        "disable_endpoint": "/v1/worker/contact-channels/contact_channel.../disable"
      }
    ],
    "available": ["web_console", "email", "sms", "slack", "discord", "telegram", "webhook", "mcp_callback", "mobile_push"]
  }
}
```

An exported API key or token is an authority client, not a durable master
secret. It must carry scopes, expiry or rotation policy, spend limits when
applicable, last-use visibility, and revoke behavior.

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
  "task_id": "task://abc",
  "run_id": "run://123",
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
GET  /v1/worker/config-revisions
POST /v1/worker/config-revisions
GET  /v1/worker/change-plans
POST /v1/worker/change-plans
GET  /v1/worker/change-plans/{change_plan_id}
POST /v1/worker/change-plans/{change_plan_id}/dry-run
POST /v1/worker/change-plans/{change_plan_id}/apply
POST /v1/worker/change-plans/{change_plan_id}/rollback
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
GET  /v1/worker/contact-channels
POST /v1/worker/contact-channels
PATCH /v1/worker/contact-channels/{channel_id}
POST /v1/worker/contact-channels/{channel_id}/test
POST /v1/worker/contact-channels/{channel_id}/disable
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
  "worker_composition_ref": "composition://runtime-auditor/1.0.0/qwen-coder/local",
  "selected_model_route_ref": "model_route://qwen-coder-local",
  "active_config_revision_ref": "config_revision://runtime-auditor/heath/default/7",
  "pending_change_plan_refs": ["change_plan://runtime-auditor/heath/default/8"],
  "execution_privacy_posture_ref": "privacy_posture://local",
  "runtime_assignment_id": "assign_456",
  "runtime_management_channel_ref": "management_channel://assign_456",
  "execution_profile": "hosted | provider | depin_mutual_blind | tee_enterprise | customer_vpc | local",
  "persistence_profile": "ephemeral | session | zero_to_idle | persistent",
  "interaction_surfaces": ["chat", "task", "api", "model_compatible_api", "mcp", "scheduler"],
  "contact_channel_bindings": [
    {
      "channel_ref": "contact_channel://slack/product-analytics",
      "kind": "slack",
      "posture": "summary_delivery",
      "connector_ref": "connector://slack/workspace_123",
      "integration_surface_ref": null,
      "redaction_policy_ref": "policy://redacted-weekly-digest",
      "quiet_hours_policy_ref": "policy://business-hours",
      "last_test_receipt_ref": "receipt://..."
    }
  ],
  "notification_policy_ref": "policy://...",
  "status": "starting | running | idle | suspended | archived | failed",
  "thread_endpoint": "/v1/threads",
  "subscription": {
    "mode": "per_invocation | warm_runtime | managed_monthly",
    "entitlement_ref": "ioi.ai://entitlement/...",
    "budget_policy_ref": "policy://..."
  }
}
```

### Managed Instance Configuration Change

Persistent managed workers should not be updated through an unstructured
`PATCH`. The PATCH endpoint is compatibility sugar for creating a config
revision and, when required, a change plan.

```json
{
  "change_plan_id": "change_plan://runtime-auditor/heath/default/8",
  "worker_instance_id": "agent://runtime-auditor/heath/default",
  "from_config_revision_ref": "config_revision://runtime-auditor/heath/default/7",
  "to_config_revision_ref": "config_revision://runtime-auditor/heath/default/8",
  "change_kinds": ["connector_binding", "schedule", "model_route"],
  "risk_class": "policy_widening",
  "required_gates": ["authority_provider", "dry_run"],
  "status": "waiting_for_authority",
  "dry_run_endpoint": "/v1/worker/change-plans/change_plan_8/dry-run",
  "apply_endpoint": "/v1/worker/change-plans/change_plan_8/apply",
  "rollback_config_revision_ref": "config_revision://runtime-auditor/heath/default/7",
  "receipt_refs": ["receipt://..."]
}
```

Safe live edits may apply immediately after admission. Connector, tool, standing
order, route-policy, harness, runtime, memory-sharing, package-version, privacy,
or authority-broadening changes must expose their required gates before apply.

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
GET  /v1/mcp/manifest
POST /v1/mcp/call
```

MCP exposure is the tool-style compatibility face for harnesses and other
agents. It must bind back to the worker package or managed instance, use the
same authority-client and receipt rules as direct task execution, and avoid raw
user-secret custody.

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
GET  /v1/marketplace/instances/{worker_instance_id}/config-revisions
POST /v1/marketplace/instances/{worker_instance_id}/config-revisions
GET  /v1/marketplace/instances/{worker_instance_id}/change-plans
POST /v1/marketplace/instances/{worker_instance_id}/change-plans
POST /v1/marketplace/instances/{worker_instance_id}/change-plans/{change_plan_id}/dry-run
POST /v1/marketplace/instances/{worker_instance_id}/change-plans/{change_plan_id}/apply
POST /v1/marketplace/instances/{worker_instance_id}/change-plans/{change_plan_id}/rollback
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
  "interaction_surfaces": ["chat", "task", "api", "model_compatible_api", "mcp", "workflow_node"],
  "contact_delivery_channels_available": ["web_console", "email", "sms", "slack", "discord", "telegram", "webhook", "mcp_callback", "mobile_push"],
  "required_connector_refs": ["connector://databricks-sql"],
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
  "contact_channel_setup_url": "https://aiagent.xyz/instances/agent_.../contact-channels",
  "thread_endpoint": "/v1/threads",
  "integration_exports": "/v1/marketplace/instances/agent_.../integration-exports",
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
   state, standing orders, inbox, schedules, contact/delivery channels, and
   memory summary.
6. Web consoles are clients over daemon/domain APIs; they must not hide a
   separate execution loop inside aiagent.xyz.
7. Integration exports must be projections over declared worker interfaces and
   scoped authority clients, not unbounded provider secrets.
8. Contact channels must disclose whether they are notification-only or also
   work integrations. Notification-only channels cannot hold secrets, protected
   plaintext, durable authority, or high-risk approvals.
9. Pairing routes must return and persist the exact
   `LocalAgentPairingSessionEnvelope` lifecycle. Pairing completion records
   bootstrap submission only; it must not imply Worker registration, room
   admission, authority, capability, benchmark standing, publication, or task
   success.
10. A room-scoped guest must not require a private/public aiagent.xyz record,
    and its participant lease must not become ambient reusable-worker access.
11. Private Worker registration must default to owner/org visibility and
    `private_only` routing eligibility. No endpoint may silently publish,
    benchmark, rank, route, monetize, or train from it.
12. Public promotion must use a separate disclosure proposal, marketplace
    admission, benchmark posture, and publish action. Cancelling or rejecting
    promotion must leave the private registration unexposed.
13. Prompt, persona, values, goals, display name, copied bootstrap text, and
    self-reported model/runtime claims are descriptive inputs, not identity,
    capability, independence, evidence, or authority.
14. Pairing bootstrap actions are a closed set and never include room-database
    access, raw secrets, ambient MCP, budget, spend, effect execution, install,
    invocation, publication, or settlement.
