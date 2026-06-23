# Connector and Tool Contracts

Status: canonical low-level reference.
Canonical owner: this file for RuntimeToolContract, ConnectorMapping
references, Hypervisor MCP Gateway profiles, tool API, connector API, risk
classes, and approval rules.
Supersedes: older flattened tool capability examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-06-22.

## Purpose

Connectors expose typed, permissioned, receipted guest capabilities into
workflows, workers, and Hypervisor. Tools are not ambient authority; every tool
has a contract, risk class, primitive capability requirements, authority scope
requirements, and receipt obligations. Effectful connector calls execute through
the Hypervisor Daemon hypervisor/control plane, not from Hypervisor clients,
application surfaces, or extension hosts.

## RuntimeToolContract

```json
{
  "tool_id": "tool://gmail.send",
  "namespace": "gmail",
  "display_name": "Send Gmail message",
  "version": "1.0.0",
  "input_schema": {},
  "output_schema": {},
  "risk_class": "external_message",
  "effect_class": "read | draft | write_reversible | external_message | commerce | funds | policy_widening | secret_export",
  "concurrency_class": "safe_parallel | resource_scoped | exclusive | serialized",
  "timeout": {
    "default_ms": 30000,
    "max_ms": 120000
  },
  "primitive_capabilities_required": ["prim:net.request"],
  "authority_scopes_required": ["scope:gmail.send"],
  "semantic_data": {
    "ontology_refs": [],
    "connector_mapping_refs": [],
    "input_object_model_refs": [],
    "output_object_model_refs": []
  },
  "analytics_policy": {
    "emit_usage_signal": true,
    "capture_intent": "explicit | inferred | none",
    "capture_arguments": "none | schema_only | redacted | full_private",
    "missing_capability_signal": true,
    "quality_signal_refs": []
  },
  "approval_required": true,
  "evidence_required": ["request_preview", "provider_response"],
  "redaction_policy": "redact_body | hash_only | full_private",
  "owner": "connector://gmail"
}
```

Tool analytics are improvement signals, not execution truth. They may record
call volume, latency, error class, missing-capability requests, intent,
redacted argument shape, and quality labels, but consequential proof still
comes from daemon-admitted events, wallet authority, Agentgres state, and
receipts.

## Hypervisor MCP Gateway Profile

The Hypervisor MCP Gateway exposes selected RuntimeToolContracts, surface MCP
contracts, session actions, Foundry actions, and receipt/replay views to external
agents or harnesses. The gateway profile is the contract that limits what a
given MCP consumer can discover, preview, propose, or execute.

```json
{
  "gateway_profile_id": "mcp_gateway://project-auditor-readonly",
  "display_name": "Project Auditor Read-only Gateway",
  "audience": "external_agent | ci_agent | marketplace_worker | enterprise_agent | local_harness",
  "profile_kind": "discovery_readonly | project_session | connector_preview | operator_proposal | effectful_approved | foundry_eval_training | receipts_replay_proof",
  "subject_ref": "agent://external/runtime-auditor",
  "project_refs": ["project://ioi"],
  "session_refs": [],
  "surface_refs": ["surface://connectors-tools-mcp", "surface://receipts-replay"],
  "exposed_tools": [
    {
      "mcp_tool_name": "hypervisor.project.inspect",
      "backing_contract_ref": "tool://project.inspect",
      "contract_kind": "runtime_tool_contract | surface_mcp_contract | operator_plane_contract",
      "risk_class": "read",
      "effect_class": "read",
      "readiness": "ready",
      "dry_run_required": false,
      "approval_required": false,
      "authority_scopes_required": ["scope:project.read"],
      "receipt_obligations": ["ToolExecutionReceipt"]
    }
  ],
  "authority_client_ref": "wallet_client://...",
  "authority_scope_refs": ["scope:project.read"],
  "privacy_posture_ref": "privacy://redacted",
  "budget_policy_ref": "policy://gateway-budget",
  "rate_limit_ref": "policy://gateway-rate-limit",
  "expires_at": "2026-05-02T12:00:00Z",
  "revocation_ref": "revocation://...",
  "last_use_ref": "event://...",
  "manifest_ref": "mcp_manifest://...",
  "receipt_refs": []
}
```

Gateway profiles do not grant authority by themselves. They bind a manifest to
wallet.network authority clients, daemon admission, Agentgres refs, policy, and
receipt obligations. A gateway profile may expose a tool as discoverable while
still returning `not_connected`, `scope_insufficient`, `dry_run_required`,
`approval_required`, `policy_blocked`, or `degraded` for a particular operation.

## Hypervisor MCP Gateway API

```http
GET  /v1/mcp/gateways
POST /v1/mcp/gateways
GET  /v1/mcp/gateways/{gateway_profile_id}
PATCH /v1/mcp/gateways/{gateway_profile_id}
POST /v1/mcp/gateways/{gateway_profile_id}/revoke
GET  /v1/mcp/gateways/{gateway_profile_id}/manifest
POST /v1/mcp/gateways/{gateway_profile_id}/call
GET  /v1/mcp/gateways/{gateway_profile_id}/events
GET  /v1/mcp/gateways/{gateway_profile_id}/receipts
```

Effectful gateway calls should occur inside an admitted run or operator-plane
operation:

```json
{
  "gateway_profile_id": "mcp_gateway://project-auditor-readonly",
  "mcp_tool_name": "hypervisor.connector.gmail.trash_preview",
  "input": {},
  "run_id": "run_123",
  "authority_grant_id": "grant_123",
  "approval_id": "approval_123",
  "idempotency_key": "idem_...",
  "requested_receipt_shape": ["ToolExecutionReceipt", "PolicyDecisionReceipt"]
}
```

## ConnectorMapping

Connector mappings bind provider payloads and actions to IOI canonical domain
objects. A connector payload is source material; it is not domain truth until a
ConnectorMapping and, where consequential, a DataRecipe map it into an
ontology-bound object, dataset, or projection.

```json
{
  "connector_mapping_id": "mapping://gmail-quote-thread",
  "connector_id": "connector://gmail",
  "ontology_ref": "ontology://construction-estimating/v1",
  "source_schema_ref": "provider_schema:gmail.thread",
  "target_object_model_refs": ["object-model://Quote", "object-model://Approval"],
  "field_mappings": [
    {
      "source": "thread.messages[].body",
      "target": "Quote.source_text",
      "redaction": "pii_filter"
    }
  ],
  "action_mappings": [
    {
      "tool_id": "tool://gmail.create_draft",
      "canonical_action": "Approval.request_clarification",
      "authority_scope_required": "scope:gmail.create_draft"
    }
  ],
  "evidence_required": ["source_message_hash", "mapping_version", "redaction_receipt"],
  "redaction_policy_ref": "policy://redact-customer-contact"
}
```

## Tool API

```http
GET  /v1/tools
GET  /v1/tools/{tool_id}
POST /v1/tools/{tool_id}/dry-run
POST /v1/tools/{tool_id}/call
GET  /v1/tools/{tool_id}/policy
GET  /v1/tools/{tool_id}/receipts/{receipt_id}
```

Effectful calls should occur within a run:

```json
{
  "run_id": "run_123",
  "tool_id": "tool://gmail.send",
  "input": {},
  "authority_grant_id": "grant_123",
  "approval_id": "approval_123",
  "idempotency_key": "idem_..."
}
```

## Connector API

```http
GET  /v1/connectors
GET  /v1/connectors/{connector_id}
POST /v1/connectors/{connector_id}/auth/start
POST /v1/connectors/{connector_id}/auth/callback
GET  /v1/connectors/{connector_id}/tools
GET  /v1/connectors/{connector_id}/subscriptions
POST /v1/connectors/{connector_id}/subscriptions
DELETE /v1/connectors/{connector_id}/subscriptions/{subscription_id}
```

## Risk Classes

```text
read
local_write
draft
write_reversible
external_message
commerce
funds
credential_touching
secret_export
policy_widening
system_destructive
```

## Connector Examples

```text
gmail.search
gmail.read_thread
gmail.create_draft
gmail.send_with_approval
calendar.find_availability
calendar.create_event
drive.search_docs
drive.read_doc
github.open_issue
github.comment_pr
slack.post_message
instacart.create_cart_draft
instacart.submit_order
blender.run_python
freecad.export_step
```

## Approval Rules

```text
read: no approval by default
draft: no approval or soft approval
external_message: approval required by default
commerce: approval required
funds: approval + step-up required
secret_export: disabled by default
policy_widening: step-up + explicit approval required
```

## Non-Negotiables

1. Every tool must have a RuntimeToolContract.
2. Every effectful tool must bind to an authority grant.
3. High-risk tools require wallet.network approval.
4. Tools cannot inherit ambient connector secrets.
5. Tool output must include receipt-ready evidence.
6. Connector output used for training, evaluation, projection, routing, or
   service delivery must pass through a ConnectorMapping and, when transformed,
   a receipted DataRecipe.
7. Hypervisor MCP Gateway profiles must be scoped, expiring or revocable,
   auditable, and bound to backing contracts; they must not expose an unbounded
   master tool surface.
