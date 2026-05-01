# Connector and Tool Contracts

Status: canonical low-level reference.
Canonical owner: this file for RuntimeToolContract, tool API, connector API, risk classes, and approval rules.
Supersedes: older flattened tool capability examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

Connectors expose typed, permissioned, receipted tools into workflows, workers, and Autopilot. Tools are not ambient authority; every tool has a contract, risk class, primitive capability requirements, authority scope requirements, and receipt obligations.

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
  "approval_required": true,
  "evidence_required": ["request_preview", "provider_response"],
  "redaction_policy": "redact_body | hash_only | full_private",
  "owner": "connector://gmail"
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
