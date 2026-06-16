# Connector and Tool Contracts

Status: canonical low-level reference.
Canonical owner: this file for RuntimeToolContract, ConnectorMapping references, tool API, connector API, risk classes, and approval rules.
Supersedes: older flattened tool capability examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-20.

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
  "approval_required": true,
  "evidence_required": ["request_preview", "provider_response"],
  "redaction_policy": "redact_body | hash_only | full_private",
  "owner": "connector://gmail"
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
