# Connectors, Tools, and Capability Registry Specification

## Canonical Definition

**Connectors expose external systems as typed, permissioned, receipted tools inside the IOI runtime.**

Tools are not arbitrary function calls. Every effectful tool must have a contract, risk class, capability requirement, policy target, and receipt obligation.

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
slack.import_thread
instacart.create_cart_draft
instacart.submit_order
blender.render_preview
freecad.export_step
```

## RuntimeToolContract

Every tool should declare:

```yaml
RuntimeToolContract:
  id: gmail.send
  namespace: gmail
  display_name: Send Gmail message
  input_schema: ...
  output_schema: ...
  risk_domain: external_message
  effect_class: external_write
  concurrency_class: serialized_by_account
  timeout_default: 30s
  timeout_max: 120s
  cancellation_behavior: best_effort
  capability_required: cap:gmail.send
  approval_scope_fields:
    - recipient
    - subject
    - body_hash
  evidence_required:
    - send_receipt
  redaction_policy: redact_body_by_default
  owner_module: wallet-connector-gmail
  version: 1
```

## Risk Classes

```text
read_only
local_write
external_draft
external_message
commerce_cart
commerce_order
funds_transfer
credential_access
policy_widening
secret_export
```

## Connector Authority

Connector secrets live in wallet.network.

The runtime receives:

- operation-scoped capability;
- short-lived access token if absolutely necessary;
- internal execution by wallet/guardian when possible.

It should not receive raw refresh tokens or long-lived secrets.

## Tool Registry

The tool registry should:

- discover native tools;
- register connector tools;
- register MCP tools;
- register workflow-as-tool subgraphs;
- expose schemas;
- expose risk classes;
- expose capability requirements;
- expose policy explanations;
- feed tool-quality models.

## Workflow Integration

Connectors should add tools to the harness/canvas through the registry, not through hardcoded calls.

Workflow nodes should bind to `RuntimeToolContract`.

## Commerce Connector Policy

High-risk commerce tools should be split:

```text
cart/search/draft     = medium risk
submit/purchase/order = high risk, human approval required
```

Example:

```yaml
instacart.create_cart_draft:
  risk: commerce_cart
  approval_required: false_or_policy

instacart.submit_order:
  risk: commerce_order
  approval_required: true
```

## Local Creative Connectors

Blender/CAD connectors can be earlier because they are local artifact-production tools with lower external-effect risk.

They should still emit artifacts and receipts.

## Invariants

1. No effectful tool without contract.
2. No connector secret outside wallet.network unless explicitly and temporarily released.
3. No high-risk action without approval/capability.
4. No tool result trusted without output schema validation.
5. No marketplace worker may bypass tool policy.
6. Tool quality should be measured and fed back into routing over time.

## One-Line Doctrine

> **Connectors do not give agents secrets. They give agents capability-scoped tools.**

