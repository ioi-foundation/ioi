# Common Objects and Envelopes

Status: canonical low-level reference.
Canonical owner: this file for shared envelope names, ID namespaces, primitive capability tiers, authority grants, and receipt/run/event envelope fields.
Supersedes: older flattened capability-tier examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This file defines the shared low-level objects that every IOI/Web4 component must understand. The goal is to prevent split-brain API design between `@ioi/agent-sdk`, IOI CLI/TUI, agent-ide, Autopilot, IOI daemon, Agentgres, wallet.network, aiagent.xyz, sas.xyz, workflow compositor, harnesses, benchmarks, hosted/self-hosted workers, and IOI L1 contracts.

## Canonical Envelope Types

```text
ManifestEnvelope
AuthorityScopeRequestEnvelope
AuthorityGrantEnvelope
TaskEnvelope
RunEnvelope
RuntimeEventEnvelope
ReceiptEnvelope
ArtifactEnvelope
DeliveryEnvelope
SettlementEnvelope
ContributionEnvelope
QualityEnvelope
DisputeEnvelope
```

## Common ID Conventions

```text
ai://...                global intelligence/app/worker/service namespace
ioi://publisher/...     publisher identity
agent://...             agent or worker instance
worker://...            worker package or worker type
service://...           sas.xyz service definition
run://...               runtime run identity
task://...              task identity
artifact://...          Agentgres artifact ref
receipt://...           receipt identity
cid://...               Filecoin/CAS content ref
wallet://...            wallet.network account or authority ref
prim://...              primitive execution capability ref
scope://...             wallet.network authority scope ref
grant://...             authority grant or lease ref
```

All IDs must be globally unique within their declared namespace. IDs that become public must be stable. Runtime-local IDs may be temporary but must map to stable Agentgres IDs when settled.

## Capability and Authority Tiers

IOI uses two separate tiers that must not be collapsed into a single generic capability field:

```text
Primitive execution capabilities:
  prim:fs.read
  prim:fs.write
  prim:sys.exec
  prim:ui.interact
  prim:net.request
  prim:model.invoke

Authority scopes and leases:
  scope:gmail.read
  scope:gmail.send
  scope:calendar.create
  scope:repo.write
  scope:commerce.order_submit
```

Primitive capabilities are runtime feasibility and isolation primitives. They describe the low-level action classes a runtime/tool requires.

Authority scopes are wallet.network policy grants over resources, providers, identities, budgets, approvals, and expiry. They describe what a subject is allowed to do.

Provider names, fixture names, tool availability, and authority scopes must never alter semantic intent ranking. They may affect admission, policy, routing feasibility, and verification requirements only after the intent has been understood.

## ManifestEnvelope

```yaml
ManifestEnvelope:
  manifest_id: ai://...
  manifest_type: app | worker | service | runtime | domain | tool | connector
  version: semver_or_hash
  publisher_id: ioi://publisher/...
  manifest_root: hash
  body_ref: cid://... | https://... | agentgres://...
  signature:
    scheme: ed25519 | secp256k1 | ml-dsa | hybrid
    public_key_ref: ...
    signature: base64
  l1_commitment:
    chain_id: ioi-mainnet
    contract: ManifestRootRegistry
    tx_hash: optional
  status: draft | active | deprecated | revoked
```

## AuthorityScopeRequestEnvelope

```yaml
AuthorityScopeRequestEnvelope:
  authority_request_id: authreq_...
  subject_id: agent://... | worker://... | runtime://...
  issuer_id: wallet://... | org://... | policy://...
  primitive_capabilities_required:
    - prim:model.invoke
    - prim:fs.read
  authority_scopes_requested:
    - scope:gmail.read
    - scope:repo.write
  resource_scope:
    resources:
      - agentgres://project/autopilot/*
      - file://workspace/src/**
    constraints:
      max_budget_usd: 10
      expiry: 2026-05-01T00:00:00Z
      approval_required_for:
        - external_message
        - commerce
  policy_hash: hash
  request_hash: hash
  authority_grant_id: optional
  status: requested | granted | denied | expired | revoked
```

## AuthorityGrantEnvelope

```yaml
AuthorityGrantEnvelope:
  authority_grant_id: grant_...
  request_id: authreq_...
  issuer_id: wallet://... | org://... | policy://...
  subject_id: agent://... | worker://... | runtime://...
  authority_scopes:
    - scope:gmail.read
    - scope:repo.write
  primitive_capability_constraints:
    - prim:fs.read
    - prim:fs.write
  resources:
    - agentgres://project/autopilot/*
    - file://workspace/src/**
  constraints:
    max_budget_usd: 10
    expires_at: 2026-05-01T00:00:00Z
    max_calls: optional
    approval_required_for:
      - external_message
      - commerce
  revocation_epoch: integer
  status: active | expired | revoked
```

## TaskEnvelope

```yaml
TaskEnvelope:
  task_id: task_...
  requester_id: wallet://... | agent://... | service://...
  objective: string
  task_class: coding | research | workflow | commerce | render | connector | service_delivery | other
  privacy_class: public | internal | confidential | regulated
  execution_profile: local | hosted | depin_mutual_blind | tee_enterprise | customer_vpc
  input_refs:
    - artifact://...
    - agentgres://object/...
  output_contract:
    type: report | patch | artifact | delivery_bundle | service_result | worker_result
    required_receipts:
      - execution
      - validation
  constraints:
    deadline: optional
    max_budget: optional
    human_approval: optional
  primitive_capabilities_required:
    - prim:model.invoke
  authority_scopes_required:
    - scope:model.invoke.external
  created_at: timestamp
```

## RunEnvelope

```yaml
RunEnvelope:
  run_id: run_...
  task_id: task_...
  runtime_id: runtime://...
  worker_id: optional
  service_id: optional
  state: queued | assigned | starting | running | awaiting_approval | paused | completed | failed | cancelled
  assignment:
    node_id: node://...
    placement_reason: string
    privacy_mode: mutual_blind | enterprise_secure | local | hosted
  event_stream: /v1/runs/{run_id}/events
  artifacts_endpoint: /v1/runs/{run_id}/artifacts
  receipts_endpoint: /v1/runs/{run_id}/receipts
  trace_endpoint: /v1/runs/{run_id}/trace
  inspect_endpoint: /v1/runs/{run_id}/inspect
  scorecard_endpoint: /v1/runs/{run_id}/scorecard
  stop_condition: optional
  task_state_ref: optional
  agentgres_projection_watermark: optional
```

## RuntimeEventEnvelope

```yaml
RuntimeEventEnvelope:
  event_id: evt_...
  parent_event_id: optional
  run_id: run_...
  task_id: task_...
  turn_id: optional
  kind: session.started | model.requested | model.completed | tool.proposed | policy.decided | approval.requested | tool.started | tool.completed | artifact.created | receipt.emitted | run.completed | run.failed
  timestamp: timestamp
  actor_id: agent://... | runtime://... | wallet://...
  privacy_class: public | internal | private | secret
  redaction_status: full | redacted | hash_only
  payload: object
  receipt_ref: optional
  cursor: integer
  terminal: boolean
```

## ReceiptEnvelope

```yaml
ReceiptEnvelope:
  receipt_id: receipt_...
  receipt_type: policy | approval | model_invocation | tool_execution | artifact | validation | delivery | settlement | contribution | quality
  run_id: optional
  task_id: optional
  actor_id: string
  input_hash: optional
  output_hash: optional
  policy_hash: optional
  authority_grant_id: optional
  primitive_capabilities: []
  authority_scopes: []
  artifact_refs: []
  timestamp: timestamp
  signature: optional
  l1_commitment: optional
```

## ArtifactEnvelope

```yaml
ArtifactEnvelope:
  artifact_id: artifact_...
  cid: bafy...
  sha256: hash
  size_bytes: integer
  media_type: string
  privacy_class: public | internal | private | encrypted
  encryption:
    mode: none | envelope | threshold | tee_sealed
    key_ref: optional
  provenance:
    run_id: optional
    worker_id: optional
    operation_id: optional
    receipt_id: optional
  access_policy_ref: optional
```

## DeliveryEnvelope

```yaml
DeliveryEnvelope:
  delivery_id: delivery_...
  service_order_id: optional
  worker_invocation_id: optional
  run_id: run_...
  output_artifacts: []
  evidence_bundle: []
  quality_summary: object
  policy_summary: object
  settlement_status: pending | accepted | disputed | paid | refunded
  acceptance_deadline: optional
```

## SettlementEnvelope

```yaml
SettlementEnvelope:
  settlement_id: settle_...
  chain_id: ioi-mainnet
  contract: string
  action: escrow_lock | payout_release | license_mint | dispute_open | dispute_resolve | reputation_root_update
  amount: optional
  token: IOI | stablecoin | credit
  related_delivery_id: optional
  related_receipt_root: optional
  tx_hash: optional
```

## ContributionEnvelope

```yaml
ContributionEnvelope:
  contribution_id: contrib_...
  contributor_id: worker://... | service://... | publisher://... | tool://... | model://...
  consumer_id: wallet://... | service://... | agent://...
  task_id: task_...
  contribution_type: worker_invocation | service_delivery | tool_use | model_use | dataset_use | workflow_use | verification
  usage_hash: hash
  quality_delta: optional
  reward_claim: optional
  license_ref: optional
  receipt_ref: receipt://...
```
