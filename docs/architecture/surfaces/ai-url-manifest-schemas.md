# ai:// Manifest Schemas

Status: canonical low-level reference.
Canonical owner: this file for `ai://` manifest schema examples and resolution flow.
Supersedes: overlapping manifest examples in plans/specs when schema fields conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

`ai://` is the naming and resolution layer for canonical Web4. It identifies apps, workers, services, domains, tools, connectors, runtimes, and intelligence objects.

## Manifest Types

```text
AppManifest
DomainManifest
WorkerManifest
ServiceManifest
RuntimeManifest
ToolManifest
ConnectorManifest
ModelEndpointManifest
```

## AppManifest

```json
{
  "manifest_type": "app",
  "ai_name": "ai://aiagent.xyz",
  "name": "aiagent.xyz",
  "version": "1.0.0",
  "publisher_id": "ioi://publisher/ioi",
  "domain_ref": "agentgres://domain/aiagent.xyz",
  "contracts": {
    "worker_registry": "0x...",
    "license_registry": "0x..."
  },
  "resolvers": ["https://resolver.aiagent.xyz"],
  "interfaces": {
    "web": "https://aiagent.xyz",
    "api": "https://api.aiagent.xyz/v1"
  },
  "manifest_root": "sha256:..."
}
```

## DomainManifest

```json
{
  "manifest_type": "domain",
  "domain_id": "agentgres://domain/sas.xyz",
  "domain_type": "marketplace_service",
  "kernel_deployment": {
    "operator": "ioi://publisher/ioi",
    "replication": "single | replicated | enterprise | sovereign",
    "public_endpoint": "https://domain.sas.xyz"
  },
  "agentgres": {
    "schema_version": 5,
    "supported_consistency": ["local_cached", "projection_consistent", "state_root_consistent"]
  },
  "l1_contracts": {
    "service_registry": "0x...",
    "service_order_escrow": "0x..."
  }
}
```

## WorkerManifest

```json
{
  "manifest_type": "worker",
  "worker_id": "ai://workers.runtime-auditor.ioi",
  "name": "Runtime Auditor",
  "version": "1.0.0",
  "publisher_id": "ioi://publisher/ioi",
  "description": "Audits IOI runtime traces and proposes hardening tasks.",
  "worker_type": "task_worker | persistent_worker | tool_worker | verifier | planner",
  "package": {
    "cid": "bafy...",
    "sha256": "...",
    "encryption": "none | marketplace_envelope | tee_required"
  },
  "interfaces": {
    "task": "/v1/agent/tasks",
    "worker": "/v1/worker",
    "interagent": "/v1/interagent"
  },
  "primitive_capabilities_required": ["prim:fs.read", "prim:sys.exec", "prim:model.invoke"],
  "authority_scopes_required": ["scope:repo.read"],
  "risk_profile": {
    "max_default_risk": "read",
    "approval_required_for": ["file.write", "external_message"]
  },
  "quality_profile": {
    "scorecard_ref": "agentgres://quality/runtime-auditor",
    "benchmark_refs": []
  },
  "license": {
    "type": "open | source_visible | run_only | hosted_only | paid_license",
    "terms_root": "sha256:..."
  }
}
```

## ServiceManifest

```json
{
  "manifest_type": "service",
  "service_id": "ai://services.weekly-runtime-audit.sas",
  "name": "Weekly Runtime Audit",
  "version": "1.0.0",
  "publisher_id": "ioi://publisher/ioi",
  "service_type": "managed_outcome | local_workflow | subscription | quote_based",
  "outcome_contract": {
    "deliverables": ["audit_report", "risk_updates", "task_requests"],
    "acceptance_criteria": ["evidence_refs_present", "critical_findings_ranked"],
    "required_receipts": ["execution", "validation", "delivery"]
  },
  "runtime_requirements": {
    "execution_profiles": ["hosted", "tee_enterprise", "customer_vpc"]
  },
  "pricing": {
    "type": "fixed",
    "amount": "50",
    "token": "IOI"
  },
  "sla": {
    "deadline_hours": 24,
    "bond_required": true
  }
}
```

## RuntimeManifest

```json
{
  "manifest_type": "runtime",
  "runtime_id": "runtime://node_abc",
  "daemon_version": "0.8.0",
  "execution_profiles": ["depin_mutual_blind", "tee_enterprise"],
  "resources": {
    "cpu": 16,
    "gpu": "optional",
    "memory_gb": 64
  },
  "attestation": {
    "mode": "none | tee",
    "profile_id": "optional"
  },
  "endpoint": "https://node.example/v1"
}
```

## ToolManifest

```json
{
  "manifest_type": "tool",
  "tool_id": "tool://gmail.send",
  "namespace": "gmail",
  "input_schema_ref": "cid://...",
  "output_schema_ref": "cid://...",
  "risk_class": "external_message",
  "primitive_capabilities_required": ["prim:net.request"],
  "authority_scopes_required": ["scope:gmail.send"],
  "approval_required": true
}
```

## Resolution Flow

```text
client resolves ai:// name
→ IOI L1 registry returns manifest root/resolver
→ client fetches manifest from resolver/Filecoin/CAS
→ client verifies hash/signature
→ client selects app/domain/runtime endpoint
→ runtime checks primitive execution capabilities
→ wallet.network grants required authority scopes
→ IOI daemon executes if needed
```
