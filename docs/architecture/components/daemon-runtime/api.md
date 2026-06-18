# Hypervisor Daemon Runtime API

Status: canonical low-level reference.
Canonical owner: this file for public daemon/runtime API endpoints, event streaming, run lifecycle, structured errors, and client-vs-runtime ownership.
Supersedes: older daemon/SDK/CLI endpoint lists when endpoint shape conflicts.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Purpose

The Hypervisor Daemon is the universal execution endpoint and hypervisor/control plane
for canonical Web4 autonomous work. The IOI CLI/headless client, optional TUI
presentation, `@ioi/agent-sdk`, future IOI ADK, Hypervisor App,
Hypervisor Web, Workbench/Foundry surfaces, provider/environment views,
Workflow Compositor, harness profiles, benchmarks, editor extension-host code,
and IOI
Authority Gateway adapters are clients, builder frameworks, or projections over
this public runtime API. They must not own separate execution semantics. Local
Hypervisor-managed daemons, hosted providers, DePIN nodes, TEE nodes, and
customer VPC nodes run daemon-compatible runtime nodes to execute workers,
workflows, model calls, tools, connectors, computer-use leases, worker-training
jobs, evaluation jobs, benchmark jobs, MoW routing decisions, and artifact
production.

Compute nodes initialize daemon-compatible runtime-node profiles, optionally
bridging into lower-level runtime services. The SDK may submit, inspect, stream,
or control work through this API, but it is not the execution substrate booted
on a compute node. The ADK may scaffold workers, service modules, harnesses,
evals, manifests, receipts, and deployment profiles over this API, but it is
not the daemon or the canonical runtime owner.

Workers, models, tools, connectors, browsers, shells, and computer-use providers
are guest workloads/capabilities from this API's point of view. Policy,
authority grants, approvals, receipts, replay records, and settlement hooks are
the trust/audit substrate that binds those guests to accountable work.

IOI Authority Gateway adapters use this API to submit proposed actions from
existing IDEs, CLI agents, hosted agents, MCP tools, shell/Git surfaces, browser
actions, API gateways, credential brokers, and CI/CD gates. Adapters project and
mediate; the daemon owns policy decisions, authority, effects, receipts, replay,
and durable state.

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

## Hypervisor Client Projections

Hypervisor App, Hypervisor Web, and CLI/headless clients render Core
projections from daemon/public runtime APIs. These endpoints are read models for
clients; they do not move runtime truth into the client.

```http
GET /v1/hypervisor/home-cockpit
```

`GET /v1/hypervisor/home-cockpit` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_home_cockpit
projection_kind = hypervisor_home_cockpit
```

The response is an `ioi.hypervisor.home_cockpit_projection.v1` projection:

```json
{
  "schema_version": "ioi.hypervisor.home_cockpit_projection.v1",
  "projection_id": "home-cockpit:hypervisor-core/default",
  "source": "daemon-home-cockpit-projection",
  "selected_project_id": "project:...",
  "runtimeTruthSource": "daemon-runtime",
  "boundary_invariant": "Home renders daemon evidence projections; it does not become runtime truth.",
  "metrics": [
    {
      "metric_ref": "home-cockpit:session",
      "label": "Active session",
      "value": "active",
      "detail": "session:...",
      "surface_ref": "surface:sessions",
      "evidence_refs": ["receipt://..."]
    }
  ]
}
```

Client fallback fixtures may keep the UI usable while the daemon is offline,
but the fixture source must be visible and must not be presented as admitted
runtime truth.

```http
GET /v1/hypervisor/session-operations
```

`GET /v1/hypervisor/session-operations` dispatches through the same daemon
runtime lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_session_operations
projection_kind = hypervisor_session_operations
```

Optional query params:

```text
project_id
session_ref
```

The response is an `ioi.hypervisor.session_operations_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.session_operations_projection.v1",
  "projection_id": "hypervisor-session-operations:...",
  "source": "daemon-session-operations-projection",
  "selected_session_ref": "session:...",
  "lifecycle_state": "active",
  "project_ref": "project:...",
  "environment_ref": "environment:...",
  "provider_candidate_ref": "provider:...",
  "selected_adapter_ref": "workbench-adapter:...",
  "authority_scope_refs": ["scope:workspace.read"],
  "access_lease_ref": "lease:access/...",
  "log_lease_ref": "lease:logs/...",
  "archive_ref": "artifact://...",
  "restore_ref": "agentgres://restore/...",
  "session_rail": [],
  "detail_tabs": [],
  "right_inspector_panels": [],
  "bottom_inspector_panels": [],
  "ports_services": [],
  "tasks": [],
  "terminal_events": [],
  "latest_receipt_refs": ["receipt://..."],
  "runtimeTruthSource": "daemon-runtime"
}
```

This projection powers Hypervisor session rails, session detail tabs, changes
and authority inspectors, ports/services/tasks/terminal inspectors, access/log
leases, and restore/archive refs. The client may inspect this state, but any
state transition still requires a daemon operation, wallet.network authority
where relevant, and Agentgres admission/receipt linkage.

```http
GET /v1/hypervisor/project-state
```

`GET /v1/hypervisor/project-state` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_project_state
projection_kind = hypervisor_project_state
```

Optional query params:

```text
project_id
```

The response is an `ioi.hypervisor.project_state_projection.v1` projection:

```json
{
  "schema_version": "ioi.hypervisor.project_state_projection.v1",
  "projection_id": "project-state:...",
  "source": "daemon-project-state-projection",
  "selected_project_id": "project:...",
  "records": [
    {
      "project_id": "project:...",
      "name": "Project",
      "description": "Workspace scope",
      "environment": "local",
      "root_path": "/workspace",
      "workspace_ref": "workspace://...",
      "current_session_ref": "session:...",
      "environment_ref": "environment:...",
      "provider_candidate_ref": "provider-candidate:...",
      "adapter_preference_ref": "workbench-adapter:...",
      "custody_posture": "local_private",
      "restore_state": "active",
      "agentgres_object_head_ref": "agentgres://object-head/...",
      "state_root_ref": "agentgres://state-root/...",
      "artifact_refs": ["artifact://..."],
      "archive_ref": "artifact://agentgres/archive/...",
      "restore_ref": "agentgres://restore/...",
      "latest_receipt_refs": ["receipt://..."]
    }
  ],
  "project_boundary_invariant": "Projects group workspace refs, sessions, adapter preferences, artifact refs, archive refs, restore refs, state roots, and receipts. Hypervisor clients inspect project state; Agentgres admits project truth and storage backends only hold bytes.",
  "runtimeTruthSource": "daemon-runtime"
}
```

Project state projections may reference encrypted archives and storage-backed
payloads, but those refs are restore material only. Restore validity and live
project truth remain Agentgres-admitted facts backed by daemon operations and
receipt linkage.

```http
GET /v1/hypervisor/agents
```

`GET /v1/hypervisor/agents` dispatches through the daemon runtime lifecycle
projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_agents
projection_kind = agents
```

Optional query params:

```text
project_id
```

The response feeds the `ioi.hypervisor.agents_projection.v1` client projection.
Daemon-native agent rows may be normalized by clients into configured runtime
actors with harness bindings, model routes, skills, memory bindings,
wallet.network capability leases, Agentgres operation refs, state roots, and
receipts:

```json
{
  "schema_version": "ioi.hypervisor.agents_projection.v1",
  "projection_id": "agents:...",
  "source": "daemon-agents-projection",
  "selected_project_ref": "project:...",
  "runtimeTruthSource": "daemon-runtime",
  "records": [
    {
      "agent_ref": "agent:...",
      "label": "Configured agent",
      "objective": "Scoped work objective",
      "status": "running",
      "workspace_ref": "workspace://...",
      "session_ref": "session:...",
      "runtime": {
        "harness_selection_ref": "harness-selection:...",
        "harness_label": "Default Harness Profile",
        "truth_boundary": "daemon_owned",
        "model_route_ref": "model-route:...",
        "adapter_target_ref": "adapter-target:...",
        "privacy_posture_ref": "privacy:ctee-private-workspace"
      },
      "skill_bindings": [],
      "memory_bindings": [],
      "capability_leases": [],
      "agentgres_operation_refs": ["agentgres://operation/..."],
      "state_root_ref": "agentgres://state-root/...",
      "latest_receipt_refs": ["receipt://..."]
    }
  ]
}
```

Agents are not a wallet-only capability table. They are configured runtime
actors over Hypervisor Core. External harnesses, model providers, and code-tool
clients may supply proposals, but the daemon remains runtime truth; Agent Wiki /
ioi-memory owns semantic memory; wallet.network leases credential use; and
Agentgres records admitted operational facts.

```http
GET /v1/hypervisor/automation-compositor
```

`GET /v1/hypervisor/automation-compositor` dispatches through the daemon
runtime lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_automation_compositor
projection_kind = hypervisor_automation_compositor
```

Optional query params:

```text
project_id
```

The response is an `ioi.hypervisor.automation_compositor_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.automation_compositor_projection.v1",
  "projection_id": "automation-compositor:...",
  "source": "daemon-automation-compositor-projection",
  "selected_project_id": "project:...",
  "runtimeTruthSource": "daemon-runtime",
  "compositor_boundary_invariant": "Workflow Compositor edits and proposes; the Hypervisor Daemon admits execution; Agentgres records operational truth.",
  "workflow_template_refs": ["workflow-template:..."],
  "run_recipe_refs": ["run-recipe:..."],
  "graph_refs": ["workflow://graph/..."],
  "templates": [
    {
      "template_ref": "workflow-template:...",
      "label": "Template",
      "description": "Reusable workflow template.",
      "graph_ref": "workflow://graph/...",
      "recipe_ref": "run-recipe:...",
      "required_scope_refs": ["scope:workflow.run"],
      "model_route_policy_ref": "model-route-policy:...",
      "receipt_policy_ref": "receipt-policy:workflow/...",
      "latest_receipt_refs": ["receipt://..."]
    }
  ],
  "run_recipes": [],
  "graphs": [],
  "runs": [],
  "latest_receipt_refs": ["receipt://..."],
  "agentgres_operation_refs": ["agentgres://operation/workflow/..."],
  "state_root_ref": "agentgres://state-root/workflow-compositor/..."
}
```

Automation compositor projections power Hypervisor Automations/Workflows
surfaces, reusable recipes, scheduled/manual run previews, graph references,
and workflow receipt evidence. The client may render and edit proposals through
the Workflow Compositor, but workflow execution, state-root mutation, receipt
creation, and package promotion still require daemon admission, wallet/network
authority where relevant, and Agentgres operation linkage.

```http
GET /v1/hypervisor/model-infrastructure
```

`GET /v1/hypervisor/model-infrastructure` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_model_infrastructure
projection_kind = hypervisor_model_infrastructure
```

Optional query params:

```text
project_id
session_ref
```

The response is an `ioi.hypervisor.model_infrastructure_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.model_infrastructure_projection.v1",
  "projection_id": "model-infrastructure:...",
  "source": "daemon-model-infrastructure-projection",
  "selected_project_id": "project:...",
  "selected_session_ref": "session:...",
  "runtimeTruthSource": "daemon-runtime",
  "infrastructure_boundary_invariant": "Models renders daemon-owned model routes, provider endpoints, loaded instances, custody policy, authority scopes, and receipts.",
  "inventory_source": "daemon-model-mount-inventory",
  "checked_at": "2026-06-17T00:00:00.000Z",
  "model_route_refs": ["model-route:..."],
  "endpoint_refs": ["model-endpoint:..."],
  "loaded_instance_refs": ["model-instance:..."],
  "provider_refs": ["provider:..."],
  "routes": [
    {
      "route_ref": "model-route:...",
      "role": "default",
      "status": "active",
      "privacy_posture": "local",
      "provider_ref": "provider:...",
      "endpoint_refs": ["model-endpoint:..."],
      "loaded_instance_refs": ["model-instance:..."],
      "model_weight_custody_lane": "local_or_open_weight",
      "authority_scope_refs": ["scope:model.invoke"],
      "receipt_refs": ["receipt://..."]
    }
  ],
  "providers": [],
  "session_bindings": [],
  "model_weight_custody_policy_refs": ["model-weight-custody:..."],
  "latest_receipt_refs": ["receipt://..."]
}
```

Model infrastructure projections power the Hypervisor Models surface and
session setup summaries. The model-mounting UI can configure providers,
downloads, tokens, routes, and benchmarks, but it remains a configuration
client. Model invocation, route selection, credential use, provider fallback,
weight-custody admission, and receipt creation remain daemon-mediated and
Agentgres-linked.

```http
GET /v1/hypervisor/provider-placement
```

`GET /v1/hypervisor/provider-placement` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_provider_placement
projection_kind = hypervisor_provider_placement
```

Optional query params:

```text
project_id
```

The response is an `ioi.hypervisor.provider_placement_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.provider_placement_projection.v1",
  "projection_id": "provider-placement:...",
  "source": "daemon-provider-placement-projection",
  "selected_project_ref": "project:...",
  "anti_gateway_invariant": "Hypervisor integrates providers directly; route catalogs may suggest candidates, but wallet.network authorizes spend/secret release and Agentgres records admitted truth.",
  "candidates": [
    {
      "candidate_ref": "provider-candidate:...",
      "label": "Provider",
      "integration_kind": "local_machine | customer_cloud | hyperscaler_confidential | depin_compute | decentralized_storage | gpu_market",
      "direct_provider_ref": "provider:...",
      "workload_fit": "Public, redacted, local, confidential, storage, or restore workload fit.",
      "privacy_posture": "local_custody | customer_controlled | confidential_compute | ctee_split_required | encrypted_storage_only | provider_trust",
      "wallet_authority_scope_refs": ["scope:provider.spend"],
      "agentgres_receipt_ref": "receipt://provider/...",
      "storage_policy_ref": "storage-policy:...",
      "restore_policy_ref": "agentgres://restore/...",
      "risk_labels": ["Provider root expected"]
    }
  ],
  "runtimeTruthSource": "daemon-runtime"
}
```

Provider placement projections are candidate/read models for Hypervisor
clients. They may include local machines, customer cloud accounts,
hyperscaler confidential-compute lanes, DePIN compute, decentralized storage,
and GPU markets. They do not create a mandatory cloud router, do not authorize
spend or secret release, do not make provider state authoritative, and do not
turn storage backends into restore truth. wallet.network authorizes spend and
secret/declassification release; Agentgres admits lifecycle, receipt, archive,
restore, and state-root truth.

```http
GET /v1/hypervisor/receipt-evidence
```

`GET /v1/hypervisor/receipt-evidence` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_receipt_evidence
projection_kind = hypervisor_receipt_evidence
```

Optional query params:

```text
project_id
session_ref
```

The response is an `ioi.hypervisor.receipt_evidence_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.receipt_evidence_projection.v1",
  "projection_id": "receipt-evidence:...",
  "source": "daemon-receipt-evidence-projection",
  "records": [
    {
      "receipt_ref": "receipt://...",
      "kind": "session_lifecycle | authority | provider_placement | harness_comparison | environment_lease | artifact_restore",
      "summary": "Evidence summary.",
      "source_projection_ref": "session-operations:...",
      "agentgres_operation_refs": ["agentgres://operation/..."],
      "artifact_refs": ["artifact://..."],
      "trace_refs": ["trace://..."],
      "state_root_ref": "agentgres://state-root/...",
      "replay_ref": "agentgres://replay/...",
      "status": "admitted | draft | pending | blocked"
    }
  ],
  "receipt_boundary_invariant": "Receipts make transitions attributable; Agentgres admits operational truth; Hypervisor clients only render evidence projections.",
  "runtimeTruthSource": "daemon-runtime"
}
```

Receipt evidence projections let Hypervisor clients inspect operational
evidence, replay refs, traces, artifact refs, Agentgres operation refs, and
state roots without becoming receipt truth. Filtering, drill-in replay, and
pagination must remain daemon/Agentgres-backed rather than client-authored.

```http
POST /v1/hypervisor/provider-operations
```

`POST /v1/hypervisor/provider-operations` creates a provider operation
proposal through the daemon runtime lifecycle boundary with:

```text
operation_kind = runtime.lifecycle_operation.hypervisor_provider_operation_proposal
projection_kind = hypervisor_provider_operation_proposal
```

Request body:

```json
{
  "project_ref": "project:...",
  "candidate_ref": "provider-candidate:...",
  "direct_provider_ref": "provider:...",
  "operation_kind": "request_access_lease | launch_session | zero_to_idle | archive | restore",
  "wallet_authority_scope_refs": ["scope:provider.spend"],
  "storage_policy_ref": "storage-policy:...",
  "restore_policy_ref": "agentgres://restore/..."
}
```

The response is an `ioi.hypervisor.provider_operation_proposal.v1` object:

```json
{
  "schema_version": "ioi.hypervisor.provider_operation_proposal.v1",
  "proposal_ref": "provider-operation:...",
  "source": "daemon-provider-operation-proposal",
  "project_ref": "project:...",
  "candidate_ref": "provider-candidate:...",
  "direct_provider_ref": "provider:...",
  "operation_kind": "zero_to_idle",
  "admission_state": "requires_wallet_lease",
  "wallet_lease_ref": "lease:wallet/provider/...",
  "required_scope_refs": ["scope:provider.spend"],
  "agentgres_operation_ref": "agentgres://operation/provider/...",
  "receipt_ref": "receipt://provider/...",
  "state_root_ref": "agentgres://state-root/provider/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/...",
  "custody_invariant": "Provider operations are proposals until wallet.network grants a scoped lease and Agentgres admits the lifecycle operation, receipt, archive, restore, and state-root refs."
}
```

Provider operation proposals are not provider truth and are not authority
grants. They are daemon/Core admission objects that bind a candidate,
requested lifecycle action, wallet scope requirements, archive/restore refs,
state-root refs, and receipt refs before any provider-side deployment, access,
archive, zero-to-idle, or restore operation can proceed.

```http
GET /v1/hypervisor/core-taxonomy
```

`GET /v1/hypervisor/core-taxonomy` returns the daemon-visible Hypervisor Core
taxonomy used by product clients and conformance checks.

The response is an `ioi.runtime.hypervisor_core_taxonomy.v1` object:

```json
{
  "schema_version": "ioi.runtime.hypervisor_core_taxonomy.v1",
  "taxonomy_ref": "hypervisor-core-taxonomy:canonical",
  "core": {
    "id": "hypervisor-core",
    "execution_owner": "hypervisor-daemon",
    "runtimeTruthSource": "daemon-runtime"
  },
  "first_class_clients": [
    { "kind": "app" },
    { "kind": "web" },
    { "kind": "cli_headless" }
  ],
  "optional_presentations": [
    { "kind": "tui_presentation", "parent_client": "hypervisor-cli-headless" }
  ],
  "application_surfaces": [
    { "id": "workbench", "truth_owner": "hypervisor-daemon" },
    { "id": "automations", "truth_owner": "hypervisor-daemon" },
    { "id": "foundry", "truth_owner": "hypervisor-daemon" }
  ],
  "retired_surface_aliases": [
    {
      "alias": "fleet",
      "replacement": "sessions/providers/environments"
    }
  ],
  "adapter_target_families": [
    { "id": "code_editor" },
    { "id": "terminal" },
    { "id": "provider" },
    { "id": "hypervisoros_node" }
  ],
  "agent_harness_adapters": [
    { "id": "codex_style", "authority": "proposal_source_only" },
    { "id": "claude_style", "authority": "proposal_source_only" },
    { "id": "deepseek_style", "authority": "proposal_source_only" }
  ]
}
```

The taxonomy endpoint is not a runtime dispatcher. It is a stable
implementation-visible boundary that keeps clients, application surfaces,
adapter targets, AgentHarnessAdapters, and truth owners from collapsing back
into editor-host or Fleet-era product language.

```http
POST /v1/hypervisor/approved-operations
```

`POST /v1/hypervisor/approved-operations` admits an already-proposed
Hypervisor operation for execution only after the operation has passed the
wallet.network authority path and the Agentgres truth path.

Request body:

```json
{
  "operation_family": "session | provider",
  "proposal_ref": "session-operation:... | provider-operation:...",
  "proposal_schema_version": "ioi.hypervisor.session_operation_proposal.v1",
  "proposal_source": "daemon-session-operation-proposal",
  "project_ref": "project:...",
  "session_ref": "session:...",
  "environment_ref": "environment:...",
  "provider_candidate_ref": "provider:...",
  "candidate_ref": "provider-candidate:...",
  "direct_provider_ref": "provider:...",
  "operation_kind": "restore_session | zero_to_idle | ...",
  "target_ref": "agentgres://restore/...",
  "wallet_approval_ref": "approval://wallet/...",
  "wallet_lease_ref": "lease:wallet/...",
  "required_scope_refs": ["scope:..."],
  "authority_receipt_refs": ["receipt://wallet/..."],
  "agentgres_operation_ref": "agentgres://operation/...",
  "receipt_ref": "receipt://...",
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/..."
}
```

The response is an `ioi.runtime.hypervisor_approved_operation_admission.v1`
object:

```json
{
  "schema_version": "ioi.runtime.hypervisor_approved_operation_admission.v1",
  "admission_id": "hypervisor-approved-operation:...",
  "operation_family": "session",
  "proposal_ref": "session-operation:...",
  "proposal_schema_version": "ioi.hypervisor.session_operation_proposal.v1",
  "proposal_source": "daemon-session-operation-proposal",
  "project_ref": "project:...",
  "operation_kind": "restore_session",
  "decision": "admitted",
  "execution_status": "admitted_for_execution",
  "wallet_approval_ref": "approval://wallet/...",
  "wallet_lease_ref": "lease:wallet/...",
  "required_scope_refs": ["scope:..."],
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "receipt_refs": ["receipt://..."],
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/...",
  "runtimeTruthSource": "daemon-runtime"
}
```

Approved operation admission rejects fixture or unverified proposal sources.
The endpoint is not a provider adapter and not a wallet approval UI. It is the
daemon admission boundary that proves the selected proposal, wallet approval,
wallet lease, Agentgres operation refs, receipts, archive/restore refs, and
state root are bound before Hypervisor executes the session or provider
lifecycle operation.

### Runtime Manifest

```json
{
  "runtime_id": "runtime://node_abc",
  "runtime_type": "local_hypervisor | hosted_ioi | provider | depin | hypervisoros | tee | customer_vpc",
  "daemon_version": "0.8.0",
  "default_harness_profile": "2026.05.default-harness-profile.v1",
  "agentgres_version": "0.2.0",
  "supported_execution_profiles": ["local", "hosted", "provider", "depin_mutual_blind", "hypervisoros_bare_metal", "tee_enterprise", "customer_vpc"],
  "supported_interfaces": ["agents", "managed_instances", "projects", "sessions", "missions", "adapter_targets", "environment_ops", "threads", "runs", "workers", "training", "benchmarks", "routing", "tools", "models", "connectors", "authority_gateway", "action_requests", "artifacts", "receipts", "trace", "replay", "scorecards"],
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

## Worker/Agent and Run Lifecycle

In the daemon API, `agents` are product-facing managed worker instances. The
protocol actor remains the worker package/version; the agent instance binds that
worker to an owner, runtime assignment, persistence profile, memory/archive
policy, and interaction surface.

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

### Create Managed Agent Instance

```json
{
  "worker_manifest_ref": "ai://workers.runtime-auditor.ioi@1.0.0",
  "install_id": "install_123",
  "owner_id": "wallet://user_123",
  "execution_profile": "local | hosted | provider | depin_mutual_blind | hypervisoros_bare_metal | tee_enterprise | customer_vpc",
  "persistence_profile": "ephemeral | session | zero_to_idle | persistent",
  "interaction_surfaces": ["chat", "task", "api", "scheduler"],
  "subscription_profile": "per_invocation | warm_runtime | managed_monthly",
  "memory_policy": {
    "mode": "none | session | agentgres_refs | sealed_archive",
    "archive_on_idle": true
  },
  "authority_policy": {
    "primitive_capabilities_required": ["prim:model.invoke"],
    "authority_scopes_required": ["scope:repo.read"],
    "approval_required_for": ["external_message", "file.write"]
  }
}
```

Response:

```json
{
  "agent_id": "agent://runtime-auditor/heath/default",
  "worker_id": "worker://runtime-auditor.ioi",
  "runtime_assignment_id": "assign_456",
  "status": "starting",
  "thread_endpoint": "/v1/threads",
  "runs_endpoint": "/v1/agents/agent_.../runs"
}
```

## Data Recipe, Worker Training, Benchmark, and MoW Routing API

Data recipe, transformation, training, evaluation, benchmark, and routing
endpoints are daemon execution surfaces. Hypervisor, CLI/headless, optional TUI,
SDK, ADK, harnesses,
and benchmarks can call them as clients; they must not implement a separate
semantic-data or training runtime.

```http
POST /v1/data-recipes/{recipe_id}/run
GET  /v1/data-recipes/runs/{transformation_run_id}
GET  /v1/data-recipes/runs/{transformation_run_id}/receipts
POST /v1/ontology-projections/{projection_id}/refresh
POST /v1/training/specs
GET  /v1/training/specs/{training_id}
POST /v1/training/{training_id}/batch-plans
POST /v1/training/{training_id}/generation-batches
POST /v1/training/{training_id}/quality-gate-reports
POST /v1/training/{training_id}/cost-ledgers
POST /v1/training/{training_id}/run
POST /v1/training/{training_id}/curate
POST /v1/training/{training_id}/evaluate
POST /v1/training/{training_id}/publish
GET  /v1/training/{training_id}/receipts
POST /v1/benchmarks/runs
GET  /v1/benchmarks/runs/{benchmark_run_id}
GET  /v1/benchmarks/runs/{benchmark_run_id}/receipts
POST /v1/mow/route
GET  /v1/mow/routes/{routing_decision_id}
GET  /v1/mow/routes/{routing_decision_id}/receipt
```

These endpoints bind to DataRecipeEnvelope, TransformationRunEnvelope,
OntologyProjectionEnvelope, WorkerTrainingEnvelope, BenchmarkEnvelope,
RoutingDecisionEnvelope, and the receipt types defined in the runtime receipt
reference.

## Thread and Turn Control API

Interactive clients use threads for operator-facing sessions and turns for
bounded user/model/runtime exchanges. A thread may map to one or more runs,
jobs, tool invocations, subagents, snapshots, or restore decisions, but the
thread API is still a daemon control surface over canonical runtime contracts.

```http
POST /v1/threads
GET  /v1/threads
GET  /v1/threads/{thread_id}
GET  /v1/threads/{thread_id}/usage
POST /v1/threads/{thread_id}/resume
POST /v1/threads/{thread_id}/fork
POST /v1/threads/{thread_id}/mode
POST /v1/threads/{thread_id}/model
POST /v1/threads/{thread_id}/thinking
POST /v1/threads/{thread_id}/compact
GET  /v1/threads/{thread_id}/events
GET  /v1/threads/{thread_id}/events/stream
POST /v1/threads/{thread_id}/turns
GET  /v1/threads/{thread_id}/turns
GET  /v1/threads/{thread_id}/turns/{turn_id}
POST /v1/threads/{thread_id}/turns/{turn_id}/interrupt
POST /v1/threads/{thread_id}/turns/{turn_id}/steer
```

Hypervisor App, Hypervisor Web, CLI/headless, optional TUI, SDK, ADK,
Workflow Compositor, Workbench/Foundry surfaces, and provider/environment views may
render these controls differently, but they must converge on these daemon
contracts rather than maintaining private session loops.

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
  "execution_profile": "local | hosted | depin_mutual_blind | hypervisoros_bare_metal | tee_enterprise",
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

## Project, Session, Mission, and Adapter APIs

Projects, sessions, missions, adapter targets, and environment operations are
daemon/Core APIs. Hypervisor App, Hypervisor Web, CLI/headless clients,
Workbench, Foundry, provider/environment views, SDK/ADK clients, and agent harness adapters may
render or call these APIs, but they must not maintain parallel lifecycle truth.

### Projects

```http
GET  /v1/projects
POST /v1/projects
GET  /v1/projects/{project_id}
PATCH /v1/projects/{project_id}
GET  /v1/projects/{project_id}/sessions
GET  /v1/projects/{project_id}/missions
GET  /v1/projects/{project_id}/adapter-connection-profiles
```

### Sessions and Environment Ops

```http
GET  /v1/environment-classes
GET  /v1/environment-classes/{environment_class_id}
POST /v1/sessions
POST /v1/sessions/from-project
POST /v1/sessions/from-context-url
GET  /v1/sessions
GET  /v1/sessions/{session_id}
GET  /v1/sessions/{session_id}/environment
GET  /v1/sessions/{session_id}/status
GET  /v1/sessions/{session_id}/events
POST /v1/sessions/{session_id}/start
POST /v1/sessions/{session_id}/mark-active
POST /v1/sessions/{session_id}/exec
GET  /v1/sessions/{session_id}/logs
GET  /v1/sessions/{session_id}/ssh-config
POST /v1/sessions/{session_id}/stop
POST /v1/sessions/{session_id}/archive
POST /v1/sessions/{session_id}/unarchive
POST /v1/sessions/{session_id}/restore
DELETE /v1/sessions/{session_id}
```

External agent harnesses should use the session/environment-ops API for
structured command execution, readiness polling, logs, and cleanup. They should
not scrape Hypervisor product UI.

Environment lifecycle responses should expose `HypervisorEnvironmentClass`,
`HypervisorEnvironmentOpsProfile`, `HypervisorEnvironmentLifecycleState`,
activity signal refs, archive refs, restore refs, state-root refs, and receipt
refs when present. Provider lifecycle state may be evidence, but it is not
Agentgres truth.

Canonical session/environment API objects include
`HypervisorEnvironmentClass`, `HypervisorEnvironmentOpsProfile`,
`HypervisorEnvironmentLifecycleState`, `HypervisorEnvironmentActivitySignal`,
`HypervisorSessionAccessLease`, `HypervisorEnvironmentService`,
`HypervisorEnvironmentTask`, `HypervisorEnvironmentPort`, and
`HypervisorScmAuthRequirement`.

Archive and restore operations must not silently mutate local or provider files
as canonical state. Archive payloads are restore material. Restore validity is
operation-backed through Agentgres, artifact refs, state-root refs, policy refs,
authority refs, and receipts.

### Environment Services, Tasks, and SCM Auth

```http
GET  /v1/sessions/{session_id}/services
POST /v1/sessions/{session_id}/services
GET  /v1/sessions/{session_id}/services/{service_id}
POST /v1/sessions/{session_id}/services/{service_id}/start
POST /v1/sessions/{session_id}/services/{service_id}/stop
GET  /v1/sessions/{session_id}/tasks
POST /v1/sessions/{session_id}/tasks
GET  /v1/sessions/{session_id}/tasks/{task_id}
POST /v1/sessions/{session_id}/tasks/{task_id}/start
POST /v1/sessions/{session_id}/tasks/{task_id}/stop
GET  /v1/sessions/{session_id}/tasks/{task_id}/executions
GET  /v1/sessions/{session_id}/scm-auth-requirements
POST /v1/sessions/{session_id}/scm-auth-requirements/{requirement_id}/satisfy
```

Services and tasks are daemon-visible environment resources. A dev server,
model server, eval job, shell task, provider action, archive, or restore is not
just UI process state once it has authority, cost, privacy, replay, or receipt
impact.

SCM auth requirements are brokered capability/credential requests. Satisfying
one may require wallet.network step-up, secret-release policy, a scoped lease,
and a receipt. The daemon must not persist durable SCM credentials as ordinary
workspace files in provider-visible environments.

### Short-Lived Access and Log Tokens

```http
POST /v1/sessions/{session_id}/access-tokens
POST /v1/sessions/{session_id}/log-tokens
DELETE /v1/sessions/{session_id}/access-tokens/{token_id}
```

`HypervisorSessionAccessLease` is the canonical authority object. Token
endpoints may return derived bearer material for editor, SSH, browser, log,
support, port-share, or environment-ops access, but token material is not the
durable grant.

Access and log tokens are short-lived, audience-bound, revocation-epoch-bound,
lease-bound, and receipted. Durable editor, SSH, browser, log, support, or
environment-ops credentials are non-conformant unless they are explicitly
local-only and outside the remote/provider trust boundary.

### Ports, Browser Open, and Support Bundles

```http
GET  /v1/sessions/{session_id}/ports
POST /v1/sessions/{session_id}/ports/{port}/share
POST /v1/sessions/{session_id}/ports/{port}/revoke
POST /v1/sessions/{session_id}/browser-open
POST /v1/sessions/{session_id}/support-bundles
GET  /v1/sessions/{session_id}/support-bundles/{bundle_id}
```

Port sharing, browser previews, and support bundles must bind to policy, risk
labels, redaction status, session refs, and receipts when they cross a local,
private, shared, or provider-hosted boundary.

### Adapter Targets and Connection Profiles

```http
GET  /v1/adapter-targets
GET  /v1/adapter-targets/{target_id}
GET  /v1/adapter-connection-profiles
GET  /v1/adapter-connection-profiles/{profile_id}
POST /v1/adapter-targets/{target_id}/resolve-open-url
POST /v1/adapter-targets/{target_id}/launch
```

Adapter APIs resolve concrete connection profiles for editor, terminal,
browser, VM/container, HypervisorOS, and hosted-worker targets. A raw editor
name is not an execution or mediation contract.

### Background Missions

```http
POST /v1/missions
GET  /v1/missions
GET  /v1/missions/{mission_id}
PATCH /v1/missions/{mission_id}
POST /v1/missions/{mission_id}/start
POST /v1/missions/{mission_id}/disable
GET  /v1/missions/{mission_id}/executions
GET  /v1/mission-executions/{execution_id}
GET  /v1/mission-executions/{execution_id}/actions
GET  /v1/mission-executions/{execution_id}/outputs
GET  /v1/mission-executions/{execution_id}/receipts
```

Missions are background/manual/scheduled/webhook/event-triggered autonomous
work with trigger policy, review contract, output contract, and receipts. They
are not hidden interactive sessions.

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
GET  /v1/threads/{thread_id}/approvals
POST /v1/threads/{thread_id}/approvals/{approval_id}/decision
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

## Action Mediation / Authority Gateway API

Authority Gateway adapters submit proposed actions before they become effects.
The daemon evaluates policy, requests authority or approval when needed, records
the decision, executes through governed runtime paths, and emits receipts/replay
records.

```http
POST /v1/action-requests
GET  /v1/action-requests/{action_request_id}
POST /v1/action-requests/{action_request_id}/approve
POST /v1/action-requests/{action_request_id}/deny
POST /v1/action-requests/{action_request_id}/execute
GET  /v1/action-requests/{action_request_id}/receipts
GET  /v1/threads/{thread_id}/action-requests
POST /v1/threads/{thread_id}/action-requests
```

Action request shape:

```json
{
  "action_request_id": "ar_123",
  "source_adapter": {
    "adapter_id": "adapter://cursor-terminal/heath",
    "adapter_kind": "ide_extension | cli_wrapper | mcp_gateway | shell_wrapper | git_hook | workspace_watcher | api_proxy | browser_adapter | hosted_agent_gateway | ci_gate",
    "source_tool": "cursor | vscode | codex | claude_code | jetbrains | openhands | hosted_agent"
  },
  "proposed_action": {
    "kind": "shell | file | git | mcp_tool | api | browser | deploy | secret",
    "summary": "npm install inside workspace",
    "command_preview": "npm install",
    "diff_preview_ref": null,
    "target_refs": ["workspace://repo"],
    "external_action": false
  },
  "risk_class": "package_install",
  "primitive_capabilities_required": ["prim:sys.exec", "prim:net.request"],
  "authority_scopes_required": ["scope:repo.write"],
  "policy_decision": {
    "status": "pending | allowed | denied | requires_approval | transform_required",
    "policy_hash": "sha256:..."
  },
  "receipt_obligations": ["policy_decision", "execution", "artifact_or_diff"],
  "run_id": "run_123",
  "thread_id": "thread_123"
}
```

Adapters may attach observations, previews, redacted diffs, command captures,
and external agent metadata. They do not directly write files, invoke connectors,
inject secrets, deploy, mutate Git, or call tools when the policy path says the
effect must cross the daemon.

## Tool API

```http
GET  /v1/tools
GET  /v1/tools/{tool_id}
POST /v1/tools/{tool_id}/dry-run
POST /v1/tools/{tool_id}/call
GET  /v1/tools/{tool_id}/policy
POST /v1/threads/{thread_id}/tools/{tool_id}/invoke
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

## MCP Manager API

MCP manager endpoints expose tool/resource/prompt discovery and governed MCP
tool invocation to Hypervisor App, Hypervisor Web, CLI/headless clients,
optional TUI views, SDK, ADK, Workbench, Workflow Compositor, Foundry
surfaces, and provider/environment views.
Global MCP routes are thread-scoped daemon protocol APIs; retired top-level
`/v1/mcp*` and legacy `/api/v1/mcp*` routes are not compatibility fallbacks.

```http
GET  /v1/threads/{thread_id}/mcp/status
POST /v1/threads/{thread_id}/mcp/validate
POST /v1/threads/{thread_id}/mcp/import
POST /v1/threads/{thread_id}/mcp/servers
DELETE /v1/threads/{thread_id}/mcp/servers/{server_id}
POST /v1/threads/{thread_id}/mcp/servers/{server_id}/enable
POST /v1/threads/{thread_id}/mcp/servers/{server_id}/disable
GET  /v1/threads/{thread_id}/mcp/tools/search
GET  /v1/threads/{thread_id}/mcp/tools/{tool_id}
POST /v1/threads/{thread_id}/mcp/tools/{tool_id}/invoke
POST /v1/threads/{thread_id}/mcp/serve
```

MCP endpoints do not bypass runtime tool contracts, primitive capability
requirements, authority scopes, or receipts.

## Memory API

Memory endpoints expose daemon-governed memory status, validation, policy,
paths, and records for the Agent Wiki / `ioi-memory` context plane. The daemon
may read, validate, propose, or project memory records, but authoritative
behavior-affecting memory changes must compile into Agentgres-compatible
operations such as `ContextMutation` with policy, authority, evidence, and
receipts.

Draft, fuzzy, task-local, and speculative memory may remain in the memory plane
or runtime hot state. Durable memory state belongs in Agentgres-compatible state
or explicit wallet/connector-backed stores; UI caches, retrieval indexes,
embeddings, and wiki views remain projections.

```http
GET  /v1/memory
GET  /v1/memory/records
GET  /v1/memory/policy
GET  /v1/memory/path
POST /v1/memory/validate
GET  /v1/threads/{thread_id}/memory/status
POST /v1/threads/{thread_id}/memory/validate
GET  /v1/threads/{thread_id}/memory/policy
GET  /v1/threads/{thread_id}/memory/path
GET  /v1/threads/{thread_id}/memory
POST /v1/threads/{thread_id}/memory
PATCH /v1/threads/{thread_id}/memory/{memory_id}
DELETE /v1/threads/{thread_id}/memory/{memory_id}
```

## Subagent API

Subagents are delegated work items under the same runtime substrate. They must
inherit thread/run authority posture, budget limits, output contracts,
cancellation behavior, and receipt requirements.

```http
GET  /v1/threads/{thread_id}/subagents
POST /v1/threads/{thread_id}/subagents
POST /v1/threads/{thread_id}/subagents/{subagent_id}/wait
GET  /v1/threads/{thread_id}/subagents/{subagent_id}/result
POST /v1/threads/{thread_id}/subagents/{subagent_id}/input
POST /v1/threads/{thread_id}/subagents/{subagent_id}/cancel
POST /v1/threads/{thread_id}/subagents/{subagent_id}/resume
POST /v1/threads/{thread_id}/subagents/{subagent_id}/assign
POST /v1/threads/{thread_id}/subagents/cancel
```

## Jobs, Usage, and Context Budget API

Jobs are daemon-visible long-running work units. Usage and context-budget
endpoints allow clients to render cost, token, context-pressure, and compaction
state without creating private accounting.

```http
GET  /v1/jobs
GET  /v1/jobs/{job_id}
POST /v1/jobs/{job_id}/cancel
GET  /v1/usage
GET  /v1/threads/{thread_id}/usage
POST /v1/context-budget
POST /v1/threads/{thread_id}/context-budget
POST /v1/threads/{thread_id}/compaction-policy
```

## Workspace Trust, Snapshot, Restore, and Diagnostics API

Workspace trust, rollback snapshots, restore gates, and diagnostics repair are
operator controls over patch/workspace state. They must emit events and
receipts and must not silently mutate canonical state.

```http
POST /v1/threads/{thread_id}/workspace-trust/{warning_id}/acknowledge
GET  /v1/threads/{thread_id}/snapshots
POST /v1/threads/{thread_id}/snapshots
POST /v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-preview
POST /v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-apply
POST /v1/threads/{thread_id}/diagnostics/repair-decisions/{decision_id}/execute
GET  /v1/threads/{thread_id}/workflow-edit-proposals
POST /v1/threads/{thread_id}/workflow-edit-proposals
POST /v1/threads/{thread_id}/workflow-edit-proposals/{proposal_id}/apply
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
6. SDK, ADK, CLI/headless, optional TUI, GUI, Workflow Compositor, harness
   profiles, and benchmark clients must observe the same run contracts rather
   than owning separate runtimes.
7. Workflow Compositor owns directed workflow/service shape; selected
   HarnessProfiles resolve scoped steps under daemon gates.
8. The Default Harness Profile is the reference scaffold/fallback
   HarnessProfile, not a peer runtime, not the only admissible harness, and not
   a meta-harness.
9. TUI controls must be represented as daemon/domain API controls, not as hidden
   client-only state transitions.
10. Compute/runtime nodes run daemon-compatible profiles; SDK helpers may be
   present inside worker or client code, but they are not the execution owner.
10. Training, evaluation, benchmark, and MoW routing paths are daemon/runtime
   jobs with receipts, not product-surface private loops.
11. Authority Gateway adapters submit action requests and observations; they do
    not own policy, effects, secrets, receipts, replay, or durable runtime
    state, and they must not overclaim control over opaque third-party agents.
12. Project, session, mission, adapter, environment-ops, access-token,
    log-token, port, browser-open, and support-bundle APIs are daemon/Core
    lifecycle APIs; product clients and agent harnesses must not invent private
    lifecycle truth for them.
