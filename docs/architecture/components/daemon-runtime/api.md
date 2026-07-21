# Hypervisor Daemon Runtime API

Status: canonical low-level reference.
Canonical owner: this file for public daemon/runtime API endpoints, event
streaming, run lifecycle, OutcomeRoom/GoalRun execution APIs, structured errors,
and client-vs-runtime ownership.
Supersedes: older daemon/SDK/CLI endpoint lists when endpoint shape conflicts.
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: reference
Implementation status: partial (many route families live; the registered information-flow/declassification contracts are schema/projection substrate, while production propagation and enforcement remain planned; the shared work-lifecycle integrity/replay kernel, local append store, projection repair, cancellation planner, archive/snapshot writer, and status route are target-only; generalized GoalRunProfile resolution, local-agent pairing, OutcomeRoom discussion/artifact resolution, native Embodied Runtime APIs, non-tool MCP normalization, production browser-context propagation, and remaining browser/computer-use IFC are also target-only; source of truth is the daemon route registry)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-18

## Purpose

> **Reference-wall notice.** This file enumerates the public daemon API
> surface by hand. The source of truth for live endpoints is the daemon
> route registry (`crates/node/src/bin/hypervisor-daemon.rs` +
> `hypervisor_daemon_routes/`); route families land incrementally, so
> presence here is the committed surface, not proof a family is live.
> Generator TODO: emit the endpoint listing from a route scan and keep
> only contract semantics hand-written here.

The Hypervisor Daemon is the universal public admission, orchestration, and
control-plane endpoint, and the general-purpose execution endpoint, for canonical
Web4 autonomous work. The IOI CLI/headless client, optional TUI
presentation, `@ioi/agent-sdk`, future IOI ADK, future IOI ODK, Hypervisor App,
Hypervisor Web, Developer Workspace/Foundry surfaces, other application surfaces,
Environments views, Workflow Compositor, harness profiles,
benchmarks, OutcomeRoom/CollaborativeWorkGraph clients, editor extension-host
code, and IOI
Authority Gateway adapters are clients, builder frameworks, or projections over
this public runtime API. They must not own separate execution semantics. Local
Hypervisor-managed daemons, hosted providers, DePIN nodes, TEE nodes, and
customer VPC nodes run daemon-compatible runtime nodes to execute workers,
workflows, model calls, tools, connectors, computer-use leases, worker-training
jobs, evaluation jobs, benchmark jobs, MoW routing decisions, and artifact
production.

Native Embodied Runtime does not require every controller, MCU, PLC, RTOS
partition, robot, drone, or other physical leaf to host the full daemon or share
one language, scheduler, transport, kernel, or hardware architecture. One or
more daemon-compatible control endpoints admit the exact
`EmbodiedRuntimeGraphManifest`, profile set, placements, policy and safety
bindings, activation transaction, leases, and evidence. Composable `micro`,
`edge`, and `site` footprints then execute their admitted native component and
stream contracts beneath a local `LocalControlSupervisor`. The supervisor and
independently available local safety paths remain authoritative at the physical
boundary when the daemon, site coordinator, model, network, wallet, or ledger is
unavailable.

Compute nodes initialize daemon-compatible runtime-node profiles, optionally
bridging into lower-level runtime services. The SDK may submit, inspect, stream,
or control work through this API, but it is not the execution substrate booted
on a compute node. The ADK may scaffold workers, service modules, harnesses,
evals, manifests, receipts, and deployment profiles over this API. The ODK may
scaffold ontology-aware surfaces, domain apps, data recipes, connector mappings,
eval packs, operator/MCP contracts, and package descriptors over this API and
the semantic data-plane contracts. Neither kit is the daemon or the canonical
runtime owner.

Workers, models, tools, connectors, browsers, shells, and computer-use providers
are guest workloads/capabilities from this API's point of view. Policy,
authority grants, approvals, receipts, replay records, and settlement hooks are
the trust/audit substrate that binds those guests to accountable work.

IOI Authority Gateway adapters use this API to submit proposed actions from
existing IDEs, CLI agents, hosted agents, MCP tools, shell/Git surfaces, browser
actions, API gateways, credential brokers, and CI/CD gates. Adapters project and
mediate. Local/domain policy and the applicable authority provider authorize;
the daemon admits and enforces work, mediates or executes effects, emits
receipts, and orchestrates replay; Agentgres owns admitted durable operational
state.

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

### Target work-lifecycle mechanism status

```http
GET /v1/hypervisor/work-lifecycle/status
```

This route is target-only and is not present in the current daemon registry.
If implemented, the read-only diagnostic reports the shared lifecycle kernel,
durable local record/projection/archive/snapshot counts, per-kind
legal-transition counts, and live owner-route bindings. It does not create or transition a GoalRun,
GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation, ContextCell, or
external handle. Until an owner route is explicitly listed in
`live_owner_route_bindings`, that route does not claim append-only lifecycle
integration merely because the shared mechanism exists.

The target owner-write sequence is:

```text
owner route validates domain intent and authority
  -> submit exact-head WorkLifecycleRecord
  -> shared kernel validates kind-specific edge, authority, time, hash,
     idempotency, and child-ref typing
  -> durable record commit
  -> rebuildable active projection
  -> owner/domain receipt and event
```

Cancellation remains a separate fanout execution after the cancel/revoke fact:
the planner returns required drain/fence/timeout/compensation/reconciliation
actions, but only child-owner receipts prove their completion. Automatic hot-
log pruning, archive-only resume, production Agentgres persistence, and all
owner-route bindings remain explicit nonclaims in the current status response.
The mechanism checks declared authority classes and nonempty grant refs; the
owning PEP must still verify grant signature, scope, expiry, and revocation
before commit.

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
  "project_ref": "project://...",
  "runtimeTruthSource": "daemon-runtime",
  "boundary_invariant": "Home renders daemon evidence projections; it does not become runtime truth.",
  "metrics": [
    {
      "metric_ref": "home-cockpit:session",
      "label": "Active session",
      "value": "active",
      "detail_route": "/work/sessions/session%3A%2F%2F...",
      "workspace_ref": "hypervisor-workspace://work",
      "session_ref": "session://...",
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
  "selected_adapter_ref": "code-editor-adapter:...",
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
state transition still requires a daemon operation, the applicable
local/domain/protocol authority, and Agentgres admission/receipt linkage.

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
  "project_ref": "project://...",
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
      "adapter_preference_ref": "code-editor-adapter:...",
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
POST /v1/hypervisor/project-operations
```

`POST /v1/hypervisor/project-operations` creates a daemon-authored proposal for
project archive and restore operations. Hypervisor clients may request the
operation from the Projects shell, but they do not execute it locally and do not
turn encrypted archive bytes into restore truth.

The route dispatches through the daemon runtime lifecycle boundary with:

```text
operation_kind = runtime.lifecycle_operation.hypervisor_project_operation_proposal
projection_kind = hypervisor_project_operation_proposal
```

Request body:

```json
{
  "project_id": "project-or-workspace-id",
  "workspace_ref": "workspace://...",
  "operation_kind": "archive | restore",
  "agentgres_object_head_ref": "agentgres://object-head/...",
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/...",
  "latest_receipt_refs": ["receipt://..."]
}
```

The response is an `ioi.hypervisor.project_operation_proposal.v1` object:

```json
{
  "schema_version": "ioi.hypervisor.project_operation_proposal.v1",
  "proposal_ref": "project-operation:...",
  "source": "daemon-project-operation-proposal",
  "project_id": "project-or-workspace-id",
  "workspace_ref": "workspace://...",
  "operation_kind": "restore",
  "admission_state": "requires_authority_lease",
  "authority_profile_ref": "policy://authority-profile/project-restore/...",
  "authority_profile_hash": "sha256:...",
  "required_scope_refs": ["scope:agentgres.restore", "scope:artifact.decrypt"],
  "agentgres_operation_ref": "agentgres://operation/project/...",
  "receipt_ref": "receipt://project/...",
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/...",
  "runtimeTruthSource": "daemon-runtime"
}
```

Project operation proposals are not execution admissions. Archive/restore
execution still requires the current approval and lease of the authority
provider that owns the requested scopes, Agentgres operation refs, receipts,
state roots, and the approved-operation admission boundary. wallet.network is
mandatory when restore/apply requires portable delegated authority or its
owned secret, decryption, declassification, spend, external-effect, or
high-risk scope; an ordinary deployment-local restore is not wallet-dependent
by definition. A v1 adapter may read historical `requires_wallet_lease` and
`wallet_lease_ref` fields only when that wallet-owned posture actually applies;
target canonical state emits the provider-neutral fields above.

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
  "selected_project_ref": "project://...",
  "runtimeTruthSource": "daemon-runtime",
  "compositor_boundary_invariant": "Workflow Compositor edits and proposes; the Hypervisor Daemon admits execution; Agentgres records operational truth.",
  "workflow_template_revision_refs": ["workflow-template://.../revision/..."],
  "automation_spec_revision_refs": ["automation://.../revision/..."],
  "graph_refs": ["workflow://graph/..."],
  "templates": [
    {
      "workflow_template_revision_ref": "workflow-template://.../revision/...",
      "label": "Template",
      "description": "Reusable workflow template.",
      "graph_ref": "workflow://graph/...",
      "automation_spec_revision_ref": "automation://.../revision/... | null",
      "required_scope_refs": ["scope:workflow.run"],
      "model_route_policy_ref": "model-route-policy:...",
      "receipt_policy_ref": "receipt-policy:workflow/...",
      "latest_receipt_refs": ["receipt://..."]
    }
  ],
  "automation_specs": [],
  "graphs": [],
  "runs": [],
  "latest_receipt_refs": ["receipt://..."],
  "agentgres_operation_refs": ["agentgres://operation/workflow/..."],
  "state_root_ref": "agentgres://state-root/workflow-compositor/..."
}
```

Automation compositor projections power Hypervisor Automations/Workflows
surfaces, immutable WorkflowTemplate revisions, AutomationSpecs,
scheduled/manual run previews, graph references, and workflow receipt
evidence. The client may render and edit proposals through
the Workflow Compositor, but workflow execution, state-root mutation, receipt
creation, and package promotion still require daemon admission, wallet.network
authority where relevant, and Agentgres operation linkage.

```http
POST /v1/hypervisor/automation-runs/proposals
```

`POST /v1/hypervisor/automation-runs/proposals` creates a daemon-authored
proposal to activate one occurrence of an exact AutomationSpec revision.
Hypervisor clients may request a projected activation, but the Workflow
Compositor and App shell do not become runtime truth.

The route dispatches through the daemon runtime lifecycle boundary with:

```text
operation_kind = runtime.lifecycle_operation.hypervisor_automation_run_proposal
projection_kind = hypervisor_automation_run_proposal
```

Request body:

```json
{
  "project_ref": "project://...",
  "automation_spec_revision_ref": "automation://.../revision/...",
  "automation_spec_content_hash": "sha256:...",
  "requested_automation_installation_binding_revision_ref": "install://automation/.../revision/...",
  "requested_automation_installation_binding_hash": "sha256:...",
  "requested_parameter_set_ref": "artifact://... | null",
  "requested_parameter_set_hash": "sha256:... | null",
  "requested_activation_override_set_ref": "artifact://... | null",
  "requested_activation_override_set_hash": "sha256:... | null",
  "operation_kind": "activate_occurrence",
  "activation_kind": "manual | schedule | webhook | event | monitor | service | queue",
  "activation_event_ref": "event://... | null",
  "required_scope_refs": ["scope:..."],
  "receipt_policy_ref": "receipt-policy:...",
  "context_cell_refs": ["context_cell://..."],
  "artifact_refs": ["artifact://..."],
  "latest_receipt_refs": ["receipt://..."],
  "state_root_ref": "agentgres://state-root/..."
}
```

The response is an `ioi.hypervisor.automation_run_proposal.v1` object:

```json
{
  "schema_version": "ioi.hypervisor.automation_run_proposal.v1",
  "proposal_ref": "proposal://automation-run/...",
  "source": "daemon-automation-run-proposal",
  "project_ref": "project://...",
  "workflow_template_revision_ref": "workflow-template://.../revision/...",
  "workflow_template_content_hash": "sha256:...",
  "automation_spec_revision_ref": "automation://.../revision/...",
  "automation_spec_content_hash": "sha256:...",
  "candidate_automation_installation_binding_revision_ref": "install://automation/.../revision/...",
  "candidate_automation_installation_binding_hash": "sha256:...",
  "candidate_parameter_set_ref": "artifact://... | null",
  "candidate_parameter_set_hash": "sha256:... | null",
  "candidate_activation_override_set_ref": "artifact://... | null",
  "candidate_activation_override_set_hash": "sha256:... | null",
  "resolution_preview_ref": "artifact://... | null",
  "operation_kind": "activate_occurrence",
  "activation_kind": "manual | schedule | webhook | event | monitor | service | queue",
  "activation_event_ref": "event://...",
  "admission_state": "ready_for_daemon_admission",
  "required_scope_refs": ["scope:..."],
  "action_proposal_ref": "action://workflow/...",
  "agentgres_operation_ref": "agentgres://operation/automation/...",
  "receipt_ref": "receipt://automation/...",
  "state_root_ref": "agentgres://state-root/...",
  "context_cell_refs": ["context_cell://..."],
  "artifact_refs": ["artifact://..."],
  "latest_receipt_refs": ["receipt://..."],
  "runtimeTruthSource": "daemon-runtime"
}
```

Automation run proposals are not execution admissions. Final execution still
requires wallet.network approval where required, Agentgres operation refs,
receipt refs, state roots, and the approved-operation admission boundary.
The `AutomationSpec` supplies standing activation semantics and binds the
immutable `WorkflowTemplate`; the request supplies only permitted parameters
and activation overrides. It does not restate the graph, global harness hints,
or concrete authority grants. The response is a nonbinding candidate and may
carry a resolution-preview artifact; it never emits an
`AutomationRunResolutionReceipt` or mints the `automation-run://` identity.
Final approved-operation admission reloads the AutomationSpec and intended
owner-scope AutomationInstallationBinding, verifies their exact hashes and the
spec's bound WorkflowTemplate revision/hash, revalidates current enablement,
policy, admission, and revocation state, resolves the permitted inputs and
dependency closure, atomically creates the AutomationRun, and emits its
resolution receipt. Multiple installations are never selected by guesswork;
the requested binding is only a candidate until this atomic admission. Package promotion remains
the Packages/Foundry governance path, never an AutomationRun activation kind.

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
page_cursor
page_size
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
POST /v1/hypervisor/model-route-mutation-admissions
```

`POST /v1/hypervisor/model-route-mutation-admissions` admits a model-route
change before the model router may bind, select, enable, disable, or update a
provider-backed route. It is the daemon boundary for route mutation, credential
lease posture, model-weight custody admission, provider-trust disclosure, and
Agentgres receipt refs.

Request body:

```json
{
  "mutation_kind": "select_route | bind_session_route | enable_route | disable_route | update_provider_credentials",
  "route_ref": "model-route:...",
  "project_ref": "project:...",
  "session_ref": "session:...",
  "provider_ref": "provider:...",
  "provider_kind": "local | customer | hosted_api | tee | provider_trust",
  "endpoint_refs": ["model-endpoint:..."],
  "loaded_instance_refs": ["model-instance:..."],
  "credential_posture": "no_credentials_required | wallet_credential_lease | provider_vault_token | customer_boundary | unsafe_plaintext_secret",
  "authority_scope_refs": ["scope:model.route.mutate"],
  "credential_scope_refs": ["scope:secret.use"],
  "wallet_approval_ref": "approval://wallet/...",
  "wallet_lease_ref": "lease:wallet/...",
  "provider_credential_lease_ref": "lease:wallet/provider-credential/...",
  "model_weight_custody_admission_ref": "model-weight-custody-admission:...",
  "privacy_posture_ref": "privacy-posture:...",
  "provider_trust_acceptance_ref": "approval://provider-trust/...",
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "receipt_refs": ["receipt://..."],
  "state_root_ref": "agentgres://state-root/..."
}
```

The response is an `ioi.runtime.model_route_mutation_admission.v1` object with
`admission_state = admitted_for_model_router`. The endpoint fails closed when
the route lacks wallet approval, wallet lease, `scope:model.route.mutate`,
model-weight custody admission, privacy posture, credential lease, TEE
attestation, customer boundary, provider-trust acceptance, Agentgres operation
refs, receipts, or state-root refs required by the route posture. Unsafe
plaintext secret routes additionally require explicit `scope:secret.export`,
secret disclosure receipts, and provider-trust acceptance.

```http
GET /v1/hypervisor/privacy-posture
```

`GET /v1/hypervisor/privacy-posture` dispatches through the daemon runtime
lifecycle projection boundary with:

```text
operation_kind = runtime.lifecycle_projection.hypervisor_privacy_posture
projection_kind = hypervisor_privacy_posture
```

Optional query params:

```text
project_id
session_ref
```

The response is an `ioi.hypervisor.execution_privacy_posture_projection.v1`
projection:

```json
{
  "schema_version": "ioi.hypervisor.execution_privacy_posture_projection.v1",
  "projection_id": "privacy-posture:...",
  "source": "daemon-privacy-posture-projection",
  "project_ref": "project:...",
  "selected_session_ref": "session:...",
  "selected_privacy_ref": "privacy:ctee-private-workspace",
  "default_model_route_ref": "model-route:...",
  "workspace_segments": [
    {
      "segment_ref": "workspace-segment:...",
      "label": "Encrypted state refs",
      "custody_class": "encrypted_blob_ref",
      "node_plaintext_allowed": false,
      "owner": "agentgres",
      "evidence_refs": ["artifact://..."]
    }
  ],
  "model_weight_policies": [
    {
      "lane": "forbidden_plaintext_mount",
      "label": "Forbidden plaintext mount",
      "protects_workspace_state": true,
      "protects_model_weights_from_provider_root": false,
      "allowed_postures": ["ctee_split"],
      "admission_summary": "Remote nodes receive no protected plaintext.",
      "authority_scope_refs": ["scope:privacy.enforce_no_plaintext_custody"]
    }
  ],
  "provider_candidates": [],
  "admission_controls": [],
  "unsafe_mount_receipt_ref": "receipt://privacy/...",
  "runtimeTruthSource": "daemon-runtime"
}
```

Privacy posture projections power the Hypervisor Privacy/cTEE surface and
session setup warnings. They distinguish workspace plaintext custody,
declassification gates, model-input/output posture, provider-root exposure, and
model-weight custody. The client renders and reviews the posture. Safe
model-weight route changes are submitted back through
`POST /v1/hypervisor/model-weight-custody-admissions`; provider-trust mounts,
forbidden plaintext mounts, unsafe workspace mounts, wallet declassification
policy, and Agentgres privacy receipts remain daemon/wallet/Agentgres-mediated.

```http
POST /v1/hypervisor/private-workspace-mount-admissions
```

`POST /v1/hypervisor/private-workspace-mount-admissions` admits a concrete
workspace mount posture before a session, adapter, model route, or provider
target may receive workspace material. It is the daemon boundary for
Plaintext-Free Runtime Mounting: public trunks and redacted projections may be
provider-readable, encrypted refs stay sealed, private heads route through
cTEE/TEE/local/customer-custody handles, and unsafe plaintext exceptions require
wallet declassification evidence.

Request body:

```json
{
  "workspace_ref": "workspace://...",
  "mount_ref": "mount://...",
  "segment_ref": "workspace-segment:private-head",
  "provider_ref": "provider:...",
  "custody_class": "public_trunk | redacted_projection | encrypted_blob_ref | private_head | capability_exit | unsafe_plaintext_mount",
  "mount_target": "local_device | user_owned_node | browser_client | rented_gpu | customer_cloud | tee_session",
  "execution_privacy_posture": "private_native | ctee_split | encrypted_storage_only | confidential_compute | remote_api_provider_trust | unsafe_plaintext_mount",
  "provider_root_can_read_plaintext": false,
  "protected_plaintext_requested": false,
  "required_controls": ["ctee_private_head_handle"],
  "authority_scope_refs": ["scope:ctee.private-head.evaluate"],
  "wallet_approval_ref": "approval://wallet/...",
  "wallet_lease_ref": "lease:wallet/...",
  "user_disclosure_ref": "disclosure://...",
  "provider_trust_acceptance_ref": "approval://provider-trust/...",
  "declassification_receipt_refs": ["receipt://privacy/declassification/..."],
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "artifact_refs": ["artifact://..."],
  "state_root_ref": "agentgres://state-root/..."
}
```

The response is an `ioi.runtime.private_workspace_mount_admission.v1` object:

```json
{
  "schema_version": "ioi.runtime.private_workspace_mount_admission.v1",
  "decision": "admitted | admitted_declassification | admitted_unsafe_exception",
  "workspace_ref": "workspace://...",
  "mount_ref": "mount://...",
  "custody_class": "private_head",
  "mount_target": "rented_gpu",
  "execution_privacy_posture": "ctee_split",
  "provider_root_can_read_plaintext": false,
  "protected_plaintext_requested": false,
  "protected_plaintext_exposed_to_provider_root": false,
  "protects_workspace_plaintext_from_provider_root": true,
  "receipt_ref": "receipt://private-workspace-mount/...",
  "runtimeTruthSource": "daemon-runtime"
}
```

The endpoint fails closed for redacted projections without redaction evidence,
encrypted blob refs that request plaintext, capability exits that expose
plaintext, private-head rented-node mounts without cTEE private-head handles,
TEE/customer-cloud mounts without attestation or customer-boundary refs, and
unsafe plaintext exceptions without wallet approval, wallet lease,
provider-trust acceptance, user disclosure, and declassification receipts.

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
  "page_cursor": "cursor:... | null",
  "next_page_cursor": "cursor:... | null",
  "page_size": 25,
  "has_more": false,
  "records": [
    {
      "receipt_ref": "receipt://...",
      "kind": "session_lifecycle | authority | provider_placement | harness_comparison | terminal_transcript | environment_lease | artifact_restore",
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
Clients may request `page_cursor` / `page_size` values, but those cursors are
projection inputs only. The daemon and Agentgres decide which records exist,
which cursor follows, and whether more admitted history is available.

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
GET /v1/hypervisor/core-taxonomy?schema=ioi.runtime.hypervisor_core_taxonomy.v2
```

`GET /v1/hypervisor/core-taxonomy` returns daemon-visible stable Hypervisor
Core registration metadata for bootstrap, compatibility, and conformance. It
is not a request-scoped launch catalog and must never be used to bypass the
policy-filtered product-surface projection.

The target response is an `ioi.runtime.hypervisor_core_taxonomy.v2` object:

```json
{
  "schema_version": "ioi.runtime.hypervisor_core_taxonomy.v2",
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
  "core_workspaces": [
    { "workspace_ref": "hypervisor-workspace://home", "workspace_key": "home", "display_name": "Home", "canonical_route": "/home" },
    { "workspace_ref": "hypervisor-workspace://systems", "workspace_key": "systems", "display_name": "Systems", "canonical_route": "/systems" },
    { "workspace_ref": "hypervisor-workspace://projects", "workspace_key": "projects", "display_name": "Projects", "canonical_route": "/projects" },
    { "workspace_ref": "hypervisor-workspace://applications", "workspace_key": "applications", "display_name": "Applications", "canonical_route": "/applications" },
    { "workspace_ref": "hypervisor-workspace://work", "workspace_key": "work", "display_name": "Work", "canonical_route": "/work" }
  ],
  "owner_applications": [
    { "surface_ref": "surface://hypervisor/studio", "surface_key": "studio", "surface_class": "owner_application", "canonical_route": "/studio" },
    { "surface_ref": "surface://hypervisor/automations", "surface_key": "automations", "surface_class": "owner_application", "canonical_route": "/automations", "supported_placements": ["permanent_shell", "applications_catalog"] },
    { "surface_ref": "surface://hypervisor/ontology", "surface_key": "ontology", "surface_class": "owner_application", "canonical_route": "/ontology" },
    { "surface_ref": "surface://hypervisor/data", "surface_key": "data", "surface_class": "owner_application", "canonical_route": "/data" },
    { "surface_ref": "surface://hypervisor/governance", "surface_key": "governance", "surface_class": "owner_application", "canonical_route": "/governance" },
    { "surface_ref": "surface://hypervisor/provenance", "surface_key": "provenance", "surface_class": "owner_application", "canonical_route": "/provenance" },
    { "surface_ref": "surface://hypervisor/evaluations", "surface_key": "evaluations", "surface_class": "owner_application", "canonical_route": "/evaluations" },
    { "surface_ref": "surface://hypervisor/improvement", "surface_key": "improvement", "surface_class": "owner_application", "canonical_route": "/improvement" },
    { "surface_ref": "surface://hypervisor/foundry", "surface_key": "foundry", "surface_class": "owner_application", "canonical_route": "/foundry" },
    { "surface_ref": "surface://hypervisor/packages", "surface_key": "packages", "surface_class": "owner_application", "canonical_route": "/packages" },
    { "surface_ref": "surface://hypervisor/developer-workspace", "surface_key": "developer-workspace", "surface_class": "owner_application", "canonical_route": "/developer-workspace" },
    { "surface_ref": "surface://hypervisor/developer-console", "surface_key": "developer-console", "surface_class": "owner_application", "canonical_route": "/developer-console" },
    { "surface_ref": "surface://hypervisor/embodied-systems", "surface_key": "embodied-systems", "surface_class": "owner_application", "canonical_route": "/embodied-systems", "surface_availability": "planned" }
  ],
  "substrate_applications": [
    { "surface_ref": "surface://hypervisor/environments", "surface_key": "environments", "surface_class": "substrate_application", "canonical_route": "/environments" },
    { "surface_ref": "surface://hypervisor/operations", "surface_key": "operations", "surface_class": "substrate_application", "canonical_route": "/operations" }
  ],
  "dynamic_registration_classes": [
    "tool_surface",
    "extension_application"
  ],
  "normalized_record_contracts": [
    "HypervisorApplicationSurfaceRegistration",
    "HypervisorRouteAliasRegistration",
    "HypervisorSurfaceReleaseRecord",
    "HypervisorSurfaceInstallationBinding",
    "HypervisorSystemInterfaceBinding",
    "HypervisorSurfaceServingBinding",
    "HypervisorProductSurfaceProjection"
  ],
  "route_alias_registrations": [
    {
      "route_alias_ref": "route-alias://hypervisor/sessions",
      "owner_ref": "hypervisor-workspace://work",
      "alias_route_pattern": "/sessions",
      "resolution": {
        "kind": "static_route",
        "target_route_template": "/work/sessions"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
    },
    {
      "route_alias_ref": "route-alias://hypervisor/missions",
      "owner_ref": "hypervisor-workspace://work",
      "alias_route_pattern": "/missions/{legacy_subject_id?}",
      "resolution": {
        "kind": "typed_resolver",
        "resolver_kind": "legacy_work_subject",
        "resolver_contract_ref": "api://hypervisor/legacy-work-subject-resolution"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
    },
    {
      "route_alias_ref": "route-alias://hypervisor/workbench",
      "owner_ref": "surface://hypervisor/developer-workspace",
      "alias_route_pattern": "/workbench",
      "resolution": {
        "kind": "static_route",
        "target_route_template": "/developer-workspace"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
    },
    {
      "route_alias_ref": "route-alias://hypervisor/marketplace",
      "owner_ref": "surface://hypervisor/packages",
      "alias_route_pattern": "/marketplace",
      "resolution": {
        "kind": "static_route",
        "target_route_template": "/packages/marketplace"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
    },
    {
      "route_alias_ref": "route-alias://hypervisor/legacy-agent-studio",
      "owner_ref": "surface://hypervisor/studio",
      "alias_route_pattern": "/__ioi/agent-studio",
      "resolution": {
        "kind": "static_route",
        "target_route_template": "/studio"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
    },
    {
      "route_alias_ref": "route-alias://hypervisor/fleet",
      "owner_ref": "surface://hypervisor/embodied-systems",
      "alias_route_pattern": "/fleet",
      "resolution": {
        "kind": "typed_resolver",
        "resolver_kind": "contextual_surface",
        "resolver_contract_ref": "api://hypervisor/fleet-context-resolution"
      },
      "preserve_context": {
        "query": true,
        "hash": true,
        "embed_and_return_state": true,
        "open_application_identity_and_back_stack": true,
        "typed_context_kinds": [
          "organization", "project", "system", "goal_run", "outcome_room",
          "automation_run", "session", "work_queue", "work_item", "work_run"
        ]
      },
      "failure_mode": "fail_closed"
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

The taxonomy endpoint is not a runtime dispatcher or launch-eligibility
oracle. It exposes definition-owned workspace and application metadata plus
compatibility and adapter contracts. It must not copy release distribution or
admission, installation state, System-interface enablement, serving health, or
derived launchability onto the stable registration rows.

```http
POST /v1/hypervisor/product-surface-projections
```

`POST /v1/hypervisor/product-surface-projections` compiles the one
request-scoped, policy-filtered navigation, Applications, command-palette, and
contextual-launch projection. Its inputs are the stable registrations plus
`HypervisorSurfaceReleaseRecord`,
`HypervisorSurfaceInstallationBinding`,
`HypervisorSystemInterfaceBinding`, and
`HypervisorSurfaceServingBinding` records admitted by their canonical owners.
The compiler also applies authenticated organization/user preferences, current
typed context, and policy decisions. No client may join these records or infer
launchability locally.

Request body:

```json
{
  "schema_version": "ioi.hypervisor.product_surface_projection_request.v1",
  "user_ref": "user://...",
  "org_ref": "org://...",
  "context": {
    "project_ref": "project://... | null",
    "system_ref": "system://... | null",
    "goal_run_ref": "goal://... | null",
    "outcome_room_ref": "outcome-room://... | null",
    "automation_run_ref": "automation-run://... | null",
    "session_ref": "session://... | null",
    "work_queue_ref": "work_queue://... | null",
    "work_item_ref": "work_item://... | null",
    "work_run_ref": "work_run://... | null"
  },
  "requested_group_kinds": [
    "first_party_applications",
    "tools_for_context",
    "organization_applications",
    "installed_applications",
    "system_interfaces",
    "recommended",
    "recent",
    "favorites"
  ],
  "preference_projection_refs": ["preference://..."]
}
```

The daemon derives the authenticated principal and deployment tenant from the
admitted request boundary. `user_ref` and `org_ref` are selectors that must
match that principal and an admitted tenant-membership binding; they are never
caller-asserted authority. A mismatch fails before preference lookup, policy
filtering, aggregation, or caching. `request_context_hash` binds the
authenticated principal, organization/tenant, policy and registration
versions, requested groups, preferences, and every typed context ref so cached
projections cannot cross users, organizations, Systems, or work subjects.

The response is an
`ioi.hypervisor.product_surface_projection.v1` object. The representative
entries below are deliberately complete: real responses contain one row for
every eligible workspace and application registration, not a second
hand-maintained card catalog.

```json
{
  "schema_version": "ioi.hypervisor.product_surface_projection.v1",
  "projection": {
    "projection_id": "projection://hypervisor/product-surface/...",
    "request_context_hash": "hash:...",
    "workspace_registration_refs": [
      "hypervisor-workspace://home",
      "hypervisor-workspace://systems",
      "hypervisor-workspace://projects",
      "hypervisor-workspace://applications",
      "hypervisor-workspace://work"
    ],
    "application_registration_refs": [
      "surface://hypervisor/studio",
      "surface://hypervisor/embodied-systems"
    ],
    "workspace_entries": [
      {
        "workspace_ref": "hypervisor-workspace://work",
        "display_name": "Work",
        "canonical_route": "/work",
        "route_alias_refs": [
          "route-alias://hypervisor/sessions",
          "route-alias://hypervisor/missions"
        ],
        "launchable": true,
        "disabled_reason_codes": [],
        "launch_binding": {
          "kind": "core_workspace",
          "workspace_ref": "hypervisor-workspace://work"
        },
        "typed_context_refs": [
          "org://...",
          "project://...",
          "work_queue://..."
        ]
      }
    ],
    "application_entries": [
      {
        "surface_ref": "surface://hypervisor/studio",
        "surface_key": "studio",
        "family_id": "build",
        "display_name": "Studio",
        "summary": "Compose bounded autonomous institutions over real substrate objects.",
        "primary_user_job": "Constitute and compose a System or direct autonomous-work package.",
        "publisher_ref": "org://ioi",
        "primary_owner_application_ref": null,
        "tool_kind": null,
        "selected_release_ref": "package://hypervisor/studio/release/...",
        "selected_installation_ref": "install://hypervisor/studio/...",
        "selected_system_binding_ref": null,
        "selected_serving_binding_ref": "surface-serving://hypervisor/studio/...",
        "eligible_release_refs": [
          "package://hypervisor/studio/release/..."
        ],
        "eligible_installation_refs": [
          "install://hypervisor/studio/..."
        ],
        "eligible_system_binding_refs": [],
        "eligible_serving_binding_refs": [
          "surface-serving://hypervisor/studio/..."
        ],
        "surface_class": "owner_application",
        "surface_origin": "first_party",
        "surface_creation_method": "hand_authored",
        "surface_distribution": "bundled",
        "surface_availability": "available",
        "surface_admission_state": "not_applicable",
        "surface_installation_state": "installed",
        "surface_package_disposition": "active",
        "selected_installation_enablement_state": "enabled",
        "selected_system_enablement_state": null,
        "effective_enablement_state": "enabled",
        "surface_capability_depth": "workflow_complete",
        "surface_operational_state": "serving",
        "effective_visibility": "organization",
        "effective_audience_refs": ["org://..."],
        "effective_object_contract_refs": ["object-model://hypervisor/studio"],
        "effective_allowed_action_refs": ["action://hypervisor/studio/compose"],
        "effective_authority_preview_policy_ref": "policy://hypervisor/studio/default",
        "group_kinds": ["first_party_applications"],
        "canonical_route": "/studio",
        "resolved_launch_route": "/studio",
        "route_alias_refs": [
          "route-alias://hypervisor/legacy-agent-studio"
        ],
        "launchable": true,
        "disabled_reason_codes": [],
        "launch_binding": {
          "kind": "serving_binding",
          "serving_binding_ref": "surface-serving://hypervisor/studio/..."
        },
        "typed_context_refs": ["org://...", "project://..."]
      },
      {
        "surface_ref": "surface://hypervisor/embodied-systems",
        "surface_key": "embodied-systems",
        "family_id": "operate",
        "display_name": "Embodied Systems",
        "summary": "Commission and operate embodied units and fleets.",
        "primary_user_job": "Coordinate embodied Systems through admitted native graphs and a deployment-bound LocalControlSupervisor.",
        "publisher_ref": "org://ioi",
        "primary_owner_application_ref": null,
        "tool_kind": null,
        "selected_release_ref": null,
        "selected_installation_ref": null,
        "selected_system_binding_ref": null,
        "selected_serving_binding_ref": null,
        "eligible_release_refs": [],
        "eligible_installation_refs": [],
        "eligible_system_binding_refs": [],
        "eligible_serving_binding_refs": [],
        "surface_class": "owner_application",
        "surface_origin": "first_party",
        "surface_creation_method": "hand_authored",
        "surface_distribution": null,
        "surface_availability": "planned",
        "surface_admission_state": null,
        "surface_installation_state": null,
        "surface_package_disposition": null,
        "selected_installation_enablement_state": null,
        "selected_system_enablement_state": null,
        "effective_enablement_state": "not_applicable",
        "surface_capability_depth": null,
        "surface_operational_state": null,
        "effective_visibility": null,
        "effective_audience_refs": [],
        "effective_object_contract_refs": [],
        "effective_allowed_action_refs": [],
        "effective_authority_preview_policy_ref": null,
        "group_kinds": ["recommended"],
        "canonical_route": "/embodied-systems",
        "resolved_launch_route": null,
        "route_alias_refs": ["route-alias://hypervisor/fleet"],
        "launchable": false,
        "disabled_reason_codes": ["planned"],
        "launch_binding": null,
        "typed_context_refs": ["org://...", "system://..."]
      }
    ],
    "policy_decision_refs": ["decision://..."],
    "generated_at": "timestamp",
    "read_model_only": true
  }
}
```

Every selected ref must belong to its corresponding eligible set. Release,
installation, System-interface, and serving records must preserve identical
`surface_ref`; installation, System-interface, and serving records must
preserve the selected `release_ref`; and a System-scoped serving binding must
preserve the selected installation and System binding. The launch binding is a
discriminated one-of mapping and must name exactly the selected compatible ref.
Effective enablement is disabled when either the selected installation gate or
selected System-interface gate is disabled. A null release-, installation-, or
serving-owned projected axis means no eligible source record was selected; it
is not another canonical enum state.

Implementation status: the current core-taxonomy code path still emits the
narrower v1 hard-coded taxonomy, and the product-surface projection endpoint is
not implemented. Until typed registrations, normalized owner records, and the
request-scoped policy compiler exist, a v2 taxonomy request and a
product-surface projection request must return typed unavailable/unsupported
responses rather than relabeling v1 data or compiling launch state in a client.
The v1 shape is transitional implementation evidence, not target product
doctrine.

```http
POST /v1/hypervisor/session-launch-recipe-admissions
```

`POST /v1/hypervisor/session-launch-recipe-admissions` admits a selected
`HypervisorSessionLaunchRecipe` before the client may request harness binding
or spawn. The admission binds its exact owner-qualified recipe revision, target
binding, project, surface route, model route, privacy posture, authority
scopes, receipt preview, Agentgres operation refs, and state-root intent under
daemon runtime truth.

Request body:

```json
{
  "schema_version": "ioi.hypervisor.session_launch_recipe_admission_request.v1",
  "session_launch_recipe": {
    "schema_version": "ioi.hypervisor.session_launch_recipe.v1",
    "session_launch_recipe_ref": "session-launch-recipe://developer-workspace/default/revision/1",
    "content_hash": "sha256:...",
    "kind": "developer_workspace",
    "surface_ref": "surface://hypervisor/developer-workspace",
    "required_inputs": ["project", "adapter_preference", "harness"],
    "model_mount_policy": "inherit",
    "harness_profile_policy": "select",
    "authority_scope_templates": ["scope:workspace.read"],
    "privacy_posture_templates": ["public_trunk", "redacted_projection"]
  },
  "target_binding": {
    "schema_version": "ioi.hypervisor.new_session_target_binding.v1",
    "target_binding_ref": "target-binding:new-session/developer-workspace.default/ioi",
    "session_launch_recipe_ref": "session-launch-recipe://developer-workspace/default/revision/1",
    "target_kind": "developer_workspace",
    "surface_ref": "surface://hypervisor/developer-workspace",
    "project_ref": "project://ioi",
    "session_route_ref": "session-route:developer-workspace/developer-workspace.default/ioi",
    "code_editor_adapter_target_ref": "code-editor-target:vscode",
    "runtimeTruthSource": "daemon-runtime"
  },
  "model_route_ref": "model-route:hypervisor/default-local",
  "privacy_posture_ref": "privacy:redacted-projection",
  "authority_scope_refs": ["scope:workspace.read", "scope:workspace.patch"],
  "receipt_preview_ref": "receipt-preview:new-session/developer-workspace",
  "expected_receipt_refs": [
    "receipt-preview:new-session/developer-workspace",
    "receipt-policy:harness-adapter/default"
  ],
  "agentgres_operation_refs": [
    "agentgres://operation/hypervisor/session-launch-recipe/developer-workspace"
  ],
  "receipt_refs": ["receipt://hypervisor/session-launch-recipe/developer-workspace"],
  "requires_daemon_gate": true,
  "runtimeTruthSource": "daemon-runtime"
}
```

The response is an
`ioi.runtime.hypervisor_session_launch_recipe_admission.v1` object. A launched
session must not be considered `daemon_admitted` unless it carries this recipe
admission, followed by harness binding admission, harness launch, spawn, and
readiness records.

The live v1 adapter may still accept the historical nested `recipe` and
`recipe_ref` field names. It must normalize them to the owner-qualified
`session_launch_recipe` and exact `session_launch_recipe_ref` above before
admission and must not emit a generic Recipe identity in target v2 state.

```http
POST /v1/hypervisor/approved-operations
```

`POST /v1/hypervisor/approved-operations` admits an already-proposed
Hypervisor operation for execution only after the operation has passed the
applicable local/domain/protocol authority path and the Agentgres truth path.
wallet.network is mandatory when the operation invokes portable delegated
authority or one of its owned spend, secret/decryption, declassification,
external-effect, or high-risk scopes.

Request body:

```json
{
  "operation_family": "session | provider | project | automation",
  "proposal_ref": "session-operation:... | provider-operation:... | project-operation:... | proposal://automation-run/...",
  "proposal_schema_version": "ioi.hypervisor.session_operation_proposal.v1",
  "proposal_source": "daemon-session-operation-proposal",
  "proposal_revision_ref": "session-operation:... | provider-operation:... | project-operation:... | null",
  "proposal_content_hash": "sha256:...",
  "proposal_resolution_receipt_ref": "receipt://... | null",
  "automation_activation_binding": {
    "automation_run_proposal_ref": "proposal://automation-run/...",
    "automation_spec_revision_ref": "automation://.../revision/...",
    "automation_spec_content_hash": "sha256:...",
    "automation_installation_binding_revision_ref": "install://automation/.../revision/...",
    "automation_installation_binding_hash": "sha256:...",
    "activation_event_ref": "event://...",
    "candidate_parameter_set_hash": "sha256:... | null",
    "candidate_activation_override_set_hash": "sha256:... | null"
  },
  "project_ref": "project://...",
  "workspace_ref": "workspace://...",
  "session_ref": "session://...",
  "environment_ref": "environment://...",
  "provider_candidate_ref": "provider://...",
  "candidate_ref": "provider-candidate:...",
  "direct_provider_ref": "provider://...",
  "operation_kind": "restore_session | zero_to_idle | activate_occurrence | ...",
  "target_ref": "agentgres://restore/...",
  "authority_provider_ref": "authority://provider/...",
  "approval_authority_snapshot_hash": "sha256:...",
  "authority_decision_ref": "authority://decision/...",
  "authority_decision_hash": "sha256:...",
  "authority_grant_ref": "grant://...",
  "authority_grant_hash": "sha256:...",
  "authority_lease_ref": "lease://authority/... | null",
  "authority_lease_hash": "sha256:... | null",
  "required_scope_refs": ["scope:..."],
  "authority_receipt_refs": ["receipt://authority/..."],
  "agentgres_operation_ref": "agentgres://operation/...",
  "receipt_ref": "receipt://...",
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/..."
}
```

The target response is an
`ioi.runtime.hypervisor_approved_operation_admission.v2` object:

```json
{
  "schema_version": "ioi.runtime.hypervisor_approved_operation_admission.v2",
  "admission_id": "hypervisor-approved-operation:...",
  "admission_ref": "hypervisor-approved-operation:...",
  "admission_hash_profile": "ioi.runtime.hypervisor-approved-operation-admission-jcs-sha256.v1",
  "admission_hash": "sha256:...",
  "operation_family": "session",
  "proposal_ref": "session-operation:...",
  "proposal_schema_version": "ioi.hypervisor.session_operation_proposal.v1",
  "proposal_source": "daemon-session-operation-proposal",
  "proposal_revision_ref": "session-operation:...",
  "proposal_content_hash": "sha256:...",
  "proposal_resolution_receipt_ref": "receipt://...",
  "project_ref": "project://...",
  "operation_kind": "restore_session",
  "decision": "admitted",
  "execution_status": "admitted_for_execution",
  "executor_kind": "session_lifecycle_adapter",
  "execution_plan_ref": "execution-plan://hypervisor/...",
  "execution_dispatch_ref": "dispatch://hypervisor/...",
  "execution_plan": {
    "schema_version": "ioi.runtime.hypervisor_approved_operation_execution_plan.v1",
    "execution_plan_ref": "execution-plan://hypervisor/...",
    "dispatch_ref": "dispatch://hypervisor/...",
    "admission_ref": "hypervisor-approved-operation:...",
    "admission_hash_profile": "ioi.runtime.hypervisor-approved-operation-admission-jcs-sha256.v1",
    "admission_hash": "sha256:...",
    "executor_kind": "session_lifecycle_adapter",
    "dispatch_status": "awaiting_executor"
  },
  "authority_provider_ref": "authority://provider/...",
  "approval_authority_snapshot_hash": "sha256:...",
  "authority_decision_ref": "authority://decision/...",
  "authority_decision_hash": "sha256:...",
  "authority_grant_ref": "grant://...",
  "authority_grant_hash": "sha256:...",
  "authority_lease_ref": "lease://authority/... | null",
  "authority_lease_hash": "sha256:... | null",
  "required_scope_refs": ["scope:..."],
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "receipt_refs": ["receipt://..."],
  "state_root_ref": "agentgres://state-root/...",
  "archive_ref": "artifact://agentgres/archive/...",
  "restore_ref": "agentgres://restore/...",
  "runtimeTruthSource": "daemon-runtime"
}
```

Every admitted consequential operation carries a mandatory scoped
`authority_grant_ref`/`authority_grant_hash` pair. A provider may additionally
materialize an operation-scoped lease; `authority_lease_ref` and
`authority_lease_hash` are either both non-null or both null. Null means that
the exact grant is itself the execution binding, never that authority was not
required.

`admission_hash_profile` is the closed profile
`ioi.runtime.hypervisor-approved-operation-admission-jcs-sha256.v1`.
`admission_hash` is exactly:

```text
"sha256:" + lowercase_hex(
  SHA-256(UTF8(RFC8785_JCS({
    "domain": "ioi.runtime.hypervisor-approved-operation-admission-jcs-sha256.v1",
    "value": admission_without_only_the_top_level_admission_hash_and_the_nested_execution_plan_admission_ref_hash_profile_and_hash
  })))
)
```

The `value` is the complete target v2 response object. The only exclusions are
the top-level `admission_hash` and the nested execution plan's
`admission_ref`, `admission_hash_profile`, and `admission_hash` binding fields;
no provider, decision, grant, optional lease, scope, proposal, or
Agentgres-evidence fact is excluded. The execution plan retains that exact
admission ref, profile, and hash without a circular self-hash.

The live Rust v1 handler still requires `wallet_approval_ref` and
`wallet_lease_ref` for every admitted operation and emits
`ioi.runtime.hypervisor_approved_operation_admission.v1`. That is a partial
wallet-specific precursor, not proof of the provider-neutral target. A v1
boundary adapter may map those fields into the target authority fields only
when wallet.network actually owns the requested scopes and can resolve the
mandatory grant pair plus the paired optional lease representation. Ordinary
local/domain authority requires the v2 successor path and must remain typed
unavailable until it exists.

For `operation_family: automation`, `proposal_revision_ref` and
`proposal_resolution_receipt_ref` are null. The exact
`proposal://automation-run/...` plus `proposal_content_hash` identifies the
candidate, while `automation_activation_binding` supplies the spec,
installation-binding, occurrence, parameter, and override commitments to
revalidate. Final admission alone returns and stores:

```json
{
  "automation_run_ref": "automation-run://...",
  "automation_run_resolution_receipt_ref": "receipt://...",
  "automation_spec_revision_ref": "automation://.../revision/...",
  "automation_spec_content_hash": "sha256:...",
  "automation_installation_binding_revision_ref": "install://automation/.../revision/...",
  "automation_installation_binding_hash": "sha256:...",
  "workflow_template_revision_ref": "workflow-template://.../revision/...",
  "workflow_template_content_hash": "sha256:...",
  "execution_status": "admitted_for_execution"
}
```

The automation proposal is not an AutomationSpec revision and has no
pre-admission AutomationRun resolution receipt. Mismatch, disabled/revoked
binding, stale proposal hash, or changed policy fails closed before the
`automation-run://` identity is minted.

Approved operation admission rejects fixture or unverified proposal sources.
The endpoint is not a provider adapter and not a wallet approval UI. It is the
daemon admission boundary that proves the selected proposal, applicable
authority approval and lease, Agentgres operation refs, receipts,
archive/restore refs, and state root are bound before Hypervisor executes the
session or provider lifecycle operation.

The approved-operation boundary consumes the proposal's already frozen typed
composition. It never restates an unversioned template, graph, launch action,
or generic run recipe. The current Rust v1 input's `template_ref`,
`run_recipe_ref`, `graph_ref`, and `launch_action_ref` fields are deprecated
compatibility inputs only: an adapter may accept them long enough to resolve
and verify the exact `AutomationSpec` and `WorkflowTemplate` revision, then
must record the normalized revision/hash/resolution receipt and omit those
aliases from canonical output. Resolution failure is typed-unavailable, not a
best-effort execution.

The admission response also returns a daemon-owned execution plan. The plan is
not execution by itself and must remain `awaiting_executor` until a concrete
session, provider, project, or workflow-compositor adapter consumes it and
returns admitted execution receipts. This gives adapters a single execution
handoff without letting clients turn approval into local side effects.

```http
POST /v1/hypervisor/approved-operation-dispatches
```

`POST /v1/hypervisor/approved-operation-dispatches` is the executor-facing
handoff for a daemon-owned execution plan. The endpoint does not approve an
operation and does not create a plan. It consumes the exact
`ioi.runtime.hypervisor_approved_operation_execution_plan.v1` returned by
approved-operation admission and requires a mounted executor for the plan's
`executor_kind`.

The live daemon mounts a default approved-operation executor registry for the
first local lifecycle adapters:

```text
session_lifecycle_adapter
  executor://hypervisor/session/lifecycle-adapter

provider_lifecycle_adapter
  executor://hypervisor/provider/lifecycle-adapter

project_lifecycle_adapter
  executor://hypervisor/project/lifecycle-adapter

workflow_compositor_runner
  executor://hypervisor/automation/workflow-compositor-runner
```

Provider-specific, cloud-specific, editor-specific, and workflow-specific
adapters may replace these registry entries later, but they still consume the
same daemon-owned execution plan and return receipt/state-root evidence.

Request body:

```json
{
  "execution_plan_ref": "execution-plan://hypervisor/...",
  "dispatch_ref": "dispatch://hypervisor/...",
  "executor_kind": "session_lifecycle_adapter",
  "executor_ref": "executor://hypervisor/session/local-workstation",
  "execution_plan": {
    "schema_version": "ioi.runtime.hypervisor_approved_operation_execution_plan.v1",
    "execution_plan_ref": "execution-plan://hypervisor/...",
    "dispatch_ref": "dispatch://hypervisor/...",
    "executor_kind": "session_lifecycle_adapter",
    "dispatch_status": "awaiting_executor",
    "wallet_lease_ref": "lease:wallet/...",
    "agentgres_operation_refs": ["agentgres://operation/..."],
    "receipt_refs": ["receipt://..."],
    "state_root_ref": "agentgres://state-root/...",
    "runtimeTruthSource": "daemon-runtime"
  }
}
```

The response is an `ioi.runtime.hypervisor_approved_operation_dispatch.v1`
receipt-bearing dispatch record:

```json
{
  "schema_version": "ioi.runtime.hypervisor_approved_operation_dispatch.v1",
  "execution_plan_ref": "execution-plan://hypervisor/...",
  "dispatch_ref": "dispatch://hypervisor/...",
  "execution_attempt_ref": "execution-attempt://hypervisor/...",
  "dispatch_status": "executed | failed | blocked",
  "execution_status": "completed | failed | blocked",
  "executor_kind": "session_lifecycle_adapter",
  "executor_ref": "executor://hypervisor/session/local-workstation",
  "operation_family": "session",
  "operation_kind": "restore_session",
  "wallet_lease_ref": "lease:wallet/...",
  "required_scope_refs": ["scope:..."],
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "receipt_refs": ["receipt://...", "receipt://.../executed"],
  "previous_state_root_ref": "agentgres://state-root/...",
  "next_state_root_ref": "agentgres://state-root/...",
  "artifact_refs": ["artifact://..."],
  "trace_refs": ["trace://..."],
  "runtimeTruthSource": "daemon-runtime"
}
```

Dispatch fails closed when no executor is mounted, the client supplies
camelCase aliases, the supplied refs do not match the plan, the plan is not
`awaiting_executor`, the plan is not daemon-runtime truth, or the executor
does not return an execution receipt. This keeps provider, session, project,
and automation adapters behind the same plan/receipt boundary instead of
letting approved UI actions become direct side effects.

### Runtime Manifest

```json
{
  "runtime_id": "runtime://node_abc",
  "runtime_type": "local_hypervisor | hosted_ioi | provider | depin | hypervisoros | tee | customer_vpc",
  "daemon_version": "0.8.0",
  "default_harness_profile": "2026.05.default-harness-profile.v1",
  "agentgres_version": "0.2.0",
  "supported_execution_profiles": ["local", "hosted", "provider", "depin_mutual_blind", "hypervisoros_bare_metal", "tee_enterprise", "customer_vpc"],
  "supported_interfaces": ["agents", "managed_instances", "projects", "work", "sessions", "goal_runs", "outcome_rooms", "automation_runs", "adapter_targets", "environment_ops", "threads", "runs", "workers", "training", "benchmarks", "routing", "tools", "models", "connectors", "authority_gateway", "action_requests", "artifacts", "receipts", "trace", "replay", "scorecards"],
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
GET  /v1/work-queues
POST /v1/work-queues
GET  /v1/work-queues/{work_queue_id}
PATCH /v1/work-queues/{work_queue_id}
GET  /v1/work-queues/{work_queue_id}/items
POST /v1/work-items
GET  /v1/work-items
GET  /v1/work-items/{work_item_id}
PATCH /v1/work-items/{work_item_id}
POST /v1/work-items/{work_item_id}/runs
GET  /v1/work-items/{work_item_id}/runs
GET  /v1/work-runs
GET  /v1/work-runs/{work_run_id}
GET  /v1/work-runs/{work_run_id}/status
GET  /v1/work-runs/{work_run_id}/events
GET  /v1/work-runs/{work_run_id}/conversation
GET  /v1/work-runs/{work_run_id}/conversation/history
GET  /v1/work-runs/{work_run_id}/conversation/live
GET  /v1/work-runs/{work_run_id}/conversation/blobs
GET  /v1/work-runs/{work_run_id}/transcript
GET  /v1/work-runs/{work_run_id}/logs
GET  /v1/work-runs/{work_run_id}/support-bundle
GET  /v1/work-runs/{work_run_id}/integration-status
GET  /v1/work-runs/{work_run_id}/review-state
POST /v1/work-runs/{work_run_id}/comments
POST /v1/work-runs/{work_run_id}/input
POST /v1/work-runs/{work_run_id}/stop
POST /v1/work-runs/{work_run_id}/cancel
POST /v1/work-runs/{work_run_id}/replay
GET  /v1/models
GET  /v1/repositories
GET  /v1/account
```

`/v1/runs` is the generic runtime execution lifecycle. `/v1/work-*` is the
Hypervisor delegated-agent-work product contract layered over that lifecycle:
queues define intake, work items define requested work, and work runs define
one governed execution attempt with project/environment context,
conversation/transcript/log refs, integration status, usage counters, review
state, delivery refs, receipts, and replay refs.

### Delegated Agent Work Run

```json
{
  "work_item": {
    "source_kind": "new_session | automation_trigger | pull_request | issue_event | webhook | schedule | api",
    "project_ref": "project://...",
    "original_request_ref": "artifact://...",
    "code_context": {
      "repository_refs": ["repo://..."],
      "environment_ref": "hypervisor_environment_lifecycle:...",
      "pull_request_ref": "scm_pr://..."
    },
    "desired_delivery": "report | patch | pull_request | deployment | service_response",
    "review_contract_ref": "review_contract://...",
    "authority_scope_refs": ["grant://..."]
  },
  "work_run": {
    "session_ref": "session://...",
    "harness_selection_ref": "harness_selection:...",
    "model_configuration_ref": "model_configuration:...",
    "reasoning_profile_ref": "reasoning_profile:...",
    "desired_phase": "running",
    "current_phase": "pending | running | waiting_for_input | ready_for_review | completed | failed",
    "current_activity": "string",
    "conversation_projection_ref": "hypervisor_work_run_conversation:...",
    "transcript_ref": "artifact://...",
    "integration_status_refs": ["hypervisor_work_run_integration_status:..."],
    "used_environment_refs": ["hypervisor_environment_lifecycle:..."],
    "usage": {
      "iterations": 0,
      "input_tokens": 0,
      "output_tokens": 0,
      "cached_input_tokens": 0,
      "context_window_length": 0
    },
    "review_state_ref": "hypervisor_work_run_review_state:...",
    "receipt_refs": ["receipt://..."]
  }
}
```

`POST /v1/work-runs/{work_run_id}/comments` accepts human or reviewer input,
including optional file/hunk refs. It must deliver the comment as admitted work
run input, not as a direct mutation of the agent service's internal state.

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

## Agent Operating Plane API

The Agent Operating Plane is the daemon-owned control surface for configured
agents, agent sessions, agent executions, conversation streams, turn controls,
subagent delegation, model/LLM integration posture, runner reconciliation,
usage accounting, and security telemetry.

It is not a second runtime beside `/v1/runs`, `/v1/work-*`, or
`/v1/threads`. Product-facing agent actions compile into WorkQueue, WorkItem,
WorkRun, Session, Thread, Turn, HarnessProfile, ModelConfiguration,
RuntimeToolContract, wallet.network, Agentgres, and receipt objects.

```http
POST /v1/agent-sessions
GET  /v1/agent-executions
GET  /v1/agent-executions/{agent_execution_id}
POST /v1/agent-executions/{agent_execution_id}/input
POST /v1/agent-executions/{agent_execution_id}/control
GET  /v1/agent-executions/{agent_execution_id}/events
GET  /v1/agent-executions/{agent_execution_id}/events/stream
POST /v1/agent-executions/{agent_execution_id}/outputs
POST /v1/agent-executions/{agent_execution_id}/stop
POST /v1/agent-executions/{agent_execution_id}/delete
GET  /v1/runtime/runner-requests/stream
POST /v1/runtime/runner-responses
POST /v1/runtime/llm-usage-events
POST /v1/runtime/exec-events
```

`POST /v1/agent-sessions` may atomically create or select an environment,
create a session, start a configured agent, and submit initial input. The
request must not smuggle provider credentials, workspace plaintext, or
unadmitted execution into the client.

```json
{
  "agent_ref": "agent://...",
  "project_ref": "project://...",
  "environment_request": {
    "create_from_project_ref": "project://...",
    "development_environment_recipe_ref": "development-environment-recipe://.../revision/...",
    "environment_class_ref": "environment-class://..."
  },
  "initial_input": {
    "text": "Implement the approved change."
  },
  "mode": "agent | plan | goal",
  "model_configuration_ref": "model-configuration://...",
  "reasoning_effort": "low | medium | high | extra_high",
  "speed": "standard | fast",
  "harness_selection_ref": "harness-selection://...",
  "tool_binding_refs": ["tool://..."],
  "mcp_server_refs": ["mcp://..."],
  "authority_scope_refs": ["scope:..."],
  "budget_ref": "budget://...",
  "receipt_policy_ref": "receipt-policy://..."
}
```

The response binds all created or selected runtime objects:

```json
{
  "session_ref": "session://...",
  "environment_ref": "hypervisor_environment_lifecycle:...",
  "agent_execution_ref": "agent-execution://...",
  "work_item_ref": "work_item://...",
  "work_run_ref": "work_run://...",
  "thread_ref": "thread:...",
  "conversation_projection_ref": "hypervisor_work_run_conversation:...",
  "wallet_lease_refs": ["lease:wallet/..."],
  "agentgres_operation_refs": ["agentgres://operation/..."],
  "state_root_ref": "agentgres://state-root/...",
  "receipt_refs": ["receipt://..."],
  "runtimeTruthSource": "daemon-runtime"
}
```

Agent execution status should include phase, desired phase, current activity,
current operation, model configuration, mode, usage, waiting interests,
integration status, outputs, conversation refs, transcript refs, support bundle
refs, receipts, and Agentgres refs. Common phases:

```text
pending
running
waiting_for_input
ready_for_review
stopped
completed
failed
```

`POST /v1/agent-executions/{agent_execution_id}/input` accepts explicit input
blocks and control messages:

```json
{
  "user_input": {
    "id": "input_...",
    "text": {"content": "Please respond to the review comment."},
    "metadata": {"source": "reviewer", "modes": ["agent"]}
  },
  "agent_message": {
    "type": "update | complete",
    "role": "parent | child",
    "sender_execution_ref": "agent-execution://...",
    "payload_ref": "artifact://..."
  },
  "wake_event": {
    "kind": "timer_fired | loop_retrigger | environment_ready"
  },
  "model_configuration_ref": "model-configuration://...",
  "turn_options": {"modes": ["agent", "plan", "goal"]},
  "control_input": {
    "compact": false,
    "goal": "pause | resume | complete | clear | set",
    "delete_queued_message_ref": "input_..."
  }
}
```

Conversation streams should use typed blocks rather than a generic event bag.
Valid block families include:

```text
user_input_seen
user_input
user_input_deleted
text
action_started
action_completed
file_modification
environment_creation
host_authentication_required
code_annotation
todo_group
todo_item
thought
agent_mode_change
clarifying_questions
next_steps_proposal
available_commands
```

Runner reconciliation APIs are internal/runtime-node APIs. They allow
daemon-compatible runners to watch admitted requests, report responses, update
agent execution status, request actor tokens, list integrations, report model
usage, report runner metrics, update snapshots and warm pools, and publish
lifecycle observations. Runner APIs must never create an alternate source of
truth: every returned mutation must bind back to WorkRun, Session, Agentgres,
wallet, receipt, and state-root refs.

`POST /v1/runtime/llm-usage-events` records model usage:

```json
{
  "idempotency_key": "usage_...",
  "runner_ref": "runner://...",
  "agent_execution_ref": "agent-execution://...",
  "model_ref": "model://...",
  "model_route_ref": "model-route://...",
  "llm_integration_ref": "llm-integration://...",
  "input_tokens": 0,
  "cached_input_tokens": 0,
  "cache_input_creation_tokens": 0,
  "output_tokens": 0,
  "context_tier": "standard | extended",
  "service_tier": "standard | fast"
}
```

`POST /v1/runtime/exec-events` records security-relevant process execution:

```json
{
  "environment_ref": "hypervisor_environment_lifecycle:...",
  "executable": "/usr/bin/git",
  "filename": "git",
  "kernel_controls_action": "allow | deny | log | require_approval",
  "process": {
    "pid": 123,
    "tid": 123,
    "name": "git",
    "cmdline": "git status --short",
    "ppid": 1,
    "pgid": 123,
    "sid": 123
  },
  "timestamp": "2026-06-21T00:00:00Z"
}
```

## Data Recipe, Worker Training, Benchmark, and MoW Routing API

Data recipe, transformation, training, evaluation, benchmark, and routing
endpoints are daemon execution surfaces. Hypervisor, CLI/headless, optional TUI,
SDK, ADK, ODK, harnesses,
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
POST /v1/threads/{thread_id}/reasoning
POST /v1/threads/{thread_id}/speed
POST /v1/threads/{thread_id}/control
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
Workflow Compositor, Developer Workspace/Foundry surfaces, other application surfaces,
and Environments views may render these controls differently, but
they must converge on these daemon contracts rather than maintaining private
session loops.

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

## Project, Work, Session, and Adapter APIs

Projects, typed work records, sessions, adapter targets, and environment operations are
daemon/Core APIs. Hypervisor App, Hypervisor Web, CLI/headless clients,
Developer Workspace, Foundry, other application surfaces, Environments
views, SDK/ADK/ODK clients, and agent harness adapters may render or call these
APIs, but they must not maintain parallel lifecycle truth.

### Projects

```http
GET  /v1/projects
POST /v1/projects
GET  /v1/projects/{project_id}
PATCH /v1/projects/{project_id}
GET  /v1/projects/{project_id}/sessions
GET  /v1/projects/{project_id}/work
GET  /v1/projects/{project_id}/adapter-connection-profiles
```

### Sessions and Environment Ops

```http
GET  /v1/environment-classes
GET  /v1/environment-classes/{environment_class_id}
GET  /v1/development-environment-recipes
POST /v1/projects/{project_id}/development-environment-recipes
GET  /v1/development-environment-recipes/{recipe_id}
PATCH /v1/development-environment-recipes/{recipe_id}
POST /v1/sessions
POST /v1/sessions/from-project
POST /v1/sessions/from-context-url
GET  /v1/sessions
GET  /v1/sessions/{session_id}
GET  /v1/sessions/{session_id}/environment
GET  /v1/sessions/{session_id}/status
GET  /v1/sessions/{session_id}/events
GET  /v1/sessions/{session_id}/lifecycle-observations
POST /v1/sessions/{session_id}/start
POST /v1/sessions/{session_id}/mark-active
POST /v1/sessions/{session_id}/exec
GET  /v1/sessions/{session_id}/logs
GET  /v1/sessions/{session_id}/ssh-config
POST /v1/sessions/{session_id}/stop
POST /v1/sessions/{session_id}/snapshots
POST /v1/sessions/{session_id}/backups
POST /v1/sessions/{session_id}/archive
POST /v1/sessions/{session_id}/unarchive
POST /v1/sessions/{session_id}/restore
DELETE /v1/sessions/{session_id}
```

External agent harnesses should use the session/environment-ops API for
structured command execution, readiness polling, logs, and cleanup. They should
not scrape Hypervisor product UI.

Environment lifecycle responses should expose `HypervisorEnvironmentClass`,
`HypervisorEnvironmentOpsProfile`, `HypervisorDevelopmentEnvironmentRecipe`,
`HypervisorDevelopmentEnvironmentRecipeResolution`,
`HypervisorEnvironmentStartupPlan`,
`HypervisorEnvironmentLifecycleState`, activity signal refs, lifecycle
observation refs, snapshot refs, backup refs, archive refs, restore refs,
state-root refs, and receipt refs when present.
Provider lifecycle state may be evidence, but it is not Agentgres truth.

Canonical session/environment API objects include
`HypervisorEnvironmentClass`, `HypervisorEnvironmentOpsProfile`,
`HypervisorDevelopmentEnvironmentRecipe`,
`HypervisorDevelopmentEnvironmentRecipeResolution`,
`HypervisorEnvironmentStartupPlan`,
`HypervisorEnvironmentLifecycleState`,
`HypervisorEnvironmentLifecycleObservation`,
`HypervisorEnvironmentActivitySignal`, `HypervisorEnvironmentStopPolicy`,
`HypervisorEnvironmentSnapshot`, `HypervisorEnvironmentBackup`,
`HypervisorSessionAccessLease`, `HypervisorEnvironmentService`,
`HypervisorEnvironmentTask`, `HypervisorEnvironmentPort`,
`HypervisorScmAuthRequirement`, `HypervisorWorkQueue`,
`HypervisorWorkItem`, `HypervisorWorkRun`,
`HypervisorWorkRunConversationProjection`,
`HypervisorWorkRunIntegrationStatus`, and
`HypervisorWorkRunReviewState`.

Development environment recipe APIs manage reusable setup contracts for
Developer Workspace and other development-oriented sessions: substrate, image or
devcontainer refs, checkout/workspace locations, init tasks, services, ports,
editor adapters, environment variable refs, secret requirements, SCM auth,
cache/warmup policy, model/harness defaults, privacy posture, and authority
templates. Recipe resolution must be `resolved` before the daemon can admit the
exact `HypervisorEnvironmentStartupPlan` as the session's lifecycle
predecessor; neither the reusable recipe nor its resolution alone is launch
authority or runtime readiness.

Snapshot, backup, archive, and restore operations must not silently mutate
local or provider files as canonical state. Snapshot and backup payloads are
restore material. Archive payloads are policy-bound restore material. Restore
validity is operation-backed through Agentgres, artifact refs, state-root refs,
policy refs, authority refs, and receipts.

`POST /v1/sessions/{session_id}/stop` accepts a stop policy such as
`graceful`, `immediate`, or `abort`. The selected policy is lifecycle evidence
until the daemon records the resulting state, receipts, cleanup posture,
snapshot/backup/archive refs when applicable, and state-root transition.

### Environment Services, Tasks, and SCM Auth

```http
GET  /v1/sessions/{session_id}/services
POST /v1/sessions/{session_id}/services
GET  /v1/sessions/{session_id}/services/{service_id}
POST /v1/sessions/{session_id}/services/{service_id}/start
POST /v1/sessions/{session_id}/services/{service_id}/stop
GET  /v1/sessions/{session_id}/services/{service_id}/health
GET  /v1/sessions/{session_id}/services/{service_id}/logs
GET  /v1/sessions/{session_id}/agent-work
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
model server, agent service, eval job, shell task, provider action, archive, or
restore is not just UI process state once it has authority, cost, privacy,
replay, or receipt impact.

An agent service is an environment service with a stable service reference,
package/binary/container hash, start command, healthcheck, memory store, port
refs, log refs, work queue refs, and support-bundle policy. The service is
runtime posture. The durable work truth remains the WorkItem/WorkRun plus
Agentgres operations, receipts, artifacts, and review state.

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

### Work Projection And Legacy Mission Aliases

```http
GET  /v1/work
GET  /v1/work/{subject_kind}/{subject_id}
GET  /v1/projects/{project_id}/work
GET  /v1/hypervisor/autonomous-systems/{system_id}/work

GET  /v1/missions
GET  /v1/missions/{legacy_mission_id}
```

`/v1/work` is a policy-filtered read projection. Every row returns a canonical
`subject_kind` and `subject_ref` for exactly one `GoalRun`, `OutcomeRoom`,
`AutomationRun`, `Session`, `WorkQueue`, `WorkItem`, or `WorkRun`, plus only the status,
authority, cost, evidence, review, incident, and replay facets the caller may
see. The projection has no universal writable lifecycle and owns no runtime,
authority, budget, evidence, or receipt truth.

`Reviews` and `Incidents` are Work views over facet-bearing typed rows, not
additional `subject_kind` values. RuntimeAssignment is a placement facet. The
legacy Issues route resolves to the Incidents view while detail actions route
to the domain or owner application that owns the review or incident record.

Background, interactive, and supervisory are execution modes on Session,
WorkRun, RuntimeAssignment, or participant execution; they do not define a
Mission object. Reusable trigger, schedule, webhook, workflow, monitor,
approval-flow, and service behavior remains an `AutomationSpec`; one activation
is an `AutomationRun`; durable bounded pursuit is a `GoalRun`; shared pursuit is
an `OutcomeRoom`.

The two `/v1/missions` reads are migration aliases only. A legacy identifier
must resolve through an admitted alias/migration receipt to exactly one GoalRun
or OutcomeRoom and return that typed subject and its canonical URL. New Mission
writes, universal Mission updates, and Mission execution subresources are
non-conformant. Clients start, disable, review, or reconcile work through the
typed owner APIs. An ambiguous legacy record enters typed review and may not be
silently guessed.

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
  "run_id": "run://123",
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
  "risk_class": "system_destructive",
  "primitive_capabilities_required": ["prim:sys.exec", "prim:net.request"],
  "authority_scopes_required": ["scope:repo.write"],
  "policy_decision": {
    "status": "pending | allowed | denied | requires_approval | transform_required",
    "policy_hash": "sha256:..."
  },
  "receipt_obligations": ["policy_decision", "execution", "artifact_or_diff"],
  "run_id": "run://123",
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
GET  /v1/models/route-contracts
POST /v1/models/route-contracts
POST /v1/models/quote
POST /v1/models/mount
POST /v1/models/unmount
POST /v1/models/invoke
GET  /v1/models/invocations/{id}
```

The current session binding shim executes only active/available Ollama routes;
sealed BYOK and multi-transport execution remain unimplemented. Target model
calls resolve versioned commercial-rights/privacy contracts and `Auto`,
`Pinned`, or `Compare` policy before invocation. An aggregator such as
OpenRouter remains a replaceable adapter; fallback that changes provider/model
or posture is a semantic substitution with model-route/invocation receipt and
re-verification obligations. MoW `RoutingDecisionReceipt` remains reserved for
accountable worker routing.

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
optional TUI views, SDK, ADK, Developer Workspace, Workflow Compositor, Foundry
surfaces, other application surfaces, and Environments views.
Thread-scoped MCP routes are the canonical target protocol APIs. Current master
still mounts top-level `/v1/mcp`, `/v1/mcp/servers`, `/v1/mcp/tools`,
`/v1/mcp/resources`, and `/v1/mcp/prompts` routes. They are live
implementation drift/compatibility surfaces pending explicit classification or
retirement; their presence does not make them the canonical thread-scoped
contract.

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
GET  /v1/threads/{thread_id}/mcp/resources/search
GET  /v1/threads/{thread_id}/mcp/resources/{resource_id}
POST /v1/threads/{thread_id}/mcp/resources/{resource_id}/read
GET  /v1/threads/{thread_id}/mcp/prompts/search
GET  /v1/threads/{thread_id}/mcp/prompts/{prompt_id}
POST /v1/threads/{thread_id}/mcp/prompts/{prompt_id}/imports
POST /v1/threads/{thread_id}/mcp/elicitation-requests
POST /v1/threads/{thread_id}/mcp/elicitation-requests/{request_id}/responses
POST /v1/threads/{thread_id}/mcp/external-task-bindings
GET  /v1/threads/{thread_id}/mcp/external-task-bindings/{binding_id}
POST /v1/threads/{thread_id}/mcp/external-task-bindings/{binding_id}/cancel
GET  /v1/threads/{thread_id}/mcp/apps/search
GET  /v1/threads/{thread_id}/mcp/apps/{app_id}/descriptor
POST /v1/threads/{thread_id}/mcp/serve
```

MCP endpoints do not bypass runtime tool contracts, primitive capability
requirements, authority scopes, or receipts.

The route families normalize protocol objects before use:

```text
tools        -> RuntimeToolContract
resources    -> PolicyBoundDataView | ArtifactRef | MemoryProjection + ContextLease
prompts      -> tainted import input for SkillManifest | GoalRunProfile | invocation
elicitation  -> typed user-input request; wallet approval remains separate
tasks        -> opaque external handle bound to HarnessInvocation
Apps         -> sandboxed extension_application descriptor and surface
```

Every response returns the canonical backing ref, effective gateway-profile
revision, policy/lease posture, source protocol version, and normalization or
typed-unavailable decision. A prompt import never auto-installs a skill or
profile. A resource read never mints its own access. An elicitation response is
never authority approval. An MCP Task never supplies GoalRun, AutomationRun,
WorkRun, or receipt identity. An MCP App descriptor never authorizes direct
host or provider mutation.

Implementation status: the audited live slice remains tool-centric and has
protocol-version/session-assumption drift across transports. Resource, prompt,
elicitation, external-task, and App normalization routes above are target
contract. Until implemented, they fail typed-unavailable; clients must not use
the live top-level `/v1/mcp*` compatibility surfaces or private state to
simulate the missing thread-scoped semantics.

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

The target `POST` and `PATCH` durable record mutations require
`information_flow_parent_labels`; they may also supply
`information_flow_label_ref` and
`information_flow_derivation_kind = memory_import | summarization`. Immediately
before `persist_record`, the daemon hashes the actual planned payload, joins
every supplied parent plus any replayed prior record label, stores the derived
`information_flow_label`, and only then invokes storage. Missing or invalid
parents must fail closed without a write. Current master does not implement
this propagation seam for memory mutations. Delete, policy/event records,
portable export, and external memory connectors remain with their owning
contracts as well.

## Subagent API

Subagents are delegated work items under the same runtime substrate. They must
inherit thread/run authority posture, budget limits, output contracts,
cancellation behavior, and receipt requirements.

When a subagent participates in an OutcomeRoom, the spawn additionally carries
`outcome_room_ref`, `room_participant_lease_ref`, and usually
`work_claim_lease_ref`. The room owns join/sleep/wake/retire/quarantine and
frontier state; the subagent's GoalRun owns one bounded pursuit. A spawned
process is not automatically an independent participant or party.

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

Subagent list/result projections should expose current claim, lease expiry,
heartbeat or wake condition, spend, last contribution, blockers, evidence,
verification, and cancellation/quarantine posture. Clients must not reduce
background work to an opaque process count or token stream.

## Jobs, Usage, and Context Budget API

Jobs are daemon-visible long-running work units. Usage and context-budget
endpoints allow clients to render cost, token, context-pressure, and compaction
state without creating private accounting.

Usage projections may normalize managed work into Work Credits, but must retain
supplier/model/endpoint/price-schedule versions, billed usage classes, every
attempt/fallback/escalation, supplier-billed status, runtime/tool/storage cost,
external worker/verifier/service cost, fee basis, adjustment, and receipt refs.
The current flat OCU-per-model-receipt implementation is not supplier-invoice
reconciliation and must not be used to promise a fixed paid multi-model
allowance.

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

## Identity, Access, Secrets, and Metering API

The daemon-local deployment-governance plane. It identifies **who** is operating
this deployment and scopes org-surface access; it does NOT authorize
consequential crossings — those still require the authority provider that owns
the requested scope. wallet.network owns portable delegation and its designated
high-risk scopes; deployment-local or domain authority may own ordinary local
effects. Identity and roles are never machine authority. Passwords and inbound
tokens are hashed/sealed at rest (surfaced at most once); secret values are
sealed and never returned by a read; metering consumption is derived from
recorded receipts. Enforcement is fail-safe: `auto` mode authenticates when the
deployment is exposed (loopback stays open), with a one-time lockout bootstrap.
Canon:
[`../hypervisor/identity-access-and-metering.md`](../hypervisor/identity-access-and-metering.md).

Identity, sessions, and gated enforcement:

```http
POST   /v1/hypervisor/auth/login
POST   /v1/hypervisor/auth/logout
GET    /v1/hypervisor/auth/whoami
GET    /v1/hypervisor/auth/policy
PUT    /v1/hypervisor/auth/policy
GET    /v1/hypervisor/auth/bootstrap-status
POST   /v1/hypervisor/auth/bootstrap
GET    /v1/hypervisor/principals
POST   /v1/hypervisor/principals
DELETE /v1/hypervisor/principals/{principal_id}        # ?purge=true hard-removes; default soft-deactivates
POST   /v1/hypervisor/principals/{principal_id}/password
GET    /v1/hypervisor/principals/{principal_id}/lease-grants
POST   /v1/hypervisor/principals/{principal_id}/lease-grants
DELETE /v1/hypervisor/principals/{principal_id}/lease-grants/{connector_id}
```

Federated login (SSO/OIDC — id_token verified vs JWKS + nonce) and SCIM 2.0
provisioning (the SCIM bearer is hash-only at rest):

```http
GET    /v1/hypervisor/sso-configurations
POST   /v1/hypervisor/sso-configurations
DELETE /v1/hypervisor/sso-configurations/{sso_id}
POST   /v1/hypervisor/auth/oidc/start
POST   /v1/hypervisor/auth/oidc/callback
GET    /v1/hypervisor/scim-configurations
POST   /v1/hypervisor/scim-configurations
DELETE /v1/hypervisor/scim-configurations/{id}
GET    /scim/v2/ServiceProviderConfig
GET    /scim/v2/Users
POST   /scim/v2/Users
GET    /scim/v2/Users/{id}
PATCH  /scim/v2/Users/{id}
PUT    /scim/v2/Users/{id}
DELETE /scim/v2/Users/{id}
GET    /scim/v2/Groups
POST   /scim/v2/Groups
GET    /scim/v2/Groups/{id}
PATCH  /scim/v2/Groups/{id}
PUT    /scim/v2/Groups/{id}
DELETE /scim/v2/Groups/{id}
```

Invites, domain verification (DNS-TXT over DoH), and custom domain:

```http
GET    /v1/hypervisor/org-invite
POST   /v1/hypervisor/org-invite
POST   /v1/hypervisor/org-invite/accept
GET    /v1/hypervisor/domain-verifications
POST   /v1/hypervisor/domain-verifications
POST   /v1/hypervisor/domain-verifications/{id}/verify
DELETE /v1/hypervisor/domain-verifications/{id}
GET    /v1/hypervisor/custom-domain
PUT    /v1/hypervisor/custom-domain
```

Secrets (value sealed at rest; reads return metadata only) and inbound API
access tokens (hash-only; plaintext surfaced once):

```http
GET    /v1/hypervisor/secrets
POST   /v1/hypervisor/secrets
POST   /v1/hypervisor/secrets/{id}/value
DELETE /v1/hypervisor/secrets/{id}
GET    /v1/hypervisor/api-tokens
POST   /v1/hypervisor/api-tokens
DELETE /v1/hypervisor/api-tokens/{id}
```

Metering & cost (current OCU projections are derived from receipts; target Work
Credit billing requires invoice-grade route-attempt reconciliation plus
wallet-backed budget/explicit top-up or overage consent):

```http
GET    /v1/hypervisor/usage/consumption
GET    /v1/hypervisor/budget
PUT    /v1/hypervisor/budget
POST   /v1/hypervisor/budget/reconcile
```

## Autonomous-System Control APIs

Current master mounts the narrow M1.3 genesis-admission owner routes. The held
M1.4 cut adds a separate pre-activation sequence-zero materialization route;
neither crossing activates a System:

```http
POST /v1/hypervisor/autonomous-systems
GET  /v1/hypervisor/autonomous-systems?system_id={canonical_system_ref}
GET  /v1/hypervisor/autonomous-systems/{canonical_record_key}
POST /v1/hypervisor/autonomous-systems/{canonical_record_key}/sequence-zero-materialization
GET  /v1/hypervisor/autonomous-systems/{canonical_record_key}/sequence-zero-materialization
```

`POST /autonomous-systems` accepts the immutable package release, proposed
instantiation, and exact wallet approval grant. The daemon re-runs the pure
proposal compiler, derives the governing constitution authority and admission
effect, resolves the authority through wallet.network, durably prepares the
admission, statefully consumes the exact grant under
`scope:autonomous_system.genesis_admit`, and only then commits the immutable
record, portable receipt, and mandatory Agentgres evidence. Exact GETs
reconstruct and compare all local and Agentgres evidence before returning
`200`; one-sided, malformed, or mismatched proof fails closed. The result is
`authorized`, not active.

`POST /{canonical_record_key}/sequence-zero-materialization` accepts only the
expected M1.3 admission-record and admission-receipt roots plus an exact wallet
approval grant. The daemon re-verifies the immutable M1.3 local and Agentgres
evidence, derives every profile/component and sequence-zero root, resolves the
same governing authority under the distinct
`scope:autonomous_system.genesis_materialize` scope, durably prepares and
statefully consumes that grant, and admits the materialization, receipt,
component registry, and wallet-use evidence into four mandatory Agentgres
domains. The M1.3 aggregate is never mutated. The materialization retains the
M1.3 proposal's initial state/receipt roots only as named `proposed_initial_*`
trace fields; its operational roots are independently derived. A
content-addressed `deployment_profile_ref` ending in
`/revision/sha256:<hash>` binds that hash as `deployment_profile_root`.
Immutable master-era M1.3 records with an unversioned deployment ref instead
bind a domain-separated compatibility commitment to the exact admitted ref.
That compatibility form may materialize but does not claim captured profile
content and cannot authorize activation; a later governed transition must
supply a content-addressed revision. Exact GET reconstructs all evidence before
returning it.

The following wider bounded-System control routes remain target-only. They
expose constitution, deployment, observed membership, failover, lifecycle, and
optional IOI Network enrollment only after their owner contracts land:

```http
GET  /v1/hypervisor/autonomous-systems/{system_id}/topology
GET  /v1/hypervisor/autonomous-systems/{system_id}/constitution
POST /v1/hypervisor/autonomous-systems/{system_id}/upgrade-proposals

GET  /v1/hypervisor/autonomous-systems/{system_id}/node-memberships
POST /v1/hypervisor/autonomous-systems/{system_id}/node-memberships/propose
POST /v1/hypervisor/autonomous-systems/{system_id}/node-memberships/{membership_id}/transition
POST /v1/hypervisor/autonomous-systems/{system_id}/node-memberships/{membership_id}/catch-up
POST /v1/hypervisor/autonomous-systems/{system_id}/node-memberships/{membership_id}/verify-root

POST /v1/hypervisor/autonomous-systems/{system_id}/failover/evaluate
POST /v1/hypervisor/autonomous-systems/{system_id}/failover/restore
POST /v1/hypervisor/autonomous-systems/{system_id}/failover/promote
POST /v1/hypervisor/autonomous-systems/{system_id}/failover/profile-native-transition

POST /v1/hypervisor/autonomous-systems/{system_id}/lifecycle/transitions
POST /v1/hypervisor/autonomous-systems/{system_id}/network-enrollment/transitions
POST /v1/hypervisor/autonomous-systems/{system_id}/network-service-invocations
```

M1.4 derives the sequence-zero operation/transition/state/receipt commitments
from canonical admitted inputs; callers never author commitment truth. The
result is `materialized_pending_activation`, not an active profile. Active
profile admission and `initialize`/`activate` lifecycle transitions remain
distinct future crossings. Genesis, materialization, and activation receipts
remain distinct and bind their own exact release, constitution, profiles,
authority decision, roots, and transition commitment.

All mutation routes create typed proposals or lifecycle transitions; none
directly mutates a constitution, membership role, writer epoch, ordering rule,
oracle policy, successor, dissolution state, or enrollment. Local/domain
governance and the applicable authority provider authorize; the daemon admits,
enforces, executes, receipts, and fails closed; Agentgres records desired
profiles and observed state.

The topology projection distinguishes desired role counts from observed
memberships, readiness, catch-up offsets, verified roots, leases, writer epochs,
fencing, failure-domain evidence, RPO/RTO, partition/degraded posture, and
conformance receipts. `restore` is valid only when the active recovery mechanism
is `single_writer_restore`; `unavailable_fail_closed` exposes no recovery effect
until governance admits a profile change. `promote` is valid only when the
active mechanism is `single_writer_promotion` under `single_authority` or
`replicated_single_authority`; it requires an admitted hot standby, current
catch-up and root evidence, a higher writer epoch, and old-writer fencing.
Threshold, BFT, and external-finality systems use `profile-native-transition`
only when the mechanism is `ordering_profile_native`; the typed transition must
bind the active profile plus its
threshold, view/round, membership, or external-finality recovery proof and may
not synthesize a writer epoch. An ambiguous partition cannot be promoted or
reconfigured through either API. Node addition never widens system authority or
finality implicitly.

## Native Embodied Runtime APIs

These routes are the target public control and admission surface for native
Embodied Runtime. They are not present in the currently audited daemon registry.
The object and execution semantics are owned by
[`embodied-runtime.md`](./embodied-runtime.md); canonical wire contracts are
owned by
[`common-objects-and-envelopes.md`](../../foundations/common-objects-and-envelopes.md),
and physical authority and safety remain owned by
[`physical-action-safety.md`](../../foundations/physical-action-safety.md).

Definitions, compilation, and admission:

```http
GET  /v1/hypervisor/embodied/runtime-capabilities
POST /v1/hypervisor/embodied/runtime-graphs/compile
POST /v1/hypervisor/embodied/runtime-graphs/admit
GET  /v1/hypervisor/embodied/runtime-graphs/{manifest_id}
POST /v1/hypervisor/embodied/physical-stream-contracts/admit
POST /v1/hypervisor/embodied/embodiment-adapters/admit
POST /v1/hypervisor/embodied/action-policy-contracts/admit
POST /v1/hypervisor/embodied/resource-groups/admit
GET  /v1/hypervisor/embodied/resource-groups/{group_revision_id}/resolved-leaves
```

Compilation produces an inert candidate. Admission freezes one exact
`EmbodiedRuntimeGraphManifest`, transitive component and stream hashes,
`NativeEmbodiedRuntimeProfile` footprints, `EmbodiedRuntimeExecutionStratum`
placements, exact resource leaves, adapters, policies, and assurance
requirements. None of these endpoints grants authority, activates a graph,
arms a controller, or proves a physical state safe.

Transactional graph lifecycle and separate mission arming:

```http
POST /v1/hypervisor/embodied/graph-activations
GET  /v1/hypervisor/embodied/graph-activations/{activation_id}
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/prepare
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/validate
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/commit
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/abort
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/deactivate
POST /v1/hypervisor/embodied/graph-activations/{activation_id}/rollback
POST /v1/hypervisor/embodied/physical-mission-controls/{control_id}/arming-transitions
```

The activation routes operate one `EmbodiedGraphActivationTransaction` through
local prepare, validation, commit-or-abort, deactivation, and rollback. Commit
may reach only `active_unarmed`. Arming and disarming are separate typed
physical-mission transitions requiring current authority, safety, mission,
resource, world/sensor, lease, and supervisor admission; graph activation never
implies either transition. Multi-node coordination records local receipts and
fences but does not claim global physical atomicity.

Live local supervision and proposal-only action chunks:

```http
GET  /v1/hypervisor/embodied/local-control-supervisors
GET  /v1/hypervisor/embodied/local-control-supervisors/{supervisor_id}
POST /v1/hypervisor/embodied/local-control-supervisors/{supervisor_id}/lifecycle-transitions
POST /v1/hypervisor/embodied/action-chunks
GET  /v1/hypervisor/embodied/action-chunks/{action_chunk_id}
POST /v1/hypervisor/embodied/action-chunks/{action_chunk_id}/transitions
```

An `EmbodiedActionChunk` remains a finite, expiring,
`non_authoritative_proposal`. Its transition endpoint may record selection,
rejection, expiry, supersession, or safety-gated queue admission; it may not
directly execute the chunk or bypass the `LocalControlSupervisor`. Supervisor
lifecycle transitions cannot weaken its final local veto, exclusive actuator
writer fence, watchdog, recovery, or emergency behavior. There is deliberately
no generic raw-actuator-command endpoint.

Same-system fleet work, physical-space coordination, replay, and assurance:

```http
POST /v1/hypervisor/embodied/fleet-mission-allocations
GET  /v1/hypervisor/embodied/fleet-mission-allocations/{allocation_id}
POST /v1/hypervisor/embodied/fleet-mission-allocations/{allocation_id}/transitions
POST /v1/hypervisor/embodied/spacetime-reservations
GET  /v1/hypervisor/embodied/spacetime-reservations/{reservation_id}
POST /v1/hypervisor/embodied/spacetime-reservations/{reservation_id}/transitions
GET  /v1/hypervisor/embodied/telemetry-streams
GET  /v1/hypervisor/embodied/telemetry-streams/{stream_id}
POST /v1/hypervisor/embodied/physical-replay-bundles
GET  /v1/hypervisor/embodied/physical-replay-bundles/{replay_bundle_id}
POST /v1/hypervisor/assurance/evidence-bundles/{bundle_id}/embodied-deployment-case
GET  /v1/hypervisor/assurance/evidence-bundles/{bundle_id}/embodied-deployment-case
```

`FleetMissionAllocationLease` answers which unit owns which work;
`SpacetimeReservationLease` independently answers where and when an admitted
attempt may occupy shared physical space. Neither is actuator authority or a
safety decision. The assurance binding records one
`EmbodiedDeploymentAssuranceCase` inside its owning `AssuranceEvidenceBundle`;
it creates no second assurance registry, blanket certification, or arming
right. Same-system fleet and swarm work uses these native L0 contracts. AIIP is
reserved for independently governed system boundaries.

## OutcomeRoom, GoalRun, And Step-Resolution APIs

Goal-shaped work should not be coordinated by copying prompts between harnesses.
Two API scales compose:

```text
OutcomeRoom / CollaborativeWorkGraph
  dynamic participants, shared frontier, claim/resource leases, attempts,
  findings, verifier challenges, admission, contribution lineage, and replay

GoalRun / step-resolution broker behavior
  one bounded grounding, execution, verification, repair, course-correction,
  and completion loop for a goal or claimed frontier item
```

The currently audited live slice exposes only GoalRun create/list/get,
`start`, `reconcile`, and event projection. It admits
`parallel_implement_reconcile` with one deterministic conductor, at most two
implementers, and software-shaped `ImplementationResultPayload` results. The
local-agent pairing, room, dynamic-participation, generic-result, and remaining
fine-grained routes below are target contract; their presence here is not a
live-route claim.

Live audited GoalRun routes:

```http
POST /v1/hypervisor/goal-runs
GET  /v1/hypervisor/goal-runs
GET  /v1/hypervisor/goal-runs/{goal_ref}
POST /v1/hypervisor/goal-runs/{goal_ref}/start
POST /v1/hypervisor/goal-runs/{goal_ref}/reconcile
GET  /v1/hypervisor/goal-runs/{goal_ref}/events
```

Target pursuit-profile discovery and nonbinding validation routes:

```http
GET  /v1/hypervisor/goal-run-profiles
GET  /v1/hypervisor/goal-run-profiles/{profile_id}/revisions/{revision_id}
POST /v1/hypervisor/goal-run-profiles/{profile_id}/revisions/{revision_id}/validate
```

Studio and Packages own profile authoring, successor-revision release, and
registry lifecycle. These daemon routes discover an exact eligible revision,
or return a nonbinding validation/compatibility preview. They do not create a
resolution identity, mutate the released profile, grant authority, or reserve
components. `POST /goal-runs` atomically revalidates, resolves, admits, creates
the resolved-component and active-skill snapshots, emits the
`GoalRunProfileResolutionReceipt`, and creates the GoalRun so no preview can be
replayed across registry, policy, revocation, or availability drift.

The target `POST /v1/hypervisor/goal-runs` request supplies the exact immutable
profile and requested inputs; its admitted response binds the atomic resolution
explicitly:

```json
{
  "goal_run_profile_revision_ref": "goal-run-profile://.../revision/...",
  "goal_run_profile_content_hash": "sha256:...",
  "requested_override_set_ref": "artifact://... | null",
  "requested_override_set_hash": "sha256:... | null",
  "owner_ref": "user://... | org://... | project://... | system://...",
  "user_intent_ref": "intent://... | prompt://...",
  "constraint_refs": ["constraint://..."],
  "outcome_room_ref": "outcome-room://... | null",
  "room_participant_lease_ref": "participant-lease://... | null"
}
```

```json
{
  "goal_run_id": "goal://...",
  "goal_run_profile_revision_ref": "goal-run-profile://.../revision/...",
  "goal_run_profile_content_hash": "sha256:...",
  "admitted_override_set_ref": "artifact://... | null",
  "admitted_override_set_hash": "sha256:... | null",
  "effective_constraint_envelope_ref": "constraint://...",
  "effective_constraint_envelope_hash": "sha256:...",
  "resolved_component_set_snapshot_ref": "artifact://...",
  "resolved_component_set_hash": "sha256:...",
  "active_skill_set_snapshot_ref": "active-skill-set://...",
  "active_skill_set_hash": "sha256:...",
  "initial_role_topology_revision_ref": "role_topology://.../revision/... | null",
  "initial_role_topology_content_hash": "sha256:... | null",
  "goal_run_profile_resolution_receipt_ref": "receipt://...",
  "admission_status": "admitted",
  "run_status": "draft"
}
```

Every newly admitted GoalRun binds exactly one profile revision. Simple or
ad-hoc UX resolves the built-in generic-adaptive profile instead of creating a
profileless exception. A later profile edit cannot rewrite the run; adopting a
successor or different profile requires an explicit receipted migration or
fork. The audited live create route predates generalized profile resolution and
remains partial until it emits these fields.

Target local-agent pairing routes:

```http
POST /v1/hypervisor/local-agent-pairings
GET  /v1/hypervisor/local-agent-pairings/{pairing_ref}
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/claim
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/complete
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/cancel
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/revoke
```

`POST /v1/hypervisor/local-agent-pairings` is an authenticated operator action that creates a
short-lived `LocalAgentPairingSessionEnvelope` with target `room_guest`,
`private_worker`, or `organization_worker`. It returns the one-time plaintext
challenge/device code and generated bootstrap instruction exactly once; the
server persists only its commitment/hash and must not log or re-display the
secret. The envelope binds expiry, claim-attempt limit and count, pairing
transport, room or registry target, allowed bootstrap operations, and creator
principal.

`POST .../claim` proves possession of the challenge and binds the candidate
public key, observed origin, and harness/agent descriptor. It does not
mint a bearer credential with general API access. `POST .../complete` accepts
only the signed `WorkerComposition` draft/ref and/or
`RoomParticipationRequestEnvelope` allowed by the session target. Completion
does not admit the worker, create a `RoomParticipantLease`, grant context,
tools, authority, resources, or budget, expose room state, publish a
marketplace listing, establish reputation, or authorize payment. Those remain
separate owner decisions and leases.

The creator may inspect status, cancel an incomplete session, or revoke future
bootstrap use after a binding exists. Candidate polling, if a
deployment permits it, is possession-bound and returns only pairing lifecycle
state and the next allowed bootstrap action. Expired, replayed,
origin-mismatched, key-mismatched, attempt-exhausted, completed, or revoked
sessions fail closed. Rate limits apply by creator, origin, network posture,
and target. Lifecycle and admission evidence reuse the existing
authentication, policy-decision, and room-admission event/receipt owners rather
than inventing a pairing receipt that claims competence.

A prompt-only bootstrap is proposal-only and remains tainted. Pairing evidence
alone cannot raise its result above `attested`; any stronger assurance must
come from the admitted claim's evidence, isolation, verifier, acceptance,
adjudication, and settlement path. Pairing is pre-AIIP first-mile
authentication. After admission, cross-domain work uses AIIP and the same
scoped Hypervisor MCP/tool gateway and lease contracts as any other participant.

Target OutcomeRoom / CollaborativeWorkGraph routes:

```http
POST  /v1/hypervisor/outcome-rooms
GET   /v1/hypervisor/outcome-rooms
GET   /v1/hypervisor/outcome-rooms/{room_ref}
POST  /v1/hypervisor/outcome-rooms/{room_ref}/upgrade-proposals
POST  /v1/hypervisor/outcome-rooms/{room_ref}/lifecycle/transitions

POST /v1/hypervisor/outcome-rooms/{room_ref}/discovery
POST /v1/hypervisor/outcome-rooms/{room_ref}/discovery/pause
POST /v1/hypervisor/outcome-rooms/{room_ref}/discovery/withdraw
GET  /v1/hypervisor/outcome-room-discoveries
GET  /v1/hypervisor/outcome-room-discoveries/{discovery_ref}
POST /v1/hypervisor/outcome-room-discoveries/{discovery_ref}/participation-requests
GET  /v1/hypervisor/outcome-rooms/{room_ref}/participation-requests
POST /v1/hypervisor/outcome-rooms/{room_ref}/participation-requests/{request_ref}/decide

POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/join
GET  /v1/hypervisor/outcome-rooms/{room_ref}/participants
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/heartbeat
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/sleep
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/retire
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/quarantine
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports
GET  /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}/acknowledge
POST /v1/hypervisor/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}/revoke

POST /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget
GET  /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget
POST /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget/quote
POST /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget/reserve
POST /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget/adjust
POST /v1/hypervisor/outcome-rooms/{room_ref}/network-goal-budget/reconcile

POST /v1/hypervisor/outcome-rooms/{room_ref}/offers
GET  /v1/hypervisor/outcome-rooms/{room_ref}/offers
GET  /v1/hypervisor/outcome-rooms/{room_ref}/offers/{offer_ref}
POST /v1/hypervisor/outcome-rooms/{room_ref}/offers/{offer_ref}/allocate
POST /v1/hypervisor/outcome-rooms/{room_ref}/offers/{offer_ref}/withdraw
GET  /v1/hypervisor/outcome-rooms/{room_ref}/frontier
POST /v1/hypervisor/outcome-rooms/{room_ref}/frontier
POST /v1/hypervisor/outcome-rooms/{room_ref}/claims
POST /v1/hypervisor/outcome-rooms/{room_ref}/claims/{claim_ref}/renew
POST /v1/hypervisor/outcome-rooms/{room_ref}/claims/{claim_ref}/release
POST /v1/hypervisor/outcome-rooms/{room_ref}/claims/{claim_ref}/reassign

POST /v1/hypervisor/outcome-rooms/{room_ref}/attempts
POST /v1/hypervisor/outcome-rooms/{room_ref}/findings
POST /v1/hypervisor/outcome-rooms/{room_ref}/verifier-challenges
POST /v1/hypervisor/outcome-rooms/{room_ref}/admission-proposals
POST /v1/hypervisor/outcome-rooms/{room_ref}/admission-proposals/{proposal_ref}/decide
GET  /v1/hypervisor/outcome-rooms/{room_ref}/replay
```

`POST /outcome-rooms` is a package-to-genesis convenience over the autonomous-
system create path. It selects the reusable OutcomeRoom release and proposes one
new room `system_id`, constitution, active profile set, and cryptographic origin;
the room cannot become open/active until genesis and activation are admitted.
The hosted service/domain may operate many such room systems.

Room create/update routes never mint free-form mutable aggregates. Every
frontier item, offer, claim, attempt, finding, challenge, result, delta, lease,
budget transition, and state export compiles into a typed admission proposal
carrying schema/kind, exact participant lease or room-system issuer, expected
room revision and predecessor commitment, payload root, policy, and decision.
The admitted response returns the admission receipt, monotonic sequence,
resulting revision, transition commitment, state root, and receipt root. The
object-specific routes above are conveniences over this one
`RoomAdmittedObjectBase` transition contract, not bypasses around it.

Discovery list/query accepts policy-qualified filters such as
`category_ref`, `semantic_profile_ref`, `capability_ref`,
`eligibility_profile_ref`, `affiliation_posture`, `privacy_posture`, `region`,
`max_quote`, `verifier_profile_ref`, `settlement_posture`, and an opaque
`cursor`. It returns signed, versioned `OutcomeRoomDiscoveryEnvelope` objects
plus the next cursor. Eligibility filtering is advisory until the typed
participation admission decision; no query response grants access or authority.

Every room declares `hosted_admission` or `federated_admission` shared-state admission. Room APIs
carry refs and policy-bound projections; they do not imply a global mutable
Agentgres graph. Cross-domain participation binds
`MultiPartyCollaborationEnvelope` and AIIP sequencing while each participant
retains home-domain truth and private context.

Discovery routes expose only a versioned, policy-bound
`OutcomeRoomDiscoveryEnvelope`; they do not return private room state or grant
membership. Participation requests require a typed admission decision before a
lease exists. Retire/revoke releases or reassigns live claims, terminates future
access, and emits a policy-filtered `ParticipantStateBundleEnvelope` plus export
receipt. That bundle must remain usable without continued access to the hosted
room database.

`POST .../participants/join` is only a host-local or invitation convenience. It
must create or adopt a typed `RoomParticipationRequestEnvelope`, run the same
admission decision, and return the resulting lease/receipt refs; it may never
mint a participant lease as a bypass.

The Network/Open budget routes create or bind a separate
`NetworkGoalBudgetEnvelope`, price/quote eligible external work, reserve against
the declared cap, and reconcile allocation, contribution, dispute, refund, and
settlement refs. They may delegate procurement or settlement to marketplace or
service-order owners, but they may never draw silently from ordinary Goal Space
Work Credits.

Offer allocation composes the existing resource scheduler, quote/budget, queue,
preemption, fairness, custody/locality, and receipt paths. It admits a typed
`ResourceAllocationDecision`; the room route is not a second scheduler or an
unreceipted first-party allocation shortcut.

Target fine-grained GoalRun / broker routes:

```http
PATCH /v1/hypervisor/goal-runs/{goal_ref}
POST /v1/hypervisor/goal-runs/{goal_ref}/grounding-loop
POST /v1/hypervisor/goal-runs/{goal_ref}/context-cells
POST /v1/hypervisor/goal-runs/{goal_ref}/context-leases
POST /v1/hypervisor/goal-runs/{goal_ref}/handoffs
POST /v1/hypervisor/goal-runs/{goal_ref}/harness-invocations
GET  /v1/hypervisor/goal-runs/{goal_ref}/harness-invocations
GET  /v1/hypervisor/harness-invocations/{harness_invocation_id}
GET  /v1/hypervisor/harness-invocations/{harness_invocation_id}/events
POST /v1/hypervisor/goal-runs/{goal_ref}/verify
POST /v1/hypervisor/goal-runs/{goal_ref}/continue
POST /v1/hypervisor/goal-runs/{goal_ref}/close
```

An OutcomeRoom claim creates or binds a GoalRun with optional room,
participant, claim, attempt, and admission-policy refs. Context handoffs carry
`task_brief`, generic `work_result` / `outcome_delta`, `blocker`,
`decision_request`, `verification_result`, or `continuation_summary` packets.
`ImplementationResultPayload` is the software profile of `WorkResult`; files,
patches, diffs, and tests are not universal result fields.

The broker adapts a `TaskBriefPayload` to a selected HarnessProfile or Agent
Harness Adapter, records normalized HarnessAdapterEvents, returns a
`WorkResult` / `OutcomeDelta`, and applies a VerifierPath. Reconciliation uses
the normalized result, receipts, evidence, domain-profile fields, uncertainty,
and handoffs to choose repair, escalation, memory proposal, room-frontier
update, continuation, or completion.

Hard rules:

- harness adapters may render prompts, commands, terminal scripts, or
  provider-specific session input internally, but raw chat text is not the
  durable cross-harness contract;
- room participants cannot write shared frontier state directly; the declared
  hosted/federated admission policy orders and admits updates;
- participant/claim membership never widens context, authority, privacy,
  resource, or budget leases;
- participant messages, artifacts, mappings, findings, and evaluator changes
  remain untrusted until admitted;
- background workers expose participant/claim leases, heartbeat or wake
  condition, spend, blockers, evidence, verification, and control state.

## Bounded Improvement Campaign APIs

The routes in this section are target contract and are not present in the
currently audited daemon. The live improvement surface remains the narrower
proposal/simulation/apply path described by
[`improvement-governance-gates.md`](./improvement-governance-gates.md).

Ordinary one-shot changes may continue to submit a direct `UpgradeProposal`.
Only adaptive, repeated, sealed-evaluation, multi-epoch, or recursively claimed
work needs an `ImprovementCampaign`.

Target agenda and campaign routes:

```http
POST /v1/hypervisor/improvement-agendas
GET  /v1/hypervisor/improvement-agendas
GET  /v1/hypervisor/improvement-agendas/{agenda_ref}/revisions/{revision_ref}
POST /v1/hypervisor/improvement-agendas/{agenda_ref}/revisions/{revision_ref}/release

POST /v1/hypervisor/improvement-campaigns
GET  /v1/hypervisor/improvement-campaigns
GET  /v1/hypervisor/improvement-campaigns/{campaign_ref}
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/admit
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/start
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/pause
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/stop
GET  /v1/hypervisor/improvement-campaigns/{campaign_ref}/candidates
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/attempts
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/findings
```

Target evaluation and exposure routes:

```http
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/evaluation-epochs
GET  /v1/hypervisor/evaluation-epochs/{epoch_ref}
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/freeze
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/activate
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/challenge
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/close
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/invalidate
GET  /v1/hypervisor/evaluation-epochs/{epoch_ref}/exposure
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/exposure/reserve
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/exposure/spend
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/exposure/release
POST /v1/hypervisor/evaluation-epochs/{epoch_ref}/rotate
```

Target synchronization, claim, and promotion routes:

```http
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/order-cutoffs
GET  /v1/hypervisor/improvement-campaigns/{campaign_ref}/order-cutoffs
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/evidence-claims
GET  /v1/hypervisor/improvement-evidence-claims/{claim_ref}
POST /v1/hypervisor/improvement-evidence-claims/{claim_ref}/challenge
POST /v1/hypervisor/improvement-campaigns/{campaign_ref}/upgrade-proposals
```

Create and admit are separate. Campaign creation records a proposed immutable
contract revision; admission resolves the owner-scope improvement-governance
profile and, when System-scoped, the constitution, plus the mutable target,
protected exclusions, exact incumbent root, selected GoalRunProfile and
component closure, target path/order, active-depth ceiling, learning boundary,
evaluator-independence posture, and disjoint ancestor budget reservations. Only
admission may create the coordinating GoalRun or make the campaign runnable.

Epoch freeze commits the evaluator contract before confirmatory candidate
access. Exposure operations append entries against the frozen ledger head and
must use expected-head concurrency; changing candidate identity, spawning a
child, or raising claimed target order never restores spent exposure or
statistical-risk allowance. Challenge and invalidation append lifecycle records
and dependent-claim impact; they never mutate the frozen epoch body.

`POST .../order-cutoffs` emits an `ImprovementOrderCutoffReceipt`, not an
authority-bearing synchronization object. It accepts only eligible typed
evidence at one adjacent target-order edge, binds denied or quarantined classes,
and cannot include evidence produced by a successor activated in the same sync
wave. Promotion remains an `UpgradeProposal` evaluated by the target owner's
ordinary Governance and release API.

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
6. SDK, ADK, ODK, CLI/headless, optional TUI, GUI, Workflow Compositor, harness
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
11. Training, evaluation, benchmark, and MoW routing paths are daemon/runtime
    jobs with receipts, not product-surface private loops.
12. Authority Gateway adapters submit action requests and observations; they do
    not own policy, effects, secrets, receipts, replay, durable runtime state,
    or total control over opaque third-party agents.
13. Delegated agent work must use WorkQueue/WorkItem/WorkRun, Session,
    Thread/Turn, HarnessProfile, ModelConfiguration, wallet, Agentgres, and
    receipt contracts for long-running or background work; hidden
    service-local job state is not canonical run state.
14. Project, typed work, session, adapter, environment-ops, access-token,
    log-token, port, browser-open, and support-bundle APIs are daemon/Core
    lifecycle APIs; product clients and agent harnesses must not invent private
    lifecycle truth for them.
15. Runner reconciliation, LLM usage reporting, exec/security telemetry,
    subagent message routing, and conversation streaming are runtime contracts
    that must bind back to admitted work, state roots, and receipts.
16. Cross-harness goal work must flow through GoalRun, ContextHandoff,
    ContextLease, HarnessInvocation, HarnessAdapterEvent, generic
    WorkResult/OutcomeDelta, VerifierPath, and receipt contracts.
    `ImplementationResultPayload` is the software profile. Raw chat text may be
    adapter evidence, but it is not the durable conductor/worker interface.
17. OutcomeRoom/CollaborativeWorkGraph is the dynamic shared-frontier layer
    above bounded GoalRuns. It must not become a peer runtime or an implicitly
    global Agentgres graph.
18. Every room declares hosted or federated ordering/admission, and every
    cross-domain room binds MultiPartyCollaborationEnvelope plus AIIP refs.
19. Participant and work-claim leases bound context, authority, resources,
    budget, heartbeat, wake, release, reassignment, quarantine, and revocation;
    room membership never grants ambient power.
20. Background work must be observable through participant/claim state, spend,
    evidence, verification, blockers, replay, and controls.
21. Work Credit projections must reconcile to route attempts and supplier cost
    before paid allowance claims; flat OCU-per-receipt metering is not
    invoice-grade reconciliation.
22. Every newly admitted GoalRun freezes one exact GoalRunProfile revision,
    permitted overrides, resolved-component snapshot/hash, and profile-
    resolution receipt; an ad-hoc request uses the generic-adaptive profile.
23. MCP protocol objects normalize to canonical IOI tool, context, input,
    invocation, and extension-surface owners. Protocol sessions and task
    handles never replace run, authority, state-root, or receipt identity.
