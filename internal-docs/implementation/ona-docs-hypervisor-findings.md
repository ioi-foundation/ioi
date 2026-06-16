# Ona Docs Crawl Findings For Hypervisor Architecture

Status: internal implementation research note.
Created: 2026-06-16.
Scope: Ona documentation crawl for editor, external-agent, API, environment,
guardrail, lifecycle, and runner patterns that may improve Hypervisor's
Core/client/surface/adapter architecture.

## Question

Could Ona's public docs reveal better ways to specify how Hypervisor should
handle multiple VS Code-family editors, other IDEs, external agent harnesses,
CLI/headless operation, persistent workspaces, background agents, and governed
runtime infrastructure?

Short answer:

```text
Our current Hypervisor Core/client/surface/adapter taxonomy is directionally
right.

The main missing layer is not a different product taxonomy. It is a more
implementation-grade adapter/session contract:

  adapter connection profiles
  external harness environment ops
  background mission/automation profiles
  workspace persistence and retention profiles
  lower-than-agent enforcement posture
  support/log/redaction/export contracts
```

## Sources Crawled

Primary entry points:

- <https://ona.com/docs/ona/getting-started>
- <https://ona.com/docs/api-reference>
- <https://ona.com/docs/llms.txt>

Relevant subpages:

- <https://ona.com/docs/ona/editors/overview>
- <https://ona.com/docs/ona/editors/vscode>
- <https://ona.com/docs/ona/editors/vscode-browser>
- <https://ona.com/docs/ona/editors/cursor>
- <https://ona.com/docs/ona/editors/windsurf>
- <https://ona.com/docs/ona/editors/jetbrains>
- <https://ona.com/docs/ona/editors/zed>
- <https://ona.com/docs/ona/environments/agent-environments>
- <https://ona.com/docs/ona/environments/persistent-storage>
- <https://ona.com/docs/ona/environments/archive-auto-delete>
- <https://ona.com/docs/ona/agents/overview>
- <https://ona.com/docs/ona/agents/codex>
- <https://ona.com/docs/ona/automations/overview>
- <https://ona.com/docs/ona/guardrails/overview>
- <https://ona.com/docs/ona/guardrails/veto>
- <https://ona.com/docs/ona/guardrails/datawall>
- <https://ona.com/docs/ona/understanding/core-components>
- <https://ona.com/docs/ona/understanding/architecture>

Local docs compared:

- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/components/hypervisor/fleet.md`
- `internal-docs/implementation/refine-architecture.md`
- `internal-docs/implementation/runtime-package-boundaries.md`
- `internal-docs/implementation/runtime-module-map.md`

## Executive Read

Ona's docs are useful because they are less abstract and more operational. They
make five things explicit:

1. Editors are not product identity. They are connection profiles into a
   governed environment.
2. External agents are not first-class product clients. They are CLI/API users
   that create, inspect, exec, SSH into, and clean up environments.
3. Background agents/automations are different from interactive sessions.
4. Guardrails need below-agent enforcement, not only policy prose.
5. Environment lifecycle is a first-class product/API concept: persistent
   storage, rebuild semantics, archive, unarchive, deletion, budgets, and
   policies.

That resonates strongly with the current Hypervisor direction. The architecture
should keep the cleaner taxonomy we just canonized:

```text
Hypervisor Core
  shared substrate and stable contracts

Hypervisor App / Hypervisor Web / CLI-headless
  first-class clients

Workbench / Foundry / Fleet / Agents / Models / cTEE / Receipts
  application surfaces

VS Code / Cursor / Windsurf / JetBrains / Zed / browser IDE / terminal / VM
  adapter targets

Codex / Claude Code / Grok Build / OpenHands / Aider / CI agents
  Agent Harness Adapters
```

But the current docs are still slightly underspecified at the implementation
edge. We define what the categories are; Ona shows the operational subcontracts
each category needs.

## Findings

### 1. Add `AdapterConnectionProfile`

Ona's editor docs are not just a list of supported editors. They classify each
editor by connection mode and capability:

- VS Code, Cursor, and Windsurf use the same extension over SSH.
- VS Code Browser is a browser mode with no local install.
- JetBrains uses Toolbox plus a plugin and supports prebuild warmup.
- Zed and other SSH-capable editors use manual SSH setup through the CLI.
- Browser handling, port forwarding, rebuilds, policies, and support logs vary
  by editor family.

Our docs correctly say editors are adapter targets, not product identity. What
is missing is the implementation-grade profile for how a target connects and
what surfaces are available.

Recommended object:

```yaml
AdapterConnectionProfile:
  profile_id: adapter_connection_profile:...
  target_kind:
    vscode | vscode_browser | cursor | windsurf | jetbrains |
    zed | ssh_editor | terminal | browser_ide
  connection_mode:
    ssh_extension | browser_embedded | toolbox_plugin |
    manual_ssh | environment_ops_api | local_bridge
  launch_mode:
    one_click | uri_scheme | browser_tab | cli_generated_ssh |
    embedded_surface | manual
  required_local_components:
    - string
  required_remote_components:
    - string
  supports:
    rebuild: true
    port_forwarding: true
    browser_url_handling: true
    automation_controls: true
    log_export: true
    prebuild_warmup: false
  devcontainer_customization_keys:
    - customizations.vscode.extensions
    - customizations.jetbrains.plugins
  policy_coverage:
    organization_editor_policy: covered | partial | not_covered
    support_bundle_redaction_required: true
  known_limitations:
    - string
```

Canon implication:

- Keep `AdapterTarget` as the high-level category.
- Add `AdapterConnectionProfile` as the implementable connection contract.
- Make "editor choice is a session preference" concrete: the session resolves
  an adapter profile, not just an editor string.

### 2. Add external harness environment-ops contracts

Ona's "Using environments from external agents" page gives a complete lifecycle
for Claude Code, Cursor, and custom scripts:

```text
discover projects
discover environment classes
create environment from project or URL
create non-blocking and poll readiness
execute commands through EnvironmentOps API
use JSON output for agents
SSH when interactive shell is needed
stop or delete environment
```

This maps almost perfectly to our `AgentHarnessAdapter`, but our current docs
stop at "proposal in, daemon gate, wallet authority, Agentgres receipts out."
That is correct but not enough to implement the adapter.

Recommended object:

```yaml
AgentHarnessEnvironmentOpsProfile:
  profile_id: agent_harness_env_ops:...
  harness_kind:
    codex | claude_code | grok_build | openhands | aider |
    cursor_agent | windsurf_agent | shell_agent | ci_agent | custom
  discovery:
    projects: list | search | fixed
    runtime_classes: list | policy_filtered | fixed
  environment_lifecycle:
    create_from_project: true
    create_from_context_url: true
    non_blocking_create: true
    readiness_poll: true
    stop: true
    archive: optional
    delete: true
  command_execution:
    mode:
      environment_ops_api | ssh | shell_wrapper | mcp_gateway
    structured_output:
      json | yaml | text
    exit_code_passthrough: true
    timeout_policy_ref: policy:...
  cleanup_obligations:
    on_success: stop | archive | delete | keep
    on_failure: stop | archive | keep_for_debug
  receipt_obligations:
    - environment_created
    - command_executed
    - output_captured
    - environment_stopped_or_deleted
```

Canon implication:

- `AgentHarnessAdapter` should own "how existing agents operate Hypervisor
  sessions" through a stable environment-ops profile.
- External harnesses should get structured output and exit-code semantics; they
  should not scrape UI.

### 3. Split interactive sessions from background missions/automations

Ona distinguishes interactive environments from background automations. An
automation is triggered manually, on a schedule, by PR events, or by webhooks;
it runs a closed-loop workflow and produces reviewable outputs. Ona also notes
that automation environments are isolated execution contexts rather than
interactive environments.

Our docs have `HypervisorSession`, Default Harness Profile loops, workflows,
and Fleet, but we do not yet have a crisp "background mission" object that is
separate from an interactive Workbench session.

Recommended object:

```yaml
HypervisorMission:
  mission_id: mission:...
  mission_kind:
    manual | schedule | webhook | pull_request | issue_event |
    policy_event | service_outcome | marketplace_job
  interactive:
    false
  project_ref: project:...
  workflow_ref: workflow:...
  default_harness_profile_ref: dhp:...
  runtime_assignment_ref: runtime_assignment:...
  trigger_policy_ref: policy:...
  review_contract:
    output_refs:
      - artifact://...
    required_receipts:
      - receipt://...
    human_review_required: true
  status:
    enabled | disabled | queued | running | blocked |
    completed | failed | archived
```

Canon implication:

- `HypervisorSession` should remain the broad live context.
- `HypervisorMission` should describe non-interactive, background, triggerable
  autonomous work.
- Workbench can show missions, but missions should not be modeled as editor
  tabs.

### 4. Sharpen the coordination plane vs execution plane

Ona's architecture page separates management plane from runners:

- management plane coordinates auth, orgs, guardrails, runner coordination,
  dashboard, and API;
- runners handle code access, secrets, agent execution, build/test, and
  environment provisioning.

We have the pieces:

```text
console.ioi.ai / Hypervisor Web / product clients
  coordination and projections

Hypervisor Daemon / HypervisorOS / runtime nodes
  execution

wallet.network
  authority

Agentgres
  admitted truth
```

But implementation docs could benefit from a formal `PlaneDataFlow` table,
especially for sensitive code/secrets/private workspace state.

Recommended addition:

```text
Coordination surfaces may know:
  identity refs, policy refs, session refs, status, receipt summaries,
  redacted logs, billing/cost, approval state.

Execution nodes may touch:
  source checkout, workspace bytes, secrets released under lease,
  model/tool execution, test/build commands, local logs.

Agentgres admits:
  operations, refs, receipts, state roots, artifact meaning.

Storage backends hold:
  encrypted payload bytes and archives.
```

Canon implication:

- Add a "Plane Data Flow" subsection to Hypervisor/Fleet/Daemon docs.
- Make "management/control surface does not custody plaintext workspace" an
  explicit conformance hook, especially for Hypervisor Web and console.ioi.ai.

### 5. Add below-harness enforcement posture

Ona's Veto docs are direct: enforcement above the agent can be observed and
circumvented; Veto moves enforcement below userspace as an LSM. Its Datawall
plan fingerprints confidential material and compares outbound traffic, then
emits structured events.

We already have stronger architectural ideas in cTEE and daemon gating, but for
ordinary non-cTEE coding sessions and external agent harnesses we are still a
little underspecified about enforcement layers beneath the harness.

Recommended object:

```yaml
NodeEnforcementProfile:
  profile_id: node_enforcement:...
  runtime_node_ref: runtime_node:...
  enforcement_layers:
    - daemon_gate
    - sandbox
    - seccomp
    - ebpf
    - lsm
    - network_proxy
    - ctee
    - hardware_tee
  executable_policy:
    deny_by_path: false
    deny_by_hash: true
    rename_resistant: true
  egress_policy:
    allowlist_ref: policy:...
    dlp_fingerprint_sets:
      - fingerprint_set:...
    tls_visibility_model:
      none | metadata | endpoint | plaintext_at_proxy | kernel_fingerprint
  event_receipts:
    - ExecutableDeniedReceipt
    - EgressDetectionReceipt
    - DataLeakageIncidentReceipt
```

Canon implication:

- Do not overclaim. We should not say Hypervisor magically makes every editor
  or CLI agent safe.
- Do say that a serious HypervisorOS/provider node can expose an enforcement
  posture below the external harness and receipt detections/blocks.
- Connect this to cTEE: cTEE prevents protected plaintext custody; enforcement
  posture constrains ordinary plaintext/public/redacted workloads and detects
  violations.

### 6. Add workspace persistence and retention profiles

Ona's environment docs define what persists across stop/start, what survives a
Dev Container rebuild, what prebuild snapshots do, and how archive/auto-delete
works. Deletion is irreversible; archived environments can be restored; org
policy can override user preferences.

We have persistent workspaces and managed instance lifecycle concepts, but
Hypervisor sessions need a specific persistence contract.

Recommended object:

```yaml
WorkspacePersistenceProfile:
  profile_id: workspace_persistence:...
  session_ref: hypervisor_session:...
  stop_start_persistence:
    repo_checkout: persists
    home_dir: persists | reset
    generated_artifacts: persists | artifact_ref_only
    system_packages: image_defined | persists
  rebuild_semantics:
    image_derived_paths: reset
    workspace_paths: bind_mounted
    private_workspace_paths: sealed_or_guardian_projected
  prebuild_snapshot:
    enabled: true
    includes:
      - dependencies
      - built_artifacts
      - indexes
    excludes:
      - secrets
      - private_plaintext
  retention:
    stopped_to_archived_after: duration
    archived_to_delete_after: duration | never
    policy_override_ref: policy:...
  restore:
    requires_agentgres_restore_receipt: true
```

Canon implication:

- Hypervisor sessions and aiagent managed instances should share retention
  grammar.
- cTEE private workspaces need separate treatment for sealed/private paths.
- "Archive" should mean state refs remain restoreable under Agentgres authority;
  "delete" should have explicit irreversible semantics.

### 7. Add prebuild, warm pool, and index warmup profiles

Ona makes prebuilds and JetBrains warmup product-visible. That matters because
startup time determines whether agents can fan out across many tasks.

We already talk about Fleet, provider placement, runtime nodes, and caches, but
we have not named the performance artifact objects clearly.

Recommended object:

```yaml
EnvironmentWarmupProfile:
  profile_id: warmup:...
  project_ref: project:...
  runtime_class_ref: runtime_class:...
  prebuild_ref: prebuild:...
  warm_pool_ref: warm_pool:... | null
  warmed_assets:
    - devcontainer_image
    - dependency_cache
    - language_server_index
    - jetbrains_backend
    - model_cache
    - test_fixture_cache
  invalidation_refs:
    - file:.devcontainer/devcontainer.json
    - file:package-lock.json
    - policy:...
  receipts:
    - PrebuildReceipt
    - WarmPoolReceipt
```

Canon implication:

- Fleet should manage warm pools and prebuilds as infrastructure posture, not
  just node inventory.
- Workbench should surface why a session is cold, warm, or stale.

### 8. Add `HypervisorProject` as an implementation anchor

Ona's project is a useful anchor: repository URL, devcontainer, environment
class, secrets, automations, and policies. Hypervisor has projects in spirit,
but the current Hypervisor Core docs jump from clients/sessions/adapters into
runtime assignment without a crisp project bundle.

Recommended object:

```yaml
HypervisorProject:
  project_id: project:...
  repo_refs:
    - git://...
  workspace_policy_ref: policy:...
  runtime_class_defaults:
    - runtime_class:...
  adapter_connection_profiles:
    - adapter_connection_profile:...
  agent_harness_profiles:
    - agent_harness_env_ops:...
  devcontainer_refs:
    - artifact://...
  mission_refs:
    - mission:...
  secret_policy_refs:
    - policy:...
  agentgres_domain_ref: agentgres://domain/...
```

Canon implication:

- `HypervisorProject` should become the unit that ties Workbench, missions,
  Fleet placement, secrets, adapter preferences, and Agentgres projections.
- This would reduce ambiguity between "workspace", "session", "repo", and
  "project".

### 9. Add short-lived access/log token semantics

Ona's API reference lists environment access tokens, log tokens, runner tokens,
host authentication tokens, and identity token exchange. That is a good reminder
that our adapter/session model needs short-lived tokens that are not raw wallet
authority.

Recommended object:

```yaml
SessionAccessToken:
  token_id: session_token:...
  session_ref: hypervisor_session:...
  token_kind:
    environment_access | log_stream | editor_open | ssh |
    support_bundle | runner_registration | host_auth
  issued_to:
    client_ref: hypervisor_client:... | adapter_target:...
  authority_ref: grant://...
  expires_at: timestamp
  scopes:
    - scope:...
  redaction_policy_ref: policy:...
  receipt_ref: receipt://...
```

Canon implication:

- wallet.network remains authority, but adapter clients should receive
  short-lived operational tokens, not durable secrets.
- Log tokens and support bundles need explicit redaction policies.

### 10. Add port/browser/log/support-bundle policy

Ona's editor docs include port forwarding, browser URL handling, trace logging,
log export, and a warning that logs may contain sensitive information. This is
easy to overlook, but it matters for agentic workspaces because browser previews
and support bundles can leak state.

Recommended objects:

```yaml
PortExposurePolicy:
  allowed_bind_hosts:
    - localhost
  public_share_allowed: false
  requires_step_up_for_public_url: true
  receipt_required: true

BrowserOpenPolicy:
  local_browser_forwarding: allowed
  remote_browser_forwarding: policy_gated
  auto_open_urls:
    allowed | prompt | denied

SupportBundlePolicy:
  export_allowed: true
  redaction_required: true
  secret_scan_required: true
  user_confirmation_required: true
  receipt_required: true
```

Canon implication:

- Adapter docs should not stop at "browser automation" and "port forwarding."
- Every preview/share/log export pathway is an authority/data boundary.

## API Implications

Ona's API reference is organized around service families that map cleanly to
Hypervisor:

```text
Agent executions
Workflow executions / actions / outputs
Editors list / resolve URL / retrieve
Environments create / token / logs token / start / stop / unarchive
Environment automation services / tasks / executions
Events list / watch
Runners / runner configuration / environment classes
Secrets / identity / org policies
Prebuilds / warm pools
```

Recommended Hypervisor API additions or clarifications:

```http
POST /v1/adapter-targets/list
POST /v1/adapter-targets/resolve-open-url
POST /v1/adapter-targets/connection-profile

POST /v1/sessions/create-from-project
POST /v1/sessions/create-from-context-url
POST /v1/sessions/access-token
POST /v1/sessions/log-token
POST /v1/sessions/exec
POST /v1/sessions/ssh-config
POST /v1/sessions/archive
POST /v1/sessions/unarchive
POST /v1/sessions/delete

POST /v1/missions/create
POST /v1/missions/start
POST /v1/missions/disable
POST /v1/missions/executions/list
POST /v1/missions/executions/actions/list
POST /v1/missions/executions/outputs/list

POST /v1/enforcement/events/watch
POST /v1/enforcement/profiles/get

POST /v1/prebuilds/create
POST /v1/warm-pools/create
POST /v1/warm-pools/update
```

These should be daemon/Core APIs with wallet-issued authority and Agentgres
receipt linkage, not UI-owned behavior.

## Current Alignment Score

| Area | Current IOI/Hypervisor alignment | Notes |
| --- | --- | --- |
| Product taxonomy | Strong | New Core/client/surface/adapter split is right. |
| VS Code-family editors | Good conceptually, underspecified operationally | Need `AdapterConnectionProfile`. |
| JetBrains/Zed/non-VS Code editors | Partially specified | Need connection modes, policy coverage, and warmup differences. |
| External CLI/hosted agents | Good doctrine, partial implementation contract | Need environment-ops profile and structured output/cleanup obligations. |
| Background automations | Partial | Need `HypervisorMission` separate from interactive sessions. |
| Management/execution plane split | Good but could be clearer | Add data-flow and custody table. |
| Guardrails below agents | Strong philosophy, incomplete implementation posture | Add `NodeEnforcementProfile` and event receipts. |
| Workspace persistence/retention | Partial | Need `WorkspacePersistenceProfile`, archive/delete semantics. |
| Prebuilds/warm pools | Under-specified | Important for large-scale agent UX and cost. |
| Short-lived operational tokens | Under-specified | Needed for editor open, logs, SSH, support bundles, runners. |
| Ports/browser/log exports | Under-specified | Treat as authority/data boundaries. |

## Recommended Patch Order

1. Extend `docs/architecture/components/hypervisor/core-clients-surfaces.md`
   with `AdapterConnectionProfile`, `AgentHarnessEnvironmentOpsProfile`, and
   `HypervisorMission`.
2. Extend `docs/architecture/components/daemon-runtime/api.md` with adapter
   open/resolve, session exec, log token, access token, archive/unarchive, and
   mission execution families.
3. Extend `docs/architecture/components/hypervisor/fleet.md` with prebuild,
   warm pool, workspace persistence, and direct provider placement details.
4. Extend `docs/architecture/components/daemon-runtime/hypervisoros.md` or add
   a new enforcement doc for `NodeEnforcementProfile`, blocked executable
   receipts, and egress-detection receipts.
5. Extend `docs/architecture/_meta/vocabulary.md`,
   `docs/architecture/_meta/source-of-truth-map.md`, and
   `docs/architecture/_meta/implementation-matrix.md` with the new terms.

## Anti-Patterns To Add

```text
editor adapter = same feature surface across every editor
VS Code extension = universal adapter contract
Cursor/Windsurf AI loop = Hypervisor runtime truth
external agent CLI = trusted client
EnvironmentOps command = bypasses daemon authority
automation = interactive session
archive = backup without Agentgres restore authority
delete = reversible archive
log export = harmless support action
port forwarding = purely local convenience
prebuild cache = canonical workspace state
kernel guardrail = cTEE privacy guarantee
```

## Bottom Line

Ona reinforces the architecture we are converging toward:

```text
One governed substrate.
Many editor/client surfaces.
External agents as guests/adapters.
Execution happens in governed environments.
Lifecycle, logs, ports, tokens, and guardrails are first-class contracts.
```

The main change I would make is to move from category doctrine to operational
profiles. Hypervisor already says the right thing at the top. The next docs/API
level should make each adapter, harness, mission, workspace, token, and
enforcement posture concrete enough that a developer can implement it without
rediscovering the edge cases.
