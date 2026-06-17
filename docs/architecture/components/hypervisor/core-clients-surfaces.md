# Hypervisor Core, Clients, Application Surfaces, Sessions, and Adapters

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Core product taxonomy, first-class
client boundaries, application-surface boundaries, session boundaries, and
adapter-target doctrine.
Supersedes: live product prose that treats "Hypervisor IDE" as the parent
Hypervisor product, treats the Electron/VS Code shell as the product identity,
or treats editor integrations as runtime ownership.
Superseded by: none.
Last alignment pass: 2026-06-16.

## Canonical Definition

**Hypervisor is the shared governed autonomous-work substrate.**

Hypervisor is not one IDE, one editor fork, one GUI canvas, one terminal client,
or one cloud workspace. Hypervisor is the product/runtime substrate that lets
users and organizations operate governed sessions across local machines, remote
VMs, browsers, editors, terminals, hosted workers, HypervisorOS nodes, and
provider infrastructure.

Core product doctrine:

```text
One Core.
Many first-class clients.
Many application surfaces.
Every consequential action governed.
```

## Hypervisor Core

**Hypervisor Core** is the shared product/runtime substrate used by Hypervisor
clients and application surfaces.

It is not a new runtime beside the Hypervisor Daemon. The daemon remains the
execution owner inside Hypervisor Core. The Rust/WASM workload/kernel substrate
is the step/module execution backend under the daemon as implementation
converges.

Hypervisor Core includes or coordinates:

- session orchestration;
- daemon API boundary;
- Workflow Compositor graph projection and HarnessProfile selection/mediation
  path;
- model, worker, service, tool, connector, browser, terminal, and
  computer-use routing;
- adapter registry and adapter-target mediation;
- receipt and replay projections;
- local product projections;
- policy admission hooks;
- wallet.network authority gateway integration;
- Agentgres admission/projection bridge;
- cTEE / Private Workspace custody posture integration;
- provider integration and runtime assignment surfaces.

Hypervisor Core binds to, but does not own:

- **wallet.network** for authority, secrets, capability leases, approvals,
  declassification, spend, revocation, and step-up;
- **Agentgres** for admitted operational truth, state roots, artifact refs,
  archive/restore validity, receipt refs, and projections;
- **storage backends** for payload bytes;
- **AIIP** for bounded autonomous-work handoffs;
- **IOI L1 / compatible L1s** for selected public, economic, rights, dispute,
  registry, and cross-domain commitments.

Canonical shape:

```text
Hypervisor
  -> first-class clients
      Hypervisor App
      Hypervisor Web
      Hypervisor CLI / Headless Client
      SDK / ADK clients
  -> application surfaces
      Workbench
      Foundry
      Fleet
      Agents
      Models
      cTEE / Privacy
      Receipts / Audit
      Connectors
  -> Hypervisor Core
      shared substrate and stable contracts
  -> Hypervisor Daemon
      execution owner
  -> Workflow Compositor
      high-level directed workflow/service graph projection over Core
  -> Harness Profiles
      selected step-resolution adapters, including Default Harness Profile
  -> Rust/WASM workload/kernel substrate
      step/module execution backend
```

## First-Class Clients

First-class clients are the ways humans, teams, scripts, and programs operate
the same Hypervisor Core.

```text
Hypervisor App
  native desktop client over Hypervisor Core

Hypervisor Web
  browser/team/remote client over Hypervisor Core

Hypervisor CLI / Headless Client
  terminal, scripting, CI, node-ops, and headless operator client over
  Hypervisor Core; TUI is an optional presentation of this client, not a
  separate first-class client lane

SDK / ADK clients
  protocol clients and builder frameworks over daemon/domain contracts
```

First-class clients may render different interaction patterns, but they must
share the same authority, session, daemon, receipt, replay, Agentgres, wallet,
cTEE, and provider contracts.

They do not own runtime truth.

## Application Surfaces

Application surfaces are major product modes inside one or more first-class
clients.

```text
Hypervisor Workbench
  code, systems, workflow, workspace, editor, terminal, browser, and
  debugging surface

Hypervisor Foundry
  worker creation, training, evaluation, benchmarking, packaging, and
  improvement surface

Hypervisor Fleet
  infrastructure, provider, node, workspace, VM/container/microVM/WASM,
  GPU, storage, cTEE posture, cost, health, and migration surface
```

Other surfaces may include Agents, Services, Models, cTEE / Privacy,
Receipts / Audit, Connectors, and Settings.

Application surfaces are not separate apps with separate runtime truth. They
are governed projections and control surfaces over Hypervisor Core, the
Hypervisor Daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
integrations.

## Hypervisor Workbench

**Hypervisor Workbench** is the code/systems/workspace surface. It replaces
"Hypervisor IDE" as the live product term for the code-oriented Hypervisor
experience.

Workbench may appear in:

- Hypervisor App;
- Hypervisor Web;
- remote browser workspaces;
- VS Code-family adapters;
- Cursor, Windsurf, JetBrains, and other editor adapters;
- terminal/tmux-oriented operator views.

Workbench can open and operate sessions through many editors. The editor is an
adapter target, not the product identity.

## Workflow Compositor

**Workflow Compositor** is the high-level directed-work surface over Hypervisor
Core. It is a shared graph/projection model used by Workbench, Foundry, Fleet,
Agents, Services, and SDK/ADK clients when work needs explicit structure.

The compositor owns:

- service and workflow graph shape;
- typed step contracts;
- dependencies and handoff edges;
- acceptance criteria and review points;
- delivery contract and reusable templates;
- harness, model, worker, provider, and verifier selection hints;
- replay, receipt, authority, cTEE, and context-topology projections for the
  graph.

It does not own:

- execution semantics;
- wallet.network authority;
- Agentgres truth;
- model private reasoning;
- persistent workspace memory;
- Foundry training or distillation;
- the selected harness's internal loop.

For each executable step, the compositor selects or recommends a path such as:

```text
direct daemon-native tool
Rust/WASM service module
workload container job
model or inference mount
Private Workspace / cTEE action
verifier step
external AIIP/capability exit
selected HarnessProfile
```

The selected `HarnessProfile` resolves the scoped step. The Default Harness
Profile is the reference scaffold/fallback profile. External harnesses such as
Codex, Claude Code, Grok Build, OpenHands, Aider, DeepSeek TUI-like runtimes,
or Hermes-like runtimes may be mediated as harness profiles or agent harness
adapters when they produce the common boundary objects and obey daemon gates.

## Hypervisor Sessions

**Hypervisor Sessions** are live governed workspaces, runs, or control contexts
managed through Hypervisor Core.

Examples:

```text
local workspace session
remote VM workspace session
browser sandbox session
hosted worker-node session
persistent HypervisorOS node session
terminal session
editor session
computer-use session
Foundry / eval / training session
Fleet / provider management session
```

A session binds:

- user, org, project, or worker identity;
- authority grants and capability leases;
- policy and approval state;
- runtime assignment;
- context chamber / task refs where applicable;
- cTEE custody posture where applicable;
- Agentgres refs and receipt obligations;
- adapter targets;
- replay and restore metadata.

## Hypervisor Adapters And Targets

**Hypervisor Adapters** bridge sessions into external tools and environments.
They observe or submit proposed actions through available control points. They
do not become authority owners, secret owners, runtime truth, Agentgres, or the
daemon.

Adapter targets may include:

```text
VS Code / VS Code Insiders
Cursor
Windsurf
JetBrains IDEs
browser IDEs / Codespaces-like workspaces
Git / GitHub / GitLab
terminal / shell / tmux
browser automation
local apps and OS surfaces
cloud VMs and containers
HypervisorOS nodes
hosted worker nodes
```

## Agent Harness Adapters

Agent harness adapters are a special adapter family for existing CLI or hosted
agent harnesses.

Examples:

```text
Codex
Claude Code
Grok Build
OpenHands
Aider
Cursor/Windsurf agent loops
shell/tmux agent loops
CI agents
hosted coding agents
```

They are not Hypervisor clients and not runtime truth. They are guest harnesses
or adapter targets that submit proposed work through Hypervisor Core and the
Hypervisor Daemon.

Canonical flow:

```text
external agent harness
  -> Hypervisor Agent Harness Adapter
  -> ActionProposal / ToolIntent / CapabilityRequest
  -> Hypervisor Daemon gate
  -> wallet.network authority
  -> approved execution
  -> Agentgres receipts/replay
```

The product message is:

```text
Keep your agent harness.
Put consequential execution behind Hypervisor.
```

Implementation-facing selection contract:

```text
HypervisorHarnessSelectionOption
  selection_kind:
    harness_profile | agent_harness_adapter

Default Harness Profile
  selection_kind: harness_profile
  role: reference_scaffold_fallback
  model route: Hypervisor model mount by default
  runtime truth: daemon-runtime

AgentHarnessAdapterProfile
  selection_kind: agent_harness_adapter
  examples:
    Codex CLI
    Codex Desktop Linux
    Claude Code CLI
    Grok Build CLI
    DeepSeek TUI
    Aider CLI
    OpenHands
    shell/tmux agent
    generic CLI
  truth boundary:
    proposal_source_only
  required bindings:
    execution lane
    model route policy
    workspace mount policy
    authority scopes
    receipt policy
```

The New Session flow should expose the selected harness beside the selected
model route, privacy posture, authority scope, and receipt preview. External
harnesses must not silently fall back from a local/private model route to a
provider-trust model route; provider-trust or adapter-native routes are explicit
privacy posture states.

Every external harness run should produce a `HarnessAdapterReceipt` binding the
selection ref, execution lane, model route ref, workspace mount policy,
authority scope refs, privacy posture ref, Agentgres operation refs, and
artifact refs.

Adapter doctrine:

```text
Editor choice is a session preference.
Adapter targets resolve through connection profiles.
Adapter targets propose or project.
Hypervisor Core mediates.
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres records truth.
```

## Adapter Connection Profiles

An adapter target is the destination a user sees. An
`AdapterConnectionProfile` is the implementable contract that tells Hypervisor
how a session connects to that destination.

Examples:

```text
VS Code / Cursor / Windsurf
  SSH extension or local bridge profile

VS Code Browser / browser IDE
  embedded browser profile

JetBrains
  Toolbox/plugin or remote-development profile

Zed / generic editor
  manual SSH profile

terminal / tmux / shell
  terminal session profile
```

The profile declares connection mode, launch path, required local and remote
components, supported features, policy coverage, and known limitations. It is
the concrete mechanism behind the rule:

> **Editor choice is a session preference, not Hypervisor's product identity.**

## Agent Harness Environment Ops

Agent harness adapters need a stable environment-operations contract so
external agent harnesses can discover, create, inspect, execute in, and clean
up Hypervisor-governed sessions without scraping product UI.

Environment-ops contracts cover:

```text
project discovery
runtime/environment class discovery
create session from project or context URL
non-blocking create and readiness polling
structured command execution
SSH or shell access when explicitly allowed
logs and output capture
stop / archive / delete
cleanup obligations
receipt obligations
```

External harnesses may receive structured outputs and exit codes. They do not
get durable secrets, plaintext custody, or authority except through
wallet.network capability leases and receipts.

## Projects, Sessions, And Missions

`HypervisorProject`, `HypervisorSession`, and `HypervisorMission` are distinct.

```text
HypervisorProject
  stable project/workspace identity, repository/context roots, policy defaults,
  persistence defaults, adapter preferences, and Agentgres domain links

HypervisorSession
  live interactive or operator-facing workspace/run/control context

HypervisorMission
  background/manual/scheduled/webhook/event-triggered autonomous work that may
  run without an interactive editor or terminal attached
```

Missions are how Hypervisor represents background automations and long-running
outcome work. A mission may create sessions and runs, but it is not merely an
editor tab. It has trigger policy, review contract, authority requirements,
output contract, and receipt obligations.

## Access, Ports, Browser, Logs, And Support

Remote sessions need explicit operational policies because these surfaces can
leak protected information even when no file write occurs.

Canonical objects:

```text
SessionAccessToken
  short-lived access token for editor, SSH, browser, logs, or environment-ops
  access; issued under wallet.network authority and bound to session, audience,
  expiry, scopes, and revocation epoch

PortExposurePolicy
  declares which local/session ports may be opened, forwarded, shared,
  previewed, or exposed externally

BrowserOpenPolicy
  declares whether browser URLs can be auto-opened, proxied, externally shared,
  recorded, or blocked

SupportBundlePolicy
  declares what logs, traces, environment metadata, screenshots, redacted diffs,
  and diagnostic files may leave the session
```

These are not convenience details. They are part of the custody and authority
boundary. Log export, browser previews, port forwarding, screenshots, SSH
config, and support bundles must be policy-bound, redacted where required, and
receipted when they affect privacy, authority, dispute, or restore.

## Lifecycle

```text
operator opens Hypervisor App, Hypervisor Web, CLI, or headless client
  -> client requests or resumes a Hypervisor Session
  -> Hypervisor Core resolves surface, adapter target, policy, and runtime posture
  -> Workflow Compositor shapes directed work when needed
  -> selected HarnessProfile, service module, tool, model, or verifier resolves scoped steps
  -> Hypervisor Daemon evaluates proposed actions under policy and authority gates
  -> wallet.network authorizes scopes, spend, secrets, capability leases, or declassification
  -> adapter target, runtime node, tool, model, worker, or service performs approved work
  -> raw results normalize into observations
  -> receipts and Agentgres operations are emitted
  -> client/application surface displays replay, state, approvals, artifacts, and next actions
```

## Minimal Implementation Objects

```yaml
HypervisorClient:
  client_id: hypervisor_client:...
  client_kind:
    app | web | cli | headless | sdk | adk | embedded
  presentation_mode:
    gui | web | command_line | tui | script | ci | embedded
  user_ref: wallet://... | user://...
  org_ref: org://... | null
  core_endpoint_ref: hypervisor_core://...
  supported_surfaces:
    - workbench
    - foundry
    - fleet
  adapter_targets:
    - adapter_target:...

HypervisorSurface:
  surface_id: hypervisor_surface:...
  surface_kind:
    workbench | foundry | fleet | agents | services |
    models | ctee_privacy | receipts_audit | connectors
  client_ref: hypervisor_client:...
  session_refs:
    - hypervisor_session:...
  projection_refs:
    - agentgres://projection/...

HypervisorSession:
  session_id: hypervisor_session:...
  project_ref: project:... | null
  session_kind:
    local_workspace | remote_vm_workspace | browser_sandbox |
    hosted_worker | hypervisoros_node | terminal | editor |
    computer_use | foundry_eval_training | fleet_provider
  daemon_ref: daemon://...
  runtime_assignment_ref: runtime_assignment:... | null
  authority_refs:
    - grant://...
    - lease://...
  agentgres_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  adapter_targets:
    - adapter_target:...
  adapter_connection_profile_refs:
    - adapter_connection_profile:...
  workspace_persistence_profile_ref: workspace_persistence:... | null
  ctee_posture_ref: ctee_posture:... | null
  access_token_refs:
    - session_access_token:...
  port_exposure_policy_ref: policy://... | null
  browser_open_policy_ref: policy://... | null
  support_bundle_policy_ref: policy://... | null
  status:
    requested | active | waiting_for_approval | blocked |
    completed | archived | restore_available

AdapterTarget:
  target_id: adapter_target:...
  target_kind:
    vscode | cursor | windsurf | jetbrains | browser_ide |
    git | terminal | browser_automation | local_app |
    cloud_vm | container | hypervisoros_node | hosted_worker
  mediation_level:
    observe_only | propose_actions | gated_execution | managed_session
  connection_profile_refs:
    - adapter_connection_profile:...
  limits:
    - string

AdapterConnectionProfile:
  profile_id: adapter_connection_profile:...
  target_kind:
    vscode | vscode_browser | cursor | windsurf | jetbrains |
    zed | ssh_editor | terminal | browser_ide | local_bridge
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
  policy_coverage:
    organization_editor_policy: covered | partial | not_covered
    support_bundle_redaction_required: true
  known_limitations:
    - string

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
    timeout_policy_ref: policy://...
  cleanup_obligations:
    on_success: stop | archive | delete | keep
    on_failure: stop | archive | keep_for_debug
  receipt_obligations:
    - environment_created
    - command_executed
    - output_captured
    - environment_stopped_or_deleted

HypervisorProject:
  project_id: project:...
  owner_ref: wallet://... | org://...
  repository_refs:
    - repo://...
  context_roots:
    - artifact://... | workspace://...
  default_policy_refs:
    - policy://...
  default_workspace_persistence_profile_ref: workspace_persistence:... | null
  preferred_adapter_connection_profile_refs:
    - adapter_connection_profile:...
  agentgres_domain_ref: agentgres://domain/... | null

HypervisorMission:
  mission_id: mission:...
  mission_kind:
    manual | schedule | webhook | pull_request | issue_event |
    policy_event | service_outcome | marketplace_job
  interactive: false
  project_ref: project:...
  workflow_ref: workflow:...
  default_harness_profile_ref: dhp:...
  runtime_assignment_ref: runtime_assignment:... | null
  trigger_policy_ref: policy://...
  review_contract:
    required: true
    reviewer_refs:
      - wallet://... | org_role://...
  output_contract_ref: output_contract://...
  receipt_refs:
    - receipt://...
  status:
    enabled | disabled | running | waiting_for_review |
    completed | failed | archived

SessionAccessToken:
  token_id: session_access_token:...
  session_ref: hypervisor_session:...
  audience:
    editor | ssh | browser | logs | environment_ops | support
  scopes:
    - scope:...
  issued_by: wallet://... | daemon://...
  expires_at: timestamp
  revocation_epoch: integer
  receipt_ref: receipt://...
```

## Conformance Checks

- No Hypervisor client may write canonical run/session/task truth without the
  daemon and Agentgres admission path.
- No application surface may become a private runtime loop beside the
  Hypervisor Daemon.
- No adapter target may receive secrets, declassification authority, or
  payment authority except through wallet.network leases and receipts.
- Workbench, Foundry, and Fleet must share Core session, authority, receipt,
  replay, and projection contracts.
- Editor integrations must make mediation limits visible.
- Every editor, terminal, browser, VM, and harness target must resolve through
  an `AdapterConnectionProfile`; a string editor preference is not enough.
- Agent harness adapters must use daemon/Core environment-ops APIs for
  discovery, execution, logs, and cleanup rather than scraping Hypervisor UI or
  directly mutating workspaces.
- Background missions must be modeled as `HypervisorMission` objects with
  trigger policy, review contract, authority requirements, output contract, and
  receipts; they must not be hidden interactive sessions.
- Remote access, SSH, browser previews, logs, support bundles, and environment
  operations must use short-lived session access tokens bound to wallet.network
  authority and revocation epochs.
- Port forwarding, browser-open behavior, and support bundle export must be
  explicit policy objects when the session is remote, shared, private, or
  provider-hosted.
- Remote/private sessions must declare cTEE, TEE, provider-trust, or local-only
  posture before protected workspace state is mounted or projected.

## Anti-Patterns

Avoid:

```text
Hypervisor = VS Code fork
Hypervisor IDE = parent product
Hypervisor App owns Core
Hypervisor Web owns Core
CLI/headless owns a separate runtime loop
TUI = separate first-class client lane
external CLI agent harness = Hypervisor client
Codex/Claude Code/Grok Build = runtime truth
editor name string = adapter contract
support bundle = harmless log export
port preview = not a data boundary
SSH token = durable credential
background automation = hidden editor session
Workbench = runtime truth
Foundry = direct self-mutation path
Fleet = infrastructure runtime or authority owner
editor adapter = full execution boundary
adapter target = secret vault
Core = replacement for wallet.network
Core = replacement for Agentgres
Core = peer runtime beside the daemon
remote workspace = private workspace without cTEE/TEE/local-only posture
```

Correct:

```text
Hypervisor = shared autonomous-work substrate
Hypervisor Core = shared contracts and control substrate
Hypervisor Daemon = execution owner
App/Web/CLI-headless = first-class clients
TUI = optional CLI presentation
Workbench/Foundry/Fleet = application surfaces
Sessions = governed live workspaces/runs
Adapters = mediated bridges to targets
Agent harness adapters = mediated bridges for external agent harnesses
wallet.network = authority
Agentgres = admitted truth
```

## Related Canon

- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md)
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md)
- [`../daemon-runtime/api.md`](../daemon-runtime/api.md)
- [`fleet.md`](./fleet.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
- [`../../_meta/vocabulary.md`](../../_meta/vocabulary.md)
