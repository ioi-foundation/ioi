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
- Default Harness Profile execution path;
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

Adapter doctrine:

```text
Editor choice is a session preference.
Adapter targets propose or project.
Hypervisor Core mediates.
Hypervisor Daemon executes.
wallet.network authorizes.
Agentgres records truth.
```

## Lifecycle

```text
operator opens Hypervisor App, Hypervisor Web, CLI, or headless client
  -> client requests or resumes a Hypervisor Session
  -> Hypervisor Core resolves surface, adapter target, policy, and runtime posture
  -> Hypervisor Daemon evaluates proposed actions under Default Harness Profile or direct tool/module policy
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
  ctee_posture_ref: ctee_posture:... | null
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
  limits:
    - string
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
