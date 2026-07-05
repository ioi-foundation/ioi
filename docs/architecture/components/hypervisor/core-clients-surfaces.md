# Hypervisor Core, Clients, Application Surfaces, Sessions, and Adapters

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Core product taxonomy, first-class
client boundaries, application-surface boundaries, session boundaries, and
adapter-target doctrine.
Supersedes: live product prose that treats one editor shell as the parent
Hypervisor product, treats Electron/VS Code hosting as the product identity, or
treats editor integrations as runtime ownership.
Superseded by: none.
Last alignment pass: 2026-06-23.
Doctrine status: canonical
Implementation status: partial (product shell, sessions, automations, and estate surfaces live; several application surfaces roadmap)
Implementation refs:
  - `apps/hypervisor/`
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-05

## Canonical Definition

**Hypervisor is the governed autonomy substrate where work becomes reusable
capability.**

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
Work becomes reusable capability when evidence, authority, evaluation, and
promotion justify it.
```

Product IA doctrine:

```text
Home starts or resumes work.
Projects organize persistent software/system work.
Automations own durable workflows, pipelines, APIs, and services.
Applications expose specialized vertical and platform surfaces.
Sessions show live and historical execution.
Hypervisor Core governs the runtime/control boundary underneath.
```

Product boundary doctrine:

```text
ioi.ai asks and coordinates goals.
Hypervisor runs governed autonomous work.
Automations make durable workflows and services.
ioi.ai coordinates multi-model and multi-path pursuit when a goal calls for it.
Foundry builds models, workers, evals, datasets, ontology-bound packages,
and deployment candidates.
Workbench develops, debugs, and operates systems.
Canvas visually edits automations; it is not runtime truth.
```

Product direction doctrine:

```text
Hypervisor is the open autonomy control plane and operating environment for
autonomous systems.

It lets people and organizations build, run, govern, observe, and improve
autonomous work across local machines, cloud providers, enterprise
infrastructure, cTEE/private workspaces, DePIN compute, model providers,
workers, tools, and domain applications without surrendering runtime truth,
authority, or capability supply to one vendor.
```

## Hypervisor Lineage And Operator Entry Contract

Hypervisor must not merely borrow the word "hypervisor" metaphorically. It must
be a real substrate-control product that also virtualizes autonomy. The Type 3
autonomy layer is the differentiator, but it is strongest when it can govern the
Type 1 and Type 2 substrate beneath autonomous work.

Hypervisor supports three substrate modes as deployment and control postures of
one product:

```text
Type 1 substrate mode:
  HypervisorOS / appliance / cluster control for machines, GPUs, storage,
  networks, VMs, containers, microVMs, sandboxes, local models, robotics
  runtimes, devices, and trusted execution.

Type 2 substrate mode:
  Hypervisor Desktop / Workstation hosted on a normal OS for local VMs,
  sandboxes, models, tools, agents, connectors, projects, environments, and
  developer/operator workflows.

Type 3 autonomy mode:
  Autonomy virtualization across sessions, WorkRuns, workers, harnesses, model
  routes, tools, authority, receipts, replay, outcomes, and promotion.

Hypervisor virtualizes autonomy, but it also governs the substrate autonomy runs
on.
```

The product should preserve the interaction grammar infrastructure operators and
desktop virtualization users already expect:

```text
Substrate
  what hosts, providers, runtimes, GPUs, endpoints, devices, and capacity exist?

Inventory
  what environments, sessions, workers, routes, packages, connectors, and
  endpoints exist, who owns them, and what state are they in?

Create / Import
  how do I create, clone, import, restore, or template an environment, worker,
  route, package, provider recipe, ODK blueprint, or embodied package?

Console
  what is running right now, what is it doing, how do I interrupt, repair,
  hand off, inspect artifacts, or open the live workspace?

Operations
  what is healthy, saturated, blocked, failed, queued, degraded, over budget,
  migrating, falling back, or awaiting remediation?

Governance / Ledger
  who is allowed to do what, which approvals are pending, what changed, why did
  it happen, can it be replayed, restored, rolled back, promoted, or audited?
```

These are required product capabilities, not permanent rail items. They resolve
through the existing shell and catalog:

| Operator expectation | Hypervisor home |
| --- | --- |
| Substrate overview | Operations, Environments, HypervisorOS/provider detail, Hypervisor Desktop / Workstation |
| Inventory | Applications catalog, Operations tables, Environments, Sessions |
| Create / import wizard | Home, New Session, Projects, Environments, Developer & Integrations, ODK |
| Live console / machine window | Workbench, Sessions, Run Timeline, Open Application |
| Snapshots / checkpoints / restore | Work Ledger, Workbench, Environments |
| Networks / storage / devices | Environments, Developer & Integrations, Governance, HypervisorOS, Robot Fleets / Embodied |
| Tasks / events / logs / alerts | Operations and Work Ledger |
| RBAC / policy / audit / lifecycle | Governance, Work Ledger, Operations |

Do not hide these behind only AI-native language such as model routes, agent
harnesses, or conductor loops. Product surfaces may reinterpret the controlled
object upward from VM to environment/session/worker/route/run, but the visible
controls must still feel like infrastructure control: table-first inventories,
create/import wizards, detail pages, live consoles, health/alert panels,
tasks/events, checkpoints, and policy/audit views.

The stable product truth is:

```text
Type 1 and Type 2 are the trustable substrate.
Type 3 is the autonomy virtualization layer above them.
Hypervisor includes all three without becoming merely another VM manager.
```

## Product Language Layers

Hypervisor product surfaces should present subsystem capabilities as familiar
user controls first. The architecture may name subsystem owners, but ordinary
product copy should not make users think they must understand every internal
plane before they can do useful work.

Use three vocabulary layers:

| Layer | Audience | Preferred terms |
| --- | --- | --- |
| Product | users and buyers | agents, jobs, projects, sessions, permissions, connected apps, delivery channels, evidence, receipts, run history, payments, revoke |
| Admin / builder | operators, org admins, builders | policies, scopes, work ledger, evals, worker packages, runtime profiles, data recipes, ontology kits, surface descriptors, integration surfaces, authority clients |
| Protocol / architecture | implementers, auditors, protocol integrators | wallet.network, Agentgres, Hypervisor Daemon, authority grants, Agentgres operations, ContributionReceipts, IOI L1 commitments |

Default product wording should be outcome-shaped:

```text
discover agent
-> hire / install
-> configure access
-> choose delivery channels
-> run / schedule
-> review evidence
-> pay / renew / revoke
```

The underlying architecture still binds those steps to authority providers,
daemon admission, Agentgres truth, receipts, marketplace attribution, and
settlement where applicable. Those subsystem names belong in advanced details,
audit exports, developer views, proof drilldowns, and protocol docs.

Term map for product surfaces:

| Protocol / owner term | Product-facing default |
| --- | --- |
| wallet.network | SSO, permissions, connected access, authority, recovery, powered-by label in advanced contexts |
| Agentgres | Work Ledger, evidence, run history, receipts, state/history |
| Hypervisor Daemon | secure runtime, execution environment, worker runtime |
| IOI L1 / mainnet | proof network, settlement, public commitment |
| aiagent.xyz | agent marketplace, worker marketplace, agent supply |
| ContributionReceipt | contribution record, payout evidence, attribution |

Users should not be bounced between domains to grant ordinary access. Hypervisor
and aiagent.xyz should embed the permission and connector flows; wallet.network
may appear as the powered-by authority provider for advanced security,
recovery, portable authority, CLI/MCP/SDK clients, audit export, cross-app
account governance, and high-assurance step-up.

The product should make the full autonomous-system lifecycle legible without
turning lifecycle categories into default navigation:

```text
Build
Run
Govern
Observe
Improve
```

Package, publish, trade, and marketplace flows are downstream paths for
reusable capability. They should be available from Foundry, Marketplace,
Projects, Automations, Sessions, or aiagent.xyz handoffs when useful, not forced
into every task.

Conceptual split:

```text
Work
  live governed activity: sessions, WorkRuns, tasks, connector actions, code
  changes, workflow steps, service deliveries, research paths, training runs

Capability
  reusable autonomous capacity: workers, automations, model routes, data
  recipes, evals, tools, packages, service modules, conductor advisors,
  marketplace listings
```

## Hypervisor Core

**Hypervisor Core** is the shared runtime/control substrate used by Hypervisor
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
- delegated agent-work queues, work items, work runs, review states, and
  conversation/transcript/log projections;
- model, worker, service, tool, connector, browser, terminal, and
  computer-use routing;
- adapter registry and adapter-target mediation;
- Hypervisor MCP Gateway profile mediation for external agents and harnesses;
- Ontology Development Kit descriptor mediation for ontology-aware generated
  surfaces, domain apps, eval packs, worker plans, and surface conformance;
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
      SDK / ADK / ODK clients
  -> default shell
      Home
      Projects
      Automations
      Applications
      Sessions
  -> application surfaces
      Workbench
      Agent Studio
      Foundry
      ODK
      Domain Apps
      Developer & Integrations
      Governance
      Operations
      Work Ledger
      Environments
      Marketplace
      Robot Fleets / Embodied
  -> session, project, and contextual views
      Services / Tasks / Ports / Logs / Restore
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

SDK / ADK / ODK clients
  protocol clients and builder frameworks over daemon/domain contracts
```

First-class clients may render different interaction patterns, but they must
share the same authority, session, daemon, receipt, replay, Agentgres, wallet,
cTEE, provider, and ontology/domain-contract contracts.

They do not own runtime truth.

### Protocol Gateways

Protocol gateways are compatibility ingress points over Hypervisor Core. They
are not separate first-class clients, separate runtimes, or ambient authority
lanes.

The primary protocol gateway is the **Hypervisor MCP Gateway**:

```text
Hypervisor MCP Gateway
  authority-scoped MCP profiles for external agents, local harnesses, CI agents,
  marketplace workers, and enterprise agents to discover, preview, propose, or
  execute selected Hypervisor capabilities
```

The gateway should expose selected capabilities from Applications, Projects,
Sessions, Automations, Foundry, Developer & Integrations, Work Ledger, and the
Hypervisor Operator Plane through declared profiles. It must compile every
tool or action to RuntimeToolContract, surface MCP contract, or operator-plane
contract refs, then route effectful work through daemon admission,
wallet.network authority, Agentgres, receipts, and replay.

Gateway profiles are bound to wallet.network authority clients, origin bindings,
grants, leases, policy refs, and admitted dependency refs. If a bound authority
client or profile becomes expired, revoked, suspicious, or quarantined,
Hypervisor must fail closed for effectful calls, return a scoped failure
explanation to the external agent, and propagate quarantine to dependent
sessions, WorkRuns, connector calls, and pending approvals through Agentgres and
receipts. The gateway is never a durable API key or master MCP.

Correct:

```text
external agent -> Hypervisor MCP Gateway profile -> declared tool/surface
contract -> daemon/wallet/Agentgres/receipt boundary
```

Avoid:

```text
Hypervisor MCP Gateway = master key
Hypervisor MCP Gateway = direct provider credential broker
Hypervisor MCP Gateway = host/platform mutation bypass
Hypervisor MCP Gateway = runtime beside Hypervisor Core
```

## Top-Level Product IA

The default Hypervisor shell should stay small enough that new users can tell
where work lives:

```text
+ New Session

Home
Projects
Automations
Applications
Sessions

Open Application
  optional singular shell slot for the currently open application
```

This is a product-navigation doctrine, not a new ownership graph. The durable
owners remain the daemon, wallet.network, Agentgres, storage backends, AIIP, and
IOI L1 as defined by their canonical docs.

Use these product meanings:

```text
Home
  default command surface for starting, resuming, approving, or inspecting work

Projects
  persistent software/system work containers with repos, files, environments,
  development environment recipes, adapter preferences, policy defaults, linked
  automations, and receipts

Automations
  durable workflow/service/API/trigger/approval-flow objects

Applications
  catalog, search, launcher, and management surface for specialized surfaces
  over Hypervisor Core

Sessions
  live and historical governed execution contexts
```

Avoid turning platform primitives into permanent top-level nav. Agents, Workers,
Models, Connectors, MCP servers, Ontology, Policies, Receipts, Monitoring,
Foundry, Marketplace, and similar surfaces should live in the Applications
catalog and may appear as the singular Open Application while active. Favorites,
recommended apps, promoted apps, recent apps, and organization shortcuts are
catalog affordances and user/org preferences, not canonical shell categories.
The architecture must not require every user to manage the full primitive list
in the default shell.

The Applications catalog is query-first. A client may render it as a modal,
command palette, full page, or embedded picker, but it must support search,
filtering, recent/favorite/recommended entries, and context-aware launch paths
without expanding the permanent rail. A visible empty `Pinned Applications`
region is not canonical; pinned/favorite/promoted entries are catalog, Home, or
project/session affordances. `Open Application` remains a singular active
surface slot when a specialized surface is selected.

The Applications catalog may include these first-party product surfaces. The
left-hand labels are the preferred product names; parenthetical phrases
preserve older architectural family names where those still help cross-reference
contracts:

```text
Workbench
Environments
Agent Studio (Agents / Workers, memory profiles, harness projections)
Foundry
ODK (Ontology, Data / Knowledge, Blueprints, Surface Generate)
Domain Apps (generated domain apps, Analyst/query lens)
Developer & Integrations (Connections, Connectors / Tools / MCP, APIs, SDKs, ADK)
Governance (Authority / Govern, privacy, policy, approvals, release/change controls)
Operations (Operate / Monitoring, jobs, incidents, resource posture)
Work Ledger (Receipts / Replay, artifacts, lineage, proof)
Marketplace
Robot Fleets / Embodied (roadmap)
```

## Context, Integrations, And Memory Placement

Connectors, skills, memory, MCP servers, model routes, policies, receipts,
providers, evals, and similar primitives are not permanent shell rail items.
They appear through the Applications catalog, the singular Open Application
slot, and scoped context panels where the user is configuring a concrete piece
of work.

The primary product venue for the full integration estate is
Developer & Integrations:

```text
Developer & Integrations
  connectors and connected apps
  MCP servers and surface MCPs
  provider accounts and BYOK/BYOA
  APIs, SDKs, ADK, webhooks, service accounts
  conformance and developer app registration
```

User and organization settings expose only scoped slices of that estate:

```text
User settings
  personal connected apps
  personal memory and skill preferences
  delivery/contact channels
  personal BYOK/BYOA defaults

Organization settings
  organization connectors and service accounts
  connector allowlists and provider policies
  SSO/OIDC, retention, audit, export, shared-memory policy
  workspace defaults and administrative enrollment
```

Contextual surfaces expose the same primitives where they are actually used:

```text
New Session
  agent, model, harness, tools, memory, privacy, budget, authority

Agent Studio
  worker tools, skills, memory profile, model/harness, endpoint/package posture

Projects
  project memory, project connectors, environment recipes, policy defaults

Automations
  workflow/service triggers, connector steps, approval requirements, delivery

Managed agent console
  instance connectors, schedules, contact channels, memory posture, updates
```

Durable workflows remain Automations. Personal shortcuts, reusable snippets, or
templates may appear inside Skills, Launch Policies, Developer & Integrations,
or contextual setup panels when they serve the current task, but Hypervisor
should not add a generic Workflows child tab. Scheduled services, workflow graph
truth, approval flows, delivery paths, and Automation records belong to the
top-level Automations surface.

Do not copy reference-product tab taxonomies as Hypervisor product structure.
Hypervisor has a top-level Automations surface for durable triggers, schedules,
service graphs, approvals, delivery, and background missions. Agent Studio, New
Session, Projects, and Developer & Integrations may project automation
readiness, connector availability, skills, memory posture, and launch policies
where they are used, but they must not cannibalize Automations as a child tab or
rename durable Automations into generic workflows.

Agent Wiki / `ioi-memory` is the durable memory substrate. Harness-local
"brains," scratchpads, summaries, embeddings, and vendor memory features are
adapters or projections over admitted memory. They do not own portable user,
project, org, worker, or managed-instance knowledge.

The compact doctrine:

```text
Ask in ioi.ai.
Start or resume work from Home.
Build software in Projects.
Build workflows in Automations.
Open specialized tools in Applications.
Track execution in Sessions.
Run consequential work through Hypervisor Core, the daemon, wallet.network,
Agentgres, and receipt/replay boundaries.
```

## Lifecycle Lens

The product-management lifecycle is:

```text
Build
  Projects, Workbench, Automations, Canvas, SDK/ADK/ODK,
  Developer & Integrations, ODK, Foundry, Marketplace facets

Run
  Sessions, daemon runtime, providers, environments, HypervisorOS, cTEE,
  code execution, computer use, worker/model/tool routing, memory, restore

Govern
  wallet.network, authority scopes, capability leases, approvals, secrets,
  policy gates, privacy, declassification, risk, semantic governance,
  registries

Observe
  receipts, replay, traces, logs, lineage, state roots, evaluations,
  executable eval worlds, simulations, online monitors, quality alerts, work
  analytics, tool analytics, feedback, examples

Improve
  Foundry, evals, benchmarks, worker/model promotion, data recipes,
  distilled ontology datasets, cost/work ledgers, feedback annotations,
  rollout outcomes, routing improvements

Package / Market
  Autonomous System Packages, worker manifests, templates, patterns,
  marketplace installs, aiagent.xyz, sas.xyz outcomes, IOI settlement triggers
```

The first five verbs are the stable mental model. Package / Market is a
downstream path for reusable capability and should be available when capability
is ready to publish, install, sell, settle, or attribute. Do not expose this
planning taxonomy as primary navigation unless product testing proves the stable
shell is insufficient.

## Capability Lifecycle Control

Hypervisor should make reusable capability lifecycle legible without creating a
generic top-level `Lifecycle` product family. Lifecycle control is a
cross-surface projection over shared Core contracts.

The durable product shape is:

```text
Governance release/change facet
  primary cockpit for capability promotion, release, rollout, pause,
  rollback, recall, kill-switch, remote-config, release-target, gate,
  cohort, and deployment-risk coordination

Owning application surfaces
  local lifecycle evidence and work state, with lifecycle strips, blocked
  reasons, authority gates, run/job refs, dependency impact, receipts, replay,
  proof refs, and deep links back to Governance, Operations, or Work Ledger
```

Release/change controls are a Governance facet. They may appear as an Open
Application view, change-plane panel, org/admin view, Foundry handoff,
Automations handoff, or contextual detail drawer. They should not become a
permanent shell rail item or separate peer product by default.

Local ownership stays explicit:

```text
Environments
  environment create/start/readiness/idle/archive/restore/delete,
  provider placement, ports, services, tasks, logs, restore posture

Operations
  queued/running/failed/retried jobs, builds, retries, and execution status

Operations resource facet
  queues, quotas, rate limits, capacity, utilization, spend, and budgets

Foundry
  dataset, eval, build, training, artifact conversion, registration, and
  promotion-candidate lifecycle

Agent Studio
  agent/harness/tool/memory-profile/memory-projection/authority/eval-readiness
  and worker/package candidacy

Automations
  trigger, workflow, service, API, schedule, catch-up, and run lifecycle

Marketplace / Work Ledger
  install, publish, package, artifact, recall evidence, contribution, and
  settlement handoffs

Governance / Operations
  human approval, policy review, remediation, incident, and support gates

Work Ledger / ODK
  dependency, provenance, and impact graph

Work Ledger
  transition trace, receipt, proof, settlement, and replay inspection
```

Every serious capability detail page should expose a small lifecycle strip and
detail drawer appropriate to its object kind. Common fields include owner
surface, current version, target version, active release target, rollout
policy, rollback policy, recall policy, authority refs, approval gates,
dependency impact, resource pressure, job/run refs, incident refs, receipt refs,
replay refs, proof refs, and operator/MCP contracts.

The lifecycle projection is not a new truth store. Agentgres admits truth,
wallet.network authorizes, the Hypervisor Daemon executes, Foundry builds and
evaluates, Marketplace/aiagent/MoW attributes external supply when applicable,
and Work Ledger inspects evidence.

## Application Surfaces

Application surfaces are major product modes inside one or more first-class
clients.

```text
Hypervisor Workbench
  code, systems, workflow, workspace, editor, terminal, browser, and
  debugging surface, including development environment recipes and lifecycle
  observations where they help users start, inspect, restore, or tear down work

Hypervisor Automations
  durable workflow, trigger, schedule, API/service, approval-flow, and
  background-mission surface, including durable missions created from ioi.ai
  collaborative outcome handoffs

Hypervisor Foundry
  model catalog, registry, model routes/mounts, tuning, persistent training
  pipelines, dataset factory runs, experiment optimization, artifact
  conversion, evaluation, executable eval worlds, interactive worlds,
  gameplay trajectory datasets, scenario curricula, world-model candidates,
  spatial-temporal policy candidates, transfer gates, tool-call audits,
  trajectory scorecards, datasets, endpoints, monitoring, worker/package
  creation, certification-run candidates, and ontology-aware improvement surface

Hypervisor Canvas
  visual builder/editor inside Automations, Workbench, or Foundry where useful;
  not a separate product plane or runtime owner
```

Other surfaces may include specialized agent/worker consoles, model consoles,
service/API consoles, domain-operation consoles, organization admin views, and
settings panes. Work analytics, tool analytics, feedback/annotation, release
control, run replay, and data-recipe views may also appear as catalog entries or
sub-surfaces when they help a user inspect, improve, roll out, or govern work.
These should still resolve through the Applications catalog, the singular Open
Application slot, session/project detail, or contextual panels instead of
becoming new default top-level shell categories.

User-facing configuration should prefer simple labels:

```text
Agent      configurable worker-backed agent or adapter
Mode       Agent | Plan | Goal
Model      product-facing model choice
Reasoning  Low | Medium | High | Extra high
Speed      Standard | Fast
Harness    advanced execution topology, hidden unless relevant
```

`Agent` is the buildable product object. `Worker` remains the durable protocol
actor/package boundary. `Model` is the product-facing label; `ModelRoute`
remains the internal runtime object for provider, custody, fallback, spend,
privacy, eligibility, and invocation policy. `Harness` is the visible
power-user label for selected `HarnessProfile` or adapter topology; it should
not be exposed as "execution profile" in ordinary composer controls.

Application surfaces are not separate apps with separate runtime truth. They
are governed projections and control surfaces over Hypervisor Core, the
Hypervisor Daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
integrations.

Provider and infrastructure posture is part of Hypervisor's default session,
project, provider, and environment views.

## Hypervisor New Session

`+ New Session` launches governed work. It is not generic chat and not a
private UI state transition.

A New Session request should bind:

```text
intent
project or application context
work execution mode: foreground session | one-off background handoff |
                     durable automation | background mission
worker/model/tool route
provider and environment profile
authority scope
privacy posture
expected receipt shape
replay/eval posture
handoff destination
review and delivery contract
```

Hypervisor Core admits the request through daemon, wallet.network, Agentgres,
privacy, provider, and receipt boundaries before consequential work begins.

A New Session may atomically bind project/environment recipe, selected agent,
initial input, mode, model configuration, reasoning effort, speed/service tier,
harness selection, tools/connectors, memory policy, authority, budget, eval,
and receipt posture. That bundle is a daemon-admitted launch recipe, not a
client-local chat setting.

## Hypervisor Home

**Hypervisor Home** is the default command and resume surface.

Implementation status: live first slice — owned serve surface `/__ioi/home`
(`renderHome` in `apps/hypervisor/scripts/serve-product-ui.mjs`) renders four
read-only strips over live daemon projections (pending approval requests;
runs blocked at a wallet gate incl. `awaiting_authority_*` failover runs;
resume sessions/running work; newest Work Ledger proof), each with an honest
empty state and a named daemon-unreachable degraded state; reachable from the
Applications launcher modal without a pinned rail item. Goal-prompt drafting
is not built yet.

Home may accept goal prompts, show recent sessions, surface waiting approvals,
and route the user into a Project, Automation, Application, Session, receipt, or
replay. Home is allowed to draft work, but it must not become the durable owner
of automations, projects, or sessions.

Home should stay a low-friction command and resume surface. Dense panes for
code, diffs, comments, terminals, ports, tasks, logs, or environment controls
belong in active Project, Workbench, Session, or Open Application contexts where
the user has selected the work scope.

Correct:

```text
Home starts or resumes governed work.
Home can ask Hypervisor Core to create a New Session.
Home can draft an Automation or Foundry job for review.
```

Avoid:

```text
Home = durable automation owner
Home = ioi.ai chat replacement
Home = default deploy-as-service funnel
```

## Hypervisor Projects

**Hypervisor Projects** are persistent software/system work containers.

A Project may bind repositories, files, branches, packages, assets,
environments, adapter preferences, linked automations, sessions, policies,
secrets scopes, artifacts, receipts, and Agentgres domain links. Workbench is
the IDE-grade code/systems mode inside or attached to a Project; the Project is
the durable object.

Project-owned product state is still admitted through the canonical owners:
daemon/Core for execution semantics, wallet.network for authority and secret
release, Agentgres for operational truth and restore validity, and storage
backends for bytes.

Correct:

```text
Open the Project.
Use Workbench or an editor adapter to inspect and change it.
Resume the Project's governed Sessions.
```

Avoid:

```text
Project = editor folder with no Agentgres identity
Workbench = parent product
editor adapter = project truth
```

## Hypervisor Applications

**Hypervisor Applications** is the catalog, launcher, and vertical surface layer
inside Hypervisor.

An Application is a specialized UI/work surface over Hypervisor Core that
creates, inspects, modifies, or governs Projects, Automations, Sessions,
Agents, Workers, Models, Environments, ODK descriptors, Domain Apps,
Developer & Integrations, Governance, Operations, Work Ledger, Marketplace, or
other domain objects. Older family labels such as `Providers / Environments`,
`Connections`, `Connectors / Tools / MCP`, `Data / Knowledge`, `Ontology`,
`Workshop`, `Domain Blueprints`, `Authority / Govern`, `Release Controls`,
`Resource Management`, `Operations Center`, `Learning Center`, and
`Receipts / Replay` remain aliases or facets for those product surfaces.

Applications may be first-party, organization-built, ODK-generated,
marketplace, or vertical-specific. They are product surfaces, not separate
runtimes or authority owners.

Examples:

```text
Workbench
Environments
Agent Studio
Foundry
ODK
Domain Apps
Developer & Integrations
Governance
Operations
Work Ledger
Marketplace
Robot Fleets / Embodied
```

Applications may contain or manage Automations, Projects, or Sessions, but they
do not replace those durable object classes.

Applications is also the product breadth layer for installable or generated
surfaces. Repeated work should be promoted from private sessions into governed
patterns, templates, packages, workers, domain apps, or marketplace entries
when reuse, evaluation, installation, or settlement matters.

### Application Surface Registration Contract

Every durable Hypervisor application surface should have a registration contract
before it becomes first-class product inventory. The contract may start as a
client-local descriptor and promote into daemon/Agentgres records when install,
permissioning, packaging, replay, audit, or marketplace behavior needs durable
identity.

A surface registration should declare:

- stable surface id, display name, summary, and family;
- canonical owner doc and owning object families;
- supported placements: Applications catalog, Open Application, Home
  suggestion, Project context, Session context, org/admin view, or operator
  console;
- composition pattern: list/detail, command/search, modal wizard, canvas/editor,
  object view, graph view, review inbox, monitoring console, lineage/replay
  view, lifecycle strip/detail drawer, package/install flow, or generated
  domain surface;
- launch modes and target bindings, including project/session compatibility;
- daemon/API dependencies and Agentgres object refs;
- operator-plane tool or MCP contract refs, including which actions are
  inspect-only, propose-only, or effectful;
- host/platform mutation boundary: whether an action may be requested by child
  sessions, only by the Hypervisor Operator Plane, or only by a human/admin;
- required authority scopes, policy posture, and privacy posture;
- receipt, replay, eval, package, and promotion obligations where applicable;
- lifecycle-control posture where applicable: local owner, state machine,
  current/target refs, rollout/rollback/recall posture, blocking gates, linked
  jobs/runs, dependency impact, and Governance release/change deep links;
- ontology and ODK posture where applicable: DomainOntology refs,
  CanonicalObjectModel refs, DataRecipe refs, PolicyBoundDataView refs,
  OntologyProjection refs, OntologySurfaceDescriptor refs, and generated
  artifact refs;
- install, favorite, recent, recommended, and marketplace metadata where
  applicable.

Before a surface becomes durable first-class product inventory, it should pass an
implementation-pressure check. The check should prove that the surface can carry
at least one end-to-end operator job without relying on hidden runtime ownership
or happy-path-only assumptions.

The pressure check should cover:

- the primary user/operator job the surface exists to complete;
- the minimal object set needed for that job;
- empty, loading, missing-prerequisite, degraded, blocked, approval-pending,
  failed, recovery, and completed states;
- connector, authority, policy, privacy, provider, environment, and budget
  readiness where applicable;
- which actions are inspect-only, propose-only, effectful, reversible,
  review-gated, rollback-capable, or publishable;
- where receipts, replay, proof/settlement drilldowns, logs, artifacts, and
  evaluation results appear;
- whether child sessions may request an action or whether the action must route
  through the Hypervisor Operator Plane or a human/admin.

The registration contract prevents Applications from becoming a junk drawer: a
surface must say what it operates, where it can open, what authority it needs,
and which canonical owners retain truth.

ODK-generated surfaces must pass the same registration contract as hand-authored
surfaces. The Ontology Development Kit may scaffold the descriptor, code,
fixtures, test cases, package skeletons, and conformance checks, but generated
React, templates, examples, or local descriptors are not runtime truth,
authority truth, semantic truth, or marketplace truth. Durable generated
surfaces still bind to Hypervisor Core, daemon APIs, Agentgres ontology/object
refs, policy-bound views, authority requirements, receipts, replay, and
conformance profiles.

### Application Composition Contract

Application surfaces are composed from reusable UX primitives over shared
Hypervisor contracts. A surface should not invent a bespoke product island when
one of the standard composition patterns can carry the job.

Canonical composition primitives:

```text
catalog/search launcher
Open Application frame
list/detail workspace
command composer
modal or step wizard
canvas/editor projection
object view
object-view editor
graph view
review/approval inbox
monitoring or resource console
lifecycle strip / release-control detail drawer
lineage/replay/evidence view
artifact/build/job view
package/install/publish flow
generated domain surface
```

Composition primitives are presentation and workflow affordances. They do not
own runtime truth, authority, semantic truth, model truth, storage truth, or
settlement truth. Each composition must bind to the same application
registration contract: owning object families, daemon/API dependencies,
operator-plane tool or MCP contracts, authority/privacy posture, Agentgres refs,
receipts, replay, eval/package obligations, and supported placements.

Generated applications, organization-built surfaces, domain apps, templates,
walkthroughs, examples, and builder outputs must compile into this same
registration/composition contract before they become durable inventory.

Application surface modes should be treated as first-class catalog or
contextual inventory when they matter to product outcomes. They are not
permanent rail items, but they should not be hidden as vague panels either.

Relevant surface modes include:

```text
Automations tool/function builder
ODK generate / blueprint surface builder
solution designer / architecture planner
walkthrough / recipe builder
object view
object-view editor
value type manager
graph/object explorer
scheduler
object/state monitor
authority clients
OAuth/client applications
granular permissions
resource queues and rate limits
retention and declassification views
restricted views
checkpoints / review gates
issues / action queue
artifact registry
build/job tracker
workflow lineage
code templates
branch/change view
developer console
linter / diagnostics
widget or extension builder
source/sync/listener manager
data health
dataset / time-series explorer
model library
model rules / guardrails
inference readiness
domain app consoles
```

Each mode should be classified under an owning product surface, such as
Automations, ODK, Governance, Environments, Work Ledger, Operations,
Projects / Workbench, Foundry, Marketplace, Developer & Integrations, or
Domain Apps. Older family labels such as `Data / Knowledge`, `Ontology`,
`Workshop`, `Domain Blueprints`, `Providers / Environments`,
`Release Controls`, `Resource Management`, `Authority / Govern`,
`Receipts / Replay`, and `Patterns / Examples / Training` are aliases or
facets, not separate product surfaces.

## Hypervisor Operator Plane

The Hypervisor Operator Plane is the governed control-plane harness for
operating Hypervisor itself.

It is not ioi.ai, not a child session harness, and not an ambient host
administrator. It is a distinct operating lane that uses the same configuration
substrate as sessions:

```text
AgentRecord
ModelConfiguration
ReasoningEffort
ServiceTier
HarnessProfile
Tool/MCP contracts
authority scopes
receipt policy
```

The operator lane exists so a user or organization can ask Hypervisor to inspect
and modify Hypervisor-level product state without granting child environments
host control. It may operate application surfaces, registry entries, authority
requests, provider posture, model eligibility, automation specs, package
metadata, and project/session coordination only through declared surface
contracts.

The control flow is:

```text
user intent or application surface request
  -> Hypervisor Operator Plane AgentRecord
  -> selected ModelConfiguration + HarnessProfile
  -> surface RuntimeToolContract / MCP contract
  -> daemon admission
  -> wallet.network authority
  -> Agentgres operation, receipt, projection, and replay
```

Child session harnesses may request, propose, or explain platform actions. They
must not directly mutate host or platform state such as the Applications
registry, provider settings, authority grants, model route eligibility, or
organization policy. Effectful host/platform changes route through the
Hypervisor Operator Plane, daemon admission, wallet.network, Agentgres, and
receipts.

ioi.ai dogfoods this plane as a first-party intent-to-outcome product. It does
not get privileged substrate semantics. A third party should be able to build an
ioi.ai-like coordinator from Hypervisor application surfaces, operator-plane
contracts, WorkRuns, Automations, Foundry, wallet authority, Agentgres truth,
and receipts.

If ioi.ai uses backend or headless conductors, those conductors are ordinary
Hypervisor clients over App/Web/SDK/CLI-headless-equivalent contracts. They may
submit operator-plane requests, inspect authorized projections, and coordinate
handoffs, but they cannot become a custom headless Hypervisor instance, hold
connector secrets, bypass wallet.network, mutate host/platform state directly,
or admit private truth outside daemon and Agentgres paths.

## Builder Surfaces

**Tool / Function Builder** is an alias for typed-function and tool-building
flows housed primarily in Automations and Developer & Integrations. It may
appear in Applications, in Automations node creation, in project context, or in
package/pattern flows. Its outputs compile into `RuntimeToolContract`,
primitive capability declarations, authority scopes, schema validation, receipt
obligations, and optional Automations nodes.

**ODK Generate** is the product path for object-aware application shells,
widgets, forms, dashboards, operator consoles, autonomous-system blueprints, and
generated domain apps. It may use ODK object/action/value types, ODK data
recipes, Workbench code, Automations, tool contracts, and package metadata.

These builder paths are proposal and packaging paths over Hypervisor Core. They
do not own runtime truth, authority, semantic truth, or storage truth. Effectful
actions they expose to agents must use the Hypervisor Operator Plane, daemon
admission, authority-provider gates as required, Agentgres, and receipts.

## Learning, Patterns, Examples, And Training

**Learning / Patterns / Examples / Training** is an enablement facet, not a
standalone product surface. It may appear in Home, Applications, Marketplace,
Foundry, ODK, Domain Apps, and onboarding flows when a recipe can become
governed work.

It is not passive documentation. It is a product path from learning or
exploration into governed work:

```text
role track
  -> guided speedrun
  -> installable example or solution diagram
  -> project, session, automation, data recipe, ontology pack, eval, or package
  -> authority request
  -> execution through Hypervisor Core and the daemon
  -> receipts, replay, evaluation, improvement, and promotion
```

This surface may expose:

- role tracks for agent builders, automation builders, application builders,
  data engineers, ontology builders, model engineers, operators, security
  admins, and marketplace providers;
- guided speedruns that launch governed New Session recipes;
- installable examples for agents, automations, data recipes, ontology packs,
  eval packs, dashboard/application shells, model routes, provider profiles,
  and marketplace packages;
- solution diagrams and architecture planners that compile into reviewed
  Workbench, Automations, Foundry, ODK, or Domain App
  proposals.

Every serious example should declare the vertical problem, required data and
ontology contracts, selected agents/workers/models/tools, authority scopes,
session or automation launch path, receipt/eval/replay posture, and package or
marketplace promotion path.

Use this surface to increase useful autonomous work, not raw runtime. A good
example is valuable because it becomes a launchable work path, an eval path, a
reusable package path, and sometimes a recurring managed-service path.

It does not own:

- daemon execution;
- wallet.network authority;
- Agentgres truth;
- Foundry training or promotion;
- marketplace settlement;
- domain app runtime truth.

## Hypervisor Workbench

**Hypervisor Workbench** is the code/systems/workspace surface.

Workbench may appear in:

- Hypervisor App;
- Hypervisor Web;
- remote browser workspaces;
- VS Code-family adapters;
- Cursor, Windsurf, JetBrains, and other editor adapters;
- terminal/tmux-oriented operator views.

Workbench can open and operate sessions through many editors. The editor is an
adapter target, not the product identity.

## Hypervisor Automations

**Hypervisor Automations** is the durable orchestration surface over
Hypervisor Core and the Workflow Compositor.

Automations is for work the user wants to save, run again, trigger, schedule,
publish as an internal service, or expose through an API/webhook.

Automations may own product-level projections for:

- automation specs and versions;
- trigger, schedule, webhook, queue, and API entrypoints;
- workflow/service graphs backed by Workflow Compositor contracts;
- review points, approval gates, and output contracts;
- change plans, rollout gates, release channels, maintenance windows,
  suppression windows, canary/adjudication, recall, and remediation workflows;
- run history, mission status, receipt views, and replay links;
- service templates and reusable recipes;
- Canvas editor state where a visual view is useful.

Automation graphs may include:

```text
trigger nodes
worker/agent nodes
task/shell nodes
tool/MCP nodes
model-route nodes
data recipe nodes
ontology action nodes
approval/wallet gate nodes
eval/test nodes
deployment/change nodes
pull-request and delivery nodes
receipt/replay nodes
output mapping panels
run history panels
```

Automations does not own:

- execution semantics;
- wallet.network authority or secret release;
- Agentgres truth, receipts, archive refs, or restore validity;
- model private reasoning;
- Foundry training, distillation, or package publication;
- the selected harness's internal step loop.

Common automation modes:

```text
manual workflow
scheduled workflow
event/webhook-triggered workflow
pull-request or issue-triggered workflow
background mission
approval flow
service/API endpoint
queue worker
marketplace service recipe
collaborative mission
```

The durable object is the automation spec and its Agentgres-backed run history,
not the editor that created it.

ioi.ai may hand off a collaborative outcome into Automations when a goal needs
many models, harnesses, workers, sessions, branches, connectors, or verifier
lanes. The ioi.ai coordination pattern is owned by
[`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md).

One-off agent handoffs and durable automations are different products over the
same execution substrate:

```text
one-off handoff
  preserves the user's prompt or work request as a single work item
  creates or selects a governed environment for that work
  returns a durable work-run ref once accepted
  does not create a reusable automation definition by default

durable automation
  stores a versioned automation spec
  has declared triggers, limits, steps, review gates, and delivery contracts
  can be created, updated, started, disabled, replayed, and audited
  should not silently duplicate an existing name/project trigger match
```

Automations should support step families such as `agent`, `task`, `approval`,
`pull_request`, `report`, `deployment`, `remediation`, and `webhook/API`.
An `agent` step resolves through a HarnessProfile or Agent Harness Adapter; a
`task` step resolves through daemon-owned environment task execution; a
`pull_request` step is a delivery contract, not proof of completion by itself.
Every consequential step still emits receipts and Agentgres-backed run history.

## Hypervisor Canvas

**Hypervisor Canvas** is a visual editor/presentation for composing and
inspecting graph-shaped work.

Canvas may appear inside Automations, Workbench, or Foundry. Its default home
for durable workflows and services is Automations.

Canvas may display:

- nodes and edges;
- typed step contracts;
- trigger and schedule refs;
- approval and policy checkpoints;
- cTEE/privacy posture;
- receipt and replay projections;
- harness, model, worker, service, verifier, and provider selection hints.

Canvas does not own execution, authority, state truth, receipts, or workflow
semantics. It edits or visualizes objects owned by Automations, the Workflow
Compositor, Foundry, or other product surfaces.

Use this product phrasing:

```text
Open this automation in Canvas.
```

Avoid:

```text
Canvas owns the automation.
Canvas runs the service.
Canvas is the product plane.
```

## Hypervisor Foundry

**Hypervisor Foundry** is the worker/model/eval/persistent-training/dataset/
registry/endpoint/package surface over Hypervisor Core.

Foundry produces and improves things that other surfaces use:

- model catalog entries and model cards;
- model registry entries, model routes, and model-mount candidates;
- WorkerPackages and worker manifests;
- datasets, feature views, ontology-bound datasets, and holdouts;
- dataset factory runs, persistent training pipelines, experiment optimization
  cycles, artifact conversion runs, endpoints, batch inference, metadata, and
  monitoring projections;
- eval suites, benchmarks, and verifier candidates;
- training, distillation, fine-tuning, and dataset recipes;
- quality gates and promotion proposals;
- package publication proposals for aiagent.xyz or private catalogs.

Foundry may consume Automations traces, Workbench runs, agent corrections,
receipts, and evaluation results, but it does not directly self-mutate the
runtime. Durable improvements enter through governed proposals, eval gates,
wallet.network approvals when needed, and Agentgres admission.

Foundry is owned in detail by [`foundry.md`](./foundry.md). ioi.ai may consume
Foundry evals and promote lessons into Foundry proposals, but ioi.ai
coordination is not Foundry and Foundry is not a chat room.

## Workflow Compositor

**Workflow Compositor** is the high-level directed-work surface over Hypervisor
Core. It is a shared graph/projection model used by Automations, Workbench,
Foundry, other application surfaces, Environments views, and
SDK/ADK/ODK clients when work needs explicit structure.

The compositor owns:

- service and workflow graph shape;
- typed step contracts;
- dependencies and handoff edges;
- acceptance criteria and review points;
- change-plan gates, rollout cohorts, maintenance windows, suppression windows,
  recall/remediation handoff edges, and blocked-reason projections;
- delivery contract and reusable templates;
- harness, model, worker, provider, and verifier selection hints;
- replay, receipt, authority, cTEE, and context-topology projections for the
  graph.

It does not own:

- execution semantics;
- wallet.network authority;
- Agentgres truth;
- model private reasoning;
- persistent workspace, project, or managed-instance memory;
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
provider / environment management session
```

A session binds:

- user, org, project, or worker identity;
- work item and work run refs when the session is executing delegated agent
  work;
- authority grants and capability leases;
- policy and approval state;
- runtime assignment;
- context cell / task refs where applicable;
- cTEE custody posture where applicable;
- Agentgres refs and receipt obligations;
- adapter targets;
- replay and restore metadata.

Sessions are the execution truth window. A session view should be able to show
the live or historical transcript, step graph, tool/model calls,
terminal/browser/computer-use activity, authority gates, privacy posture,
provider and environment state, logs, traces, receipts, state roots, replay
availability, and package or promotion options.

Trace and replay inspection should use one coherent path. A user should be able
to open a session, workrun, automation run, or workflow node; inspect grouped
turns or run segments; scan a waterfall of agent/model/tool/connector/MCP/
browser/terminal/environment/authority/eval/settlement spans; and open a detail
drawer for overview, event, request, response, graph, logs, authority, receipts,
proof/settlement, and artifacts. Proof and settlement detail is a drilldown from
work inspection, not a separate chain-first default view.

For delegated agent work, the session should also expose a stable
`HypervisorWorkRun` view: desired/current phase, selected agent or harness,
project/environment code context, model and reasoning settings, iteration and
token/context-window usage, MCP/connector integration status, current activity,
conversation history, live stream, transcript, support/log refs, used
environments, comments sent back to the run, review state, and delivery refs.
This makes long-running work observable without tying the product to one agent
implementation.

## Receipts, Replay, And Improvement

Traces and logs are necessary diagnostics, but they are not sufficient proof.
For consequential work, Hypervisor surfaces should converge on receipts and
replay so a user, organization, marketplace, verifier, or settlement path can
answer:

```text
what happened
why it happened
under whose authority
against which policy
with which artifacts
whether it can be replayed, challenged, improved, packaged, or settled
```

The improvement loop is:

```text
sessions and receipts
  -> examples and traces
  -> eval datasets
  -> failure clusters
  -> prompt/tool/model/worker/data-recipe fixes
  -> simulation/offline/online evaluation
  -> promotion or rollback
  -> better routing and work acceptance
```

Foundry, Automations, Applications, Sessions, Receipts/Replay, and marketplace
surfaces should expose this loop without giving any one UI surface runtime
truth.

Receipts/Replay surfaces may include a proof explorer for deep inspection across
runs, but the default UX should stay work-first: show the event, authority,
policy, receipt, replay, artifact, and proof state first; show raw transaction
hashes, chain IDs, contract refs, bridge refs, or gas details only when the
receipt is anchored/settled or the user opens proof, settlement, dispute,
governance, developer, or evidence-export detail.

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

The New Session flow should expose the selected launch recipe and selected
harness beside the selected model route, privacy posture, authority scope, and
receipt preview. The recipe is not launchable until Hypervisor Core asks the
daemon to admit it as a `HypervisorSessionLaunchRecipeAdmission`. That
admission binds recipe, target binding, project, session route, model route,
privacy posture, authority scopes, receipt refs, Agentgres operation refs, and
state root before any harness binding can be requested.

Session composition may run in an Auto/MoW-selected mode or a user-directed mode.
In both modes the selected harness, model route, worker, or managed agent must
consume a brokered capability manifest rather than connector credentials. The
manifest is derived from Hypervisor Connectors / Tools / MCP registry state,
session/project policy, privacy posture, authority posture, receipt policy, and
revocation state.

External harnesses must not silently fall back from a local/private model route
to a provider-trust model route; provider-trust or adapter-native routes are
explicit privacy posture states.

The launch result must include a `HarnessSessionBinding`:

```text
HarnessSessionBinding
  session_route_ref
  harness_selection_ref
  harness_launch_route_ref
  model_configuration_ref
  model_route_ref
  model_route_policy
  model_route_availability_state
  brokered_capability_manifest_ref
  mcp_gateway_profile_refs
  connector_refs
  workspace_mount_policy
  privacy_posture_ref
  authority_scope_refs
  receipt_policy_ref
  expected_receipt_refs
  example_root_ref, when applicable
  requires_daemon_gate: true
```

The binding is not sufficient by itself. Hypervisor Core must first request a
daemon-side `HypervisorSessionLaunchRecipeAdmission`, then a
`HarnessSessionBindingAdmission`, then a `HarnessSessionLaunch`, then a
`HarnessSessionSpawn`, then a `HarnessSessionReadiness`, then a
`HarnessSessionTerminalAttach` before a host-terminal launched session may be
reported as `daemon_admitted`. The admission chain is the local-first harness
gate: it can admit Codex OSS, the example Claude Code bring-up path, and
DeepSeek TUI over the local OpenAI-compatible Codex OSS / Qwen model route
without provider API authentication, while blocking provider-trust shortcuts,
external harness cTEE custody claims, missing local model endpoints/instances,
and any harness runtime-truth claim.

The first launch-ready host-dev contract is Codex OSS over local Ollama/Qwen:

```text
HarnessSessionLaunch
  schema_version: ioi.runtime.harness_session_launch.v1
  launch_lane: host_dev_pty
  command_contract:
    codex --oss --local-provider ollama
      --model ${HYPERVISOR_LOCAL_CODEX_OSS_MODEL:-qwen}
      --sandbox workspace-write
      --ask-for-approval on-request
      --cd ${HYPERVISOR_SESSION_WORKSPACE}
  model_mount_contract:
    provider: ollama
    api_format: openai_compatible
  secret_release_policy: none
```

The launch contract still does not run the process. It resolves the harness,
model mount, authority posture, workspace policy, command template, and receipt
refs. The daemon must then emit a `HarnessSessionSpawn`:

```text
HarnessSessionSpawn
  schema_version: ioi.runtime.harness_session_spawn.v1
  spawn_lane: host_terminal_session
  spawn_state: ready_for_client_pty_attach
  command_contract:
    resolved_argv:
      codex --oss --local-provider ollama
        --model qwen
        --sandbox workspace-write
        --ask-for-approval on-request
        --cd <workspace_root>
    pty_transport: hypervisor_client_terminal_adapter
    process_custody: client_host_pty_after_daemon_spawn_admission
  terminal_attach_contract:
    root: <workspace_root>
    command_line: <daemon-resolved command>
  secret_release_policy: none
```

Spawn readiness is still not terminal execution authority. The daemon must
admit a `HarnessSessionReadiness` record proving the local harness route is
usable, then admit a `HarnessSessionTerminalAttach` record:

```text
HarnessSessionTerminalAttach
  schema_version: ioi.runtime.harness_session_terminal_attach.v1
  attach_lane: hypervisor_client_terminal_adapter
  attach_state: client_pty_attach_admitted
  client_attach_contract:
    root: <workspace_root>
    command_line: <daemon-resolved command>
    initial_write: <daemon-resolved command + newline>
    pty_transport: hypervisor_client_terminal_adapter
    process_custody: client_host_pty_after_daemon_attach_admission
    transcript_stream_ref: agentgres://trace/harness-terminal-transcript/<id>
  terminal_transcript_projection:
    schema_version: ioi.runtime.harness_terminal_transcript_projection.v1
    transcript_state: awaiting_client_stream
```

The native Hypervisor client may attach a host PTY only after the attach
admission exists, then write the daemon-resolved `initial_write` and stream
terminal output into the transcript projection. The client is a PTY transport,
not the source of runtime truth. A native client may immediately observe PTY
output with `readTerminalSession` and fold the observed chunks, cursor, terminal
session ref, and stream state into the transcript projection, but those
observations remain evidence under the daemon-admitted transcript stream ref.
It may then continue polling the same terminal session until the PTY closes,
updating the transcript projection and emitting observation/closure receipts.
Closed transcript observations SHOULD be materialized as `terminal_transcript`
receipt-evidence records with Agentgres operation refs, artifact refs, trace
refs, state-root refs, and replay refs. The client may construct the projection
for display, but durable replay and restore truth belongs to Agentgres.
Web/headless clients may record spawn, readiness, attach, and transcript
projection contracts without a local PTY until a compatible terminal transport
is available.

The example Claude Code path and DeepSeek TUI remain first-session candidates
that may bind to the same local model configuration, but they are not
launch-ready until their daemon-owned launch contracts exist. This is a
configuration path, not proof that external harnesses own runtime truth.

Every external harness run should produce a `HarnessAdapterReceipt` binding the
selection ref, execution lane, model route ref, workspace mount policy,
authority scope refs, privacy posture ref, Agentgres operation refs, and
artifact refs.

Containerized harness adapters require a stricter daemon-side lane contract.
Docker and Podman are execution lanes, not privacy guarantees. A
`HarnessContainerLanePlan` must bind:

```text
runtime:
  docker | podman
container_image_ref
command_argv_hash
mounts:
  source_ref
  target_path
  access:
    read_only | read_write_scratch
  custody:
    public_trunk | redacted_projection
network_policy:
  disabled | allowlist
env_policy_ref
authority_scope_refs
privacy_posture_ref
```

The corresponding `HarnessContainerLaneReceipt` must include the same image,
argv hash, mounts, network policy, env policy, authority scope refs, privacy
posture ref, Agentgres operation refs, artifact refs, and an explicit
`exit_status` (`not_executed`, `success`, `failure`, or `blocked`).

By default, external container harnesses may not mount `plain_workspace` or
`ctee_private_workspace` custody, may not receive raw host paths, may not mount
host container sockets, and may not receive plaintext env maps or secret argv.
Those constraints keep container lanes useful for public-trunk and redacted
fixtures without pretending Docker or Podman provide cTEE privacy.

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

## Hypervisor Environment Ops

Some Hypervisor Sessions have a managed environment behind them: a local
workspace, remote VM, container, microVM, browser sandbox, hosted worker,
HypervisorOS node, provider workspace, or editor-attached runtime. Hypervisor
environment ops are the daemon/Core contracts for creating, starting, stopping,
inspecting, leasing access to, archiving, restoring, and deleting those managed
session resources.

An environment is not runtime truth by itself. It is the managed resource that
hosts work. The Hypervisor Daemon owns lifecycle semantics, wallet.network owns
authority and credential release, Agentgres owns admitted state/receipts/restore
truth, and storage backends hold payload bytes.

Environment-ops contracts cover:

```text
project discovery
environment class discovery
create session from project or context URL
non-blocking create and readiness polling
start / stop / mark-active lifecycle
structured command execution
SSH or shell access when explicitly allowed
service and task discovery / start / stop
port discovery / share / revoke
logs and output capture
SCM auth requirements and satisfaction
archive / unarchive / restore / delete
activity signals
cleanup obligations
receipt obligations
```

External harnesses, Workbench, Automations, Foundry, Canvas views, Hypervisor
App/Web, CLI/headless clients, and Environments views may receive
structured outputs and exit codes. They do not get durable secrets, plaintext
custody, or authority except through wallet.network capability leases and
receipts.

Canonical environment ops objects:

```text
HypervisorEnvironmentClass
HypervisorEnvironmentOpsProfile
HypervisorEnvironmentLifecycleState
HypervisorEnvironmentActivitySignal
HypervisorSessionAccessLease
HypervisorEnvironmentService
HypervisorEnvironmentTask
HypervisorEnvironmentPort
HypervisorScmAuthRequirement
```

Archive and restore doctrine:

```text
archive refs and restore refs are Agentgres/artifact-plane objects
encrypted blobs are restore material, not restore truth
restore applies through daemon lifecycle operations and Agentgres receipts
local/provider files must not be silently mutated as canonical restore
```

Zero-to-idle and restore doctrine:

```text
zero_to_idle releases compute/provider resources without deleting workspace truth
storage backends may continuously receive encrypted workspace/archive material
restore rehydrates from Agentgres-bound archive/payload refs
provider/devcontainer/log output explains the lifecycle but does not prove it
```

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

> **Reference-wall notice.** The object listing below is hand-maintained
> reference material, not additional doctrine. The source of truth for
> shipped shapes is the daemon's route/object registry in code; this wall
> is a design-surface commitment that may lead implementation. Do not
> narrow it, but do not read presence here as shipped — see the file's
> `Implementation status`. Generator TODO: emit this section from the
> daemon schema registry instead of maintaining it by hand.

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
    - home
    - projects
    - sessions
    - applications
    - automations
    - workbench
    - foundry
    - agents
    - services
    - models
    - privacy
    - receipts
  adapter_targets:
    - adapter_target:...

HypervisorSurface:
  surface_id: hypervisor_surface:...
  surface_kind:
    home | projects | automations | applications | sessions | workbench |
    foundry | canvas | agents | services | models | ctee_privacy |
    receipts_audit | connectors
  client_ref: hypervisor_client:...
  session_refs:
    - hypervisor_session:...
  projection_refs:
    - agentgres://projection/...

HypervisorAutomationSpec:
  automation_id: automation:...
  project_ref: project:...
  automation_kind:
    manual_workflow | scheduled_workflow | webhook_workflow |
    background_mission | approval_flow | service_api |
    queue_worker | marketplace_service_recipe | outcome_room
  graph_ref: workflow:...
  compositor_contract_ref: workflow_compositor://...
  trigger_policy_ref: policy://...
  review_contract_ref: review_contract://... | null
  output_contract_ref: output_contract://... | null
  harness_selection_hints:
    - harness_profile:... | agent_harness_adapter:...
  authority_refs:
    - grant://... | lease://...
  agentgres_refs:
    - agentgres://operation/...
  receipt_policy_ref: policy://...
  version:
    semver: string
    state_root_ref: state_root://...
  status:
    draft | enabled | disabled | archived

HypervisorAutomationRun:
  automation_run_id: automation_run:...
  automation_ref: automation:...
  mission_ref: mission:... | null
  session_refs:
    - hypervisor_session:...
  trigger_ref: trigger://... | webhook://... | schedule://... | null
  daemon_ref: daemon://...
  agentgres_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  artifact_refs:
    - artifact://...
  status:
    queued | running | waiting_for_approval | blocked |
    succeeded | failed | canceled | archived

HypervisorCanvasView:
  canvas_view_id: canvas_view:...
  owner_surface:
    automations | workbench | foundry
  target_ref:
    automation:... | workflow:... | foundry_job:... | project:...
  layout_ref: artifact://... | null
  projection_refs:
    - agentgres://projection/...

HypervisorSession:
  session_id: hypervisor_session:...
  project_ref: project:... | null
  session_kind:
    local_workspace | remote_vm_workspace | browser_sandbox |
    hosted_worker | hypervisoros_node | terminal | editor |
    computer_use | foundry_eval_training | provider_management |
    environment_management
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
  environment_class_ref: hypervisor_environment_class:... | null
  environment_ops_profile_ref: hypervisor_environment_ops:... | null
  environment_lifecycle_state_ref: hypervisor_environment_lifecycle:... | null
  ctee_posture_ref: ctee_posture:... | null
  access_lease_refs:
    - hypervisor_session_access_lease:...
  access_token_refs:
    - session_access_token:... # derived token material, not durable authority
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

HypervisorEnvironmentClass:
  environment_class_id: hypervisor_environment_class:...
  class_kind:
    local_workspace | remote_vm | container | microvm | wasm |
    browser_sandbox | hosted_worker | hypervisoros_node |
    provider_workspace | customer_cloud | enterprise_cluster
  provider_ref: provider://... | local://... | null
  resource_shape:
    cpu: string
    memory: string
    gpu: string | null
    storage: string
  privacy_postures:
    - local_only
    - provider_trust
    - ctee_split_path
    - hardware_tee
    - customer_controlled
  persistence_modes:
    - ephemeral
    - session
    - zero_to_idle
    - persistent
  attestation_policy_ref: policy://... | null
  cost_policy_ref: policy://... | null

HypervisorEnvironmentOpsProfile:
  profile_id: hypervisor_environment_ops:...
  environment_class_ref: hypervisor_environment_class:...
  consumer_kind:
    workbench | foundry | provider_environment_view |
    agent_harness_adapter | app | web | cli_headless |
    sdk | adk | connector
  discovery:
    projects: list | search | fixed
    environment_classes: list | policy_filtered | fixed
  environment_lifecycle:
    create_from_project: true
    create_from_context_url: true
    non_blocking_create: true
    readiness_poll: true
    start: true
    stop: true
    mark_active: true
    archive: optional
    unarchive: optional
    restore: optional
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

AgentHarnessEnvironmentOpsProfile:
  profile_id: agent_harness_env_ops:...
  extends: hypervisor_environment_ops:...
  harness_kind:
    codex | claude_code | grok_build | openhands | aider |
    cursor_agent | windsurf_agent | shell_agent | ci_agent | custom
  truth_boundary:
    proposal_source_only

HypervisorEnvironmentLifecycleState:
  lifecycle_state_id: hypervisor_environment_lifecycle:...
  session_ref: hypervisor_session:...
  environment_class_ref: hypervisor_environment_class:...
  status:
    requested | provisioning | starting | ready | active | idle |
    stopping | stopped | archiving | archived | restoring |
    restore_available | deleting | deleted | failed | blocked
  provider_state_ref: provider_state://... | null
  activity_signal_refs:
    - hypervisor_environment_activity:...
  archive_ref: artifact://... | null
  restore_ref: agentgres://restore/... | null
  state_root_ref: state_root://... | null
  receipt_refs:
    - receipt://...

HypervisorEnvironmentActivitySignal:
  activity_signal_id: hypervisor_environment_activity:...
  session_ref: hypervisor_session:...
  signal_kind:
    user_active | agent_active | task_running | service_running |
    port_open | log_written | file_changed | network_activity |
    work_run_active | review_waiting | idle_candidate | idle_confirmed |
    restore_required | policy_blocked
  observed_at: timestamp
  evidence_refs:
    - artifact://... | trace://... | receipt://...
  visibility:
    local | shared | support | provider_visible | redacted

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
  work_queue_refs:
    - hypervisor_work_queue:...
  agentgres_domain_ref: agentgres://domain/... | null

HypervisorWorkQueue:
  work_queue_id: hypervisor_work_queue:...
  project_ref: project:... | null
  owner_ref: wallet://... | org://...
  queue_kind:
    one_off_handoffs | automation_runs | review_queue |
    background_missions | service_requests | custom
  intake_policy_ref: policy://...
  default_environment_profile_ref: hypervisor_environment_ops:... | null
  default_harness_selection_ref: harness_selection:... | null
  default_model_configuration_ref: model_configuration:... | null
  status:
    active | paused | draining | archived
  receipt_refs:
    - receipt://...

HypervisorWorkItem:
  work_item_id: hypervisor_work_item:...
  queue_ref: hypervisor_work_queue:...
  project_ref: project:... | null
  source_kind:
    new_session | automation_trigger | pull_request | issue_event |
    webhook | schedule | human_comment | api | collaborative_outcome
  original_request_ref: artifact://... | null
  normalized_intent_ref: intent://... | null
  code_context:
    repository_refs:
      - repo://...
    environment_ref: hypervisor_environment_lifecycle:... | null
    pull_request_ref: scm_pr://... | null
  desired_delivery:
    none | report | patch | pull_request | deployment | service_response
  review_contract_ref: review_contract://... | null
  authority_scope_refs:
    - grant://...
  status:
    draft | queued | admitted | running | waiting_for_input |
    ready_for_review | completed | failed | canceled | archived
  receipt_refs:
    - receipt://...

HypervisorWorkRun:
  work_run_id: hypervisor_work_run:...
  work_item_ref: hypervisor_work_item:...
  session_ref: hypervisor_session:...
  automation_run_ref: automation_run:... | null
  workflow_action_ref: workflow_action:... | null
  selected_agent_ref: worker://... | agent_harness_adapter:... | null
  harness_selection_ref: harness_selection:...
  model_configuration_ref: model_configuration:...
  reasoning_profile_ref: reasoning_profile:... | null
  desired_phase:
    pending | running | waiting_for_input | stopped
  current_phase:
    pending | running | waiting_for_input | ready_for_review |
    stopped | completed | failed | canceled
  current_activity: string
  current_operation_ref: trace://... | null
  code_context_ref: artifact://... | project://... | null
  base_commit_ref: scm_commit://... | null
  git_branch_ref: scm_branch://... | null
  git_worktree_ref: workspace://... | null
  agentgres_patch_branch_ref: agentgres_patch_branch://... | null
  conversation_projection_ref: hypervisor_work_run_conversation:...
  transcript_ref: artifact://... | trace://... | null
  support_bundle_ref: artifact://... | null
  integration_status_refs:
    - hypervisor_work_run_integration_status:...
  used_environment_refs:
    - hypervisor_environment_lifecycle:...
  usage:
    iterations: integer
    input_tokens: integer
    output_tokens: integer
    cached_creation_tokens: integer
    cached_input_tokens: integer
    context_window_length: integer
    context_window_limit: integer | null
  output_refs:
    - artifact://... | patch://... | receipt://...
  review_state_ref: hypervisor_work_run_review_state:... | null
  merge_proposal_ref: merge_proposal://... | pull_request://... | null
  merge_decision_ref: merge_decision://... | null
  receipt_refs:
    - receipt://...

HypervisorWorkRunConversationProjection:
  conversation_projection_id: hypervisor_work_run_conversation:...
  work_run_ref: hypervisor_work_run:...
  history_ref: artifact://... | null
  live_stream_ref: stream://... | null
  blob_store_ref: artifact://... | null
  comments:
    - comment_ref: comment://...
      file_ref: artifact://... | null
      hunk_ref: diff_hunk://... | null
      submitted_by: wallet://... | org_role://...
      delivered_at: timestamp | null
  read_model_only: true

HypervisorWorkRunIntegrationStatus:
  integration_status_id: hypervisor_work_run_integration_status:...
  work_run_ref: hypervisor_work_run:...
  integration_ref: connector://... | mcp://... | tool://...
  phase:
    unknown | connected | degraded | failed | auth_required |
    policy_blocked | revoked
  failure_message: string | null
  authority_ref: grant://... | null
  evidence_refs:
    - trace://... | receipt://...

HypervisorWorkRunReviewState:
  review_state_id: hypervisor_work_run_review_state:...
  work_run_ref: hypervisor_work_run:...
  phase:
    not_required | waiting_for_review | changes_requested |
    approved | rejected | superseded
  reviewer_refs:
    - wallet://... | org_role://...
  delivery_refs:
    - pull_request://... | artifact://... | deployment://...
  receipt_refs:
    - receipt://...

HypervisorMission:
  mission_id: mission:...
  mission_kind:
    manual | schedule | webhook | pull_request | issue_event |
    policy_event | service_outcome | marketplace_job |
    collaborative_outcome
  interactive: false
  project_ref: project:...
  workflow_ref: workflow:...
  automation_ref: automation:... | null
  outcome_room_ref: outcome_room:... | null
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

HypervisorSessionAccessLease:
  access_lease_id: hypervisor_session_access_lease:...
  session_ref: hypervisor_session:...
  lease_kind:
    editor | ssh | browser | logs | environment_ops | support |
    port_share | scm_auth | task_exec
  authority_ref: grant://...
  policy_ref: policy://...
  audience:
    user | org_role | adapter | support | harness | service
  issued_token_ref: session_access_token:... | null
  expires_at: timestamp
  revocation_epoch: integer
  receipt_ref: receipt://...

HypervisorEnvironmentService:
  service_id: hypervisor_environment_service:...
  session_ref: hypervisor_session:...
  service_kind:
    model_server | dev_server | database | queue | browser |
    worker | agent_service | evaluator | custom
  service_reference: string | null
  command_ref: artifact://... | null
  port_refs:
    - hypervisor_environment_port:...
  status:
    declared | starting | running | degraded | stopped | failed
  health_ref: trace://... | receipt://... | null
  receipt_refs:
    - receipt://...

HypervisorEnvironmentTask:
  task_id: hypervisor_environment_task:...
  session_ref: hypervisor_session:...
  task_kind:
    shell | build | test | eval | benchmark | migration |
    package_install | git_operation | pull_request | code_review_response |
    agent_run | provider_action | archive | restore | custom
  work_run_ref: hypervisor_work_run:... | null
  authority_refs:
    - grant://...
  status:
    queued | running | succeeded | failed | canceled | blocked
  execution_result_ref: result://... | null
  receipt_refs:
    - receipt://...

HypervisorEnvironmentPort:
  port_id: hypervisor_environment_port:...
  session_ref: hypervisor_session:...
  port: integer
  protocol:
    http | https | tcp | udp | websocket | grpc
  exposure:
    closed | local_preview | shared_preview | external | blocked
  policy_ref: policy://...
  access_lease_ref: hypervisor_session_access_lease:... | null
  receipt_ref: receipt://... | null

HypervisorScmAuthRequirement:
  requirement_id: hypervisor_scm_auth_requirement:...
  session_ref: hypervisor_session:...
  provider:
    github | gitlab | bitbucket | self_hosted_git | custom
  required_for:
    clone | fetch | push | pull_request | issue | release
  credential_mode:
    oauth | deploy_key | ssh_key | fine_grained_token | brokered_secret
  authority_ref: grant://... | null
  secret_release_policy_ref: policy://...
  status:
    pending | satisfied | denied | expired | revoked
  receipt_ref: receipt://... | null
```

For code WorkRuns, the default materialized backing is a Git branch or worktree
created from a pinned base commit. Agentgres patch branches remain the canonical
coordination, attribution, authority, validation, and merge-decision layer. The
Git branch/worktree makes file review, IDE integration, tests, and PR export
concrete; the Agentgres patch branch owns the expected-head merge contract,
receipts, comments, validation refs, work attribution, and final admitted truth.
Child environments stay isolated: they clone, edit, test, and propose. They do
not mutate host state directly.

## Conformance Checks

- No Hypervisor client may write canonical run/session/task truth without the
  daemon and Agentgres admission path.
- No application surface may become a private runtime loop beside the
  Hypervisor Daemon.
- No application surface may become a bespoke island when a standard
  composition primitive plus the application registration contract can carry the
  product job.
- No child session harness may mutate host/platform state directly; it may
  request or propose actions that the Hypervisor Operator Plane admits through
  declared surface contracts.
- No Hypervisor application surface may expose effectful operator tooling
  without RuntimeToolContract or MCP contract refs, wallet authority posture,
  Agentgres refs, and receipt obligations.
- No adapter target may receive secrets, declassification authority, or
  payment authority except through wallet.network leases and receipts.
- Code WorkRuns that produce file changes should bind isolated child
  environments to both a materialized Git branch/worktree and an Agentgres patch
  branch unless the work is explicitly read-only, non-code, or ephemeral.
- Workbench, Automations, Foundry, Canvas, other application surfaces, and
  Environments views must share Core session, authority, receipt,
  replay, and projection contracts.
- Automations must use Workflow Compositor contracts for graph shape and the
  daemon/Agentgres path for execution truth; it must not invent a separate
  automation runtime.
- Canvas must remain an editor/projection over automation, workflow, and
  Foundry objects; it must not become runtime truth.
- Editor integrations must make mediation limits visible.
- Every editor, terminal, browser, VM, and harness target must resolve through
  an `AdapterConnectionProfile`; a string editor preference is not enough.
- Agent harness adapters must use daemon/Core environment-ops APIs for
  discovery, execution, logs, and cleanup rather than scraping Hypervisor UI or
  directly mutating workspaces.
- Hypervisor environment lifecycle changes, service/task execution, access/log
  leases, port exposure, SCM auth, archive, and restore must produce Agentgres
  refs and receipts when they affect authority, privacy, replay, cost, or
  restore.
- `SessionAccessToken` is derived token material under a
  `HypervisorSessionAccessLease`; it is not the durable authority object.
- Background missions must be modeled as `HypervisorMission` objects with
  trigger policy, review contract, authority requirements, output contract, and
  receipts; they must not be hidden interactive sessions.
- ioi.ai collaborative outcome handoffs and Collaborative Missions must use the
  Automations, session, daemon, wallet.network, Agentgres, and Foundry/eval
  paths defined in
  [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md);
  they must not collapse into ungoverned multi-agent chat.
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
one editor shell = parent product
Hypervisor App owns Core
Hypervisor Web owns Core
ioi.ai chat = durable automation owner
ioi.ai = Hypervisor Operator Plane
ioi.ai = privileged Hypervisor substrate
Home = dense Workbench terminal/diff/file console
Applications = unstructured app drawer
Pinned Applications = permanent empty rail region
Open Application = multiple simultaneous primary app frames
application composition = bespoke product island
generated app = unregistered host surface
CLI/headless owns a separate runtime loop
TUI = separate first-class client lane
external CLI agent harness = Hypervisor client
Codex/Claude Code/Grok Build = runtime truth
editor name string = adapter contract
Canvas = automation runtime
Canvas = product plane
support bundle = harmless log export
port preview = not a data boundary
SSH token = durable credential
encrypted blob = restore truth
provider lifecycle state = Agentgres truth
background automation = hidden editor session
automation spec = chat transcript
ioi.ai collaborative outcome = group chat
ioi.ai collaborative outcome = unbounded swarm
Hypervisor Operator Plane = ambient host administrator
child session harness = host platform administrator
Git branch = canonical attribution/truth layer
code WorkRun = no materialized branch/worktree by default
Workbench = runtime truth
Foundry = direct self-mutation path
provider posture = standalone provider-management product
provider posture = infrastructure runtime or authority owner
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
Workbench/Automations/Foundry = application surfaces
Application composition = reusable UX primitives over shared Core contracts
Canvas = visual editor/projection
ioi.ai = intent-to-outcome coordination, including multi-model/multi-path
goal pursuit when useful
Hypervisor Operator Plane = governed control-plane harness over declared
application-surface contracts
code WorkRun = isolated child environment + materialized Git branch/worktree +
Agentgres patch branch + receipts
Provider and infrastructure posture = Environments views through
Applications, Open Application, sessions, projects, provider settings,
org/admin views, or operator consoles
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
- [`providers-and-environments.md`](./providers-and-environments.md)
- [`identity-access-and-metering.md`](./identity-access-and-metering.md)
- [`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md)
- [`foundry.md`](./foundry.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
- [`../../_meta/vocabulary.md`](../../_meta/vocabulary.md)
