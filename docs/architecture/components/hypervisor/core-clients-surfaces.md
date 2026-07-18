# Hypervisor Core, Clients, Workspaces, Application Surfaces, Sessions, and Adapters

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Core product taxonomy, first-class
client boundaries, core-workspace boundaries, application-surface boundaries,
Work and Session projections, and adapter-target doctrine, including
Hypervisor's projection of ioi.ai Goal Spaces and OutcomeRooms through Work and
the Hypervisor-owned **Connect local agent** pairing/adapter surface. Dedicated
Improvement, Evaluations, and Foundry owner contracts remain in
[`improvement.md`](./improvement.md), [`evaluations.md`](./evaluations.md), and
[`foundry.md`](./foundry.md).
Supersedes: live product prose that treats one editor shell as the parent
Hypervisor product, treats Electron/VS Code hosting as the product identity, or
treats editor integrations as runtime ownership.
Superseded by: none.
Last alignment pass: 2026-07-17.
Doctrine status: canonical
Implementation status: mixed (the existing Home, New Session, Projects,
Automations, Applications, Sessions, owner-application, environment, and
operational surfaces are broad and verifier-gated; the canonical Systems and
Work workspaces, taxonomy-v2 registrations/compiler, Packages-first product
home, Developer Workspace rename, generated/installed application registry,
typed legacy-Mission migration, and corresponding routes are target contracts
and are not shipped as one complete path. `LocalAgentPairingSessionEnvelope`,
Connect local agent UX, and room-admitted local-agent gateway issuance also
remain planned. The bounded ImprovementCampaign, EvaluationEpoch, protected-
evaluation exposure, and evaluator-validity owner paths are target contracts,
not one shipped end-to-end implementation).

Taxonomy status: TARGET CANONICAL (2026-07-15) — Systems and Work are core
workspaces; twelve enduring baseline owner applications, one conditional
planned Embodied Systems owner registration, two substrate applications, tool
surfaces, and extension applications remain dimensionally distinct.
Missions retires as a peer application and `HypervisorMission` retires as a
generic truth object. Packages owns mandatory local package lifecycle;
Marketplace is its optional discovery/exchange mode. Developer Workspace is the
preferred product label for the former Workbench. ODK remains a developer kit,
generated and installed applications compile into the common registration
contract, and older mapping documents remain archived historical evidence.
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
Systems is the stable contextual home for live bounded institutions.
Projects organize persistent build and work context.
Automations own reusable standing behavior.
Applications expose specialized owner, substrate, tool, and extension surfaces.
Work projects pursued, collective, triggered, executing, review, incident, and
historical work through typed canonical subjects.
Sessions provide bounded interactive, headless, or supervisory execution and
control contexts inside Work.
Hypervisor Core governs the runtime/control boundary underneath.
```

Product boundary doctrine:

```text
ioi.ai asks and conducts subscribed Goal Spaces.
Hypervisor runs governed autonomous work.
Automations make durable workflows and services.
ioi.ai coordinates single-path work or an OutcomeRoom/CollaborativeWorkGraph
when persistent multi-participant pursuit calls for it.
Foundry builds models, workers, evals, datasets, ontology-bound packages,
deployment candidates, and admitted experimental runs.
Evaluations freezes independent judgment contracts and maintains their
validity, exposure, and re-verification posture.
Improvement coordinates optional multi-epoch improvement campaigns and hands
supported candidate changes to their target owners.
Governance and the target owner decide admission, activation, and effect
recovery.
Developer Workspace develops, debugs, and operates systems and workspaces.
Canvas visually edits automations; it is not runtime truth.
```

The same persistent collective outcome appears as a **Goal Space** in ioi.ai
and as **Work / Room detail** in Hypervisor. It is not duplicated state and it
does not justify a permanent Mission or Swarm application. A simple question,
direct run, ordinary automation, or single-session task remains direct.
`Mission` may remain optional product language over exactly one explicit
GoalRun or OutcomeRoom subject; it creates no independent identity, lifecycle,
budget, authority, evidence, status, or receipts.

Product-budget boundary:

```text
ioi.ai Goal Space subscription
  conductor, persistence, collaboration, memory, receipts, replay, and a
  bounded monthly grant of non-transferable Hypervisor Work Credits

same-domain managed execution
  consumes included/top-up/committed Work Credits under Auto, Pinned, or
  Compare policy

independent Network / Open participation
  uses a separately visible goal budget, bounty, service order, or procurement
  limit and preserves actual party/worker/service commercial records
```

Hypervisor owns execution and managed-work usage truth, not the ioi.ai account
subscription. The product must not imply that named-user foundation-model seats
are pooled machine capacity.

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
  route, package, provider recipe, system blueprint, or embodied package?

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
| Substrate overview | Operations, Environments, provider detail, Hypervisor Desktop / Workstation |
| Inventory | Systems, Work, Applications catalog, Operations tables, Environments |
| Create / import wizard | Home, New, Projects, Environments, Studio, Developer Console |
| Live console / machine window | Developer Workspace, Work / Sessions, Run Timeline, Open Application |
| Snapshots / checkpoints / restore | Provenance, Developer Workspace, Environments |
| Networks / storage / devices | Environments, Developer Console, Governance |
| Tasks / events / logs / alerts | Work (logical work), Operations (infrastructure), Provenance (evidence) |
| RBAC / policy / audit / lifecycle | Governance, Provenance, Operations |

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
| Agentgres | Provenance (work ledger), evidence, run history, receipts, state/history |
| Hypervisor Daemon | secure runtime, execution environment, worker runtime |
| IOI L1 / mainnet | proof network, settlement, public commitment |
| aiagent.xyz | agent marketplace, worker marketplace, agent supply |
| ContributionReceipt | contribution record, payout evidence, attribution |
| OutcomeRoom / CollaborativeWorkGraph | Goal Space in ioi.ai; Work / Room detail in Hypervisor |
| RoomParticipantLease / WorkClaimLease | participant status/current work with advanced lease details |
| Work Credits | managed-work allowance and usage budget |

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

Package lifecycle is mandatory for reusable release material; Marketplace
discovery and exchange is optional. Packages flows should be available from
Foundry, Packages, Projects, Automations, Work, or aiagent.xyz handoffs when
useful, while commerce is never forced into ordinary local work.

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
      Systems
      Projects
      Automations
      Applications
      Work
  -> owner applications
      Studio
      Automations
      Ontology
      Data
      Governance
      Provenance
      Evaluations
      Improvement
      Foundry
      Packages
      Developer Workspace
      Developer Console
  -> substrate applications (type 1 + 2 face)
      Environments
      Operations
  -> tool surfaces
      owner-bound editors, inspectors, inboxes, graphs, wizards, and reports
  -> extension applications
      generated, organization-authored, installed, or third-party interfaces
  -> conditional owner application
      Embodied Systems (planned registration; nonlaunchable until built)
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
Sessions, Automations, Foundry, Developer Console, Provenance, and the
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

### Connect local agent

ioi.ai may embed a screenshot-simple **Connect local agent** modal inside a Goal
Space, and aiagent.xyz may link to the same flow when a local Worker wants to
join eligible work. The canonical product boundary is nonetheless singular:

```text
ioi.ai
  embeds room-specific Connect local agent and projects admission/work status

Hypervisor
  implements the shared LocalAgentPairingSessionEnvelope through its
  deployment-local lifecycle, local adapter/sidecar, candidate key and origin
  binding, daemon ingress, and post-admission MCP gateway profile

aiagent.xyz
  owns the separate opt-in private reusable Worker record or public package,
  benchmark, listing, routing-eligibility, reputation, and marketplace
  settlement projections/refs; it does not own authority, operational truth,
  or public finality
```

Pairing does not publish an agent to aiagent.xyz and does not require a public
marketplace listing. A one-room candidate may remain private and ephemeral. A
later **Save to My workers** or **Publish on aiagent.xyz** action is an
explicit handoff with its own package, rights, benchmark, admission, and
publication state.

The default modal should preserve the screenshot's low-friction copy/paste
shape while showing the actual trust transition:

```text
CONNECT LOCAL AGENT

1  CHOOSE AGENT
   Codex | Claude Code | OpenCode | Aider | generic CLI/MCP | local sidecar

2  AGENT PROFILE
   display name; optional operating style; declared harness/capabilities;
   privacy and local-runtime posture

3  PAIR THIS DEVICE
   one copyable command or prompt; one-time expiring challenge/device code;
   candidate generates the signing key and binds its origin

4  REQUEST ROOM ACCESS
   show public/policy-bound room objective, requested role, verifier,
   contribution, privacy, budget/quote, and admission terms

5  CONNECTED
   only after admission: participant lease, permitted views, scoped expiring
   gateway profile, current claim, expiry, heartbeat, pause, and revoke
```

The bootstrap may contain an endpoint, public discovery ref, adapter
instructions, expiry, and one-time challenge. It must never contain a broad
organization read/write token, raw model/provider or connector credential,
ambient private room context, wallet grant, durable API key, or master MCP
manifest. The challenge is hash-only at rest and returned once. The candidate
generates its own signing key; Hypervisor binds the public key and origin but
never retains the private key.

Pairing authenticates the candidate only. Before typed room admission it may
read the signed `OutcomeRoomDiscoveryEnvelope`, submit its scoped
`WorkerComposition` proposal, and then submit a
`RoomParticipationRequestEnvelope`; it has no membership, private context,
claim, tool, spend, or effect authority. Only an admitted
`RoomParticipantLeaseEnvelope` lets Hypervisor issue the matching scoped,
expiring, revocable gateway profile. Every effectful tool still crosses the
backing contract's policy, authority, daemon-admission, receipt, and replay
path.

Prompt-only compatibility remains useful when an existing agent cannot install
a native adapter or sidecar. The UI must label it **Proposal only / low
assurance**. An admitted prompt-only participant may read its permitted
projection and submit tainted proposals or artifact refs, but cannot receive
effectful tools, claim daemon-instrumented execution, auto-promote work, accrue
portable reputation or payout from pairing alone, or become a marketplace
listing. The result may later reach a stronger assurance stage through the
normal sandbox, evidence, verifier, acceptance, and room/domain admission path;
that does not retroactively verify the hidden agent runtime.

The surface must project the exact pairing lifecycle without mixing downstream
admission into it: `created`, `challenge_issued`, `agent_proof_received`,
`bootstrap_bound`, `composition_submitted`, `participation_submitted`,
`completed`, `expired`, `rejected`, `cancelled`, `revoked`, or `failed_closed`.
Friendly labels may map one-to-one to those values. `admitted` belongs to the
separate composition or room-participation decision, never pairing status.
After admission the Goal Space/Work participant view shows the participant
and work-claim leases, gateway/profile expiry, current claim, heartbeat,
evidence/assurance posture, spend, quarantine, release, retire, and revoke
controls rather than representing the agent as an opaque live token stream.

The shared schema is owned by
[`LocalAgentPairingSessionEnvelope`](../../foundations/common-objects-and-envelopes.md#localagentpairingsessionenvelope);
deployment-local lifecycle handling is owned by
[`identity-access-and-metering.md`](./identity-access-and-metering.md#local-agent-pairing-sessions).
Gateway-profile binding is owned by
[`connector-and-tool-contracts.md`](../connectors-tools/contracts.md#local-agent-pairing-profile-binding).

## Top-Level Product IA

The default Hypervisor shell should stay small enough that new users can tell
where work lives:

```text
+ New
  System
  Session
  Goal
  Project
  Automation

Home
Systems
Projects
Automations
Applications
Work

Open Application
  optional singular shell slot for the currently open application
```

`New Session` remains a one-click and keyboard-first action even when `+ New`
is the visible creation affordance. Product navigation must not make an
ordinary direct Session pay the ceremony cost of a System or GoalRun.

This is a product-navigation doctrine, not a new ownership graph. The durable
owners remain the daemon, wallet.network, Agentgres, storage backends, AIIP, and
IOI L1 as defined by their canonical docs.

Use these product meanings:

```text
Home
  default command surface for starting, resuming, approving, or inspecting work

Systems
  inventory and contextual workspace for one stable constitution-bound
  institution across releases, nodes, models, upgrades, recovery, and migration

Projects
  persistent build/work containers with repos, files, environments,
  development environment recipes, adapter preferences, policy defaults, linked
  automations, and receipts

Automations
  one owner-application identity for reusable workflow, service, API, trigger,
  monitor, schedule, queue, and approval-flow definitions and their activations

Applications
  catalog, search, launcher, and management surface for registered owner,
  substrate, tool, generated, and installed extension surfaces

Work
  read-only, policy-filtered projection across GoalRuns, OutcomeRooms,
  AutomationRuns, Sessions, WorkItems, WorkRuns, reviews, incidents, and history

Sessions
  bounded interactive, headless, or supervisory execution/control contexts
  available as a first-class Work view and direct creation action
```

Avoid turning platform primitives into permanent top-level nav. Agents, Workers,
Models, Connectors, MCP servers, Ontology, Policies, Receipts, Monitoring,
Foundry, Packages/Marketplace, and similar surfaces should live in the Applications
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

The product estate has dimensional classes rather than one flattened list.
Home, Systems, Projects, Applications, and Work are core workspaces. Automations
is one owner-application registration with a shell placement, not a duplicate
workspace registration. `surface_availability: planned` is a state, not another
class.

```text
Core workspaces
  Home
  Systems
  Projects
  Applications
  Work

Owner applications
  Studio            (system & agent composition; absorbs Agent Studio as its agent lens)
  Automations       (durable triggers, schedules, monitors, services, process graphs)
  Ontology          (the semantic world-model: object/link/action types, functions,
                     value types, object exploration and saved sets — Ontology family)
  Data              (supply the world-model: sources, syncs, data recipes, datasets,
                     media sets, consent posture — Data/Knowledge family)
  Governance        (authority, approvals, leases, release gates, kill switches, budgets)
  Provenance        (receipts, lineage, replay, state roots — Work Ledger family)
  Evaluations       (suite revisions, frozen epochs, scorecards, holdout/exposure,
                     evaluator validity, feedback, re-verification)
  Improvement       (agendas, optional campaigns, target/candidate lineage,
                     synchronization, proposals, activation/recovery handoff)
  Foundry           (candidate/evaluator asset construction, admitted experiments,
                     models/routes/mounts, tuning, datasets, training pipelines)
  Packages          (local package, release, install, dependency, impact, recall lifecycle;
                     Marketplace is an optional discovery/exchange mode)
  Developer Workspace
                    (code, files, terminal, ports inside environments;
                     Workbench is a compatibility alias)
  Developer Console (connectors, MCP, APIs, OAuth clients, SDK on-ramps, conformance —
                     Developer & Integrations family; UI touchpoint of the developer kit)

Substrate applications (type 1 + 2 face)
  Environments
  Operations        (infrastructure: scheduler health, providers, placement/failover,
                     storage custody, capacity, provider spend)

Tool surfaces
  owner-bound editors, inspectors, pickers, inboxes, graphs, wizards, reports,
  dashboards, comparisons, and consoles; one primary owner, many contextual consumers

Extension applications
  generated, organization-authored, developer-kit-generated, installed, or
  marketplace-distributed interfaces admitted through the common registration

Conditional specialist owner application
  Embodied Systems  (`owner_application`; deployment-neutral `planned`
                     registration; nonlaunchable until built)
```

### Canonical Target Routes And Compatibility Aliases

Routes are part of the registration contract, not names inferred by a client.
The v2 target route ledger is:

| Surface/action | Canonical target route | Compatibility aliases or rule |
| --- | --- | --- |
| Home | `/home` | `/ai`, `/__ioi/home` |
| New Session | `/work/new-session` | `/ai#new-session`; remains a one-click action |
| Systems | `/systems` | no fabricated System rows during migration |
| Projects | `/projects` | existing Project context is preserved |
| Applications | `/applications` | one catalog/compiler projection |
| Work | `/work` | `/sessions` → `/work/sessions`; `/missions` → typed GoalRun/OutcomeRoom view |
| Studio | `/studio` | `/__ioi/agent-studio` |
| Automations | `/automations` | shell placement and application identity resolve to the same registration |
| Ontology | `/ontology` | current ontology/ODK subroutes remain contextual aliases |
| Data | `/data` | `/__ioi/odk#data-planes` |
| Governance | `/governance` | `/__ioi/governance` |
| Provenance | `/provenance` | `/__ioi/work-ledger` |
| Evaluations | `/evaluations` | `/__ioi/evaluations`, `/__ioi/feedback` |
| Improvement | `/improvement` | `/__ioi/agent-studio#improvement-proposals`, `/__ioi/improvement/changes` |
| Foundry | `/foundry` | `/__ioi/foundry` |
| Packages | `/packages` | `/marketplace`, `/__ioi/marketplace` → `/packages/marketplace` |
| Developer Workspace | `/developer-workspace` | `/workbench`, `/__ioi/workbench` |
| Developer Console | `/developer-console` | `/__ioi/connections` |
| Environments | `/environments` | `/__ioi/environments` |
| Operations | `/operations` | `/__ioi/operations` |
| Embodied Systems | `/embodied-systems` reserved | planned and nonlaunchable; `/fleet` must resolve contextually rather than aliasing to one owner |

An extension application's general route is compiled as
`/applications/{surface_key}`. A System-bound interface resolves under
`/systems/{system_id}/interfaces/{system_binding_id}`. Aliases must preserve
query, hash, embed/return state, and every typed Organization, Project, System,
GoalRun, OutcomeRoom, AutomationRun, Session, WorkQueue, WorkItem, and WorkRun
context. Additional current aliases remain admitted registration data; they do
not create another product identity.

The durable owner-application jobs are derived from the lifecycle of a bounded
autonomous institution: constitute, compose, ground, govern, run, prove,
evaluate, improve, package, deploy, operate, recover/migrate/succeed, and
retire/dissolve. Systems keeps the live institution at the center; Work keeps
heterogeneous work coherent without creating a universal work object.

The conditional Embodied Systems `owner_application` registration is
deployment-neutral and does not enlarge the twelve enduring baseline owner
jobs until it becomes available. Its native projection centers admitted
`EmbodiedRuntimeGraphManifest` revisions, composable `micro`/`edge`/`site`
profiles, physical streams and action-policy contracts, exact resource groups,
`LocalControlSupervisor` state, graph activation transactions, fleet allocation,
`SpacetimeReservationLease` state, telemetry/replay, and deployment-bound
assurance. Existing robot, vehicle, industrial, and device controllers enter
through an admitted `EmbodimentAdapter` and, where required, a compatibility-only
`LocalControlBridge`; neither replaces the native runtime contract or the
supervisor's final local veto. Embodied Systems does not require HypervisorOS;
it remains an optional Type 1 substrate when stronger node control, measurement,
or containment is useful.

ODK is NOT an application: it is the developer kit (CLI, templates, scaffolds,
generated SDKs, docs, conformance). Its object planes remain substrate and
surface through the suite — ontologies and value types through Ontology,
data recipes and sources through Data,
surface descriptors through Studio, manifests through Packages — and its
developer tooling through Developer Console and the kit itself.

Generated domain apps will often use React or another proven application
framework and may be the most prominent System interface. They remain
projections and intent surfaces over constitution, daemon, authority,
Agentgres, deployment, and receipt contracts. IOI's value is not replacing the
UI framework; it is supplying the governed autonomous-system substrate beneath
one or many UI replicas.

## Context, Integrations, And Memory Placement

Connectors, skills, memory, MCP servers, model routes, policies, receipts,
providers, evals, and similar primitives are not permanent shell rail items.
They appear through the Applications catalog, the singular Open Application
slot, and scoped context panels where the user is configuring a concrete piece
of work.

The primary product venue for the full integration estate is
Developer Console:

```text
Developer Console
  connectors and connected apps
  MCP servers and surface MCPs
  connector, tool, and provider-integration registrations
  APIs, OAuth clients, SDKs, ADK, webhooks, and service registrations
  conformance and developer app registration
  developer-kit on-ramps: scaffolds, templates, generated SDKs
```

Developer Console defines and validates integration/configuration
registrations; it does not own provider runtime lifecycle, placement, health,
capacity, or spend. Environments and Operations own those projections and
actions, while settings own personal or organization credential and policy
defaults.

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
  Enterprise Learning Boundary defaults, provider secondary-use and
  cross-customer learning policy, custody/region, capability-exit posture
  workspace defaults and administrative enrollment
```

Contextual surfaces expose the same primitives where they are actually used:

```text
New Session
  agent, model, harness, tools, memory, privacy, learning-from-this-work posture,
  budget, authority

Studio
  system boundary, agent lens (worker tools, skills, memory profile,
  model/harness), compiled InstitutionalLearningBoundaryProfile,
  endpoint/package posture

Projects
  project memory, project connectors, environment recipes, learning-boundary
  build policy, policy defaults

Automations
  workflow/service triggers, connector steps, approval requirements, delivery

Managed agent console
  instance connectors, schedules, contact channels, memory posture, updates

Governance / Data / Ontology / Models / Foundry / Provenance / Environments
  contextual policy, source-rights, route-rights, eligible-evidence,
  learning-flow, custody, export, revocation-impact, and model-swap projections
```

Durable workflows remain Automations. Personal shortcuts, reusable snippets, or
templates may appear inside Skills, Launch Policies, Developer Console,
or contextual setup panels when they serve the current task, but Hypervisor
should not add a generic Workflows child tab. Scheduled services, workflow graph
truth, approval flows, delivery paths, and Automation records belong to the
top-level Automations surface.

Do not copy reference-product tab taxonomies as Hypervisor product structure.
Hypervisor has a top-level Automations surface for durable triggers, schedules,
service graphs, approvals, and delivery. Studio, New
Session, Projects, and Developer Console may project automation
readiness, connector availability, skills, memory posture, and launch policies
where they are used, but they must not cannibalize Automations as a child tab or
rename durable Automations into generic workflows.

Agent Wiki / `ioi-memory` is the durable memory substrate. Adapter-local
"brains," scratchpads, summaries, embeddings, and vendor memory features are
adapters or projections over admitted memory. They do not own portable user,
project, org, worker, or managed-instance knowledge.

### Enterprise Learning Boundary Is A Cross-Cutting Facet

**Enterprise Learning Boundary** is the product-facing projection of the
canonical `InstitutionalLearningBoundaryProfile`. It is primarily configured in
Governance and organization/project/system settings, then rendered where a
specific source, route, job, derivative, export, or environment makes the
decision relevant. It must not become a fourteenth suite application, a second
privacy selector beside `Standard`/`Private`, or a new truth or authority plane.

The product should answer four concrete questions:

```text
What learning material is covered?
Where may it travel, in which representation, and under whose custody?
Which institution/provider uses and derivative rights are admitted?
Can the institution export the eligible capability and continue without this model?
```

Organization and project settings supply build defaults. Studio compiles them
into the proposed system package/genesis profile. The admitted live system
revision remains authoritative; a later organization-default change creates a
governed upgrade proposal rather than silently changing the system. Sessions,
GoalRuns, model invocations, transformations, and Foundry jobs snapshot that
boundary and may narrow it. Any widening requires explicit authority and a new
admitted decision.

Suggested projections remain contextual:

- Governance owns boundary policy, exceptions, declassification, export,
  deletion, revocation, incident, and system-upgrade review;
- Data and Ontology expose source-rights, consent, intended-use, recipe, and
  derivative-impact posture;
- Models and Developer Console expose the registered bidirectional
  provider/customer learning terms, retention, ZDR, custody, fallback, and
  provider-exposure configuration relevant to model and integration choice;
- Evaluations and Improvement protect private rubrics/corrections and show which
  eligible observations produced candidates, promotions, regressions, or
  rollback;
- Foundry shows the exact boundary, eligibility, source-rights, route-rights,
  destination scope, and export disposition before a job begins;
- Provenance derives a metadata-safe learning-flow graph from source through
  eligibility, use, derivative, promotion, egress/export, and revocation;
- Environments and Operations show actual placement, keys, custody, egress
  enforcement, and proof posture; and
- Home, Systems, and Work show only concise boundary health, blockers, and
  incidents appropriate to their context.

User choices such as ephemeral only, remember within the system, admit to a
private eval, or propose for private improvement are policy requests. They can
narrow or request an authorized transition; they are never toggles that override
source rights or the compiled system boundary.

The compact doctrine:

```text
Ask in ioi.ai.
Start or resume work from Home.
Build software in Projects.
Build workflows in Automations.
Open specialized tools in Applications.
Start, supervise, inspect, review, replay, and resume work in Work.
Open Sessions for bounded interactive, headless, or supervisory execution.
Run consequential work through Hypervisor Core, the daemon, wallet.network,
Agentgres, and receipt/replay boundaries.
```

## Lifecycle Lens

The product-management lifecycle is:

```text
Build
  Projects, Developer Workspace, Studio, Automations, Ontology, Data, Canvas,
  SDK/ADK/developer kit, Developer Console, Foundry, Packages facets

Run
  Systems, Work, Sessions, daemon runtime, providers, environments, cTEE,
  code execution, computer use, worker/model/tool routing, memory, restore

Govern
  Governance: wallet.network, authority scopes, capability leases, approvals,
  secrets, policy gates, privacy, declassification, risk, semantic governance,
  registries

Observe
  Provenance: receipts, replay, traces, logs, lineage, state roots;
  Evaluations: frozen judgment epochs, scorecards, holdout/exposure posture,
  evaluator validity, challenges, re-verification, quality alerts, feedback

Improve
  Improvement: direct proposals or optional campaign/agenda coordination,
  candidate comparison, synchronization, and target-owner change handoff;
  Foundry: candidate/evaluator asset construction, admitted experiments,
  models, workers, data recipes, and distilled ontology datasets;
  Governance: activation, canary/cohort, rollback, recall, and recovery decision

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
  proof refs, and deep links back to Governance, Operations, or Provenance
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

Systems
  stable System identity, active package/revision/constitution/profile refs,
  lifecycle summary, logical desired-versus-observed topology, health, and
  contextual deep links; Systems is a read model and never admits a transition

Work
  GoalRun, OutcomeRoom, AutomationRun, Session, WorkItem, WorkRun, review,
  incident, blocker, and history projections with typed canonical subjects

Operations
  queued/running/failed/retried infrastructure jobs; provider, placement,
  capacity, custody, member readiness, catch-up, verified roots, leases, writer
  epochs, fencing, RPO/RTO, degraded/partition posture, and admitted add, drain,
  promote, or remove operations

Operations resource facet
  queues, quotas, rate limits, capacity, utilization, spend, and budgets

Foundry
  dataset, evaluator-asset, candidate-build, admitted experiment, training,
  artifact conversion, registration, and promotion-bundle construction

Studio
  system-boundary/agent/harness/tool/memory-profile/memory-projection/
  authority/eval-readiness and worker/package candidacy; Studio packages
  constitution and deployment intents but never owns observed membership,
  writer, failover, or lifecycle truth

Automations
  trigger, workflow, service, API, schedule, catch-up, and run lifecycle

Evaluations
  eval-suite revision, frozen epoch, scorecard, holdout/exposure, evaluator
  validity, challenge, feedback-consent, and re-verification lifecycle

Improvement
  agenda, optional campaign, target/candidate lineage, synchronization cutoff,
  candidate nomination, and UpgradeProposal handoff lifecycle

Packages / Provenance
  package, release, install, publish, dependency, impact, recall evidence,
  contribution, and optional Marketplace/settlement handoffs

Governance / Work / Operations
  human approval and policy review (Governance), logical remediation/incidents
  (Work), and infrastructure remediation/support (Operations)

Provenance / Ontology
  dependency, provenance, and impact graph

Provenance
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
runs admitted experiments, Evaluations maintains independent judgment,
Improvement coordinates bounded change, Governance decides activation and
effect recovery, Marketplace/aiagent/MoW attributes external supply when
applicable, and Provenance inspects evidence.

## Application Surfaces

Application surfaces are major product modes inside one or more first-class
clients.

Implementation status — shell ownership program (2026-07-05): the product
shell is owned by ADOPTION, not recreation, so no "current version vs
recreated version" gap exists for discrepancies to hide in. The running
bundle is vendored as an editable source tree
(`apps/hypervisor/product-ui/owned/public`, built by
`apps/hypervisor/scripts/vendor-product-ui.mjs`: app chunks beautified, third-party
`vendor-*.js` verbatim, hand edits preserved as recorded owned-edits) and the
live estate serves from it (`IOI_PRODUCT_UI_PUBLIC`). Every ownership step is
gated by the shell-parity oracle (`verify-hypervisor-shell-parity.mjs`, 6
checks): per-file AST equivalence (esbuild minify(original) ==
minify(owned), byte-for-byte), wire equivalence for all 383 assets through
the real serve-time transforms, and a committed behavioral freeze
(`apps/hypervisor/shell-parity/`) covering DOM fingerprints, the runtime
animation inventory sampled through load (transient spinners included),
network manifest, and console signature per route. Intentional changes land
as owned-edits plus a reviewed baseline re-freeze in the same change; the
first fold (the augmentation script tag moving into the owned index.html) is
in. Serve-time code transforms must stay formatting-tolerant — they apply to
both the minified original and the beautified owned source.

### The Autonomous-Systems Owner Applications

The owner applications are durable expert workbenches over the lifecycle of a
bounded autonomous institution. Every application earns its place through one
distinct object/lifecycle job; an editor, graph, inbox, inspector, picker,
wizard, or report that lacks such a job is an owner-bound tool rather than a
peer application. Reference-product captures and parity certificates may
inform interaction design but never determine this taxonomy.

```text
Hypervisor Studio
  system and agent composition surface: typed canvas over real substrate
  objects — agents (model + harness + tools + memory + policies), the
  connections between them, and the system boundary (authority scopes, tool
  allow-lists via capability leases, budgets); saves draft blueprints and
  promotes them through governed gates; absorbs the former Agent Studio as its
  agent-level lens

Hypervisor Automations
  reusable workflow, trigger, schedule, monitor, API/service, approval-flow,
  queue, and process-graph definitions plus their activations;
  condition-over-object-set → governed effect is its core grammar

Hypervisor Ontology
  the semantic world-model systems act on: ontologies (object/link/action
  types), functions, value types, object exploration and saved object sets,
  ontology health and history — every semantic object carries its
  consent/visibility ladder

Hypervisor Data
  supply the world-model: sources/syncs, data recipes, datasets, time-series
  and media sets — nothing enters a system's view without a governed recipe,
  and every data object carries its consent posture; consumes connector
  bindings from Connections, never owns them

Hypervisor Governance
  authority and control surface: approvals inbox, authority scopes and
  capability leases, release gates, cohorts, kill switches, budgets,
  retention/marking policy, justification checkpoints; constitution and
  protected-amendment history, ordering/finality, oracle policy, successor and
  guardian paths, migration/fork/adoption, dissolution/decommission, and IOI
  Network enrollment/assurance are explicit high-assurance facets

Hypervisor Provenance
  the proof plane: chronological receipt stream, lineage graph of
  runs/artifacts/authority where every edge is a receipt, state roots, replay
  entries, custody receipts; exposes editable domain object -> immutable source
  snapshot -> derived export, including the exact tool/workflow revision,
  transformation run, and receipt for each derived edge; evolves the former
  Work Ledger card

Hypervisor Evaluations
  independent judgment surface: released eval-suite revisions, immutable
  evaluation epochs, visible/sealed/transfer/adversarial portfolios, scorecards
  over systems/agents/models, holdout custody and exposure, evaluator validity,
  challenges, re-verification, operator feedback with evidence-eligibility
  consent, quality dashboards, and start-from-object-set analyses

Hypervisor Improvement
  safe-change cockpit: immutable agenda revisions, optional multi-epoch
  campaigns, target/order and candidate lineage, negative knowledge,
  candidate comparison and nomination, synchronization cutoffs, improvement
  claims, direct proposals, what-if simulations, and target-owner activation/
  recovery handoffs; ordinary one-shot UpgradeProposal remains valid;
  Governance gates and decides activation while Improvement coordinates

Hypervisor Foundry
  candidate/evaluator asset builder and admitted experimental executor: model
  catalog, registry, model routes/mounts, tuning, persistent training pipelines,
  dataset factory runs, subordinate experiment optimization, artifact
  conversion, executable eval assets and jobs, interactive worlds, gameplay
  trajectory datasets, scenario curricula, world-model candidates, spatial-
  temporal policy candidates, transfer-gate candidates, tool-call audits,
  trajectory scorecards, datasets, endpoints, monitoring, worker/package
  creation, certification-run candidates, and ontology-aware capability builds;
  not campaign owner, evaluation-epoch truth, candidate-selection authority, or
  release owner

Hypervisor Embodied Systems (planned and nonlaunchable until built)
  native physical-operations surface: commission units, controllers,
  calibration, and exact resource groups; inspect admitted runtime graphs,
  profile/stratum placement, streams, policies, and local supervisors; prepare
  and observe graph activation without implying arming; allocate fleet work and
  reserve shared spacetime as separate leases; supervise live operations,
  intervention, telemetry, replay, incidents, recovery, and deployment-bound
  assurance. Studio authors graph source, Foundry produces candidates and
  evidence, Governance owns consequential admission, and the daemon plus
  Agentgres own execution and operational truth. The surface never becomes
  actuator authority or a safety controller.

Hypervisor Packages
  mandatory local package lifecycle: package candidates, immutable releases,
  dependencies, installed bindings, affected-System impact, deprecation,
  revocation, and receipted recall; Marketplace is an optional discovery,
  publishing, exchange, attribution, and organization-to-organization mode

Hypervisor Developer Workspace
  code, systems, workflow, workspace, editor, terminal, browser, and
  debugging surface, including development environment recipes and lifecycle
  observations where they help users start, inspect, restore, or tear down
  work; Workbench remains a compatibility alias

Hypervisor Developer Console
  extension surface: connector, connected-app, MCP, tool, and provider-
  integration registrations; APIs and OAuth/service registrations; function,
  widget, and extension registries; conformance; and developer-kit on-ramps
  (scaffolds, templates, generated SDKs). Environments and Operations own
  provider lifecycle, placement, health, capacity, and spend

Hypervisor Canvas
  visual builder/editor inside Studio, Automations, Developer Workspace, or
  Foundry where useful; not a separate product plane or runtime owner
```

Source-neutral tool placement is canonical at the owner boundary:

| Tool surface | Primary owner and placement |
| --- | --- |
| Pipeline Builder / Recipe Builder | Data / Recipes |
| Data Connections | Data / Sources |
| Ontology Manager | Ontology / Schema |
| Object Explorer | Ontology / Explore |
| Approvals | Governance / Approvals |
| Model Catalog | Foundry / Models |
| Marketplace | Packages / Marketplace |
| System Designer (legacy Solution Designer) | Studio / System Design |
| Process Graphs (legacy Machinery) | Automations / Process Graphs |
| Monitors (legacy Automate) | Automations / Monitors |
| Change Inbox (legacy Upgrade Assistant) | Improvement / Changes |
| Evaluation Suites (legacy AIP Evals) | Evaluations / Suites |

`Work / Incidents` and `Work / Reviews` are workspace views, not tool
registrations and not truth owners. The legacy Issues route resolves to
`Work / Incidents`. Each row keeps its typed work subject; incident and review
refs remain facets owned by the applicable domain or owner application, and
detail actions route there. This prevents a core workspace from masquerading
as a tool's primary owner.

These tool labels may be directly searchable and launchable, but direct launch
opens them under their primary owner and current Organization, Project, System,
Work, GoalRun, OutcomeRoom, or Session context. They do not become peer product
identities. Other specialized consoles, admin views, analytics, release
controls, replay, and data-recipe views remain owner-bound tools or contextual
projections.

Generated and installed extension applications are launchable
Applications-catalog entries. Studio authors interface descriptors; the
developer kit may scaffold them; Packages admits and versions them; Marketplace
may distribute them; the product-surface compiler exposes eligible installed
bindings. Creation method and distribution channel do not change the extension
application's registration class or grant it runtime, authority, System, or
Agentgres ownership.

User-facing configuration should prefer simple labels:

```text
Agent      configurable worker-backed agent or adapter
Mode       Agent | Plan | Goal
Model      product-facing model choice
Reasoning  Low | Medium | High | Extra high
Speed      Standard | Fast
Resolver   advanced scoped-step profile/adapter, hidden unless relevant
Execution  Auto | Pinned | Compare, shown when route plurality matters
```

`Agent` is the buildable product object. `Worker` remains the durable protocol
actor/package boundary. `Model` is the product-facing label; `ModelRoute`
remains the internal runtime object for provider, custody, fallback, spend,
privacy, eligibility, and invocation policy. `Resolver` is the power-user
label for a selected `HarnessProfile` or AgentHarnessAdapter. `RoleTopology`
and WorkflowTemplate own topology; the resolver owns only one scoped step.
Ordinary composer controls may continue to hide this distinction behind Agent
and Mode.

`Auto` means one eligible route or a declared verified escalation cascade;
`Pinned` means one selected eligible route with fail-closed fallback policy;
`Compare` means N-of-N attempts with visible verifier/synthesis and cost
lineage. These controls do not redefine Worker, ModelRoute, runtime node, or
party identity.

Application surfaces are not separate apps with separate runtime truth. They
are governed projections and control surfaces over Hypervisor Core, the
Hypervisor Daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
integrations.

Provider and infrastructure posture is part of Hypervisor's default session,
project, provider, and environment views.

## Hypervisor New Session

`New Session` launches one bounded governed execution/control context. It is
not generic chat, not a private UI state transition, and not an implicit way to
create an AutomationSpec, GoalRun, OutcomeRoom, or generic Mission object.

A New Session request should bind:

```text
intent
organization, project, system, application, or direct context when applicable
session mode: interactive | headless | supervisory
optional typed attachment: GoalRun | AutomationRun | WorkItem | OutcomeRoom
                           participant/claim/attempt
worker/model/tool route
execution policy: Auto | Pinned | Compare
contributor scope: My workers | Organization | Network / Open
managed-work budget ref and separate Network/Open goal-budget ref when used
provider and environment profile
authority scope
privacy posture
expected receipt shape
replay/eval posture
handoff destination
review and delivery contract
```

Execution/custody (`Standard` or `Private`), contributor scope, and placement
are orthogonal. Choosing Network/Open must not widen privacy, authority, data,
retention, or export policy. `Auto`, `Pinned`, and `Compare` are execution
policies over eligible routes, not subscription tiers.

Hypervisor Core admits the request through daemon, wallet.network, Agentgres,
privacy, provider, and receipt boundaries before consequential work begins.

A New Session may atomically bind organization/project/system context,
project/environment recipe, selected agent,
initial input, mode, model configuration, reasoning effort, speed/service tier,
harness selection, tools/connectors, memory policy, authority, budget, eval,
execution policy, contributor scope, Network/Open goal budget when applicable,
typed GoalRun/AutomationRun/WorkItem/room-work refs, and receipt posture. That
bundle is a daemon-admitted launch recipe, not a client-local chat setting.
Creating durable intent or standing behavior remains an explicit New Goal or
New Automation action even when a Session is attached immediately afterward.

Implementation status: live — New Session IS the product shell's polished
composer page (goal prompt, agent picker, project/URL/scratch intake), at
`/ai#new-session`; the rail's `+ New Session` action and Ctrl+O land there.
An Advanced-launch affordance on the composer opens the owned governed
launcher modal (registry-fed harness/model with disabled-reasons, venue
picker, placement preview) — one daemon-backed launch lane, no forked truth.

## Hypervisor Home

**Hypervisor Home** is the default command and resume surface.

Implementation status: live — Home is an owned EXPLORER rendered over the
shell at `/ai` (the rail's Home destination and default view), built from the
shell's own design tokens (`renderExplorer`/`applyAiViews` in
`apps/hypervisor/scripts/augmentation/` (modular `00-core.js`…`80-automations.js`), owns no truth): welcome hero
with a live summary; get-started actions (New Session / Applications /
Automations); first-class governed-work rows (approvals waiting, runs parked
at a wallet gate incl. `awaiting_authority_*` failover runs, failed runs —
each opening the OWNING surface in the Open Application slot, collapsing to
one all-clear line when quiet, naming a daemon outage rather than papering
over it); Recent tabs (sessions / projects / runs) with honest empty states;
and the Applications estate grid. It expands into the owned full readout
`/__ioi/home` (`renderHome` in `serve-product-ui.mjs`: decisions / blocked /
resume / newest-proof strips with honest empty + degraded states). The
composer is deliberately NOT the home page — it is New Session — and there is
no second "Home" entry in the Applications launcher.

Home may accept goal prompts, show recent typed Work subjects, surface waiting
approvals, and route the user into a System, Project, Automation, Application,
GoalRun, OutcomeRoom, Session, receipt, or replay. Home is allowed to draft
work, but it must not become the durable owner of systems, goals, automations,
projects, or sessions.

Home should stay a low-friction command and resume surface. Dense panes for
code, diffs, comments, terminals, ports, tasks, logs, or environment controls
belong in active Project, Developer Workspace, Session, or Open Application contexts where
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

**Hypervisor Projects** are persistent build and work-context containers. A
Project is not the live identity of a bounded autonomous System.

A Project may bind repositories, files, branches, packages, assets,
environments, adapter preferences, linked Systems, automations, GoalRuns,
sessions, policies,
secrets scopes, artifacts, receipts, and Agentgres domain links. Workbench is
the compatibility label for the IDE-grade **Developer Workspace** inside or
attached to a Project; the Project is the durable context object.

Project-owned product state is still admitted through the canonical owners:
daemon/Core for execution semantics, wallet.network for authority and secret
release, Agentgres for operational truth and restore validity, and storage
backends for bytes.

Correct:

```text
Open the Project.
Use Developer Workspace or an editor adapter to inspect and change it.
Resume the Project's typed Work and governed Sessions.
```

Avoid:

```text
Project = editor folder with no Agentgres identity
Workbench = parent product
editor adapter = project truth
Project = live System identity
```

## Hypervisor Systems

**Hypervisor Systems** is the stable inventory and contextual workspace for
live constitution-bound autonomous institutions. It projects one `system_id`
across package revisions, node membership changes, model-route changes,
upgrades, recovery, migration, succession, and dissolution. It is not a truth
store and never mints or mutates System identity by itself.

A System workspace provides the following contextual modes over existing
owners:

| Mode | Primary projections |
| --- | --- |
| Overview | identity, purpose, active revision, constitution/profile refs, lifecycle, health, and attention |
| Design | Studio, Ontology, Data, and Automations |
| Operate | Work, Automations, Environments, Operations, and Embodied Systems where applicable |
| Govern | Governance authority, budgets, protected change, learning boundary, lifecycle, and enrollment |
| Evidence | Provenance and Evaluations |
| Improve | Improvement, Foundry, and Governance |
| Interfaces | Studio, Packages, Developer Console, and admitted generated interfaces |

Systems may compare desired and observed topology, but Operations performs
admitted provider, placement, fencing, failover, and member actions; Governance
authorizes protected transitions; daemon/domain contracts execute; Agentgres
records admitted truth. A direct Session, Project, AutomationSpec, or standalone
GoalRun never requires System genesis.

Implementation status: target contract. Autonomous-system contract/API slices
exist in canon, but a complete policy-filtered Systems inventory, permanent
shell destination, and blank-to-genesis product path are not shipped.

## Hypervisor Work

**Hypervisor Work** is the unified core workspace for starting, supervising,
inspecting, intervening in, reviewing, replaying, and resuming heterogeneous
work. It is a policy-filtered read model, not a canonical `Work` object or one
universal lifecycle.

```text
Work / Active
Work / Goals
Work / Sessions
Work / Rooms
Work / Queues
Work / Reviews
Work / Incidents
Work / History
```

Every Work row declares a typed `subject_kind` and canonical `subject_ref` and
deep-links to the type-specific owner. Work may derive display facets across
GoalRun, OutcomeRoom, AutomationRun, Session, WorkItem, WorkRun, review, and
incident states, but it never writes one common status back over them. Policy
filtering occurs before search, counts, recents, aggregation, and caching.

System, Project, organization, and OutcomeRoom scope remain orthogonal to work
kind. System-bound work projects into `System / Operate`; direct, Project,
organization, and room work remains valid without a parent System unless its
own canonical contract requires one.

Implementation status: target contract. The existing Sessions root, jobs,
GoalRun views, automation-run views, and issue/blocker aggregates are migration
inputs, not proof that the unified Work workspace or typed projection is live.

Canonical routing follows the object model rather than preserving a retired
peer application:

```text
/work                         -> Work / Active
/work/goals                   -> Work / Goals
/work/sessions                -> Work / Sessions
/work/rooms                   -> Work / Rooms
/work/queues                  -> Work / Queues
/work/reviews                 -> Work / Reviews
/work/incidents               -> Work / Incidents
/work/history                 -> Work / History
/sessions                     -> compatibility alias for Work / Sessions
/missions                     -> compatibility alias resolved through typed legacy aliases
/missions/{legacy_subject_id} -> Work / Goals or Work / Rooms after typed resolution
```

New writes never mint a generic Mission id. A legacy Mission route must resolve
through `HypervisorLegacyWorkSubjectAlias` to one typed canonical subject before
rendering; unresolved or ambiguous aliases fail closed. Redirects preserve
organization, Project, System, query, hash, embedded-shell, backing-subject, and
Open Application context, then render the canonical breadcrumb and back-stack
identity rather than perpetuating Mission as a peer owner.
Typed details resolve beneath the matching view by canonical subject identity;
for example, `/work/queues/{work_queue_id}`,
`/work/reviews/{facet_projection_id}`, and
`/work/incidents/{facet_projection_id}`. A review or incident detail remains a
read-only Work facet whose source object deep-links to its canonical owner; the
route does not mint a generic review or incident work subject.

## Hypervisor Applications

**Hypervisor Applications** is the catalog, launcher, and vertical surface layer
inside Hypervisor.

An Application is a registered specialized UI/work surface over Hypervisor Core
that creates, inspects, modifies, or governs typed domain objects. Applications
may project Projects, Systems, Work subjects, Automations, Sessions, agents,
workers, models, environments, surface descriptors, extension applications,
Governance, Provenance, Packages, or other domain objects without owning their
truth. Older family labels such as `Providers / Environments`,
`Connections`, `Connectors / Tools / MCP`, `Data / Knowledge`,
`Ontology Studio`, `Workshop`, `Domain Blueprints`, `Authority / Govern`, `Release Controls`,
`Resource Management`, `Operations Center`, `Learning Center`, and
`Receipts / Replay` remain aliases or facets for those product surfaces.

Publisher identity, origin, creation method, distribution channel,
availability, admission state, installation state, package disposition,
enablement state, capability depth, and operational state are independent dimensions. A
first-party, organization-authored, developer-kit-generated, marketplace-
distributed, or vertical application remains a product surface, not a separate
runtime or authority owner.

The first-party owner set plus substrate lane is:

```text
Studio · Automations · Ontology · Data · Governance · Provenance ·
Evaluations · Improvement · Foundry · Packages · Developer Workspace ·
Developer Console
Environments · Operations   (substrate lane)
Embodied Systems            (conditional `owner_application`; `planned` and
                             nonlaunchable until built)
```

Applications may contain or manage Automations, Projects, or Sessions, but they
do not replace those durable object classes.

Applications is also the product breadth layer for installable or generated
surfaces. Repeated work should be promoted from private sessions into governed
patterns, templates, packages, workers, domain apps, or marketplace entries
when reuse, evaluation, installation, or settlement matters.

### Application Surface Registration Contract

Every durable Hypervisor application surface must have one discriminated
registration before it becomes first-class product inventory:

```text
surface_class
  owner_application
  substrate_application
  tool_surface
  extension_application
```

`extension_application` covers organization-authored, generated, installed,
and third-party application interfaces. Those attributes resolve through the
independent origin, creation, distribution, admission, installation, and
operational dimensions; they are not separate classes. Core workspaces use a sibling
`HypervisorCoreWorkspaceRegistration` so one product-surface compiler can serve
navigation and catalog projections without pretending Home, Systems, Projects,
Applications, or Work is an application.

An imported MCP App is a sandboxed extension surface, not a new runtime or
truth owner. Ephemeral rendering remains an invocation-scoped sandboxed view.
When the surface is durably installed, `extension_application` release,
admission, installation, enablement, System-binding, serving, action,
authority-preview, and revocation contracts own it like any other extension.
UI-initiated actions still cross the Hypervisor MCP Gateway,
RuntimeToolContract, daemon, policy, authority, and receipt boundaries.

The following dimensions remain independent:

```text
publisher_ref
  org://... | user://... | ioi://publisher/... | null

surface_origin
  first_party | organization | external_publisher

surface_creation_method
  hand_authored | studio_generated | developer_kit_generated | imported | adapted

surface_distribution
  bundled | direct_package | organization_catalog | private_registry | marketplace

surface_availability
  planned | preview | limited | available | deprecated | unavailable

surface_admission_state
  not_applicable | candidate | under_review | admitted | rejected | revoked

surface_installation_state
  not_applicable | not_installed | installing | installed | update_available |
  uninstalling | uninstalled

surface_package_disposition
  not_applicable | active | deprecated | superseded | recalled

surface_enablement_state
  not_applicable | enabled | disabled

surface_capability_depth
  browse | inspect | propose | act | workflow_complete

surface_operational_state
  inactive | starting | ready | serving | degraded | blocked | stopped | unavailable
```

`surface_availability` describes whether the product registration is offered;
`surface_admission_state` records registry acceptance;
`surface_installation_state` records the local binding transition;
`surface_package_disposition` records the bound release's lifecycle;
`surface_enablement_state` records the administrator or deployment decision
that permits ordinary launch;
`surface_capability_depth` declares the deepest permitted interaction; and
`surface_operational_state` reports current serving health. None is derived from
another, and a degraded installed application does not become uninstalled,
unadmitted, recalled, or less capable merely because its runtime is unhealthy.

A developer-kit-generated, marketplace-distributed extension application is
therefore still one extension registration. Marketplace distribution does not
turn it into the Packages owner, and `planned` does not create another
application kind.

`org://...` or `user://...` identifies the accountable organization or person
inside the deployment boundary, and `ioi://publisher/...` identifies an
admitted external publisher.
An `external_publisher` registration must carry a non-null
`ioi://publisher/...` ref. `publisher_ref: null` is permitted only for bundled
first-party registrations whose accountability is fixed by the release.

The record family is normalized so one stable definition never absorbs
per-release, per-installation, per-System, or per-runtime cardinality:

| Record | Cardinality and owned state |
| --- | --- |
| `HypervisorApplicationSurfaceRegistration` | one stable `surface://...` definition; class, publisher/origin, creation method, product availability, owner/job, routes, contexts, contracts, and obligations |
| `HypervisorRouteAliasRegistration` | one unique `route-alias://...` mapping owned by one workspace or application registration; static target or typed fail-closed resolver plus context-preservation rules |
| `HypervisorSurfaceReleaseRecord` | one immutable package release for that surface; distribution, admission, package disposition, capability depth, versioned descriptor, and exact executable contracts |
| `HypervisorSurfaceInstallationBinding` | one organization/project installation of one release; installation, deployment enablement, audience, allowed objects/actions, and authority preview |
| `HypervisorSystemInterfaceBinding` | one installation bound to one admitted System; System-specific enablement and narrower audience, allowed objects/actions, and authority preview |
| `HypervisorSurfaceServingBinding` | one serving route/runtime for an installation or System binding; operational health only |
| `HypervisorProductSurfaceProjection` | one request-scoped policy-filtered join; selected and eligible binding refs, groups, launchability, disabled reasons, and typed launch target |

The normalized family collectively declares:

- stable surface id, display name, summary, surface class, family,
  publisher identity, origin, creation method, distribution channel, availability,
  admission state, installation state, package disposition, enablement state,
  capability depth, and operational state;
- distinct package, immutable release, installation-binding, and optional
  System-binding refs where the surface is packaged or installed;
- canonical route, compatibility aliases, canonical owner doc, primary owning
  object family, and optional consuming/contextual application ids;
- primary user job, supported roles, and supported placements: Applications
  catalog, Open Application, Home, Project, System, Work, GoalRun, OutcomeRoom,
  AutomationRun, Session, organization/admin, or operator console;
- composition pattern: list/detail, command/search, modal wizard, canvas/editor,
  object view, graph view, review inbox, monitoring console, lineage/replay
  view, lifecycle strip/detail drawer, package/install flow, or generated
  domain surface;
- launch modes and typed target bindings, including Project/System/Work/Session
  compatibility;
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
- ontology and developer-kit posture where applicable: DomainOntology refs,
  CanonicalObjectModel refs, DataRecipe refs, PolicyBoundDataView refs,
  OntologyProjection refs, OntologySurfaceDescriptor refs, and generated
  artifact refs;
- package, release, install, favorite, recent, recommended, and Marketplace metadata where
  applicable.

A tool registration additionally declares exactly one primary owner, a tool
kind (`editor`, `inspector`, `picker`, `inbox`, `graph`, `wizard`, `report`,
`dashboard`, `comparison`, or `console`), object/action contracts, and its
inspect/propose/effect boundary. A tool may have many contextual consumers.
Shared code-level UX primitives are not multi-owner tool registrations.
Before a shared primitive becomes canonical substrate, at least two owner or
substrate surfaces should consume it or its promotion should be justified by a
cross-surface conformance requirement. Its code package may have a maintainer,
but product truth remains with each consuming registration and object owner.

An extension registration additionally links distinct package candidate,
admitted release, installation binding, serving binding, disable, recall, and
revocation refs. A draft or organization-wide tool may omit a System binding.
An effectful System interface must bind an admitted package, installation,
System/context, allowed-action, and authority-preview contract before launch.
An `OntologySurfaceDescriptor` is an input to this registration; it is not a
launchable application by itself.

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

Kit-generated surfaces must pass the same registration contract as hand-authored
surfaces. The developer kit (ODK) may scaffold the descriptor, code,
fixtures, test cases, package skeletons, and conformance checks, but generated
React, templates, examples, or local descriptors are not runtime truth,
authority truth, semantic truth, or marketplace truth. Durable generated
surfaces still bind to Hypervisor Core, daemon APIs, Agentgres ontology/object
refs, policy-bound views, authority requirements, receipts, replay, and
conformance profiles.

### Product-Surface Compiler

Navigation, Applications, command-palette, contextual launch, search, recent,
favorite, and recommendation projections must be produced from one compiler:

```text
core-workspace registrations
  + static owner, substrate, tool, and planned registrations
  + typed route-alias registrations
  + daemon/Agentgres-admitted release, installation, System-interface,
    and serving records
  + authenticated organization and user preferences
  + Organization, Project, System, GoalRun, OutcomeRoom, AutomationRun,
    Session, WorkQueue, WorkItem, and WorkRun typed context
  + Work workspace route/filter state, which never becomes a work:// identity
  -> request-scoped policy-filtered product-surface projection
```

Policy filtering occurs before aggregation and caching. One stable registration
appears once even when it matches several groups. Drafts never appear as
ordinary launchable apps. Disable, recall, and revocation remove launch
eligibility immediately. Partial daemon or preference-service failure preserves
safe static first-party inventory without leaking cached organization, user, or
System state. Release identity, installation-binding identity, and System-
binding identity remain distinct even when one catalog row joins all three.

The compiled catalog exposes stable user-meaningful groups without turning
them into new registrations:

```text
First-party applications
Tools for this context
Organization applications
Installed applications
System interfaces
Recommended for this context
Recent and favorites
```

A registration may appear in several groups but retains one identity, primary
owner, canonical route, and typed launch binding.

Capture provenance, screenshots, pixel certificates, and parity matrices may
remain implementation evidence on a tool registration. They have zero authority
over registration class, catalog membership, owner, capability, or maturity.

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
governed System/genesis wizard
typed object/resource picker
canvas/editor projection
object view
object-view editor
graph view
review/approval inbox
monitoring or resource console
lifecycle strip / release-control detail drawer
authority preview drawer
desired-versus-observed topology
lineage/replay/evidence view
incident/remediation queue
proposal/diff/simulation drawer
artifact/build/job view
package/install/publish flow
generated/installed application frame
executable walkthrough
Organization / Project / System / Application / Tool / Object breadcrumb
honest empty/degraded/blocked/read-only/permission-denied states
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

### Bounded-System Builder Experience Contract

Hypervisor must compress the architecture into one ordinary creation journey
without weakening any owner boundary:

```text
blank or installable template
  -> describe the institution, people/agents, resources, actions, and success
  -> Studio compiles one inspectable package/genesis proposal
  -> validate contracts and show typed blockers
  -> preview authority, policy, cost, topology, evidence, and lifecycle
  -> simulate the selected work and consequential effects where applicable
  -> propose and approve through the existing owner paths
  -> instantiate one stable System
  -> operate it through Systems, Work, and its generated interfaces
  -> inspect every material decision, effect, result, and receipt
  -> upgrade, recover, migrate, suspend, recall, or dissolve through governance
```

The visual Studio, declarative files, ADK, SDK, and CLI are editors and
projections over one source-neutral build representation. They may optimize for
different users, but they must compile the same package, profile, ontology,
action, policy, authority, evidence, deployment, lifecycle, surface, and
admission contracts. A user may move from a compact guided form to the complete
typed declaration and back without losing meaning, inventing hidden defaults,
or forking truth.

The default flow uses product language—System, goals, agents, data, actions,
permissions, evidence, and recovery—and progressively discloses protocol nouns.
Advanced users can inspect every resolved ref, hash, policy source, override,
and receipt. Templates prefill declarations but never pre-authorize effects,
claim evidence coverage, choose hidden provider rights, or create live state.

The builder is successful only when a first-time operator can create, validate,
simulate, admit, operate, inspect, and retire a bounded institution without
manual database edits, private backend surgery, or a second bespoke application
workflow. Fast composition is therefore a product acceptance contract over the
canonical owners, not permission for Studio to absorb their state or authority.

Application surface modes should be treated as first-class catalog or
contextual inventory when they matter to product outcomes. They are not
permanent rail items, but they should not be hidden as vague panels either.

Relevant surface modes include:

```text
Automations tool/function builder
blueprint / generated-surface builder (Studio; kit-scaffolded)
system designer / architecture planner (Studio)
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

Each mode should be classified under an owning surface, such as Studio,
Automations, Ontology, Data, Governance, Work, Provenance, Evaluations,
Improvement, Foundry, Packages, Projects / Developer Workspace, Developer
Console, or the substrate lane (Environments, Operations). Older family labels such as
`Data / Knowledge`, `Ontology Studio`,
`Workshop`, `Domain Blueprints`, `Providers / Environments`,
`Release Controls`, `Resource Management`, `Authority / Govern`,
`Receipts / Replay`, and `Patterns / Examples / Training` are aliases or
facets, not separate product surfaces.

## Hypervisor Operator Plane

The Hypervisor Operator Plane is the governed control-plane surface and
operation lane for operating Hypervisor itself.

It is not ioi.ai, not a child Session or HarnessInvocation, and not an ambient host
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

Selected AgentHarnessAdapters and their child HarnessInvocations may request,
propose, or explain platform actions. They
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
flows housed primarily in Automations and Developer Console. It may
appear in Applications, in Automations node creation, in project context, or in
package/pattern flows. Its outputs compile into `RuntimeToolContract`,
primitive capability declarations, authority scopes, schema validation, receipt
obligations, and optional Automations nodes.

**Surface Generate** (Studio, scaffolded by the developer kit) is the product
path for object-aware application shells, widgets, forms, dashboards, operator
consoles, autonomous-system blueprints, and generated domain apps. It may use
ontology object/action/value types, data recipes, Developer Workspace code, Automations,
tool contracts, and package metadata.

These builder paths are proposal and packaging paths over Hypervisor Core. They
do not own runtime truth, authority, semantic truth, or storage truth. Effectful
actions they expose to agents must use the Hypervisor Operator Plane, daemon
admission, authority-provider gates as required, Agentgres, and receipts.

## Learning, Patterns, Examples, And Training

**Learning / Patterns / Examples / Training** is an enablement facet, not a
standalone product surface. It may appear in Home, Applications, Packages,
Foundry, Studio, Ontology, Data, and onboarding flows when a recipe can become
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
  Studio, Developer Workspace, Automations, Foundry, Ontology, or Data
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

## Hypervisor Developer Workspace

**Hypervisor Developer Workspace** is the code/systems/workspace surface.
`Workbench` and `HypervisorWorkbench` remain compatibility labels for existing
routes, packages, APIs, and saved links during migration; they are not a second
product identity.

Developer Workspace may appear in:

- Hypervisor App;
- Hypervisor Web;
- remote browser workspaces;
- VS Code-family adapters;
- Cursor, Windsurf, JetBrains, and other editor adapters;
- terminal/tmux-oriented operator views.

Developer Workspace can open and operate Sessions through many editors. The editor is an
adapter target, not the product identity.

## Hypervisor Automations

**Hypervisor Automations** is the reusable-standing-behavior surface over
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
- AutomationRun history, resulting GoalRun/Session/WorkRun refs, receipt views,
  and replay links;
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
monitor / condition-over-object-set
approval flow
service/API endpoint
queue worker
marketplace service recipe
```

The durable reusable object is `AutomationSpec`; one activation is an
`AutomationRun`. An AutomationRun may finish directly, request one or more
bounded Sessions/WorkRuns, explicitly create or link one or more GoalRuns, or
contribute typed work to an existing OutcomeRoom. It does not become a GoalRun
merely because it is long-running, headless, or bound to a System.

```text
AutomationSpec
  -> exact AutomationInstallationBinding
  -> AutomationRun
      -> direct result or approval-only completion
      -> optional Session(s) / WorkRun(s)
      -> optional explicit GoalRun(s)
      -> optional typed OutcomeRoom contribution
```

Background, interactive, and supervisory are execution modes on Sessions,
WorkRuns, RuntimeAssignments, or participants. They are not Automation or
Mission object kinds. System, Project, organization, and room scope are
expressed by the exact AutomationInstallationBinding and remain orthogonal to
AutomationSpec and AutomationRun identity.

ioi.ai may hand off a collaborative outcome into Automations when a goal needs
many models, harnesses, workers, sessions, branches, connectors, or verifier
lanes. The ioi.ai coordination pattern is owned by
[`../../domains/ioi-ai/collaborative-outcome-pattern.md`](../../domains/ioi-ai/collaborative-outcome-pattern.md).

The durable handoff binds the OutcomeRoom/CollaborativeWorkGraph directly and
creates or links explicit AutomationRuns, GoalRuns, WorkItems, WorkRuns, and
Sessions as required. Automations owns reusable triggers, schedules, services,
and workflow graph shape; it does not own room participation, shared-frontier
admission, local participant truth, or generic attempt/finding semantics. Each
claimed work item resolves through a bounded GoalRun. Dynamic
join/sleep/wake/retire/quarantine and claim/resource leases remain room-level
contracts rather than hidden automation state. No generic `HypervisorMission`
wrapper is created.

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

Canvas may appear inside Automations, Developer Workspace, or Foundry. Its default home
for durable workflows and services is Automations.

Canvas may display:

- nodes and edges;
- typed step contracts;
- trigger and schedule refs;
- approval and policy checkpoints;
- cTEE/privacy posture;
- receipt and replay projections;
- harness, model, worker, service, verifier, and provider selection hints;
- OutcomeRoom frontier, participant, claim, attempt, finding, verifier-
  challenge, authority, budget, and contribution-lineage projections when
  opened from Work / Rooms or a Goal Space handoff.

Canvas does not own execution, authority, state truth, receipts, or workflow
semantics. It edits or visualizes objects owned by Automations, the Workflow
Compositor, Foundry, Work subject owners, or other product surfaces.

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

## Hypervisor Evaluations

**Hypervisor Evaluations** owns independent judgment lifecycle over Hypervisor
Core. It releases evaluation-suite revisions, freezes exact target, incumbent,
task-distribution, evaluator, threshold, statistical, and applicability roots
into `EvaluationEpoch` contracts, maintains protected-evaluation exposure and
evaluator-validity lineage, and coordinates challenges and re-verification.

Foundry, Developer Workspace, Data, Ontology, and domain owners may build
evaluation assets. The daemon executes admitted evaluation jobs. Evaluations
owns neither those build/execution lifecycles nor campaign selection or release
authority. It owns the judgment boundary by which their observations become
decision-bearing evidence.

Evaluations is owned in detail by [`evaluations.md`](./evaluations.md).

## Hypervisor Improvement

**Hypervisor Improvement** is the optional campaign and safe-change cockpit over
Hypervisor Core. It authors immutable ImprovementAgenda revisions, coordinates
multi-epoch ImprovementCampaign state around bounded GoalRuns, renders target/
candidate ancestry and negative knowledge, coordinates adjacent-order evidence
cutoffs, records an attributable candidate nomination, and constructs the
target-specific `UpgradeProposal` handoff.

The direct change path remains canonical for ordinary one-shot patches. A
campaign is used only when adaptive or multi-epoch work needs durable candidate,
evaluation-exposure, synchronization, or recursive-seat lineage. Improvement
does not own execution, evaluation truth, or release authority; Governance and
the target owner admit protected work and decide activation and effect recovery.

Improvement is owned in detail by [`improvement.md`](./improvement.md).

## Hypervisor Foundry

**Hypervisor Foundry** is the candidate/evaluator asset builder and admitted
experimental executor for worker/model/eval/persistent-training/dataset/
registry/endpoint/package work over Hypervisor Core.

Foundry produces and improves things that other surfaces use:

- model catalog entries and model cards;
- model registry entries, model routes, and model-mount candidates;
- WorkerPackages and worker manifests;
- datasets, feature views, ontology-bound datasets, and holdouts;
- dataset factory runs, persistent training pipelines, subordinate experiment
  optimization cycles, artifact conversion runs, endpoints, batch inference,
  metadata, and monitoring projections;
- eval-suite, benchmark, eval-world, scorer, and verifier candidates plus
  admitted experimental and reproduction jobs;
- training, distillation, fine-tuning, and dataset recipes;
- quality gates and promotion proposals;
- package publication proposals for aiagent.xyz or private catalogs.

Foundry may consume Automations traces, Developer Workspace runs, agent
corrections, receipts, and evaluation results, but it does not directly
self-mutate the runtime. Its experiment optimizer is a subordinate execution
profile that may link to an ImprovementCampaign and EvaluationEpoch; it does
not own the campaign, freeze evaluation truth, select the release candidate, or
make the release decision. Durable improvements enter through governed
proposals, independent eval gates, wallet.network approvals when needed, and
Agentgres admission.

Foundry also binds the active `InstitutionalLearningBoundaryProfile`, individual
training-evidence eligibility, source rights, model-route rights, derivative
lineage, and revocation impact before it consumes evidence or promotes a derived
artifact. A green learning-boundary projection is never ambient permission to
train on every trace.

Foundry is owned in detail by [`foundry.md`](./foundry.md). ioi.ai may consume
Foundry evals and promote lessons into Foundry proposals, but ioi.ai
coordination is not Foundry and Foundry is not a chat room.

## Hypervisor Packages

**Hypervisor Packages** is the mandatory local lifecycle owner for reusable
release material. It manages package candidates, immutable admitted releases,
dependencies, installation bindings, serving eligibility, affected-System
impact, deprecation, disable, recall, revocation, rollback inputs, and the
receipts that connect those transitions. A package may carry an application,
RuntimeToolContract, Worker, GoalRunProfile revision, WorkflowTemplate
revision, HarnessProfile revision, SkillManifest revision, AutomationSpec
revision, ontology/DataRecipe bundle, System profile, generated interface, or
other typed artifact without erasing that artifact's own canonical object
contract.

Packages contain immutable definitions, requirements, compatibility pins, and
templates. They never contain SkillEntries, ActiveSkillSetSnapshots, concrete
MCP gateway profiles, ContextLeases, RuntimeAssignments, authority grants,
connector credentials, or subject/session/run-scoped bindings. A package may
carry an MCP gateway requirement or immutable template reference; the concrete
`mcp_gateway://...` profile is separately admitted and revocable for live work
or a live System.

Package admission does not grant runtime authority, create a live System, or
make an application launchable by itself. Installation and serving remain
explicit bindings evaluated against organization, Project, System, policy,
capability, dependency, environment, and authority context. Agentgres retains
admitted package/install truth; daemon/Core executes admitted effects;
wallet.network governs protected authority; Packages supplies the lifecycle
projection and requests those owners admit transitions.

Marketplace is an optional Packages mode and distribution channel for
discovery, publishing, exchange, attribution, commercial terms, and
organization-to-organization acquisition. A private or air-gapped deployment
must retain complete package, release, install, disable, recall, and revocation
semantics without Marketplace. The compatibility route `Marketplace` resolves
to `Packages / Marketplace`; it never becomes a second package owner.

Recall and revocation are not cosmetic catalog states. The product-surface
compiler must immediately remove ineligible launches, expose affected installs
and Systems, and route protected stop, rollback, migration, or remediation
actions through their canonical owners. Packages must not silently mutate or
terminate a live System merely because one release changes state.

Implementation status: target canonical owner. Package and worker-package
concepts exist across current surfaces, but the unified Packages workspace,
admitted install registry, compiler integration, and Marketplace-as-mode route
migration are not yet fully shipped.

## Workflow Compositor

**Workflow Compositor** is the high-level directed-work surface over Hypervisor
Core. It is a shared graph/projection model used by Automations, Developer Workspace,
Foundry, other application surfaces, Environments views, and
SDK/ADK/ODK clients when work needs explicit structure.

Its reusable canonical object is `WorkflowTemplateEnvelope`: an immutable,
content-addressed directed graph revision. A template never runs itself.
`AutomationSpec`, `GoalRun`, `AutomationRun`, `WorkRun`, a Foundry job, or
another typed run owner supplies activation and execution identity.

The compositor owns:

- service and workflow graph shape;
- typed step contracts;
- dependencies and handoff edges;
- acceptance criteria and review points;
- change-plan gates, rollout cohorts, maintenance windows, suppression windows,
  recall/remediation handoff edges, and blocked-reason projections;
- delivery contract and immutable WorkflowTemplate revisions;
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
- the selected HarnessProfile's internal loop.

The Workflow Compositor and CollaborativeWorkGraph are complementary, not
aliases. The compositor owns a declared directed WorkflowTemplate. The
collaborative graph owns a live, potentially changing frontier of questions,
hypotheses, claims, attempts, findings, resources, and verifier challenges.
Room admission may materialize frontier work as GoalRuns or durable Automation
steps, but a sea-of-agents topology is not hard-coded into either substrate.

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
Profile is the reference scaffold/fallback profile. External agent harnesses such as
Codex, Claude Code, Grok Build, OpenHands, Aider, DeepSeek TUI-like runtimes,
or Hermes-like runtimes are mediated through exact AgentHarnessAdapter
revisions. A semantic HarnessProfile may select or constrain a compatible
adapter, but vendor/process mechanics never become a HarnessProfile family.
The resulting HarnessInvocation must emit the common boundary objects and obey
daemon gates.

## GoalRun Profiles

`GoalRunProfile` is the reusable product object for adaptive pursuit. Studio
may author and compare profile revisions; Packages versions, distributes,
recalls, and revokes released revisions; Work / Goals and ioi.ai select or
explain the profile for a GoalRun; Improvement proposes successor revisions;
Provenance exposes the resolution snapshot and receipt. None of those surfaces
creates a second runtime owner.

New Goal UX may present a friendly Recipe or mode name, but the backing
`goal-run-profile://.../revision/...` ref must be inspectable. Direct ad hoc
work resolves through the versioned generic-adaptive profile. Advanced editors
may expose optional WorkflowTemplate refs, role/topology requirements,
SkillManifest and tool requirements, verifier and acceptance contracts,
budgets, stop/recovery/escalation policy, compatible domains, and permitted
override schema. They must not embed credentials, live leases, selected
RuntimeAssignments, attempts, artifacts, or domain lifecycle state.

## Hypervisor Sessions

**Hypervisor Sessions** are bounded governed execution/control contexts managed
through Hypervisor Core. A Session may be `interactive`, `headless`, or
`supervisory`; headless does not imply a different durable work kind.

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

A Session binds:

- user, organization, project, system, or worker context when applicable;
- its explicit session mode;
- AutomationRun or GoalRun refs when it executes part of standing behavior or
  pursued intent;
- work item and work run refs when the session is executing delegated agent
  work;
- authority grants and capability leases;
- policy and approval state;
- runtime assignment;
- context cell / task refs where applicable;
- GoalRun plus optional OutcomeRoom, participant, claim, and attempt refs when
  the session performs collaborative frontier work;
- cTEE custody posture where applicable;
- Agentgres refs and receipt obligations;
- adapter targets;
- replay and restore metadata.

Sessions are bounded execution truth windows. A Session view should be able to show
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

For OutcomeRoom work, a session is one participant/claim/attempt drilldown, not
the room itself. Work / Room detail owns the graph-first shared view; Sessions own
the bounded execution view. A background participant must expose claim, lease,
heartbeat/wake, spend, evidence, verification, blocker, and cancellation or
quarantine projections rather than only transcript tokens.

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
  -> policy-eligible eval data and failure clusters
  -> direct UpgradeProposal or optional ImprovementCampaign
  -> Foundry and other target owners build immutable candidates
  -> Evaluations freezes and applies independent judgment
  -> candidate nomination and target-specific UpgradeProposal
  -> Governance activation, continued review, rejection, or effect recovery
  -> better routing and work acceptance
```

Improvement, Evaluations, Foundry, Governance, Automations, Applications,
Sessions, Receipts/Replay, and marketplace surfaces should expose this loop
without giving any one UI surface runtime truth. An ordinary change does not
need a campaign, and a campaign never bypasses the target owner's standard
change path.

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

When the external harness is connected through a Goal Space, adapter launch is
preceded by a `LocalAgentPairingSessionEnvelope`. Pairing binds the candidate's
generated public key and origin but supplies no room membership or authority.
The admitted participant lease and post-admission gateway profile determine the
permitted projection, proposal, and tool surface; the harness never receives an
organization-wide token or ambient workspace/room access.

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

AgentHarnessAdapter
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

External harnesses, Developer Workspace, Automations, Foundry, Canvas views, Hypervisor
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

## Systems, Projects, Work, Goals, Automations, Rooms, And Sessions

These product and protocol concepts remain distinct:

| Object or surface | Durable meaning | Must not collapse into |
| --- | --- | --- |
| Project | Build/work context: repositories, files, environments, drafts, receipts, and defaults | Live System identity |
| System | One constitution-bound institution across releases, nodes, models, recovery, and migration | Package, node, process, GoalRun, Session, or UI |
| Package | Reusable versioned release material that may instantiate many Systems | Live membership or System lifecycle |
| Work | Read-only core workspace over typed pursued/executing/review subjects | Runtime, authority, evidence truth, or universal lifecycle |
| AutomationSpec | Reusable trigger, schedule, monitor, workflow, service, API, queue, or approval-flow definition | One activation, GoalRun, or transcript |
| AutomationInstallationBinding | Successor-versioned scope enablement and narrowing overlay for one exact AutomationSpec | Trigger/graph definition, one activation, concrete grant, or execution truth |
| AutomationRun | One activation freezing the exact WorkflowTemplate, AutomationSpec, and AutomationInstallationBinding | Reusable definition or durable collective objective |
| GoalRun | Durable bounded outcome pursuit with constraints, continuation, attempts, verification, and course correction | Automation definition or Session transcript |
| OutcomeRoom | Persistent shared pursuit above admitted participant GoalRuns | Every goal, global swarm, or Mission wrapper |
| Session | Bounded interactive, headless, or supervisory execution/control context | Durable intent or reusable trigger definition |
| WorkRun | One governed execution attempt of a WorkItem inside a Session/environment | Goal identity or shared room frontier |
| Node | Admitted deployment member with declared role, leases, failure domain, and observed state | System identity or automatic authority |
| Application | Registered owner, substrate, tool, or extension control surface | Runtime, authority, or canonical truth |

The canonical relationship model is:

```text
human / API / System event -> optional GoalRun
AutomationSpec + exact AutomationInstallationBinding
  -> AutomationRun -> direct completion or explicit GoalRun(s)
OutcomeRoom -> accepted participant GoalRun(s)
GoalRun -> zero or more Sessions over time
Session -> zero or more WorkRuns
WorkRun -> results, evidence, receipts -> GoalRun and optional OutcomeRoom
```

A GoalRun survives Session termination, worker replacement, compaction, sleep,
restore, and course correction. A direct terminal/editor/environment/provider
Session may exist without a GoalRun. An AutomationRun may finish without a
GoalRun and, when no managed execution occurs, without a Session. An
OutcomeRoom can outlive every participating Session.

For a persistent collective outcome, Work / Room detail is graph-first:

```text
objective, acceptance, constraints, deadline, visibility, stop policy
work frontier and typed state
participants, affiliations, leases, heartbeat/wake, spend, and blockers
claims, attempts, findings, negative results, contradictions, and evidence
evaluation, guardrails, Pareto frontier, verifier versions and challenges
approvals, authority/privacy incidents, pause, kill, and quarantine
contribution and derivation lineage
replay explaining topology, budget, verifier, and course corrections
```

A live feed or chat is a social projection over this graph, not its truth. The
product must not add a permanent Mission or Swarm application. `Mission` may be
an optional label or creation preset only when it resolves to exactly one typed
GoalRun or OutcomeRoom subject. It creates no independent canonical id,
authority, lifecycle, budget, status, evidence, or receipts.

If a future sponsor engagement proves it needs a distinct multi-goal
acceptance, service-level, termination, budget, and authority lifecycle, add a
narrow `OutcomeContract` or `ServiceOrder`. Do not revive Mission as a
polymorphic wrapper around unrelated work kinds.

This retirement is deliberately narrow. Typed domain language and objects such
as `PhysicalMissionControlEnvelope`, `FleetMissionCoordinationRecord`, and
`FleetMissionAllocationLease` remain valid. Their generic work binding resolves
through an explicit GoalRun or discriminated work-subject ref rather than a
generic `HypervisorMission` identity.

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
When a support bundle, telemetry export, crash report, screenshot, model call,
or human-review packet crosses an institutional learning boundary, it also
requires the applicable `LearningEgressReceipt` posture. The receipt records
IOI-observed admission or pre-egress blocking; it does not prove a recipient's
hidden deletion, retention, or learning behavior.

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
    - systems
    - projects
    - applications
    - automations
    - work
    - sessions
    - developer_workspace
    - foundry
    - agents
    - services
    - models
    - privacy
    - receipts
  adapter_targets:
    - adapter_target:...

HypervisorCoreWorkspaceRegistration:
  workspace_id: hypervisor-workspace://...
  workspace_kind: home | systems | projects | applications | work
  workspace_key: string # URL-safe; equals workspace_kind in taxonomy v2
  display_name: string
  canonical_route: string
  route_alias_refs: [route-alias://...]
  supported_context_kinds:
    - organization | project | system | goal_run | outcome_room |
      automation_run | session | work_queue | work_item | work_run
  registration_is_projection_only: true
  writes_through_canonical_owners: true

HypervisorRouteAliasRegistration:
  route_alias_ref: route-alias://...
  owner_ref:
    hypervisor-workspace://... | surface://...
  alias_route_pattern: string
  resolution:
    one_of:
      - kind: static_route
        target_route_template: string
      - kind: typed_resolver
        resolver_kind:
          legacy_work_subject | contextual_surface | package_marketplace
        resolver_contract_ref: api://...
  preserve_context:
    query: true
    hash: true
    embed_and_return_state: true
    open_application_identity_and_back_stack: true
    typed_context_kinds:
      - organization | project | system | goal_run | outcome_room |
        automation_run | session | work_queue | work_item | work_run
  failure_mode: fail_closed

HypervisorApplicationSurfaceRegistration:
  surface_id: surface://...
  surface_key: string # URL-safe and unique in one deployment catalog; never inferred from surface_id
  surface_class:
    owner_application | substrate_application | tool_surface |
    extension_application
  family_id: string
  display_name: string
  publisher_ref:
    org://... | user://... | ioi://publisher/... | null
  surface_origin: first_party | organization | external_publisher
  surface_creation_method:
    hand_authored | studio_generated | developer_kit_generated | imported |
    adapted
  surface_availability:
    planned | preview | limited | available | deprecated | unavailable
  summary: string
  primary_user_job: string
  canonical_route: string
  route_alias_refs: [route-alias://...]
  canonical_owner_doc_ref: doc://...
  primary_owner_application_ref: surface://... | null
  primary_object_family: string
  declared_object_contract_refs:
    [ontology://... | object-model://... | object-set://... | schema://...]
  declared_action_contract_refs:
    [ontology-action://... | action://... | tool://... | mcp://...]
  tool_surface_contract:
    required_when: surface_class == tool_surface
    otherwise: null
    tool_kind:
      editor | inspector | picker | inbox | graph | wizard | report |
      dashboard | comparison | console
    object_contract_refs:
      [ontology://... | object-model://... | object-set://... | schema://...]
      # definition-level ceiling; release owns the exact executable set
    action_contract_refs:
      [ontology-action://... | action://... | tool://... | mcp://...]
      # definition-level ceiling; release owns the exact executable set
    capability_descriptor_refs: [capability://...]
    required_primitive_refs: [prim:...]
    required_scope_refs: [scope:...]
    shared_primitive_refs: [ui-primitive://...]
    evidence_refs: [artifact://...]
  consuming_surface_refs: [surface://...]
  supported_context_kinds:
    - organization | project | system | goal_run | outcome_room |
      automation_run | session | work_queue | work_item | work_run
  supported_roles: [string]
  supported_placements:
    - permanent_shell | applications_catalog | open_application | home |
      project | system | work | goal_run | outcome_room | automation_run |
      session | organization_admin | operator_console
  composition_pattern: string
  launch_modes:
    - direct | contextual | open_application | command_palette | api
  daemon_api_dependency_refs: [api://...]
  agentgres_projection_refs: [agentgres://projection/...]
  declared_operator_contract_refs: [tool://... | mcp://...]
  effect_boundary: inspect_only | propose_only | effectful
  mutation_boundary:
    child_request | operator_plane | human_admin | not_applicable
  authority_policy_refs: [policy://...]
  privacy_policy_refs: [policy://...]
  receipt_policy_refs: [policy://...]
  replay_policy_refs: [policy://...]
  evaluation_policy_refs: [policy://...]
  promotion_policy_refs: [policy://...]
  ontology_refs:
    [ontology://... | object-model://... | data-recipe://.../revision/... | view://...]
  parity_evidence_refs: [artifact://...] # evidence only; never membership authority

HypervisorSurfaceReleaseRecord:
  release_ref: package://.../release/...
  surface_ref: surface://...
  package_ref: package://...
  surface_distribution:
    - bundled | direct_package | organization_catalog | private_registry |
      marketplace
  surface_admission_state:
    not_applicable | candidate | under_review | admitted | rejected | revoked
  surface_package_disposition:
    not_applicable | active | deprecated | superseded | recalled
  surface_capability_depth:
    browse | inspect | propose | act | workflow_complete
  descriptor_ref: surface-descriptor://... | artifact://...
  object_contract_refs:
    [ontology://... | object-model://... | object-set://... | schema://...]
  action_contract_refs:
    [ontology-action://... | action://... | tool://... | mcp://...]
  operator_contract_refs: [tool://... | mcp://...]
  dependency_release_refs: [package://.../release/...]
  admission_decision_ref: decision://... | null
  agentgres_operation_refs: [agentgres://operation/...]
  state_root_ref: agentgres://state-root/... | null
  evidence_refs: [artifact://... | receipt://...]

HypervisorSurfaceInstallationBinding:
  installation_ref: install://...
  surface_ref: surface://...
  release_ref: package://.../release/...
  org_ref: org://...
  project_ref: project://... | null
  surface_installation_state:
    not_applicable | not_installed | installing | installed | update_available |
    uninstalling | uninstalled
  surface_enablement_state: not_applicable | enabled | disabled
  visibility: private | organization | permissioned | public
  audience_refs: [user://... | org://... | authority://...]
  allowed_object_contract_refs:
    [ontology://... | object-model://... | object-set://... | schema://...]
  allowed_action_refs: [ontology-action://... | action://... | tool://...]
  authority_preview_policy_ref: policy://...
  decision_ref: decision://... | null
  agentgres_operation_refs: [agentgres://operation/...]
  state_root_ref: agentgres://state-root/... | null
  receipt_refs: [receipt://...]

HypervisorSystemInterfaceBinding:
  system_binding_ref: package_binding://...
  surface_ref: surface://...
  release_ref: package://.../release/...
  installation_ref: install://...
  system_ref: system://...
  surface_enablement_state: not_applicable | enabled | disabled
  visibility: private | organization | permissioned | public
  audience_refs: [user://... | org://... | authority://...]
  allowed_object_contract_refs:
    [ontology://... | object-model://... | object-set://... | schema://...]
  allowed_action_refs: [ontology-action://... | action://... | tool://...]
  authority_preview_policy_ref: policy://...
  binding_admission_ref: decision://...
  agentgres_operation_refs: [agentgres://operation/...]
  state_root_ref: agentgres://state-root/...
  evidence_refs: [artifact://...]
  receipt_refs: [receipt://...]

HypervisorSurfaceServingBinding:
  serving_binding_ref: surface-serving://...
  surface_ref: surface://...
  release_ref: package://.../release/...
  installation_ref: install://...
  system_binding_ref: package_binding://... | null
  resolved_route: string
  runtime_ref: runtime://... | null
  surface_operational_state:
    inactive | starting | ready | serving | degraded | blocked | stopped |
    unavailable
  health_observation_refs: [observation://...]
  agentgres_projection_ref: agentgres://projection/... | null
  receipt_refs: [receipt://...]

HypervisorProductSurfaceProjection:
  projection_id: projection://hypervisor/product-surface/...
  request_context_hash: hash
  workspace_registration_refs: [hypervisor-workspace://...]
  application_registration_refs: [surface://...]
  workspace_entries:
    - workspace_ref: hypervisor-workspace://...
      display_name: string
      canonical_route: string
      route_alias_refs: [route-alias://...]
      launchable: boolean
      disabled_reason_codes: [string]
      launch_binding:
        kind: core_workspace
        workspace_ref: hypervisor-workspace://...
      typed_context_refs:
        - org://... | project://... | system://... | goal://... |
          outcome-room://... | automation-run://... | session://... |
          work_queue://... | work_item://... | work_run://...
  application_entries:
    - surface_ref: surface://...
      surface_key: string
      family_id: string
      display_name: string
      summary: string
      primary_user_job: string
      publisher_ref:
        org://... | user://... | ioi://publisher/... | null
      primary_owner_application_ref: surface://... | null
      tool_kind:
        editor | inspector | picker | inbox | graph | wizard | report |
        dashboard | comparison | console | null
      selected_release_ref: package://.../release/... | null
      selected_installation_ref: install://... | null
      selected_system_binding_ref: package_binding://... | null
      selected_serving_binding_ref: surface-serving://... | null
      eligible_release_refs: [package://.../release/...]
      eligible_installation_refs: [install://...]
      eligible_system_binding_refs: [package_binding://...]
      eligible_serving_binding_refs: [surface-serving://...]
      surface_class:
        owner_application | substrate_application | tool_surface |
        extension_application
      surface_origin: first_party | organization | external_publisher
      surface_creation_method:
        hand_authored | studio_generated | developer_kit_generated | imported |
        adapted
      surface_distribution:
        bundled | direct_package | organization_catalog | private_registry |
        marketplace | null
      surface_availability:
        planned | preview | limited | available | deprecated | unavailable
      surface_admission_state:
        not_applicable | candidate | under_review | admitted | rejected |
        revoked | null
      surface_installation_state:
        not_applicable | not_installed | installing | installed |
        update_available | uninstalling | uninstalled | null
      surface_package_disposition:
        not_applicable | active | deprecated | superseded | recalled | null
      selected_installation_enablement_state:
        not_applicable | enabled | disabled | null
      selected_system_enablement_state:
        not_applicable | enabled | disabled | null
      effective_enablement_state:
        not_applicable | enabled | disabled
      surface_capability_depth:
        browse | inspect | propose | act | workflow_complete | null
      surface_operational_state:
        inactive | starting | ready | serving | degraded | blocked | stopped |
        unavailable | null
      effective_visibility:
        private | organization | permissioned | public | null
      effective_audience_refs: [user://... | org://... | authority://...]
      effective_object_contract_refs:
        [ontology://... | object-model://... | object-set://... | schema://...]
      effective_allowed_action_refs:
        [ontology-action://... | action://... | tool://...]
      effective_authority_preview_policy_ref: policy://... | null
      group_kinds:
        - first_party_applications | tools_for_context |
          organization_applications | installed_applications |
          system_interfaces | recommended | recent | favorites
      canonical_route: string
      resolved_launch_route: string | null
      route_alias_refs: [route-alias://...]
      launchable: boolean
      disabled_reason_codes:
        - planned | unavailable | not_admitted | rejected | revoked |
          not_installed | installing | disabled | recalled | policy_denied |
          missing_context | runtime_unavailable
      launch_binding:
        one_of:
          - null
          - kind: surface
            surface_ref: surface://...
          - kind: installation
            installation_ref: install://...
          - kind: system_interface
            system_binding_ref: package_binding://...
          - kind: serving_binding
            serving_binding_ref: surface-serving://...
      typed_context_refs:
        - org://... | project://... | system://... | goal://... |
          outcome-room://... | automation-run://... | session://... |
          work_queue://... | work_item://... | work_run://...
  policy_decision_refs: [decision://...]
  join_invariants:
    - every eligible or selected release record has
      release.surface_ref == application_entry.surface_ref
    - every eligible or selected installation has
      installation.surface_ref == application_entry.surface_ref and
      installation.release_ref in eligible_release_refs
    - every eligible or selected System-interface binding has
      system_binding.surface_ref == application_entry.surface_ref,
      system_binding.release_ref == installation.release_ref, and
      system_binding.installation_ref in eligible_installation_refs
    - every eligible or selected serving binding has
      serving.surface_ref == application_entry.surface_ref,
      serving.release_ref == installation.release_ref,
      serving.installation_ref in eligible_installation_refs, and, when
      non-null, serving.system_binding_ref in eligible_system_binding_refs
    - selected refs are members of their corresponding eligible-ref sets; when
      non-null, the discriminated launch binding names exactly one selected
      compatible ref, and launchable true requires a non-null launch binding
    - resolved_launch_route is non-null iff launchable is true and is compiled
      from the selected serving, System-interface, installation, or surface
      binding in that precedence order; clients never derive it from
      canonical_route or concatenate a System route locally
    - effective_enablement_state is disabled when either selected applicable
      installation or System-interface gate is disabled; launch requires every
      selected applicable gate to be enabled or not_applicable
    - the selected immutable release's exact object, action, and operator
      contracts are subsets of the stable definition's declared ceilings;
      installation allowed objects/actions are subsets of the selected release,
      and a selected System-interface binding may only narrow installation
      visibility, audience, objects, actions, and authority posture, never
      widen them
    - an effectful launch against a live System requires a selected admitted
      System-interface binding; organization- or Project-scoped surfaces remain
      bounded by their installation visibility, audience, actions, and
      authority-preview policy
    - a null release-, installation-, or serving-owned projected axis means no
      eligible record of that owner kind was selected; null is projection
      absence and never a new canonical enum value
  generated_at: timestamp
  read_model_only: true

HypervisorGoalRunActivationContract:
  activation_contract_ref: action://goal-run/activate/...
  workflow_step_ref: workflow-step://...
  activation_mode: create | join_existing
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_content_hash: hash
  permitted_override_mapping_ref: schema://... | null
  existing_goal_ref_parameter_ref: schema://... | null

HypervisorAutomationSpec:
  automation_id: automation://...
  automation_revision_ref: automation://.../revision/...
  predecessor_revision_ref: automation://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | ioi://publisher/...
  applicable_scope_constraint_refs: []
  automation_kind:
    manual_workflow | scheduled_workflow | webhook_workflow |
    event_workflow | monitor | approval_flow | service_api |
    queue_worker | marketplace_service
  workflow_template_revision_ref: workflow-template://.../revision/...
  workflow_template_content_hash: hash
  compositor_contract_ref: workflow_compositor://...
  activation_parameter_schema_or_binding_ref: schema://... | artifact://... | null
  trigger_schedule_monitor_service_or_queue_contract_refs: []
  activation_review_contract_ref: review_contract://... | null
  delivery_contract_ref: output_contract://... | null
  goal_run_activation_contract_refs:
    - action://goal-run/activate/...
  concurrency_and_idempotency_policy_refs: []
  authority_requirement_refs: []
  allowed_activation_override_schema_ref: schema://... | null
  agentgres_refs:
    - agentgres://operation/...
  receipt_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: draft | released | deprecated | revoked

HypervisorAutomationInstallationBinding:
  automation_installation_ref: install://automation/...
  binding_revision_ref: install://automation/.../revision/...
  predecessor_binding_revision_ref: install://automation/.../revision/... | null
  binding_hash: hash
  automation_spec_revision_ref: automation://.../revision/...
  automation_spec_content_hash: hash
  owner_scope_ref: org://... | project://... | system://... | user://...
  enablement_state: enabled | disabled | archived
  policy_and_authority_overlay_refs: []
  admission_receipt_ref: receipt://...
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: proposed | active | suspended | archived | revoked

HypervisorAutomationRun:
  automation_run_id: automation-run://...
  automation_ref: automation://...
  automation_spec_revision_ref: automation://.../revision/...
  automation_spec_content_hash: hash
  automation_installation_binding_revision_ref: install://automation/.../revision/...
  automation_installation_binding_hash: hash
  workflow_template_revision_ref: workflow-template://.../revision/...
  workflow_template_content_hash: hash
  admitted_parameter_set_ref: artifact://... | null
  admitted_parameter_set_hash: hash | null
  admitted_activation_override_set_ref: artifact://... | null
  admitted_activation_override_set_hash: hash | null
  resolution_receipt_ref: receipt://...
  resolved_component_set_snapshot_ref: artifact://...
  resolved_component_set_hash: hash
  system_ref: system://... | null
  goal_run_refs:
    - goal://...
  outcome_room_ref: outcome-room://... | null
  work_item_refs:
    - work_item://...
  work_run_refs:
    - work_run://...
  session_refs:
    - session://...
  activation_kind: manual | schedule | webhook | event | monitor | service | queue
  activation_event_ref: event://... | null
  daemon_ref: daemon://...
  authority_lease_refs:
    - lease://... | grant://...
  agentgres_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  artifact_refs:
    - artifact://...
  work_result_refs:
    - work-result://...
  outcome_delta_refs:
    - outcome-delta://...
  status:
    queued | running | waiting_for_approval | blocked |
    succeeded | failed | canceled | archived

HypervisorCanvasView:
  canvas_view_id: canvas_view:...
  owner_surface:
    automations | developer_workspace | foundry
  target_ref:
    automation://... | workflow-template://.../revision/... |
    workflow://... | foundry_job://... | project://...
  layout_ref: artifact://... | null
  projection_refs:
    - agentgres://projection/...

HypervisorSession:
  session_id: session://...
  project_ref: project://... | null
  system_ref: system://... | null
  session_mode: interactive | headless | supervisory
  session_kind:
    local_workspace | remote_vm_workspace | browser_sandbox |
    hosted_worker | hypervisoros_node | terminal | editor |
    computer_use | foundry_eval_training | provider_management |
    environment_management
  daemon_ref: daemon://...
  runtime_assignment_ref: runtime-assignment://... | null
  automation_run_ref: automation-run://... | null
  work_item_ref: work_item://... | null
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  room_participant_lease_ref: participant-lease://... | null
  work_claim_lease_ref: work-claim://... | null
  attempt_ref: attempt://... | null
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
    developer_workspace | foundry | provider_environment_view |
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
  session_ref: session://...
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
  session_ref: session://...
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
  project_id: project://...
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
    - work_queue://...
  linked_system_refs:
    - system://...
  agentgres_domain_ref: agentgres://domain/... | null

HypervisorWorkQueue:
  work_queue_id: work_queue://...
  project_ref: project://... | null
  system_ref: system://... | null
  owner_ref: wallet://... | org://...
  queue_kind:
    one_off_handoffs | automation_runs | goal_runs | review_queue |
    incident_queue | service_requests | custom
  intake_policy_ref: policy://...
  default_environment_profile_ref: hypervisor_environment_ops:... | null
  default_harness_selection_ref: harness_selection:... | null
  default_model_configuration_ref: model_configuration:... | null
  status:
    active | paused | draining | archived
  receipt_refs:
    - receipt://...

HypervisorWorkItem:
  work_item_id: work_item://...
  queue_ref: work_queue://...
  project_ref: project://... | null
  system_ref: system://... | null
  automation_run_ref: automation-run://... | null
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  work_claim_ref: work-claim://... | null
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
  work_run_id: work_run://...
  work_item_ref: work_item://...
  session_ref: session://...
  system_ref: system://... | null
  automation_run_ref: automation-run://... | null
  goal_run_ref: goal://... | null
  outcome_room_ref: outcome-room://... | null
  room_participant_lease_ref: participant-lease://... | null
  work_claim_ref: work-claim://... | null
  attempt_ref: attempt://... | null
  runtime_assignment_ref: runtime-assignment://... | null
  workflow_action_ref: workflow_action:... | null
  accountable_actor_ref:
    worker://... | agent://... | system://... | service://... |
    org://... | user://... | domain://... | null
  harness_selection_ref: harness_selection:...
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  harness_invocation_refs:
    - harness_invocation://...
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
  work_result_refs:
    - work-result://...
  outcome_delta_refs:
    - outcome-delta://...
  review_state_ref: hypervisor_work_run_review_state:... | null
  merge_proposal_ref: merge_proposal://... | pull_request://... | null
  merge_decision_ref: merge_decision://... | null
  receipt_refs:
    - receipt://...

HypervisorWorkRunConversationProjection:
  conversation_projection_id: hypervisor_work_run_conversation:...
  work_run_ref: work_run://...
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
  work_run_ref: work_run://...
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
  work_run_ref: work_run://...
  phase:
    not_required | waiting_for_review | changes_requested |
    approved | rejected | superseded
  reviewer_refs:
    - wallet://... | org_role://...
  delivery_refs:
    - pull_request://... | artifact://... | deployment://...
  receipt_refs:
    - receipt://...

HypervisorWorkSubjectProjection:
  projection_row_id: hypervisor_work_subject_projection:...
  subject_kind:
    goal_run | outcome_room | automation_run | session | work_queue |
    work_item | work_run
  subject_ref:
    goal://... | outcome-room://... | automation-run://... |
    session://... | work_queue://... | work_item://... | work_run://...
  org_ref: org://... | null
  project_ref: project://... | null
  system_ref: system://... | null
  canonical_detail_route: string
  display_facets:
    activity: active | waiting | blocked | review | completed | failed | archived
    execution_mode: interactive | headless | supervisory | not_applicable
  review_facet_projection_refs: [projection://...]
  incident_facet_projection_refs: [projection://...]
  source_projection_refs: [agentgres://projection/...]
  policy_decision_refs: [decision://...]
  read_model_only: true

HypervisorWorkFacetProjection:
  facet_projection_id: projection://hypervisor/work-facet/...
  facet_kind: review | incident
  facet_type: string
  facet_ref: string # canonical typed ref owned by the source domain
  owner_ref:
    surface://... | agentgres://domain/... | wallet://... | system://... |
    org://...
  subject_kind:
    goal_run | outcome_room | automation_run | session | work_queue |
    work_item | work_run
  subject_ref:
    goal://... | outcome-room://... | automation-run://... |
    session://... | work_queue://... | work_item://... | work_run://...
  canonical_detail_route: string
  source_projection_ref: agentgres://projection/... | projection://...
  policy_decision_refs: [decision://...]
  read_model_only: true

`HypervisorWorkFacetProjection` is only a policy-filtered cross-owner pointer.
It may project `HypervisorWorkRunReviewState`, `review://wallet/...`,
`approval-request://...`, `artifact_incident://...`, `incident://...`, or a
typed physical/domain incident without converting any of them into a universal
Review or Incident truth object.

RuntimeAssignment is a placement facet and source projection for the typed row
it serves, not a direct Work subject. Fleet allocation and other domain leases
remain facets or linked domain objects unless they acquire an independently
owned work lifecycle and canonical detail route.

HypervisorLegacyWorkSubjectAlias:
  alias_id: hypervisor_legacy_work_subject_alias:...
  legacy_kind: mission
  legacy_ref: mission://...
  resolution_status: resolved | needs_review | rejected
  subject_kind: goal_run | outcome_room | null
  subject_ref: goal://... | outcome-room://... | null
  decision_ref: decision://... | null
  evidence_refs: [artifact://... | agentgres://operation/...]
  migration_receipt_ref: receipt://... | null
  read_only_compatibility_record: true

HypervisorOutcomeRoomProjection:
  projection_id: hypervisor_outcome_room_projection:...
  outcome_room_ref: outcome-room://...
  objective_and_acceptance_ref: outcome-room://...
  work_frontier_projection_ref: projection://...
  participant_projection_ref: projection://...
  attempts_findings_projection_ref: projection://...
  evaluation_challenge_projection_ref: projection://...
  authority_privacy_projection_ref: projection://...
  budget_spend_projection_ref: projection://...
  contribution_lineage_projection_ref: projection://...
  replay_ref: replay://...
  read_model_only: true

SessionAccessToken:
  token_id: session_access_token:...
  session_ref: session://...
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
  session_ref: session://...
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
  session_ref: session://...
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
  session_ref: session://...
  task_kind:
    shell | build | test | eval | benchmark | migration |
    package_install | git_operation | pull_request | code_review_response |
    agent_run | provider_action | archive | restore | custom
  work_run_ref: work_run://... | null
  authority_refs:
    - grant://...
  status:
    queued | running | succeeded | failed | canceled | blocked
  execution_result_ref: result://... | null
  receipt_refs:
    - receipt://...

HypervisorEnvironmentPort:
  port_id: hypervisor_environment_port:...
  session_ref: session://...
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
  session_ref: session://...
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

Automation definition and activation are revision-bound. A released
AutomationSpec patch creates a successor revision; a WorkflowTemplate patch
creates a successor template revision. Each AutomationRun freezes the exact
AutomationSpec, AutomationInstallationBinding, and WorkflowTemplate
revisions/hashes, admitted parameters, resolution receipt, and live authority
leases. Later template/spec/binding edits, enablement changes, recall, or
revocation never silently rewrite an active run. Concrete grants and leases do
not belong in the reusable AutomationSpec.

`content_hash` excludes only the AutomationSpec registry lifecycle/status
projection. Owner- or System-scoped enablement and narrowing policy overlays
belong to `HypervisorAutomationInstallationBinding`; a released spec never
contains live enablement. Each installation binding revision is immutable;
`binding_hash` commits the exact spec pin, owner scope, enablement, policy and
authority overlays. The admission receipt and registry lifecycle/status are
excluded; the receipt binds the already-computed binding hash. A binding-body
change creates a successor revision. A
goal-shaped workflow step must reference a
`HypervisorGoalRunActivationContract` that pins the exact GoalRunProfile and
declares `create` or `join_existing`. The admitted AutomationRun records the
resulting GoalRun ref, while that GoalRun retains its separate profile
resolution receipt. Routine workflow steps leave the activation-contract list
empty.

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
- Home, Systems, Projects, Applications, and Work must register as core
  workspaces, not applications. Automations remains an owner application with a
  first-class shell placement; Sessions remains a typed execution object and
  Work view, not a peer application registration.
- `New Session` must create only a bounded Session. New System, Goal, Project,
  and Automation flows must remain explicit typed commands even when the shell
  presents them in one New menu.
- A Project must not silently become live System identity. A System may link
  Projects, packages, work, interfaces, and nodes, while direct Projects,
  Sessions, Automations, and GoalRuns remain valid without System genesis.
- Every durable application surface must use exactly one registration class:
  `owner_application`, `substrate_application`, `tool_surface`, or
  `extension_application`. Publisher identity, origin, creation method, distribution
  channel, availability, admission state, installation state, package
  disposition, enablement state, capability depth, and operational state remain independent
  dimensions and must not be inferred from that class or from one another.
- One product-surface compiler must produce navigation, Applications,
  command-palette, contextual-launch, search, recent, favorite, and
  recommendation projections. It must filter authorization and visibility
  before aggregation or caching, deduplicate by stable registration id, fail
  safely to eligible static inventory, and remove recalled, revoked,
  uninstalled, blocked, unavailable, or otherwise ineligible launches
  immediately.
- A stable surface registration must not absorb mutable release,
  installation, System-interface, or serving state. Those states belong to the
  normalized release/binding records and may join only in a request-scoped
  projection with typed eligible/selected refs and unavailable reasons.
- A `tool_surface` registration must name exactly one
  `primary_owner_application_ref` and a complete `tool_surface_contract`;
  non-tool registrations must not populate that discriminated block.
- Workspace/surface identities, application surface keys, and canonical routes
  must be unique in the applicable deployment catalog. Every alias
  resolves to exactly one registered identity and canonical route;
  alias-versus-canonical and cross-identity alias collisions fail closed. No
  navigation, search, catalog, command-palette, or launch row may point to an
  unregistered or orphan route.
- `permanent_shell` is reserved for the Automations owner registration in
  taxonomy v2. Home, Systems, Projects, Applications, and Work derive from core
  workspace registrations; no tool, extension, substrate, or other owner
  application may self-promote into the permanent rail through metadata.
- Raw capture/review routes under `/__apps` are development evidence only and
  must never appear as production product inventory. `Ported apps`, `Harvested
  seeds`, `Pixel certified`, and `Substrate bound` are verifier/evidence labels,
  not end-user catalog groups, registration classes, or launchability claims.
- `Work / Reviews` and `Work / Incidents` must remain policy-filtered views over
  typed work subjects and cross-owner facet projections. They may not introduce
  universal Review/Incident subjects or make Work the owner of a tool/domain
  record.
- Packages must remain the mandatory lifecycle owner for reusable releases and
  installs. Marketplace is only an optional Packages mode and distribution
  channel; absence of Marketplace must not weaken private package admission,
  installation, disable, recall, revocation, impact, or receipt semantics.
- Generated or installed application code must not become launchable product
  inventory until an admitted registration, package/release/install binding,
  allowed-action contract, policy filter, and authority preview make the
  current launch eligible.
- Every tool surface must declare exactly one primary owner even when several
  applications consume it. A code-level UX primitive may be shared without a
  tool registration, but it must not become an independent truth owner.
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
- Developer Workspace, Automations, Foundry, Canvas, other application surfaces, and
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
- New writes must not create `HypervisorMission`, `mission://`, or generic
  `mission_ref` truth. `/missions` compatibility routes must resolve through a
  typed legacy alias to a GoalRun or OutcomeRoom and then render the canonical
  Work route; ambiguous or missing aliases fail closed.
- Typed physical mission, route, and actuation-plan objects may remain inside
  the Embodied Runtime domain. They are domain contracts for physical work,
  not a generic Hypervisor work container or peer product application.
- Reusable or background behavior must be modeled as an `AutomationSpec` plus
  typed `AutomationRun`, GoalRun, OutcomeRoom contribution, WorkItem/WorkRun, or
  Session refs as applicable. Background, interactive, headless, supervisory,
  scheduled, event-driven, and monitor execution are modes, not Mission object
  classes or hidden editor sessions.
- Work must remain a policy-filtered projection over typed canonical subjects;
  it must not mint a universal Work status, owner, lifecycle, or id and write it
  back over GoalRun, OutcomeRoom, AutomationRun, Session, WorkItem, WorkRun,
  review, or incident owners.
- A persistent collective outcome must be one underlying OutcomeRoom projected
  as ioi.ai Goal Space and Hypervisor Work / Room detail, not duplicated product
  state.
- Goal Space and Work / Room UI must be graph-first and expose frontier, participants,
  participant/claim leases, attempts, findings, verifier challenges, spend,
  authority/privacy blockers, contribution lineage, and replay. Chat and live
  feeds remain projections.
- Network/Open discovery UI must query signed, versioned
  `OutcomeRoomDiscoveryEnvelope` projections by category, semantic profile,
  capability, eligibility/affiliation, privacy/locality, budget/quote,
  verifier, and settlement posture. Joining creates a typed participation
  request and shows the admission decision; it never silently mints membership.
- Connect local agent must use `LocalAgentPairingSessionEnvelope` with a
  one-time expiring challenge/device code stored hash-only at rest, a candidate-
  generated key, and an origin binding. Pairing authenticates a candidate but
  never grants room membership, context, tools, authority, reputation, payout,
  or publication.
- A local-agent MCP/gateway profile may be issued only after a matching typed
  room-admission decision creates an active participant lease. The profile must
  be scoped, expiring, revocable, bound to candidate key/origin/room/policy, and
  no broader than the admitted lease.
- Prompt-only local-agent compatibility must be labeled proposal-only and low
  assurance. Submitted messages, artifacts, and proposals remain tainted until
  the normal isolation, evidence, verification, and room/domain admission path
  accepts them.
- Goal Space and Work / Room participant controls must expose claim release,
  retirement/revocation, portable participant-state export, acknowledgement,
  supersession, and future-access revocation while preserving historical
  contribution, receipt, acceptance, and dispute lineage.
- Direct questions, sessions, one-off handoffs, and ordinary automations must
  remain direct; no OutcomeRoom or permanent Swarm surface is required by
  default.
- Same-domain multi-model, multi-worker, or multi-node execution must not be
  labeled multi-party. Independent party status requires separate principals
  retaining authority, truth, risk, challenge, and settlement control.
- `Auto`, `Pinned`, and `Compare` must show the selected policy, material
  fallback/escalation, actual attempt/verifier lineage, and budget posture;
  hidden multi-route burn is non-conforming.
- Work Credit allowance and separately funded Network/Open participation must
  remain distinguishable in budget projections even when ioi.ai presents one
  user-facing quote.
- ioi.ai collaborative outcome and room handoffs must use the
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
Home = dense Developer Workspace terminal/diff/file console
Applications = unstructured app drawer
core workspace = application registration
application class = publisher, creation, distribution, availability, admission,
installation, package disposition, enablement, capability depth, or operational state
one surface registration = duplicated navigation/catalog/search/recent records
tool used by several applications = several primary owners
generated UI = launchable before package admission and install binding
Marketplace = mandatory package lifecycle or second package owner
package install = runtime authority or live System identity
package recall = silent mutation or termination of live Systems
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
OutcomeRoom = permanent Swarm application
OutcomeRoom = duplicated Goal Space and Work / Room truth
Work = universal canonical status or lifecycle written over every subject kind
System = renamed Project
Project = implicit live System identity
New Session = implicit Goal, Automation, or System creation
generic Mission = background-work or collective-work truth object
background agent = invisible process or token stream
same-owner seed fleet = independent multi-party network
Goal Space subscription = pooled provider chat seats
Network / Open spend = hidden ordinary seat burn
Connect local agent = shared organization read/write token
pairing challenge = reusable durable API credential
pairing success = room membership or effect authority
prompt-only local agent = verified runtime
local-agent pairing = automatic aiagent.xyz publication
local-agent gateway = raw provider credentials or ambient room context
Auto = hidden multi-route execution
Pinned = silent fallback
Hypervisor Operator Plane = ambient host administrator
child session harness = host platform administrator
Git branch = canonical attribution/truth layer
code WorkRun = no materialized branch/worktree by default
Developer Workspace = runtime truth
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
Home/Systems/Projects/Applications/Work = core workspaces
Developer Workspace/Automations/Foundry = application surfaces
Evaluations = independent epoch, exposure, validity, and re-verification owner
Improvement = optional campaign and direct-change coordination cockpit
Foundry = candidate/evaluator asset builder and admitted experiment executor
Governance + target owner = activation and effect-recovery authority
Workbench = compatibility alias for Developer Workspace
Systems = stable contextual inventory of live constitution-bound Systems
Projects = persistent build and work-context containers
Work = policy-filtered typed projection, never a universal truth object
Packages = mandatory release/install/recall lifecycle owner
Marketplace = optional Packages discovery/exchange mode and distribution channel
Application composition = reusable UX primitives over shared Core contracts
Canvas = visual editor/projection
ioi.ai = intent-to-outcome coordination, including multi-model/multi-path
goal pursuit when useful
Goal Space = ioi.ai outcome product projection
Work / Room detail = Hypervisor projection of the same persistent OutcomeRoom
OutcomeRoom = graph-first shared frontier above bounded GoalRuns
background participants = visible claims, leases, spend, evidence, and controls
Hypervisor Operator Plane = governed control-plane harness over declared
application-surface contracts
code WorkRun = isolated child environment + materialized Git branch/worktree +
Agentgres patch branch + receipts
Provider and infrastructure posture = Environments views through
Applications, Open Application, sessions, projects, provider settings,
org/admin views, or operator consoles
Sessions = bounded governed execution/control contexts projected in Work
Adapters = mediated bridges to targets
Agent harness adapters = mediated bridges for external agent harnesses
Connect local agent = one-time candidate pairing, then typed room admission
LocalAgentPairingSessionEnvelope = authentication, never authorization
room_guest participant lease = prerequisite for its scoped expiring gateway profile
private/organization worker = active registration + admitted invocation/session/run scope
prompt-only local agent = visibly low-assurance proposal source
aiagent.xyz reusable/public Worker record = separate explicit handoff
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
- [`../../foundations/economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md)
- [`improvement.md`](./improvement.md)
- [`evaluations.md`](./evaluations.md)
- [`foundry.md`](./foundry.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
- [`../../_meta/vocabulary.md`](../../_meta/vocabulary.md)
