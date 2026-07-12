# Current Canon Defaults

Status: canonical cross-owner digest.
Canonical owner: this file for the current high-level defaults that span
multiple architecture owners. Subject-specific doctrine remains owned by the
files named in [source-of-truth-map.md](./source-of-truth-map.md).
Supersedes: the inline "Current canonical defaults" digest formerly embedded in
[source-of-truth-map.md](./source-of-truth-map.md).
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (cross-owner digest)
Last implementation audit: 2026-07-05

## Purpose

This digest keeps the current architecture defaults easy to scan without turning
the source-of-truth map into a long doctrine file. Use it when you need the
latest cross-owner mental model before editing a specific owner doc.

This file does not replace the owner docs. When a detail needs
implementation-grade precision, edit the canonical owner named in
[source-of-truth-map.md](./source-of-truth-map.md) first and keep this digest
synchronized.

## Reading Order

1. Start with [start-here.md](./start-here.md) for the five-minute stack model.
2. Use this digest for the current cross-owner defaults.
3. Use [source-of-truth-map.md](./source-of-truth-map.md) to find the edit-first owner.
4. Use [implementation-matrix.md](./implementation-matrix.md) to map a concept to durable forms, code anchors, and conformance hooks.

## Current Defaults

### Capability, authority, and runtime ownership

- `prim:*` means primitive execution capability;
- `scope:*` means wallet/provider authority scope;
- daemon/public runtime APIs own execution semantics;
- Hypervisor Daemon runtime nodes are the hypervisor/control plane for
  autonomous execution;
- Workflow Compositor owns high-level directed workflow/service shape:
  graph, dependencies, step contracts, review points, delivery contracts,
  and reusable templates;
- HarnessProfiles are daemon-executed or daemon-mediated step-resolution
  profiles/adapters; they must produce common boundary objects and cannot
  own execution truth;
- the Default Harness Profile is IOI's reference scaffold/fallback
  HarnessProfile for loop-native scoped step resolution; it is not a peer
  runtime, not the only admissible harness, not a meta-harness, and not the
  owner of high-level workflow composition;
### Goal Kernel and collective pursuit

- ioi.ai and Hypervisor Sessions use the Goal Kernel / Goal Microharness shape
  for one bounded goal or claimed subgoal: durable GoalRun state,
  GoalGroundingLoop, RoleTopology, independent Context Cells, scoped Context
  Leases, typed Context Handoffs, selected HarnessProfiles, generic
  `WorkResult` / `OutcomeDelta`, VerifierPath evidence, and continuation state;
- the GoalGroundingLoop receives intent, classifies risk, gathers grounding,
  inspects current state, derives constraints and acceptance, selects or adapts
  topology, leases context/resources/authority, executes or delegates, monitors,
  verifies, repairs or escalates, reconciles receipts/memory/skills, and
  continues or closes. It optimizes useful progress per token, not model calls;
- persistent collective pursuit uses an `OutcomeRoom` /
  `CollaborativeWorkGraph` above one or more GoalRuns. The room owns the shared
  objective, participant leases, work frontier, claim leases, resource and
  capability offers, attempts, findings, verifier challenges, contribution
  lineage, admission policy, discussion projections, and replay. It is not a
  peer runtime or a globally mutable Agentgres graph;
- the minimum Internet-of-Intelligence network proof is an independently
  operated external Worker discovering eligible work through a versioned,
  policy-bound `OutcomeRoomDiscovery`, negotiating semantic/action profiles,
  submitting a typed `RoomParticipationRequest`, receiving bounded leases,
  returning a verifiable contribution, preserving credit/dispute lineage, and
  exiting with a portable `ParticipantStateBundle`. It must not require one
  runtime, operational database, administrator, or continued IOI-host trust;
- `WorkResult` / `OutcomeDelta` is the general cross-harness result seam.
  `ImplementationResultPayload` remains the software profile with file, patch,
  diff, and test fields; research, ontology, incident, service, review,
  evaluation, and physical-mission results do not inherit software fields;
- cross-harness coordination uses typed ContextHandoffs, ContextLeases,
  TaskBriefPayloads, HarnessInvocations, HarnessAdapterEvents, generic results,
  VerifierPaths, and receipts. Adapter-private prompts or commands and raw chat
  are not the durable contract;
- ordinary direct work collapses to one GoalRun, worker, model route,
  automation, service, or session. OutcomeRoom machinery appears only when a
  durable shared frontier, multiple attempts, dynamic participants, independent
  verification, or cross-domain contribution justifies its cost;
- ordinary verification may use deterministic checks, receipts, diffs, tests,
  browser/runtime evidence, and acceptance reconciliation. Independent verifier
  harnesses are policy-triggered for publish, mount, external connectors, spend,
  secrets, unsafe plaintext, marketplace admission, production mutation,
  physical action, compliance, challenge, or cross-party acceptance;

### Persistent intelligence

- persistent workspace intelligence such as skills, Agent Wiki /
  `ioi-memory`, wiki facts, learned tool affordances, and durable
  behavior-affecting context is workspace/project/domain state that should
  survive model/harness swaps when workspace identity, compatibility,
  provenance, policy, and authority allow;
- the Hypervisor Daemon is the deterministic execution substrate for
  portable, verifiable autonomous systems;

### Hypervisor substrate and product structure

- Hypervisor includes Type 1, Type 2, and Type 3 substrate modes as deployment
  and control postures of one product. Type 1 is HypervisorOS / appliance /
  cluster control where the Hypervisor Daemon is node root. Type 2 is Hypervisor
  Desktop / Workstation hosted on a normal OS for local VMs, sandboxes, models,
  tools, agents, connectors, and environments. Type 3 is autonomy virtualization
  across sessions, WorkRuns, workers, model routes, tools, authority, receipts,
  replay, outcomes, and promotion. Type 3 is the differentiator; Type 1 and Type
  2 are the trustable substrate beneath it. HypervisorOS improves control,
  integrity, containment, measurement, reproducibility, and policy enforcement,
  but it does not replace cTEE no-plaintext-custody;
- Hypervisor must expose real substrate-control grammar, not only agent
  orchestration. Substrate, inventory, create/import, console, operations,
  governance, and ledger expectations should resolve through Operations,
  Environments, Workbench, Sessions, Work Ledger, Governance, Developer &
  Integrations, Hypervisor Desktop / Workstation, and HypervisorOS/provider
  detail views without expanding the permanent rail by default;
- Hypervisor manages sessions, environments, providers, and cross-session
  infrastructure posture directly through the Applications catalog, the
  singular Open Application slot, session detail, project settings, provider
  settings, org/admin views, and operator console panels; provider posture
  is not a separate product or truth layer;
- BYO provider integration is a provider-neutral object plane with a priority
  adapter ladder, not a vendor taxonomy. SSH/bare-metal is the conformance
  adapter; simple GPU VMs, GPU runtimes, GPU marketplaces, enterprise
  hyperscalers, customer clusters, DePIN compute, and decentralized storage
  custody follow as adapters under the same `ProviderAccount`,
  `RuntimeNode`, `PlacementDecision`, `SnapshotRef`, `RestoreRef`,
  `SpendReceipt`, and `ProviderOperationReceipt` contract. BYO provider spend
  is customer-borne and transparent; direct local/self-managed BYO carries no
  percentage-of-provider-spend fee, while BYO or pinned cloud venues run through
  Hypervisor may carry a visible adapter/orchestration fee when Hypervisor
  brokers credentials, provisions, manages leases, snapshots, restores, tracks
  cost, emits receipts, or tears down resources. Hypervisor monetizes
  orchestration, governance, custody, receipts, restore, support, private
  posture, and managed convenience rather than hiding provider markup;
- runtime placement presents four user choices: run local, use my
  infrastructure, pick a cloud, or let Hypervisor choose. Underneath those
  choices are three placement sources: `connected`, `managed`, and
  `optimized`. `Connected` means the user owns the provider bill, with no
  percentage fee on direct self-managed spend and visible orchestration fees
  only when Hypervisor performs provider lifecycle work. `Managed` means IOI or
  a partner is provider-of-record and Work Credits or margin are legitimate.
  `Optimized` means Hypervisor creates visible routing/procurement/failover or
  billing-aggregation value and may charge only with challengeable placement or
  routing evidence;
- Hypervisor Core is the shared runtime/control substrate whose execution
  owner is the Hypervisor Daemon; it is not a peer runtime beside the daemon,
  not a replacement for wallet.network, and not a replacement for Agentgres;
- Hypervisor App, Hypervisor Web, and Hypervisor CLI/headless are
  first-class clients over Hypervisor Core; TUI is an optional presentation
  of the CLI/headless client, not a separate first-class client lane;
- Hypervisor's default shell is Home, Projects, Automations, Applications,
  and Sessions; Applications is a query-first catalog rather than permanent
  rail expansion, `Open Application` is a singular active surface slot, and
  specialized platform and vertical surfaces should resolve through the
  Applications catalog, Open Application, or contextual views unless product
  testing proves a new top-level category is needed;
- IOI is one open, edge-sovereign operating fabric for governed autonomous
  systems. Federated ontologies make a domain legible; GoalRuns and collective
  pursuit create purposeful work; Hypervisor is the reference execution and
  control environment; local/domain governance and authority providers authorize;
  Agentgres admits each domain's operational truth; AIIP connects domains; IOI
  L1 settles selected commitments. The semantic world plane and Hypervisor are
  complementary halves of one architecture, not peer product theses;
- Hypervisor is the governed autonomy substrate where work becomes reusable
  capability. Work is live governed activity such as a session, run,
  connector action, code change, research path, training job, workflow step,
  or service delivery. Capability is reusable autonomous capacity such as a
  worker, automation, model route, data recipe, eval, tool, package,
  conductor advisor, service module, or marketplace listing;
- Hypervisor product direction is an open autonomy control plane and
  operating environment for autonomous systems, organized by a simple
  lifecycle lens of Build, Run, Govern, Observe, and Improve behind the
  stable shell. Package / Market is a marketplace/settlement path that follows
  from improved capability, not a default navigation burden;
- Product surfaces should use layered language. Users and buyers see agents,
  jobs, sessions, permissions, connected apps, delivery channels, evidence,
  payments, and revoke controls. Admins and builders see policies, scopes,
  work ledgers, evals, worker packages, runtime profiles, data recipes, ontology
  kits, surface descriptors, and authority clients. Protocol, audit, and
  implementation views may name
  wallet.network, Agentgres, Hypervisor Daemon, authority grants, IOI L1
  commitments, and ContributionReceipts. Subsystem names support trust; they
  should not carry the default product pitch;
- Hypervisor's compounding loop is: governed work happens; receipts,
  artifacts, traces, corrections, and evals accumulate; failures and wins are
  mined; Foundry proposes or builds reusable capability; aiagent.xyz/MoW
  attributes external supply when marketplace workers contribute; future
  work routes better under policy, authority, receipts, and replay;
### Goal Space product and economics

- ioi.ai presents one Goal Space subscription, not separate single-node and
  network-node products. The subscription covers conductor/account experience,
  persistent goal state, portable memory, policy, receipts, replay,
  collaboration, ordinary support, and a bounded monthly grant of
  non-transferable Work Credits. Additional managed work uses opt-in top-ups,
  overage, or committed spend; independent Network/Open workers, verifiers, and
  services use a separately bounded goal budget, bounty, procurement limit, or
  service order;
- IOI reproduces the simplicity of a foundation-model seat without pooling,
  sharing, browser-automating, or reselling named-user chat/workspace limits as
  production worker capacity. Managed supply uses open/self-hosted weights,
  provider APIs, managed/dedicated endpoints, negotiated inference capacity,
  customer BYOK/BYOA, and explicitly authorized OEM/reseller paths. Aggregators
  are replaceable procurement/routing adapters, not the product moat or sole
  inference authority;
- every provider/model candidate resolves a versioned route contract covering
  commercial posture, access mode, customer-facing and automation/downstream
  rights, credential principal, provider/model terms, endpoint/model versions,
  provider allowlists, data collection/ZDR, region, fallback, price,
  parameters, and training/distillation rights. Missing rights fail closed;
  inference rights never imply training rights; model/provider fallback is a
  semantic substitution that emits route evidence and re-runs applicable
  verification/acceptance;
- `Auto` / 1-of-N, `Pinned`, and `Compare` / N-of-N are routing policies, not
  subscription tiers. Auto may use a verified cheap-first cascade; Pinned fails
  closed unless fallback was authorized; Compare accounts for every admitted
  attempt, verifier, and synthesis step;
- execution/custody (`Standard` or `Private`), contributor scope (`My workers`,
  `Organization`, or `Network / Open`), and placement (local, customer
  infrastructure, selected cloud, or Hypervisor-selected) are orthogonal.
  Contributor scope never declassifies data or widens authority. Multi-model,
  multi-worker, and multi-node work does not become multi-party unless separate
  principals control authority, truth, challenge, risk, and settlement;
- `Standard` permits disclosed, policy-qualified provider-trust model routes
  over the private-native substrate. `Private` adds no-provider-trust model
  routing through local, BYO, customer-boundary, cTEE, TEE, or another
  custody-proven route. Managed private compute/proof may consume Work Credits
  or require enterprise capacity; merely connecting an app or using local/BYO
  execution is not a connector tax;
- IOI's economic posture is open substrate, paid network. The Verified Work
  Graph is receipt-backed economic memory across accountable worker, harness,
  model, tool, provider, authority, cost, evaluation, acceptance, contribution,
  and dispute state. Work Credits normalize managed product costs but remain
  non-transferable product credits, not cash, a speculative token, or a labor
  payout rail. Direct BYOK removes the provider-cost component and retains only
  explicit conductor/runtime/governance/support charges;
- the sellable allowance is planned, not built. Current flat OCU receipt
  metering is not supplier-invoice reconciliation. Commercial activation
  requires route-attempt and billed-token/compute telemetry, supplier/broker
  cost, IOI fee basis, adjustments, caps, explicit overage consent, positive
  cohort margin, bounded p95 COGS, and accepted outcomes per dollar;
- Agentgres remains bundled operational truth infrastructure; ordinary
  wallet.network authority remains bundled safety infrastructure; marketplace
  and service owners retain their fees; IOI L1/token/BME economics attach only
  after verified work demand and liquidity justify public coordination;

### Governed autonomous systems and sparse settlement

- Intelligent blockchains are self-driving bounded actors: stateful
  autonomous-system domains that can monitor state, route work, request
  authority, recover, improve future behavior, and settle what matters only
  inside explicit authority, policy, budget, safety, receipt, replay,
  rollback, recall, and proof envelopes. Bounded recursive improvement is
  proposal-mediated improvement, not direct self-mutation or
  self-escalation;
- Hypervisor Workbench, Environments, Agent Studio, Foundry, ODK, Domain Apps,
  Developer & Integrations, Governance, Operations, Work Ledger, Marketplace,
  and roadmap Robot Fleets / Embodied are application surfaces over Hypervisor
  Core, not runtime-truth owners. Automations is a shell-blessed durable work
  container over the same Core. Favorites, recommended apps, promoted apps,
  pinned apps, and organization shortcuts are catalog, Home, project/session,
  or user preference affordances, not canonical shell categories;
- Hypervisor application surfaces should register stable identity, owner doc,
object families, allowed placements, launch modes, project/session
compatibility, daemon/API dependencies, authority/privacy posture,
operator-plane tool or MCP contract refs, host/platform mutation boundary,
composition pattern, receipts/replay/eval/package obligations, and
install/favorite/recommended metadata before becoming durable first-class
inventory;
- Autonomous-system domain manifests and ODK blueprints must be concrete
enough to instantiate real domains, not only diagrams. They should name
source/project bindings, runtime placement, authority scopes, connector
requirements, exposed operator/API/MCP/AIIP interfaces, generated domain
app refs, release targets, rollback/recall/kill-switch posture, receipt
schemas, replay obligations, and settlement/dispute posture when
applicable;
- Hypervisor application composition primitives include catalog/search
  launcher, Open Application frame, list/detail workspace, command composer,
  modal or step wizard, canvas/editor projection, object view, object-view
  editor, graph view, review/approval inbox, monitoring/resource console,
  lineage/replay/evidence view, artifact/build/job view,
  package/install/publish flow, and generated domain surface. These are UX
  composition patterns over shared Core contracts, not new truth owners;
- Hypervisor capability lifecycle control is a cross-surface projection, not
  a separate runtime, authority owner, or permanent shell category. Governance
  owns the release/change facet for promote, deploy, roll out, pause, rollback,
  recall, kill-switch, remote-config, release-target, gate, and cohort
  coordination across reusable capability; local surfaces still own their local
  evidence and work state. Environments owns environment runtime lifecycle,
  Operations owns execution queue/run/remediation and capacity/queue/spend
  posture, Foundry owns build/eval/training and promotion candidates,
  Automations owns trigger/workflow/service lifecycle, Marketplace and Work
  Ledger own install/publish/package evidence and artifact/contribution
  handoffs, Governance and Operations own human approval, policy, remediation,
  and incident gates, ODK and Work Ledger own dependency, provenance, and
  impact views, and Work Ledger owns trace/proof inspection;
- agent-ready development environments are stateful, interactive, and
  potentially adversarial. For untrusted or cross-tenant autonomous work,
  Hypervisor should use VM, microVM, HypervisorOS, customer-boundary, TEE, or
  cTEE profiles as the isolation claim; devcontainers and containers are setup
  or inner-sandbox lanes unless admitted inside an appropriate boundary.
  Readiness means the daemon admitted recipe, tasks, services, resources,
  connectivity, ports, caches, authority, receipts, and restore posture, not
  merely that a shell or container started;
- application surface modes such as solution planners, walkthrough builders,
  typed tool/function builders, object views, value-type managers,
  graph/object explorers, schedulers, object/state monitors, authority
  clients, client applications, granular permissions, resource queues,
  retention/declassification views, restricted views, checkpoints,
  issues/action queues, artifact registries, build/job trackers, workflow
  lineage, code templates, branch/change views, developer consoles,
  diagnostics, widget builders, source/sync/listener managers, data health,
  dataset/time-series explorers, model libraries, model rules/guardrails,
  inference readiness, and domain consoles are Applications catalog or
  contextual surface inventory, not permanent shell categories;
- Learning / Patterns / Examples / Training is the role-guided recipe facet for
  turning learning
  tracks, solution diagrams, example apps, starter automations, data recipes,
  ontology packs, eval packs, and package templates into governed sessions,
  automations, Foundry jobs, domain apps, receipts, replay, promotion
  proposals, and marketplace paths. It appears through Home, Applications,
  Marketplace, Foundry, ODK, Domain Apps, and onboarding rather than as a
  separate final product app;
- Agents are configurable, buildable product objects over Hypervisor Core;
  Workers remain the accountable protocol package/manifest boundary.
  Product controls such as Agent, Mode, Model, Reasoning, Speed, Harness,
  Tools / Integrations, Memory, Authority, Budget, Evals, and Work Ledger
  posture compile into daemon records, wallet authority, model routing,
  HarnessProfile selection, Agentgres operations, and receipts;
- Model is the product-facing control label inside New Session, Agent Studio,
  Foundry, and related surfaces; ModelRoute remains the implementation/runtime
  object for provider, custody, fallback, spend, privacy, eligibility, and
  invocation policy;
- Hypervisor's Agent Operating Plane is daemon-owned: configured agent
  records, agent/session admission, work queues, work items, work runs,
  turn control, conversation streams, subagent delegation, runner
  reconciliation, usage accounting, and exec/security telemetry are
  runtime contracts, not client-local state;
- Hypervisor's Operator Plane is the governed control-plane harness for
  operating Hypervisor itself. It uses the same `AgentRecord`,
  `ModelConfiguration`, `ReasoningEffort`, `ServiceTier`, `HarnessProfile`,
  tool/MCP contract, authority, and receipt substrate as sessions, but it is
  not ioi.ai, not a child session harness, and not an ambient host
  administrator. Backend/headless conductors are client projections over
  this same substrate, not custom privileged Hypervisor instances;
- Hypervisor Automations is the durable workflow, trigger, schedule,
  API/service, approval-flow, queue, and background-mission surface over the
  Workflow Compositor; it is not a peer runtime and does not own
  wallet.network authority or Agentgres truth;
- ioi.ai is the outcome conductor and Goal Space product. It may coordinate
  multiple models, harnesses, workers, connectors, sessions, verifier paths,
  attempt strategies, and independent contributors over Hypervisor when a goal
  calls for it. Its durable projection is a cross-session outcome graph and,
  for persistent collective goals, an OutcomeRoom workstream graph over
  authorized participants, claims, attempts, findings, receipts, artifacts,
  spend, authority blockers, challenges, replay, and contribution refs;
- ioi.ai dogfoods Hypervisor as a first-party coordinator. Similar
  coordinators should be buildable from Hypervisor application surfaces,
  operator-plane contracts, WorkRuns, Automations, Foundry, wallet.network,
  Agentgres, aiagent.xyz/MoW contribution refs, and receipts without
  privileged substrate access;
- Hypervisor Foundry is the capability factory: the surface where observed
  work, datasets, executable eval worlds, interactive worlds, gameplay
  trajectory datasets, scenario curricula, traces, failures, and proposals
  become reusable models, workers, world-model candidates, spatial-temporal
  policies, data recipes, evals, model routes, packages, endpoints,
  conductor-advisor candidates, certification-run candidates, transfer gates,
  or promotion proposals. ioi.ai may draft or consume Foundry refs, but Foundry
  owns training/eval lineage;
- federated Domain Ontologies and Data Recipes are IOI's semantic world plane.
  Domains retain namespaced local canonicality and interoperate through versions,
  overlays, crosswalks, challengeable semantic mapping decisions, and policy-
  bound projections rather than one global ontology or database. Admitted
  assertions preserve provenance, valid/transaction time, uncertainty,
  supporting and contradicting evidence, applicability, supersession, and
  dispute; admission does not make a proposition universally true;
- `OntologyActionContract` is the semantic/action bridge: target object and
  typed IO, pre/postconditions, invariants, capability/runtime binding, risk,
  authority, dry-run, idempotency, retry, ambiguous-effect reconciliation,
  compensation, verification, evidence, receipts, and physical-safety posture;
- ODK is the first-party Hypervisor surface over the semantic world plane;
  Foundry consumes ODK-governed ontology/data artifacts for training,
  evaluation, simulation, worker/package generation, and capability
  improvement, but does not own semantic truth. `Data / Knowledge`,
  `Ontology`, `Data Studio`, `Ontology Studio`, `Workshop`, and
  `Domain Blueprints` are aliases or facets, not separate final product apps;
- the Ontology Development Kit is the source-neutral builder kit over Domain
  Ontologies, Canonical Object Models, Data Recipes, Connector Mappings,
  PolicyBoundDataViews, OntologyProjections, evals, and workflow schemas. It may
  scaffold or validate object-aware surfaces, domain apps, operator consoles,
  eval packs, worker/package skeletons, and marketplace-ready ontology packs,
  but it is not a runtime, truth store, authority layer, data warehouse,
  training-consent owner, marketplace, or settlement layer;
- Connectors / Tools / MCP is a first-party Hypervisor surface over the
  authority-aware registry; MCP servers, external agent tools, and
  workflow-as-tool subgraphs must compile to RuntimeToolContract, primitive
  capabilities, authority scopes, policy decisions, and receipt obligations;
  the Hypervisor Operator Plane may consume those contracts, while child
  sessions may request or propose but must not directly mutate host/platform
  state. ioi.ai connector/auth escalation is a handoff through these
  contracts, wallet.network authority, daemon admission, and Agentgres
  receipts, not a direct provider path;
- wallet.network is the autonomous-work authority wallet and gateway for
  identity, auth factors, guardian surfaces, key shards, provider credential
  bindings, delegated authority, leases, approvals, secrets, spend, data-use
  permission, declassification, revocation, policy simulation inputs,
  gateway decisions, risk labels, portable authority refs for training-data
  use, and authority receipts. Hypervisor/Foundry/Data/Agentgres own local
  governance and eligibility state; wallet.network supplies delegated
  authority when that state needs secrets, spend, decryption,
  declassification, provider trust, publication/export, cross-domain reuse,
  or autonomous-agent-executable power. Agents and workers do not receive
  raw secrets as product doctrine; they receive scoped, revocable authority
  leases mediated by wallet.network and daemon policy;
- Hypervisor Workbench is the live code/systems surface term;
- editor integrations such as VS Code, Cursor, Windsurf, JetBrains, browser
  IDEs, terminals, VMs, local OS surfaces, and HypervisorOS nodes are
  adapter targets, not Hypervisor's product identity;
- external CLI or hosted agent harnesses such as Codex, Claude Code, Grok
  Build, OpenHands, Aider, shell/tmux agents, CI agents, and hosted coding
  agents are Agent Harness Adapters; they submit proposed work through
  Hypervisor Core and the daemon and do not become Hypervisor clients or
  runtime truth;
- host-terminal harness sessions become daemon-admitted only after recipe
  admission, harness binding admission, launch, spawn, readiness, terminal
  attach, and transcript projection refs are all bound; a Hypervisor client
  PTY is transport, not runtime truth;
- code WorkRuns should bind isolated child environments to a materialized Git
  branch/worktree and an Agentgres patch branch: Git/worktree backs file
  review, tests, IDE use, and PR export; Agentgres owns coordination,
  attribution, authority, validation, receipts, and admitted merge truth;
- Hypervisor is the flagship product substrate for building, deploying, and
  governing autonomous systems through daemon/runtime contracts;
- Hypervisor product UX direction belongs in the canonical owner docs; any
  private sprint, research, or product-reference scaffold must be translated
  into ownership, authority, state, receipt, privacy, and adapter contracts
  before it becomes doctrine;
- ioi.ai Goal Chat is an intent and coordination surface: it may ask,
  invoke, inspect, summarize, and draft Hypervisor work, but durable
  workflows/services must hand off to Hypervisor Automations and execution
  must pass through the Hypervisor Daemon;
- IOI Authority Gateway is the daemon sidecar/compatibility profile for
  existing IDE, CLI, browser, hosted-agent, and MCP/tool ecosystems; it is
  not a separate runtime;
- Agentgres is operation-backed domain truth with a Postgres bridge;
- Agent Wiki / `ioi-memory` is the adjacent context-memory plane for what
  agents can know, retrieve, and remember; Agentgres admits and proves
  durable memory mutations when they become canonical, shared, portable,
  replayable, policy-relevant, routing-relevant, training-relevant, or
  restore-relevant; worker packages may declare memory compatibility, managed
  instances own concrete memory profiles/archives, and harnesses consume
  policy-filtered memory projections rather than owning durable memory by
  themselves;
- Agentgres artifact refs own payload meaning, lifecycle,
  policy/authority linkage, receipts, replay/import metadata,
  archive/restore validity, and state-root validity;
- private user/app state follows the same split as private agent state:
  Agentgres owns canonical refs and meaning, storage backends hold encrypted
  bytes, authority providers and local/domain policy control
  viewing/decryption/mutation authority, wallet.network is mandatory for
  portable delegated authority, secrets, decryption leases, external effects,
  or high-risk approval, and IOI L1 receives only selected
  public/economic/cross-domain commitments;
- wallet.network is the authority wallet/gateway for autonomous agents and
  autonomous finance. It may render as a Wallet cockpit in high-trust or
  advanced contexts, but ordinary product flows should usually present it as
  SSO, permissions, connected access, approvals, recovery, and revoke controls
  embedded inside the current product. It owns auth-factor posture, guardian
  and key-shard posture, provider credential binding posture, agent/session
  authority, exchange authority, trade authority, risk disclosure, approval,
  signing/denial, revocation, protection actions, and wallet receipts, while
  agents, routes, venues, connectors, and provider adapters only produce
  requests or candidates;
- `decentralized.exchange` is a preferred first-party route-intelligence
  engine for asset conversion, not a mandatory exchange UI, exchange
  backend, authority layer, liquidity owner, execution owner, or trust root;
- `decentralized.trade` is a preferred first-party venue, market, and
  exposure-intelligence engine, not a mandatory trading UI, broker,
  custodian, user position owner, authority layer, venue execution owner, or
  trust root;
- `decentralized.cloud` is a preferred first-party resource-intelligence
  engine for infrastructure capacity, not a mandatory cloud UI, cloud control
  plane, provider account owner, VM lifecycle owner, authority layer, restore
  truth layer, storage custody owner, or trust root;
- Hypervisor has direct provider integrations for cloud compute, storage,
  GPUs, confidential compute, DePIN, local machines, customer cloud,
  enterprise infrastructure, decentralized storage, and user-specified
  provider routes;
- aiagent.xyz is the capability market for benchmarked, installable,
  attributable autonomous capability. It is the discovery, procurement,
  installation, initialization, and routing layer for ontology-bound digital
  and embodied workers; it
  indexes workers through `DigitalWorkerOntology`, `VerticalOntologyPack`,
  `IntegrationSurface`, `ManagedWorkerOnboardingPlan`,
  `ManagedWorkerInstance`, managed-instance lifecycle,
  `ManagedWorkerInstanceConfigRevision`, `ManagedWorkerInstanceChangePlan`,
  `RuntimeManagementChannel`, `ContactDeliveryChannel`,
  receipts, benchmarks, authority, runtime posture, and safety posture instead
  of hardcoded vertical directories;
- decentralized.exchange/trade/cloud produce route, venue, exposure, and
  infrastructure-capacity candidates; wallet.network authorizes; Hypervisor
  deploys or executes; venues and providers perform; Agentgres records; IOI L1
  settles by trigger;
- storage backends such as Filecoin/CAS, S3, local disk, and object stores
  hold payload bytes only; missing, invalid, stale, or unavailable payloads
  become Agentgres `ArtifactAvailabilityIncident` records plus repair
  receipts when they affect admitted work;
- Private Workspace backed by cTEE is the daemon-owned workspace/execution
  profile for persistent rented GPU Hypervisor Nodes that must keep protected
  plaintext off provider-controlled nodes by default;
- Candidate-Lattice Private Decoding is the default protected-agency strategy
  for Private Workspace backed by cTEE: rented nodes generate candidates,
  sealed/private heads select or deny;
- IOI kernel is the L0 substrate;
- IOI L1 is the public settlement, registry, dispute, and governance root;
- autonomous systems can execute anywhere; IOI settles what matters;
- AIIP moves delegated autonomous work, collaborative-pursuit updates,
  negotiated semantic profiles, authority leases, receipts, settlement intents,
  disputes, reputation queries, and handoffs across bounded execution domains;
- AIIP uses the same semantic protocol for local Hypervisor microharness
  routing and external autonomous-system handoffs, while transport and
  settlement mode vary by profile;
- governed autonomous-system chains are system-local execution chains with
  policy, modules, proposals, receipts, state roots, and governed upgrades;
- a Hypervisor Node is a local settlement, orchestration, authority-integration
  and enforcement, state,
  replay, routing, and interop domain for many governed autonomous-system
  chains;
- Hypervisor App, Hypervisor Web, CLI/headless, Workbench, Automations,
  Foundry, other application surfaces, and Environments views
  are not the Hypervisor Node; they are clients, application surfaces, or
  projections, while the node is the local settlement domain composed around
  Hypervisor Daemon, Agentgres, wallet.network authority paths, local
  registries, receipts, and replay;
- Hypervisor Nodes settle autonomous work locally; IOI L1 settles machine
  labor globally;
- IOI topology is edge-in and fractal;
- verifiable bounded agency is IOI's execution-boundary alignment thesis:
  workers may reason or propose probabilistically, but consequential effects
  cross reality only through bounded authority, policy, receipts, and
  verification;
- Smarter-agent runtime loop is the bounded cognition discipline for
  model pass, action proposal, gate, execution, observation, receipt, and
  re-entry; it is mediated by Hypervisor Daemon/Core and never owns
  execution authority by itself;
- `physical_action` is a high-risk effect class, not a generic tool-call
  variant; actuator-affecting work must bind to Physical Action Safety
  objects such as `PhysicalActionPolicy`, `SafetyEnvelope`,
  `EmergencyStopAuthority`, `SensorEvidenceReceipt`, and
  `ActuatorCommandReceipt` before execution;
- Embodied Runtime is the runtime companion to Physical Action Safety. It
  owns robot/fleet identity, controller bindings, sensor and actuator
  registries, local control bridges, heartbeat/failsafe posture, world
  models, maps, zones, calibration, environment state, physical command
  queues, telemetry streams, physical replay, sim-to-real gates, incidents,
  recovery, operator handoff, and fleet-level policy for live physical
  domains. Embodied execution is explicitly two-speed: the slow governance
  plane authorizes bounded mission/action envelopes; a certified local
  control-and-safety plane executes high-frequency control, retains local
  emergency stop, and emits segment commitments plus exception receipts;
- workers, models, tools, connectors, browsers, shells, and computer-use
  providers are guest workloads/capabilities executed through daemon
  enforcement under local/domain policy and applicable authority grants;
- policy, receipts, replay, approvals, authority scopes, and settlement hooks
  are the shared trust/audit substrate. A receipt binds only its declared
  boundary fact; evidence, verification, acceptance, adjudication, and
  settlement are distinct assurance stages;
- clients are projections or operators, not private runtime truth;
- Environments views in Hypervisor App, Hypervisor Web,
  CLI/headless projections, and console.ioi.ai are projections and control
  lenses over daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
  substrate; they are not separate apps with separate runtime truth;
- CLI/headless, SDK, ADK, and ODK are separate surfaces: CLI/headless is the
  operator/scripting/CI client, TUI is an optional presentation of it, SDK is
  the low-level protocol/client library, ADK is the autonomous-system builder
  framework, and ODK is the ontology-aware surface/domain-app/data-recipe builder
  kit over semantic data-plane contracts;
- IDE/CLI/browser/hosted-agent adapters mediate through available control
  points only and must not claim total interception of opaque tools;
- models and agents may reason or propose; local/domain policy and the
  applicable authority provider authorize consequential power, while the daemon
  admits, enforces, executes, receipts, and fails closed at the deterministic
  execution boundary;
- Hypervisor's primary build artifact is an Autonomous System Package;
- Autonomous System Package lifecycle is compose -> bind -> simulate ->
  authorize -> run -> verify -> inspect receipts -> package -> deploy ->
  promote -> improve;
- Worker is the protocol actor;
- Model is a cognition backend;
- MoW is labor routing;
- Worker Training is the supply-creation lifecycle;
- TrainingBatchPlan, RawBatchArchive, QualityGateReport,
  ModelCapacityProfile, and TrainingCostLedger are first-class Foundry and
  Agentgres objects when batch-level training mechanics matter;
- Domain Ontologies and Data Recipes are the semantic data plane, surfaced
  in Hypervisor through ODK facets, Domain Apps, or contextual views;
- DistilledOntologyDataset is the compact high-signal data substrate for
  efficient specialist training and evaluation when useful;
- participant messages, artifacts, findings, semantic mappings, and verifier
  suggestions remain hostile/untrusted input until admitted. They cannot
  automatically promote into durable memory, ontology, routing, authority, or
  production capability; risk may require independent verification,
  separation of duty, affiliation disclosure, anti-Sybil/collusion controls,
  quarantine, and reversible promotion;
- external-effect work declares `replayable`, `checkpointable`,
  `compensatable`, `reconciliation_required`, or `non_retryable` posture.
  Environment restoration never establishes outcome restoration;
- governed autonomous-system chains are system-local state machines, not a
  mandatory public chain per agent, GoalRun, tool call, or receipt. Public
  consensus remains sparse and trust-driven;
- `adaptive_work_graph` is a local execution strategy only;
  `CollaborativeWorkGraph` is the shared-frontier collaboration profile above
  GoalRuns. Neither is a peer runtime.
