# Hypervisor Bounded-DAS Application Taxonomy — Winning-State Comparison and Migration Plan

> **Execution routing (2026-07-17): active specialist ledger.** Preserve this
> file for `UX-00`, taxonomy migration detail, seed coverage, pressure tests,
> and usability measures. Stage activation and product order are owned by the
> [target-end-state master guide](./ioi-target-end-state-master-implementation-guide.md);
> current Hypervisor canon owns names and membership.

Status: comparative product-architecture plan; non-canonical working document  
Date: 2026-07-14  
Scope: Hypervisor shell, application taxonomy, Palantir-seeded UX surfaces, generated applications, and the system-centered bounded-DAS journey  
Canonical authority remains: docs/architecture, especially the source-of-truth map, governed-autonomous-systems, and core-clients-surfaces

## 1. Executive verdict

Hypervisor is on the right architectural track, but the current product topology is still transitional.

The canonical lifecycle families are mostly the correct expert workbenches. The decisive correction is to put the bounded autonomous institution itself at the center of the product:

> One stable System is the primary product object. Focused applications operate governed projections of that System. Palantir-derived ports are reusable tools and interaction grammars inside those applications. Generated domain applications are the System's end-user interfaces.

Five changes produce the cleanest long-term state:

1. Add a first-class Systems home and System workspace around stable system identity.
2. Expand Sessions into one unified Work workspace and retire Missions as a peer application: `GoalRun` is durable pursued intent, `OutcomeRoom` is collective pursuit, `AutomationSpec` is reusable standing behavior, and `Session`/`WorkRun` are bounded execution contexts. Background is an execution mode, not an object kind.
3. Separate first-party owner applications, nested tool surfaces, and generated or installed applications in the catalog model.
4. Preserve Palantir-derived UX as component and workflow evidence, never as authority over IOI product taxonomy.
5. Separate mandatory local package lifecycle from optional Marketplace discovery and commerce.

The current thirteen-family division should therefore be decomposed rather than preserved literally:

~~~text
Missions as fleet-of-systems identity
  -> Systems as the durable shell home and contextual workspace for system_id

Missions as a background-work and collective-work catch-all
  -> Work as the unified shell workspace for pursued and executing work
  -> GoalRun as the durable bounded outcome pursuit
  -> OutcomeRoom as the shared pursuit above participant GoalRuns
  -> Session and WorkRun as bounded interactive or headless execution contexts
  -> AutomationSpec and AutomationRun as reusable behavior and one activation
~~~

`Mission` may remain a product-facing label or creation preset for a durable GoalRun, or for an OutcomeRoom when the pursuit is collective. It must not remain a catch-all truth object that duplicates automation, goal, room, budget, authority, attempt, and receipt state. A durable OutcomeRoom may itself be the bounded System, with its own system identity and genesis; it is not necessarily a child object inside another System. Direct sessions, project work, automations, stand-alone GoalRuns, and non-System headless work must remain possible without forcing premature genesis.

This is not a proposal to merge the truth planes into a monolith. It is a proposal to give users one coherent System context while Studio, Ontology, Data, Governance, Provenance, Evaluations, Improvement, Foundry, Operations, and the other owners retain their distinct jobs and contracts.

## 2. What this plan must determine

The comparison is complete only when it answers:

- Which concepts deserve permanent shell placement?
- Which current cards are true application owners?
- Which current cards are tools, lenses, inboxes, editors, or templates inside an owner?
- Which product surface is the primary home for a bounded institution from package candidate through genesis, operation, upgrade, migration, succession, and dissolution, without claiming canonical truth ownership?
- How should Projects, Systems, Work, Sessions/WorkRuns, AutomationSpecs/Runs, GoalRuns, OutcomeRooms, Applications, packages, nodes, and generated interfaces differ?
- Which Palantir interaction patterns are reusable and which encode a centralized data-platform ontology that IOI must not inherit?
- Which IOI-native surfaces have no adequate Palantir analogue?
- Can one topology serve very different bounded DAS deployments without adding a new application for every ontology?
- Can the migration preserve current routes and operational work while removing duplicate product identities?
- What proof demonstrates that the resulting topology helps users create and operate bounded autonomous institutions rather than merely browse an impressive app estate?

## 3. Evidence baseline

### 3.1 Canonical product direction

The pre-reconciliation baseline captured when this plan began defined:

- a small default rail: New Session, Home, Projects, Automations, Applications, Sessions, plus one singular Open Application slot;
- thirteen autonomous-systems application families;
- Environments and Operations as a separate substrate lane;
- generated applications as launchable catalog entries;
- Embodied Systems as a deployment-neutral planned surface;
- ODK as a developer kit rather than an application;
- Enterprise Learning Boundary as a cross-cutting facet rather than another application;
- a bounded autonomous system as one logical institution whose stable system identity survives node, model-route, upgrade, recovery, and migration changes.

The thirteen current families are:

1. Studio
2. Automations
3. Ontology
4. Data
5. Governance
6. Missions
7. Provenance
8. Evaluations
9. Improvement
10. Foundry
11. Marketplace
12. Workbench
13. Developer Console

Most family boundaries are directionally strong because they separate composition, meaning, data supply, authority, execution, evidence, judgment, improvement, capability creation, distribution, hands-on work, and extension. Missions is the exception: its current definition combines execution mode, trigger source, durable goal state, collective room state, and work inspection that already have stronger canonical owners.

### 3.2 Implemented catalog shape

The current implementation exposes several overlapping taxonomies:

| Layer | Current implementation |
| --- | --- |
| Suite families | Thirteen hard-coded family cards |
| Certified ports | Thirteen Palantir-derived child surfaces shown as peer apps |
| Substrate | Environments and Operations |
| Horizon | A stale HypervisorOS-labelled embodied card |
| Generated apps | Separate manager and claims in copy, but not emitted into the main application catalog |
| Route ownership | Repeated independently in shell augmentation, the Applications estate, surface registry, and seed inventory |

The end-user result is approximately twenty-six apparent suite or ported applications before substrate and horizon entries. The duplication is structural:

- Data is both a family and Pipeline Builder plus Data Connection.
- Ontology is both a family and Ontology Manager plus Object Explorer.
- Governance is both a family and Approvals.
- Studio is both a family and Solution Designer plus Machinery.
- Evaluations is both a family and AIP Evals.
- Improvement is both a family and Upgrade Assistant.
- Missions is both a family and Issues.

The central implementation defect is in the catalog membership rule: every shell-pixel-certified parity seed becomes an application. UX certification is useful evidence about a surface. It must never decide whether a product application exists.

The current Missions implementation reinforces the overlap diagnosis. It renders one aggregate over daemon automation runs, scheduled AutomationSpecs, run failures, and GoalRun blockers; its own empty state tells the user to run an automation to populate the queue. The inspected Hypervisor runtime exposes no independent `/v1/missions` record path. That is useful implementation evidence, not the architectural reason for the change: the decisive reason is that no unique Mission invariant remains after AutomationSpec/Run, GoalRun, OutcomeRoom, Session/WorkRun, authority, budget, review, and receipt ownership are separated.

### 3.3 Operational depth is much narrower than catalog breadth

The certified port registry currently declares:

| Operational state | Surfaces |
| --- | --- |
| Workflow complete | Pipeline Builder |
| Act | Data Connection, Ontology Manager, Approvals |
| Inspect | Object Explorer |
| Browse | Automate, AIP Evals, Model Catalog, Marketplace, Issues, Solution Designer, Machinery, Upgrade Assistant |

Only five of the thirteen certified ports are extracted and bound through the current surface-module contract. The rest retain flatter handlers. This is a valid migration state, but the product must not flatten all maturity levels into the same Open label.

### 3.4 Concrete route and ownership drift

| Product identity | Current route or wording | Target concern |
| --- | --- | --- |
| Studio | /__ioi/agent-studio | Legacy agent-level identity is wider than its proper lens |
| Data | /__ioi/odk#data-planes | Canon says ODK is a kit, not an application |
| Missions | Shell points to Sessions while estate points to Missions | Duplicate work homes and an overloaded wrapper across AutomationSpec, GoalRun, OutcomeRoom, Session and WorkRun |
| Provenance | /__ioi/work-ledger | Compatibility route still carries the former product name |
| Evaluations | Shell points to Feedback while estate points to Evaluations | Family route disagreement |
| Improvement | Agent Studio anchor, plus a separate Changes tool | Owner remains entangled with Studio |
| Developer Console | /__ioi/connections | Connector subset stands in for the wider extension surface |
| Embodied horizon | HypervisorOS | Stale versus deployment-neutral Embodied Systems canon |
| Machinery | Registered under Studio | Its process and state-machine grammar belongs primarily to Automations |
| Generated apps | Separate /__ioi/domain-apps manager | Not present in the catalog that promises to launch them |

### 3.5 Current strengths to preserve

The plan must not erase what is already correct:

- one native shell rail and one singular Open Application frame;
- embedded application routing that removes the double-rail failure mode;
- explicit capabilities and operational-state metadata for certified ports;
- fail-fast requirements for action, authority, and receipt declarations;
- a source-neutral shell around ported interaction grammars;
- honest empty, degraded, and not-yet-bound states;
- a clear split between systems work and infrastructure Operations in canon;
- the recurring create grammar discovered in the reference corpus:

~~~text
choose a governed starting object
  -> compose in a typed wizard or canvas
  -> preview or simulate
  -> propose
  -> admit through authority
  -> execute
  -> inspect outcome and receipts
  -> evaluate
  -> improve or promote
~~~

## 4. Winning-state decision rubric

Every surface should be classified by the following test.

### 4.1 Permanent shell category

A concept earns permanent shell placement only when it is:

- a high-frequency cross-role destination;
- understandable without platform vocabulary;
- a stable user work container rather than a specialized primitive;
- useful across most bounded-DAS ontologies;
- not merely a shortcut into one owner application.

### 4.2 First-party owner application

A surface earns owner-application status only when it:

- owns a durable job across multiple DAS types;
- has a distinct object or lifecycle responsibility;
- has non-trivial authority, evidence, or operational semantics;
- remains useful as an expert workbench outside one vertical template;
- cannot be represented honestly as a tool or contextual lens inside another owner;
- does not create a second runtime, truth store, or authority plane.

### 4.3 Tool surface

A surface is a tool when it is primarily:

- an editor, inspector, picker, inbox, graph, comparison, dashboard, wizard, or report;
- scoped to objects owned by one or more owner applications;
- meaningfully launched from a System, Project, Work, GoalRun, OutcomeRoom, AutomationRun, Session, or object context;
- reusable as a view without becoming a new truth owner.

Tools may be searchable and directly launchable. Direct launch does not make them peer products.

### 4.4 Generated or installed application

A generated or installed application is:

- an organization- or publisher-authored interface;
- bound to admitted surface descriptors, package versions, System context, ontology projections, and allowed actions;
- potentially the most prominent end-user interface;
- never the owner of constitution, authority, execution, or canonical state merely because it renders them.

### 4.5 Substrate surface

A substrate surface owns infrastructure lifecycle and posture:

- environments;
- providers;
- placement;
- capacity;
- custody;
- failover machinery;
- scheduler and daemon health.

It must not absorb logical System identity or pursued work.

## 5. Target product topology

### 5.1 System is the organizing center

The clean topology is:

~~~mermaid
flowchart TD
    Shell["Shell: Home · Systems · Projects · Automations · Applications · Work"]
    System["System workspace: one stable system identity"]
    Work["Work workspace: GoalRuns · Sessions · Rooms · queues · reviews"]
    Owners["Owner applications: specialized lifecycle workbenches"]
    Tools["Tools and lenses: editors · inboxes · graphs · pickers · reports"]
    Generated["Generated and installed system interfaces"]
    Core["Hypervisor Core · daemon · Agentgres · authority · receipts · storage"]

    Shell --> System
    Shell --> Work
    Shell --> Owners
    Shell --> Generated
    System --> Work
    System --> Owners
    Work --> Tools
    Owners --> Tools
    System --> Generated
    Work --> Core
    Owners --> Core
    Tools --> Core
    Generated --> Core
~~~

### 5.2 Recommended shell

The strongest long-term shell is:

~~~text
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
  one optional active specialized surface
~~~

Systems deserves permanent placement. Creating and operating bounded autonomous institutions is the product's defining job, and no existing shell category is a truthful substitute:

- Projects organize build work and contextual resources.
- Systems are live constitution-bound institutions.
- Automations define reusable standing behavior and the conditions under which it activates.
- Work is the unified inventory and inspection surface for pursued and executing work.
- GoalRuns preserve durable bounded outcome pursuit.
- Sessions are bounded interactive, headless, or supervisory execution and control contexts.
- OutcomeRooms coordinate persistent collective pursuit above participant GoalRuns.
- Applications are control surfaces and generated projections.

Two adoption invariants prevent the System-centered product from becoming coercive:

- starting a direct Session, Project, AutomationSpec, or stand-alone GoalRun never requires creating a System; and
- replacing the visible New Session control with a New menu must preserve a one-click and keyboard-first New Session path.

### 5.3 Canonical product-object distinctions

| Object | Durable meaning | Must not collapse into |
| --- | --- | --- |
| Project | Build and work container: repos, files, environments, drafts, receipts, defaults | Live System identity |
| System | One bounded autonomous institution across releases, nodes, models, upgrades, recovery, and migration | Process, node, package, GoalRun, Session, or UI |
| Package | Reusable versioned release material that may instantiate many Systems | Live System membership or lifecycle |
| Work | Core workspace and policy-filtered projection across pursued work, execution, reviews, incidents, and history | Canonical runtime, authority, or evidence truth |
| Session | Bounded interactive, headless, or supervisory execution/control context; may attach to a GoalRun, AutomationRun, room claim, or attempt | Durable intent, reusable trigger definition, or shared room truth |
| AutomationSpec | Durable reusable trigger, schedule, workflow, API, service, monitor, or approval-flow definition | One activation, GoalRun, transcript, or runtime truth |
| AutomationRun | One activation of an AutomationSpec; it may finish directly, create a GoalRun, or contribute bounded work to an existing room | Reusable definition or durable collective objective |
| GoalRun | Durable bounded outcome pursuit for one owner, participant, or subteam, including constraints, topology, continuation, attempts, results, verification, and course correction | Automation definition, Session transcript, or shared room frontier |
| OutcomeRoom | Flagship collective-work DAS profile over bounded GoalRuns and accepted participants; a durable room has its own System identity | Global swarm runtime, every GoalRun, or necessarily a child of another System |
| Node | Admitted deployment member with explicit roles, leases, failure domain, and observed state | System identity or automatic authority |
| Application | Specialized first-party control surface or generated interface | Runtime, authority, or canonical truth |

`Mission` is not a separate canonical row. It may be user-facing shorthand or a creation profile for a durable GoalRun, or for an OutcomeRoom when the pursued outcome is collective. Any Mission-labelled surface must expose the underlying type and refs; it cannot create an independent `HypervisorMission` truth wrapper unless a future invariant is proven that GoalRun, AutomationSpec/Run, OutcomeRoom, WorkItem/WorkRun, and their admitted relationships cannot express.

The only plausible reason to add another durable object would be a separately contracted sponsor-facing engagement spanning several independent or sequential GoalRuns and AutomationRuns with its own acceptance, SLA, termination, budget, and authority lifecycle while not being an OutcomeRoom. If that requirement becomes real, model it explicitly as an `OutcomeContract`, `ServiceOrder`, or similarly narrow object. Do not resurrect a polymorphic Mission container.

Background is orthogonal to all of these objects. It is an execution and supervision mode on Session, WorkRun, RuntimeAssignment, or worker participation—not the definition of a mission.

### 5.4 One unified Work workspace

The existing Sessions workspace should evolve into `Work`. Preserve `Sessions` as a compatibility route and a first-class view inside Work during migration.

~~~text
Work / Active
Work / Goals
Work / Sessions
Work / Rooms
Work / Queues
Work / Reviews
Work / Incidents
Work / History
~~~

The canonical lowering and projection model is:

~~~mermaid
flowchart LR
    Human["Human · API · system event"] --> GoalRun
    AutomationSpec --> AutomationRun
    AutomationRun -->|may instantiate| GoalRun
    AutomationRun -->|may execute directly| Session
    OutcomeRoom -->|coordinates participant work| GoalRun
    GoalRun -->|uses zero or more over time| Session
    Session --> WorkRun
    WorkRun --> Evidence["results · attempts · evidence · receipts"]
    Evidence --> GoalRun
    Evidence --> OutcomeRoom
~~~

This preserves one coherent place to start, supervise, inspect, intervene in, review, replay, and resume work without pretending that a transcript, a scheduled definition, and a collective outcome are the same object. A headless Session remains openable as an operator-facing control and inspection context. A GoalRun can survive Session termination, worker replacement, compaction, sleep, or course correction. An OutcomeRoom can outlive every participating Session.

The Work workspace owns no canonical work truth. It composes policy-filtered projections from GoalRun, AutomationRun, OutcomeRoom, WorkItem, WorkRun, Session, RuntimeAssignment, authority, Agentgres, and receipt contracts. System-scoped work projects into `System / Operate`; direct, Project-scoped, organization-scoped, and room-scoped work remains valid without a parent System unless the underlying object itself requires one.

Required projection invariants:

- every Work row declares a typed `subject_kind` and canonical `subject_ref` and deep-links to the type-specific detail;
- one AutomationSpec may have many AutomationRuns; an AutomationRun may finish directly or explicitly create or join zero or more GoalRuns;
- one GoalRun may use zero or many Sessions over its lifetime; closing or replacing a Session cannot close, fork, or silently mutate the GoalRun;
- a Session may exist without a GoalRun for direct terminal, editor, environment, provider, support, or other bounded operator work;
- an OutcomeRoom coordinates accepted participant GoalRuns without collapsing their owners, leases, attempts, evidence, or local truth;
- Work may map type-specific lifecycle states into display facets, but it cannot write one universal status machine back over heterogeneous objects;
- authority, budgets, review, output, learning-boundary, and receipt obligations resolve on the appropriate admitted definition, run, goal, room, assignment, claim, or result rather than being copied into a Mission wrapper;
- policy filtering applies before aggregation, so Work search, counts, incidents, recents, and caches cannot leak private GoalRun or OutcomeRoom state.

### 5.5 One persistent System workspace

Every live System should have a stable workspace:

~~~text
System / Overview
System / Design
System / Operate
System / Govern
System / Evidence
System / Improve
System / Interfaces
~~~

These are contextual modes over existing owners:

| System mode | Primary owner projections | Core questions answered |
| --- | --- | --- |
| Overview | Systems, Home | What is this institution, why does it exist, what is its state, and what needs attention? |
| Design | Studio, Ontology, Data, Automations | What is being composed, what world does it understand, what data may ground it, and what behavior is declared? |
| Operate | Systems, Work, Automations, Environments, Operations, Embodied Systems | What outcomes and executions are active, where are they running, on which admitted members, with which assignments, health, incidents, and degraded modes? |
| Govern | Governance | Which constitution, authority, budgets, amendment rules, learning boundary, lifecycle paths, AIIP terms, and optional network services apply? |
| Evidence | Provenance, Evaluations | What happened, what proves it, how was it judged, and what remains uncertain or disputed? |
| Improve | Improvement, Foundry, Governance | What change is proposed, what evidence supports it, how was it simulated, and who may promote, roll back, or reject it? |
| Interfaces | Studio, Packages, Developer Console | Which generated apps, APIs, MCP profiles, operator views, and delivery channels expose the System? |

The workspace is a context router and coherent read model. It must not duplicate owner truth.

### 5.6 Revised owner taxonomy

Systems and Work sit outside the expert-application families as stable core workspaces, like Projects and Applications. Systems is the primary product context and read model for a live System. Work is the primary product context and read model for GoalRuns, Sessions, AutomationRuns, OutcomeRooms, queues, reviews, and incidents. Neither is a canonical truth owner.

The thirteen current family registrations evolve into twelve enduring owner-application jobs. Missions retires as a peer application because its defensible work belongs to the Work core workspace and its durable semantics already belong to GoalRun, AutomationSpec/Run, OutcomeRoom, Session, and WorkRun:

| Current family | Winning disposition | Primary product responsibility |
| --- | --- | --- |
| Studio | Keep and narrow | Package and blueprint composition, agent lens, generated-interface descriptors; never observed live membership |
| Automations | Keep | Durable conditions, triggers, schedules, workflows, services, and process graphs |
| Ontology | Keep | Versioned object, link, action, function, value-type, object-set, overlay, and mapping semantics |
| Data | Keep; give it a dedicated home | Sources, syncs, recipes, datasets, media, rights and consent posture |
| Governance | Keep and deepen | Constitution, admission, authority, approvals, budgets, protected change, lifecycle continuity, learning boundary, AIIP and enrollment decisions |
| Missions | Retire as a peer owner; preserve only as a compatibility label/profile | Move run inventory, GoalRun and OutcomeRoom projections, frontiers, participants, claims, attempts, blockers, reviews and work incidents into Work. Do not preserve `HypervisorMission` as a catch-all truth wrapper. |
| Provenance | Keep | Receipts, lineage, replay, state roots, custody and qualified assertions |
| Evaluations | Keep | Evals, scorecards, feedback consent, verifier challenges and operational assurance |
| Improvement | Keep; give it a dedicated home | Discover, author, simulate and drive change candidates, canary recommendations and remediation; Governance admits or rejects promotion, rollout, rollback, recall and kill decisions |
| Foundry | Keep | Model catalog and routes, training, tuning, datasets, capability candidates and promotion handoffs |
| Marketplace | Evolve to Packages, retaining Marketplace as an optional mode | My packages, installed packages, releases, dependencies, recall and impact; optional discovery, publishing and exchange |
| Workbench | Keep; rename the product surface Developer Workspace | Code, files, terminal, ports, debugging and environment-bound hands-on work; the clearer label avoids collision with the broader Work workspace |
| Developer Console | Keep; give it a canonical route | Connectors, MCP, integration/configuration registrations, APIs, clients, SDKs, extensions and conformance; Environments/Operations own provider lifecycle and health |

Separate substrate:

| Surface | Winning disposition |
| --- | --- |
| Environments | Environment lifecycle, readiness, ports, services, tasks and substrate posture |
| Operations | Cross-estate infrastructure and member operations: provider health, placement, provisioning, capacity, custody, failure domains, fencing, failover, RPO/RTO and provider spend |

Embodied Systems is a conditional thirteenth `owner_application` registration with `surface_availability: planned`, contextually shown or recommended when a System has embodied domains or the user has a fleet role, and nonlaunchable until its route and implementation exist. It projects Embodied Runtime truth and never defines a separate System type or requires HypervisorOS.

### 5.7 Systems, Work, Automations, Governance, and Operations seam

| Concern | Systems | Work | Automations | Governance | Operations | Canonical execution and truth |
| --- | --- | --- | --- | --- | --- | --- |
| System identity and lifecycle status | Primary contextual home and read model | Filters work by System when applicable | References System scope without changing object kind | Decides protected lifecycle transitions | Shows resulting deployment effects | Domain kernel and daemon execute; Agentgres admits |
| Standing behavior | Shows System-scoped policies and health rollups | Shows activation and resulting-work projections | Owns AutomationSpec authoring, triggers, schedules, workflows, services and AutomationRun history | Applies policy, authority, budget and review gates | Supplies placement and capacity posture | Daemon activates definitions; Agentgres records runs and receipts |
| GoalRun and OutcomeRoom pursuit | Shows a System-scoped rollup | Primary inventory, control, inspection, review, frontier and participant surface | May explicitly instantiate or contribute to a GoalRun; never becomes one merely because it is long-running or System-bound | Applies policy, budget, authority and admission gates | Supplies placement and capacity posture | Daemon coordinates work; Agentgres admits state and evidence |
| Session and WorkRun execution | Shows a System-scoped execution rollup | Primary bounded execution, intervention, transcript, trace and replay surface | May request bounded execution for an activation | Applies effect, review and emergency gates | Supplies runtime placement, custody and health | Daemon executes; Agentgres records receipts and admitted results |
| Member add, drain, promote or remove | Initiates or explains in System context | No ownership | No ownership | Approves when authority or assurance changes | Provisions, fences and operates members | Daemon and domain membership path execute; Agentgres admits |
| Improvement and release | Shows current and proposed revision | Supplies outcome evidence | May schedule or execute admitted rollout steps | Admits, rejects, pauses, recalls or rolls back | Executes admitted rollout and rollback actions | Daemon executes; Agentgres records receipts |

Systems presents System-filtered logical topology and explains desired-versus-observed state. Operations remains the functional cross-estate control surface for provisioning, fencing, failover and member operations. Governance authorizes any change that alters authority, assurance or protected deployment posture.

## 6. Application catalog and registry correction

### 6.1 Extend the existing Application Surface Registration Contract

Do not create unrelated hand-maintained catalogs. Extend the canonical
Application Surface Registration Contract as one normalized record family so a
stable definition never absorbs per-release, per-installation, per-System, or
per-runtime cardinality:

~~~text
HypervisorApplicationSurfaceRegistration
  surface_id: surface://...
  surface_key: URL-safe deployment-catalog-unique string; never inferred
  surface_class:
    owner_application
    substrate_application
    tool_surface
    extension_application

  publisher_ref:
    org://... | user://... | ioi://publisher/... | null

  surface_origin:
    first_party
    organization
    external_publisher

  surface_creation_method:
    hand_authored
    studio_generated
    developer_kit_generated
    imported
    adapted

  surface_availability:
    planned | preview | limited | available | deprecated | unavailable

  canonical_route: string
  route_alias_refs: [route-alias://...]
  primary_user_job: string
  supported_placements:
    [permanent_shell | applications_catalog | open_application | contextual]
  launch_modes: [string]
  authority/privacy/receipt/replay/eval/promotion policy refs

HypervisorRouteAliasRegistration
  route_alias_ref: route-alias://...
  owner_ref: hypervisor-workspace://... | surface://...
  alias_route_pattern: string
  resolution:
    static target_route_template | typed fail-closed resolver contract
  preserve query/hash/embed/return state, singular Open Application identity
  and back-stack, and every typed context ref

HypervisorSurfaceReleaseRecord
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
  exact versioned descriptor, object, action, and operator-contract refs

HypervisorSurfaceInstallationBinding
  installation_ref: install://...
  surface_ref: surface://...
  release_ref: package://.../release/...
  org_ref: org://...
  surface_installation_state:
    not_applicable | not_installed | installing | installed | update_available |
    uninstalling | uninstalled
  surface_enablement_state: not_applicable | enabled | disabled
  org/Project visibility, audience, allowed-object/action, and
  authority-preview refs

HypervisorSystemInterfaceBinding
  system_binding_ref: package_binding://...
  installation_ref: install://...
  system_ref: system://...
  surface_enablement_state: not_applicable | enabled | disabled
  narrowed visibility/audience/allowed-object/action/authority-preview refs

HypervisorSurfaceServingBinding
  serving_binding_ref: surface-serving://...
  installation_ref: install://...
  system_binding_ref: package_binding://... | null
  surface_operational_state:
    inactive | starting | ready | serving | degraded | blocked | stopped |
    unavailable

HypervisorProductSurfaceProjection
  request-scoped join of one stable surface with eligible release,
  installation, System-interface, and serving bindings
  policy-safe display, family, publisher, primary-owner, and tool-kind metadata
  group_kinds:
    first_party_applications | tools_for_context | organization_applications |
    installed_applications | system_interfaces | recommended | recent |
    favorites
  launchable: boolean
  disabled_reason_codes: [string]
  selected installation enablement, selected System enablement, and
  derived effective enablement
  effective visibility, audience, objects, actions, and authority-preview refs
  canonical definition route plus compiler-resolved launch route
  discriminated launch binding (or null when nonlaunchable) and typed context refs
~~~

Classification, publisher ref, origin, creation method, distribution channel,
availability, admission state, installation state, package disposition,
enablement state, capability depth, and operational state are separate axes.
Installation is
state, not an application class; the developer kit is a creation method, not a
publisher; marketplace is a distribution channel, not origin. Planned is an
availability state, not an application kind. Owner-application maturity is
judged against its own durable job and must not be inflated by the maturity of
its strongest child tool.

An external publisher requires a non-null `ioi://publisher/...` ref; an
organization-origin surface requires its accountable `org://...` or
`user://...` ref. Null is reserved for bundled first-party registrations whose
publisher accountability is fixed by the release. Package identity, immutable
release identity, installation-binding identity, and System-binding identity
remain distinct; serving bindings are distinct again. One surface definition
may therefore have many releases, installations, System bindings, and serving
routes without duplicating or mutating the definition.
Stable object/action/operator declarations are ceilings; the immutable release
owns the exact executable descriptor and contracts. Installation contracts are
subsets of the selected release, and a System binding may only narrow the
installation boundary. A definition edit can therefore never silently expand
an already installed release.
Every join must preserve surface identity across release, installation, System
binding, and serving binding; release identity across installation, System
binding, and serving binding; and System-binding identity wherever a serving
route is System-scoped. A launch binding is a discriminated mapping, never an
independent kind union plus ref union. Installation-level and System-level
enablement remain separately visible; effective enablement is disabled when
either applicable gate is disabled and launch requires every applicable gate
to be enabled or not applicable.

Systems, Home, Projects, Applications and Work remain core shell workspace identities, not application registrations. Sessions is a typed Work view and compatibility route, not a second workspace registration. A core-workspace definition may live beside the application registrations so one product-surface compiler can generate navigation and catalog projections without pretending that Systems or Work is another app. Automations is one owner-application registration with a shell placement, not two identities.

Preserve the current surface registry as the tool runtime and action-binding authority. The product compiler joins:

- static owner, substrate and planned application registrations;
- registered tool surfaces and their runtime metadata;
- admitted generated and installed records from daemon and Agentgres truth;
- request-scoped organization, user, Project, System, GoalRun, OutcomeRoom,
  AutomationRun, Session, WorkQueue, WorkItem, and WorkRun projections.

Parity matrices, screenshots, pixel certificates and capture provenance remain implementation evidence attached to a tool surface. They never grant product membership. Native IOI tools may exist without parity evidence.

### 6.2 Canonical route ledger

The target routes are contract fields, not client-inferred labels:

| Surface or action | Canonical target route | Compatibility rule |
| --- | --- | --- |
| Home | `/home` | `/ai` and `/__ioi/home` |
| New Session | `/work/new-session` | `/ai#new-session`; remains one click |
| Systems | `/systems` | never fabricate Systems during migration |
| Projects | `/projects` | preserve Project context |
| Applications | `/applications` | consume the common compiler projection |
| Work | `/work` | `/sessions` → `/work/sessions`; `/missions` → typed GoalRun/OutcomeRoom resolution |
| Studio | `/studio` | `/__ioi/agent-studio` |
| Automations | `/automations` | shell placement and app identity share one registration |
| Ontology | `/ontology` | current ontology/ODK routes remain contextual aliases |
| Data | `/data` | `/__ioi/odk#data-planes` |
| Governance | `/governance` | `/__ioi/governance` |
| Provenance | `/provenance` | `/__ioi/work-ledger` |
| Evaluations | `/evaluations` | `/__ioi/evaluations` and `/__ioi/feedback` |
| Improvement | `/improvement` | current improvement routes remain aliases |
| Foundry | `/foundry` | `/__ioi/foundry` |
| Packages | `/packages` | `/marketplace` and `/__ioi/marketplace` → `/packages/marketplace` |
| Developer Workspace | `/developer-workspace` | `/workbench` and `/__ioi/workbench` |
| Developer Console | `/developer-console` | `/__ioi/connections` |
| Environments | `/environments` | `/__ioi/environments` |
| Operations | `/operations` | `/__ioi/operations` |
| Embodied Systems | `/embodied-systems` reserved | planned and nonlaunchable; `/fleet` resolves contextually |

Work owns `/work/goals`, `/work/sessions`, `/work/rooms`,
`/work/queues`, `/work/reviews`, `/work/incidents`, and `/work/history`.
Typed detail routes preserve canonical subject or facet identity. General
extension applications compile to `/applications/{surface_key}`; admitted
System interfaces compile to
`/systems/{system_id}/interfaces/{system_binding_id}`. Every alias preserves
query, hash, embed/return state, and Organization, Project, System, GoalRun,
OutcomeRoom, AutomationRun, Session, WorkQueue, WorkItem, and WorkRun context.
Workspace/surface IDs and canonical routes are unique. Every alias resolves to
exactly one registration and canonical route or one typed fail-closed resolver;
alias-versus-canonical and cross-identity alias collisions fail closed. No
emitted navigation, search, catalog, command-palette, or launch row may point
to an unregistered or orphan route.

### 6.3 Minimum registration contract

Stable application-surface registrations should carry:

- stable surface ID, display title, family and class;
- publisher identity/origin, creation method, and availability;
- canonical route and compatibility aliases;
- canonical owner doc and primary owning object family;
- optional consuming or contextual application IDs;
- primary user job and supported roles;
- supported permanent-shell, catalog, Open Application, Home, Project, System,
  Work, GoalRun, OutcomeRoom, Session, organization and operator placements;
- composition pattern and launch modes;
- daemon, API and Agentgres dependencies;
- authority crossings, mutation boundary and proof obligations;
- lifecycle-control, ontology and promotion posture where applicable;
- maturity wording that is true for that registration itself.

Tool registrations should additionally carry:

- exactly one primary owner application;
- tool kind: editor, inspector, inbox, graph, picker, wizard, report, dashboard or comparison;
- object and action contracts;
- read, propose and effectful behavior;
- required capability leases and receipts;
- shared-component dependencies;
- optional UX seed, evidence grade and parity refs.

Shared UX primitives are code-level components, not multi-owner catalog registrations. One tool may be consumed contextually by several applications while retaining one primary owner.

The normalized release, installation, System-interface, and serving records
must carry distribution/admission/disposition/capability,
installation/deployment enablement, System enablement/audience/actions, and
operational health respectively. The product projection joins them without
moving those fields back onto the stable definition.

Extension-application registrations should additionally distinguish:

- draft candidate;
- admitted package;
- installed binding;
- serving runtime;
- disabled;
- recalled;
- revoked.

They should carry the owning organization, package and surface-descriptor refs, ontology and data projections, allowed actions, authority-preview policy, visibility, audience, deployment posture and evidence refs. A draft package or organization-wide tool may have no System binding. An effectful System interface must have an admitted System/context binding before launch.

### 6.4 Dynamic, policy-filtered catalog projection

The target catalog cannot be a globally cached static matrix:

~~~text
static registrations
  + daemon-admitted package, generated-interface, and install records
  + authenticated organization and user preferences
  + Project, System, GoalRun, OutcomeRoom, and Session context
  -> policy-filtered catalog projection
~~~

Required behavior:

- daemon or preference-service failure does not hide static first-party inventory;
- drafts and publish candidates never appear as ordinary launchable applications;
- one stable registration appears once even when it matches several groups;
- organization, user, context and cache data never leak across tenants or Systems;
- release ID, installation ID and System-binding ID remain distinguishable;
- disable, recall or revocation removes launch eligibility immediately;
- favorites and recents are projections over stable entries, not new entries.

Applications should be query-first and present user-meaningful filters:

~~~text
First-party applications
Tools for this context
Organization applications
Installed applications
System interfaces
Recommended for this context
Recent and favorites
~~~

Internal categories such as Ported apps, Harvested seeds, Pixel certified or Substrate bound must never appear as end-user product taxonomy.

A user may search for Pipeline Builder and launch it directly. The result should open as:

~~~text
Data / Pipeline Builder
System: system://...
Project: project://...
~~~

It should not appear as an unrelated peer product beside Data.

## 7. Current certified Palantir-port disposition

| Current certified surface | Current family | Winning product placement | User-facing tool label | Required semantic reshape |
| --- | --- | --- | --- | --- |
| Pipeline Builder | Data | Data / Recipes | Pipeline Builder or Recipe Builder | Governed sources and recipes, rights and consent, receipted materialization |
| Data Connection | Data | Data / Sources | Data Connections | Connector use binding, sync posture, credential and egress boundaries |
| Ontology Manager | Ontology | Ontology / Schema | Ontology Manager | Versioned sovereign ontology, action contracts, mappings, provenance and consent |
| Object Explorer | Ontology | Ontology / Explore | Object Explorer | Governed object sets, saved scopes, visibility and assertion provenance |
| Approvals | Governance | Governance / Approvals | Approvals | Authority, constitution, release, lifecycle, budget and exception decisions |
| Issues | Missions | Work / Incidents | Incidents | Reusable subject-routed inbox: GoalRun, AutomationRun, Session, claim and attempt blockers appear in Work; lifecycle or constitution incidents open in System context with Governance action; provider, fencing, replica and capacity incidents route to Operations |
| Model Catalog | Foundry | Foundry / Models | Model Catalog | Replaceable cognition supply, route rights, custody, eval and learning-boundary posture |
| Marketplace | Marketplace | Packages / Marketplace | Marketplace | Optional discovery and exchange over admission-previewed packages; no ambient authority or context |
| Solution Designer | Studio | Studio / System Design | System Designer | Real package, constitution candidate, agent, policy, route, topology and interface objects |
| Machinery | Studio | Automations / Process Graphs | Process Graphs | Move primary ownership from Studio to Automations; nodes become governed workflow or state-machine objects |
| Automate | Automations | Automations / Monitors | Monitors | Conditions over governed object sets and events; effects are admitted and receipted |
| Upgrade Assistant | Improvement | Improvement / Changes | Change Inbox | Evidence-backed proposals, deadlines, simulation, canary and rollback requests; Governance admits the resulting change |
| AIP Evals | Evaluations | Evaluations / Suites | Evaluation Suites | Systems, agents, routes and outputs as subjects; evidence and consent-aware EvalRuns |

Compatibility routes may remain throughout migration. The product hierarchy and descriptor ownership should change before physical route removal.

## 8. Broader Palantir-seeded UX relevance

The broader capture corpus is most valuable as an interaction-grammar library.

| Seed family | Reusable IOI grammar | Winning owner or substrate |
| --- | --- | --- |
| Solution Design, Logic, Workshop, Module, Slate | Typed system and interface composition, inspectors, preview, publish | Studio |
| Object Monitoring, Machinery, Rules, Scheduler | Condition-effect wizard, state graph, schedules, trigger feeds | Automations |
| Ontology Manager, Value Types, Hubble, Vertex | Schema workbench, object explorer, saved sets, relation graph | Ontology |
| Data Connection, Hyperauto, Pipeline Builder, Dataset, Contour, Fusion | Source-first ingestion, recipes, previews, analysis lenses | Data |
| Approvals, Checkpoints, permissions, Cipher, Retention, Control Panel | Inboxes, scoped policy, justification, fail-closed admin states | Governance |
| Job Tracker, Issues, Data Health, Resource Management | Run inventory, incidents, health and spend rollups | Work or Operations according to logical-work versus infrastructure ownership |
| Monocle, Workflow Lineage, Notepad export | Evidence graph, history, health, replay and report export | Provenance |
| Evals, Insight, Quiver, Contour | Suite library, governed subject selection, comparison and scorecards | Evaluations |
| Upgrade Assistant, Linter, Developer Branching | Change inbox, impact, proposal diff, validation and rollback | Improvement |
| Model Catalog, Model Studio, ML, Compute Module | Catalog, compare, training workspace and promotion gates | Foundry |
| Marketplace, Artifacts, examples, Walkthroughs, Code Templates | Package registry, install, recall and executable templates | Packages, with optional Marketplace mode |
| Code Workspaces, Repositories, Compass, Carbon | Environment launch, files, code, terminals and resource selection | Developer Workspace |
| Developer Console, Custom Widgets, Functions, OAuth clients | Build-inside versus scaffold-outside, SDKs, registrations and conformance | Developer Console |
| Map, time series, allocation, work and health patterns | Fleet telemetry, geospatial allocation and incidents | Embodied Systems specialist application |

### 8.1 Evidence and readiness grading

Every seed disposition must record three independent judgments:

| Axis | Values |
| --- | --- |
| UX evidence grade | bootable editor, captured wizard, complete landing, shell-only, bundle-inferred, dead or redirect |
| Contract readiness | runtime-bound, read-model-ready, contract-defined, contract-missing |
| Disposition | adopt, component-extract, reference-only, live re-harvest required, reject |

Current evidence should be read with these qualifications:

- Machinery, Solution Design, Monocle and Object Monitoring contain the strongest captured grammars.
- Workshop or Module, Slate, Logic, Quiver, Vertex and several builder editors have documented editor gaps; their concepts may be strong while their captured implementation is incomplete.
- Developer Console and Custom Widgets have origin-fold or CORS mounting gaps.
- Map and Resource Management are comparatively weak UX seeds.
- The local-composition crosswalk is archived historical evidence, not product-mapping authority.
- Evidence quality never substitutes for the IOI contract and effect boundary.

### 8.2 Reusable UX primitives to extract

The long-term value is a shared IOI application grammar, not a collection of copied mini-products:

1. Context-aware application catalog with search, recent, favorite, recommended and object-sensitive launch.
2. Typed resource and object picker with scope, owner, status, saved sets and permission posture.
3. Dense inventory-to-inspector pattern with stable deep links.
4. Governed creation and genesis wizard.
5. Typed canvas with object-aware nodes, proposals, inspectors, layout tools and explicit unsaved versus admitted state.
6. Lifecycle strip showing version, phase, blockers, authority gates, jobs, receipts and next permitted transitions.
7. Authority preview drawer showing requested scopes, budgets, affected Systems, evidence, approvers, expiry and revocation posture.
8. Desired-versus-observed topology view with node roles, assignments, watermarks, failure domains, fencing, RPO/RTO and degraded state.
9. Lineage, evidence and replay drawer shared by Systems, Provenance, Evaluations and Improvement.
10. Incident and remediation queue with status, assignment, priority, affected objects, evidence and governed actions.
11. Proposal, diff, simulation, release, canary and rollback drawer.
12. Package, install, publish, version and recall flow.
13. Generated application frame with System context and authority-aware actions.
14. Executable walkthrough that materializes real governed objects rather than passive tutorial content.
15. Honest empty, unavailable, degraded, read-only and permission-denied states.
16. Persistent context breadcrumb:

~~~text
Organization / Project / System / Application / Tool / Object
~~~

### 8.3 Graft boundary

Every adopted action grammar must change semantics at the effect boundary:

~~~text
reference object action
  -> IOI proposal
  -> policy and authority preview
  -> daemon admission and execution
  -> receipt and resulting canonical projection
  -> evaluation or improvement handoff when applicable
~~~

A copied button, graph, or wizard is not operational until this path is real.

### 8.4 Cargo-cult traps

Reject:

- one reference-product app becoming one Hypervisor app;
- pixel parity deciding product membership;
- Ported apps as an end-user category;
- a visual canvas becoming runtime, semantic, or lineage truth;
- generic resource IDs replacing typed IOI objects;
- dataset permissions standing in for capability authority;
- favorite, folder, install, or organization chrome copied without an IOI owner contract;
- a graph edge described as proof without a receipt or qualified assertion;
- logical Work and infrastructure Operations being merged;
- a process, VM, node, or replica being treated as the logical System;
- Governance becoming ambient administrator power;
- one universal centralized ontology being assumed;
- marketplace installation bypassing local admission;
- HypervisorOS becoming the price of embodied participation;
- every new canonical object earning another application card.

## 9. IOI-native UX Palantir cannot provide

The following require native product design even when a port supplies useful visual grammar:

- package candidate to genesis and activation;
- constitution drafting, protected clauses and amendment;
- lifecycle continuity: recover, migrate, fork, adopt, succeed, retire and dissolve;
- stable System identity across releases, nodes, models and interfaces;
- desired versus observed multi-node topology;
- same-System useful work assignment, leases, verification, reconciliation and duplicate-effect prevention;
- conditional AIIP terms negotiation, semantic crosswalk risk, work awards and portable exit;
- Enterprise Learning Boundary, source rights, bidirectional provider rights, eligible derivatives and capability exit;
- OutcomeRoom frontier, participants, claims, attempts, findings, challenges and contribution lineage;
- local-agent pairing versus participant admission versus reusable-worker publication;
- EmbodiedResourceGroup, physical-unit membership, command and acknowledgement, certified local safety loops and emergency stop;
- optional IOI Network and L1 service enrollment;
- explicit oracle and external-world evidence posture;
- system-level succession, residual assets, obligations and terminal evidence.

These are the differentiating bounded-institution surfaces. They should receive more product attention than additional browse-only port breadth.

### 9.1 Post-Taxonomy Seed Coverage Ledger (`UX-00`)

This ledger rebases the capture and certification estate against the current
canonical product topology. It is implementation evidence, not architecture
authority. Canonical surface membership and owner boundaries come from
`docs/architecture`; named reference-product surfaces remain confined to this
ignored implementation artifact and the local capture corpus.

“Direct certified seed” means a certified child-tool or interaction seed, not
a complete workspace or application. A direct seed may be contextually
consumed elsewhere, but it has exactly one primary disposition below.

#### Frozen target census

| Target id | Class and owner/truth boundary | Canonical route | Registry/compiler and serving checkpoint |
| --- | --- | --- | --- |
| `workspace:home` | Core workspace; projection only | `/home` | Registered `partial`; `/ai` is a compatibility alias |
| `workspace:systems` | Core workspace; no independent truth store | `/systems` | Registered `planned`; unavailable and nonlaunchable |
| `workspace:projects` | Core workspace; Project context projection | `/projects` | Registered `partial`; canonical route serves |
| `workspace:applications` | Core workspace; product-surface compiler projection | `/applications` | Registered `static_shadow`; `/__ioi/applications` is a compatibility alias |
| `workspace:work` | Core workspace; typed heterogeneous-work projection | `/work` | Registered `compatibility_only`; `/__ioi/missions` is a compatibility alias and `/sessions` remains an adjacent compatibility route |
| `application:studio` | Owner application | `/studio` | Registered `partial`; compatibility route serves |
| `application:automations` | Owner application | `/automations` | Registered `partial`; compatibility route serves |
| `application:ontology` | Owner application | `/ontology` | Registered `partial`; compatibility route serves |
| `application:data` | Owner application | `/data` | Registered `partial`; compatibility route serves |
| `application:governance` | Owner application | `/governance` | Registered `partial`; compatibility route serves |
| `application:provenance` | Owner application | `/provenance` | Registered `partial`; compatibility route serves |
| `application:evaluations` | Owner application | `/evaluations` | Registered `partial`; compatibility route serves |
| `application:improvement` | Owner application | `/improvement` | Registered `partial`; compatibility route serves |
| `application:foundry` | Owner application | `/foundry` | Registered `partial`; compatibility route serves |
| `application:packages` | Owner application; Marketplace is an optional mode | `/packages` | Registered `compatibility_only`; Marketplace predecessor serves while the target Packages lifecycle remains not started |
| `application:developer-workspace` | Owner application; Workbench is a compatibility alias | `/developer-workspace` | Registered `partial`; Workbench compatibility route serves |
| `application:developer-console` | Owner application | `/developer-console` | Registered `partial`; Connections compatibility route serves |
| `application:environments` | Substrate application | `/environments` | Registered `partial`; compatibility route serves |
| `application:operations` | Substrate application; infrastructure-only | `/operations` | Registered `partial`; compatibility route serves |
| `application:embodied-systems` | Conditional specialist owner application | `/embodied-systems` | Registered `planned`; unavailable and nonlaunchable |
| `extension-application:*` | Typed extension-application class; each admitted registration owns its interface lifecycle, never domain truth | `/applications/{surface_key}` | Target contract registered; daemon/package/install/System-binding inventory is `not_connected`, with no admitted entries |

The checkpoint above describes registration and serving posture only. It must
not be read as canonical capability maturity. The following status overlay
keeps those dimensions separate and makes every target's still-open proof
state explicit:

| Target | Registry/compiler | Serving posture | Canonical capability status | Seed status | `UX-00` proof |
| --- | --- | --- | --- | --- | --- |
| Home | registered `partial` | `/ai` compatibility | unassessed per target | mapped, candidate-only | open |
| Systems | registered `planned` | unavailable/nonlaunchable | not started | mapped, native-first | open |
| Projects | registered `partial` | `/projects` canonical | unassessed per target | mapped, candidate-only | open |
| Applications | `static_shadow` | compatibility route | partial static compiler; policy and dynamic bindings absent | mapped; structural compiler verified | terminal proof open |
| Work | registered `compatibility_only` | Missions compatibility; Sessions adjacent | canonical contract not started; compatibility UI partial | `Issues` rebased | open |
| Studio | registered `partial` | compatibility route | unassessed per target | `Solution Designer` rebased | open |
| Automations | registered `partial` | compatibility route | unassessed per target | `Automate` and `Machinery` rebased | open |
| Ontology | registered `partial` | compatibility route | unassessed per target | `Ontology Manager` and `Object Explorer` rebased | open |
| Data | registered `partial` | compatibility route | unassessed per target | `Pipeline Builder` and `Data Connection` rebased | open |
| Governance | registered `partial` | compatibility route | unassessed per target | `Approvals` rebased | open |
| Provenance | registered `partial` | compatibility route | unassessed per target | mapped, candidate-only | open |
| Evaluations | registered `partial` | compatibility route | unassessed per target | `AIP Evals` rebased | open |
| Improvement | registered `partial` | compatibility route | unassessed per target | `Upgrade Assistant` rebased | open |
| Foundry | registered `partial` | compatibility route | unassessed per target | `Model Catalog` rebased | open |
| Packages | registered `compatibility_only` | Marketplace compatibility | target lifecycle not started | `Marketplace` rebased | open |
| Developer Workspace | registered `partial` | Workbench compatibility | unassessed per target | mapped, candidate-only | open |
| Developer Console | registered `partial` | Connections compatibility | unassessed per target | mapped, candidate-only | open |
| Environments | registered `partial` | compatibility route | unassessed per target | mapped, candidate-only | open |
| Operations | registered `partial` | compatibility route | unassessed per target | mapped, candidate-only | open |
| Embodied Systems | registered `planned` | unavailable/nonlaunchable | not started | mapped, native-first | open |
| Extension applications | contract only; inventory `not_connected` | no admitted instances | lifecycle and inventory not started | mapped, native-first | open |

#### Core workspaces

| Target | Direct certified seed | Broader candidate seeds | IOI-native requirements | Disposition | Terminal proof obligation |
| --- | --- | --- | --- | --- | --- |
| Home | None | Narrative Home, Applications modal, Recent/Compass, Walkthroughs, Training | Role- and context-aware attention, System/Work/authority rollups, honest unavailable/degraded state, owner deep links | Component-extract discovery and onboarding grammar; native Home composition | `UX00-CW-HOME`: novice and operator fixtures show only policy-eligible real projections; every card deep-links to its owner; daemon/preference failure neither invents truth nor hides static recovery paths |
| Systems | None | Solution Design, Workshop/Module, Object Monitoring, Monocle, Resource Management | Stable System identity, blank-to-genesis, contextual Overview/Design/Operate/Govern/Evidence/Improve/Interfaces modes, desired/observed membership, lifecycle continuity | Reference/component-extract inspectors; native-first System workspace | `UX00-CW-SYSTEMS`: one System survives node, model-route, package, and interface replacement; each mode routes to its owner; genesis, degraded operation, recovery, migration, and dissolution are distinguishable |
| Projects | None | Compass/Files, Code Repositories, Developer Branching, installed-example resource graph | Project context orthogonal to System and work kind, direct sessions without forced genesis, policy-filtered resource/System/work associations | Component-extract resource navigation; native project projection | `UX00-CW-PROJECTS`: one Project supports direct Session work plus zero, one, or several Systems without identity collapse or cross-project/tenant leakage |
| Applications | None | Applications modal, Narrative Home, Marketplace discovery, Compass resource detail | One policy-filtered compiler for workspace/application/tool/extension registrations; independent origin, creation, distribution, admission, installation, enablement, capability, and operational dimensions | Component-extract search/detail grammar; reject certification-derived membership; native compiler/catalog | `UX00-CW-APPLICATIONS`: a certification toggle cannot change membership; one extension appears once across organization/install/System contexts; disable, recall, or revocation removes launch eligibility immediately |
| Work | `Issues` — partial incident/inbox seed; rebind from Missions | Job Tracker, Scheduler, Object Monitoring, Data Health, Monocle, Approvals | Typed projections of GoalRun, OutcomeRoom, AutomationRun, Session, WorkRun, queues, reviews, and incidents; no universal status or generic incident truth; subject-owner routing and policy filtering | Adopt/component-extract Issues as Work / Incidents; retire Missions ownership; native typed aggregation | `UX00-CW-WORK`: Mission aliases resolve to an explicit GoalRun or OutcomeRoom; background mode never changes object kind; incident actions route to the typed source owner; private work is absent from counts, search, cache, and detail |

#### Enduring owner applications

| Target | Direct certified seed | Broader candidate seeds | IOI-native requirements | Disposition | Terminal proof obligation |
| --- | --- | --- | --- | --- | --- |
| Studio | `Solution Designer` | Solution Design, Agent Studio, Workshop/Module, Slate, Logic, Custom Widgets | Source-neutral package/blueprint composition, agent lens, constitution/policy/topology/interface descriptors, visual/code equivalence, proposal and genesis preview; never observed live truth | Adopt certified designer as tool; component-extract builder grammar; native package/genesis semantics | `UX00-OA-STUDIO`: visual and code edits compile identically; draft, proposed, admitted, and observed states remain distinct; genesis/effect requests cross authority and daemon boundaries |
| Automations | `Automate`, `Machinery` — Machinery rebinds from Studio | Object Monitoring, Scheduler, Foundry Rules, Logic, Job Tracker | AutomationSpec/AutomationRun separation, typed condition-over-object-set grammar, schedules/triggers/services/process graphs, admitted effects and receipts | Adopt both certified tools; rebind Machinery to Process Graphs; component-extract scheduler/rules grammar | `UX00-OA-AUTOMATIONS`: one spec produces distinct runs; routine completion does not mint a GoalRun; escalated pursuit does; every consequential effect is authorized and receipted |
| Ontology | `Ontology Manager`, `Object Explorer` | Value Types, Hubble, Vertex, Object Monitoring, Insight | Versioned sovereign object/link/action/function/value semantics, saved sets, mappings, consent/visibility, assertion provenance; no universal centralized ontology | Adopt both certified tools; component-extract schema/explore/graph grammar; replace centralized assumptions | `UX00-OA-ONTOLOGY`: schema revision, governed object-set exploration, action-contract binding, mapping, consent, and provenance operate through real ontology projections and fail closed when unavailable |
| Data | `Pipeline Builder`, `Data Connection` | Builder, Hyperauto, Dataset, Contour, Fusion, Data Health, Workflow Lineage, Time Series Catalog, Document Intelligence | Sources/syncs, DataRecipes, datasets/media, rights, consent, credential and egress boundaries, materialization lineage | Adopt both certified tools; component-extract analysis/health grammar; native rights and receipt semantics | `UX00-OA-DATA`: source-to-recipe-to-materialized projection completes with rights/consent checks, exact lineage, receipt, denial, degraded sync, and recovery fixtures |
| Governance | `Approvals` | Checkpoints, Control Panel, Resource Management, Cipher, Retention, Linter, Sensitive Data Scanner, Foundry Rules | Constitution, protected clauses, exact authority, capability leases, budgets, lifecycle/succession, learning boundary, AIIP and optional network enrollment; no ambient admin power | Adopt certified approvals; component-extract policy/admin controls; native constitutional and authority lifecycle | `UX00-OA-GOVERNANCE`: exact-action review binds subject, context, risk, scope, expiry, factor, decision, and receipt; recovery cannot reconstruct authority; protected transitions cannot bypass admission |
| Provenance | None | Monocle, Workflow/Data Lineage, Job Tracker, Notepad export, Artifacts | Receipt chronology, qualified assertion graph, source-snapshot-derived-export lineage, state/receipt roots, replay, custody, contradiction and challenge | Candidate-only; component-extract lineage/history grammar; native-first proof semantics | `UX00-OA-PROVENANCE`: an operator can move from visible outcome to exact operation, authority, evidence, artifact lineage, roots, replay, contradiction, and offline-verifiable export without a fabricated “proof” edge |
| Evaluations | `AIP Evals` | Evals, Insight, Quiver, Contour, model comparison and target-selection patterns | Immutable suite revisions and epochs, subject selection, holdout/exposure custody, evaluator validity, feedback consent, challenges and re-verification; no promotion authority | Adopt certified suite tool; component-extract compare/scorecard grammar; native epoch and custody semantics | `UX00-OA-EVALUATIONS`: frozen epoch reproduces, exposure is visible, invalid evaluator and challenge paths work, and score output cannot activate a candidate |
| Improvement | `Upgrade Assistant` | Linter, Developer Branching, Checkpoints, Job Tracker | Agenda/campaign separation, candidate ancestry, negative knowledge, comparison, simulation, canary recommendation, proposal and target-owner activation/recovery handoff | Adopt certified change inbox; component-extract diff/checkpoint grammar; native campaign and proposal lineage | `UX00-OA-IMPROVEMENT`: candidate lineage, rejected results, simulation, canary, rollback proposal, and Governance handoff remain inspectable; Improvement cannot self-promote |
| Foundry | `Model Catalog` | Model Studio, ML Library, Foundry Inference, Code Workspaces, Compute Module, Agent Studio | Model/route/mount catalog, tuning/training/dataset/capability candidates, route rights, custody, learning-boundary posture and promotion handoffs; not evaluation or release owner | Adopt certified catalog; component-extract training/compare grammar; native route-rights and candidate contracts | `UX00-OA-FOUNDRY`: create or select a candidate, bind eligible route and rights, execute admitted experiment, hand evidence to Evaluations/Improvement, and refuse an ineligible provider without losing institutional state |
| Packages | `Marketplace` — rebind from peer Marketplace family | Marketplace, Artifacts, examples, Walkthroughs, Code Templates, Compass install flows | Mandatory local candidate/release/install/dependency/impact/deprecation/revocation/recall lifecycle; Marketplace remains optional discovery/exchange | Adopt certified listing tool only as Packages / Marketplace; component-extract install/template grammar; native package lifecycle | `UX00-OA-PACKAGES`: one immutable release instantiates two independent Systems; upgrade of one does not mutate the other; recall shows impact and requires System-specific governed disposition |
| Developer Workspace | None | Code Workspaces, Code Repositories, Compass, Carbon, Developer Branching, notebook/editor/terminal panels | Environment-bound code/files/terminal/ports/debugging, Session/WorkRun binding, restore/teardown, artifact and receipt handoff through daemon contracts | Candidate-only; component-extract workspace/editor grammar; native environment and governed-effect integration | `UX00-OA-DEVELOPER-WORKSPACE`: direct project Session and System-bound work both open correctly; restart restores declared state; host effects fail closed without authority and return receipts when admitted |
| Developer Console | None | Developer Console, Custom Widgets, Functions/Logic, OAuth clients, Code Templates and SDK examples | Connector, MCP, RuntimeToolContract, API/client, OAuth/service, widget/extension registration, developer-kit scaffolding and conformance; provider lifecycle stays elsewhere | Candidate-only; re-harvest incomplete mounts where necessary; component-extract registration grammar; native conformance | `UX00-OA-DEVELOPER-CONSOLE`: register and revoke one connector/tool/API surface, project least privilege through native and MCP bindings, run conformance, and prove no credential or provider-health ownership leaks into the console |

#### Substrate, conditional, and extension surfaces

| Target | Direct certified seed | Broader candidate seeds | IOI-native requirements | Disposition | Terminal proof obligation |
| --- | --- | --- | --- | --- | --- |
| Environments | None | Code Workspaces, Compute Module, Resource Management, Job Tracker, workspace/resource selectors | EnvironmentRecipe construction, readiness, services/tasks/ports, restore/teardown, custody and provider binding; no logical System or pursued-work ownership | Candidate-only; component-extract environment/runtime panels; native lifecycle contracts | `UX00-SA-ENVIRONMENTS`: create, inspect, stop, restore, and tear down an environment with honest readiness/degraded state, exact context, no fabricated persistence, and no System identity mutation |
| Operations | None; certified `Issues` may be consumed contextually but remains primarily placed in Work | Resource Management, Job Tracker, Monocle, Data Health, Object Monitoring, Control Panel, Issues | Desired/observed topology, providers, placement, capacity, custody, fencing, failover, RPO/RTO, scheduler/daemon health, infrastructure incidents and spend | Candidate-only; component-extract monitoring/admin grammar; native topology/failover semantics | `UX00-SA-OPERATIONS`: inject provider/member failure, show desired versus observed state, fence before failover, preserve logical System identity, prevent duplicate effect, expose recovery and receipt evidence |
| Embodied Systems (`planned`) | None | Map, Time Series Catalog, Quiver, Vertex, allocation patterns, Resource Management, Object Monitoring, Monocle, Issues | Unit/controller commissioning, EmbodiedResourceGroup, runtime graph/profile placement, streams/action policy, local supervisor, sim/HIL/live transfer, fleet and spacetime leases, telemetry/replay/incidents, local safety veto; no mandatory HypervisorOS | Native-first; component-extract only visualization/allocation grammar; reject remote-control and OS-dependency assumptions; remain nonlaunchable until proof passes | `UX00-OA-EMBODIED`: commission existing-controller units, form an exact resource group, simulate then admit a graph, allocate work separately from spacetime, refuse stale/unsafe command locally, record acknowledgement/incident/replay, and operate without HypervisorOS |
| Extension applications: generated, organization-authored, imported, installed, and marketplace-distributed | None end-to-end | Workshop/Module, Slate, Custom Widgets, Developer Console, Marketplace, Walkthroughs, Solution Design | One normalized registration → immutable release → admission → install → optional System binding → serving → action/authority → disable/recall/revoke lifecycle; source-neutral UI framework | Component-extract application-builder and install grammar; native-first registration and authority lifecycle | `UX00-EA-LIFECYCLE`: generate/package/admit/install/bind/serve one interface, install the same release into two Systems without data/authority/cache leakage, execute only through declared object/action contracts, then disable, recall, and revoke it cleanly |

#### Ledger closure rules

`UX-00` closes only when:

1. the target set is exactly the canonical estate for the frozen revision;
2. each of the thirteen certified ports has one primary disposition;
3. `Issues`, `Marketplace`, and `Machinery` have been rebased to their target
   placement;
4. every candidate seed carries a concrete capture/evidence ref, evidence
   grade, contract-readiness grade, and disposition rather than only a family
   name;
5. every target without a certified seed has a native design and proof fixture;
6. certification evidence is detached from catalog membership;
7. core workspaces, owner applications, substrate applications, tools, and
   extension applications are compiled as distinct classes;
8. no child tool inflates its parent’s operational maturity;
9. every adopted effect grammar terminates in proposal, authority/policy
   evaluation, daemon execution, receipt, and authoritative projection;
10. visual similarity and semantic correctness are verified separately;
11. source-specific terminology remains confined to ignored discovery and
    implementation evidence;
12. a verifier fails when canon adds, removes, renames, or reclasses a target
    without a ledger update.

## 10. Pressure-test matrix

The target taxonomy must pass all of these without inventing a new owner application for each case.

| Bounded-DAS case | Core lifecycle | Expected product path | Present gap exposed |
| --- | --- | --- | --- |
| Single-authority inheritance or funds-use institution | Constitution, oracle policy, spending authority, succession, terminal disposition; no public consensus required | New System → Studio → Ontology/Data → Governance → genesis → Systems → Provenance | No first-class System creation and lifecycle home |
| Enterprise operational institution | Private ontology/data, Enterprise Learning Boundary, replaceable models, multi-node continuity | Systems → Data/Ontology → Governance → Foundry → Operations → Provenance/Evaluations | Cross-cutting facets exist in canon but lack one coherent System projection |
| Existing robot or drone fleet | Existing controllers, admitted gateways, embodied resource groups, local safety loops, allocation and failover | New System → Studio → Governance → Systems/Embodied → Operations → Provenance | Embodied UX absent; stale HypervisorOS framing |
| ioi.ai collaborative OutcomeRoom | Room genesis, local-agent pairing, participants, frontier, claims, verifier challenges, contribution lineage | ioi.ai handoff → Systems / Work / Rooms → participant GoalRuns and Sessions → Provenance/Evaluations → Improvement | OutcomeRoom and participant work are not yet projected directly without a Mission wrapper |
| Two sovereign logistics Systems | Independent truth and authority, negotiated AIIP terms, semantic mappings, work leases, evidence and settlement | System A / Govern → AIIP terms → System B decision → GoalRuns, work claims and receipts in each System | No native cross-System negotiation and mapping UX |
| Generated React operator application | Surface descriptor, allowed actions, install, release, replicas and stable System identity | Studio / Interfaces → Packages admission → Applications → System context | Generated apps are claimed but not emitted into the live catalog or mounted as a complete path |
| Autonomous software-delivery institution | Repos, environments, workers, automations, evals, change proposals and release governance | Project → Developer Workspace → Studio/Automations → Governance → Systems → Provenance/Improvement | Strong horizontal pieces, but no institution-centered end-to-end path |
| Model-provider removal | Route replacement without loss of institutional memory, evals, policy or identity | System / Govern → Foundry route change → Evaluations → canary → Improvement/Governance → Provenance | Current Agent Studio concentrates controls that belong to several owners |
| Migration, fork, succession and dissolution | Explicit continuity decision, authority, asset/data/key disposition and terminal root | System / Govern → proposal → evidence/review → admitted lifecycle transition | Not represented in current running UX |
| Direct governed developer session | Open repo, run one governed session, inspect result, exit | Project → New Session → Developer Workspace or Work / Sessions → result | System-centered IA must not force System creation |
| System-bound health monitor | Reusable periodic rule evaluates admitted node health; routine checks finish directly and a detected breach opens bounded remediation | System / Automations → AutomationSpec → AutomationRun → optional GoalRun → Work | Trigger definitions, activations and pursued outcomes can otherwise collapse into one Mission object |
| Manual durable outcome | Operator pursues a bounded result across worker replacement, sleep, retries and several execution contexts | New Goal → GoalRun → headless and operator Sessions → Work / Goals → evidence | Session churn can otherwise become accidental goal identity |
| One package, two independent Systems | Shared release material; separate genesis, state, authority and upgrade decisions | Packages → instantiate A and B → upgrade A only | Package, installation and System identity can otherwise collapse |
| Rejected AIIP cooperation | Both Systems remain locally complete after incompatible terms | System A / Govern → proposal → System B rejects → both continue locally | Product must not imply cooperation duty or degraded base utility |
| Learning-boundary route refusal | Prohibited provider secondary use, model swap, retained private memory/evals/lineage | System / Govern → Foundry route check → refuse → eligible replacement → evaluate | Provider choice can otherwise leak institutional learning or strand capability |
| Reused generated interface | One interface package bound independently to Systems A and B | Packages → install twice → Applications / System Interfaces | Tenant, System, authority or cache leakage |
| Partitioned embodied fleet | Stale command arrives after expiry during partition | Embodied Systems → local safety refusal → acknowledgement/incident → replay | Remote orchestration can otherwise dominate certified local safety |
| Package recall | Affected Systems are identified; none is silently mutated or stopped | Packages / Recall → impact → Governance decisions per System | Package action can otherwise bypass live-System authority |
| Recovery from archive | Roots, archive refs, authority and replay are validated before restore | System / Govern → Operations restore → Provenance | Payload availability can otherwise be mistaken for valid recovery |

### 10.1 Detailed acceptance walks

#### A. Single-node bounded institution

The user can:

1. create a System from blank or template;
2. define purpose, beneficiaries, prohibitions and lifecycle rules;
3. select single-authority ordering with no public consensus;
4. bind ontology, data recipes, oracle/evidence policy, budgets and authority;
5. preview the compiled package and genesis;
6. obtain required approval;
7. activate the System;
8. see the stable identity in Systems;
9. inspect every consequential transition and receipt;
10. amend, suspend and dissolve it through explicit paths.

#### B. Multi-node enterprise System

The user can:

1. declare desired roles and failure domains;
2. admit a second member without creating a second System;
3. distinguish desired from observed topology;
4. exercise controlled failover with fencing and no authority widening;
5. allocate useful work across admitted members;
6. reconcile partition, lease-expiry and duplicate-effect cases;
7. remove a model provider while preserving institutional learning and eval continuity.

#### C. Existing embodied fleet

The user can:

1. enroll existing robots through lightweight admitted bridges;
2. form embodied resource groups;
3. retain certified local safety loops and emergency stop;
4. allocate work at System level without routing servo control through a remote model loop;
5. observe command, acknowledgement, telemetry and safety receipts;
6. operate without installing HypervisorOS on every unit;
7. optionally use HypervisorOS where stronger measurement or containment is valuable.

#### D. Open OutcomeRoom and AIIP

The user can:

1. distinguish room System identity from its current participant GoalRuns, Sessions and AutomationRuns;
2. pair a local agent without granting membership or effect authority;
3. review and admit a bounded participant lease;
4. publish and claim work-frontier items;
5. preserve negative results and verifier challenges;
6. federate with another sovereign System only after exact terms acceptance;
7. preserve separate truth, exit and dispute paths;
8. attribute contributions without implying payout or settlement.

## 11. Gap scorecard

| Criterion | Current direction | Current implementation | Winning requirement |
| --- | --- | --- | --- |
| Stable bounded-System identity | Strong in canon | No first-class product home | Systems rail and workspace |
| Lifecycle owner boundaries | Mostly strong | Legacy routes and overlaps | Stable owner descriptors |
| App versus tool distinction | Stated indirectly | Fails: certified seeds become peer apps | Typed descriptor split |
| Query-first catalog | Canonical | Missing search/filter/recent/favorite/recommended completeness | One compiled catalog projection |
| Operational honesty | Strong in port registry | Estate labels all cards open | Capability- and maturity-aware display |
| Generated applications | Strong thesis | Separate candidate manager, absent from main catalog | Admitted generated-app registry and launch path |
| Constitution and genesis UX | Strong contracts | Absent | Native System creation flow |
| Multi-node continuity | Strong contracts | Absent from product | Desired/observed topology and lifecycle actions |
| Useful same-System distribution | Strong contracts | Absent from product | Assignments, leases, reconciliation and receipts |
| OutcomeRoom | Strong product doctrine | Not generalized | Work / Rooms plus the room's own System context after genesis |
| Enterprise Learning Boundary | Strong cross-cutting canon | Absent in app code | Contextual System and owner projections |
| Embodied Systems | Strong deployment-neutral canon | Not built; stale label | Optional fleet projection and native safety UX |
| Palantir UX value | Rich evidence corpus | Too coupled to product membership | Shared primitives and owner-bound tools |

## 12. Migration plan

### Phase 0 — Freeze the comparison baseline

Deliver:

- machine-readable inventory of every shell category, family, port, route, generated-app candidate, substrate surface and horizon entry;
- route and owner conflict ledger;
- capability and operational-state matrix;
- object-owner matrix;
- screenshot and verifier links for every certified port;
- the complete `UX-00` twenty-one-row post-taxonomy seed coverage ledger,
  including one primary disposition for every certified port and explicit
  candidate-only/native-first status for every unseeded target.

Proof gate:

- every visible Applications entry resolves to exactly one descriptor candidate;
- every route has one proposed canonical owner and optional compatibility aliases;
- no serving route or served title is removed during the baseline freeze;
  target registration labels may rebase only with explicit compatibility
  metadata;
- the frozen canonical target set and ledger target set are equal;
- all thirteen certified ports are accounted for exactly once;
- certification can no longer be interpreted as product membership.

### Phase 1 — Decide and canonicalize taxonomy v2

Create an ADR and update canon only after review of this comparison.

Decisions:

- System is a first-class product object and shell category;
- Systems is the primary shell home and contextual read model, not an owner application or truth store;
- Work replaces Sessions as the broad core workspace while Sessions remains a typed view and compatibility route;
- Missions retires as a peer owner application and `Mission` remains only an optional product label/profile over one explicit GoalRun or OutcomeRoom subject;
- background, interactive and supervisory are execution modes rather than object classes;
- AutomationSpec owns reusable standing behavior, AutomationRun owns one activation, GoalRun owns durable bounded outcome pursuit, Session/WorkRun own bounded execution context, and OutcomeRoom owns shared pursuit;
- a durable OutcomeRoom may itself be the bounded System rather than a child of another System;
- core workspaces, owner applications, tools, generated apps and substrate surfaces remain distinct;
- the existing Application Surface Registration Contract gains explicit class, origin, availability and operational axes;
- Operations remains infrastructure-only;
- Packages versus canonical Marketplace naming is closed explicitly without making local package lifecycle depend on commerce;
- Embodied Systems remains a deployment-neutral planned first-party application and does not require HypervisorOS;
- generated interfaces are first-class System outputs.

Proof gate:

- source-of-truth map, current defaults, core clients and governed-system owner docs agree;
- no accepted wording implies that a GoalRun, OutcomeRoom participant, Session, node, process, UI or package is the System;
- no accepted wording forces direct or project work to materialize a System;
- System, Project, organization and room scope remain orthogonal to work kind: binding an AutomationSpec to a System cannot turn it into a GoalRun or Mission;
- a Mission-labelled profile has exactly one explicit backing subject and creates no independent authority, lifecycle, budget, status, evidence, or truth;
- domain-specific safety contracts such as `PhysicalMissionControlEnvelope` remain intact while their generic work binding migrates to `goal_run_ref` or a discriminated `work_subject_ref`.

### Phase 2 — Introduce the descriptor model in shadow mode

Implement:

- the discriminated HypervisorApplicationSurfaceRegistration family;
- core-workspace navigation definitions beside, but not inside, the application catalog;
- a join from static registrations to the existing tool runtime registry;
- daemon-admitted package, generated-interface and installation records;
- request-scoped organization, user, Project, System, GoalRun, OutcomeRoom, AutomationRun and Session projections;
- one policy-filtered compiler serving navigation, catalog and API projections;
- compatibility alias support;
- registration invariants and schema validation.

Compile and compare in shadow before changing presentation. Cut presentation
over only after route coverage and singular-container behavior pass.

Revise the current verifiers in the same cut:

- verify-hypervisor-home-surface.mjs must stop requiring every certified seed to be a peer catalog application;
- verify-hypervisor-app-runtime-safety.mjs must stop requiring certified-matrix and catalog membership equality;
- verify-hypervisor-native-shell-integration.mjs must derive canonical routes from registrations rather than hard-coded transitional families;
- verify-hypervisor-surface-modules.mjs must preserve runtime binding invariants without making parity evidence the source of product identity;
- verify-hypervisor-shell-parity.mjs must remain green; later Systems navigation is an explicit owned-shell edit with a reviewed baseline re-freeze, not a brittle string transform.

Retain the valuable assertions:

- every port-derived tool has valid parity evidence;
- native tools may exist without parity evidence;
- tool runtime, action, authority, receipt and route-isolation invariants remain;
- owner applications do not require pixel certification.

Proof gate:

- parity evidence has zero authority over product membership;
- shell and Applications estate consume the appropriate views of the same product-surface compiler;
- no duplicated hard-coded family lists remain after cutover;
- route coverage does not regress;
- partial daemon or preference failure preserves static first-party inventory without leaking cached tenant state.

Implementation checkpoint (2026-07-17; structural rebase implemented,
full `UX-00` remains open):

- the static first-party layer now compiles five core workspaces, twelve
  enduring owner applications, two substrate applications, one planned
  conditional owner application, and
  one extension-application target contract from
  `apps/hypervisor/scripts/product-surface-registry.mjs`;
- Embodied Systems remains `owner_application`; its conditional placement and
  `planned` availability do not create another application class;
- extension origin, creation method, and distribution channel remain separate,
  while dynamic daemon/package/install/System-binding inventory is explicitly
  `not_connected`;
- the thirteen certified runtime surfaces remain in
  `surface-registry.mjs` as evidence and runtime mounts, with twelve typed
  tool placements and one Work / Incidents view;
- `app-catalog.mjs`, the API, Applications estate, launcher, and Home consume
  the grouped v2 projection;
- `Missions`, peer `Marketplace`, and `Workbench` no longer appear as
  application registrations; their serving routes remain compatibility
  aliases for Work, Packages, and Developer Workspace;
- `verify-hypervisor-product-surface-catalog.mjs` proves the twenty-one-row
  census, exact thirteen-surface crosswalk, planned nonlaunchability, and
  certification-membership independence.

This checkpoint does not close `UX-00` or Phase 2. The structural census,
primary certified-port dispositions, structural per-target status overlay, and
certification-membership separation are implemented. Candidate-by-candidate
evidence refs and grades, contract-readiness assessment, proof-fixture refs,
terminal per-target verification, and a canon-to-ledger drift gate remain open,
as do daemon-admitted release, installation, System-interface and serving
bindings, request-scoped policy filtering, dynamic extension inventory,
canonical route migration, and tenant/System cache-isolation proof.

### Phase 3 — Correct Applications information architecture

Implement:

- query-first search and filtering;
- first-party, organization, installed and System-interface groups;
- recent, favorites and context-aware recommendations;
- direct tool search with owner breadcrumb;
- truthful maturity and capability labels;
- generated apps in the same catalog projection;
- removal of Ported apps as a user-visible category.

Proof gate:

- Data appears once as an owner; Pipeline Builder appears as Data / Pipeline Builder;
- no seed is promoted by certification alone;
- an admitted organization-generated app launches through the same catalog without becoming an owner application;
- the same app is not duplicated when it is organization-authored, installed and System-bound;
- every tool shows its correct parent-owner breadcrumb;
- no owner maturity is inflated by child-tool maturity;
- the singular Open Application contract remains intact.

### Phase 4 — Land bounded-System contracts and read models

Follow the canonical execution-horizon and canon-to-code sequencing before exposing permanent inventory:

~~~text
taxonomy and compiler shadow work
  -> package, genesis, constitution, ordering and lifecycle contract slice
  -> deployment and membership read model
  -> creation primitives and conformance
  -> honest Systems inventory and workspace
  -> visible blank-to-genesis journey
~~~

Implement the minimum contract slice for:

- package candidate and immutable release identity;
- one-time genesis and stable System identity;
- active constitution and profile refs;
- single-node deployment and observed membership;
- lifecycle state and exact permitted transitions;
- authority, evidence and receipt obligations;
- read models needed by Systems inventory and detail.

Bring the minimum golden-path primitives forward here:

- governed object and template picker;
- lifecycle strip;
- authority preview;
- creation wizard shell;
- honest missing-contract and blocked states.

A feature-gated diagnostic projection may precede these contracts. Do not add a permanently empty Systems destination to the production rail and imply readiness.

Proof gate:

- package, release, installation, System and node identity are distinct;
- genesis and lifecycle transitions have daemon, Agentgres and receipt paths;
- desired and observed deployment state are distinct;
- read models exist before permanent Systems navigation;
- no draft or sample row is presented as a live System.

### Phase 5 — Add Systems workspace and the blank-to-genesis golden path

First expose:

- Systems rail entry;
- honest inventory and stable System detail route;
- Overview, Design, Operate, Govern, Evidence, Improve and Interfaces modes;
- contextual deep links into existing owner applications;
- package, genesis, active revision, constitution, deployment and lifecycle refs;
- no fabricated live System rows.

Then implement one complete, narrow creation path:

~~~text
blank or template
  -> purpose and constitution
  -> ontology and data profile
  -> agent, capability and automation composition
  -> ordering, evidence, deployment and lifecycle profiles
  -> authority and learning-boundary readiness
  -> preview
  -> governed genesis
  -> activation
  -> Systems workspace
~~~

Use Studio as the composition workbench and Governance for admission. The domain admission path mints and records the identity; Systems projects that admitted identity after genesis. Systems never mints or owns canonical System truth.

Proof gate:

- no draft package is shown as a live System;
- genesis is one-time and receipted;
- every missing contract is a blocker, not an optimistic checkbox;
- a single-authority, single-node, no-public-consensus profile completes end to end.
- one System identity remains stable while the user moves through owner applications;
- System detail never claims observed state from a desired profile alone;
- member detail deep-links to Operations without turning the node into the System.

### Phase 6 — Rehome current controls and compatibility routes

| Transitional location | Target owner |
| --- | --- |
| Agent Studio system composition | Studio |
| Agent Studio model routes and mounts | Foundry |
| Agent Studio improvement proposals | Improvement |
| Agent Studio governance and rollout controls | Governance |
| ODK Data anchor | Dedicated Data home |
| Work Ledger route | Provenance canonical route |
| Feedback route used as Evaluations home | Evaluations canonical route |
| Connections route | Developer Console canonical route |
| Sessions and Missions peer homes | Work canonical home; `/sessions` resolves to Work / Sessions and `/missions` resolves to a Mission-labelled GoalRun/OutcomeRoom filter or creation profile; Systems retains a separate inventory and context route |
| Machinery under Studio | Automations / Process Graphs |
| HypervisorOS horizon label | Embodied Systems |
| Marketplace-only package path | Packages home with Marketplace as an optional discovery mode |

Keep aliases until:

- all internal links use canonical routes;
- saved links and tests have compatibility coverage;
- telemetry shows no material legacy use or an explicit cutoff is approved;
- docs and seed inventory no longer claim superseded ownership.

Every compatibility alias must preserve:

- query parameters and hashes;
- embedded mode;
- Organization, Project, System and Work context plus backing GoalRun, OutcomeRoom, AutomationRun and Session refs where applicable;
- canonical breadcrumb identity;
- back behavior;
- one Open Application identity.

Migrate canonical work relationships before retiring either alias:

- one-off objective and continuation state becomes a GoalRun;
- reusable trigger, schedule, webhook, monitor, service, workflow and approval definition becomes an AutomationSpec;
- one trigger activation becomes an AutomationRun and may link explicit GoalRuns, WorkItems, WorkRuns, Sessions, or an OutcomeRoom;
- collective objective, frontier, participants, claims, attempts, findings, challenges, budget, contribution lineage and replay remain on OutcomeRoom and its admitted child objects;
- bounded interactive, headless and supervisory execution context remains Session/WorkRun;
- Marketplace-originated work resolves to its ServiceOrder, WorkItem and GoalRun rather than a marketplace Mission kind;
- domain-specific physical work retains its safety and command envelope while replacing a generic `mission_ref` with a typed GoalRun or work-subject binding;
- presentation-only Mission metadata becomes a non-authoritative profile containing exactly one typed backing `subject_ref`.

Contract migration must remove or replace `HypervisorAutomationRun.mission_ref`, add explicit GoalRun and OutcomeRoom association refs where needed, let WorkRun bind its GoalRun directly instead of inferring only through Session, and key `HypervisorOutcomeRoomProjection` directly by `outcome_room_ref` without a required Mission wrapper. Stop new canonical `HypervisorMission` writes before migrating stored records. Ambiguous records must enter a typed review queue; they must never be silently guessed into a new kind. Each accepted remapping emits an ID-alias or migration receipt so saved links, evidence and replay remain resolvable.

Raw capture routes under /__apps should become development and review-only. Remove them from production catalog, search and owner copy before deleting the underlying evidence.

### Phase 7 — Standardize and expand shared UX primitives

Promote the primitives introduced for the golden path into shared, source-neutral components, then add the remaining cross-application grammar:

1. object/resource picker;
2. lifecycle strip;
3. authority preview;
4. typed creation wizard;
5. typed canvas;
6. desired/observed topology;
7. evidence and replay drawer;
8. proposal and diff drawer;
9. package/install flow;
10. contextual breadcrumb and launch contract.

Each primitive should have:

- source-neutral product naming;
- typed inputs and empty/degraded states;
- read/effect boundary;
- authority and receipt hooks;
- accessibility and keyboard behavior;
- visual fixtures;
- at least two owner-application consumers before it is considered shared.

Proof gate:

- no copy-paste forks for the same picker, drawer, lifecycle strip or topology view;
- no visual primitive owns runtime truth;
- port parity tests and IOI semantic tests remain separate.

### Phase 8 — Deepen core bounded-System operations

Map each increment to the canonical execution horizons instead of creating a second architecture sequence. Minimal constitution, genesis and single-node membership already belong to Phases 4 and 5. Add later lifecycle and distribution depth in this order:

1. protected amendment, recovery, migration, succession and dissolution;
2. desired-versus-observed node topology and controlled failover;
3. useful same-System work placement, leases, reconciliation and duplicate-effect prevention;
4. Enterprise Learning Boundary projections;
5. OutcomeRoom and local-agent admission;
6. EmbodiedResourceGroup and physical-safety posture;
7. conditional AIIP terms and semantic mappings;
8. optional IOI Network and L1 enrollment.

Each addition should be a core System projection, an existing owner-bound tool,
or the conditional Embodied Systems `owner_application` planned registration
before considering a new application family.

Proof gate:

- lifecycle changes remain Governance decisions and daemon/domain operations;
- Systems explains System-scoped topology while Operations performs admitted member operations;
- one useful workload is placed, executed, verified and reconciled across admitted members;
- a rejected AIIP proposal leaves both Systems locally complete;
- stale embodied commands fail closed under local safety, expiry and emergency-stop policy.

### Phase 9 — Elevate generated System interfaces

Use Workshop, Module, Slate and Custom Widgets as UX evidence for a Studio Interfaces mode.

Implement:

- interface template selection;
- object, action, visualization and role binding;
- preview against governed projections;
- authority and data-exposure review;
- surface descriptor creation;
- packaging and Packages admission;
- launch from Applications and System / Interfaces;
- explicit candidate, admitted, installed, serving, disabled, recalled and revoked states;
- version, recall, disable and migration handling.

Proof gate:

- one generated React application can be deployed in more than one UI replica while the underlying System identity, authority and evidence remain stable;
- one interface package can bind independently to Systems A and B without cross-System data, authority or cache leakage;
- no draft or publish candidate is launchable as an ordinary application;
- the generated UI cannot bypass daemon actions;
- uninstalling or replacing the UI does not delete the System.

### Phase 10 — Run the pressure-test program

Create deterministic fixtures and Playwright journeys for every case in Section 10.

For each case, record:

- objects created;
- product surface and canonical contract path used for every transition;
- authority decision;
- evidence and receipt;
- failure and degraded behavior;
- route and context continuity;
- whether a new app was required;
- any overlap or missing owner.

Taxonomy passes only if the cases fit without:

- duplicate truth;
- hidden authority;
- one app becoming a catch-all;
- System identity changing with a node, model, package or UI;
- reference-seed vocabulary leaking into user doctrine.

### Phase 11 — Retire transitional topology

After the new paths are proven:

- remove parity-derived catalog membership;
- remove duplicate hard-coded catalogs;
- retire Ported apps grouping;
- retire the Missions owner registration, peer card and canonical truth writes after every retained record has a typed backing subject;
- preserve `/missions` and any New Mission affordance only as compatibility or product-language projections over GoalRun or OutcomeRoom until their explicit cutoff;
- remove superseded Domain Apps ownership;
- retire obsolete Agent Studio, ODK-as-app, Work Ledger, Connections and route aliases;
- update or archive the stale internal suite guide;
- update screenshot, route and verifier ledgers;
- keep raw capture evidence as historical UX evidence only.

## 13. Proof gates

### 13.1 Architecture gates

- One object kind has one primary owner.
- System, Project, Package, AutomationSpec, AutomationRun, GoalRun, OutcomeRoom, Session, WorkRun, Node and Application remain distinct.
- Every application has an existence reason and durable job.
- Every tool has an owner and launch context.
- Systems and Work are projections, not new truth stores.
- Systems aggregates institution context; Work projects pursued, collective and executing work; Automations owns reusable standing behavior; Governance decides protected transitions; Operations performs admitted infrastructure and member operations.
- Background, interactive and supervisory are execution modes and never change an object's kind.
- System binding is an orthogonal scope and never converts an AutomationSpec or AutomationRun into a GoalRun.
- Mission is at most a presentation profile over exactly one typed GoalRun or OutcomeRoom subject; it has no independent canonical ID, authority, budget, lifecycle, state, evidence, or receipts.
- Generated interfaces remain projections.

### 13.2 Authority and truth gates

- Effectful controls declare authority and receipt obligations.
- Every System transition goes through daemon and Agentgres admission.
- Draft, proposed, desired, observed, admitted and verified states are visibly distinct.
- A receipt proves only its declared fact.
- Empty or unsupported state is preferred to fabrication.
- AIIP compatibility creates no duty to cooperate.
- Physical action never degrades into an ordinary tool-call presentation.
- Package recall exposes affected Systems but never silently mutates or stops them.
- Restore validates roots, archive refs, authority and replay rather than treating payload availability as recovery truth.

### 13.3 Catalog gates

- One product-surface compiler serves shell, Applications page, command palette and APIs through appropriate projections.
- Product membership is independent of pixel certification.
- Search finds owner apps, nested tools and generated apps without flattening their kinds.
- Maturity labels match actual capabilities.
- Every launchable System interface has admitted System, package, surface and authority refs; drafts and organization-wide tools may omit a System binding but cannot claim that launch class.
- Compatibility aliases cannot become second product identities.
- User and organization visibility is isolated in catalog results and caches.
- Disable, recall and revocation remove launch eligibility immediately.
- Partial daemon or preference failure preserves safe static inventory.

### 13.4 UX gates

- Users retain Organization, Project, System and typed Work-subject context across app switches.
- Back, deep links and singular Open Application work.
- Compatibility aliases preserve query, hash, embedded mode, System, Project and Work context, and the backing GoalRun, OutcomeRoom, AutomationRun or Session ref.
- `/sessions` and `/missions` resolve into one Work workspace identity rather than opening peer products.
- New Session remains one-click and keyboard-first even after Work replaces Sessions in the permanent rail.
- The full bounded-System lifecycle is discoverable without knowing IOI protocol names.
- Expert users can direct-launch tools.
- Different roles see relevant projections without a custom product fork.
- Empty, degraded, blocked, read-only and permission-denied states are deliberate.
- Key paths meet accessibility and keyboard-navigation requirements.

### 13.5 Verification gates

Required automated coverage:

- descriptor-schema and uniqueness tests;
- object-owner and route-owner invariants;
- compiled-catalog snapshot tests;
- compatibility-route tests;
- tool capability and maturity invariants;
- generated-app admission and revocation tests;
- effectful-action fail-closed tests;
- System lifecycle contract tests;
- one AutomationSpec producing distinct AutomationRuns without duplicating its definition;
- an AutomationRun completing routine or approval-only work without inventing a GoalRun or, when no managed execution occurs, a Session; and a goal-shaped activation explicitly creating or linking a GoalRun;
- GoalRun continuity across zero, one or many interactive, headless and supervisory Sessions;
- a direct bounded Session existing and completing without a GoalRun or System;
- Session and WorkRun replacement without duplicated goal acceptance, budget, authority or receipts;
- OutcomeRoom coordination of multiple participant GoalRuns without a Mission wrapper;
- type-safe Work aggregation and policy-filtering tests, including private goal and room non-disclosure;
- Mission-profile tests proving that no independent canonical ID or writable universal lifecycle is created;
- canonical-record migration, alias-receipt and ambiguous-record review tests;
- domain-specific physical mission-control fail-closed tests after migration to a typed work-subject ref;
- Playwright journeys for every pressure test;
- source-neutral copy scan;
- visual diffs for adopted interaction grammars;
- semantic tests separate from visual parity tests;
- no-orphan-route and no-unregistered-app checks;
- parent-owner breadcrumb tests for every tool;
- standalone and embedded compatibility-route tests;
- existing action-runtime, surface-module, shell-parity and operational-depth gates after invalid membership assertions are replaced;
- a contract/read-model prerequisite test before Systems may enter permanent production navigation.

## 14. Success metrics

Measure:

- time from blank or template to first valid genesis preview;
- time from genesis to locating the live System and its evidence;
- percentage of app launches that preserve System and Project context;
- number of visible peer application identities;
- number of duplicated hard-coded catalog owners;
- percentage of effectful surfaces at workflow-complete maturity;
- percentage of System lifecycle transitions with direct evidence and replay links;
- generated app install-to-launch completion rate;
- task success for novice operator, institution designer, developer, governance reviewer and fleet operator;
- number of pressure tests that require a new owner application;
- model-provider replacement success without loss of institutional context or eval continuity;
- percentage of Work rows with a valid typed canonical subject ref and deep link;
- GoalRun continuation success across Session replacement, sleep and restore;
- number of standalone Missions product identities or canonical writes remaining, with a target of zero after migration.

The target is not the smallest app count. It is the smallest stable set of owner applications that covers the bounded-institution lifecycle without semantic overlap.

## 15. Canonical decisions

### Recommended decisions

- Add Systems to the permanent shell after the bounded-System contracts and read model pass their gates.
- Make Systems a core inventory and context workspace, not an application or truth owner.
- Replace Sessions with Work as the permanent broad workspace while retaining Sessions as a typed view, quick action and compatibility route.
- Retire Missions as a peer owner application and canonical catch-all; retain Mission only as optional product language backed explicitly by GoalRun or OutcomeRoom.
- Allow a durable OutcomeRoom to be the bounded System it represents.
- Preserve twelve durable owner-application jobs; migrate the current Missions family into Work projections and typed canonical objects.
- Rename the current Workbench product surface Developer Workspace so it cannot be confused with Work.
- Make Packages the owner of mandatory local lifecycle and Marketplace an optional discovery, publishing and commerce mode. Preserve Marketplace routes only as compatibility aliases where necessary.
- Retain Embodied Systems as a conditional thirteenth `owner_application`
  registration with planned availability, not a new System type; keep it
  nonlaunchable until built.
- Make generated interfaces a first-class output of Studio and a first-class input to Applications.
- Extend the existing Application Surface Registration Contract and compile dynamic, policy-filtered product projections.
- Stop adding peer apps from parity evidence immediately.

### ADR 0016 resolutions

1. Should the permanent label be Systems or Institutions?
   - Recommendation: Systems. It is broader, already matches system identity, and does not imply a legal entity.
2. Should the permanent broad-work label be Work or Sessions?
   - Recommendation: Work. Session is an execution-context type and cannot truthfully name a workspace that also projects durable GoalRuns, AutomationRuns and OutcomeRooms. Preserve New Session and Work / Sessions as first-class affordances.
3. How should Work, Automations, GoalRuns, OutcomeRooms, and Sessions divide responsibility?
   - Recommendation: Automations owns reusable AutomationSpecs and their activations; GoalRun owns durable bounded outcome pursuit; OutcomeRoom owns shared collective pursuit; Session and WorkRun own bounded execution context; Work projects all of them without becoming truth. System, Project and organization scope is orthogonal.
4. Should Embodied Systems appear as a direct catalog entry?
   - Recommendation: yes as a planned specialist application when the deployment has embodied resources or the role is fleet-oriented; otherwise recommend it contextually.
5. Should Marketplace be renamed Packages and Marketplace?
   - Decision: Packages is the base owner with My Packages, Installed,
     Releases, Recall and Marketplace modes, because package lifecycle is
     mandatory while commerce is optional. Marketplace remains an optional mode
     and compatibility route, never package truth.
6. Should Automations appear both in the rail and Applications catalog?
   - Recommendation: one application identity may have multiple launch affordances. It must not become two descriptors.

## 16. Recommended first implementation cut

Do not begin by porting another broad reference surface.

The clean first cut is a taxonomy-v2 shadow compiler:

1. describe the thirteen current families, two substrate surfaces, current horizon entry, thirteen certified tools and generated-app candidates using the discriminated registrations, with Missions explicitly marked for fold and retirement rather than emitted into the target owner catalog;
2. assign one canonical owner and route to each;
3. attach parity and operational evidence only to tool descriptors;
4. compile a shadow catalog;
5. compare shadow and current route coverage;
6. add invariants for duplicate IDs, route disagreement, missing owners and maturity claims;
7. leave the visible UI unchanged until the projection is complete.

The next contract cut should canonicalize the Work spine and typed Mission-record migration alongside the minimal package, genesis, constitution, deployment-membership and lifecycle contract: explicit GoalRun, OutcomeRoom, AutomationRun, Session and WorkRun associations; no new `HypervisorMission` writes; deterministic remapping and alias receipts for existing records. Only then should the honest Systems and Work inventories enter permanent navigation. The first vertical product milestone is one single-node, single-authority bounded institution moving from blank template through governed genesis into Systems with receipts, plus one durable GoalRun surviving replacement of its bounded execution Session.

## 17. Final target statement

> Hypervisor should not become a drawer of Palantir-shaped applications. It should become the system-centered operating environment in which users constitute, compose, ground, govern, run, prove, evaluate, improve, distribute and retire bounded autonomous institutions. Focused owner applications provide expert workbenches over shared contracts; reusable Palantir-seeded UX primitives make those workbenches coherent; generated domain applications become each institution's tailored face; and Hypervisor Core preserves the authority, truth, evidence and lifecycle boundary beneath all of them.

Systems is the stable shell home and context for each bounded institution. Work is the unified projection of durable GoalRuns, collective OutcomeRooms, AutomationRuns, Sessions, WorkRuns, queues, reviews and incidents. Automations owns reusable standing behavior; Mission remains optional product language over an explicit GoalRun or OutcomeRoom rather than another truth object. Governance decides protected transitions. Operations performs admitted infrastructure and membership operations. The daemon and domain kernel execute, and Agentgres admits truth. Expert applications and generated interfaces project this shared reality without becoming alternative owners.

## 18. Primary local references inspected

- docs/architecture/_meta/source-of-truth-map.md
- docs/architecture/_meta/current-canon-defaults.md
- docs/architecture/_meta/execution-horizons.md
- docs/architecture/_meta/canon-to-code-delta.md
- docs/architecture/components/hypervisor/core-clients-surfaces.md
- docs/architecture/foundations/governed-autonomous-systems.md
- docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md
- docs/architecture/components/daemon-runtime/embodied-runtime.md
- docs/architecture/foundations/institutional-learning-boundary.md
- apps/hypervisor/scripts/app-catalog.mjs
- apps/hypervisor/scripts/surface-registry.mjs
- apps/hypervisor/scripts/augmentation/30-shell.js
- apps/hypervisor/scripts/serve-product-ui.mjs
- apps/hypervisor/scripts/harvest-seed-inventory.mjs
- apps/hypervisor/harvest-app-parity-matrix.json
- internal-docs/prompts/autonomous-systems-suite/suite-guide.md
- internal-docs/reverse-engineering/palantir/local-composition-application-crosswalk.md
- internal-docs/prompts/hypervisor-palantir-product-environment-graft-map.md
- internal-docs/prompts/hypervisor-palantir-application-surface-decision-ledger.md
