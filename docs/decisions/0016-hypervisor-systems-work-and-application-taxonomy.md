# ADR 0016: Make Systems And Work The Hypervisor Product Spine

- Status: Accepted
- Date: 2026-07-15
- Owners: Hypervisor / bounded-DAS domains / daemon runtime / wallet.network / Agentgres

## Context

Hypervisor already has the right substrate boundaries: clients project shared
Core contracts, the Hypervisor Daemon executes, wallet.network authorizes, and
Agentgres admits operational truth. Its product taxonomy nevertheless mixed
several unlike concepts:

- a live bounded System had no permanent inventory or contextual workspace;
- Sessions named a workspace that also needed to show durable goals, automation
  activations, collective rooms, queues, reviews, and incidents;
- Missions duplicated `GoalRun`,
  `AutomationSpec`/`AutomationInstallationBinding`/`AutomationRun`,
  `OutcomeRoom`, `Session`, and `WorkRun` semantics without a unique invariant;
- Workbench could be confused with the broader work inventory;
- Marketplace combined mandatory local package lifecycle with optional
  discovery and commerce;
- static cards, tools, generated interfaces, substrate surfaces, origin, and
  implementation maturity were not independently classified.

The result was a catalog that described useful capabilities but did not make
the bounded System the primary product object or preserve clear truth owners.

## Decision

The stable product spine is:

```text
+ New
  System | Session | Goal | Project | Automation

Home
Systems
Projects
Automations
Applications
Work

Open Application
  one optional active application slot
```

`New Session` remains a one-click and keyboard-first action. `Systems`, `Work`,
`Home`, `Projects`, and `Applications` are core workspaces, not application
registrations or new truth stores. Automations is both an owner application and
a shell-blessed launch destination under one stable identity.

### Systems

`Systems` is the inventory and contextual workspace for admitted live bounded
Systems. A System workspace composes policy-filtered projections through:

```text
Overview | Design | Operate | Govern | Evidence | Improve | Interfaces
```

It exposes stable `system_id`, constitution, genesis, desired and observed
deployment, member topology, authority, active work, evidence, improvement, and
interfaces. It neither mints System identity nor owns constitution, runtime,
authority, deployment, or receipt truth.

### Work

`Work` is the unified workspace for pursued, collective, and executing work:

```text
Active | Goals | Sessions | Rooms | Queues | Reviews | Incidents | History
```

Every row has a typed `subject_kind` and canonical `subject_ref`. Work composes
policy-filtered projections; it does not impose one lifecycle or copy authority,
budget, evidence, or status into a wrapper.

The object boundaries are:

```text
AutomationSpec  reusable standing behavior
AutomationInstallationBinding
                immutable successor-versioned scope enablement and narrowing
AutomationRun   one activation of an AutomationSpec
GoalRun         durable bounded outcome pursuit
OutcomeRoom     persistent collective pursuit and shared frontier
Session         bounded interactive, headless, or supervisory execution context
WorkRun         one admitted execution of a WorkItem, optionally bound directly
                to a GoalRun
```

Reusable composition remains outside those live work identities. A
`GoalRunProfile` declares how one class of adaptive goals should converge; a
`WorkflowTemplate` declares immutable directed-work shape; an `AutomationSpec`
binds an exact template revision to standing activation behavior; an immutable
successor-versioned `AutomationInstallationBinding` binds one exact spec into
an owner/System scope with only narrowing overlays; and an `AutomationRun`
freezes the exact template, spec, and installation-binding revisions/hashes for
one activation. A `SkillManifest` supplies procedure and support material; a
`HarnessProfile` resolves one scoped assigned step. Packages distribute these
typed components without taking over their owners, and “Recipe” remains
product language rather than a generic runtime or envelope.

Background execution is a mode of Session, WorkRun, RuntimeAssignment, or
participant operation. It is not a Mission object kind.

Generic `HypervisorMission` is retired as canonical truth. `Mission` may remain
an optional label or creation profile backed by exactly one `GoalRun` or
`OutcomeRoom`; it has no independent identity, authority, budget, lifecycle,
status, evidence, or receipts. If a future sponsor engagement needs its own
multi-goal acceptance, SLA, termination, budget, and authority lifecycle, it
must introduce a narrow `OutcomeContract` or `ServiceOrder`, not revive a
polymorphic Mission wrapper.

Domain-specific terms such as `PhysicalMissionControlEnvelope` and
`FleetMissionCoordinationRecord` remain valid. They describe physical safety or
fleet coordination, not the retired generic Hypervisor object; their general
work binding uses `goal_run_ref` or a discriminated `work_subject_ref`.

### Applications And Tools

Each durable product surface is independently classified by:

```text
surface_class
  owner_application | substrate_application | tool_surface |
  extension_application

surface_origin
  first_party | organization | external_publisher

surface_creation_method
  hand_authored | studio_generated | developer_kit_generated | imported |
  adapted

surface_distribution
  bundled | direct_package | organization_catalog | private_registry |
  marketplace

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

A `tool_surface` has exactly one primary owner application and may be consumed
contextually by many others. Reusable code-level UX primitives are not product
registrations or truth owners. `Work / Reviews` and `Work / Incidents` are
policy-filtered facet views over typed source objects, not generic Work-owned
tools or new canonical subjects.

The accountable publisher is a separate `publisher_ref`:
`org://...` or `user://...` for an accountable publisher inside the deployment
boundary, or
`ioi://publisher/...` for an admitted external publisher. Null is reserved for
bundled first-party surfaces whose accountability is fixed by the release.
Core workspaces use a
sibling workspace registration and are not coerced into an application class.
All listed axes remain independent. Product
membership compiles from static first-party registrations plus daemon-admitted
release, installation, System-interface, and serving records; organization and
user policy/preferences; and current Organization, Project, System, GoalRun,
OutcomeRoom, AutomationRun, Session, WorkQueue, WorkItem, and WorkRun context.
UX lineage or a Palantir-derived interaction pattern is evidence, never product
membership.

The axes resolve across a normalized record family rather than one mutable
catch-all row: `HypervisorApplicationSurfaceRegistration` owns stable
definition identity; `HypervisorSurfaceReleaseRecord` owns release admission,
distribution, disposition, capability, the versioned surface descriptor, and
the exact executable object/action/operator contracts beneath the definition's
declared ceilings; `HypervisorSurfaceInstallationBinding`
owns installation state, deployment enablement, and the organization/Project
visibility, audience, allowed-object/action, and authority-preview boundary;
`HypervisorSystemInterfaceBinding` owns one admitted System binding and may
only narrow those launch boundaries; and
`HypervisorSurfaceServingBinding` owns serving health.
`HypervisorProductSurfaceProjection` joins those records for one request and
never turns the join into another truth owner.

The twelve enduring baseline first-party owner-application jobs are:

```text
Studio | Automations | Ontology | Data | Governance | Provenance |
Evaluations | Improvement | Foundry | Packages | Developer Workspace |
Developer Console
```

`Environments` and `Operations` remain substrate applications. `Embodied
Systems` is a conditional thirteenth `owner_application` registration with
`surface_availability: planned`: it may be shown or recommended for embodied
contexts, but it is nonlaunchable until its route and implementation exist. It
may project existing robots, controllers, gateways, resource groups, and
certified local safety loops; it does not create another System kind or require
HypervisorOS.

`Packages` owns mandatory local package admission, installed inventory,
releases, dependencies, recall, and impact. `Marketplace` is an optional mode
for discovery, publishing, and exchange. Marketplace availability never owns
package or installation truth.

For packaged surfaces, package identity, immutable release identity,
installation-binding identity, System-binding identity, and System identity
remain distinct (`package://...`, `package://.../release/...`, `install://...`,
`package_binding://...`, and `system://...`). One release may be installed and
bound independently to multiple Systems without merging their authority or
state.

`Developer Workspace` is the product label for code, files, terminals,
browsers, ports, debugging, and environment-bound hands-on work. `Workbench`
is a compatibility name and route only.

Generated and installed applications are first-class catalog entries only after
admission. Candidate, admitted, installed, serving, disabled, recalled, and
revoked states must remain distinguishable; a draft descriptor is not
launchable software.

## Migration And Compatibility

- Every compatibility route is a typed
  `HypervisorRouteAliasRegistration` owned by exactly one workspace or
  application registration. Static aliases name one target route; Mission and
  other contextual aliases name a fail-closed typed resolver. Alias collisions,
  orphan targets, and context-dropping redirects are invalid.
- `/sessions` resolves to `Work / Sessions`.
- `/missions` resolves to a Work-backed GoalRun/OutcomeRoom profile or filter.
- `/workbench` resolves to Developer Workspace.
- existing Marketplace links resolve to `Packages / Marketplace`.
- aliases preserve query, hash, embed mode, return path, Open Application
  identity, and typed Project/System/work-subject context.
- stop new canonical `HypervisorMission` writes before stored-record migration;
  deterministically remap unambiguous records, route ambiguous records to typed
  review, and emit alias/migration receipts.
- remove `HypervisorAutomationRun.mission_ref`; add explicit GoalRun,
  OutcomeRoom, WorkItem, WorkRun, and Session associations where applicable.
- require every new AutomationRun to freeze the exact WorkflowTemplate,
  AutomationSpec, and AutomationInstallationBinding revision/hash tuple;
  legacy activations missing a provable binding enter typed review rather than
  inferring one from a current scope head.
- let `HypervisorWorkRun` bind `goal_run_ref` directly.
- key `HypervisorOutcomeRoomProjection` directly by `outcome_room_ref`.

The target taxonomy may enter documentation before all product surfaces ship.
Permanent Systems navigation waits for bounded-System contracts and an honest
read model; current-code Missions, Sessions, Workbench, and Marketplace labels
remain implementation evidence and compatibility aliases until migrated.

## Consequences

- The bounded System becomes the stable organizing context without becoming a
  universal parent required for direct sessions, projects, goals, or automations.
- Work can show a coherent estate without inventing another authority or truth
  plane.
- Automations, goals, rooms, and execution contexts retain distinct invariants.
- Package lifecycle works in private and disconnected deployments.
- Generated interfaces use the same catalog, authority, evidence, and lifecycle
  rules as first-party surfaces.
- Operations retains infrastructure/member operations; Systems explains
  System-scoped topology; Governance authorizes protected changes.
- Palantir-derived UX can be grafted as reusable interaction grammar without
  importing a competing product ontology.

## Supersedes / Refines

This ADR refines ADR 0013's application-surface taxonomy and ADR 0014's
session-estate framing. It supersedes ADR 0014's `Workbench` product label and
the reading that Sessions alone name the complete work estate. It does not
change ADR 0014's IDE-of-IDEs, adapter-target, daemon, wallet.network, or
Agentgres boundaries.

## Canonical References

- `docs/architecture/components/hypervisor/core-clients-surfaces.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/foundations/canonical-enums.md`
- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/architecture/_meta/current-canon-defaults.md`
- `docs/architecture/_meta/vocabulary.md`
- `docs/architecture/_meta/implementation-matrix.md`
- `docs/architecture/_meta/execution-horizons.md`
