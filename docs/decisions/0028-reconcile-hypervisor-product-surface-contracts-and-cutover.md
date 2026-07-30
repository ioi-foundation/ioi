# ADR 0028: Reconcile Hypervisor Product-Surface Contracts And Cutover

- Status: Accepted
- Date: 2026-07-30
- Owners: Hypervisor product surfaces / identity and access / daemon runtime /
  Agentgres / schema and conformance
- Refines: ADR 0013, ADR 0016, ADR 0021, ADR 0022, ADR 0024
- Unaffected: IOI's Internet of Intelligence and Web4 category; Hypervisor
  topology; primitive ownership; GoalRun placement
- Confidence: settled for ownership, routes, state, query, and cutover
  semantics; individual surface capability admission remains evidence-gated.

## Context

The canonical surface estate already describes a normalized product-surface
compiler and most operational journeys, while the executable client still
contains parallel catalogs, legacy paths, and a reference-bundle serving
boundary. Settings also has substantive pane prose without an owned route or
cutover disposition. Program records cannot legitimately settle those durable
product decisions, and code cannot prove them by matching a reference source.

This decision closes the missing owner choices so architecture, implementation
records, executable code, schemas, and proof can converge on one contract.

## Decision

1. **Settings is a core workspace.** `HypervisorCoreWorkspaceRegistration`
   admits `settings` at `/settings`; authentication entry is `/sign-in` and is
   not an application. Settings projects scoped preferences and administration
   from their canonical owners. Existing pane families are reauthored rather
   than preserved as independent truth owners:
   - identity, account, membership, login, SSO, SCIM, secrets, and tokens remain
     identity-and-access truth;
   - connector registrations and connected applications remain Developer
     Console truth, with only scoped defaults projected into Settings;
   - environment and provider defaults remain Environments/Operations truth;
   - governance, retention, audit, export, billing, usage, memory, skill,
     delivery, and learning-boundary panes remain projections of their named
     domain owners.

2. **The daemon compiles one product-surface projection.** The six normalized
   record families named in Hypervisor canon are admitted schema contracts.
   The daemon joins them under authenticated principal, organization
   membership, typed context, policy, and preferences. Navigation,
   Applications, search, command palette, contextual launch, and Open
   Application consume that projection; clients do not keep a second catalog
   or infer launchability.

3. **Capability depth is release-owned.** A registration declares only its
   definition-level object/action ceiling. The immutable selected
   `HypervisorSurfaceReleaseRecord` owns the exact executable
   `surface_capability_depth`. Product copy and evidence may claim no greater
   depth than that admitted release proves.

4. **Context routing is not aliasing.** `HypervisorContextRouteResolver`
   resolves a canonical route from a typed context and selected compatible
   binding. It does not accept retired path spellings. The former
   `HypervisorRouteAliasRegistration` name is retired from active contracts.

5. **Legacy routes fail closed.** `/__ioi/*`, `/sessions`, `/missions`, and any
   other retired v1 path do not redirect, proxy, or dispatch. They return HTTP
   `410` with `Cache-Control: no-store` and a typed, source-neutral
   `ioi.hypervisor.route_retirement_refusal.v1` body containing
   `code: hypervisor.route_retired`, the requested route, and an optional
   canonical replacement used only as guidance. Refusal performs no read,
   mutation, or final invocation.

6. **Durable preferences are owner-backed records.** A
   `HypervisorPreferenceRecord` is scoped to an authenticated principal and
   organization, uses optimistic revision checks, and is persisted by the
   daemon through Agentgres. Theme, density, favorites, recent items, default
   organization/project, and comparable preferences use this record. Open
   menus, transient selection, draft text, scroll, focus, and unsubmitted
   layout changes are local UI state and are not durable truth.

7. **Organization identity and selection are distinct.** `org://` identifies
   the identity-and-access tenant. Membership authorizes visibility. The
   selected organization is request context and may be a preference; it does
   not create a System or a new organization truth owner. Multiple memberships
   are supported and every projection is policy-filtered before counts or
   caching.

8. **Collections are bounded server queries.** `HypervisorCollectionQuery`
   supports owner-admitted search, filter, sort, facet, and opaque cursor
   fields. The default page size is 25, maximum is 50, and the maximum
   serialized page is 1 MiB. Cursors are stable for the bound query/revision
   and cannot cross principal, organization, policy, or typed context.

9. **Surface render states use one semantic family.** Operational journeys
   render `loading`, `empty`, `missing_prerequisite`, `degraded`, `blocked`,
   `approval_pending`, `denied`, `failed`, `recovery`, and `completed` without
   treating them as synonyms. `surface_operational_state` continues to describe
   serving readiness; it is not this presentation-state family.

10. **Notifications and temporal displays remain projections.** Durable
    notification subscriptions are principal/organization-scoped daemon and
    identity records over owner events. Notification views do not own event
    truth. Timers and elapsed-time views project the temporal truth of the
    owning WorkRun, AutomationRun, Session, lease, approval, or operation; no
    shared timer service is introduced.

11. **Canvas layout does not seize graph truth.** A
    `HypervisorCanvasLayout` may persist viewport, placement, grouping, and
    presentation annotations for an owner object and revision. Ontology,
    workflow, system, dependency, work, and embodied graphs remain with their
    existing owners. Layout changes cannot mutate graph semantics.

12. **The source-owned client is authoritative executable UI.** One
    IOI-owned React application implements the shell, breadcrumb, back stack,
    Open Application frame, routes, and operational journeys. Imported bundles,
    adapters, screenshots, and comparative fixtures are replaceable evidence,
    not product authority, runtime truth, or a shipping dependency. They are
    retired after source-owned parity and negative cutover proof.

13. **Program-only controls stay program-owned.** `UX-00`, surface-to-journey
    bindings, cohort selection, usability thresholds, work-item status, gates,
    and dated canon-gap projections belong to the implementation/evidence
    program. They may be derived from canon but do not become architecture
    objects or a second sequencer.

## Consequences

- Settings, the normalized compiler, preferences, bounded queries, render
  states, route refusals, and canvas layout require admitted schemas,
  conformance, executable producers/consumers, and positive and adversarial
  evidence before claims advance.
- Existing M3 and M6–M11 obligations are amended where they already own the
  behavior; reconciliation must not duplicate those obligations under new
  names.
- ADRs 0021 and 0024 are implementation-bearing because their proof selection
  and two-mode composition constrain current surface journeys and evidence.
  Forward canon-impact edges and reverse work-item declarations must agree.
- Source-neutral names are used for durable objects, gates, records, and
  commits. External products may occur only in provenance, comparative
  evidence, compatibility matrices, or replaceable-source dispositions.

## Rejected Alternatives

- **Keep Settings as unregistered panes.** Rejected because route, ownership,
  and cutover behavior would remain ambiguous.
- **Preserve v1 redirects.** Rejected because they retain a competing route
  contract and obscure negative proof.
- **Let the client join catalogs.** Rejected because policy, principal, context,
  and launch eligibility would drift across consumers.
- **Create shared notification, timer, or graph truth planes.** Rejected because
  these are projections of existing owner records.
- **Treat this as a category or topology change.** Rejected: it completes the
  existing Hypervisor product surface without moving GoalRun, primitives, or
  IOI's category.

## Cost Of Being Wrong And Reversal

The source application and schemas are reversible behind the existing daemon
boundary. Reversal must restore neither retired routes nor client-side
authority inference. A changed Settings placement, page bound, or preference
contract requires a new accepted decision and migration evidence; durable
records must not be silently rewritten.

## Canonical References

- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/daemon-runtime/api.md`](../architecture/components/daemon-runtime/api.md)
- [`../architecture/components/hypervisor/identity-access-and-metering.md`](../architecture/components/hypervisor/identity-access-and-metering.md)
- [`../architecture/components/connectors-tools/doctrine.md`](../architecture/components/connectors-tools/doctrine.md)
- [`../architecture/components/agentgres/api-object-model.md`](../architecture/components/agentgres/api-object-model.md)
- [`../architecture/foundations/canonical-enums.md`](../architecture/foundations/canonical-enums.md)
