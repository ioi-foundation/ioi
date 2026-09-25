# ADR 0056: Organize The Hypervisor Application Estate By Four Axes And Retire Missions

Status: Accepted

Date: 2026-09-25

Refines: [ADR 0013](./0013-hypervisor-core-clients-surfaces-and-adapters.md),
[ADR 0016](./0016-hypervisor-systems-work-and-application-taxonomy.md),
[ADR 0028](./0028-reconcile-hypervisor-product-surface-contracts-and-cutover.md)

Unaffected: the one structural law (no second spine; policy only narrows);
[ADR 0030](./0030-rooms-are-a-composition-not-a-primitive-family.md) (rooms are ioi.ai compositions);
[ADR 0052](./0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)
Decision 4 and the owner rulings R-192 / S5-1 (goal pursuit is an ioi.ai product composed
over Hypervisor thread-orchestration primitives, and is no Hypervisor object);
[ADR 0054](./0054-defer-the-decentralized-candidate-engines-and-place-through-the-underlying-providers.md).

Owner ruling: accepted by the owner on 2026-09-25 ("i authorize adr"). The twelve open
questions the proposal raised are ruled below under **Rulings**.

## Context

The executable estate has three populations that disagree:

- a serve registry of 36 ported surfaces (`apps/hypervisor/scripts/surface-registry.mjs`),
  which says of itself that it is not a product catalog;
- 29 daemon catalog registrations (12 owner applications, one planned application, two
  substrate applications and 14 tool surfaces), compiled from
  `hypervisor_core_taxonomy.json`, which is the only catalog, palette and launch truth;
- canon's six core workspaces, twelve owner applications and two substrate applications.

Twenty-two registered surfaces have no catalog registration and are reachable only through
family landings and cross-links. Owner labels such as "Missions", "Marketplace", "Domain
Apps" and "Workbench" name no canon owner. Five surfaces read no daemon plane. Six pairs
duplicate one another. Meanwhile the sovereignty axis (jurisdiction packs, audit exports,
the learning boundary, storage custody, restore plans) and the standing-limits half of
bounded authority are served by the daemon and shown by no surface.

Missions is the clearest case. ADR 0016 retired Mission as canonical truth and allowed it
only as a label over one goal pursuit or one outcome room; both have since left the
Hypervisor. Its "run queue" is the automation-execution projection
(`orchestration_routes.rs`, `handle_operations`) that Operations already renders. Its
incident digest repeats the Issues inbox and Operations' "Needs attention". Its four
sibling surfaces have canon owners other than Missions: Builds and Build Schedules belong to
Automations (AutomationRun history and schedules), Issues to Operations (which owns
SupportIncidentLink), and Artifact Ecology to ioi.ai as a contributed view. The daemon
taxonomy already retires `/missions` to `/work`, and the reference product has no
equivalent application: it files Builds and Build Schedules under data integration and
Issues under support.

The one piece of Missions nobody else renders is WorkResults grouped by work subject. Its
honest home is Work, and the Work facet projection v1 cannot carry it: its subject kinds do
not include the arbitrary refs a WorkResult or a SupportIncidentLink points at.

## Decision

1. **Four axis families organize the Applications catalog**: Autonomous Systems,
   Sovereignty, Bounded Authority and External Execution. They group existing owner
   registrations. They are not truth owners, workspaces, routes or authority planes. The
   shell navigation canon defines is unchanged. A family is presentation input to the
   product-surface compiler ("presentation/serving decoration, never membership").

   | Family | Owners and tools |
   |---|---|
   | Autonomous Systems | Systems (with Artifact Ecology as a contributed view), Studio (System Designer, Workshop), Packages (Artifacts tab, Marketplace mode), Foundry (Model Catalog, specs and run plans, run a route), Evaluations, Improvement, Embodied Systems (planned) |
   | Sovereignty | Data (Sources, Recipes, Ingestion chain), Ontology (Manager, Object Explorer), Provenance (Work Ledger, Run Timeline, Lineage, Vertex, Custody & Jurisdiction) |
   | Bounded Authority | Governance (Approvals, console, Leases & Limits), Connections cockpit |
   | External Execution | Work / Sessions and New Session, Automations (Monitors, Process Graphs, Runs, Schedules), Environments (Placement), Operations (Issues), Developer Workspace (Code Workspaces, Code Repositories), Developer Console |

2. **Missions is retired.** `/__ioi/missions` answers the typed
   `ioi.hypervisor.route_retirement_refusal.v1` refusal (`hypervisor.route_retired`, no read,
   no mutation) with `/work` as its canonical replacement. Its tools are re-parented:
   Issues to Operations (`/operations/issues`), Builds and Build Schedules to Automations
   (`/automations/runs`, `/automations/schedules`), and Artifact Ecology to a System-scoped,
   ioi.ai-contributed extension registration under Systems. The WorkResult-by-subject view
   moves to Work once a Work facet projection v2 is admitted; until then Operations keeps
   listing WorkResults, ungrouped.
3. **Every surviving tool surface gets a catalog registration.** Reachability comes from the
   compiled projection, never from another surface's header.
4. **Duplicates collapse into their canon owner.** Marketplace becomes one mode of Packages
   (the `listings` port survives, `packages-marketplace` goes); Insight joins Object
   Explorer; Model Studio joins Foundry specs; Fusion joins Projects; Map joins
   Environments; Artifacts becomes a tab of Packages.
5. **Surfaces that read no plane become terminal absences.** Logic, Contour, Notepad, Quiver
   and Custom Widgets get a recorded adjudication and a typed retirement. Their seeds are
   preserved, never mass-deleted.
6. **Two read-first lanes are added over existing planes**: Provenance / Custody &
   Jurisdiction and Governance / Leases & Limits. Neither mints a plane, an owner
   application or an authority. The learning boundary stays a cross-cutting profile.
7. **No new daemon plane is introduced.** The contract and daemon changes this requires are
   named: a Work facet projection v2; identity and compare-and-swap on the state-machine
   plane before Process Graphs is declared effectful; taxonomy registrations (a data change,
   not a contract change) for the surviving tools.

## Rulings

The proposal left twelve questions for the owner. With the ADR accepted, each is ruled on
the proposal's recommendation unless noted.

1. **Family grouping is presentation.** It is static input to the product-surface compiler.
   A daemon-registered `catalog_family` axis (a registration v3) waits for the first
   extension or organization application that must classify itself.
2. **The shell navigation does not change** in this program. Whether Systems gets a
   permanent nav entry is a separate decision.
3. **Operations owns Issues.** Work / Incidents becomes a facet view pointing at it (v2).
4. **The subject grouping is lost in the interim.** Operations keeps listing WorkResults; no
   interim `/work/results` view is minted.
5. **Artifact Ecology stays in the Hypervisor** as a System-scoped contributed view.
6. **No-plane landings are terminal absences** answered by a typed retirement, with the seed
   preserved.
7. **Legacy `/__ioi/missions/*` tool routes keep serving** beside their canonical routes
   until each tool's cutover, as the seed-preservation rule requires.
8. **No authority node is stood up for the owner's deployment by this program.** Leases &
   Limits shows standing envelopes as a named absence until the owner configures one.
9. **Rebinding onto the governed planes** (`evaluation-*`, `improvement-campaigns` and
   agendas, the `automation-specs` / installations / runs triple) is a separate program.
10. **Canon tool renames are deferred.** Titles checked by pixel certifications do not move.
11. **Run a route (Inference) belongs to Foundry.**
12. **Custody & Jurisdiction is read-first.** Jurisdiction-pack admission stays with its
    ecosystem-assurance owner; no admission verb lands on a Hypervisor surface.

## Amendment 1 (2026-09-25, owner): the best-in-class substrate decides, not today's daemon

The owner, the same day: "whether the daemon plane needs to play catch up relative to the best
in class autonomous systems substrate, the best autonomous system substrate has a higher weight
and therefore should be the deciding metric."

1. **What a best-in-class autonomous-systems substrate offers decides whether a lane belongs in
   the topology.** Whether a daemon plane backs the lane today is a cost and sequencing input,
   never a veto. A lane the benchmark carries and the daemon lacks is a daemon backlog item.
2. **Decision 5 and Ruling 6 are re-adjudicated under this test.** Logic, Contour, Notepad,
   Quiver and Custom Widgets, and every reference lane with no counterpart, are judged by whether
   a best-in-class autonomous-systems substrate carries them. They are not judged by whether a
   plane exists. The ones that fail it become terminal absences as Decision 5 says. The ones
   that pass it stay, and the daemon catches up.
3. **Decision 7 is narrowed.** New daemon planes are allowed where the benchmark requires them.
   Each is admitted contract-first: a registered contract and the daemon route before any
   surface claims it. Each evolves the existing spine, never a second one, and policy still only
   narrows.
4. **The no-dead-control rule is unchanged.** A lane that runs ahead of its plane renders its
   unbuilt verbs as named, disabled gaps with a reason that survives reading, and says what the
   plane will be. It never renders a live-looking control that does nothing, and the client never
   mints the missing truth.
5. **Plane-backed lanes with no surface join step M8**:
   - Studio / Templates, over `workflow-templates`, `vertical-ontology-packs` and `skill-manifests`, as the start of System genesis.
   - Improvement / Change Plans, over `release-change-plans` and release controls.
   - Compute Modules, over `domain-app-runtimes` and `managed-worker-*`.
   - Checkpoints folds into Leases & Limits.
   - Workflow Lineage folds into Lineage.

   The remaining lanes and their plane backlog come from the benchmark re-adjudication.

## Execution order

Add before moving, and move dependants before removing, so no gate ever looks for a
consumer that has gone. Each step is a cut that leaves the estate green and re-measures its
pins from the gate's own count.

- **M1** Re-parent registry owners and correct capability declarations (no route or DOM
  change).
- **M2** Canonical tool routes and catalog registrations for the surviving tools (additive).
- **M3** Work facet projection v2; Work / Incidents becomes real. It runs beside M4 and M5.
- **M4** Move dependants off the Missions root: the native-shell hop, the propagation
  consumer, the compiler's "open today" pointer, the route shell's `/work` serving list.
- **M5** Retire the Missions root: registry row, taxonomy registration, protected-seed
  record (with successor and no-fallback proof), its parity verifier.
- **M6** Collapse duplicates, one cut each.
- **M7** No-plane landings become terminal absences.
- **M8** The two read-first lanes, each with all of a new surface's populations in one cut.
- **M9** Catalog family grouping in the launcher.

## Consequences

- The catalog reads as four jobs a buyer recognizes, and each owner application keeps
  exactly one truth boundary.
- Missions' protected-seed record, native-shell hop, propagation consumer and canon
  references move in the same cuts, in the order add, then move, then remove.
- Operations becomes the visible owner of incident intake, and Work / Incidents becomes a
  real facet view instead of a typed absence.
- The sovereignty axis becomes visible without a new application, in line with the canon
  guard that the learning boundary is not an application.
- A surface change moves roughly fifteen pinned populations; four need a live serve.

## Rejected alternatives

- **Keep Missions as a Work alias.** ADR 0022 Decision 2 and ADR 0028 Decision 5 forbid
  aliases.
- **Rename Missions to "Runs" or "Operations center".** It would still duplicate Automations
  and Operations and still own no object.
- **Make the four families truth owners or new workspaces.** That would be a second spine
  and a catalog outside the compiler.
- **Make Work own filed issues.** SupportIncidentLink is Operations-owned, and Work is a
  read model.
- **Re-home Missions' pieces under a new goal-shaped work object.** Forbidden by R-192,
  S5-1 and ADR 0052 Decision 4.

## Cost of being wrong and reversal

Re-parenting and catalog grouping reverse by editing data. The retired Missions root can be
restored from history, but not as an alias: a restoration needs a new decision naming a
unique invariant Missions owns. Preserved seeds and terminal adjudications keep the removed
landings recoverable. Contract successors keep their predecessors valid for records already
written.
