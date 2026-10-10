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
   preserved, never mass-deleted. *(Re-adjudicated by Amendment 1: Logic, Custom Widgets and
   Quiver's time-series core are kept.)*
6. **Two read-first lanes are added over existing planes**: Provenance / Custody &
   Jurisdiction and Governance / Leases & Limits. Neither mints a plane, an owner
   application or an authority. The learning boundary stays a cross-cutting profile.
7. **No new daemon plane is introduced.** The contract and daemon changes this requires are
   named: a Work facet projection v2; identity and compare-and-swap on the state-machine
   plane before Process Graphs is declared effectful; taxonomy registrations (a data change,
   not a contract change) for the surviving tools. *(Narrowed by Amendment 1: new planes are
   admitted contract-first where the benchmark requires them.)*

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
   preserved. *(Re-adjudicated by Amendment 1: the benchmark, not plane coverage, decides.)*
7. **Legacy `/__ioi/missions/*` tool routes keep serving** beside their canonical routes
   until each tool's cutover, as the seed-preservation rule requires.
8. **No authority node is stood up for the owner's deployment by this program.** Leases &
   Limits shows standing envelopes as a named absence until the owner configures one.
9. *(Reversed by Amendment 1, answer 5.)* **Rebinding onto the governed planes** (`evaluation-*`, `improvement-campaigns` and
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

### Amendment 1 — re-adjudication (2026-09-25, owner-accepted)

Every lane was re-judged under §1 (a read-only research pass, with the reference tenant read
over CDP and public product documentation cited). A lane belongs when a best-in-class
autonomous-systems substrate carries it and canon places it under an owner; a reference lane
is evidence, never membership. The benchmark covered durable agent execution (Temporal,
LangGraph), evaluation and observability (LangSmith, Braintrust, Arize), ontology, lineage and
data governance (Palantir Foundry/AIP, Databricks Unity Catalog), policy and bounded authority
(OPA, Cedar, IAM Access Analyzer, Teleport, AWS Budgets), sandboxed and served execution (E2B,
Modal, Kubernetes operators) and fleet operations with telemetry (Formant, Foxglove). Of 84
lanes, 61 stay on existing planes (12 merging into a surviving surface), 13 stay with named
gaps while their plane is built, and 10 are terminal absences. The owner accepted the result
and every recommendation it made ("yes to all").

1. **Decision 5, re-adjudicated.**
   - Logic becomes **Ontology / Functions** (canon Ontology owns functions).
   - Custom Widgets becomes **Developer Console / Extensions**.
   - Quiver splits. Its time-series core becomes **Operations / Telemetry**, seeded from the
     preserved Quiver port (a rebinding of the seed, not a recreation). Its BI dashboard
     builder is a terminal absence.
   - Contour and Notepad stay terminal absences: dataset BI and document authoring, which no
     autonomous-systems substrate carries.
2. **Reference lanes with no counterpart.**
   - Kept on existing planes: Value Types → an Ontology Manager tab; Resource Management →
     Leases & Limits and an Operations resource facet; Workflow Lineage → Lineage; Compute
     Modules → **Automations / Services**; Examples and Walkthroughs → Studio / Templates.
   - Kept with named gaps: Time Series Catalog → Data / Time series; Data Health →
     Operations / Health (authored as monitors); Linter → Operations / Recommendations;
     Notifications → a core inbox projection and a Settings pane; Checkpoints → Leases &
     Limits; Global Branching → Improvement / Change sets; Sensitive Data Scanner → Data /
     Sensitive data; Cipher → protect and reveal on Data / Restricted views; Document
     Intelligence → Data / Ingestion chain.
   - Terminal absences: SQL Studio, AIP Analyst, Carbon workspaces, Foundry Rules, Slate,
     AI FDE, Training — each covered by another lane or outside the substrate.
3. **Corrections to §5.** Checkpoints is not plane-backed: the daemon holds no justification
   record, so its lane shows a named gap until the justification-checkpoint plane lands.
   Change Plans over `release-change-plans` is the packaged Hypervisor's own update and
   rollback; System change sets (Global Branching) are a separate plane.
4. **Plane backlog**, each admitted contract-first (registered schema, generated contract,
   daemon route, then a surface), each extending the named plane, none minting authority
   (where one touches authority it only adds obligations). Ordered by benchmark weight × lanes
   unblocked ÷ build cost:

   | # | Contract | Extends | Unblocks |
   |---|---|---|---|
   | 1 | notification subscription + inbox | projection subscription leases, event streams | Notifications; alert routing |
   | 2 | health check + result | monitor-mode automation specs, support incidents | Operations / Health; Work / Incidents facets |
   | 3 | tool/function revision + test run | the runtime tool-contract registry, ontology action contracts | Ontology / Functions; agent and automation tools |
   | 4 | change set (reusing the branch-merge plan) | improvement proposals, cohorts and release controls | Improvement / Change sets; Studio preview |
   | 5 | justification checkpoint + record | authority evaluate, approval requests | Leases & Limits / Checkpoints |
   | 6 | telemetry stream (+ range, derived series) | event streams (ephemeral and admitted classes) | Data / Time series; Operations / Telemetry; Embodied observe |
   | 7 | posture finding (+ rules) | enforcement coverage, idle sweep, lease usage | Operations / Recommendations; unused-access findings |
   | 8 | sensitive-data scan + finding | data sources, media censuses, policy-bound views | Data / Sensitive data |
   | 9 | reversible field protection | redaction recipe, policy-bound views, declassification | Restricted views protect and reveal |
   | 10 | document-extraction transformation kind | transformation runs, media snapshots | Ingestion chain |
   | 11 | widget-set descriptor kind | surface descriptors, packages | Developer Console / Extensions |
   | 12 | embodied fleet (canon objects) | machines, physical-action intents, episodes | Embodied Systems |

   The Work facet projection v2 and state-machine identity with compare-and-swap stay in the
   backlog from Decision 7.
5. **The owner's answers to the re-adjudication's questions.**
   1. The justification-checkpoint plane is admitted (5 above).
   2. Automations owns Compute Modules, as Services.
   3. Ontology owns Functions; Automations' tool builder consumes them.
   4. Notifications is a core inbox projection plus a Settings pane, in no family.
   5. **Ruling 9 is reversed.** Rebinding Evaluations onto the governed `evaluation-*` plane,
      Automations onto the `automation-specs` / installations / runs triple, and Improvement
      onto campaigns and agendas is sequenced beside planes 1–5, not deferred.
   6. The telemetry plane starts now; it serves software agents' metric trends as well as
      embodied systems.
   7. Sensitive-data scanning admits the finding and marking-proposal contract with both
      in-house scan specs and external scanners able to post findings; a marking may only
      narrow.
   8. Reversible protection keeps key custody with wallet.network / cTEE, and a reveal is a
      single-use declassification approval.
   9. The preserved Quiver port seeds the Telemetry lane.
   10. Ruling 8 stands: standing envelopes stay a named absence until the owner configures an
       authority node.

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
- **M7b** The re-adjudication's terminal absences are recorded with their adjudications, seeds
  preserved.
- **M8b** Each named-gap lane lands with all of its populations in one cut; its unbuilt verbs
  are disabled and name the plane that will serve them, and no lane claims a verb before that
  plane's route exists.
- **P1–P12** The plane backlog, contract-first, in the order above, with the governed-plane
  rebinding (answer 5) beside planes 1–5.
- **M9** Catalog family grouping in the launcher.

## Amendment 2 (2026-09-25, owner-delegated): M6 execution rulings

The owner delegated these decisions ("I authorize you to make the decision(s)"). They apply
M6's rule literally: a duplicate retires only once its survivor carries every lane it
showed, or once the lane has been ported into the survivor from the duplicate's own code.

1. **A merged route names its successor on the page, never in the refusal.** The registered
   refusal admits only Work routes or null as `canonical_replacement_route`. So a merged
   duplicate retires with a null replacement, and the page a browser gets names and links
   the survivor. There is no redirect alias. When a duplicate's lanes land in more than one
   survivor, the page names each one.
2. **M6a needed no port.** Insight's lanes are Object Explorer's. Model Studio's one verb is
   the Foundry spec builder's (`/__ioi/foundry/specs/new`; the bare `/specs` path has no
   page). The Map port's live lane is the Placement section of Environments.
3. **Fusion retires in M8, not M6.** Three of its lanes survive elsewhere: its project list in
   Projects, its materialized sets in Object Explorer, and its declared sources in Data
   Connection. Two columns of its project table survive nowhere: each project's custody
   posture and its artifact-reference count. Porting them into the vendored Projects app
   would re-author a vendored surface. Their owner is the planned Provenance / Custody &
   Jurisdiction lane, which adopts Fusion's project-row code as its per-project table. Fusion
   retires in that cut, naming all three survivors. The difference in the source list's cap
   (Data Connection shows the newest 12, Fusion showed 20 of the same catalog) is not a lane:
   both name their cap, and neither lists the whole catalog.
4. **Artifacts needs a port before it retires.** Packages lacks most of the Artifacts page: its
   ten-plane read-state census (release controls and the SCM publication ladder among them),
   its cross-plane record table, and its taxonomy, substrate and route-count lanes. The inline
   block that renders them is extracted verbatim into a Packages tab (`/packages?tab=artifacts`),
   and only then does the route retire. The adopted census reads as the signed-in caller, like
   every other module read, rather than as the serve. Its classifications are re-derived under
   that identity, because canon filters collections by principal before it counts them.
5. **Marketplace needs no port.** The listings port takes the canonical route
   `/packages/marketplace`. The Packages module's Marketplace mode retires at its legacy mount,
   and its code stays in the module as a seed. Its counts and listing table are already rendered
   by the listings family, one hop from the landing.

The M6 order is therefore M6a (done), Marketplace, Artifacts after the port, and Fusion with M8.

## Amendment 3 (2026-09-25, owner-delegated): M7 and M7b execution rulings

1. **Terminal means a typed retirement with no successor.** Contour and Notepad shipped as landings. Each now
   answers the registered refusal (410, no replacement, nothing read or written), and a browser page says it
   is a terminal absence, says why, names this amendment, and links nowhere but Home. A typed-absence page
   would keep a registry row, and with it membership in the census, the smoke and the reachability checks,
   for a lane the benchmark rejected. Their handlers stay in the serve as seeds.
2. **Re-homed is not terminal.** Decision 5 named Logic, Widgets and Quiver beside Contour and Notepad.
   Amendment 1 re-homed all three (Ontology / Functions, Developer Console / Extensions, Operations /
   Telemetry seeded from the Quiver port). They keep serving under their current owners until those lanes
   land, and each then retires into its lane the way M6 retired a duplicate. Only Quiver's BI dashboard
   builder is terminal.
3. **The seven reference lanes are recorded, not built.** Slate, SQL Studio, AIP Analyst, Carbon, Foundry
   Rules, AI FDE and Training have `terminal_absence` adjudications. Each says what covers it or why it is
   outside the substrate, and uses the reasons from the re-adjudication. Slate's landing designation said NOW
   although no port was ever built, and its route answered a not-found page. It is TERMINAL.
4. **Functions: lane versus registration.** Canon lists "function, widget, and extension registries" under
   Developer Console, and puts Functions under Ontology elsewhere. Ontology owns the Functions lane
   (semantic functions over objects), and Developer Console owns the developer-kit registration of function
   packages. The wording is corrected in the cut that builds the Functions lane.
5. **M7b needs no wait for M8.** It moves no live population, so it lands with M7.

## Amendment 4 (2026-09-30, under the owner's authorization of 2026-09-29): Ruling 2 holds

The owner authorized one reviewed canon change set, to be applied once its end state was settled.
That set keeps canon's shell, so Ruling 2 stands as written:

1. **The shell navigation is unchanged.** `+ New`, Home, Systems, Projects, Automations,
   Applications and Work stay as `core-clients-surfaces.md` § Top-Level Product IA lists them.
   `+ New` loses Goal, a residue of R-192 (unaffected, above); that is not a navigation change.
2. **Home's composition changes inside Home.** Home becomes the composer over the board (Needs you,
   Working, Ready for review, Done) with "Your agents" and "Your systems" strips, and its
   Needs-you count opens Home filtered to what needs the viewer. `core-clients-surfaces.md`
   § Hypervisor Home owns that composition; no separate decision record is minted for it.
3. **Whether Systems keeps a permanent nav entry** remains the separate decision Ruling 2 names.

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
