# UX seed depth — the phase that ports each app's FLOWS, not just its landing

Status: **active phase** (opened 2026-09-26, R-241, at the owner's direction). Owner: the Hypervisor
app. Read [design-system.md](design-system.md) and [../AGENTS.md](../AGENTS.md) first — this phase
works inside their rules and changes none of them.

## Why this phase exists

The owner compared the app with the reference side by side (2026-09-26) and found the applications
obviously underseeded: the reference's Automate has an Overview (active-automation cards: owned by you,
for you, paused; recently viewed; recently triggered), an Automations list with a facet panel (status,
referenced resources, condition, effects, receiving notifications, owner) and a four-step New
automation wizard (Condition → Effects → Settings → Summary); ours has a single flat form. The
reference's Pipeline Builder has a create flow (name and location, batch or streaming, standard /
faster / external compute) and a graph editor (Graph / Proposals / History, undo/redo, branch, Save,
Propose, Deploy, a four-way add-data welcome card, a Pipeline outputs panel and output settings); ours
certifies the landing, and in the owner's session its slot never finished loading.

The cause is measured, not guessed. It is the depth of the HARVEST, and the ports followed it:

| Evidence (2026-09-26) | Value |
|---|---|
| Seeds in `reference-live-tenant-atlas.v1.json` | 39 |
| Seeds whose only recorded state is the landing | **33** |
| States in `reference-live-tenant-deep-atlas.v1.json` | 46 — 21 of them one app (Vertex) |
| Pixel certifications (`pixel-certifications/`) | 15 — each certifies ONE landing state at one URL |
| States the dead-control census visits beyond landings (`SURFACE_STATES`) | 5 (four Designer, one Packages) |

A pixel certification proves the landing's shell; it says nothing about the create flow, the list's
filters, the detail page, the editor or the run history. Nobody harvested those states, so nobody
ported them, so the serve filled them with hand-rolled forms — exactly the recreation the doctrine
forbids. This phase closes that, app by app.

## What "seeded to depth" means

The unit is the reference **flow state**: a route or in-page state × its control set × its data shape
(landing, list with filters, detail, create steps, edit, run / history, settings, and the empty, denied
and error forms of each). An app is **seeded to depth** when every flow state a person can reach in the
reference has, in our app:

1. **a harvested capture** — the state's markup, styles, bundle references and API response SHAPES,
   recorded from the authenticated reference and booted by the local mirror;
2. **an adopted port** — the reference's own implementation of that state vendored into the owned
   surface module (or the owned shell bundle, for the Ona-seeded shell), rebranded, never re-authored
   from a screenshot;
3. **a binding** — every data lane on the state reads and writes daemon truth through the serve lane
   or adapter; a control whose plane does not exist yet renders as a disabled, NAMED gap with a reason
   that survives reading (never a live-looking control that does nothing);
4. **a census entry** — the state is in `SURFACE_STATES`, so `check:dead-controls` clicks every
   control on it;
5. **proof** — the app's journey verifier drives the flow through the rendered forms against an
   isolated daemon, and the state's shell holds pixel parity where the data masks allow.

Reshaping is allowed where the reference is wrong for IOI (the owner's standing license), but the
starting point is always the adopted port.

## Method — harvest, adopt, rebrand, bind, freeze

The machinery exists; this phase runs it past the landing.

**H — Harvest (Arm B, read-only).** Attach over CDP to the owner's authenticated Chrome
(`ps -eo pid,cmd | grep -o 'remote-debugging-port=[0-9]*'`; currently :36831). Tabs are orchestrated
per app: the Foundry tenant for the Palantir-seeded apps, **Ona (app.gitpod.io) for Sessions** and the
rest of the shell. For each flow state record URL, sanitized DOM, network (bundles and API response
shapes) and a screenshot, and feed the local mirror (`internal-docs/reverse-engineering/palantir`,
`:9225`, on-demand harvest) so the state boots locally.
- *Observe, do not disturb.* It is a live tenant: never save, publish, delete or share. Walk a wizard
  to its last step and stop (Create stays unpressed); close dialogs with Esc or Cancel; never press an
  acknowledgement that persists a preference on the owner's account.
- *Viable demo data.* Where the tenant holds nothing for a state (many are empty), the harvest is not
  done until the state can render populated: synthesize sanitized fixtures shaped by the harvested API
  responses, served only by the mirror. Demo data never enters product code or a daemon.

**A — Adopt.** Vendor the state's ported implementation from the mirror into the owned tree beside the
app's existing port.

**R — Rebrand.** The source-neutral pass (brand, assets, copy), as for every existing port.

**B — Bind.** Each data lane to its daemon plane through the serve lane or adapter, fallthrough tracked
to zero. Planes that do not exist become named gaps on the state and join the plane backlog
(ADR 0056 Amendment 1) — the lane runs ahead of its plane, never the reverse.

**F — Freeze.** `SURFACE_STATES` entry, the app's journey verifier through forms, per-state shell
pixel parity where applicable.

## Inventory (measured 2026-09-26)

"Ref states" is what the two tenant atlases recorded; "ours" is the landing plus declared
`SURFACE_STATES`. "To harvest" lists the flow states known to exist in the reference (from the
owner's 2026-09-26 captures, the R-240 lane harvests and the atlases) that were never recorded.

| App (owner) | Our route | Ref states | Ours | To harvest (known) | Backing plane |
|---|---|---|---|---|---|
| **Automate** (Automations) | `/automations` | 1 | 1 | Overview (active cards, recently viewed/triggered); Automations list + facet panel; New automation: Condition catalog (time, objects added/removed/modified, run on all, threshold, dependency, …), Effects (action, logic, function, notification), Settings (retries, administrators, scenarios), Summary; automation detail + history | automation specs / installations / runs (canonical) + legacy executor; notification plane (P1); checkpoints (P5) |
| **Pipeline Builder** (Data) | `/data/recipes` | 1 | 1 | Create pipeline (name + location, batch/streaming, compute); graph editor (Graph / Proposals / History, add-data welcome card, outputs panel, output settings, tool rail); node config; preview; deploy | transformation recipes / runs; change sets (P4) for proposals |
| **Sessions** (Work; Ona-seeded shell) | `/work/sessions`, `/ai` | — | shell | Ona: session list, session detail (workspace, logs, ports), new-session flow, settings panes | sessions / lifecycle / environments |
| Ontology Manager (Ontology) | `/ontology/schema` | 1 | 1 | object type detail (properties, links, actions), value types, history, proposals | ontology drafts / revisions (M05.1) |
| Object Explorer (Ontology) | `/ontology/explore` | 2 | 1 | search results, object view, saved sets, exploration | object sets / projections |
| Data Connection (Data) | `/data/sources` | 1 | 1 | source detail, sync config, credentials, runs | data sources / transformations |
| Solution Designer (Studio) | `/__ioi/studio/designer` | 2 | 5 | template gallery states, AIP critic | Studio blueprints |
| Approvals (Governance) | `/governance/approvals` | 1 | 1 | request detail, policy view, history | approval requests |
| Issues (Operations) | `/operations/issues` | 1 | 1 | issue detail, assignment, comments | support incidents |
| Marketplace (Packages) | `/packages/marketplace` | 1 | 1 | listing detail, install flow | listings / packages |
| Model Catalog (Foundry) | `/__ioi/foundry/models` | 1 | 1 | model detail, versions, deploy | model routes |
| AIP Evals (Evaluations) | `/__ioi/evaluations/evalsuites` | 2 | 1 | suite editor, run results | evaluation-* plane |
| Upgrade Assistant (Improvement) | `/__ioi/improvement/changes` | 1 | 1 | change detail, plan | improvement / release change plans |
| Machinery (Automations) | `/__ioi/studio/machinery` | 2 | 1 | process editor states | Studio machinery |
| Builds / Build Schedules (Automations) | `/automations/runs`, `/automations/schedules` | 2 / 2 | 1 / 1 | build detail, schedule create | automation runs / schedules |
| Browse-only apps | workshop, logic, fusion, HyperAuto, inference, widgets, workspaces, devconsole, repositories, quiver | 1–3 | 1 | per app, to enumerate in its harvest pass | per app |

The inventory is re-measured at the start of each app's pass; the harvest's first job is to replace
"known" with an enumerated flow census for that app.

## Order

Owner visibility × plane readiness × done-bar journey legs:

1. **Automate** — the owner's first comparison, and its planes exist (canonical automation chain,
   notifications, checkpoints). The wizard maps onto them: Condition → activation kinds, Effects →
   steps, Settings → failure policy / retries (named gaps where unbuilt), Summary → create.
2. **Pipeline Builder** — the second comparison; fix-first: the slot that never finished loading is
   repaired (the Open Application slot now ends every load, R-240).
3. **Sessions** — harvested from the Ona tab, into the owned shell.
4. Ontology Manager and Object Explorer; 5. Data Connection; 6. Approvals, Issues, Marketplace, Model
   Catalog, AIP Evals, Upgrade Assistant, Machinery, Builds, Build Schedules; 7. the browse-only apps.

Each app is one cut: harvest census → adopted states → bindings and named gaps → `SURFACE_STATES` →
journey verifier → deploy to the owner's stack.

### Automate — progress and the adoption path (2026-09-26)

- **H done for the known flow:** 18 states recorded read-only over CDP (was 1) — Overview, the list
  with facets, an automation's detail (Status, Automation flow, Metadata, Monitoring rules), the wizard's
  condition catalog and all seven condition configurations, the effects step and all four effect
  configurations, Settings and Summary; evidence in `.artifacts/live-tenant-atlas/r241-automate/`
  (`flow-census.json`, screenshots) and the mirror's `tools/traffic/object-monitoring-flow/`. The 33
  bundle assets the mirror lacked were fed to it; the mirror now boots the wizard and the list locally
  with no failed request.
- **Finding that sets the path:** our Automate landing is NOT an adopted port — its source says it
  "reproduces the visible overview shell pixel-faithfully", a recreation made because the booted lane
  failed then (favorites load, CORS-blocked session lanes). Now that the mirror boots the app, the
  doctrine's path applies: **adopt the reference bundle itself** — served under the estate as a
  quarantined harvested lane, rebranded — and **answer its API calls from daemon truth through an
  adapter**, fallthrough tracked to zero (the Ona shell precedent: the owned bundle plus the IOI API
  adapter). Every flow state then arrives with the adopted app instead of being hand-ported one by one.
- **The adapter's surface (from the harvest):** the GraphQL gateway (`/graphql-gateway/api/bulk`, the
  bulk of the app's reads), the monitor registry (`/object-sentinel/api/registry/v0/*`, validation
  `validate-update`), identity (`/multipass/*`), profiles (`/people/*`), plus documentation, comments,
  object sets and function-registry reads for the effect configurations. Next: record each GraphQL
  operation's request and response shape per state (the first harvest kept response shapes only), map
  each onto the automation plane (legacy automations + the canonical spec / installation / run chain,
  notifications, checkpoints), and name every operation with no plane as a gap in place.
- **The adapter contract, measured (second harvest, GraphQL streams captured over the browser's own
  Network domain):** Overview calls `SearchMonitorsQuery`, `AutomationOverviewEventsQuery` (recently
  triggered), `SplashTableQuery` (recently viewed), `AutomationTriggeredEventPillQuery`,
  `GetCompassResource`; the list adds `AutomationNamespaceFilterComponentQuery`, `PrincipalsQuery`,
  `GetObjectTypeInSetForNotSavedSet`; every state also calls the reference's own sidebar
  (`WorkspaceSidebarQuery`, `ShellSidebarQuery`, `SidebarWithPanelQuery`, `CustomerDataSupportedQuery`
  — replaced by our shell's rail, so answered minimally), walkthroughs, announcements and marketplace
  templates (`BrowseTemplatesViewQuery`, `RecentInstallationsPopoverQuery` — named gaps). REST:
  `monitors-getMonitors`, `monitors/<rid>/published`, `validation/v0/<rid>/validate-update`, profiles,
  sessions. The adapter answers each in the captured shape (streams as event-stream).
- **Storage ruling (owner, 2026-09-26):** adopted bundles stay in the LOCAL MIRROR only — the repository
  is public and the bundle is not ours to publish. The estate's `/__apps/<slug>` lanes proxy the mirror
  and rebind specific calls to the daemon; the adapter and bindings are tracked, the bundle never is. (This
  supersedes step (1) below: nothing is vendored.)
- **First binding live (d21206891):** the adopted reference Automate list renders the Hypervisor's real
  automations — names, the cron condition in the reference's own words ("At 09:00 AM, Monday through
  Friday"), status, the creator resolved through our principal, and facet counts from daemon truth.
  Security fix found on the way: the mirror injects the reference tenant's real session token into every
  page it serves; the estate now substitutes a synthetic, unsigned identity token. Open next: manual and
  webhook automations need an honest condition — the reference vocabulary has none; today they read as
  "Time · Running on schedule" (a named gap; a condition type the app does not know is worse — it hides
  the row's name as "Restricted" and says it failed to parse — so the fix is reshaping the adopted app's
  condition labels), the referenced-resources filter, Overview's owned count, the detail page
  (`monitors/<rid>/published`), the wizard's validate + create onto the automation plane, and the shell
  embedding (drop the reference's own sidebar under our rail) before `/automations` moves to it.
- **Current build, one answer per operation (2026-09-26):** the mirror's Automate index was updated to the
  tenant's CURRENT build (all 130 runtime assets present), which ended a webpack mixed-build crash on the
  detail route; it speaks the streaming `/bulk` gateway (`{operations, requests:[{hash,name,variables}]}`,
  one `data:` event per request index). Every operation is now answered by the serve and never by the
  mirror's loose mock: bound operations from daemon truth; a SAFE list of fact-free operations (the
  reference chrome, permissions, protection, walkthroughs, branches) from the recorded answer with lists
  emptied and identity overwritten; everything else a named GraphQL error. Lesson recorded: enveloping an
  operation that DESCRIBES an automation leaked the recorded tenant monitor's facts ("Objects added ·
  Live monitoring · last triggered Jun 23") onto ours — such operations must be bound, never enveloped.
  Detail-page operations still to bind: `ResourceHeaderQuery`, `CompassResourceQuery`,
  `SingleAutomationOverviewV2Query`, `AutomationFlowQuery`, `AutomationLiveStatusQuery`,
  `AutomationStatusControlQuery`, `AutomationMonitoringRulesCardQuery`, `AutomationDependenciesQuery`,
  `ExpiryDateProjectQuery`, `GetLiveStatusForNonVersionedObjectSet`; comments `batch/page-v2` (empty pages).
- **Detail page bound (2026-09-26):** `adopted-graphql.mjs` answers each fact operation by walking the
  app's own query document (fields, aliases, fragments, inline type conditions) against a fact object built
  from the automation and its runs; recorded answers lend structure only (typenames, booleans, enum
  constants), never names, times, ids or list items. Facts declare the abstract types they implement
  (`ObjectSetMonitorLogicV3`, `ObjectSetMonitorHistoryEvent`) so fragments on unions apply. The adopted
  detail now reads: our name, Active, "Scheduled automation — runs at 09:00 AM, Monday through Friday
  (UTC)", last triggered Never, execution No events yet, no monitoring rules. Named gaps on it: our steps
  (command / agent) are not reference effects, so the effects card reads empty until reshaped; some
  metadata rows (owner, created by, automation RID) and the frequency tag; the comments batch read.
- **Read flows at zero unbound (aa11e47b8):** Overview, the list and the detail page make no call the
  adapter cannot answer (`GET /__ioi/adopted-seeds/unbound` counts by name; the drive reads it).
- **The wizard's create depends on P3 (functions).** The reference refuses Create until an effect exists,
  and its effects are Action / Logic / Function / Notification — none is a Hypervisor command or agent
  step. The Function effect is where "run this code" belongs, and canon gives functions to Ontology with
  Automations consuming them (ADR 0056 answer 3), so the create path binds once the function-revision
  plane (P3) exists: the Function effect's registry reads answer from it, and an automation created
  through the adopted wizard becomes an automation whose step runs that function. Until then the adopted
  wizard walks, and its Create is a named gap; `/automations` keeps the current create form.
- **The wizard creates (2026-09-27, ADR 0056 P3 cut 3b; `check:adopted-automate` 8/8).** The adopted
  wizard walks Condition (Time) → Effects (Function) → Settings → Summary → Save over daemon truth:
  - *Function effect.* Its registry reads (FunctionResultsQuery, FunctionPreviewQuery,
    SelectedFunctionQuery, GetFunctionDisplayName, GqlFunctionVersionSelectV2Versions,
    getFunctionParameters, FavoriteFunctionsQuery; REST `function-registry …/metadata` and `…/resolve`)
    answer from the functions plane (`adopted-functions.mjs`) — RELEASED, operable revisions only, the
    same set a function step may pin; our type algebra maps 1:1 to the reference's `FunctionDataType_*`.
  - *Save as…* offers the caller's projects as locations (an automation's required container) with two
    ancestors (root, namespace — the picker refuses fewer), validates the name against the project's
    automations, answers the OAuth-client read with none (the automation runs as its owner), and the
    security card's `validate-create` with no issue when the request translates.
  - *Save* (`POST /object-sentinel/api/registry/v0/monitors`) is translated (`automationFromMonitorRequest`)
    into `POST /v1/hypervisor/automations`: the project, a cron `schedule_spec` in the wizard's NAMED zone
    (the daemon scheduler now follows IANA zones from the host's tzdata — `zoneinfo.rs`), and one
    `function` step pinned to the released revision's content hash with its typed static inputs. The app
    then reads the new monitor version and its compass resource and lands on its detail page.
  - *Refused by name, never dropped:* object conditions, Action / Logic / Notification effects, failure
    effects, a second cron expression, dynamic function inputs. *Not enforced (named):* the wizard's
    expiry date and its retry settings. The resolver fix that made this possible — GraphQL merges every
    selection of one response key — also applies to the detail page's reads.
- **Automations opens the adopted app (2026-09-27; `check:adopted-automate` 9/9).** With
  `IOI_ADOPTED_SURFACES=1` (the owner's serves) and the local mirror able to boot it, `/automations` opens
  the adopted Automate app; `?automation=<id>` opens that automation's own page. The app's own base path
  (`/workspace/object-monitoring/…`, which its router pushes) is served as the seed, so reloads and deep
  links land in place (they used to bounce to Overview). The reference's global sidebar never shows: at
  top level OUR rail stands in its column (our routes, the caller's account chip); framed by the shell,
  neither shows. A function step now appears as the reference's Function effect — in the registry record
  and on the detail page's Automation flow (function, version, inputs). Without the opt-in or the mirror,
  `/automations` keeps the owned Automate surface, so every gate's own serve keeps one posture. `/__apps/*`
  now requires sign-in like every other product page.
- **A manual automation's page renders (2026-09-27; `check:adopted-automate` 11/11).** The detail of an
  automation with no schedule crashed ("An error has occurred"): its condition was a schedule with an
  empty cron, which the overview's cron describer refuses. The reference has no manual condition (manual
  execution is an action on any automation), so the detail now reads **"Unknown condition"** — its own
  answer for a condition it does not know — and the frequency tag reads Unknown; neither claims a schedule.
  The Owner / Created by / Updated by rows now name the Hypervisor's principal: user ids are name-based
  UUIDs (v5 shape), because the app validates ids with the `uuid` package and silently drops every
  profile lookup for any other shape.
- **The editor edits (2026-09-27; `check:adopted-automate` 13/13).** Edit → Condition / Effects /
  Settings / Summary walk over daemon truth, and one Save carries a rename (compass `updateResource` →
  PATCH name) and the monitor edit (`updateMonitor {metadata, logic}` → PATCH schedule and function
  steps, same pinned revision); the app lands back on the renamed automation. Refused by name, nothing
  written: moving to another project; saving an automation with command or agent steps the editor cannot
  show. The editor's "Insufficient permissions to save" was the app's cache holding our null answer to
  `resourceMetadata(rid: $initialRid)` — the save-location facts now scope on `initialRid`, and one
  builder describes a project folder everywhere (two copies with different permissions were merged by the
  app's cache). The detail page now shows EVERY step, in order ("Executed sequentially"): an agent step
  is the reference's Agent effect with its prompt as the one input, and a command or proposal step reads
  as the app's own "Unknown effect" — the owner's 25 automations (agent + command + proposal) used to read
  "There are no effects configured". The page's own writes land too: the description and the header rename
  (GraphQL mutations) and Pause / Resume (REST `disable`) are PATCHes of the automation; the pause
  popover's promise that in-flight executions are canceled mid-run is kept — the adopted pause cancels
  each running execution, and the daemon's executor now honors a cancel before every step (it used to run
  on and overwrite `stopped` with `done`). Settings are no longer accepted and ignored: the expiration
  date becomes the automation's `expires_at`, which the daemon enforces (its scheduler skips an expired
  automation, its webhook refuses `automation_expired`), and enabled event or effect retries are refused
  by name — the executor does not retry. The detail page's side tabs work over daemon truth: **History**
  lists the automation's runs as events (All / Auto / Manual / Errors; a person's Run now is a manual
  execution, a scheduled or webhook run an automatic trigger — each execution now names its
  `activation_kind`), **Execute** is the automation's Run now (the effect picker; a selection of only some
  effects is refused, since a run executes every step), and **Telemetry** counts its executions (runs,
  failures, runtime; the run history is one request log per execution). Two mirror feeds were needed: the
  telemetry chunk and five stylesheets it loads. The header's File → Rename renames the automation
  (`UpdateResourceName`), and the Metadata card's Location names the project (it showed a bare folder id).
  Favorite has no Hypervisor plane: it is refused by name, but the app shows no message. Move, Share and
  Move to trash are disabled — an automation stays in its project and has no sharing or trash. The
  Overview's Recently triggered lists the automation's automatic runs (a person's Run now is not a trigger)
  with the condition that fired them — it read "No events found" always. Driving it found a daemon defect:
  a function step run by the daemon's own dispatch (a webhook fire, a scheduled tick) failed with "an
  authenticated session or API token is required", so every scheduled function automation — exactly what
  the adopted wizard creates — would have failed at its time; the step now honours the dispatch identity.
  *Still open (named):* the Agent effect's title reads "Unknown Agent"
  (no agent definition bound); command and proposal steps have no reference effect to name them; the
  editor lists a manual automation's condition as Time; the refusal reason shows only as a tooltip;
  History's Edits filter lists nothing (no per-automation edit history is kept); Favorite is refused
  silently; Recently viewed always reads empty (no view history is kept). Effects run in the order the
  request states, and a request for parallel effects is refused by name (steps run one after another);
  the editor's record states that order, so it reads "Execute effects sequentially".
- **Adoption steps:** (1) vendor the booted app — `index.html` + its 34 content-addressed assets,
  18.5 MB, the same scale as the tracked Ona tree — into a quarantined harvested lane in the owned tree;
  (2) serve it at the Automate canonical route, its asset and API paths answered by the serve (assets
  from the vendored tree, API through the adapter to the daemon); (3) rebrand; drop the reference's own
  sidebar under our shell; (4) bind operation by operation, fallthrough counted to zero; (5) freeze:
  `SURFACE_STATES` for every flow state, the journey through the wizard, retire the recreation.

### Pipeline Builder — harvest and the plane it needs (2026-09-27)

- **H done for the known flow:** 11 states recorded read-only over CDP — the landing (recents, project
  and creator filters, New pipeline, marketplace examples), the create form (name and location; Batch or
  Streaming; Standard / Faster / External compute — walked, never created), and the tenant's pipeline in
  the editor (Graph with the four-way add-data welcome card, Proposals, History, Add data, Pipeline
  outputs and output settings). Evidence in `.artifacts/live-tenant-atlas/r241-pipeline/`. The mirror's
  builder index was a stale build (no script in common with the tenant's); it now serves the current
  build and every asset it and the flow reference (feeds are read-only GETs).
- **Wire contract, measured:** the landing searches `EDDIE_PIPELINE` resources over GraphQL
  (`PipelineLandingSearchQuery`, `PipelineLandingRecentsAndFavoritesQuery`), then reads details over REST
  (`eddie/api/pipelines-v2/get/by-rids`: name, attribution, published sandboxes; `get-sandboxes-with-
  snapshots`: each draft's snapshot of transforms, targets and outputs; `CurrentPipelineDeploymentQuery`).
  The Project filter searches compass (`foundry-search/api/compass/v0/search`) — a passthrough today that
  must answer with the caller's projects before the lane is shown to anyone.
- **The plane it needs.** A reference pipeline is a mutable DRAFT (a sandbox holding a snapshot of
  transforms and outputs) that is later DEPLOYED. The Hypervisor's `DataRecipe` (v2) is an immutable,
  complete revision — exact ontology revisions, connector-mapping revisions, output contracts, canon's
  transformation steps, receipt obligations — and a deploy is a `TransformationRun`. An empty new
  pipeline cannot be a DataRecipe revision, so Create (and the editor's edits) need a **recipe-draft
  plane**: an owner-scoped, mutable authoring record that is admitted as a DataRecipe revision when
  complete, contract first. Until it exists the landing can list admitted recipes and Create is a named
  gap. The owner holds no DataRecipes (six ODK transformation runs), so `/data/recipes` keeps the owned
  port until the adopted landing is at least as useful; the adoption stays in its `/__apps/pipeline` lane.
- **The plane, built (2026-09-27, ADR 0056 P4).** The recipe draft is canon's patch branch, not a new
  mutable record: a **change set** (`change-set.v1`, `/v1/hypervisor/change-sets`) pins the family's head,
  carries an append-only chain of drafts shaped as DataRecipe admission requests, validates a draft with
  admission's own checks (no revision written), and merges by admitting the draft with the pinned head as
  the expected head. A moved head is refused `change_set_base_moved`, never rebased, and the merge is
  recorded as a BranchMergePlan. `check:change-sets` 11/11 on an isolated daemon. **Next (cut 2):** the
  adopted landing lists recipes and open change sets; Create opens a founding change set; the editor's
  edits are drafts; Proposals = proposed change sets; History = the family's revisions; Deploy = merge
  plus a TransformationRun. Before the lane is shown to anyone, the compass search must answer with the
  caller's projects.
- **Cut 2a — the landing, bound (2026-09-27).** `adopted-pipeline.mjs` answers the landing: a pipeline is a
  DataRecipe family; Main is its admitted head (the only published sandbox); each open change set is a
  draft sandbox; a founding-only family is a pipeline whose Main holds no revision. Each row shows the
  recipe's declared outputs (snapshot targets: object models and dataset contracts, the latter named through
  compass), Batch, and "Not yet deployed". Search and the creator are bound; the Project filter is a named
  gap (a DataRecipe is held in no project). The project picker, the user lookup and the universal capture
  fallback no longer hand out the reference tenant's records (the fallback now flags its API answers).
  Signed out, the picker and the lookup answer nothing. `check:adopted-pipeline` 11/11 (local mirror only).
- **Cut 2b — the editor opens, read-only (2026-09-27).** About 25 opening reads (REST and GraphQL) answer
  from the Hypervisor; a pipeline opens on Main with its declared outputs and "Pipeline not yet deployed". The
  caller holds no edit operation until drafts are bound; Main forbids a direct push (only a merged change set
  moves it); the graph honestly reads "not initialized" (steps are not derived into transforms). The
  markings reads and input resolution no longer hand out tenant records. `/workspace/builder` is an adopted
  route alias. `check:adopted-pipeline` 14/14.
- **Cut 2c — Create (2026-09-27).** The adopted create form opens a FOUNDING change set (family = the name,
  slugged) and lands in the editor on its draft sandbox. Ruling: a recipe is held in the owner's recipe
  registry, never a project, so the location dialog offers "Data recipes" as its one location and a project is
  refused by name; standard batch (Spark) is a TransformationRun, faster / streaming / external are refused by
  name, as are initial datasets and a name whose family exists. `check:adopted-pipeline` 17/17. **Next
  (cut 2d):** the editor's writes as drafts to the change set (then Propose), Proposals / History, Deploy =
  merge + TransformationRun.

## Gate

`check:seed-depth` (built 2026-09-27 with the Automate cut; CI-bound): the tracked record
`apps/hypervisor/seed-depth.v1.json` lists every reference flow state of every adopted app — the harvested
states plus those found by driving the adopted app — each with ONE disposition: **bound** (a live
verifier assertion, cited by its exact text), **refused** (refused by name; a test proves it),
**named_gap** (what the person sees, and why) or **open** (known debt, counted down to zero). Renaming or
deleting a cited proof breaks the gate; the populations are pinned exactly per app and disposition, so a
state cannot quietly move from bound to open or vanish. Automate's first census: 27 states — 12 bound,
9 refused, 2 named gaps, 4 open. Apps later in the phase order carry `not_started` and no states until
their cut begins. It rides beside `check:dead-controls`, which now also probes the canonical
lanes (Work, Systems, Operations, Environments, Leases & Limits, …) that the registry never listed.

## Rules that do not bend

- Captures, screenshots and `/__apps/*` lanes are evidence; the adopted port is the product.
- No tenant data in product code; demo data lives only in the mirror's fixtures.
- Observe, do not disturb the live tenant.
- A lane may run ahead of its plane only with named gaps; the client never mints the missing truth.
