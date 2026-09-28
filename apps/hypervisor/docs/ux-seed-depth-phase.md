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
- *Leave what exists alone.* It is a live tenant. Never alter, share or delete the owner's existing resources, and
  never press an acknowledgement that persists a preference on the owner's account.
- *Build the example the state needs.* Owner, 2026-09-28, standing on every surface: "i authorize you to make any
  mutations productive to produce a quality harvest example". Where the tenant holds nothing for a state (many are
  empty), create, configure and run a clearly named example on the tenant (a source and its sync, a pipeline, an
  automation, …) until the state renders populated, then harvest it. Record every tenant write in the app's
  `.artifacts/live-tenant-atlas/<app>/TENANT-WRITES.md`. Examples are not deleted unless asked.
- *Viable demo data.* Where a state still cannot render populated, synthesize sanitized fixtures shaped by the
  harvested API responses, served only by the mirror. Demo data never enters product code or a daemon.

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
4. Ontology Manager and Object Explorer; 5. Data Connection; 6. in the master guide's recommended order (§0.6,
   adopted 2026-09-28): Control Panel Approvals with the Approvals app, the rest of Checkpoints, Network egress,
   Identity, AIP Chatbot Studio, the ontology action type and its action log, AIP Evals and Logic, then Ona Automations
   with Cost & Budgets; 7. Issues, Marketplace with DevOps, Model Catalog, Upgrade Assistant, Machinery, Builds, Build
   Schedules; 8. the browse-only apps. Model Catalog through Builds seed less of the target than anything in step 6.

Each app is one cut: harvest census → adopted states → bindings and named gaps → `SURFACE_STATES` →
journey verifier → deploy to the owner's stack.

**What the seeds are for (master guide §3.6, revised 2026-09-28: remix, not port).** The later refactor does not port
these apps one by one. It breaks every harvested state, including browse-only ones, into ingredient patterns. It gives
each pattern one home, or a recorded reason for dropping it, in a 14-surface IA organized around the substrate's own
objects (System, Run, Effect/Receipt, Agent, Policy, Ontology). Every bound seed-depth row must then re-bind on the
surface that owns its pattern (U3). For this phase, that means:
- a harvest captures the flow's states, not just a picture;
- a bound row asserts daemon truth, so it survives the move to a new surface;
- no seed is thrown away because it was only browsed.

**Substrate seeds, harvested during this phase (added 2026-09-28).** The master guide (§0.6, "Harvest before the
refactor") ranks 13 reference surfaces that the journey order never reaches. The substrate refactor rebinds owned
surfaces against harvested flow states. A capability with no seed has to be designed from scratch, with no reference
behaviour to check against. These are **harvest-only (Arm B)** cuts. They run beside the adoption cuts above and do not
reorder them:

1. Control Panel Approvals: inbox, request task, policies. A pending state needs one example request.
2. Control Panel Network egress: policies, the request dialog, Secure Tunnels, PrivateLinks, S3 bucket policies.
3. Identity: Foundry Groups, Markings, Roles, Users, Tokens and Third-party apps; Control Panel permissions; Ona
   Members, Service Accounts, Login, SCIM and OIDC. Examples needed: a marking, a group, a short-lived token, a service
   account. A secret is never recorded.
4. AIP Chatbot Studio: agent edit and view.
5. Ontology action type detail and the action log. Needs an action type on a backed object type, plus one submitted
   action.
6. The rest of the Checkpoints wizard.
7. Ona Automations.
8. AIP Evals and Logic editors.
9. Spend screens and the Linter.
10. The apps behind planes P8–P11: Sensitive Data Scanner, Cipher, Document Intelligence, Custom Widgets.
11. Workflow Lineage.
12. DevOps stores.
13. Control Panel Audit logs.

Nothing in either reference lets a person browse per-effect receipts or an agent's track record. Those surfaces are
IOI-native, with no seed to copy.

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
- **Cut 2d, the reads — Proposals and History (2026-09-27).** Proposals are the family's change sets by
  status (proposed → open, merged → merged with exact version ids, rejected / abandoned → closed); a proposal's
  page diffs declared outputs and lists its events. History is the family's own timeline: revisions (a merged
  change set's revision as a merged-proposal row) and TransformationRuns as deployments on Main, drafts on a
  change set; a queued run claims no deploy, and "Currently deployed" is the latest completed run's revision.
  Compare with… works over two aliases of one field (the resolver keys such facts `alias:field`).
  `check:adopted-pipeline` 24/24.
- **Deploy, refused by name (2026-09-27).** The deploy panel's check answers "Pipeline cannot be deployed" with
  the reason under Details (the builder admits no TransformationRun yet and nothing executes a queued one; a
  change set's drafts are not admitted revisions); a direct deploy fails the same way and admits nothing.
  Deploying is gated on the edit operation the editor withholds until its writes are bound.
  `check:adopted-pipeline` 26/26.
- **Cut 2d, the writes (2026-09-27).** The caller edits their own pipelines; Main stays protected. A branch is a
  change set on Main's head (the builder's own Create new branch dialog); a Save is the change set's next draft
  (the snapshot's outputs, everything else carried); proposing validates and proposes under the dialog's name and
  description (the daemon's propose takes them, `518fdab9e`); merging admits the latest draft; denying rejects it
  with the reason; archiving abandons it. Refused by name: transforms (ADR 0057), an output with no contract, a Save
  on Main, approvals, closing, rebasing. The autosave buffer lives in the serve's memory per caller. The missing
  checkpoint chunk had silently dropped Merge (fed to the mirror). `check:adopted-pipeline` 31/31.
  **Next:** the proposal page's checks from the change set's validation; then Sessions (the Arm A findings).

### Sessions — Arm A and cut 2 (2026-09-27)

Driving the Sessions shell against the 44 harvested states (46 rows: 28 work, 2 refused, 6 named, 5 dead, 2
unrenderable, 3 absent) found a destructive defect: the Archived view's "Delete all" deleted every environment
(`a529ab650`, fixed and deployed the same hour). Cut 2: a missing shell chunk is a named gap instead of a crash (the
file diff, the terminal pane, personal settings); the environment names its organization and runner, so the editor
openers resolve a URL and the details card renders; the env-ops bridge carries the person's session, so the terminal
works; each daemon keeps its own preference store. `check:sessions-shell` 8/8 is the Sessions gate. **Next:** the
composer's dropped choices, the invented auto-stop label, the Code tab's auto-start, failed runs shown healthy.

### Arm A — the adopted apps are clicked (2026-09-27)

`check:dead-controls` never reached the adopted apps (its serve runs without adopted surfaces; `/__apps/*` is a
reference lane to it). `check:adopted-dead-controls` is the same census over the adopted Pipeline Builder
(landing, editor, create) and Automate (overview, list, an automation's page), with its defect list pinned
exactly. It found the reference sidebar's dead links on the builder (our rail now), Automate's header project
breadcrumb going nowhere (the resolver lacked `ResourceMetadata` → `ResourceAncestor`), and — driving the
degraded axis — that a stopped or refusing daemon read as "nothing exists" across both apps (every adopted
read now checks the answer; a plane down is the app's own error state). Cross-surface: v2 DataRecipes never
reached the owner's `/data/recipes` (now the adopted builder). Every adopted app now carries a daemon-stopped
assertion in its verifier.

### Ontology Manager — harvest and the adoption path (2026-09-28)

- **H done for the known flow.** A read-only CDP census recorded 27 states: the landing (Discover); all 13 of its
  sections (object, link and action types, interfaces, shared properties, value types, groups, functions, proposals,
  history, health issues, cleanup, configuration); an object type's overview and eleven tabs (properties, security,
  datasources, observability, capabilities, object views, materializations, automations, usage, history); and Object
  Explorer's landing. Wire bodies were recorded for 17 of them, into the git-ignored mirror traffic dir
  (`tools/traffic/ontology-manager-flow/`). The mirror was fed the 36 bundle assets it lacked, and now boots the
  reference Ontology Manager locally with no failed request.
- **What the app asks for.** 54 GraphQL operations and 35 REST endpoints:
  - 13 are chrome on every page (sidebars, branch select, walkthroughs, announcements);
  - the section lists: ObjectTypesListQuery, LinkTypesListQuery, ActionTypesListQuery, InterfacesListQuery,
    SharedPropertyListQuery, TypeGroupsListQuery, SearchAllValueTypesQuery, SearchAllFunctionsQuery;
  - the ontology loads: `ontology-metadata` `v2/load/all`, `loadAllObjectTypes`, `summary`, `bulkLoadEntities`,
    `actions/types/load/all`, `entityMetadata/load`, permissions, `featureConfigurations`, `getSettings/user`;
  - the object registry: `phonograph2` metadata and usage.
- **The line that must hold first.** Every unbound REST read under the mirror prefixes is passed through to the mirror,
  and the mirror answers with the RECORDED TENANT's ontology. So the adopted app is not reachable at a canonical route
  until two things hold: its reads are bound over daemon truth, and a fence answers every other ontology or registry
  read as a named gap on the ontology surface.
- **Backing truth.** ODK domain ontologies (`canonical_object_model`: object types with properties and title property,
  action types; health counts; a receipted history), the ontology-versions plane (M05.1 published revisions), and the
  materialized object sets.
- **Cuts.**
  - O1: the landing and section lists, bound, plus the fence.
  - O2: an object type's pages.
  - O3: seed-depth rows, a journey verifier, deploy. Done 2026-09-28: `check:adopted-ontology` (16 assertions,
    each proven red by a planted defect); 35 flow states = 16 bound / 11 named gaps / 8 open (ledger CCXVI). The
    canonical route `/ontology/schema` stays the owned surface until create and edit are bound over ODK: New is
    disabled with no reason, and the type pages give a false one ("You do not have edit permissions").
  - O3b, next: create and edit. Driven 2026-09-28 on an isolated stack with edit permission on, a description edit
    reaches Review changes, and Save to ontology stays disabled. The reference saves a type only with a backing
    datasource and an object data store ("Backing datasource is missing"). An ODK type has these only once
    materialized (`odk-materialized-object-sets`, written by a materializing run under a held lease). So the cut is:
    bind a type's materialized set as its datasource, together with its object count and index failures (a failed
    materializing run); then a save becomes an ODK patch at the expected revision. Proposals from ODK's proposal
    plane and a Functions assertion follow.
  - O4: Object Explorer (`/workspace/hubble/`). Landing adopted 2026-09-28 on the same surface and fence. Its catalog
    lists the caller's ODK types, and Recents is the same Recently viewed the Ontology Manager records (asserted
    across both apps). Installed-application metadata and command-palette commands answer empty instead of passing
    through. Named gaps: counts, empty shortcuts, and lists (Compass search's shape was never recorded). Open: object
    search, since objects need a materialized set.

### Data Connection — harvest and the adoption path (2026-09-28)

- **H.** The reference app lives at `/workspace/data-ingestion-app/`. A read-only CDP census recorded the landing, the
  five sections (Sources, Syncs, Agents, Listeners, External stacks) and the connector catalog. The tenant held no
  sources, so at the owner's direction examples were built on it (tenant writes are listed in the atlas's
  `TENANT-WRITES.md`):
  - an example REST API source, which gave the setup wizard up to connection details, and a source's Overview,
    Connection settings, Webhooks and Code-imports pages;
  - the reference example "Connecting to AWS S3", installed from the splash. It brought a source, a sync and egress
    policies for Palantir's training bucket, and gave an S3 source's batch syncs table, Explore source, Virtual tables
    and Logs.
  - The sync was run twice. Both runs fail: the training bucket is not public, and the example ships placeholder
    credentials. So a sync's Overview, Configuration and Versions were harvested with a failed run, plus its build
    report.

  The local mirror boots the app with no failed asset. The GraphQL bodies (documents and streamed answers) are recorded
  in the mirror's traffic dir (`data-connection-flow/operations`).
- **Still to harvest.** A succeeded run and its dataset (they need working credentials), and the setup wizard's
  remaining steps (export configuration, code import configuration, summary).
- **Backing truth.** Data sources (`/v1/hypervisor/data-sources`: kind `rest_api`, endpoint, credential posture),
  connectors with their credentials, and the materialization ladder (connector mapping → projection → lease plan →
  materializing run → materialized object set). That ladder is the Hypervisor's import, the analog of a sync.
- **Cuts.**
  - D1: route the app (`/workspace/data-ingestion-app` → the `sources` seed) behind a fence like the ontology's;
    bind the landing and the lists (sources from the data-source plane; agents, listeners and external stacks none).
    Done 2026-09-28: `check:adopted-data-connection` 7/7; seed depth 25 = 4 bound / 5 named gaps / 16 open (ledger
    CCXIX).
  - D2: a source's pages over its data source and connector. Part 1 done 2026-09-28: a source opens from the list on
    its Overview (name, connection type, what it can do; nothing it cannot), `check:adopted-data-connection` 8/8; seed
    depth 26 = 5 bound / 5 named gaps / 16 open (ledger CCXX). The mirror's index was an old build loading new
    chunks, so the page crashed; it now matches the tenant's current build. Part 2 done 2026-09-28: Code imports
    and Webhooks bound (both off; nothing on them can turn either on), `check:adopted-data-connection` 9/9; seed depth
    28 = 7 bound / 6 named gaps / 15 open (ledger CCXXI). Connection settings' reads are bound, but the page shows a
    false "no permission": a declared source cannot change, because the data-source plane has no update route (daemon
    gap). The webhooks callout blames the runtime, which is also false.
  - D3: New source as a data-source create (REST API only; every other type refused by name). Done 2026-09-28: the
    catalog, a type's overview, name and location (filed in a project), Create — a DRAFT data source (new daemon
    `draft: true`) — connection details (the draft gets its endpoint through the new `PATCH
    /v1/hypervisor/data-sources/:id`, declarer-only, receipted, refused once a lease plan binds the source), and the
    remaining steps; an existing REST source's connection settings edit the same way, keeping the endpoint's path.
    `check:adopted-data-connection` 12/12; seed depth 30 = 14 bound / 1 refused / 7 named gaps / 8 open (ledger CCXXII).
    Traps paid: the Pipeline surface's authz answer ran on every surface (the catalog read "no add-source" and rendered
    nothing); the mirror's `sources/new` index was a June build, so the whole create flow ran an old app.
  - D4: syncs over materializing runs. Done 2026-09-28. A sync is a capability-lease plan on one of the caller's
    sources, and its builds are the plan's materializing runs. Bound: the Syncs list and its filters, a source's Batch
    syncs table, and a sync's Overview, Configuration and Versions (the plan's lease shape as its configuration). Run
    statuses were driven live: Never ran, Waiting (a run admitted, waiting for its lease), and Canceled. Run needs a
    wallet-authority grant, so it is refused by name and points at the approval flow; Delete and the other sync writes
    are refused by name. `check:adopted-data-connection` 18/18; seed depth 41 = 21 bound / 3 refused / 11 named gaps /
    6 open (ledger CCXXIV). Still open: a failed run (reaching it needs a grant), and New / Duplicate / Save.
    Named gaps: Created by (a plan records no declarer), earlier versions, and the dataset and build report apps.
    Trap paid: the Configuration page loads the reference's CustomSourceAdapter chunk, which the mirror had never
    recorded; it was fed to the mirror from the tenant's current build.

### Approvals — harvest and the adoption path (2026-09-28)

- **H.** The reference app lives at `/workspace/approvals-app/` (a request's page at `/task/<rid>`). A CDP census recorded
  60 states: the empty inbox (the three quick filters, the Request type, Status, Created by and Sort menus, search, each of
  the eight request types and their facets, the not-found page, Control Panel task ids that redirect); the reference file
  browser's Request additional access and New project dialogs, walked to make one example; and the app with that example
  pending (a request's page with its reviewer task, Invite reviewers, Edit, a comment draft). Evidence in
  `.artifacts/live-tenant-atlas/r241-approvals/` (tenant writes in its `TENANT-WRITES.md`: one example project, one pending
  access request). Control Panel's approvals inbox, task pages and policies are in `../r241-control-panel/`.
- **Backing truth.** The daemon's asks: parked wallet challenges (`/v1/hypervisor/authority/challenges`: an exact effect a
  gate refused for want of a grant, with its preimage, hashes, scope, audience, requester and decision), governance
  approval requests (`/v1/hypervisor/governance/approval-requests`: record-only, with creator, reviewer, history and
  receipts), and the approvals inbox's pending rows (`/v1/hypervisor/governance/approvals-inbox`, whose tool calls waiting
  in a run have no list route of their own).
- **Cuts.**
  - A1: route the app (`/workspace/approvals-app` → the `approvals` seed) behind a fence of its own; bind the inbox and a
    request's page. Done 2026-09-28: `check:adopted-approvals` 15/15; seed depth 74 = 29 bound / 5 refused / 38 named gaps
    / 2 open (ledger CCXXV).
    - *A request is one of the daemon's asks*, listed under the reference's Access requests type (the one that asks for
      authority): a parked challenge reads "Approve session-execute on <session>", a governance request "<kind> — <subject>".
      The seven reference types with no Hypervisor counterpart (ontology and Workshop proposals, deletions, CDM publish,
      retention changes, user intake, add reference) list none.
    - *The inbox.* Your inbox is what the caller may decide and has not (the operator for challenges and tool calls — the
      daemon refuses anyone else — and any signed-in principal for governance). Unlike the reference, the requester is NOT
      left out of their own inbox: an operator's own parked effect waits on that operator. Created by you, All requests, the
      hierarchical Status menu, search, sort, several types together and the Created by picker (the daemon's directory)
      sift it; the counts are the reference's three sub-filters over the same rows.
    - *A request's page is its record*, carried in the justification: a challenge's intent, scopes, target scope, policy
      domain and hash, request hash, audience, approval ref, expiry and decision; a governance request's ask, subject,
      required authority, what it would call and its receipts. Requesters and deciders are named from the daemon's
      directory.
    - *Decisions stay keyless.* Approve on a parked effect is refused by name toward the run's approval card: approving
      mints a grant, only the operator passphrase unseals the key that signs it, and the reference page has no passphrase
      field. Reject and close is the daemon's own deny (no key; it mints nothing) with the typed reason. A governance
      Approve is the plane's transition (the daemon names the reviewer from the session and writes the receipt); its Reject
      is refused, because the plane's rejection keeps no reason. Close on an open request, Invite reviewers, comments and any
      REST write are refused by name.
    - *Named gaps:* the reviewer task card (the reference draws one only for its own request types), Edit, Request changes
      (the same review as Reject), the access facets, Control Panel's redirecting task ids, the inbox's other pending planes
      (improvement and memory proposals, marketplace reviews), the shared sidebar entry. *Open:* a challenge's Approved,
      Completed and expired statuses, and a thread approval — mapped and unit-tested, not driven.
    - *Mirror.* The captured index was build 6.517.0 while the tenant runs 6.545.0; it was refreshed, and every chunk the
      current runtime can load (1,240 JS and CSS files, plus the harvest's 273 assets) was fed by plain GETs through the
      owner's browser. The harvest's own asset list named an older build's chunks, so feeding only those left the landing
      crashing on missing chunks.

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
- Leave the tenant's existing resources alone; build clearly named examples where a state needs one (owner, 2026-09-28).
- A lane may run ahead of its plane only with named gaps; the client never mints the missing truth.
