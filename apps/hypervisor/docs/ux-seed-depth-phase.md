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
- **Adoption steps:** (1) vendor the booted app — `index.html` + its 34 content-addressed assets,
  18.5 MB, the same scale as the tracked Ona tree — into a quarantined harvested lane in the owned tree;
  (2) serve it at the Automate canonical route, its asset and API paths answered by the serve (assets
  from the vendored tree, API through the adapter to the daemon); (3) rebrand; drop the reference's own
  sidebar under our shell; (4) bind operation by operation, fallthrough counted to zero; (5) freeze:
  `SURFACE_STATES` for every flow state, the journey through the wizard, retire the recreation.

## Gate

`check:seed-depth` (to be built with the first app's cut, in the M12.3 shape): per app, the
population of harvested reference flow states, adopted states, bound states and named-gap controls,
pinned EXACTLY; a harvested state with no adopted port, or an adopted state absent from
`SURFACE_STATES`, is red. It rides beside `check:dead-controls`, which now also probes the canonical
lanes (Work, Systems, Operations, Environments, Leases & Limits, …) that the registry never listed.

## Rules that do not bend

- Captures, screenshots and `/__apps/*` lanes are evidence; the adopted port is the product.
- No tenant data in product code; demo data lives only in the mirror's fixtures.
- Observe, do not disturb the live tenant.
- A lane may run ahead of its plane only with named gaps; the client never mints the missing truth.
