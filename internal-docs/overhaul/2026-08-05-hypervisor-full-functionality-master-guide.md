# Hypervisor Full-Functionality Master Guide — every surface operational

Goal: take every Hypervisor application surface from its current seed state to
operational — logic wired to UI — per canon, including Sessions and Settings.
Regime: post-overhaul light. Ordinary branches/PRs; per-PR bar = build + test +
lint + the standing surface rules (read truth · local UI state · existing
authority with receipts · disabled-named-gap for everything else; serve with no
test flags). No proof apparatus is rebuilt by this program.

Grounded in a three-lane audit (2026-08-05): canon requirements
(`core-clients-surfaces.md` 4,834 lines + owner docs), daemon capability
inventory (~663 routes), and UI wiring state (14 registered surfaces, 97-RPC
adapter, ~100 native readouts, 563-control census). Verified corrections to
prior beliefs: **Settings IS canonically owned** (core workspace `/settings`,
projection-only, writes-through-owners; the 2026-07-30 "ownerless" finding is
stale — the residue is a five-vs-six count drift in 5 canon locations and no
dedicated canon section). **Sessions is `/work/sessions`**, a typed Work view,
never a peer app; bare `/sessions` must die with a typed 410 (the daemon
already refuses it — `handle_retired_hypervisor_route`; it's the UI shell that
soft-404s and still advertises the dead route in tiles). **The legacy app
names are retired**: Approvals, Issues, Pipeline, Upgrade Assistant,
Connections, Missions-as-app are tool surfaces or Work views inside the twelve
owners.

## 1. The two ground trees

**Target (canon):** 12 owner applications — Studio, Automations, Ontology,
Data, Governance, Provenance, Evaluations, Improvement, Foundry, Packages,
Developer Workspace, Developer Console — plus substrate Environments and
Operations, conditional Embodied Systems (planned, nonlaunchable), and six
core workspaces (Home, Systems, Projects, Applications, Work, Settings) on 23
canonical routes. One product-surface compiler feeds nav/catalog/palette/
search; six-record registration family; ten independent state dimensions;
effectful tooling requires contract refs + authority posture + receipt
obligations; lifecycle strip on every capability detail page.

**Actual (estate):** a T1 SPA shell (29 vendor captures + 97-RPC adapter — 3
backing classes: daemon-projected, local-constant identity lies, app-local
prefs — plus 5 fixture-only RPCs), ~100 wired native `/__ioi/*` readouts, and
14 registered T3 surfaces named for the retired taxonomy (6 with governed
mutations, 8 read-only; 24 of 563 controls governed-receipted). Sessions
route absent; Settings = 20 capture panes, reads mostly daemon-backed, writes
partial, identity partly fabricated (`IDENTITY_REWRITES`). Ported-seed
preservation invariant + 6-step per-app cutover rule are in force
(`apps/hypervisor/ported-seed-preservation.v1.json`, `AGENTS.md`).

**Strategy: rehome, don't rebuild.** Every wired plane survives by moving into
its canonical owner; every rebuilt-parallel shell is forbidden by the seed
invariant. v2 cutover deletes legacy routes with typed 410s (ADR 0022), one
app at a time, per the existing cutover rule.

## 2. Wave 0 — shared plumbing (everything else stacks on this)

| W0 item | Content |
|---|---|
| W0.1 v2 shell + router | The 23 canonical routes as the shell's route table; legacy `/__ioi/*` kept serving until each app's cutover; typed-410 retirement per route at cutover. |
| W0.2 Product-surface compiler v1 | One projection feeding nav/catalog/palette/launch from registration records (daemon: `surface-descriptors`, `product-surface-projections`, `domain-apps` routes exist). Policy filtering before aggregation. Kills the three hand-maintained catalogs. |
| W0.3 Read client + authority client | Uniform read-projection fetch (the ~20 `/overview` + projections) and the authority-crossing client encoding the CapabilityLease flow (403 wallet challenge, 428 credential, receipt refs on completion). |
| W0.4 Event client on the M5 plane | UI subscriptions ride `/v1/event-streams` + `/v1/subscriptions` (durable, checkpointed, resumable); legacy per-resource SSE wrapped, not extended. |
| W0.5 Identity truth | Delete the adapter's local-constant identity (`GetOrganization`, `GetAccount`, policies, ToS) and `IDENTITY_REWRITES`; back by daemon identity/whoami/org routes or render honest absence. Kill the 5 fixture-only RPCs (Project/Insights/RunnerConfiguration) by wiring or by disabled-named-gap. |
| W0.6 Backend enablers (small routes, one PR each) | `GET /v1/hypervisor/sessions/overview`; unified approvals-inbox projection (folds the 4 disjoint approval systems); `GET /v1` capability index; scheduler read surface (`/v1/hypervisor/scheduler/status`). Central-router file is a merge hotspot — sequence these serially. |

## 3. Per-application plan (canon → assets → gaps)

Format: **owner — route — inherits (rehomed assets) — backend state — work**.

1. **Studio `/studio`** — inherits `designer` + `machinery` surfaces (worst
   ratio: 7/51 implemented). Backend: `state-machines`, ODK reads exist; no
   blueprint/canvas persistence plane. Work: typed-canvas read view over
   Systems/agents; draft blueprint objects (new daemon family
   `studio/blueprints` CRUD + promote-through-gates); Canvas stays inside
   Studio, never a peer app.
2. **Automations `/automations`** — inherits `monitors` + the Home
   automations redirect. Backend rich: automations CRUD/start/runs/webhooks +
   placement + warm pools; scheduler in-process. Work: wire spec/version list,
   trigger entrypoints, run history with GoalRun/Session refs (routes exist);
   step-family graph view over Workflow Compositor contracts; needs W0.6
   scheduler read surface; AutomationRun → result/Session/GoalRun lineage rows.
3. **Ontology `/ontology`** — inherits `schema` (deepest wired surface, 13
   governed controls) + `explorer` (read-only, currently degenerate "Loan"
   rows). Backend: ODK domain-ontologies/projections/mappings/views complete.
   Work: rehome both under `/ontology`; fix explorer's object-set reads
   (`materialized-object-sets` routes exist); enable the disabled
   proposal/branch plane through the authority client.
4. **Data `/data`** — inherits `pipeline` (8 receipted actions; 40 disabled
   controls = largest dead cluster) + `sources` (3 of 4 tabs empty). Backend:
   ODK transformation/materializing/connector-session routes complete;
   `data-sources` CRUD partial (no update/delete). Work: rehome; light up the
   40 via authority client where routes exist (deploy/scheduler plane defers
   to Automations); finish sources CRUD backend; consent-posture badges from
   policy-bound-data-views.
5. **Governance `/governance`** — inherits `approvals` surface. Backend:
   governance approval-requests, kill-switches, release-controls, cohorts,
   improvement-gates all exist; capability-leases + authority
   grants/posture/receipts exist. Work: the unified inbox (W0.6) as the
   Approvals tool; release/change cockpit facet (promotion/rollout/rollback/
   kill-switch/cohort views over existing routes); authority-scope and lease
   browser; `reviewer_ref` becomes a principal, not free text.
6. **Provenance `/provenance`** — inherits work-ledger/lineage/run-timeline/
   run-replay readouts (all wired T2). Backend: receipts read surfaces ×5
   families, replay routes, outcome-room replay/graph projections. Work:
   unify into one receipt-stream + lineage graph surface with the
   waterfall/detail-drawer contract (D6); work-first display rule (hashes only
   behind proof drilldowns).
7. **Evaluations `/evaluations`** — inherits `evalsuites` (has the estate's
   known receiptless-mutation defect — fix against the effectful-tooling
   gate). Backend: eval-suites CRUD exists; epochs/holdouts/challenges absent.
   Work: 12-section IA as read-first over suites + runs; file backend families
   (epochs, sealed-holdout custody, challenges) as the app's build-list;
   receipts on every mutation.
8. **Improvement `/improvement`** — inherits `changes`. Backend:
   improvement-proposals + approve/reject/apply/simulate, improvement-gates,
   intelligence graph/review-queue/outcome-mining exist. Work: agenda/campaign
   objects are backend gaps (file family); wire proposals inbox + what-if
   simulation views now; no "Self-improve" button, ever.
9. **Foundry `/foundry`** — inherits `models` surface + model-mount plane
   (45 routes!) + model-routes + foundry specs/run-plans + intelligence
   memory/skills. Work: platform IA (Discover/Build/Train/Evaluate/Optimize/
   Deploy/Govern) as read-first over the huge existing surface; wire
   probe/enable/select-default via authority client; training/dataset
   families largely exist under foundry+model-mount; learning-boundary badge
   is a projection, never ambient permission.
10. **Packages `/packages`** — nearest assets: `listings` surface (highest
    decorative ratio) + marketplace routes + worker-package-install-admissions.
    Backend gap: no package/release/install/recall registry — the biggest
    single backend build in the program (file: `packages/*` family with
    releases, installs, deprecation, revocation, recall + compiler hook so
    recall removes launches). Marketplace becomes the optional mode at
    `/packages/marketplace` over existing listing routes.
11. **Developer Workspace `/developer-workspace`** — inherits the wired
    workbench (`/details/:env`, EnvironmentService 14 RPCs, AgentService 10,
    terminals, editor-services/leases/targets). Work: rehome under the
    canonical route; adapter-connection-profile rule (editor = adapter
    target); wire editor-service lifecycle controls that exist server-side.
12. **Developer Console `/developer-console`** — backend rich (connectors,
    secrets, OAuth flows, MCP, api-tokens, SSO/SCIM/OIDC config, domain
    verifications), UI absent (only the BYOA connect button + `/__ioi/
    connections`). Work: registration-estate UI over existing routes:
    connectors + credential + invoke-test, MCP gateway tools, API tokens,
    conformance placeholder; owns integration *registrations*, never provider
    runtime (that's Environments/Operations).

**Substrate:** **Environments `/environments`** — env CRUD/lifecycle/logs/
ports/snapshots + provider accounts/candidates/placement/failover all exist;
UI = env readouts today; build the lifecycle cockpit read-first, actions via
authority client. **Operations `/operations`** — operations reads, storage
backends/archives/incidents, spend reconciliation, warm pools, autonomous-
systems projections exist; build the jobs/capacity/custody cockpit read-first.

**Embodied Systems** — reserved route only; nonlaunchable registration row in
the compiler; no UI work.

## 4. Sessions chapter (`/work/sessions` — a Work view, not an app)

Backend today: create/list/get/teardown/execute/events (+ ports/revoke);
"positive execution loop is Cut #2" per the daemon's own comment; the live
I/O plane is session-execution-bindings (input/stop/archive/restore/events)
plus managed-sessions + session-turns; no overview/lineage/transition routes.

1. `/work` shell with typed views: goals, sessions, rooms, queues, reviews,
   incidents, history (routes + subject_kind/subject_ref rows; policy filter
   before counts).
2. Sessions list = `/v1/hypervisor/sessions` + W0.6 overview; detail =
   D4 object fields + D5 view contract (transcript, step graph, tool/model
   calls, authority gates, receipts, replay availability) composed from
   session + execution-binding + thread + workrun reads; D7 WorkRun view; D8
   room-participant drilldown (claim/lease/heartbeat/spend/evidence — routes
   exist in the room-participation plane).
3. Lineage: file the backend gap (session lineage/fork/children projection)
   — the one first-class family with none of overview/transition/history.
4. Retirement: shell stops advertising `/__ioi/sessions` (tile + vendor
   sidebar tab); `/sessions` renders the typed 410 the daemon already emits.
5. Execution loop Cut #2 (turn loop on session-execution-bindings) is the
   product milestone that turns the view live; sequence after W0.4.

## 5. Settings chapter (`/settings` — core workspace, projection-only)

Canon: panes project canonical owner records; Settings persists only admitted
preferences + owner-backed administrative mutations; transient UI state stays
client-local. Today: 20 capture panes; reads mostly daemon-backed
(members/secrets/PATs/billing/SSO/SCIM/OIDC/service accounts); org identity +
policies + ToS are adapter constants; runners/integrations lists are local
lies; preferences backend is GET+PUT-by-id only.

1. Replace constant-backed panes with owner routes or honest absence (W0.5).
2. User pane set: connected apps (Developer Console records), memory/skill
   prefs (intelligence routes exist), delivery channels, BYOK/BYOA defaults.
3. Org pane set: connectors/service accounts, allowlists + provider policies,
   SSO/SCIM/retention (routes exist), learning-boundary defaults (projection
   + governed-upgrade-proposal on change), workspace defaults.
4. Backend: keep `preferences` for admitted preferences; add scope+schema
   listing so panes render generically; every administrative mutation routes
   to its owner and returns that owner's receipt.
5. File the canon nit: five-vs-six core-workspace count drift (5 locations)
   + missing dedicated Settings section — one-line canon PR.

## 6. Launch ladder

- **Wave 0** — plumbing W0.1–W0.6. Exit: v2 shell serves all 23 routes
  (bodies may be read-first), compiler feeds nav, identity honest.
- **Wave 1 (read-first launches)** — apps whose backends are rich today:
  Work+Sessions views, Provenance, Environments, Operations, Governance
  (reads + unified inbox), Ontology, Data, Automations, Foundry,
  Developer Workspace rehome. Exit per app: canonical route renders daemon
  truth end-to-end with honest empty/degraded states; zero fixture data.
- **Wave 2 (actions)** — authority-crossing controls via the lease client:
  Governance cockpit verbs, Data/Ontology mutations, Automations lifecycle,
  Foundry route/mount controls, Developer Console registrations, env/ops
  actions. Exit: every enabled control is receipted; everything else is
  disabled-with-named-gap; the 24 governed controls become hundreds only as
  fast as routes actually exist.
- **Wave 3 (backend builds + their UIs)** — Packages registry family (the
  big one), Studio blueprints, Evaluations epochs/holdouts/challenges,
  Improvement agendas/campaigns, session lineage, approvals-inbox if not in
  W0. Each lands backend-first, then UI in the same wave.
- **Wave 4 (cutover + execution loop)** — Sessions execution loop Cut #2;
  per-app legacy `/__ioi/*` retirement with typed 410s per the 6-step rule;
  delete the mock branches in `server.cjs`, the fixture API lane, and the
  second static copy (`product-ui/public`); Settings completion; the two
  remaining canon-file nits.

## 7. Standing rules for every PR in this program

Read truth or show honest absence — never fixture data presented as runtime
truth (the Home fallback-fixture rule generalizes: visible fixture source or
nothing). Local UI state stays local. Existing authority only, with receipts
— no effectful control without contract refs + authority posture + receipt
obligation; otherwise disabled with a named gap. One daemon-backed lane per
capability — no forked truth, no parallel shells (seed-preservation invariant
stands until each app's cutover). Serve with no test flags. The central
router file is a serialization point — backend-route PRs touching
`hypervisor-daemon.rs` don't parallelize.
