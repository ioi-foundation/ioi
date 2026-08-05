# Work — implementation brief

Canonical route: `/work` · Owner: core workspace Work (owns the Sessions view at `/work/sessions`)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted

All canon cites are `docs/architecture/components/hypervisor/core-clients-surfaces.md` unless
prefixed, and resolve against the blob at commit `21ae389fe` ("canon(C-1..C-4) + charter",
branch `overhaul/bring-to-life-charter`) — a master working tree that lags that commit will not
contain the C-1..C-4 blocks (verified: daemon + `apps/hypervisor/` bytes are identical between
`21ae389fe` and master `1ff32a1a3`; only the canon .md differs). Daemon cites are
`crates/node/src/bin/hypervisor-daemon.rs` (router) and
`crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs` (handlers). UI cites are under
`apps/hypervisor/`. Census cites (`census:`) are the 2026-07-30 inventory
(`internal-docs/audits/2026-07-30-hypervisor-surface-end-state-audit/inventory.v1.json`) and are
seed only; bytes win.

## 1. Canon digest

- Work is the unified core workspace for starting, supervising, inspecting, intervening in,
  reviewing, replaying, and resuming heterogeneous work — a policy-filtered read model, never a
  canonical `Work` object or one universal lifecycle (core-clients-surfaces.md:1675-1680;
  anti-pattern "Work = universal canonical status" :4761; object table row :3282).
- Eight typed views: Active, Goals, Sessions, Rooms, Queues, Reviews, Incidents, History
  (:1682-1691) on routes `/work` (= Active), `/work/goals`, `/work/sessions`, `/work/rooms`,
  `/work/queues`, `/work/reviews`, `/work/incidents`, `/work/history` (:1711-1720). Route-ledger
  rule: "typed views only; Sessions is `/work/sessions`" (:889).
- Every row declares typed `subject_kind` + canonical `subject_ref` and deep-links to the
  type-specific owner; Work derives display facets but never writes one common status back; policy
  filtering occurs BEFORE search, counts, recents, aggregation, and caching (:1693-1697). Row and
  facet contracts: `HypervisorWorkSubjectProjection` (:4325-4344, `read_model_only: true`) and
  `HypervisorWorkFacetProjection` (:4346-4369 — a policy-filtered cross-owner pointer only).
- No `/sessions` or `/missions` alias routes; retired paths are deleted, not aliased (ADR 0022
  Decision 2) (:1722-1725, :877-879). Typed details resolve beneath views:
  `/work/queues/{work_queue_id}`, `/work/reviews/{facet_projection_id}`,
  `/work/incidents/{facet_projection_id}`; a review/incident detail is a read-only facet that
  deep-links to its owner and mints no generic subject (:1726-1731; conformance :4589-4592).
- Work registers as a core workspace, not an application; Sessions remains a typed execution
  object and Work view, never a peer application registration (:4545-4548). Registration is
  projection-only + writes-through-owners (`HypervisorCoreWorkspaceRegistration` :3468-3478);
  route resolution fails typed, `accepts_retired_route_spellings: false` (:3480-3487).
- Sessions canon: bounded governed interactive|headless|supervisory execution/control contexts
  (:2663-2667); kinds are mechanical execution contexts, workloads are typed subject attachments
  (:2683-2686). The C-1..C-4 spine:
  - C-1 `subject_attachments[]` (owner-registered `subject_kind` + `subject_ref` +
    `attachment_role`) is the ONLY way a Session names the work it serves; the platform never
    names an application family as a dedicated field (:2692-2696, :3971-3984).
  - C-2 `foundry_eval_training` is retired from `session_kind` (:3960-3968).
  - C-3 thread/thread-fork/managed-session/session-launch-recipe/harness-session-binding records
    are ONE daemon-internal execution substrate; product surfaces compose them by read only; no
    surface may treat the thread plane as a second public spine (:3320-3328; ADR 0031 :3311-3318).
  - C-4 any UI/daemon bytes still carrying named app fields migrate at the PR that touches them
    (sites recorded in section 4).
- The master guide's D-labels resolve to these canon blocks (the guide is seed, these are the
  authority): D4 = the "A Session binds" field list (:2688-2704, minimal object :3955-4010);
  D5 = the Session view contract — transcript, step graph, tool/model calls, terminal/browser
  activity, authority gates, privacy posture, provider/environment state, logs, traces, receipts,
  state roots, replay availability, promotion options (:2706-2710); D6 = one coherent
  trace/replay path — waterfall of spans + detail drawer, proof as drilldown not default
  (:2712-2718); D7 = the stable `HypervisorWorkRun` view (:2720-2727, object :4222-4284);
  D8 = OutcomeRoom participant/claim/attempt drilldown — claim, lease, heartbeat/wake, spend,
  evidence, verification, blocker, cancellation/quarantine projections, never only transcript
  tokens (:2729-2733).
- Work / Room detail is graph-first (objective/frontier/participants/claims/evidence/lineage/
  replay); live feed or chat is a social projection over the graph (:3330-3343). Mission is
  retired as an owner: optional label/preset resolving to exactly one typed GoalRun or OutcomeRoom
  subject, no independent id/lifecycle/receipts (:3343-3352); new writes must not create
  `HypervisorMission` or `mission://` (:4638; anti-pattern :4766).
- Relationship model: GoalRun → zero or more Sessions; Session → zero or more WorkRuns; WorkRun →
  results/evidence/receipts (:3295-3309). A direct Session may exist without a GoalRun (:3305-3307).
- New Session is a one-click action at `/work/new-session` (:885) and may create only a bounded
  Session (:1478-1482; conformance :4549-4551; anti-pattern :4765). Composer identity and the
  separate Activate Goal affordance: :1523-1543 (advertised from Home — see `home.md`).
- Supporting Work objects: `HypervisorWorkQueue` (:4175-4190), `HypervisorWorkItem` (:4192-4220),
  `HypervisorWorkRunConversationProjection` (:4286-4298), `HypervisorWorkRunIntegrationStatus`
  (:4300-4310), `HypervisorWorkRunReviewState` (:4312-4323), `HypervisorOutcomeRoomProjection`
  (:4376-4388). Note: WorkItem/WorkRun legitimately carry `goal_run_ref`/`outcome_room_ref`/
  `automation_run_ref` (:4197-4199, :4227-4231) — the C-1 retirement is of named app fields on
  the SESSION object, not on WorkItem/WorkRun contracts.
- Implementation status per canon: target contract — "the existing Sessions root, jobs, GoalRun
  views, automation-run views, and issue/blocker aggregates are migration inputs" (:1704-1706).

## 2. Schema map

| Canon object / contract | Registry / canon block | Daemon route(s) today | Gap wave |
|---|---|---|---|
| HypervisorCoreWorkspaceRegistration (work row) | canon :3468-3478; served in core taxonomy | `/v1/hypervisor/core-taxonomy` hypervisor-daemon.rs:1056; workspace row w/ `/work` documented daemon-runtime/api.md:1018 | — |
| HypervisorSession | canon :3955-4010; NO schema in `docs/architecture/_meta/schemas/` (no `hypervisor-session.*.schema.json`) | `/v1/hypervisor/sessions` GET+POST :3190; `:id/events` :3195; `:id/execute` :3199; `:id/ports/revoke` :3203; `:id` GET+DELETE :3207 | schema-registry gap (W3, one-file PR) |
| Sessions overview | `ioi.hypervisor.sessions-overview.v1` | **LANDED W0.6**: `GET /v1/hypervisor/sessions/overview` hypervisor-daemon.rs:3214 (handler lifecycle_routes.rs:18034) — owner-filtered before counts; by_lifecycle_state/by_project + `subject_attachments` rollup (by_subject_kind/by_attachment_role) + newest refs; kind/mode counts named absent (not recorded on Cut #1 records) | — |
| Session lineage / fork / children / transition / history | none | route-missing (grep: no `sessions/:id/{lineage,fork,children,transition,history}`) | **W3** |
| `subject_attachments` on session records | canon :3971-3984 | **INTRODUCED W0.6**: session record + create/initial-input projections carry `subject_attachments: []` (honest empty — create accepts no attachment inputs yet); the three retired named-field sites (`goal_run_ref`/`goal_run_activation_ref` null non-grants) are migrated to the attachment model. Remaining W3 scope: attachment inputs + list/get filters | **W3** (attachment inputs + filters) |
| SessionExecutionBinding (session/env/thread/work_run composition) | daemon comment "T7-2" hypervisor-daemon.rs:2878 | create :2880; get :2884; events :2888; input :2892; stop :2896; archive :2900; restore :2904 | — |
| Session launch recipe admission | `hypervisor-session-launch-recipe-admission.v1.schema.json`; canon :2957-2973 | POST `/v1/hypervisor/session-launch-recipe-admissions` :1084 | — |
| HarnessSessionBinding (+admission, readiness, spawn, terminal-attach) | `harness-session-binding{,-admission,-readiness,-spawn,-terminal-attach}` schemas; canon :2905-3060 | binding-admissions :1088; terminal-attachments :1120; harness-bindings :1232 | — |
| Thread substrate (read-compose only, C-3) | canon :3320-3328 | `/v1/threads` + `:id`/turns/usage/approvals/snapshots/artifacts family :783-1041; managed-sessions GET :961, control POST :965; session-turns POST :770 | — |
| HypervisorWorkRun | canon :4222-4284 | workruns GET+POST :1164; `:id` :1169; `:id/execute` :1174 | — |
| HypervisorWorkQueue / HypervisorWorkItem | canon :4175-4220 | route-missing (`/v1/hypervisor/resource/work-queue` :2775 is the resource-scheduler read, NOT this object) | **W3** |
| HypervisorWorkSubjectProjection (unified Work rows) | canon :4325-4344 | route-missing as one projection; W1 composes per-family list reads client-side | **W3** (optional unified projection) |
| HypervisorWorkFacetProjection (reviews/incidents) | canon :4346-4369 | route-missing as such; nearest reads: incidents :1195, recovery-attempts :1199, approval-requests :1963, thread workspace-change-reviews :969, intelligence review-queue :1729 | **W3** |
| GoalRun (Goals view subjects) | `goal-run.v1.schema.json` + activation schemas | goal-runs :1821; `:id` :1826; results :1830; outcome-deltas :1834; start :1838; reconcile :1842; lifecycle-recovery :1846; events :1850; activations :1809-1817 | — |
| OutcomeRoom (Rooms view subjects) | `outcome-room.v2.schema.json`, `collaborative-work-graph.v1` | outcome-rooms :2383; overview :2388; `:id` :2392; transition :2396; lifecycle :2402; attach/detach-goal-run :2406/:2410; replay :2414; collaborative-work-graph :2418; discussion :2422; product-projection :2426 | — |
| Room participation plane (D8) | `room-participant-lease-envelope.v1`, `work-claim-lease.v3`, `work-frontier-item.v3`, `attempt.v3`, `work-result.v3` | participation-requests :2430-2443; participant-leases :2447-2456; work-frontier-items :2459-2474; work-claim-leases :2476-2491; resource-offers :2493; capability-offers :2510; eligibility-matches :2527; attempts :2540-2554; findings :2557-2571; verifier-challenges :2574-2587; work-results :2328-2337 | — (no heartbeat/spend endpoints — see Corrections) |
| AutomationRun (Active/History facets) | canon :3283-3285 | automations :1268; `:id/runs` :1284 | — |
| History sources | `work-lifecycle-record.v1` | work-ledger :1309; work-results :2328 + overview :2333 | — |
| Incident sources | — | incidents :1195; recovery-attempts :1199; failover runs :2630-2634 | — |
| Event consumption | M5 plane | `/v1/event-streams/...` :2350-2360; `/v1/subscriptions/...` :2363-2379 (per-resource SSE `:id/events` wrapped, not extended) | — |
| Retired-route refusal | `ioi.hypervisor.route_retirement_refusal.v1` | `/sessions`, `/missions`, `/__ioi/*path` → typed 410 :610-612; handler lifecycle_routes.rs:6451-6478 already names `canonical_replacement_route` `/work/sessions` and `/work` (:6453-6456) | — |

Backend state note: the session surface is "Lane A, Cut #1: real workspace provisioning +
environment-status/diff/readiness/receipt surfacing + fail-closed honest gates. The positive
execution loop is Cut #2" — the daemon's own comment, hypervisor-daemon.rs:3186-3188. Session
create accepts `initial_input` (validated, ≤ max bytes) + `project_ref` + optional `session_ref`;
owner is daemon-resolved and client-supplied `owner_ref` is rejected
(lifecycle_routes.rs:11166-11225). List rows: session_ref, project_ref, environment_ref,
lifecycle_state, workspace_root, editor_target_ref, slim harness_binding, latest_receipt_refs,
created_at — owner-filtered before count/truncation (lifecycle_routes.rs:17849-17890); no
partial list on registry failure (:17838-17847).

## 3. UI seed map

- **`/work` and all 8 typed views: absent.** census: `/work`, `/work/sessions`,
  `/work/new-session` all `resolves: false`; no `/work` handler exists in
  `scripts/serve-product-ui.mjs` or the augmentation modules (grep). The v2 shell (W0.1) is the
  precondition.
- **Bare `/sessions`:** the daemon already refuses it typed (hypervisor-daemon.rs:610;
  lifecycle_routes.rs:6451-6478). census: the shell rail's "Sessions (rail item)" destination
  `/sessions` renders the SPA 404 page (`renders_404_page: true`, finding "rail item whose
  destination renders the SPA 404 page"). The rail item could not be pinned to a greppable
  literal in the minified vendor captures (`product-ui/owned/public/static/assets/`) — it is
  vendor-runtime-rendered; retirement lands via shell wiring, not a capture edit.
- **Sessions root readout (wired, read-only):** `/__ioi/sessions` → `renderSessionsRoot`
  (serve-product-ui.mjs:1424-1447; route :8659-8667) reads `/v1/hypervisor/sessions` +
  `/v1/hypervisor/environments-summary`; per-lifecycle-state chips, admitted-harness-binding
  column ("selection is session truth recorded at create, never UI state" :1443), links to
  `/workspaces/:env` (workbench), `/details/:env` (vendor session detail), `/__ioi/run-timeline`.
  census: 157 controls, 0 disabled.
- **Session detail today:** the vendor workbench `/details/:env` plus the injected IOI-native
  cockpit panel + owned Run Timeline, which deliberately replaces the seeded transcript in-pane
  (augmentation/00-core.js:1-15) — WorkRun patch branch, model-driven turns, scoped terminal,
  receipts already surface there (00-core.js:3-7). This is the D5/D7 seed to rehome, not rebuild.
- **`missions` T3 surface (absorbed → Work / Rooms):** registered read_only_by_contract at
  `/__ioi/missions` (scripts/surface-registry.mjs:50); module `surfaces/missions/index.mjs` reads
  13 goal-orchestration route families (goal-runs, outcome-rooms, participation-requests,
  participant-leases, work-frontier-items, work-claim-leases, resource-offers, capability-offers,
  eligibility-matches, attempts, findings, verifier-challenges, work-results — grep of the
  module). census: 10 controls, 6 implemented, 4 daemon_read, 0 governed. Protected seed
  (`ported-seed-preservation.v1.json` protected_routes: slug `jobs`, `/__ioi/missions`,
  substrate_bound).
- **`incidents` (Issues) T3 surface (absorbed → Work / Incidents):** registered at
  `/__ioi/missions/incidents` (surface-registry.mjs:56); handler reads `/v1/hypervisor/operations`
  + `/v1/goal-orchestration/goal-runs` and derives a run-failure + goal-blocker inbox with
  open/closed/all lanes (serve-product-ui.mjs:8791-8801, lanes :5071, global rail :5130).
  Protected seed (protected_routes: `daemon_wired`).
- **Advertisement sites to retire (shell stops advertising `/__ioi/sessions`):** estate tile
  "Missions … sessions root live" → `/__ioi/sessions` (augmentation/30-shell.js:11); Open
  Application slot wiring maps `/__ioi/sessions` to "Missions" (60-shell-wiring.js:35,39); Home
  explorer "Sessions →" link (40-home-explorer.js:303); search-palette Sessions group hrefs
  (serve-product-ui.mjs:8630); build rows openUrl (serve-product-ui.mjs:7660).
- **Adjacent wired readouts feeding views:** `/__ioi/run-timeline` (10-run-timeline.js),
  `/__ioi/work-ledger`, `/__ioi/lineage`, `/__apps/jobs` + `/__apps/incidents` rebinds
  (serve-product-ui.mjs:1443). census T2: work-ledger 42 controls, run-timeline 66, lineage 21.

### Corrections vs v0

- v0 said the `/work` shell has "typed views: goals, sessions, rooms, queues, reviews, incidents,
  history" — bytes show canon defines EIGHT views: `Work / Active` is the `/work` root view and
  is part of the contract (core-clients-surfaces.md:1682-1691, :1712); v0 omitted Active.
- v0 said the D8 drilldown routes "exist in the room-participation plane" for
  "claim/lease/heartbeat/spend/evidence" — bytes: lease/claim/frontier/attempt/finding/challenge
  route families exist (hypervisor-daemon.rs:2430-2587) but there is NO heartbeat/wake or spend
  endpoint (grep); heartbeat/spend are record fields/projections to read off leases and
  participation records, not routes. The drilldown composes what exists; anything else is a named
  gap.
- v0 said bare `/sessions` "renders the typed 410 the daemon already emits" as future work —
  bytes show the daemon refusal ALREADY carries the forward map:
  `canonical_replacement_route: "/work/sessions"` for `/sessions` and `"/work"` for `/missions`
  (lifecycle_routes.rs:6453-6456); the UI only needs to stop swallowing it into the SPA 404.
- census listed 14 registered T3 surfaces implying per-slug module dirs — bytes: all 14 register
  in scripts/surface-registry.mjs:50-63, but only 6 have extracted `surfaces/<slug>/` module dirs
  (approvals, missions, object-explorer, ontology-manager, pipeline, sources — ls); the other 8
  (incl. `incidents`) bind implementations inside serve-product-ui.mjs.
- v0's "no overview/lineage/transition routes" — confirmed for `/v1/hypervisor/sessions`; the
  overview *pattern* is already daemon-idiomatic elsewhere (odk connector-sessions :1547,
  work-results :2333, outcome-rooms :2388), so W0.6 is a pattern-conformant small route, not a
  new invention.

## 4. Schema→UI binding table

Reads use the W0.3 read-projection client; authority-crossing actions use the CapabilityLease
client (403 wallet challenge → 428 credential → receipt refs on completion). Session-serving
elements bind through `subject_attachments` (C-1) — never a named app field.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| `/work` shell + 8 view tabs + breadcrumb | HypervisorCoreWorkspaceRegistration (:3468-3478) via core-taxonomy :1056 + compiler (W0.2) | absent | wired-read (W0.1) |
| Work/Active rows (cross-kind) | subject rows :4325-4344 composed from sessions :3190 + goal-runs :1821 + automations/:id/runs :1284 + workruns :1164 + outcome-rooms :2383; policy filter before counts (:1696-1697; owner-filter precedent lifecycle_routes.rs:17849-17857) | absent | wired-read |
| Work/Goals list + detail | goal-runs family :1821-1852 + activations :1809 | absent (missions surface reads these at `/__ioi/missions`) | wired-read (rehome) |
| Work/Sessions list | sessions :3190 + overview (W0.6) | wired at `/__ioi/sessions` (renderSessionsRoot :1424) | wired-read (rehome) |
| Session detail — D4 object fields | canon :2688-2704 / :3955-4010; session GET :3207 | partial (vendor `/details/:env` + cockpit panel 00-core.js) | wired-read |
| Session detail — D5 view (transcript, step graph, tool/model calls, gates, receipts, replay) | :2706-2710 composed from execution-binding GET/events :2884/:2888 + thread GET :787 + turns + workruns :1169 — read-only composition per C-3 (:3320-3328) | partial (Run Timeline iframe replaces transcript, 00-core.js:9-13) | wired-read (events via W0.4 event client; `:id/events` SSE wrapped) |
| Session detail — D6 waterfall + detail drawer | :2712-2718; run-replay/work-ledger reads :1309, :2328 | wired as separate readouts (`/__ioi/run-timeline`, `/__ioi/work-ledger`) | wired-read (compose; proof behind drilldown) |
| Session detail — subject chips/filter | `subject_attachments` :3971-3984 | field present since W0.6 (records + projections carry `subject_attachments: []`; the three C-4 named-field sites are MIGRATED — no `goal_run_ref`/`goal_run_activation_ref` remains in session code); attachments stay empty until W3 adds attachment inputs | disabled-named-gap → wired-read after W3 C-1 row (attachment inputs + filters) |
| D7 WorkRun view (phase, harness, usage, conversation, review, delivery) | :2720-2727 / :4222-4284; workruns :1164-1176 | partial (cockpit panel WorkRun pane) | wired-read |
| WorkRun execute control | workruns/:id/execute :1174 | wired in cockpit panel | wired-action-receipted (lease client) |
| Work/Rooms list + graph-first room detail | outcome-rooms :2383-2427 (graph :2418, discussion :2422, replay :2414) | wired read-only at `/__ioi/missions` (surface-registry.mjs:50) | wired-read (rehome) |
| D8 participant drilldown (claim/lease/attempt/finding/challenge/evidence) | participation plane :2430-2587 + work-results :2328 | wired read-only at `/__ioi/missions` | wired-read; heartbeat/spend panes disabled-named-gap (no routes) |
| Room verbs (transition, attach/detach goal-run) | :2396-2410 | absent in UI (read_only_by_contract registration) | wired-action-receipted (W2, lease client) |
| Work/Queues list + `/work/queues/{id}` | HypervisorWorkQueue :4175-4190 | route-missing; `/__ioi/…` has no queue UI (resource/work-queue :2775 is scheduler truth, label honestly if shown) | disabled-named-gap → W3 |
| Work/Reviews + `/work/reviews/{facet_projection_id}` | facet projection :4346-4369; nearest reads approval-requests :1963, workspace-change-reviews :969, review-queue :1729 | absent as a view | wired-read (composed, W1) → unified facet projection W3 |
| Work/Incidents + `/work/incidents/{facet_projection_id}` | facet projection :4346-4369; incidents :1195 + recovery-attempts :1199 + failover :2630 | wired derived inbox at `/__ioi/missions/incidents` (serve :8791-8801) | wired-read (rehome the derivation) |
| Work/History | work-ledger :1309 + work-results :2328/:2333 | wired readouts (`/__ioi/work-ledger`) | wired-read (rehome) |
| New Session action (`/work/new-session`) | :885, :1478-1482; POST sessions :3190 (provision receipt lifecycle_routes.rs:9915) | composer lives at `/ai#new-session` (see home.md) | wired-action-receipted (route rehome W0.1/W2) |
| Session execute / teardown / ports-revoke | :3199 / :3207 DELETE / :3203 | wired via cockpit/adapter lanes | wired-action-receipted (Cut #1 gates; positive loop = Cut #2, W4) |
| Execution-binding input/stop/archive/restore | :2892-2905 | not surfaced | wired-action-receipted (W2; live turn loop W4) |
| Session lineage pane | none (route-missing) | absent | disabled-named-gap → W3 family |
| Bare `/sessions` + `/missions` in shell | refusal contract lifecycle_routes.rs:6451-6478 | shell soft-404s (census) | render the daemon's typed 410 + replacement link; then delete rail/tile ads (W4) |
| Tile/palette ads of `/__ioi/sessions` | 30-shell.js:11, 60-shell-wiring.js:35+:39, 40-home-explorer.js:303, serve :8630, :7660 | live | delete (W4, per-app cutover rule) |

## 5. Ordered PR list

1. **W0.6 — DONE 2026-08-05** — `GET /v1/hypervisor/sessions/overview` landed
   (hypervisor-daemon.rs:3214; handler lifecycle_routes.rs:18034): counts by
   lifecycle_state/project + subject-attachment rollup + newest refs, owner-filtered before
   counts; kind/mode counts named absent (not on Cut #1 records). Same PR introduced
   `subject_attachments` on session records and migrated the three named-field sites.
2. **W0.1** — v2 shell `/work` + the 8 typed-view routes render read-first skeletons with honest
   empty/degraded states; breadcrumb + back-stack identity per :1724-1725.
3. **W1** — Work/Sessions list rehomed from `renderSessionsRoot` semantics onto the read client
   (sessions + overview); zero fixture data.
4. **W1** — Session detail read composition: D4 fields + D5 view + D6 waterfall from session GET
   + execution-binding GET/events + thread GET + workrun GET (read-only, C-3); events through the
   W0.4 event client, legacy `:id/events` SSE wrapped.
5. **W1** — Work/Goals + Work/Rooms + D8 participant drilldown: rehome the `missions` surface's
   13 goal-orchestration reads under `/work/goals` and `/work/rooms` (seed-preservation: adopt
   the module, don't rebuild).
6. **W1** — Work/Incidents: rehome the derived run-failure + goal-blocker inbox
   (serve :8791-8801) under `/work/incidents`; Work/History over work-ledger + work-results;
   Work/Reviews composed read (approval-requests + workspace-change-reviews + review-queue);
   Work/Queues renders disabled-named-gap.
7. **W2** — Session actions through the CapabilityLease client: create (from `/work/new-session`),
   execute, teardown, ports-revoke; execution-binding input/stop/archive/restore; room
   transition/attach/detach verbs. Every enabled control receipted; everything else
   disabled-named-gap.
8. **W3** — C-1 backend, remaining scope after W0.6: attachment INPUTS (owner-registered
   subject_kind/subject_ref/attachment_role admission on create/attach) + list/get filters.
   Already landed in W0.6: the field on records + all three projections, the overview rollup,
   and the migration of the three named-field sites (no `goal_run_ref`/`goal_run_activation_ref`
   remains in session code). Then Work row subject chips go live.
9. **W3** — Session lineage family (lineage/fork/children projection routes + the lineage pane);
   register the missing `hypervisor-session` schema in `_meta/schemas/`.
10. **W3** — HypervisorWorkQueue/WorkItem backend family ONLY if an implemented contract pulls
    it (queue standing rule); otherwise the named gap stands. Optional unified
    work-subject/facet projection routes.
11. **W4** — Execution loop Cut #2: positive turn loop on session-execution-bindings
    (hypervisor-daemon.rs:3186-3188), after W0.4; the Sessions view turns live.
12. **W4** — Retirement per the 6-step cutover rule (AGENTS.md, ported-seed-preservation):
    shell renders the typed 410 for `/sessions`+`/missions`; delete the `/__ioi/sessions`
    advertisements (30-shell.js:11, 60-shell-wiring.js:35/:39, 40-home-explorer.js:303,
    serve :8630/:7660); retire `/__ioi/sessions`, `/__ioi/missions`,
    `/__ioi/missions/incidents` with typed refusals + no-fallback proof.
