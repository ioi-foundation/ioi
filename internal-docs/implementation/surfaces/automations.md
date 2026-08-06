# Automations — implementation brief

Canonical route: `/automations` · Owner: Automations (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

Canon cites are `docs/architecture/components/hypervisor/core-clients-surfaces.md` unless
prefixed. Daemon cites: `crates/node/src/bin/hypervisor-daemon.rs` (router) or
`hypervisor_daemon_routes/*.rs`. UI cites: `apps/hypervisor/...`. `census:` cites:
`internal-docs/audits/2026-07-30-hypervisor-surface-end-state-audit/inventory.v1.json`
(2026-07-30; spot-verified against the live tree where load-bearing).

## 1. Canon digest

- Automations owns reusable workflow, trigger, schedule, monitor, API/service, approval-flow,
  queue, and process-graph **definitions plus their activations**; core grammar =
  condition-over-object-set → governed effect (:1308-1311). Route `/automations`; shell
  placement and application identity resolve to the same registration (:893).
- It is the reusable-standing-behavior surface over Hypervisor Core and the Workflow
  Compositor (:2300-2301) — for work the user wants to save, run again, trigger, schedule,
  publish as an internal service, or expose through an API/webhook (:2303-2304).
- May own product projections for: specs and versions; trigger/schedule/webhook/queue/API
  entrypoints; workflow/service graphs backed by Workflow Compositor contracts; review points
  and approval gates; change plans, rollout gates, canary, recall, remediation;
  **AutomationRun history with resulting GoalRun/Session/WorkRun refs, receipt views, replay
  links**; service templates; Canvas editor state (:2306-2317). Graph node vocabulary
  :2319-2336.
- Does NOT own: execution semantics; wallet authority or secret release; Agentgres truth,
  receipts, archive refs; model private reasoning; Foundry training; the selected harness's
  internal step loop (:2338-2345). Room participation / shared-frontier admission stay
  room-level contracts (:2390-2396).
- Objects: durable reusable `AutomationSpec`; one activation = `AutomationRun`;
  scope enablement = exact `AutomationInstallationBinding` (:2361-2381, :3283-3285). A run may
  finish directly, request bounded Sessions/WorkRuns, explicitly create/link GoalRuns, or
  contribute typed room work; it never becomes a GoalRun by being long-running (:2362-2365).
  Relationship model :3296-3303; an AutomationRun may finish without a GoalRun and, with no
  managed execution, without a Session (:3307-3309).
- Modes: manual/scheduled/event-webhook/PR-issue/monitor/approval-flow/service-API/
  queue-worker/marketplace-recipe (:2347-2359). Durable automations must not silently
  duplicate an existing name/project trigger match (:2408-2413).
- Step families: `agent`, `task`, `approval`, `pull_request`, `report`, `deployment`,
  `remediation`, `webhook/API`; agent resolves through HarnessProfile/adapter; task through
  daemon-owned env task execution; a PR step is a delivery contract, not proof; **every
  consequential step emits receipts and Agentgres-backed run history** (:2415-2420).
- Canvas: default home for durable workflows/services is Automations (:2427-2428);
  `HypervisorCanvasView.owner_surface` includes `automations` (:3944-3953); Canvas never owns
  execution/authority/semantics (:2443-2445). Tool placement: Process Graphs (legacy
  Machinery) → Automations / Process Graphs; Monitors (legacy Automate) → Automations /
  Monitors (:1416-1417).
- Minimal objects: `HypervisorAutomationSpec` (:3856-3883, revisioned + content-hashed, kind
  enum :3863-3866, WorkflowTemplate refs :3867-3869, registry_status :3883);
  `HypervisorAutomationInstallationBinding` (:3885-3897);
  `HypervisorAutomationRun` (:3899-3942) — carries `goal_run_refs[]`, `work_item_refs[]`,
  `work_run_refs[]`, **`session_refs[]`** (:3916-3924), resolution receipt (:3912), status
  enum (:3940-3942). `WorkflowTemplateEnvelope` is compositor-owned, immutable,
  content-addressed; a template never runs itself (:2588-2591).
- C-1..C-4 layering (implement, never re-decide): a session serving an automation names it via
  `subject_attachments` with owner-registered `subject_kind: automation_run` +
  `attachment_role` — the platform never names an app family as a dedicated session field
  (:3971-3984, :2683-2687). New Session may carry an optional typed AutomationRun attachment
  (:1490). Lineage FROM the run side uses the run's own `session_refs[]`/`goal_run_refs[]`
  (:3916-3924) plus receipts — both directions are reads, never a named session field.

## 2. Schema map

| Canon object / contract | Canon block / registry | Daemon route today | Wave |
| --- | --- | --- | --- |
| HypervisorAutomationSpec | :3856-3883; registry: none — daemon persists ad-hoc `ioi.hypervisor.automation-workflow.v1` (orchestration_routes.rs:193) | `GET/POST /v1/hypervisor/automations` (hypervisor-daemon.rs:1268-1271); `GET/PATCH/DELETE /:id` (:1273-1277). Flat mutable record: project_ref required (orchestration_routes.rs:160-169), trigger/steps/limits/schedule_spec/agent+harness+model config (:192-243); **no revisions, no content_hash, no registry_status** | wired; revisioning gap → W3 |
| AutomationInstallationBinding | :3885-3897 | **route-missing** — no binding plane; `project_ref` on the spec is the only scope | **W3** |
| HypervisorAutomationRun | :3899-3942 | executions: `POST /:id/start` (:1279-1282), `GET/POST /:id/runs` (:1284-1288), `GET /v1/hypervisor/automation-executions/:id` + `/cancel` (:2076-2084). Record `ioi.hypervisor.automation-execution.v1` carries `environment_id`, `step_results`, counts (orchestration_routes.rs:1171-1176) — **no session/goal/work refs, no resolution receipt** | wired; lineage fields → W3 |
| Webhook entrypoint + audit | :2309, :2352 | `POST /:id/webhook` (:1291-1293, own-token auth, gate-exempt — orchestration_routes.rs:57), `POST /:id/webhook-rotate` (:1295-1297, plaintext token returned once — orchestration_routes.rs:236-252), `GET /:id/webhook-events` (:1299-1301; receipted `webhook-trigger-events` rows with `receipt_id`) | wired |
| Schedule plane | :2309, scheduler mode :2111 | `schedule_spec` on the spec + **in-process scheduler**: `tokio::spawn(automation_scheduler(...))` (hypervisor-daemon.rs:3481-3486), 15s tick (:4207, :4430-4437), fires due automations through the manual-run path, never fires on create (:4440-4470); `GET /v1/hypervisor/cron-preview` (:1304-1306) | wired |
| Scheduler read surface | `ioi.hypervisor.scheduler-status.v1` / `ioi.hypervisor.scheduler-heartbeat.v1` | schedule posture: `GET /v1/hypervisor/operations` (records-derived, unchanged). **LANDED W0.6** — liveness: `GET /v1/hypervisor/scheduler/status` hypervisor-daemon.rs:1323 (handler orchestration_routes.rs:408) reads the loop-derived tick heartbeat the scheduler now persists each tick (`scheduler-heartbeats/automation-scheduler`: tick_seq, last_tick_at, scheduled_active, fired_dispatches, misfire_skips) with `live`/`stale`/`no_heartbeat_recorded` derived from heartbeat age vs the 15s interval, plus the loop's fixed catch-up/misfire posture; the schedule projection is NOT duplicated — the route points at `/operations` | — |
| Run/webhook proof stream | :2314-2315 | `GET /v1/hypervisor/work-ledger` (:1309-1311) — unified runs+webhook receipts with state_root; run timeline refs `/__ioi/run-timeline/{exec}` (orchestration_routes.rs:475) | wired |
| WorkflowTemplateEnvelope / step-family graph | :2588-2591; registry `workflow-template.v1.schema.json` (`schema://ioi/foundations/workflow-template/v1`, architecture-contract-registry.v1.json) | **route-missing** — no workflow-template family; the spec stores an opaque `workflow_graph_ref` (orchestration_routes.rs:206) | **W3** — template read/derive family + graph view |
| Step families beyond agent/task | :2415-2420 | executor implements `agent` (agentops conversation), `command`, `proposal` only (orchestration_routes.rs:1236-1330) | **W3** — `approval`/`pull_request`/`report`/`deployment`/`remediation`/`webhook` step kinds over existing owner planes |
| Monitor grammar (condition-over-object-set → effect) | :1311, :2354, :1417 | **route-missing** — trigger kinds are manual/schedule/webhook only (create default orchestration_routes.rs:172-186; census monitors missing-authority); no object-set/threshold/metric trigger authority. Object sets themselves exist: `/v1/hypervisor/odk/materialized-object-sets` (:1580) | **W3** — object-set trigger family |
| Process-graph definitions (ex-Machinery) | :1416; process-graph defs owned here :1308-1311 | `/v1/hypervisor/state-machines{,/overview,/:id}` (:1939-1953) — **definitions only by explicit design**: "NO run/step/execution, no scheduling, and no automation binding here — that is a later authority-crossing cut" (:1935-1938; state_machine_routes.rs:417) | wired read; **W3** — run/step/bind family (activations are canon-owned here) |
| AutomationRun→Session lineage | C-1..C-4 (:3971-3984, :3916-3924) | **route-missing** — `subject_attachments` appears nowhere in daemon bin code (grep clean); executions carry `environment_id` only; agent steps run agentops conversations, not HypervisorSessions (orchestration_routes.rs:1237-1260) | **W3** — lineage build (see §4 row) |
| Warm pools | orchestration/scale substrate (router comment :1266) | `GET/POST /v1/hypervisor/warm-pools`, `POST /:id/claim` (:2674-2681) | wired (Operations-facing projection; link only) |
| Placement | — | `/v1/hypervisor/placement/{resolve,metrics,venues,venue-policy,preview,decisions[,/:id]}` (:2591-2620) | wired (surface as run-placement facet, read) |
| Event plane | W0.4 rule | `/v1/event-streams` + `/v1/subscriptions` (:2350-2372); the contract already fixtures an `automation-scheduler` owner namespace with `schedule.fired` / `trigger.suppressed` classes (docs/architecture/_meta/schemas/fixtures/event-stream-v1/positive-automation-scheduler-namespace.json) | W1/W2 consumption |
| Automation affinities (intelligence, read-adjacent) | — | `/v1/hypervisor/automation-affinities[/:id]` (:1677-1686) | wired read (projection band only; intelligence-owned) |

## 3. UI seed map

**T1 shell:** `/automations` **resolves today** (census:canonical_target_routes) — it is a
vendored-SPA route with a left-rail tab (census README T1 table). Its data plane is adapter
stubs: `WorkflowService/ListWorkflows|ListWorkflowExecutions|GetWorkflowExecutionSummary`
return honest-empty constants (ioi-api-adapter.mjs:865-872), as do
`EnvironmentAutomationService` lists (:874-882). The serve file declares the SPA's org-scoped
WorkflowService surface **NOT canonical** (serve-product-ui.mjs:703-706). Classification:
traversable, dead data plane.

**T2 native readouts (the wired owner substrate):**
- `/__ioi/automations` cockpit (serve:8328 list, POST create :8369-8401): project-first spec
  cards over daemon truth (:802, :812), New form with cron preview (:985-1035; proxy :8361 →
  daemon cron-preview). Detail dispatch (:8443-8494): **Run now** (→ `POST /:id/runs`, :8452),
  **Pause/Resume** (→ `PATCH {enabled}`, :8459), inline **patch** editor (:8464-8467),
  **webhook rotate** with show-once token + URL (:8471-8476; UI band :899-906), **Delete**
  (:8491-8494). Classification: wired (reads + direct daemon actions; no lease client, no
  receipts surfaced on spec mutations).
- `/__ioi/automations/monitors` (serve:8434-8441 → `renderMonitorsPort` :4455-4574): the
  certified "Automate" landing — a **read-only projection over the real automation plane**
  (stats/paused/user-executed derived from real fields :4467-4473; honest-0 notification lane;
  authoring stays on the owner substrate, foot :4574). Classification: wired read.
- `/__ioi/operations` (serve:8802 → daemon `/v1/hypervisor/operations`): execution-health
  cockpit with per-run drawer + **Re-run / Pause / Resume** actions (:1986-1991).
- Home readout tile "Automations" → `/__ioi/automations` (:1457); project cards cross-link
  (:1410); GoalRun views link the plane via "Automation readiness" affinities band (:2751).
- Incoming from Studio at rehome: `/__ioi/studio/machinery` (serve:9616-9622, reads
  `/v1/hypervisor/state-machines`; `renderMachineryPort` definition detail with named-gap
  footer :4761 — run/step/execute, scheduling, binding, simulation, versioning all named).

**T3 registered surfaces:**
- `monitors` — registry `scripts/surface-registry.mjs:61`: owner "Automations", title
  **"Automate"**, route `/__ioi/automations/monitors`, capabilities `["browse"]`,
  operational_state `browse`. Census: 29 controls / 20 implemented (8 daemon_read, 3
  local_view, 0 governed, 9 disabled_missing_authority, 1 unsupported, 8 reference_data_only)
  (census:tier_t3_registered_applications.monitors). Missing-authority contracts: object-set
  trigger catalog, effect library, notification-subscription plane, marketplace install
  binding, monitor settings (expiration/permission-scoped visibility).
- `machinery` — registry :60 (owner-in-code "Studio") — canonical target **Automations /
  Process Graphs** (:1416; census `canon_target_name`); census 30 controls / 17 implemented,
  0 governed, 12 disabled. Transfers here (paired PR with studio.md).

**Mock lane:** `product-ui/server.cjs` still ships an "Automate" catalog fixture (:895) —
deleted at W4 per the master ladder.

### Corrections vs v0

- v0 said: "scheduler in-process with NO read surface (W0.6: `/v1/hypervisor/scheduler/status`)"
  — bytes show `GET /v1/hypervisor/operations` already projects the scheduler's schedule state
  (count, per-automation enabled/trigger/spec/next_run_at/last_run_at/concurrency/policy)
  (orchestration_routes.rs:403-435; route hypervisor-daemon.rs:1314-1316). The real W0.6 gap
  narrows to scheduler **liveness** (tick heartbeat, catch-up/misfire decisions) — today's
  projection is records-derived, not loop-derived.
- v0 said: "wire … run history with GoalRun/Session refs (routes exist)" — bytes show run rows
  are `automation-executions` carrying `environment_id` + `step_results` with **no
  session/goal refs** (orchestration_routes.rs:1171-1176); the `agent` step drives an agentops
  conversation, not a HypervisorSession (:1237-1260). Lineage refs are a Wave-3 build, not a
  wiring task.
- v0 (and the census `owner_family_in_code`) placed `machinery` under Studio — canon places
  Process Graphs (legacy Machinery) under **Automations** (:1416), and Automations owns
  process-graph definitions *plus activations* (:1308-1311); machinery rehomes here with the
  state-machines backend (definitions-only today, hypervisor-daemon.rs:1935-1938).
- Surviving `automation_run_ref` sites: **none in daemon or UI code** (repo-wide grep clean).
  All remaining sites are docs and canon-legal — `HypervisorWorkItem`/`HypervisorWorkRun`
  (:4197, :4227), product-surface projection request context
  (daemon-runtime/api.md:1099), admission response (api.md:1565), and
  `AutomationRunResolutionReceipt` (daemon-runtime/events-receipts-delivery-bundles.md:1869).
  There is no code-migration debt; the C-1..C-4 work is purely additive (`subject_attachments`
  exists in no daemon code yet — grep clean).
- v0 said Automations inherits "the Home automations redirect" — bytes show two distinct
  inheritances: the T1 SPA rail route `/automations` over non-canonical WorkflowService stubs
  (ioi-api-adapter.mjs:865-872) and the Home readout tile → `/__ioi/automations`
  (serve:1457). No redirect exists; the T1 page is a live route with a dead data plane.

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Spec list + project filter | AutomationSpec; `GET /v1/hypervisor/automations[?project_ref]` (:1268) | wired at `/__ioi/automations` (serve:8328-8348) | `wired-read` at `/automations` (read-projection client) |
| Spec detail (trigger, steps census, limits, agent/harness/model config, schedule) | spec record fields (orchestration_routes.rs:192-243) | wired (serve detail :857-961) | `wired-read`; version strip appears with W3 revisioning |
| Create automation (form + cron preview) | `POST /v1/hypervisor/automations` (:1268-1271) + `GET /v1/hypervisor/cron-preview` (:1304-1306) | wired direct POST (serve:8369-8401) | `wired-action-receipted` via lease client (403 wallet → 428 credential → receipt); duplicate name/project trigger guard per :2412-2413 |
| Run now | `POST /:id/runs` (:1284-1288) | wired direct (serve:8452) | `wired-action-receipted` (transcript state_root already recorded — orchestration_routes.rs:1361-1382) |
| Pause / Resume schedule | `PATCH /:id {enabled}` (:1273-1277) | wired direct (serve:8459) | `wired-action-receipted` |
| Edit (patch) / Delete | `PATCH`/`DELETE /:id` (:1273-1277) | wired direct (serve:8464, :8491) | `wired-action-receipted`; delete refuses when enabled schedule/webhook active (named refusal) |
| Webhook enable/rotate + show-once token + events feed | `POST /:id/webhook-rotate`, `GET /:id/webhook-events` (:1295-1301) | wired (serve:8471-8476, band :899-906) | `wired-action-receipted` (rotate); events feed `wired-read` (rows already carry `receipt_id`) |
| Run history list + run drawer (status, env, timeline ref) | automation-executions; `GET /:id/runs` (:1284), `GET /v1/hypervisor/automation-executions/:id` (:2076) | wired (list + operations drawer :1986-1991) | `wired-read` with D6 waterfall/detail-drawer contract (:2712-2718) |
| Cancel running execution | `POST /v1/hypervisor/automation-executions/:id/cancel` (:2080-2083) | route exists, no UI control | `wired-action-receipted` |
| Run detail → serving Session(s)/GoalRun(s) lineage rows | `HypervisorAutomationRun.session_refs/goal_run_refs` (:3916-3924) + sessions filtered by `subject_attachments{subject_kind: automation_run, subject_ref, attachment_role: executes}` (:3971-3984) | absent (executions carry `environment_id` only) | `disabled-named-gap` until W3 lineage lands; then `wired-read`. **Never a named session field** |
| Scheduler pane (what's scheduled, next/last fire) | operations `scheduler` block (orchestration_routes.rs:419-434; scheduled table serve:1767) | wired read | `wired-read`; liveness badge binds to W0.6 `/v1/hypervisor/scheduler/status` when it lands (`disabled-named-gap` until) |
| Monitors overview bands (active/paused stats, recently-viewed, recently-triggered) | real spec/execution fields (serve:4467-4473) | wired read | `wired-read` as `/automations/monitors` view |
| "New automation" monitor wizard (condition catalog → effects → settings) | none — object-set trigger + effect-library authority missing (census) | disabled in place | `disabled-named-gap` until W3 monitor-grammar family; then `wired-action-receipted` |
| Notification "For you" tile / subscription filter | no notification-subscription plane (census) | honest 0 | `disabled-named-gap` |
| Marketplace install lanes / template docs / wizard illustrations | vendor reference content (census: reference_data_only ×8) | decorative | `delete` at cutover |
| Process-graph (machinery) table + definition detail (states/transitions/guards/IO/history) | state-machines (:1939-1953) | wired read at `/__ioi/studio/machinery` (serve:9616) | `wired-read` at `/automations` Process Graphs view (rehome) |
| Process-graph create/edit/delete (form-based) | `POST/PATCH/DELETE /v1/hypervisor/state-machines[/:id]` (:1943-1953; history[] appended per census) | absent in UI (daemon CRUD exists) | `wired-action-receipted` |
| Process-graph run/step/monitor, simulate, version/branch, bind-to-automation | none — explicitly deferred (:1935-1938) | named gaps in footer (serve:4761) | `disabled-named-gap` until W3 activation family |
| Step-family graph view (Canvas read) | WorkflowTemplate registry schema; no daemon family | absent (`workflow_graph_ref` opaque) | `disabled-named-gap` until W3 template family; Canvas stays inside the app (:2427-2428) |
| Live updates (runs firing, schedule ticks) | `/v1/event-streams` `automation-scheduler` namespace (:2350-2361 + registry fixture) | absent (no SSE here today) | `wired-read` via W0.4 event client (M5 plane; per-resource SSE is legacy, wrapped not extended) |
| T1 SPA `/automations` WorkflowService page | adapter stubs (ioi-api-adapter.mjs:865-872) | dead data plane | `delete` at cutover (owner route replaces the rail tab; W0.5 kills the stub lane) |

## 5. Ordered PR list

1. **W1** — `/automations` v2 route renders spec list + detail read-first over the W0.3 read
   client (rehome the `/__ioi/automations` reads; zero fixture data; honest-empty states).
2. **W1** — Rehome the monitors "Automate" overview as the `/automations/monitors` view
   (read-only projection; gaps stay named in place, converted to `data-ioi-disabled-reason`).
3. **W1** — Rehome machinery as the Process Graphs view (read over state-machines); registry
   owner-family transfer paired with studio.md PR 4.
4. **W1** — Run-history pane adopts the D6 drawer over runs + work-ledger + run-timeline reads.
5. **W0.6** (serialized on the central router) — `GET /v1/hypervisor/scheduler/status`
   liveness surface (tick heartbeat, last catch-up/misfire decisions); UI badge binds after.
6. **W2** — Lifecycle actions through the CapabilityLease client: create/patch/enable/disable/
   delete/run-now/webhook-rotate/cancel (routes :1268-1301, :2076-2084); every enabled control
   receipted; duplicate-trigger guard on create.
7. **W2** — Process-graph form-based CRUD via the authority client (daemon CRUD exists;
   :1943-1953); visual authoring stays disabled-named-gap.
8. **W2** — Event client subscribes to the `automation-scheduler` namespace on
   `/v1/event-streams` for live run/schedule updates (W0.4 plane).
9. **W3 backend** — AutomationRun lineage: execution admission stamps
   `session_refs`/`goal_run_refs`/`work_run_refs` on the run record and writes the serving
   session's `subject_attachments` row (`automation_run`, `executes`) inside the daemon
   execution path; read projections both directions; UI lineage rows go live.
10. **W3 backend** — Spec revisioning + `AutomationInstallationBinding` plane per :3856-3897
    (content-hashed revisions, registry_status, scope bindings); UI version strip + binding
    panel follow in-wave.
11. **W3 backend** — Monitor grammar: object-set trigger family over materialized-object-sets
    (+ threshold/metric/time-series conditions) and the effect/step families
    `approval`/`pull_request`/`report`/`deployment`/`remediation` (:2415-2420); wizard UI
    lands in-wave.
12. **W3 backend** — WorkflowTemplate read/derive family + step-family graph (Canvas read
    view, layout via CanvasView `layout_ref`); process-graph activation/binding family (the
    deferred authority-crossing cut, :1935-1938).
13. **W4** — Cutover per the 6-step rule: typed 410s for `/__ioi/automations*`,
    `/__ioi/automations/monitors`, `/__ioi/studio/machinery`; delete the SPA WorkflowService
    stub surface and the `server.cjs` "Automate" fixture (:895); rail/nav rows come from the
    product-surface compiler only.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Automations gains provider-event mapping, workflow revision/run-attempt
identity, the legal transition graph, reconciliation views, and the
receipted outbound check projection; it owns the delivery/workflow/run/
check/attempt identity contracts (epic §3 C3, a P1 item). Its inbound lane
today is only the token-hash automation webhook
(`orchestration_routes.rs:235-245`) — provider ingestion arrives via
Developer Console's C4, mapped here at P2.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none.** The `machinery` rows below are meshed by **packet 11 (studio)**,
which owns the split-rehome map; this packet records only the ownership evidence
this surface holds, and defers the ruling to X-2(a).

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T1 SPA `/automations`** — the one canonical v2 route that **resolves today**, as a vendored-SPA route with a left-rail tab | not census T3 controls. Data plane is adapter stubs: `WorkflowService/ListWorkflows\|ListWorkflowExecutions\|GetWorkflowExecutionSummary` return honest-empty constants (`ioi-api-adapter.mjs:865-872`), as do `EnvironmentAutomationService` lists (`:874-882`). The serve file declares the SPA's org-scoped WorkflowService surface **NOT canonical** (`serve:703-706`) | `/automations` is Automations' canonical route | **retire-at-cutover** — and this row is the estate's **one live route hijack**: a canonical v2 route currently answered by a dead SPA plane. `home.md` records the sibling `/automations` redirect. The v2 shell must take the route from the SPA, not coexist with it | W0.1 · W4 |
| **T2 automations cockpit** — `/__ioi/automations` GET (serve `:8360`), POST create (`:8401`), cron-preview proxy (`:8393` → daemon), detail dispatch (`:8443-8494`) | T2 census `nat-automations`: **29 controls, 0 disabled**; `nat-automations-new`: **19 controls, 0 disabled** | Automations owns durable triggers, schedules, monitors, services — condition → governed effect | **rehome** | W1 |
| ↳ spec CRUD + lifecycle verbs | part of the T2 count: **Run now** (`POST /:id/runs`, `:8452`), **Pause/Resume** (`PATCH {enabled}`, `:8459`), inline patch editor (`:8464-8467`), **Delete** (`:8491-8494`) | governed effect requires admission + receipt | **rehome with a named defect** — these are **direct daemon actions with no lease client and no receipts surfaced on spec mutations** (§3). A spec mutation that changes what a trigger will do, without a receipt, is the same unreceipted-effectful-mutation shape as `ontology.md` §9 D-1. Recorded here; the fix is W2's lease-client wave, not this packet, because the daemon routes themselves would need the receipt family | W2 |
| ↳ webhook rotate | part of the T2 count: rotate with **show-once token + URL** (`:8471-8476`; UI band `:899-906`) | secrets are shown once and never re-readable | **rehome** — show-once is the correct posture and must survive verbatim | W1 · W2 |
| ↳ cron preview | proxy `:8393` to the daemon's own cron-preview | schedule semantics are the daemon's, not the UI's | **rehome** — the proxy is right: the UI must never compute a schedule preview locally | W1 |
| **T3 `monitors` — "Automate"** — registry `surface-registry.mjs:61`, owner Automations, route `/__ioi/automations/monitors`, capabilities `["browse"]`, `operational_state: browse`; renderer `renderMonitorsPort` (serve `:4455-4574`); protected seed, class `daemon_wired` | **29 controls, 0 governed** — correct for a `browse` surface. Stats/paused/user-executed derived from **real fields** (`:4467-4473`); honest-0 notification lane; **authoring stays on the owner substrate** (`:4574`) | Automations' certified landing over the real automation plane | see cluster rows | — |
| ↳ real-automation read cluster | 5 `daemon_read` (active-automations tiles, recently-viewed table, failures-in-last-4-weeks, recently-triggered feed, automations list) | condition → effect posture over real specs | **rehome** | W1 |
| ↳ tabs + list filters | 4 controls: 2 `daemon_read` (Automations tab, getting-started view-all) + 2 `local_view_interaction` (Overview tab, list filters) | local filtering is local | **rehome** | W1 |
| ↳ **authoring wizard cluster** | 5 controls: 1 `local_view_interaction` (step nav Condition→Effects→Settings→Summary + Next/Back) + 4 `disabled_missing_authority` (condition catalog incl. **objects added/removed/modified**, effects step, settings step, summary + Create) | **object-set monitor triggers are route-missing** (§2, W3). Object sets exist (`/odk/materialized-object-sets`); the *trigger binding* does not | **blocked-missing-route** — the wizard grammar is the right shape (`wizard` pattern, §8) and the four steps stay disabled until the trigger/effect families land. Enabling Create today would persist a spec whose conditions cannot fire | W3 |
| ↳ authoring entry points | 4 `disabled_missing_authority` (recent-installations store dropdown, New-automation header button, Help, create-your-first card) | same missing plane | **blocked-missing-route** for the two New-automation entries · **retire-at-cutover** for the installations store dropdown (a Packages path) and Help | W3 · W4 |
| ↳ **reference marketing cluster** | **8 `reference_data_only` — 28% of this surface's controls**: hero band, 3-step illustration strip, three template cards (weekly report / auto-close tickets / notify on status changes) with "Open docs", and the **Cipher example cards** | **no fixture data may be presented as truth**; the Cipher cards are a **vendor faculty** (standing P2 gate) | **retire-at-cutover** — templates are a Packages/pattern path, not local marketing; and a template card that cannot be instantiated is an advertisement | W4 |
| ↳ vendor shell chrome | 5 controls: 1 `daemon_read` (workspace nav) + 1 `unsupported_reference_session` (add-to-favorites) + 1 `disabled_missing_authority` (notifications inbox) + 2 `reference_data_only` (session chrome incl. AIP Assist, app icon + title) | carve-out; AIP Assist is a vendor faculty | **retire-at-cutover** | W4 |
| **T5 `/__apps/monitors`** — capture, owner Automations, `reference_capture`, capture state `boots_graph`… note "condition→effect monitor wizard; unbound", `reboundLane: null` (`harvest-seed-inventory.mjs:32`), grammar `wizard`, high_value | not in the 563; §3 records the proxy as insufficient | the wizard above is the functional shape | **pattern-harvest** — the condition→effect wizard grammar informs the functional pane; no code moves. The parity matrix classes `monitors` `daemon_wired`, but that class belongs to the **registered T3 surface**, not the capture | — |
| **Cross-surface reads** — `/__ioi/operations` execution-health cockpit with per-run drawer + **Re-run / Pause / Resume** (serve `:1986-1991`); home tile (`:1457`); project cards (`:1410`); GoalRun "Automation readiness" band (`:2751`) | not census T3 controls | Operations observes; **Automations owns the verbs** | **rehome** — the three remediation verbs stay Automations-owned wherever they are rendered. `operations.md` §6 records the same delegation from the consumer side, and the two rows must not drift apart | W1 · W2 |
| **`machinery` ownership evidence** — registry `surface-registry.mjs:60` says owner **"Studio"**; the audit census `canon_target_name` says **"Automations / Process Graphs"** (:1416) | 30 controls (meshed in packet 11) | one owner must hold it | **deferred — X-2(a)** — this packet records both bytes and rules nothing. The conflict is real and documented on both sides; packet 11 meshes the surface, and the ownership ruling lands as its own owner-scoped canon PR | X-2 |

**Census reconciliation.** Automations' one T3 surface carries **29 of the 563**
baseline controls: 5 + 4 + 5 + 4 + 8 + 3 = 29, exact (`machinery`'s 30 are counted
by packet 11, not here, to avoid double-counting a contested surface). Its two T2
readouts add 29 + 19 = 48 controls, 0 disabled, outside the baseline.

**Zero governed controls** on `monitors` is correct — it is registered
`operational_state: browse` and its footer says authoring stays on the owner
substrate. The T2 cockpit is where the verbs live, and that is the surface whose
mutations lack receipts.

**Disposition summary.** 7 rehome (one with a named defect) · 1 pattern-harvest ·
4 retire-at-cutover · **2 blocked-missing-route** · 1 deferred to X-2.

## 7. Ontology wiring

Automations is **almost** object-bound, and the gap is a single missing binding
rather than a structural absence — which makes it different from every
`none — not object-bound` surface so far.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Automation specs, runs, schedules, webhooks | **none — not object-bound.** Specs are platform objects | `/v1/hypervisor/automations` family | Read + Write | the automation itself is not an ontology object |
| **Condition catalog — object triggers** | `MaterializedObjectSet` | **object sets exist** at `/v1/hypervisor/odk/materialized-object-sets`; **the trigger binding is route-missing** | — | The wizard's "Objects added / removed / modified" conditions are the one place Automations would read the semantic plane. Both halves exist separately: the object sets are real, and the condition vocabulary is rendered — **the binding between them is the whole gap** (§2, W3) |
| Effects step | `OntologyActionContract` | **route-missing** (`ontology.md` §7) | — | an effect that invokes a semantic action needs the action-contract family; the same absent contract blocks Ontology's execute lanes |
| Run health / execution posture | **none** | `/v1/hypervisor/operations` | Read | substrate |
| **Write side — semantic plane** | **none** | — | — | Automations writes specs and runs; it writes no ontology fact. When object triggers land, the automation **reads** set membership and writes its own run record — never an assertion |

The ruling that keeps the W3 build honest: an object-set trigger must fire on
**admitted set membership**, not on a UI-side diff. Canon's projections carry
freshness and watermark for exactly this reason — a trigger that fires off a stale
projection without surfacing its watermark would make an automation act on a
semantic state that is no longer true.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Automations list + detail | `list_detail` | **exempt — no bindable primitive** | specs are platform objects (X-2 platform-object finding) |
| Monitors landing (tiles, failures, triggered feed) | `dashboard` / `monitoring_console` | **exempt — no bindable primitive** | same |
| **Condition → Effects → Settings → Summary wizard** | `wizard` | **exempt today — expressible after the trigger binding lands** | the only pane in the run so far whose exemption is **temporary and dated**. Once object-set triggers bind, the condition step names `MaterializedObjectSet` refs and the effects step names action refs — real invariant-11 values. Until then the descriptor would have nothing to bind |
| Spec authoring (patch editor, create form) | `object_editor` | **exempt — no write semantics in the descriptor** | fourth instance of the write-semantics finding (`ontology.md` §8, `data.md` §8 ×2) |

Zero expressible, zero rendered — but the wizard row is worth separating in the
X-4 rollup: it is the first pane whose expressibility is **blocked by a build, not
by the descriptor contract**. When W3 lands, Automations gains the run's first
genuinely descriptor-expressible *authoring-adjacent* pane.

### (b) This surface as primitive exposer

**n/a.** Automations owns no stage of the composable-application journey
(`odk-extension-apps.md` §2), exposes no ODK primitive, and holds no descriptor.

One adjacency, because the wizard makes it tempting: a generated domain app might
want to *trigger* on its own object sets. That path runs through Automations as an
ordinary automation over an admitted object set — **not** through the app, and not
as a capability the app's descriptor grants. A descriptor can name the object set;
only an admitted automation can act on it.
