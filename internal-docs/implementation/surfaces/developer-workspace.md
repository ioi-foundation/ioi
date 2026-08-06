# Developer Workspace — implementation brief

Canonical route: `/developer-workspace` · Owner: Developer Workspace (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- Owner job: "code, systems, workflow, workspace, editor, terminal, browser, and
  debugging surface, including development environment recipes and lifecycle
  observations where they help users start, inspect, restore, or tear down work"
  (core-clients-surfaces.md:1386-1390). One-line identity: "Developer Workspace
  develops, debugs, and operates systems and workspaces" (:98).
- `Workbench` / `HypervisorWorkbench` are RETIRED labels, tolerated only in existing
  routes/packages/saved links during migration — never a second product identity
  (:2281-2284); "Workbench = retired label; the owner name is Developer Workspace"
  (:4809). Route `/developer-workspace` in the v2 ledger, no aliases per ADR 0022
  (:876-880, :902).
- **The editor is an adapter target, not the product identity** (:2295-2296). The
  implementable contract is `AdapterConnectionProfile`: connection mode, launch path,
  required local/remote components, supported features, policy coverage, known limits;
  "Editor choice is a session preference, not Hypervisor's product identity"
  (:3168-3195). Surfaces it may appear in: App, Web, remote browser workspaces,
  VS Code-family / Cursor / Windsurf / JetBrains adapters, terminal/tmux views
  (:2286-2293).
- Lives inside or attached to a Project — "The owner name is the IDE-grade
  **Developer Workspace** inside or attached to a Project; the Project is the durable
  context object" (:1600-1602); correct flow: "Open the Project. Use Developer
  Workspace or an editor adapter to inspect and change it." (:1620-1622).
- Consumes, never owns, the environment-ops substrate: daemon owns lifecycle
  semantics, wallet.network owns authority/credential release, Agentgres owns admitted
  state/receipts/restore truth (:3206-3209). Developer Workspace receives structured
  outputs and exit codes — never durable secrets, plaintext custody, or authority
  except through capability leases + receipts (:3232-3236).
- Operator-expectation rows it serves: "Live console / machine window" and
  "Snapshots / checkpoints / restore" (:302-303). Build-verb participant (:1120-1122);
  Surface Generate may consume "Developer Workspace code" (:2217-2221); Canvas may
  appear inside it (:1399-1401, :2427).
- May never: be runtime truth (:4783); make one editor shell the parent product
  (:4718-4719); treat an editor name string as the adapter contract (:4746); treat the
  editor adapter as a full execution boundary (:4787) or the adapter target as a
  secret vault (:4788); densify Home into its terminal/diff/file console (:4725).
- Layering (C-1..C-4): sessions bind "typed subject attachments … the platform never
  names an application family as a dedicated field" (:2683-2687, :2692-2696) and
  "adapter targets" (:2703); the thread/managed-session/launch-recipe plane is ONE
  daemon-internal substrate composed by read only (:3320-3328). The workbench's
  sessions/runs panels are read-projections; any session-serving row binds through
  `subject_attachments`.

## 2. Schema map

Registry (`docs/architecture/_meta/schemas/`): the environment/editor planes are the
best-covered in the estate — `hypervisor-development-environment-recipe.v1` (+
`-resolution.v1`), `hypervisor-environment-backup.v1`,
`hypervisor-environment-route-binding.v1`, `harness-session-terminal-attach.v1`,
`hypervisor-session-launch-recipe-admission.v1` all exist. `AdapterConnectionProfile`
has NO registry schema; its byte-level carrier is the tracked manifest
`packages/hypervisor-adapter-targets/editor-targets.manifest.json`
(`ioi.hypervisor.editor_targets.manifest.v1`, doctrine block restates the canon rule)
+ per-editor profiles `code-editors/profiles/*.json` (vscode, vscode-browser,
insiders, cursor, windsurf, devin), read by editor_routes.rs:40-53.

| Canon object / contract | Registry / canon anchor | Daemon route(s) today |
|---|---|---|
| Environment object model (HypervisorEnvironmentClass / LifecycleState) | canon :3238-3253 | classes hypervisor-daemon.rs:1140-1143; list/create :1144-1148; summary projection :1150-1153; get :1154-1157; `:id/:action` (start/stop/delete/archive/restore) :1158-1161; logs :2688-2691; typed lifecycle projection :2228-2231 + `lifecycle/:op` :2232-2238 |
| EnvironmentOpsService (files/git/terminal Connect contract; "the native Workbench consumes" — daemon's own comment :2912-2913) | canon env-ops contract list :3211-3230 | ops-lease :2914-2921; `/supervisor/:env/supervisor.v1.EnvironmentOpsService/:method` :2922-2925; methods ReadFile/WriteFile/Find/GetGitStatus/GetGitDiff*/ListTerminalProfiles/Exec/CancelExec (supervisor_routes.rs:347-594) |
| HypervisorEnvironmentPort (+ preview gateway) | canon :3222, :3248 | ports :2928-2931; expose :2932-2935; unexpose :2936-2939 |
| Watch/PR-draft (daemon-owned snapshot + governed proposal) | canon :3214, receipts obligation :3229 | watch-state :2942-2945; pull-request-drafts :2946-2949; env-files :2907-2911 |
| HypervisorDevelopmentEnvironmentRecipe (+ resolution) | schema in registry; canon "development environment recipes" :1388 | recipes list/create :1221-1225; get :1226-1229 |
| Snapshots / backups / restore (HypervisorEnvironmentBackup) | schema in registry; canon archive/restore doctrine :3255-3271 | snapshots list/create :1207-1212; restore :1213-1216; backups create :1217-1220. **No backup LIST / restore-prepare/apply/cancel ladder** (canon :3226) → `route-missing` **W3** (small) |
| Interactive PTY terminals (T7-E, environment_ref-bound) | canon "terminal" :1387 | list/create :3105-3109; stream :3110-3113; input :3114-3117; resize :3118-3121; close :3122-3125 |
| Editor-target registry (adapter targets, probed open posture) | manifest above; canon :3166-3195 | targets list :3129-3132; get :3133-3136 |
| Editor services + host provisioning (WS-3/8; fail-closed `editor_runtime_not_provisioned`, editor_routes.rs:14-16) | canon "editor" :1387 | provisioning plans :3137-3144; services list/create :3145-3149; start :3150-3153; stop :3154-3157; rebuild :3158-3161; expose :3162-3165; status :3166-3169; logs :3170-3173; open-url :3174-3177 |
| Editor access leases (capability leases via the EXISTING authority machinery — editor_routes.rs:4-6) | canon :3232-3236 | create :3178-3181; revoke :3182-3185. **No GET list** → `route-missing` **W3** (small; needed for the lifecycle strip) |
| CodeEditorAdapterLaunchPlan admission | fixture family `hypervisor-session-launch-recipe-admission` (negative-workbench-without-adapter) | :1107-1110 |
| HarnessSessionTerminalAttach admission | `harness-session-terminal-attach.v1` schema; canon :3060 | :1119-1122 |
| Code WorkRun (materialized Git branch/worktree + patch branch, :4825-4826) | canon anti-pattern :4782 | workruns list/create :1162-1167; get :1168-1171; execute :1172-1175 |
| ScmPublicationEffect (governed publish out of an env workspace) | `schema://ioi/components/connectors-tools/scm-publication-effect/v2` in registry | publish :3088-3091 (bindings/proposals/effects are Developer Console rows, see sibling brief) |
| Session plane (read-compose only) | C-rulings; canon :3320-3328 | sessions :3189-3193; events :3194-3197; execute :3198-3201; get/teardown :3206-3210; session-turns :769-772; threads :783-798 (daemon-internal substrate — read-compose) |

## 3. UI seed map

The inherited workbench is THREE wired lanes, all serving today:

- **T1 vendor SPA shell** (`apps/hypervisor/product-ui/owned/public/`; captures under
  `details/<uuid>/index.html`, `workspaces/`; served by `serve-product-ui.mjs`, wired
  through the adapter):
  - `/details/:envId` — session detail (conversation + env panel). Adapter
    `EnvironmentService`: **14 RPCs**, all daemon-backed
    (ioi-api-adapter.mjs:399-486 → `/v1/hypervisor/environments*`); residues:
    `CreateEnvironmentLogsToken` returns a fabricated local token (:479-480),
    `MarkEnvironmentActive` is a no-op `{}` (:481-482). Adapter `AgentService`:
    **10 RPCs** (CreateAgentSession :509-519, ListAgentExecutions :521-528,
    GetAgentExecution :530-535, CreateAgentExecution/StartAgent :537-553,
    SendToAgentExecution :555-580, StopAgentExecution :582-585,
    DeleteAgentExecution :587-590, CreateAgentExecutionConversationToken :592-593
    [local constant], ListPrompts :1288) — riding a serve-local run registry plus
    daemon `/v1/threads*` writes (:526, :552, :579, :584, :589). Classified
    **partial**: wired, but the run registry is serve-local state and the thread
    writes are thread-plane write sites (see Corrections).
  - `/workspaces/:envId` — the code-workspace IDE console ("the real console; NOT
    iframed here. No owned terminal/editor" — serve-product-ui.mjs:2344). Its live
    file/git/terminal I/O is the EnvironmentOpsService bridge: SPA opens
    `ws://…/supervisor.v1.EnvironmentOpsService/` → serve WS transport
    (serve-product-ui.mjs:10408-10581, unary delegated to the daemon contract home)
    → daemon :2922-2925. Access token = real env-scoped ops lease
    (adapter:472-477 → daemon :2914-2917). **Wired.**
  - `EditorService/ListEditors` offers ONLY probed-openable targets from the daemon
    editor-target registry (adapter:677-699). **Wired.**
- **T2 native readouts** (serve-product-ui.mjs):
  - `/__ioi/workbench` (census: 200, 266 controls — the estate's biggest single
    readout) — environments-summary + editor-targets + sessions + goal-runs composed
    (serve:8840-8851, renderer :2345-2460); per-env drawer links Workbench / Session /
    Run Timeline (:2390-2435). **Wired read.**
  - `/__ioi/editor/open?environmentId=…` — drives the FULL editor-service lifecycle
    chain server-side: create service → mint access lease → start → expose → 302 to
    `open_url`, fail-closed with the daemon's reason (serve:10328-10356). **Wired
    action** (governed via capability lease).
  - Terminals panel drives `/v1/hypervisor/terminals` create/stream/input/close
    (serve:6905-6925, :6370-6397). **Wired action.**
  - `/__ioi/code` (census: 24 controls) — repos + SCM binding posture + publish trail,
    links back to Workbench (serve:1413). Read-only here; SCM registrations belong to
    Developer Console.
- **T4 dormant seed**: `ux-seeds/workspaces` is census-assigned
  `canonical_owner: "Developer Workspace"` (inventory.v1.json
  tier_t4_dormant_ux_seeds; tree at `apps/hypervisor/ux-seeds/workspaces/`) —
  reference capture only, no registration.
- Census deltas: `/developer-workspace` `resolves: false`
  (census: canonical_target_routes); no T3 registered surface exists for this owner
  (14 slugs, none workspace-shaped). Seed-preservation: serve/adapter/owned-public are
  protected seed roots (`ported-seed-preservation.v1.json` seed_roots).

### Corrections vs v0

- v0 said: "inherits the wired workbench (route `/details/:env` …)" — bytes show the
  workbench is three lanes, not one route: vendor SPA `/details/:id` (session detail)
  AND `/workspaces/:id` (the IDE console, serve-product-ui.mjs:2344) AND the native
  readout `/__ioi/workbench` (serve:8840-8851, 266 controls per census). The rehome
  must carry all three or it strands the IDE lane.
- v0 said: "wire editor-service lifecycle controls that already exist server-side" —
  bytes show the create→lease→start→expose chain ALREADY has a wired consumer
  (`/__ioi/editor/open`, serve:10328-10356); the genuinely unwired server-side
  controls are stop / rebuild / status / logs / lease-revoke
  (hypervisor-daemon.rs:3154-3173, :3182-3185). The work is narrower: surface the
  running-service inventory + those five verbs.
- v0 counts verified exact: EnvironmentService 14 RPCs (adapter:406-486), AgentService
  10 (adapter:509-593 + :1288). But two of the 14 are dishonest residues
  (fabricated logs token :479-480, no-op MarkEnvironmentActive :481-482) — v0's
  "wired workbench" overstates by exactly these.
- Thread-plane write sites to record per the C-rulings (migrate at the PR that touches
  them, target = session-execution loop / `session-turns`): adapter POSTs
  `/v1/threads` (:552), `/v1/threads/:id/turns` (:579), `/v1/threads/:id/cancel`
  (:584), DELETE `/v1/threads/:id` (:589); serve-local run registry backs
  ListAgentExecutions (:523-528). No named app-family session fields found in these
  modules — the binding residue is the write path itself.

## 4. Schema→UI binding table

Lease flow = the standing gateway order: sealed credential (428) → wallet grant (403)
→ receipted (lifecycle_routes.rs:11899-11942); editor access leases ride the same
machinery (editor_routes.rs:4-6). Reads go through the W0.3 read client.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Environment inventory (list + counts + pager) | environments-summary :1150-1153 | wired (`/__ioi/workbench` + SPA list) | `wired-read` under `/developer-workspace` |
| Env detail drawer (phase, class, project, links) | environments/:id :1154-1157 + lifecycle projection :2228-2231 | wired | `wired-read` |
| Start / Stop / Archive / Restore / Delete env | `:id/:action` :1158-1161 | wired via adapter (SPA) | `wired-action-receipted` via authority client |
| Create environment (from project / class) | :1144-1148 + classes :1140-1143 + recipes :1221-1229 | wired via adapter | `wired-action-receipted` |
| File tree / editor buffer / git status / diff | EnvironmentOpsService :2922-2925 (WS bridge serve:10408-10581) | wired | `wired-read` (writes: `wired-action-receipted` behind ops lease) |
| Terminal panes | terminals :3105-3125; ops-lease :2914-2917 | wired (serve:6905-6925) | `wired-action-receipted` (lease-scoped) |
| Ports panel (observe / expose / unexpose) | :2928-2939 | wired via adapter UpdateEnvironment (:447-452) | `wired-action-receipted` |
| Logs pane | :2688-2691 | wired | `wired-read` |
| Editor picker ("Open in …") | editor-targets :3129-3136 + manifest profiles | wired, probed-only (adapter:689-696) | `wired-read`; default editor = org/user preference, never the contract (manifest doctrine) |
| Open editor (VS Code Browser) | editor-services chain :3145-3181 | wired (`/__ioi/editor/open`) | `wired-action-receipted` |
| Editor service strip (status/logs/stop/rebuild/lease-revoke) | :3154-3177, :3182-3185 | **dead — server-only, zero UI consumers** | `wired-action-receipted` (W2) |
| Editor access-lease list on the strip | no GET list route | absent | `disabled-named-gap` → W3 row (§2) |
| Snapshots / backups / restore panel | :1207-1220 | dead (no UI consumer found) | `wired-read` + restore `wired-action-receipted`; backup-list ladder `disabled-named-gap` → W3 row (§2) |
| Agent conversation pane (`/details/:id`) | serve run registry + `/v1/threads*` (adapter:495-594) | partial (works; serve-local truth + thread-plane writes) | `wired-read` composed from session + execution-binding + turns reads; input rides the session execution loop (Cut #2, W4); session rows bind subjects via `subject_attachments` |
| Sessions / IOI-Agent-runs panels on workbench | sessions :3189-3193 + goal-runs (serve:8840-8846) | wired read | `wired-read` (subject_attachments rows) |
| WorkRun view (branch/patch/receipts) | workruns :1162-1175 + agent-run-transcripts :2950-2959 | partial (Run Timeline readout) | `wired-read` (D7 WorkRun view fields, canon :2720-2727) |
| PR draft / publish out of env | pull-request-drafts :2946-2949; scm publish :3088-3091 | wired (governed) | `wired-action-receipted`; destination-binding registration UI lives in Developer Console |
| Fabricated logs/conversation tokens (adapter:479-480, :592-593) | none | local lies | `delete` (W0.5 identity-truth rule: real token route or honest absence) |
| `MarkEnvironmentActive` no-op (adapter:481-482) | activity signals canon :3227 | local lie (silent `{}`) | `delete` or wire to a real activity-signal route when one exists (`disabled-named-gap` until then) |

## 5. Ordered PR list

1. **W1** — Register Developer Workspace + serve `/developer-workspace`: env
   inventory + detail read-first (environments-summary/get/lifecycle projection),
   rehoming the `/__ioi/workbench` renderer's data contract; `Workbench` label
   retired from nav copy (canon :2281-2284). No new truth.
2. **W1** — Editor-target picker as read view (targets + manifest posture); default
   editor exposed as preference, adapter-connection-profile rule stated in-surface
   (canon :3195-3196).
3. **W1** — Rehome the IDE lane: `/developer-workspace/:envId` mounts the existing
   SPA workbench (EnvironmentOpsService WS bridge + terminals) unchanged under the
   canonical route; legacy `/workspaces/:id`, `/details/:id` keep serving until
   cutover (seed invariant).
4. **W2** — Env lifecycle verbs (start/stop/archive/restore/delete/create) through
   the W0.3 authority client with receipt refs surfaced; ports expose/unexpose
   likewise.
5. **W2** — Editor-service lifecycle strip: running services inventory
   (list/status/logs) + stop/rebuild/lease-revoke wired to :3154-3185; open-chain
   reuses the `/__ioi/editor/open` sequence server-side.
6. **W2** — Snapshots/recipes panel: read + snapshot-create/restore receipted;
   recipe list/get read-first.
7. **W3** — Backend smalls from §2: editor-access-lease GET list; backup list +
   restore-prepare/apply/cancel ladder (canon :3226). UI follows in the same wave
   (replaces the two `disabled-named-gap` rows).
8. **W3** — Adapter honesty pass: delete fabricated logs/conversation tokens +
   MarkEnvironmentActive no-op; wire or honestly absent (W0.5 rule).
9. **W4** — Conversation lane onto the session execution loop (Cut #2):
   replace serve-local run registry + `/v1/threads*` writes with
   session-execution-binding reads + `session-turns`; `subject_attachments` rows
   throughout; event updates via `/v1/event-streams` subscriptions (W0.4), legacy
   per-resource SSE wrapped.
10. **W4** — Cutover per the 6-step rule: `/workspaces/:id`, `/details/:id`,
    `/__ioi/workbench` retired with typed 410s; ux-seeds/workspaces disposition
    decided (adopt or archive) at the same PR.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Developer Workspace gains the commit/PR check timeline, provider-observed vs
IOI-admitted state, policy preflight, receipt links, reconcile/retry, and
stale/fork/unknown states. Epic P0-1 (UI publish sends `connector_id`+`title`
against the daemon's `destination_binding_ref`+`proposal_ref` contract —
`ioi-agent-runs.mjs:450/:482/:495` vs `scm_publication_routes.rs:1773/:1798`)
and P0-2 (`/__ioi/code` substring-matched publish trail,
`serve-product-ui.mjs:1400`) are this owner's repair-or-disable items.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 3: none.** No registry slug names Developer Workspace as owner → **0 of the
563 baseline controls**. The heavy lifting here is T1 vendor SPA + T2 readouts, which
is why this surface's mesh is dominated by the **vendored-shell carve-out**: the
hidden-UX rule gives vendored shell internals a disposition row, not control-level
detail.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T1 `/workspaces/:envId`** — the code-workspace IDE console; serve declares "the real console; NOT iframed here. No owned terminal/editor" (`:2344`). Live file/git/terminal I/O rides the `EnvironmentOpsService` bridge: SPA → `ws://…/supervisor.v1.EnvironmentOpsService/` → serve WS transport (`:10408-10581`) → daemon `:2922-2925`; access token is a **real env-scoped ops lease** | vendored-shell carve-out (no control-level detail) | Developer Workspace owns the **live console**; Environments owns the substrate overview (:299-303) | **rehome** — the console is the surface. The ops-lease-backed token and the "no owned terminal/editor" honesty must survive: the estate must not grow a second, unleased terminal | W1 · W2 |
| **T1 `/details/:envId`** — session detail (conversation + env panel). `AgentService` 10 RPCs ride a **serve-local run registry** plus daemon `/v1/threads*` writes (`ioi-api-adapter.mjs:509-593`) | carve-out | session detail is **Work's** (`work.md` §6 rehomes the injected cockpit panel and Run Timeline) | **retire-at-cutover** — this route is Work's D5 seed, not Developer Workspace's, and the two briefs must not both claim it. `work.md` §6 carries the rehome row; this row carries the retirement | W4 |
| ↳ serve-local run registry + thread-plane writes | carve-out | C-3: thread/thread-fork/managed-session records are **one daemon-internal execution substrate**; product surfaces compose them **by read only** (:3320-3328) | **rehome with a named defect** — the adapter's `AgentService` writes to `/v1/threads*` directly (`:526`, `:552`, `:579`, `:584`, `:589`), which is a product surface writing the thread plane, and it keeps run state in **serve-local memory** rather than the daemon. Both are C-3 violations recorded at the byte sites; they migrate at the PR that touches them (C-4) | W4 |
| ↳ `CreateAgentExecutionConversationToken` | carve-out | tokens are daemon-issued | **rehome with a named defect** — returns a **local constant** (`ioi-api-adapter.mjs:592-593`), the same fabricated-token shape W0.5 already deleted for `CreateEnvironmentLogsToken`. Recorded here as the surviving instance of a pattern the estate has already ruled against | W2 |
| **T1 `EditorService/ListEditors`** — offers **only probed-openable targets** from the daemon editor-target registry (`adapter:677-699`) | carve-out | honest availability; a stale probe must not advertise an editor | **rehome** — probed-openable-only is the correct posture and matches the model-route registry's gotcha (`foundry.md`) | W1 |
| **T2 `/__ioi/workbench`** — serve `:8876` | T2 census `nat-workbench`: **266 controls, 0 disabled** — the estate's **largest single readout by control count** | Developer Workspace's native cockpit | **rehome** | W1 |
| **T2 `/__ioi/code`** — serve `:8685` | T2 census `nat-code`: **24 controls, 0 disabled** | code lane | **rehome** | W1 |
| **T2 `/__ioi/editor/open`** — serve `:10364`; entry points at `:2382` ("VS Code Browser ↗") and `:2430` (openable target rows) | not separately censused | editor launch over probed targets | **rehome** — the launcher only offers targets the registry reports openable | W1 |
| **T4 `ux-seeds/workspaces`** — vault from PR #93 (`manifest.json`: `canonical_owner: "Developer Workspace"`, `proposed_route: /__ioi/workbench/workspaces`, `active_registration: "none"`, `active_parity_class: reference_capture`), **with pixel certification** (`workspaces/pixel-certification.json`) | dormant seed evidence only | the Code-Workspaces launchpad grammar over the real session projection | **pattern-harvest** — and the vault is already the meshed answer, written down: it maps the launchpad grammar onto `GET /v1/hypervisor/sessions` + `GET /v1/hypervisor/editor-targets`, renders creator/last-edited-by as **honest em-dashes** because no principal or edit tracking exists on the session projection, and marks the reference's VS Code / Jupyter / RStudio filter pills as **foreign editor taxonomy** kept as named-gap chrome (`surface.mjs:5-14`). The functional pane should adopt those three rulings verbatim | — |
| ↳ pixel certification | present, unlike `ux-seeds/lineage` (`provenance.md` §6) | a passing pixel certificate **grants nothing** | **recorded, not credited** — the certificate proves captured shell grammar and no more; `manifest.json` lists three activation requirements (owner contract current, registration daemon-admitted rather than certification-derived, truth and authority reverified) that a certificate does not satisfy | — |
| **T5 `/__apps/workspaces`** — capture, owner "Workbench" (retired name), `reference_capture`, capture state `boots_landing`, grammar `editor_canvas`, high_value, `reboundLane: null` (`harvest-seed-inventory.mjs:70`) | not in the 563 | same launchpad grammar as the T4 vault | **pattern-harvest** — the capture and the vault are the same grammar at two fidelities; the vault is the better artifact because it already carries the honest mapping | — |
| **T5 `/__apps/repositories`** — capture, `reference_capture`, capture state **`blocked_missing_capture`**, grammar `table_list`, aux, `reboundLane: null` (`:71`) | not in the 563 | repository subjects reach Work through `subject_attachments` per the SCM epic (`work.md` §5); Developer Workspace renders repo state in the console | **blocked-missing-capture** — honest block, and the SCM transition-chain epic owns the repository interfaces anyway | — |
| **T5 `/__apps/notepad`** — capture, `reference_capture`, capture state `blocked_missing_capture`, grammar `document`, aux, `reboundLane: null` (`:72`) | not in the 563 | **no canon pane** — there is no notepad in the Developer Workspace contract | **blocked-missing-capture** — and doubly disposed: no capture to inspect and no canonical home to mesh it against | — |
| **Retired owner name "Workbench"** — the inventory owner field for all three captures | — | Developer Workspace is the canonical owner name | **recorded** — "Workbench" is a retired name that rehomes into Developer Workspace and is never revived as a peer | W4 |

**Census reconciliation.** Developer Workspace holds **0 of the 563** T3 baseline
controls — it has no registered surface. Its two censused T2 readouts carry
**290 controls, 0 disabled** (266 + 24), outside that baseline, and `/__ioi/workbench`
alone is the estate's largest single readout. The T1 vendor lanes are carve-out and
carry no control-level census by rule.

**Disposition summary.** 6 rehome (two carrying named defects) · 2 pattern-harvest ·
2 retire-at-cutover · **2 blocked-missing-capture** · 0 blocked-missing-route.

## 7. Ontology wiring

**None — not object-bound.** Developer Workspace's objects are environments,
sessions, workspaces, editor targets, files, terminals, ports, and repositories.
None is a `CanonicalObjectModel` instance, and the surface reads no
`/v1/hypervisor/odk/*` route.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Console (files, terminal, git, ports, tasks) | **none — not object-bound** | `EnvironmentOpsService` via the WS bridge → daemon `:2922-2925` | Read + Write (env-scoped ops lease) | file bytes are not ontology objects |
| Workspaces launchpad | **none** | `/v1/hypervisor/sessions`, `/v1/hypervisor/editor-targets` | Read | platform objects |
| **Development-environment recipes** | **not a `DataRecipe`** — `DevelopmentEnvironmentRecipe`, `/v1/hypervisor/recipes` (`hypervisor-daemon.rs:1226`) | `/v1/hypervisor/recipes` (+ `/:id`) | Read | the packet table names "development-environment recipes" as this surface's ontology starting point; at the bytes they are **not semantic-plane objects at all**. This is the same unqualified-"recipe" naming collision `data.md` §7 filed to X-2, seen from the surface that actually owns the object |
| **Write side — semantic plane** | **none** | — | — | the console writes files and runs commands under an ops lease; it writes no semantic fact |

The correction this packet makes to its own input: the charter's ontology starting
point for this surface ("development-environment recipes") resolves to a
**platform** object wearing a semantic-sounding name. Recorded rather than forced —
an honest `none` beats a binding invented to fill the column.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Workspaces launchpad table | `list_detail` | **exempt — no bindable primitive** | sessions and editor targets are platform objects (X-2 platform-object finding) |
| Console file tree + editor | `object_editor` | **exempt — not an object editor** | the pattern edits *ontology objects*; this edits **files**. A file is not an object-model instance, and treating the console as an `object_editor` would be a category error, not just an unbindable one |
| Repositories view | `list_detail` | **exempt — no bindable primitive**, and route-missing | SCM epic owns the repository interfaces |
| Terminal / ports / tasks panes | **no matching pattern** | **finding — filed against the pattern vocabulary** | a live terminal is not `monitoring_console` (which observes) — it is an interactive session. Third distinct missing-pattern finding, after the D6 waterfall (`work.md`, `provenance.md`) |

Zero expressible, zero rendered.

The console row is worth separating for X-4 because it is a **different exemption
class** from the rest of the run: everywhere else the pane could be descriptor-bound
if the primitives existed. Here the pane is **categorically not** what the pattern
describes. `object_editor` edits ontology objects; a code editor edits files;
conflating them would be the mistake, not the missing capability.

### (b) This surface as primitive exposer

**n/a — and this is the surface where the packet table said so in advance**
("consumes, does not expose"), confirmed at the bytes. Developer Workspace owns no
stage of the composable-application journey (`odk-extension-apps.md` §2), exposes no
ODK primitive, and holds no descriptor.

One adjacency, because it is where a kit on-ramp would plausibly appear: **the ODK
CLI and scaffolds are Developer Console's**, not this surface's (canon :961-967,
meshed in packet 15). A developer might *run* `odk scaffold` in this console's
terminal — that is the console doing what a console does, not Developer Workspace
exposing a kit primitive. The distinction matters at cutover: no ODK on-ramp pane
belongs here.
