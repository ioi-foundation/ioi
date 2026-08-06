# Data — implementation brief

Canonical route: `/data` · Owner: Data (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- Owner job: "supply the world-model: sources/syncs, data recipes, datasets, time-series
  and media sets — nothing enters a system's view without a governed recipe, and every
  data object carries its consent posture; consumes connector bindings from Connections,
  never owns them" (core-clients-surfaces.md:1319-1323). Connector/integration
  *registrations* are Developer Console inventory (:1392-1397); Data only consumes.
- Nav identity: "Data (supply the world-model: sources, syncs, data recipes, datasets,
  media sets, consent posture — Data/Knowledge family)" (core-clients-surfaces.md:839-840);
  route `/data` in the v2 ledger, no aliases per ADR 0022 (:876-880, :895).
  `Data / Knowledge` is an alias label, never a surface (:1744-1745, :2142).
- Two tool surfaces rehome here: Pipeline Builder / Recipe Builder → `Data / Recipes`,
  Data Connections → `Data / Sources` (core-clients-surfaces.md:1408-1409); tools launch
  under the owner with typed context, never as peer identities (:1428-1433).
- ODK is not an app; "data recipes and sources [surface] through Data" (:935-938).
- Learning boundary: Data (with Ontology) exposes "source-rights, consent, intended-use,
  recipe, and derivative-impact posture" (:1079-1080); Build lifecycle verb (:1121);
  System Design mode participant (:1648).
- Durable workflow/schedule truth belongs to Automations — "Scheduled services,
  workflow graph truth … belong to the top-level Automations surface" (:1029-1034);
  a pipeline scheduler is therefore not a Data build-list item.
- May never: separate runtime truth (:1470-1473); write canonical truth outside the
  daemon path (:4541-4543); no private runtime loop (:4543-4544); no credential material
  in declared truth — the daemon rejects plaintext secrets and credential-bearing
  endpoints outright (data_source_routes.rs:9-11, :288-304, :340-347).
- Layering (C-1..C-4): nothing on this surface serves a HypervisorSession. ODK
  `connector-sessions` are sealed substrate ladder records (hypervisor-daemon.rs:1538-1540),
  not HypervisorSessions — no `subject_attachments` binding arises; no named app-family
  session fields exist in the inherited modules (checked at the bytes).

## 2. Schema map

No Data-plane contract has an entry in
`docs/architecture/_meta/schemas/architecture-contract-registry.v1.json` (grep evidence:
no `data-source`/`odk`/`transformation`/`materializing` contract ids). The daemon
self-declares schema_versions per plane (e.g.
`ioi.hypervisor.odk.policy-bound-data-view.v1`, policy_bound_data_view_routes.rs:28-30).

| Canon object / contract | Registry / canon anchor | Daemon route(s) today |
|---|---|---|
| DataSource (declared registry record; kind vocabulary + credential POSTURE, never a secret) | canon :1319-1323; registry-absent; receipt `ioi.hypervisor.data-source-receipt.v1` (`surfaces/sources/index.mjs:75`) | list/create hypervisor-daemon.rs:2159-2163; overview :2164-2167; get :2168-2171. **No PATCH/DELETE — verified partial CRUD** → `route-missing` **W3** |
| DataRecipe ("nothing enters a system's view without a governed recipe" :1321) | canon :1906-1909 (DataRecipe refs in registration posture) | ODK CRUD :1592-1601; compatibility alias `GET /v1/hypervisor/data-recipes` :1629-1632 (retire W4) |
| ConnectorMapping (source fields → typed properties; the per-source semantic join) | registry-absent | :1372-1394 (CRUD + overview + health + history) |
| PolicyBoundDataView (authority envelope: allowed operations/subjects/property scope + retention/export/training/evaluation/publish postures; high-risk ops require named receipt obligations) | the byte-level carrier of canon consent posture (:1322); enums at policy_bound_data_view_routes.rs:35-56 | :1397-1419 (CRUD + overview + health + history) |
| TransformationRun (auditable PLAN/DRY-RUN contract; "executed/materialized are reserved for a future connector-adapter cut" — daemon's own comment :1420-1421) | registry-absent | list/create :1422-1426; overview :1427-1430; get/patch/delete :1431-1436; history :1437-1440; dry-run :1441-1444; cancel :1445-1448 |
| CapabilityLeasePlan (declares the exact lease scope; mints nothing, :1478-1480) | registry-absent | :1481-1503 (CRUD + overview + history + revoke) |
| MaterializingRun (the live authority crossing: real wallet-gated lease from the one gateway) | registry-absent; receipt `ioi.hypervisor.odk.materializing-run-receipt.v1` (`surfaces/pipeline/index.mjs:89`) | :1507-1537 (CRUD + overview + history + acquire-lease + release-lease + cancel); execute :1575-1578 |
| ConnectorSession (sealed credential crossing, `credential_required:true`, labels only) | registry-absent; receipt `ioi.hypervisor.odk.connector-session-receipt.v1` (`pipeline/index.mjs:90`) | :1541-1571 (CRUD + overview + history + open + release + cancel) |
| MaterializedObjectSet (output of one bounded receipted read; shared read with Ontology) | see ontology.md §2 | :1579-1591 (list/overview/get/DELETE — delete receipted, connector_execution_routes.rs:1112-1151) |
| Ingestion / extraction / connection-test authority (live source contact beyond the one bounded ladder read) | the daemon's own named boundary: "ingestion/extraction is not wired: an effectful pull requires a future wallet/authority crossing bound to admitted substrate (named, not built)" (data_source_routes.rs:252-254) | `route-missing` → **W3** |
| Syncs (canon names "syncs" :839) | nearest existing truth: materializing-run records (the sources module already counts them as sync activity, `sources/index.mjs:126-130`) | read view over :1507-1517 — no new family needed |
| Datasets / time-series / media sets (:1319-1321) | no daemon plane under Data (Foundry has its own dataset lanes, canon :2505) | `route-missing` → **W3** (file only after an owner ruling on Data-vs-Foundry split; do not duplicate Foundry truth) |
| Vendor connector catalog (reference's ~219-connector gallery) | daemon kind vocabulary is a fixed enum: 10 SOURCE_KINDS + 4 CREDENTIAL_POSTURES (data_source_routes.rs:40-57) | Developer Console connector registrations exist (:3022-3065) — projectable read, not a Data-owned build |

## 3. UI seed map

Registered T3 surfaces:

- **Pipeline Builder** — slug `pipeline`, route `/__ioi/pipeline`
  (`apps/hypervisor/surfaces/pipeline/index.mjs:17-19`). The governed-build workhorse:
  8 declared receipted runtime actions — admit-run, submit-lease-grant, cancel-run,
  release-lease, admit-session, submit-session-grant, release-session, execute
  (:93-102) — over the existing ODK authority only; the wallet grant rides one bounded
  opaque field, forwarded once, never persisted (:83-91). The handlers already encode
  the full authority grammar: 403 → typed challenge with public commitment hashes only
  (:123-130, :161, :201), 428 credential-unresolved (:200, :225), receipt-or-fail-closed
  on every stage (:151-152, :164-165, :228-229), idempotent resume from record status
  (:143-146, :181-183). Command table: Preview + Build enabled as read-navigation;
  Schedule + Deploy disabled with named reasons (:76-81). Control matrix at the bytes:
  83 entries — 12 daemon_action, 20 local_view, **40 disabled_reason** (the estate's
  largest dead cluster), 11 unsupported, every disabled/unsupported entry carrying its
  reason, malformed matrix fails serve boot (`pipeline/control-matrix.mjs:15-125`).
- **Data Connection** — slug `sources`, route `/__ioi/data/sources`
  (`surfaces/sources/index.mjs:24-29`). One receipted mutation: `declare`
  (POST `/v1/hypervisor/data-sources`, confirm-required, `dsr_` receipt fail-closed,
  :69-105). Declare form derives kinds/postures from daemon vocabulary
  (`overview.source_kinds`), fails closed when unreachable (:176-197); no secret field
  exists by design. Header tab row: **Sources active + 4 disabled named-gap tabs**
  (Syncs, Agents, Listeners, External stacks — :239-245). Selected-source panel renders
  real per-source connector mappings and 4 disabled record mutations with exact missing
  contracts (Edit/Delete/Test/Extract, :204-209). Sync counters are real materializing-run
  states (:126-130, :250-254). Census: 31 controls — 6 daemon_read, 3
  governed_receipted_action, 11 disabled_missing_authority (census: t3 `sources`).
- T2 native readouts feeding this owner: `/__ioi/odk` (the substrate authoring ladder),
  `/__ioi/lineage`, `/__ioi/vertex` (census t2: live 200s); work-ledger provenance links
  from every ladder record.
- T1 adapter carries no data-plane RPCs (grep `ioi-api-adapter.mjs`: only `recipes` →
  `/v1/hypervisor/recipes`, the session-launch-recipe plane, unrelated to DataRecipe).
- Live population note: the estate's one executed ladder produced the demo loan set
  (census pipeline workflow: Preview rows L-1/L-2/L-3 citing mset_18c15c5d9d5bfc0f /
  mrun_18c15c5cd7095669 / csn_18c15c5d306798fa) — the surfaces render honest empties
  otherwise.

### Corrections vs v0

- v0 said: `sources` has "3 of 4 tabs empty" — bytes show 5 tabs: Sources is live and
  the other **4 of 5** (Syncs/Agents/Listeners/External stacks) are disabled named-gap
  spans rendered in place with reasons, not empty panes (`sources/index.mjs:239-245`).
  And Syncs is not authority-missing like the others: the estate's sync truth already
  exists as materializing-run records the same module counts (:126-130).
- v0 said: "`data-sources` CRUD partial (no update/delete)" — **confirmed** at the bytes:
  GET list + POST create + GET overview + GET `:id` only (hypervisor-daemon.rs:2159-2171);
  the UI already names both absent routes verbatim in its disabled controls
  (`sources/index.mjs:205-206`).
- v0 said: "light up the 40 via authority client where routes exist" — at the bytes most
  of the 40 have **no** backing route (deploy, build-settings, branching/proposal,
  graph/node authoring, unit tests, favorites/organizations/color-grouping —
  `control-matrix.mjs`), and canon assigns scheduling to Automations (:1029-1034). The
  honestly wireable subset today: transform-plan authoring (TransformationRun CRUD +
  dry-run exists, :1422-1448 — the matrix reason "requires a TransformationRun authoring
  authority" is satisfiable as PLAN authoring), and `out.more-options` reset (DELETE
  `/odk/materialized-object-sets/:id` exists and is receipted, :1587-1591 — the census
  claim "GET-only … no retire/delete" is stale at the bytes).
- v0 said: "consent-posture badges from policy-bound-data-views" — bytes: PBV records
  carry no literal `consent` field; the carriers are the posture enums
  (retention/export/training/evaluation/publish-route) + allowed operations/subjects/
  property scope (policy_bound_data_view_routes.rs:35-56) plus the DataSource
  `credential_posture` vocabulary (data_source_routes.rs:52-57). Badges must project
  these named postures, not an invented "consent" scalar.

#### Addendum 2026-08-06 (mesh packet 7 — census reconciliation at `ba9e2ea0a`)

**`sources` census completed.** §3 listed "31 controls — 6 daemon_read, 3
governed_receipted_action, 11 disabled_missing_authority" — 20 of 31. Recounted:

| outcome | count |
|---|---|
| `daemon_read` | 6 |
| `local_view_interaction` | 7 |
| `governed_receipted_action` | **3** |
| `disabled_missing_authority` | 11 |
| `unsupported_reference_session` | 1 |
| `reference_data_only` | 3 |
| **total** | **31** |

**Pipeline matrix vs census — an 83/84 delta, resolved.** §3 gives the checked-in
control matrix as 83 entries; the census gives 84 controls. Both are correct and
they use different taxonomies. Recounted from bytes
(`surfaces/pipeline/control-matrix.mjs`, 125 lines): **83 entries — 12
`daemon_action`, 20 `local_view`, 40 `disabled_reason`, 11 `unsupported`.** The
census's 84 map onto them as 11 `daemon_read` + 1 `governed_receipted_action` = 12
`daemon_action`; 20 `local_view_interaction` = 20 `local_view`; 40
`disabled_missing_authority` = 40 `disabled_reason`; and 9
`unsupported_reference_session` + 3 `reference_data_only` = **12** against the
matrix's 11 `unsupported`. **The delta is one reference-only row the matrix does
not carry** — the census counts the vendor Foundry workspace sidebar as a control;
the matrix, which governs serve boot, scopes itself to the pipeline surface. The
matrix is the stricter artifact and the correct one to gate on; §6 clusters the
census's 84 so the reconciliation is complete either way.

Note also: pipeline holds **40 `disabled_missing_authority` controls — the
estate's largest dead cluster, 23% of all 172 disabled controls in the 563
census** — and every one carries its reason at the bytes, with a malformed matrix
failing serve boot (`control-matrix.mjs:15-125`).

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Sources: declared-source table + census (kinds, postures, wired:false boundary) | DataSource list/overview (hypervisor-daemon.rs:2159-2167) | wired read | `wired-read` |
| Sources: `declare` (New source / Connect card) | POST `/v1/hypervisor/data-sources` → `dsr_` receipt (`sources/index.mjs:69-105`) | wired-action-receipted | `wired-action-receipted` — move onto the W0.3 lease client encoding (403/428 paths currently unused on this plane; daemon refusals already typed) |
| Sources: Edit / Delete source | PATCH/DELETE `:id` | disabled named gap (routes absent) | `disabled-named-gap` → after W3 PR 6, `wired-action-receipted` with confirm |
| Sources: Test connection / Extract | ingestion authority (daemon's named gap, data_source_routes.rs:252-254) | disabled named gap | `disabled-named-gap` → W3 ingestion family; extract remains the governed ladder until then |
| Sources: Syncs tab | MaterializingRun list/overview (:1507-1517) | disabled named gap | `wired-read` (W1 — the module already computes the counters from this plane) |
| Sources: Agents / Listeners / External stacks tabs | none; reference-only lanes | disabled named gaps | `delete` at cutover |
| Sources: creator/edited-by/viewed columns + Favorites | registry lacks principal/view fields | named-gap dashes (`sources/index.mjs:142-144`) | `disabled-named-gap` → optional W3 field add on the registry record |
| Sources: connector gallery (source-type picker) | daemon SOURCE_KINDS vocabulary (served via overview :2164-2167) | wired (10 kinds) | `wired-read`; optionally enrich with a Developer Console connector-registration read projection (routes :3022-3065) — display only, Data never owns registrations (:1322-1323) |
| Sources/Recipes: consent-posture badges | PBV postures + DataSource credential_posture (§2) | partial (posture text in rows) | `wired-read` badge vocabulary shared with Ontology inspectors (W1) |
| Pipeline: ladder graph, node inspectors, file tree, warnings, preview rows | the seven ladder reads (mappings, policy views, transformation-runs, lease plans, materializing-runs, connector-sessions, sets) | wired read | `wired-read` (read-projection client W0.3; build-stage updates via `/v1/event-streams` + `/v1/subscriptions`, no new per-resource SSE) |
| Pipeline: governed Build — 8 stage actions | MaterializingRun/ConnectorSession POST lanes (§2) with `mrr_`/`csr_` receipts | wired-action-receipted, resumable, fail-closed | `wired-action-receipted` — re-encode through the shared CapabilityLease client (the 403-challenge/428-credential/receipt grammar it hand-rolls today, `pipeline/index.mjs:123-130, :200-201`) |
| Pipeline: transform strip (Transform/Join/Union/Split/Edit) | TransformationRun create/patch/dry-run (:1422-1448) | disabled named gap | `wired-action-receipted` (W2 — PLAN authoring only; execution stays reserved per :1420-1421) |
| Pipeline: `out.more-options` reset / re-materialize | DELETE `/odk/materialized-object-sets/:id` receipted (:1587-1591) | disabled named gap (stale census reason) | `wired-action-receipted` (W2, confirm; projection reset is server-side) |
| Pipeline: Schedule cmd + `rail.schedules` | Automations owns schedule truth (:1029-1034) | disabled named gap | `delete` on this surface at cutover; replace with a link to the owning Automations view |
| Pipeline: Deploy cmd + `rail.deploy` + build-settings | no daemon plane; no canon Data requirement | disabled named gap | `delete` at cutover unless a canon change names a Data deploy object |
| Pipeline: Proposals/branch tabs + `rail.changes` + Propose | ontology proposal/branch family (route-missing, ontology.md §2) | unsupported/disabled | `disabled-named-gap` → read view after the W3 family lands (shared with Ontology) |
| Pipeline: graph/node authoring, annotations, marquee, layout, import-model, LLM/AIP lanes, unit tests | no daemon planes; unit tests owned by Evaluations, models by Foundry | disabled/unsupported with reasons | `delete` at cutover (keep the owner cross-links) |
| Recipes view (new under `/data/recipes`) | ODK DataRecipe CRUD (:1592-1601) | daemon-complete, UI only in `/__ioi/odk` readout | `wired-read` list/detail in W1; `wired-action-receipted` create/patch in W2 |

No element binds a HypervisorSession; nothing requires `subject_attachments` (§1).

## 5. Ordered PR list

1. **W1** — Mount `/data` in the v2 shell: Sources at `/data/sources`, Pipeline/Recipe
   Builder at `/data/recipes` (canon placement :1408-1409), modules rehomed unchanged
   (seed-preservation invariant); legacy `/__ioi/pipeline` + `/__ioi/data/sources` keep
   serving until step 9.
2. **W1** — Syncs tab becomes a real read view over materializing-runs; recipes
   list/detail read view over ODK DataRecipe; honest empties everywhere.
3. **W1** — Consent-posture badge vocabulary: project PBV
   retention/export/training/evaluation/publish postures + DataSource
   credential_posture onto source rows, recipe details, and ladder nodes (shared
   component with Ontology inspectors).
4. **W1** — Reads move to the W0.3 read-projection client; build-stage/run updates
   subscribe on the M5 event plane (`/v1/event-streams` + `/v1/subscriptions`).
5. **W2** — The 8 Build-ladder actions and `declare` re-encode through the shared
   CapabilityLease authority client (uniform 403 wallet challenge → 428 credential →
   receipted); zero behavior change to daemon contracts.
6. **W2** — Light the honestly wireable dead controls: transform-PLAN authoring
   (create/patch/dry-run TransformationRun) and materialized-set reset (receipted
   DELETE); both confirm-gated.
7. **W3 (backend)** — DataSource PATCH + DELETE (receipted, fail-closed, same
   plaintext-secret rejections), optional principal fields; then enable Edit/Delete
   source. Serialize on `hypervisor-daemon.rs` (router merge hotspot).
8. **W3 (backend)** — Ingestion/extraction authority crossing (the daemon's own named
   gap: wallet/authority-bound effectful pull on admitted substrate); then Test
   connection/Extract and true sync scheduling **in Automations** (Data links, never
   owns the schedule). Proposal/branch read view follows the Ontology-owned W3 family.
9. **W4** — Cutover: typed 410s for `/__ioi/pipeline` + `/__ioi/data/sources` per the
   6-step rule; delete the `delete`-marked lanes (§4); retire the daemon alias
   `GET /v1/hypervisor/data-recipes` (hypervisor-daemon.rs:1629-1632); captures stay
   dormant seeds per `ported-seed-preservation.v1.json`.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; module cites are
under `apps/hypervisor/surfaces/`.

**Tier 4: none** — no vault names Data as owner.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `pipeline` — Pipeline Builder** — `surfaces/pipeline/index.mjs:17-19`, route `/__ioi/pipeline`; protected seed, class `daemon_wired`; **the only `atlas_verified` interaction-parity surface in the registry** | **84 census controls** (matrix: 83 — see the addendum). The governed-build workhorse: 8 declared receipted runtime actions (`:93-102`) | Data owns data recipes, transformation runs, policy-bound views, freshness/lineage/quality posture (`domain-ontologies-and-data-recipes.md`, "Product and Domain Roles") | see cluster rows | — |
| ↳ **governed build ladder** | 12 `daemon_action` in the matrix = 11 `daemon_read` + **1 `governed_receipted_action`** (Build) in the census. The eight actions — admit-run, submit-lease-grant, cancel-run, release-lease, admit-session, submit-session-grant, release-session, execute — encode the full authority grammar at the bytes: **403 → typed challenge carrying public commitment hashes only** (`:123-130`, `:161`, `:201`), **428 credential-unresolved** (`:200`, `:225`), **receipt-or-fail-closed at every stage** (`:151-152`, `:164-165`, `:228-229`), idempotent resume from record status (`:143-146`, `:181-183`), and the wallet grant riding **one bounded opaque field, forwarded once, never persisted** (`:83-91`) | receipted transformation execution under wallet-gated authority | **rehome** — this is the estate's most complete authority implementation. Four properties must survive verbatim: challenge-carries-hashes-only, forwarded-once-never-persisted, receipt-or-fail-closed, and idempotent resume | W1 · W2 |
| ↳ canvas + navigation cluster | 20 `local_view_interaction` (panning, canvas search, zoom in/out/fit, drag pan, ctrl+wheel, keyboard node nav, legend collapse, category eye, tray chevron, node detail sub-tabs, search outputs, output card select, selection/suggestions tabs, panels for outputs/search/file-tree, copy record ref) | local UI state is legitimately local | **rehome** — local view state needs no daemon binding and must not acquire one | W1 |
| ↳ daemon-read cluster | 11 `daemon_read` (Preview, Lineage, Ontology Manager, Add data, node click select, node context Open, Preview tab on selection, pipeline warnings tab, view lineage, edit output settings, pipeline picker IOI-only) | reads over the ODK ladder | **rehome** | W1 |
| ↳ **graph-authoring cluster — the estate's largest dead cluster** | **40 `disabled_missing_authority`**, each carrying its reason at the bytes; a malformed matrix **fails serve boot** (`control-matrix.mjs:15-125`). Includes Transform/Join/Union/Split/Reusables, node quick-actions, snapshot sampling, deploy/build-settings/schedules/unit-tests/sources panels, layout and selection tools, and the four AIP lanes (Use LLM, Generate, Explain, Import trained model) | canon gives Data recipe authoring; the AIP lanes are **vendor faculties** (standing P2 gate) | **retire-at-cutover** for the AIP lanes and the vendor chrome menus (File/Settings/Help/Share/Actions) · **blocked-missing-route** for the recipe-authoring verbs: a `DataRecipe` is immutable and content-addressed, and no authoring/revision route exists — the disabled state is correct, and 40 reasons carried at the bytes is the honest-gap discipline other surfaces should copy | W3 · W4 |
| ↳ branch / proposal / history cluster | 9 `unsupported_reference_session` (Graph/Proposals/History tabs, undo, redo, branch selector, additional branch actions, saved indicator, Propose, modify build settings, edge insert) | recipe **revisions** are canon (immutable successors); reference branching is not | **retire-at-cutover** — the reference's branch model is not the successor-revision model canon specifies; reviving it would model recipes as mutable | W4 |
| ↳ reference chrome | 3 `reference_data_only` (favorite star, batch badge, vendor Foundry workspace sidebar) | carve-out | **retire-at-cutover** | W4 |
| **T3 `sources` — Data Connection** — `surfaces/sources/index.mjs:24-29`, route `/__ioi/data/sources`; protected seed, class `daemon_wired` | **31 controls** (full breakdown in the addendum) | Data owns source inventory, connector mappings, freshness/access posture | see cluster rows | — |
| ↳ **declare lane — governed** | **3 `governed_receipted_action`**: New source, Connect to external system, source-type cards matching daemon kinds. `declare` POSTs `/v1/hypervisor/data-sources`, confirm-required, `dsr_` receipt **fail-closed** (`:69-105`); the form derives kinds/postures from daemon vocabulary (`overview.source_kinds`) and **fails closed when unreachable** (`:176-197`); **no secret field exists by design** | source declaration is a governed act; credentials never transit the surface | **rehome** — the no-secret-field-by-design property and the derive-vocabulary-or-fail-closed rule must survive | W1 · W2 |
| ↳ catalog + semantic panel cluster | 6 `daemon_read` (Sources tab, sync-counter cluster over **real materializing-run states** `:126-130`/`:250-254`, recents row click, selected-source semantic panel `?dataSource=`, declared-source census with by-kind/by-posture chips, owner-family links) | source inventory + connector mappings per source | **rehome** | W1 |
| ↳ local view cluster | 7 `local_view_interaction` (app icon nav, view Recents, view-all, table column headers, select-source-type search, cancel declare, reference/provenance lane links) | local state | **rehome** | W1 |
| ↳ **absent tabs + record mutations** | 11 `disabled_missing_authority`: the four header tabs (Syncs, Agents, Listeners, External stacks, `:239-245`), recent installations, help, upload static data, input/generate data, view Favorites, creator/last-edited columns, and **~200 branded connector cards** | DataSource PATCH/DELETE and ingestion/extraction/connection-test are **route-missing** (§2, W3); the daemon names its own `wired:false` boundary | **blocked-missing-route** for the four record mutations and the tabs · **retire-at-cutover** for the ~200 branded connector cards, which advertise integrations the estate does not have and would be fabrication if enabled | W3 · W4 |
| ↳ reference example lanes | 3 `reference_data_only` (hero band, walkthrough rows, example marketplace cards) + 1 `unsupported_reference_session` (vendor sidebar) | **no fixture data may be presented as truth**; example install is a Packages path | **retire-at-cutover** | W4 |
| **T2 ODK authoring ladder** — `/__ioi/odk` (serve `:9739`) | shared with Ontology; T2 census 36 controls, 0 disabled | ODK is the kit, not an application (:935-940) | **rehome (split by owner)** — the data-recipe, connector-mapping, policy-bound-view, transformation-run, and source planes surface under `/data`; the ontology planes under `/ontology` (`ontology.md` §6 records the same split from the other side) | W1 |
| **T5 `/__apps/pipeline`** — capture, owner Data, `reference_capture`, capture state `blocked_missing_capture`, grammar `editor_canvas`, high_value, `reboundLane: null` (`harvest-seed-inventory.mjs:41`) | not in the 563 | the Pipeline Builder above is the functional surface | **blocked-missing-capture** — the note says "boots as classified from the local capture", but the parity matrix records `blocked_missing_capture`; the functional surface is unaffected | — |
| **T5 `/__apps/sources`** — capture, `reference_capture`, capture state `shell_only`, grammar `table_list`, high_value, `reboundLane: null` (`:40`) | not in the 563; the live surface links it as a provenance lane | **pattern-harvest** — the Sources/Syncs/Listeners IA is the grammar behind the four disabled tabs; harvesting the shape does not license enabling them | — |
| **T5 `/__apps/ingest`** — capture, `reference_capture`, capture state `shell_only`, grammar `wizard`, high_value, `reboundLane: null`, "source-first pipeline wizard; unbound" (`:39`) | not in the 563 | a guided source→recipe wizard is canon's "guided views should come first" (`domain-ontologies-and-data-recipes.md`) | **pattern-harvest** — the wizard grammar is the right shape for the guided lane, and it is the only capture in Data's set that maps to a canon *preference* rather than a canon pane | — |
| **T5 `/__apps/dataset`** — capture, `reference_capture`, capture state `shell_only`, grammar `table_list`, aux, `reboundLane: null` (`:42`) | not in the 563 | the datasets/time-series/media-sets plane needs a **Data-vs-Foundry owner ruling** (§2, W3) | **blocked-missing-route** — and blocked on a ruling before a route: dispositioning it further would pre-empt the owner decision | W3 |

**Census reconciliation.** Data's two T3 surfaces carry **115 of the 563** baseline
controls: `pipeline` 84 (12 + 20 + 11 + 40 + 9 + 3, six cluster rows) and `sources`
31 (3 + 6 + 7 + 11 + 4, five cluster rows). Both sums exact.

Two estate-level facts fall out. `pipeline` holds **40 of the 172
`disabled_missing_authority` controls — 23% of every disabled control in the
estate**, and `sources` adds 11, so Data owns 51 (30%). And Data's **4 governed
controls** (1 + 3) put it third behind Ontology (13) and Governance (3, tied).

**Disposition summary.** 8 rehome (one splitting by owner) · 2 pattern-harvest ·
5 retire-at-cutover · **3 blocked-missing-route** · **1 blocked-missing-capture**.

## 7. Ontology wiring

Data is the semantic plane's **supply side**: it owns the primitives that turn
sources into ontology-bound objects. Its wiring is second only to Ontology's.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Sources catalog + declare | `DataSource` (Data-owned; **not** a semantic-plane envelope) | `/v1/hypervisor/data-sources` | **Read + Write (receipted `dsr_`)** | the outermost input node of the lineage graph; no secret field by design |
| Selected-source connector mappings | `ConnectorMapping` (`ConnectorMappingEnvelope`) | `/v1/hypervisor/odk/connector-mappings` (+ `/:id`, `/overview`, `/:id/health`, `/:id/history`) | Read (write plane exists at the route, not on this surface) | canon: a connector payload is source material, **not canonical domain truth**, until a ConnectorMapping and DataRecipe bind it (non-negotiable 2) |
| Pipeline recipes | `DataRecipe` (`DataRecipeEnvelope`) | `/v1/hypervisor/odk/data-recipes` (+ `/:id`) — **and a GET-only compatibility alias at `/v1/hypervisor/data-recipes`** (`hypervisor-daemon.rs:1639`, same handler) | Read | **Two paths, one plane.** The alias exists for previously-404 top-level paths (`hypervisor-daemon.rs:1631-1633`); it is not a second family |
| Policy-bound views | `PolicyBoundDataView` | `/v1/hypervisor/odk/policy-bound-data-views` (+ `/:id`, `/overview`, health, history) | Read | canon gates read/transform/distill/train/evaluate/export/route through these (non-negotiable 4); posture badges must project the **named** enums, never an invented "consent" scalar (§3 correction) |
| Transformation runs | `TransformationRun` + transformation receipts | `/v1/hypervisor/odk/transformation-runs` (+ dry-run, cancel, history) | Read + governed execute | every run must bind the exact recipe revision/hash **and** the identical semantic-component snapshot (non-negotiable 3) |
| Materializing runs + object sets | `MaterializedObjectSet` | `/odk/materializing-runs`, `/odk/materialized-object-sets` | Read + governed lease/execute | sync counters are real materializing-run states, not derived estimates |
| Ontology projections | `OntologyProjection` (`OntologyProjectionEnvelope`) | `/odk/ontology-projections` | Read | must expose freshness, recipe version, policy, source watermark (non-negotiable 8) |
| **`/v1/hypervisor/recipes`** (`hypervisor-daemon.rs:1226`) | **not a DataRecipe at all** — `DevelopmentEnvironmentRecipe`, handled by `recipe_routes` | `/v1/hypervisor/recipes` (+ `/:id`) | — | **Recorded as a naming-boundary finding.** `term-boundaries.md` says "Recipe" is always owner-qualified and a bare generic recipe family is a defect; this route holds the unqualified name for an environment object while the DataRecipe plane needs a prefix to disambiguate. Filed to X-2 — a route rename, not a mesh decision |
| **Write side** | `DataSource` declaration only, on this surface | — | — | recipe/mapping/view authoring routes exist but no pane writes them; the 40 disabled graph-authoring controls are that gap rendered honestly |

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

Two canonical patterns — `data_recipe_builder` and `connector_mapping_editor` —
exist for exactly these panes. Both are **exempt**, for the write-semantics reason
`ontology.md` §8 found, which now has its second and third instances.

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Sources catalog + declared-source census | `list_detail` | **descriptor-expressible** | binds `DataSource` + `ConnectorMapping` refs, daemon API deps, read-only action set |
| Selected-source semantic panel | `object_view` | **descriptor-expressible** | binds the source's mappings and posture enums |
| Pipeline graph canvas (read side: nodes, lineage, preview) | `graph` | **descriptor-expressible** | binds recipe, run, object-set, and projection refs — the same primitive set Provenance's lineage lens binds (`provenance.md` §8) |
| Pipeline graph canvas (authoring: Transform/Join/Union/Split, node mutations) | `data_recipe_builder` | **exempt — no write semantics in the descriptor** | the pattern is named for this pane. A descriptor cannot express recipe **authoring**: it has no revision successor semantics, no content-hash commitment, no receipt obligation on write |
| Connector-mapping editing | `connector_mapping_editor` | **exempt — no write semantics in the descriptor** | second pattern named for a pane it cannot express |
| Governed build ladder (admit-run → grant → execute → release) | — | **exempt — authority-crossing** | the 403-challenge / 428-credential / receipt-or-fail-closed grammar is admission, and descriptors carry none of it |

**Three expressible panes, and the sharpest evidence yet for the write-semantics
finding**: `data_recipe_builder` and `connector_mapping_editor` are two of the
eleven canonical patterns, both named for Data's authoring panes, and **neither can
express the pane it is named for**. With `object_editor` (`ontology.md` §8), three
of the eleven patterns are write-shaped and none of the three is usable. Filed to
X-2 as one finding with three instances.

Zero panes `descriptor-rendered` today.

### (b) This surface as primitive exposer

**Data owns journey stage 2** — bind the data.

| Journey stage (`odk-extension-apps.md` §2) | What Data contributes |
|---|---|
| **2 — bind the data** | `DataRecipe` revisions, `ConnectorMapping` revisions, `PolicyBoundDataView`s, `TransformationRun`s and their receipts, `MaterializedObjectSet`s, and `OntologyProjection`s — the refs a descriptor's `data_recipe_refs`, `connector_mapping_refs`, `policy_bound_data_view_refs`, and `ontology_projection_refs` fields name |

Two boundaries:

- **A policy-bound view is a ceiling, not a grant.** A generated application naming
  a `PolicyBoundDataView` ref inherits that view's limits; it does not acquire
  permission to read, train, or export. Canon is explicit that a permitted view
  alone is not training consent.
- **Recipes are immutable; a generated app pins a revision.** A descriptor naming
  `data-recipe://.../revision/...` binds that exact revision and its
  semantic-component snapshot. It must never resolve a head — which is also why the
  authoring panes above cannot be descriptor-expressed: authoring creates successors,
  and the descriptor has no successor semantics.
