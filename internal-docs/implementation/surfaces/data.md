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
