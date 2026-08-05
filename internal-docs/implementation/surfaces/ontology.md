# Ontology — implementation brief

Canonical route: `/ontology` · Owner: Ontology (owner application)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- Owner job: "the semantic world-model systems act on: ontologies (object/link/action
  types), functions, value types, object exploration and saved object sets, ontology
  health and history — every semantic object carries its consent/visibility ladder"
  (core-clients-surfaces.md:1313-1317). Saved object sets are canon-required inventory,
  not a nice-to-have (:1315).
- Route `/ontology` is in the v2 target-route ledger; no compatibility aliases — retired
  paths fail with a typed refusal per ADR 0022 (core-clients-surfaces.md:876-880, :894).
- Two tool surfaces rehome here: Ontology Manager → `Ontology / Schema`, Object
  Explorer → `Ontology / Explore` (core-clients-surfaces.md:1410-1411). Tools stay
  owner-bound, launch under the owner and current context, and never become peer product
  identities (:1428-1433); a tool has exactly one primary owner (:1913-1916, anti-pattern
  :4731).
- ODK is NOT an application: its object planes are substrate; "ontologies and value
  types [surface] through Ontology" (core-clients-surfaces.md:935-938).
  `OntologySurfaceDescriptor` is registration input, never a launchable app (:1928-1929).
- Surface registrations carry ontology posture: DomainOntology refs,
  CanonicalObjectModel refs, DataRecipe refs, PolicyBoundDataView refs,
  OntologyProjection refs, OntologySurfaceDescriptor refs (core-clients-surfaces.md:1906-1909).
- Ontology (with Data) exposes "source-rights, consent, intended-use, recipe, and
  derivative-impact posture" as learning-boundary projections (core-clients-surfaces.md:1079-1080);
  it sits in the Build lifecycle verb (:1121) and in a System workspace's Design mode (:1648).
- `Ontology Studio` is a retired alias label, never a surface (core-clients-surfaces.md:1744-1747, :2142).
- May never: separate runtime truth ("governed projections and control surfaces" only,
  :1470-1473); no client writes canonical truth outside the daemon path (:4541-4543); no
  private runtime loop beside the daemon (:4543-4544). Action-type declarations carry no
  execution authority — execution is a daemon authority crossing that does not exist yet
  (census, and the surface's own standing boundary: `surfaces/object-explorer/index.mjs:27-29`).
- Layering (C-1..C-4, implement-never-re-decide): no element on this surface serves a
  `HypervisorSession`; ODK "connector sessions" are substrate ladder records, not
  HypervisorSessions, so no `subject_attachments` binding arises here. No named
  app-family session fields exist in the four inherited modules (checked at the bytes).

## 2. Schema map

No ODK/ontology contract has an entry in
`docs/architecture/_meta/schemas/architecture-contract-registry.v1.json` (grep: no
`odk`/`ontology`/`domain-ontology` contract ids; only autonomous-system materialization
families match). The daemon self-declares `ioi.hypervisor.odk.*` schema_versions in the
route modules. Registering these is part of the known M6 surface-record gap, not this
surface's build-list.

| Canon object / contract | Registry / canon anchor | Daemon route(s) today |
|---|---|---|
| DomainOntology (draft + CanonicalObjectModel: object/link/action/value types, functions) | canon :1313-1317, :1906-1909; registry-absent (daemon `ioi.hypervisor.odk.ontology-receipt.v1`, `surfaces/ontology-manager/index.mjs:54`) | list/create hypervisor-daemon.rs:1352-1355; get/patch/delete :1356-1361; health :1362-1365; history :1366-1369 |
| OntologyProjection (declared explorer/search shape) | canon :1908; daemon comment "the explorer/search/read SHAPE" hypervisor-daemon.rs:1449-1450 | list/create :1451-1455; overview :1456-1459; get/patch/delete :1460-1465; history :1466-1469; recheck :1470-1473; retire :1474-1477 |
| MaterializedObjectSet (the only object-instance carrier; canon "saved object sets" nearest existing plane) | canon :1315; registry-absent | list :1579-1582; overview :1583-1586; get/DELETE :1587-1591 (delete is receipted + resets the tied projection, connector_execution_routes.rs:1112-1151) |
| ConnectorMapping (source fields → typed object properties; read-only in Manager) | registry-absent | list/create :1372-1376; overview :1377-1380; get/patch/delete :1381-1386; health :1387-1390; history :1391-1394 |
| ODK overview + edit vocabulary (`odk_vocabulary`) | daemon truth only | GET :1348-1351 |
| Ontology proposal/branch/merge plane (Proposals tab, History-as-branch, Propose, branch selector/actions) | no canon object named; product need per inherited seeds | `route-missing` — grep of hypervisor-daemon.rs finds no ontology proposal/branch routes (only threads/intelligence/memory/scm proposals, :885-889, :1699-1725, :1749-1759, :3098) — **W3** |
| Object-instance search plane (full-text + facets over instances) | census gap; canon "object exploration" :1315 | `route-missing` — **W3** |
| Per-principal saved explorations/lists/favorites | canon-required "saved object sets" :1315 | `route-missing` — **W3** |
| Action-type execution against instances | declarations only in COM; execution = daemon authority | `route-missing` — **W3** (sequenced behind the TransformationRun/writeback authority; see data.md) |
| Compatibility list alias `GET /v1/hypervisor/ontologies` | ADR 0022 no-alias rule :876-880 | hypervisor-daemon.rs:1623-1628 — retire at W4 cutover |

## 3. UI seed map

Registered T3 surfaces (registry slugs `schema`, `explorer`; module dirs differ):

- **Ontology Manager** — slug `schema`, route `/__ioi/ontology/manager`
  (`apps/hypervisor/surfaces/ontology-manager/index.mjs:12-17`). The estate's deepest
  wired surface: census 60 controls — 21 daemon_read, 13 governed_receipted_action, 15
  disabled_missing_authority, 5 unsupported, 3 reference_data_only (census:
  inventory.v1.json t3 `schema.control_census`). Seven declared receipted actions at the
  bytes: create-ontology, update-metadata, upsert-value-type, upsert-object-type,
  upsert-property, upsert-link-type, upsert-action-type — all through POST/PATCH
  `/odk/domain-ontologies` under optimistic concurrency (`expected_revision`), each
  returning `ioi.hypervisor.odk.ontology-receipt.v1` and failing closed on a missing
  receipt (`ontology-manager/index.mjs:53-64, :80-141`). Eleven-section IA (discover,
  object-types, properties, value-types, link-types, action-types, functions, health,
  resources, configuration, create — `surfaces/ontology-context.mjs:23`); unknown
  section fails closed. Wired: authoring + section nav + health/history + resource
  inspectors (connector-mappings + policy views loaded read-only, index.mjs:22-31).
  Dead/disabled: deletion lanes, Proposals/branch, shared-property/groups/interfaces,
  in-Manager datasource authoring, global search/palette, OaC repo (census
  `missing_authority_contracts`).
- **Object Explorer** — slug `explorer`, route `/__ioi/ontology/explorer`
  (`object-explorer/index.mjs:12-17`). Read-only by declared contract: `actions = []`
  (:29). Census 35 controls — 9 daemon_read, 0 receipted, 8 disabled, 12 unsupported.
  Wired reads: object-type catalog with working server-side `?q=` filter, shortcuts =
  real top materialized sets, object-set catalog, semantic type/set inspectors with real
  row preview + provenance refs (pre_output_receipt_ref, run/session refs, redacted
  source origin) (:52-107, :187-243). Every reference per-user/instance lane is a
  disabled named gap in place (:112-176). Loads real daemon truth via the shared model:
  `/odk/overview` + `/odk/domain-ontologies` + `/odk/ontology-projections` +
  `/odk/materialized-object-sets` (`ontology-context.mjs:91-107`).
- Shared semantic context kit: URL-carried typed context (14 keys, bounded values,
  fail-closed parsing) + owner link builders across
  Manager/Explorer/Pipeline/lineage/vertex/work-ledger (`ontology-context.mjs:18-62`).
- T2 native readouts feeding this owner: `/__ioi/odk` (substrate ladder, census: 36
  controls), `/__ioi/lineage`, `/__ioi/vertex` (census: t2 `nat-odk`, `nat-lineage`,
  `nat-vertex`; live 200s). Vendor captures `/__apps/schema`, `/__apps/explorer` are
  secondary reference grammars, never rebound surfaces (serve-product-ui.mjs:3453, :5571-5574).
- T1 adapter carries no ontology RPCs (grep of `ioi-api-adapter.mjs`: only `recipes` →
  `/v1/hypervisor/recipes`, a launch-recipe plane) — the SPA shell reaches this family
  only through the T3/T2 lanes above.

### Corrections vs v0

- v0 said: explorer is "read-only, currently degenerate 'Loan' rows" and the work is to
  "fix explorer's object-set reads (`materialized-object-sets` routes exist)" — bytes
  show the reads are already wired and fail-closed: the Explorer loads
  `/v1/hypervisor/odk/materialized-object-sets` and renders real sets, counts, and row
  previews (`ontology-context.mjs:91-107`, `object-explorer/index.mjs:97-107, :218-243`).
  The "Loan" rows are the estate's one real demo materialized set (census pipeline
  workflow: rows L-1/L-2/L-3 "First/Second/Third Loan", mset_18c15c5d9d5bfc0f), i.e., a
  data-population fact, not a read defect. The actual gap is the missing
  instance-search/exploration plane (route-missing, §2).
- v0 said: "enable the disabled proposal/branch plane through the authority client" —
  impossible as stated: no ontology proposal/branch daemon routes exist (grep evidence,
  §2). This is a W3 backend build, not a W2 wiring task.
- census (2026-07-30) said: "Deletion authority: DELETE /v1/hypervisor/odk/domain-ontologies/{id}
  … not yet contracted" and "materialized-object-sets exposes GET-only routes … no POST
  retire/delete exists" — bytes show both DELETEs exist today:
  hypervisor-daemon.rs:1356-1361 (`.delete(handle_odk_ontology_delete)`) and
  :1587-1591 (`.delete(handle_set_delete)`). Set delete is receipted
  (`materialized_output_removed`) and resets the projection
  (connector_execution_routes.rs:1112-1151); ontology delete is a bare unreceipted
  `json_del` (odk_routes.rs:253-256, :1063-1068) — an effectful mutation with no receipt,
  a defect to fix before any UI enables it.
- v0 said: "Backend: ODK domain-ontologies/projections/mappings/views complete" —
  confirmed at the bytes, with the additions that projections also carry
  recheck/retire actions (hypervisor-daemon.rs:1470-1477) and mappings a full
  CRUD+health+history set (:1372-1394).

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Manager ontology picker + 11 section nav + definition selection | DomainOntology list/get (hypervisor-daemon.rs:1352-1361); URL context (`ontology-context.mjs:18-42`) | wired | `wired-read` (read-projection client, W0.3) |
| Manager 7 authoring actions (create/update-metadata/5 upserts) | POST/PATCH `/odk/domain-ontologies` + `ioi.hypervisor.odk.ontology-receipt.v1` (`ontology-manager/index.mjs:53-64`) | wired, receipted, fail-closed on missing receipt | `wired-action-receipted` — re-plumb through the W0.3 CapabilityLease client (this plane today mutates without a wallet challenge; keep daemon truth, adopt uniform 403/428/receipt encoding) |
| Manager health + history panes | `:id/health`, `:id/history` (hypervisor-daemon.rs:1362-1369) | wired read | `wired-read` |
| Manager resources pane (connector-mappings, policy views, projections, sets) | mappings :1372-1394; policy views :1397-1419; projections :1451-1477; sets :1579-1591 | wired read (loaded in `ontology-manager/index.mjs:22-31`) | `wired-read` |
| Projection recheck / retire controls | POST `:id/recheck`, `:id/retire` (:1470-1477) | not surfaced (substrate readout only, `/__ioi/odk`) | `wired-action-receipted` (W2, lease client) |
| Cleanup / delete-ontology / delete-definition lanes | DELETE `:id` exists but unreceipted (odk_routes.rs:1063-1068, :253-256); definition-delete-in-COM has no route | disabled named gap (census) | `disabled-named-gap` until the W3 receipt fix + definition-delete land; then `wired-action-receipted` with confirm |
| Manager Proposals tab, History-as-branch, Propose, branch selector | none — route-missing (§2) | disabled named gap | `disabled-named-gap` → wire after W3 proposal/branch family |
| New → Shared property / Group / Interface / OaC repo | no canon object, no route | disabled named gap | `delete` at cutover (reference-only lanes; canon COM has no groups/interfaces, :1313-1317) |
| Header Search resources / ctrl+K palette | product-surface compiler + search projection (W0.2) | disabled named gap | `wired-read` after W0.2 |
| Explorer type catalog + `?q=` filter + shortcuts + set catalog | the four shared reads (`ontology-context.mjs:91-107`) | wired read | `wired-read` |
| Explorer semantic type/set inspectors (props, links, action declarations, row preview, provenance refs) | DomainOntology + MaterializedObjectSet reads | wired read | `wired-read` |
| Explorer "All Ontologies" scope selector | DomainOntology list exists | disabled named gap (`object-explorer/index.mjs:116`) | `wired-read` (W1 — scoped catalog param; the data already loads) |
| Explorer WAYF "Search for objects", Filter-by facets, Search instances | object-instance search plane | disabled named gap (:123-124, :214) | `disabled-named-gap` → W3 family |
| Explorer Explorations/Lists/Recents/Favorites/"Your object sets"/New exploration | per-principal saved-set plane | disabled named gap (:113-115, :139-144, :167-172) | `disabled-named-gap` → W3 family (canon-required, :1315) |
| Explorer / Manager "Execute action" / "Evaluate function" | execution authority | disabled named gap (:214, census) | `disabled-named-gap` → W3 (behind TransformationRun/writeback authority) |
| Cross-links: Pipeline node / Lineage / Vertex / Provenance / Sources per record | link builders (`ontology-context.mjs:50-62`) | wired navigation | `wired-read` (retarget hrefs to v2 routes at cutover) |
| Consent/visibility ladder on every semantic object (canon :1316-1317) | nearest carriers: PBV postures + policy view refs (see data.md §2) | absent as a rendered ladder | `wired-read` badge row (W1: project PBV postures + credential postures onto type/set inspectors); honest absence where no policy view binds |

No element on this surface serves a HypervisorSession; nothing binds
`subject_attachments` (see §1 layering note).

## 5. Ordered PR list

1. **W1** — Mount `/ontology` in the v2 shell: Manager at `/ontology/schema`, Explorer
   at `/ontology/explore`, both rehomed modules unchanged (seed-preservation invariant);
   legacy `/__ioi/ontology/*` keeps serving until step 8.
2. **W1** — Explorer ontology-scope selector goes live (scoped catalog over the already
   loaded DomainOntology list); wire the consent/visibility badge row from bound policy
   views onto the type/set inspectors (honest absence when none binds).
3. **W1** — Manager reads move to the shared read-projection client (W0.3); no behavior
   change; status updates for long ladders subscribe via `/v1/event-streams` +
   `/v1/subscriptions` (M5 plane), never new per-resource SSE.
4. **W2** — Manager authoring actions re-encode through the CapabilityLease authority
   client (403 wallet challenge → 428 credential → receipted); receipts still
   `ioi.hypervisor.odk.ontology-receipt.v1`; surface projection recheck/retire as
   receipted controls.
5. **W3 (backend, small)** — Receipt the DomainOntology DELETE (today `json_del`,
   odk_routes.rs:253-256) and add definition-delete-in-COM; then enable the Cleanup
   lanes with confirm. Serialize with other `hypervisor-daemon.rs` PRs (router is a
   merge hotspot).
6. **W3 (backend)** — Ontology proposal/branch family (propose/review/merge + branch
   refs on DomainOntology); then the Manager Proposals tab and Pipeline `rail.changes`
   read view (shared consumer, see data.md PR 8).
7. **W3 (backend)** — Per-principal saved object-set/exploration plane (canon :1315);
   then Explorer Lists/Favorites/New-exploration lanes. Object-instance search plane
   follows as its own family (or an explicit canon narrowing if instance search is
   ruled out-of-scope for bounded materialized sets).
8. **W4** — Cutover: shell stops advertising `/__ioi/ontology/*`; typed 410 per the
   6-step rule; delete the reference-only lanes marked `delete` in §4; retire the
   daemon alias `GET /v1/hypervisor/ontologies` (hypervisor-daemon.rs:1623-1628);
   `/__apps/schema` + `/__apps/explorer` captures remain dormant seeds per
   `ported-seed-preservation.v1.json`.
