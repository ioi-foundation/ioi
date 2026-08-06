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

#### Addendum 2026-08-06 (mesh packet 6 — censuses completed at `ba9e2ea0a`)

Both §3 censuses list outcome buckets that do not sum to their stated totals; the
missing buckets are recorded here and clustered in §6.

| Surface | §3 listed | Missing | Full six-bucket breakdown |
|---|---|---|---|
| `schema` (60) | 21 daemon_read · 13 governed · 15 disabled · 5 unsupported · 3 reference_data_only = **57** | `local_view_interaction` **3** | 21 · 3 · **13** · 15 · 5 · 3 = 60 |
| `explorer` (35) | 9 daemon_read · 0 governed · 8 disabled · 12 unsupported = **29** | `local_view_interaction` **5**, `reference_data_only` **1** | 9 · 5 · **0** · 8 · 12 · 1 = 35 |

`schema` holds **13 of the estate's 24 `governed_receipted_action` controls — 54%
of every governed control in the estate on one surface.** With Governance's 3
(`governance.md` §6), two surfaces account for 16 of 24.

T2 `nat-odk` (`/__ioi/odk`, serve `:9739`; sub-lane `:9776`) re-verified at
**36 controls, 0 disabled, HTTP 200**.

**The unreceipted-DELETE defect named in the bullet above is FIXED in the packet-6
landing PR** — see the new §9 defect register.

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

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`. Module cites are under
`apps/hypervisor/surfaces/`.

**Tier 4: none** — no vault names Ontology as owner.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `schema` — Ontology Manager** — `surfaces/ontology-manager/index.mjs:12-17`, route `/__ioi/ontology/manager`; protected seed, class `daemon_wired`; eleven-section IA (`ontology-context.mjs:23`), unknown section **fails closed** | **60 controls**, clustered below. The estate's deepest wired surface | Ontology owns domain ontologies, canonical object models, objects/actions/events/states/roles/invariants, projections, versions/overlays/crosswalks, action contracts, schema health, used-by (`domain-ontologies-and-data-recipes.md`, "Product and Domain Roles") | see cluster rows | — |
| ↳ **authoring cluster — governed** | 13 `governed_receipted_action`: the New menu's six lanes (button, object/link/action/value type, function) and the seven forms (section New-object-type button, 5-step wizard, edit object type, add/edit property, edit value type, edit link type, edit action type/function). All POST/PATCH `/odk/domain-ontologies` under `expected_revision` optimistic concurrency, each returning `ioi.hypervisor.odk.ontology-receipt.v1` and **failing closed on a missing receipt** (`ontology-manager/index.mjs:53-64`, `:80-141`) | receipted semantic authoring over an admitted ontology | **rehome** — 54% of the estate's governed controls live here; the `expected_revision` + fail-closed-on-missing-receipt discipline is the pattern every other surface's authoring should copy, and must survive the rehome verbatim | W1 · W2 |
| ↳ counts + health panel | 11 controls: 7 `daemon_read` (object types, properties, link types, action types, value types, functions, health issues) + 4 `disabled_missing_authority` (shared properties 0, groups 0, interfaces 0, cleanup) | schema health is a canon pane; shared properties / groups / interfaces are **not canon object kinds** | **rehome** the seven reads · **retire-at-cutover** the four: three name object kinds canon does not define, and "Cleanup" is a bulk mutation with no contract | W1 · W4 |
| ↳ configuration + selection cluster | 4 `daemon_read` (ontology configuration, ontology switcher, object-type card select, definition row select) | ontology switcher = the multi-ontology contract; **no ontology is globally canonical** | **rehome** | W1 |
| ↳ cross-surface link cluster | 6 `daemon_read` (Configure, Object Explorer →, open substrate record →, Open in Explorer/Pipeline/Lineage/Vertex/Provenance, configuration readout, configure model in substrate →) | used-by relationships across workers, automations, connectors, and apps | **rehome** — these links are the used-by pane in embryo; the shared typed-context kit (`ontology-context.mjs:18-62`, 14 bounded keys, fail-closed parsing) carries them | W1 |
| ↳ body filter cluster | 3 controls: 2 `local_view_interaction` (body search, status/visibility/add-filter facets) + 1 `disabled_missing_authority` (modify object types, bulk) | local filtering is legitimate local UI state | **rehome** the two · **retire-at-cutover** the bulk mutation (no contract) | W1 · W4 |
| ↳ New-menu absent kinds | 4 controls: 3 `disabled_missing_authority` (shared property, group, interface) + 1 `unsupported_reference_session` (Ontology-as-Code repository, Beta) | none is a canon object kind; OaC is a reference-product feature | **retire-at-cutover** — four affordances for kinds this ontology plane does not have | W4 |
| ↳ **execution lanes — absent** | 3 `disabled_missing_authority` (execute action, evaluate function, walk instances across link) | `OntologyActionContract` is canon (`semantic-plane.md`) and **not started** — `canon-to-code-delta.md` records the binding contract as absent; canon is explicit that an action name alone is not an execution contract | **blocked-missing-route** — honest block, named. These stay disabled until the action-contract family lands (§2 W3), and enabling them earlier would execute a semantic action with no admission, risk class, or receipt obligation | W3 |
| ↳ datasource backing step | 1 `disabled_missing_authority` (object type backing, Datasource step) | backing is Data's — `ConnectorMapping` + `DataRecipe` bind sources to object models | **retire-at-cutover** — in-Manager datasource authoring crosses into Data's ownership; the pane deep-links instead | W4 |
| ↳ navigation cluster | 3 controls: 1 `daemon_read` (History) + 1 `local_view_interaction` (Discover) + 1 `unsupported_reference_session` (Proposals) | proposal/branch/merge is **route-missing** (§2, W3) — no daemon route exists | **rehome** History + Discover · **blocked-missing-route** for Proposals (named, W3 backend build — not a W2 wiring task, per §3 correction) | W1 · W3 |
| ↳ app header cluster | 4 controls: 1 `reference_data_only` (app icon chip) + 2 `unsupported_reference_session` (add to favorites, branch selector) + 1 `disabled_missing_authority` (search resources ctrl+K) | per-user favorites and branches have no plane | **retire-at-cutover** | W4 |
| ↳ vendor shell chrome cluster | 7 controls: 3 `daemon_read` (Home, Applications launcher, Account) + 2 `disabled_missing_authority` (global search, AIP Assist) + 1 `reference_data_only` (What's New) + 1 `unsupported_reference_session` (Notifications) | hidden-UX carve-out; AIP Assist is a vendor faculty (standing P2 gate) | **retire-at-cutover** | W4 |
| ↳ reference example data | 1 `reference_data_only` (`[Example xxNN]` cards/rows + `Functions:575`) | **no fixture data may be presented as truth** | **retire-at-cutover** — the reference counts must never render beside real ones | W4 |
| **T3 `explorer` — Object Explorer** — `surfaces/object-explorer/index.mjs:12-17`, route `/__ioi/ontology/explorer`; **read-only by declared contract, `actions = []`** (`:29`); protected seed, class `daemon_wired` | **35 controls**, clustered below; **0 governed** — correct for a declared read-only surface | Ontology's instance/exploration lens | see cluster rows | — |
| ↳ catalog + inspector cluster | 10 controls: 8 `daemon_read` (shortcut cards from real top materialized sets, object-type catalog rows, object-set catalog rows, type inspector, set inspector, Manager row link, Open-in links, ODK substrate link) + 2 `local_view_interaction` (count badge, type filter input). Inspectors render real row previews with provenance refs — `pre_output_receipt_ref`, run/session refs, redacted source origin (`:52-107`, `:187-243`) | object sets and projections read-only; provenance refs preserved through projection | **rehome** — the provenance-refs-on-preview behavior is the honest core of this surface and must survive | W1 |
| ↳ fail-closed + embed cluster | 3 `local_view_interaction` (fail-closed unknown selection, `embed=1` native single-rail render, direct-link/refresh/back selection persistence) | fail-closed parsing of typed context | **rehome** — selection persistence through URL context is the shared kit's contract, not per-surface state | W1 |
| ↳ **instance search — absent** | 5 `disabled_missing_authority` (filter-by faceted object filters, search-for-objects input, search-for-objects primary button, search-explorations input, search instances) | object-instance search is **route-missing** (§2, W3) | **blocked-missing-route** — every reference per-user/instance lane is already a disabled named gap in place (`:112-176`), which is the correct rendering | W3 |
| ↳ **per-user exploration plane — absent** | 10 `unsupported_reference_session` (active-exploration button, new tab, more tabs, recents, favorites, your-object-sets, show-more, relevancy sort, view-mode lanes, ownership tags) + 1 `unsupported_reference_session` (ontology selector "All Ontologies") | per-principal saved explorations/object sets is **route-missing** (§2, W3); "All Ontologies" contradicts the no-globally-canonical-ontology rule | **blocked-missing-route** for saved explorations (W3, per-principal) · **retire-at-cutover** for "All Ontologies", which must not survive as a selector | W3 · W4 |
| ↳ absent action lanes | 3 `disabled_missing_authority` (row context menu, execute action, exploration workspace) | same action-contract gap as the Manager | **blocked-missing-route** — W3, and correctly disabled today | W3 |
| ↳ vendor shell + reference | 3 controls: 1 `daemon_read` (global platform sidebar), 1 `unsupported_reference_session` (add-to-favorites star), 1 `reference_data_only` (Object Explorer capture link) | carve-out | **retire-at-cutover** | W4 |
| **T2 ODK substrate ladder** — `/__ioi/odk` (serve `:9739`; sub-lane `:9776`) | T2 census `nat-odk`: **36 controls, 0 disabled**, HTTP 200 | ODK is **not an application** — it is the developer kit, and its object planes surface through the suite (`core-clients-surfaces.md:935-940`) | **rehome** — the ontology/value-type planes surface under `/ontology`; the data-recipe/source planes under `/data` (`data.md`); the descriptor/manifest planes under `/studio` and `/packages`. This readout is the one place the whole ODK ladder is visible, so its rehome **splits by owner** rather than moving whole | W1 |
| **T5 `/__apps/schema`** — capture, owner Ontology, `reference_capture`, capture state `boots_table_list`, grammar `editor_canvas`, high_value, `reboundLane: null`, "schema workbench; unbound" (`harvest-seed-inventory.mjs:45`); referenced as a secondary grammar at serve `:3453` | not in the 563 | the Manager above is the functional surface | **pattern-harvest** — grammar only; explicitly "never a rebound surface" | — |
| **T5 `/__apps/explorer`** — capture, `reference_capture`, capture state `shell_only`, grammar `table_list`, high_value, `reboundLane: null` (`:46`); referenced at serve `:5571-5574` | not in the 563 | the Explorer above is the functional surface | **pattern-harvest** | — |
| **T5 `/__apps/objectview`** — capture, `reference_capture`, capture state **`blocked_missing_capture`**, grammar `document`, aux, `reboundLane: null` (`:47`) | not in the 563 | an object-detail view would be an `object_view` descriptor pane (§8) | **blocked-missing-capture** — honest block; no claim about its grammar is supportable | — |
| **T5 `/__apps/objecteditor`** — capture, `reference_capture`, capture state **`blocked_missing_capture`**, grammar `editor_canvas`, aux, `reboundLane: null` (`:48`) | not in the 563 | an object-instance editor needs the action-contract plane first | **blocked-missing-capture** — and doubly blocked: even with a capture, editing instances requires the `OntologyActionContract` family that does not exist | — |

**Census reconciliation.** Ontology's two T3 surfaces carry **95 of the 563**
baseline controls: `schema` 60 (7 + 4 + 6 + 4 + 3 + 11 + 4 + 3 + 7 + 1 + 3 + 6 + 1,
across the twelve cluster rows above) and `explorer` 35 (2 + 10 + 5 + 5 + 2 + 3 +
3 + 3 + 2, across six cluster rows). Both sums exact. Its T2 readout adds 36
controls, 0 disabled, outside the baseline.

`schema`'s **13 governed-receipted controls are 54% of the estate's 24** — more than
half of every governed control in the Hypervisor, on one surface.

**Disposition summary.** 9 rehome · 0 rebind · 2 pattern-harvest ·
8 retire-at-cutover · **4 blocked-missing-route** (execution lanes ×2, proposals,
instance search, saved explorations — counted as four rows) · **2
blocked-missing-capture** (`objectview`, `objecteditor`). This is the run's first
surface where blocks outnumber pattern-harvests, and every block names its missing
route or capture.

## 7. Ontology wiring

Ontology is the **owner** of the semantic plane's core, so this section is a
declaration of what it owns rather than a search for bindings.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Manager — ontology CRUD, sections, health, history | `DomainOntology` (`DomainOntologyEnvelope`) | `/v1/hypervisor/odk/domain-ontologies` (+ `/:id`, `/:id/health`, `/:id/history`) | **Read + Write (receipted)** | writes go through `expected_revision` optimistic concurrency and emit `ioi.hypervisor.odk.ontology-receipt.v1`; the surface fails closed if the receipt is absent |
| Manager — object types, properties, link types, value types, functions | `CanonicalObjectModel` (`CanonicalObjectModelEnvelope`) | same routes (object model is embedded in the ontology record) | **Read + Write (receipted)** | canon models these as a separate envelope; the implementation embeds them — recorded, not a defect, but it is why "upsert object type" is an ontology patch |
| Manager — action types | `OntologyActionContract` (`OntologyActionContractEnvelope`) — **definition only** | same routes for the type; **execution route-missing** | **Write (definition, receipted)** · execution absent | canon: "an action name or connector method alone is not an execution contract." The Manager authors action *types*; the contract that binds typed IO, risk class, authority, idempotency, compensation, verifier, and receipt obligations **does not exist** — W3 |
| Manager — resource inspectors (read-only) | `ConnectorMapping`, `PolicyBoundDataView` | `/odk/connector-mappings`, `/odk/policy-bound-data-views` (`ontology-manager/index.mjs:22-31`) | Read | **owned by Data**; Ontology inspects, never authors — the boundary the datasource-backing row retires |
| Explorer — object-type catalog + shortcuts | `CanonicalObjectModel` + `MaterializedObjectSet` | `/odk/overview`, `/odk/domain-ontologies`, `/odk/materialized-object-sets` (`ontology-context.mjs:91-107`) | Read | shortcuts are the real top materialized sets, not a curated list |
| Explorer — object-set inspector + row preview | `MaterializedObjectSet` + `OntologyProjection` | `/odk/materialized-object-sets`, `/odk/ontology-projections` | Read | previews carry `pre_output_receipt_ref`, run/session refs, and redacted source origin — provenance survives projection, which non-negotiable 14 requires |
| Cross-surface typed context | not a primitive — the shared kit | `ontology-context.mjs:18-62` (14 bounded keys, fail-closed parsing) | — | the link contract between Manager, Explorer, Pipeline, lineage, vertex, and work-ledger |
| `OntologyVersion` / `OntologyOverlay` / `OntologyCrosswalk` / `SemanticMappingDecision` | canonical profiles of `DomainOntologyEnvelope` / `OntologyMappingEnvelope` | **route-missing** | — | tracked in `canon-to-code-delta.md`; the implementation has a mutable revision counter, not immutable versions. Proposals/branch/merge (§2 W3) is this gap wearing a UI name |
| `ProvenanceAssertion` | `OntologyAssertionEnvelope` | **route-missing** | — | Provenance's row (`provenance.md` §7) is the same gap seen from the other side |

**The one write-side ruling this surface needs.** Ontology is the only surface in
the run so far that writes the semantic plane, and every write is receipted, revision-
checked, and fails closed without its receipt. That discipline — not the pane
inventory — is what makes it the reference implementation. **After this packet,
deletion follows it too** (§9 D-1).

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

Ontology is where descriptor expressibility should be easiest — and it mostly is.
Five of its panes bind real primitives.

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Explorer object-type / object-set catalogs | `list_detail` | **descriptor-expressible** | binds `DomainOntology`, `CanonicalObjectModel`, `MaterializedObjectSet`, `OntologyProjection` refs + daemon API deps; read-only, so `allowed_action_refs` is honestly empty |
| Explorer object-set inspector + row preview | `object_view` | **descriptor-expressible** | same primitive set; the provenance-ref fields map to `receipt_obligations` |
| Manager section browser (object types, properties, link/value/action types, functions) | `list_detail` | **descriptor-expressible** | binds the ontology + object-model refs it is rendering |
| Manager authoring forms + 5-step wizard | `object_editor` / `wizard` | **exempt — authority-crossing writes** | a descriptor's `allowed_action_refs` can *declare* the upsert; it cannot carry `expected_revision` concurrency, the receipt obligation, or the fail-closed check. **This is the sharpest evidence in the run that `object_editor` is under-specified**: the pattern exists precisely for ontology editing, and the estate's own ontology editor cannot use it |
| Manager health panel | `dashboard` | **descriptor-expressible** | health is a projection over the ontology record |
| Manager configuration readout + used-by links | `object_view` | **exempt — cross-owner** | the used-by links span Pipeline, lineage, vertex, Provenance; same cross-owner blocker as `governance.md` §8's `review_inbox` finding |

**Four expressible panes — the run's largest count so far**, and all four are
read-side. The pattern holds across surfaces: descriptors can express reads over
ontology primitives today; they cannot express governed writes.

New X-2 finding: **`object_editor` cannot express the estate's own ontology editor**,
because the descriptor carries no concurrency token, receipt obligation, or
fail-closed admission semantics. Unlike the platform-object finding, this one is not
about missing bindings — the bindings exist. It is about the descriptor contract
having no write semantics at all.

Zero panes are `descriptor-rendered` today.

### (b) This surface as primitive exposer

**Ontology owns journey stage 1** and is the deepest exposer in the estate.

| Journey stage (`odk-extension-apps.md` §2) | What Ontology contributes |
|---|---|
| **1 — describe the domain** | `DomainOntology` records, canonical object models (object/link/value/action types, properties, functions), health projections, revision history, and the receipted authoring path that creates them |

What a user-tailored application draws from this surface: the ontology ref every
descriptor must name, the object-model refs its panes bind, the action types its
`allowed_action_refs` would reference (definitions only — the execution contract is
absent), and the materialized object sets its `list_detail`/`graph` panes render.

Two boundaries:

- **Ontology exposes definitions, not execution.** Until the
  `OntologyActionContract` family lands, a generated surface can name an action type
  and cannot run it. A kit that generated a working "execute" button today would be
  fabricating admission.
- **Ontology does not admit applications.** It describes the domain; Packages admits
  the package, Applications holds the registration, Systems binds for effect
  (`odk-extension-apps.md` §2). An ontology being healthy grants a generated app
  nothing.

## 9. Route-plane defect register (audited 2026-08-06)

Byte-verified against `crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs`
on master at `ba9e2ea0a`.

- **D-1 unreceipted effectful mutation — FIXED (packet-6 PR).**
  `DELETE /v1/hypervisor/odk/domain-ontologies/:id` called the bare `json_del`
  helper (`odk_routes.rs:253-256` via `:1063-1068`): the record was removed and
  `{ok, removed}` returned with **no receipt**, while every other mutation on the
  same object (create, patch, and all seven authoring lanes) went through
  `build_ontology_receipt` + `finalize_ontology_persist` with atomic rollback.
  Deleting an ontology is the most consequential mutation the plane has, and it was
  the only one that left no evidence. Now: the record is removed first (a receipt
  must never describe an unpersisted state), a `deleted` receipt is written, and if
  the receipt cannot persist the **record is restored** — so an unreceipted deletion
  cannot survive. A missing ontology reports honestly and attests nothing, because
  there was no mutation. Covered by
  `ontology_delete_emits_a_receipt_and_restores_the_record_when_the_receipt_cannot_persist`.
- **D-2 sibling deletes remain unreceipted — recorded, not fixed.** `json_del` still
  backs recipe (`:1318`), manifest (`:1476`), and surface-descriptor (`:1619`)
  deletion. Those three planes have **no receipt family at all** — unlike ontology,
  which had one and skipped it — so receipting them is a plane-level build, not a
  truthfulness repair. Filed for the wave that gives each plane its receipt family;
  fixing it here would have front-run that contract.
- **D-3 embedded object model — recorded.** `CanonicalObjectModel` is canonically a
  separate envelope; the implementation embeds object/link/value/action types inside
  the ontology record, which is why "upsert object type" is an ontology patch under
  the ontology's revision. Not a defect — a modelling divergence that will matter
  when `OntologyVersion` immutability lands (`canon-to-code-delta.md`).
- **D-4 action types are definitions with no execution contract — W3.** The Manager
  authors action types; `OntologyActionContract` (typed IO, preconditions, risk
  class, authority scopes, idempotency, compensation, verifier, receipt obligations)
  does not exist. The three execution controls are correctly disabled today; enabling
  them before the contract lands would execute a semantic action with no admission.
