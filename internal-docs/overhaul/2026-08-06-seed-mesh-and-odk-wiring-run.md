# Seed-Mesh + ODK Wiring Run — starter prompt

This file IS the starter prompt. A fresh session (Opus-class) begins by reading
this file top to bottom, then the Run State ledger at the bottom, and resumes
at the first unchecked packet. No other context is required or assumed. Update
the ledger in every landing PR — the file is the handoff channel between
sessions.

Sibling program to `2026-08-05-hypervisor-bring-to-life-run.md` (the build
run). This run EXTENDS Phase A: it does not build UI and it does not fork the
build ledger. Its output is documentation plus the ODK canon expansion
(packet X-0) and filed residual canon deltas: after the last packet lands,
`internal-docs/implementation/` is the fully comprehensive
master guide for wiring the entire Hypervisor product — every seed UX state
meshed to its functional end state, every pane bound to canon schemas, every
surface's ontology wiring named, and the ODK tailored-application lane
specified — on an app-per-app basis. Build sessions (bring-to-life Phase B)
then execute enriched briefs instead of thin ones.

## Mission

Three lanes, per surface:

1. **Seed mesh.** Compare every seed UX state that exists for the surface —
   native readouts (T2 `/__ioi/*`), registered surfaces (T3) with their
   control censuses, dormant seed vaults (T4 `apps/hypervisor/ux-seeds/`),
   and harvest captures (T5 `/__apps/*`) — against the brief's canonical end
   state, and record a control-cluster-level disposition ledger: what is
   adopted/rehomed, what is rebound, what is harvested for pattern only, what
   retires. Rehome-don't-rebuild and the ported-seed-preservation invariant
   remain in force; the mesh ledger is how each seed EARNS its cutover row.
2. **Ontology wiring.** Name the exact semantic-plane primitives the surface
   reads or writes (ontology refs, object models, projections, materialized
   object sets, policy-bound views, action contracts, data recipes), with
   daemon routes, so every surface's object-awareness is declared rather than
   incidental.
3. **ODK descriptor + extension lane.** Express the surface's own panes as
   `OntologySurfaceDescriptor` composition patterns where they fit, and
   record what primitives the surface EXPOSES so users can build tailored
   applications from the same kit (canon: ODK primitives surface through
   Ontology/Data/Studio/Packages/Developer Console; Surface Generate is the
   product path; kit-generated surfaces pass the same registration contract;
   extension apps compile to `/applications/{surface_key}`).

## Ground truths (verified 2026-08-06 — do not re-derive, bytes still win)

- Phase A is complete: 20 briefs + `_index.md` under
  `internal-docs/implementation/surfaces/`, uniform five-section shape
  (canon digest · schema map · UI seed map · schema→UI binding table ·
  ordered PR list), ≈190 planned PRs. `foundry.md` carries the newest
  conventions: a dated audit-amendment header line and an appended
  numbered defect-register section — this run generalizes both.
- `NOW.md` is deleted (proof-apparatus strip). The Run State ledger in
  `2026-08-05-hypervisor-bring-to-life-run.md` is the build program's spine;
  this file's ledger is the mesh program's spine. One pointer row links them.
- W0.1–W0.6 are all landed (v2 shell/23 routes, surface compiler, read +
  authority + event clients, identity truth, backend enablers). Everything
  W1+ in the build run is unchecked.
- The seed estate: 39 `/__apps/*` harvest captures (`HARVEST_APPS`,
  `apps/hypervisor/scripts/serve-product-ui.mjs:7419`; dispositions in
  `apps/hypervisor/harvest-app-parity-matrix.json` — 13 daemon_wired,
  23 reference_capture, 3 substrate_bound; owner map in
  `apps/hypervisor/scripts/harvest-seed-inventory.mjs`); 14 registered T3
  surfaces (`apps/hypervisor/scripts/surface-registry.mjs`; 6 with extracted
  modules under `apps/hypervisor/surfaces/`); 3 dormant T4 seed vaults
  (`apps/hypervisor/ux-seeds/{workspaces,widgets,lineage}`, PRs #93–#95,
  guarded by `verify-hypervisor-ux-seed-evidence.mjs`); ~99 `/__ioi/*`
  serve-lane routes. Control census: 563 controls across the 14 T3 surfaces,
  24 governed-receipted (4.3%) —
  `internal-docs/audits/2026-07-30-hypervisor-surface-end-state-audit/`
  (README §4.3 + `inventory.v1.json → control_census_563`; per-control
  source `apps/hypervisor/application-operational-depth.json`, frozen 269
  commits behind its audit HEAD — treat counts as baseline, bytes win).
- The ODK primitive set and routes (canon owner
  `docs/architecture/foundations/domain-ontologies-and-data-recipes.md`;
  envelopes in `docs/architecture/foundations/objects/semantic-plane.md`;
  routes under `/v1/hypervisor/odk/*` in `odk_routes.rs` + adjacent route
  files; DomainApp mount/serve ladder in `domain_apps_routes.rs`):
  DomainOntology · DataRecipe · OntologyDevelopmentKitManifest ·
  OntologySurfaceDescriptor (the app-shape contract, 11 composition
  patterns incl. `domain_app`) · ConnectorMapping · PolicyBoundDataView ·
  TransformationRun · OntologyProjection · MaterializedObjectSet ·
  DomainApp/DomainAppRuntime (implemented ladder, **no canonical
  envelope** — see canon-delta packet X-2).
- The extension-application story is already canon, with NO workstream in
  the build run — this run creates it (packet X-1). Load-bearing cites:
  `core-clients-surfaces.md:935-940` (primitives route through the suite),
  `:2217-2226` (Surface Generate is the product path; builder paths never
  own runtime truth), `:1955-1963` (kit-generated surfaces pass the same
  registration contract), `:1435-1441` (Studio authors descriptors, kit
  scaffolds, Packages admits/versions, compiler exposes),
  `:2053-2055` (everything compiles into the one registration/composition
  contract), `domain-ontologies-and-data-recipes.md:351-384` (generatable
  surface list; scaffolding-not-runtime boundary), invariants 10–11
  (`:578-584`).
- C-1..C-4 bind every packet: session-serving elements attach subjects via
  `subject_attachments[]` only; adding an application never edits the
  platform schema.

## Method — the mesh packet recipe

Each per-surface packet is one session-sized unit producing ONE docs PR that
amends the surface's brief. Steps:

1. **Refresh.** Re-verify the brief's §2/§3/§4 line-cites against current
   master bytes; record corrections in the brief's existing
   `### Corrections vs v0` (or a dated addendum under it). The packet input
   table below lists this surface's seed artifacts — verify each still
   exists before writing its row.
2. **Seed sweep.** Enumerate every seed artifact for this surface from all
   five tiers. For T3 surfaces, pull the control census counts and the
   per-control outcomes from `application-operational-depth.json`. For
   T5 captures, use the parity matrix class + `harvest-seed-inventory.mjs`
   owner/rebound-lane fields. Include unbound captures assigned to this
   surface in the packet table.
3. **Mesh ledger.** Append to the brief a new numbered section
   `## N. Seed mesh ledger (YYYY-MM-DD)` — one row per pane or control
   cluster: `| Seed element (tier + path) | Census/control facts | Canon end
   state (cite) | Disposition | Wave |`. Disposition vocabulary (fixed):
   - `rehome` — wired plane moves under the canonical route as-is
     (rehome-don't-rebuild).
   - `rebind` — capture lane already answers with daemon truth or can with a
     small adapter; name the lane.
   - `pattern-harvest` — interaction/layout grammar informs the functional
     pane; no code moves; seed stays dormant until estate cutover.
   - `retire-at-cutover` — superseded; dies with the surface's typed-410 PR.
   - `blocked-missing-capture` / `blocked-missing-route` — honest block,
     named.
   Every disposition row must be consistent with
   `ported-seed-preservation.v1.json` (protected routes retire only per the
   6-step rule) and with the retired-name rulings (Missions/Marketplace/
   Approvals-as-app etc. rehome into owners, never revive as peers).
4. **Ontology wiring.** Append `## N+1. Ontology wiring` — a short table:
   `| Pane/flow | Semantic primitive + envelope | Route | Read/Write |
   Notes |`. Honest `none — not object-bound` is a valid outcome; record it
   rather than inventing bindings. Write-side rows must name the admission
   path and receipt (no mutation semantics over projections — Agentgres
   positioning constraints, #168/#169).
5. **ODK descriptor + extension lane.** Append `## N+2. ODK descriptor and
   extension lane` with two short ledgers:
   (a) *This surface as descriptor consumer*: which of its panes match a
   descriptor `composition_pattern` (list_detail, object_view,
   object_editor, graph, wizard, review_inbox, monitoring_console,
   dashboard, data_recipe_builder, connector_mapping_editor, domain_app) —
   these become candidates for descriptor-driven rendering instead of
   bespoke code, referencing invariant 11's required binding set.
   (b) *This surface as primitive exposer*: what it contributes to the
   user-tailored-application journey (per the X-1 program doc) — e.g.
   Ontology exposes object/action/value types; Data exposes recipes and
   policy-bound views; Studio exposes Surface Generate; Packages admits and
   versions; Applications launches at `/applications/{surface_key}`;
   Developer Console carries kit on-ramps. Honest `n/a` allowed for
   substrate/core-workspace surfaces that only consume.
6. **Reconcile forward plan.** Fold new route-missing rows and defects into
   the brief's §2 schema map (`route-missing — W3.x`), §4 binding table, and
   §5 ordered PR list; add or extend a foundry-style
   `## Route-plane defect register` section when byte-verified defects are
   found. Never renumber existing PR lists — append.
7. **Ledger tick.** Update this file's Run State ledger row in the same PR:
   tick + one-line handoff note (PR number, anything blocked).

**Acceptance gate per packet** (the PR is not done until all hold):
- Every seed artifact listed for the surface in the packet table has a mesh
  ledger row (or a recorded correction that it no longer exists).
- Every mesh row cites a canon end state or names the missing canon.
- Census control counts are reconciled: mesh rows account for the surface's
  census total (clusters may aggregate; sums must be stated).
- Ontology and ODK sections exist, even when their honest content is `none`.
- No fixture data, no fabricated states, no renumbered history; bytes cited
  as `file:line` throughout.

## Cross-cutting packets

- **X-0 — ODK canon expansion (docs/architecture, lands FIRST).** The
  extension-application lane is canon-latent but canon-incomplete; this run
  surfaces the missing ODK details into canon itself, not only into
  internal-docs. Three owner-scoped canon PRs:
  (a) **DomainApp envelope family** — `DomainApp`, `DomainAppRuntime`, and
  the mount receipt as canonical envelopes (semantic-plane.md or a dedicated
  objects file; owner-qualified names per term-boundaries), plus the
  governed mount/serve ladder as doctrine (draft → approval+release-gated
  mount, receipted → internal serve re-validating live → stop/unmount);
  today the ladder is implemented (`domain_apps_routes.rs`) with no canon
  object — code leads canon, which is backwards.
  (b) **Composable application journey section** in
  `domain-ontologies-and-data-recipes.md` (cross-referenced from
  `core-clients-surfaces.md`): consolidate the scattered cites (:935-940,
  :1435-1441, :1955-1963, :2053-2055, :2217-2226, invariants 10-11) into
  one canonical stage ladder — describe → Studio Surface Generate / kit
  scaffold → `OntologySurfaceDescriptor` → Packages admission/versioning →
  installed binding → compiler exposure at `/applications/{surface_key}` →
  System binding for effectful launch — with the owning surface named per
  stage.
  (c) **Descriptor-expressibility rule (dogfooding invariant)** — new canon
  ruling: every first-party owner-surface pane whose shape matches a
  descriptor `composition_pattern` SHOULD be descriptor-expressible, and
  each surface brief records which panes are and why the rest are not.
  First-party surfaces and user-tailored applications share the same
  primitives — the kit is credible only if the estate itself runs on it.
  The per-surface §N+2(a) ledgers below are the enforcement surface for
  this rule; X-4 rolls their coverage into `_index.md`.
- **X-1 — ODK extension-application program doc.** Write
  `internal-docs/implementation/odk-extension-apps.md`: the user-tailored
  application lane end-to-end. Contents: the canon journey (describe →
  Studio Surface Generate / kit scaffold → `OntologySurfaceDescriptor`
  (+ `domain_app` pattern where the target is an app) → Packages admission
  and versioning → installed binding → compiler exposure at
  `/applications/{surface_key}` → for effectful System launch, admitted
  System/context refs); the DomainApp mount/serve ladder as implemented
  (`domain_apps_routes.rs` — draft → governed mount (approval + release
  control, receipted) → internal serve → stop/unmount) and how it rehomes
  under the canonical estate; the invariant-11 binding checklist as the
  descriptor conformance bar; which owner surface owns each journey stage;
  and the Slate/Logic/Contour/Fusion captures as pattern evidence for what
  generated domain apps should feel like. This doc is the umbrella the
  per-surface §N+2 sections point into.
- **X-2 — residual canon deltas.** Deltas beyond X-0's scope, filed as
  small owner-scoped canon PRs as packets surface them, never landed inside
  a mesh PR: (a) the `machinery` surface ownership conflict (registry says
  Studio; ruling needed Studio vs Automations); (b) ODK contract-registry
  registration remains the filed M6 gap — record, do not build here;
  (c) anything else the packets find (e.g. OntologyVersion/Overlay/
  Crosswalk/ActionContract remain tracked in `canon-to-code-delta.md` —
  extend that file, don't duplicate it).
- **X-3 — unbound-seed disposition sweep.** After all 20 surface packets:
  verify every one of the 39 captures has exactly one home — a mesh ledger
  row in some brief or a ruled row in
  `internal-docs/implementation/repo-ux-disposition.md`. Zero
  UNDISPOSITIONED seeds at exit (owner rulings may still be pending; the
  row then names the pending ruling).
- **X-4 — master-guide assembly.** Regenerate
  `internal-docs/implementation/surfaces/_index.md`: add mesh-status and
  ontology/ODK coverage columns to the brief table; add a short preamble
  making `_index.md` the table of contents of the completed master guide
  (briefs + epics + `odk-extension-apps.md` + `repo-ux-disposition.md`);
  add one row to the build run's ledger noting mesh completion. Exit
  criterion for the whole run: a fresh session can wire any surface to
  functional end state from `internal-docs/implementation/` alone, without
  re-deriving seed dispositions, schema bindings, or ontology/ODK lanes.

## Hidden-UX carve-out (allowed depth limit)

These get disposition rows but NOT control-level wiring detail: vendored
shell chrome internals (owned verbatim per the shell-ownership program);
embed-thread lens internals (`EMBED_THREAD_ROUTES`); dev/test-only lanes
(`__test_action`, `fallthrough/reset`); dormant T4 seed internals beyond
their mesh rows; pixel-certification mechanics. Everything else that a user
can traverse is in scope.

## Per-surface packet input table

Packet order mirrors the build run's Phase B order so mesh stays ahead of
build. `Census` = controls/receipted from the 563-census baseline. Paths:
serve = `apps/hypervisor/scripts/serve-product-ui.mjs`, registry =
`apps/hypervisor/scripts/surface-registry.mjs`, modules =
`apps/hypervisor/surfaces/`.

| # | Packet (brief) | Seed inputs to mesh | Census | Ontology/ODK starting points |
|---|---|---|---|---|
| 1 | work (`/work`, owns `/work/sessions`) | T3 `missions` (module, read-only-by-contract) + `incidents`; T5 `jobs` (REBIND serve:7550) + `incidents` (REBIND :7777); T2 `/__ioi/sessions` :8696, `/__ioi/work-ledger` :8785, run-timeline/replay :7258/:7314; W0.6 `sessions/overview` | missions 10/0 · incidents 42/0 | `subject_attachments[]` only (C-1..C-4); session subjects may carry object refs — read-side joins, no ontology writes |
| 2 | provenance (`/provenance`) | T4 `ux-seeds/lineage` (PR #95, no pixel cert); T5 `lineage`, `vertex`; T2 `/__ioi/lineage` :9679, `/__ioi/vertex` :9659 (embed-thread) | — (no T3 row) | OntologyAssertionEnvelope `provenance_assertion` profile; dependency/impact graph shared with Ontology; deep links per kind |
| 3 | environments (`/environments`) | T2 `/__ioi/environments` :8858; T5 `map` (aux) | — | descriptor pattern `monitoring_console`; env classes read-only |
| 4 | operations (`/operations`) | T2 `/__ioi/operations` :8838 (embed-thread); T5 `scheduler` (aux); W0.6 `scheduler/status` | — | `monitoring_console`/`dashboard` patterns; no semantic writes |
| 5 | governance (`/governance`) | T3 `approvals` (module; REBOUND capture); T2 `/__ioi/governance` :9938+; W0.6 approvals-inbox | approvals 40/3 | `review_inbox` is THE canonical descriptor pattern here; approvals reference ontology-governed objects read-only |
| 6 | ontology (`/ontology`) | T3 `schema` (ontology-manager module, 7 receipted actions under `expected_revision`) + `explorer` (object-explorer module, read-only); T5 `schema`, `explorer`, `objectview`, `objecteditor` (both blocked_missing_capture); T2 `/__ioi/odk` :9739 | schema 60/13 · explorer 35/0 | ODK plane OWNER: four core planes + projections + object sets; W3 families (proposal/branch/merge, instance search, saved explorations, action-type execution); unreceipted ontology DELETE defect (`odk_routes.rs:253-256`) |
| 7 | data (`/data`) | T3 `pipeline` (module + control-matrix, atlas_verified) + `sources` (module); T5 `ingest` (unbound), `pipeline`, `dataset` (aux) | pipeline 84/1 · sources 31/3 | DataRecipe (BOTH families — `/odk/data-recipes` vs `/v1/hypervisor/data-recipes` :1639 vs generic `recipes` :1226; vocabulary guard semantic-plane.md:266-267); patterns `data_recipe_builder`, `connector_mapping_editor`; PolicyBoundDataView; TransformationRun |
| 8 | automations (`/automations`) | T3 `monitors`; T2 `/__ioi/automations` :8360 (+POST :8401, cron-preview :8393); T5 `monitors` (proxy insufficient) | monitors 29/0 | object-set monitor triggers = route-missing (W3, object sets exist at `/odk/materialized-object-sets`); pattern `wizard` |
| 9 | foundry (`/foundry`) | T3 `models` (browse-only); T5 `models`, `modelstudio`, `inference` (reference-only); T2 `/__ioi/foundry` :9532+; Agent Studio `#model-routes` tab (rehome source) | models 39/0 | brief already carries W3.0–W3.4 + functional-interface targets (2026-08-06 amendment) — integrate, don't duplicate; `ontology` is a FoundrySpec kind; ontology-aware eval/worker skeletons are ODK-generatable |
| 10 | developer-workspace (`/developer-workspace`) | T4 `ux-seeds/workspaces` (PR #93 + pixel cert); T5 `workspaces`, `repositories` (blocked_missing_capture), `notepad`; T2 `/__ioi/workbench` :8876, `/__ioi/code` :8685, `editor/open` :10364 | — | development-environment recipes; descriptor patterns for object-bound editors; consumes, does not expose |
| 11 | studio (`/studio`) | T3 `designer` (7/51 impl — lowest) + `machinery` (ownership conflict → X-2b); T5 `designer`+`machinery` (proxy insufficient), `workshop`, `module` (unbound), `slate`/`logic`/`contour`/`fusion` (domain-app pattern evidence → X-1); T2 `/__ioi/studio/*` :9629/:9652, `/__ioi/domain-apps` :9869+, `/__ioi/agent-studio` :9043 (split-rehome map required: model-routes→Foundry, improvements→Improvement, intel→Settings/owners, vault/launch-policies→per canon) | designer 51/– · machinery 30/0 | Surface Generate owner; authors `OntologySurfaceDescriptor`s; reads all six ODK families into System Design; DomainApp draft creation; the extension-lane authoring stage |
| 12 | evaluations (`/evaluations`) | T3 `evalsuites`; T5 `evalsuites` (no data), `analysis`, `quiver` (named gaps); T2 `/__ioi/evaluations` :8605+ (POST/delete lanes) | evalsuites 32/3 | ontology-aware eval packs (ODK-generatable); object-set analysis binds MaterializedObjectSet |
| 13 | improvement (`/improvement`) | T3 `changes` (REBOUND); T5 `changes`; T2 `/__ioi/improvement/changes` :8455, agent-studio propose :9192 | changes 47/1 | descriptor pattern `review_inbox`; reads proposals over governed objects |
| 14 | packages (`/packages`) | T3 `listings` (REBIND); T5 `listings`, `registry`; T2 `/__ioi/marketplace` :10025+ (candidates/reviews/offers lanes) | listings 33/0 | ODK manifests surface here (daemon :1612-1616); admission/versioning stage of the extension lane; `ontology_pack` listing kind; worker-package install admission carries ontology refs |
| 15 | developer-console (`/developer-console`) | T4 `ux-seeds/widgets` (PR #94 + pixel cert); T5 `widgets`, `devconsole`, `developer` (self-bootstrapped/unbound); T2 `/__ioi/connections` :10141+, github-app :8213+, oauth :8299, slack :8319 | — | kit on-ramps (scaffolds/templates/generated SDKs, canon :961-967); widget-set authoring = descriptor-driven candidate; conformance surfaces |
| 16 | home (`/home`) | T2 `/__ioi/home` :8708, new-session lanes :8964/:9019, `goal-space` :8724, `search` :8649 | — | launches only; `n/a` likely honest for both lanes |
| 17 | systems (`/systems`) | T2 `/__ioi/systems` :9527 (+prefix) | — | System-bound interfaces `/systems/{id}/interfaces/{binding_id}` are where admitted extension apps bind to Systems |
| 18 | projects (`/projects`) | (no dedicated seeds — verify and record honest absence) | — | project-scoped object sets read-only |
| 19 | applications (`/applications`) | T2 `/__ioi/applications` :8568, `api/applications` :8561; compiler projection (W0.2) | — | the landing zone: catalog/launcher rows for extension apps at `/applications/{surface_key}`; recall-removes-launches hook (W3 Packages) |
| 20 | settings (`/settings`, + `/sign-in` entry) | T1 settings panes (inventory `tier_t1_settings_panes`); T2 login/logout/invite/sso :8046-8132, W0.5 named-gap banners; agent-studio intel/memory+skills panes (rehome per corrections — Settings owns personal prefs) | — | projection-only, writes-through-owners; `n/a` for exposure |

## Regime

Docs-first: mesh packets land documentation only (brief amendments + the two
program docs + ledger ticks). Canon deltas are separate small PRs (X-2),
never inside a mesh PR. Code lands in this run ONLY for byte-verified
honesty defects found while meshing (foundry D-1/D-2 precedent), each with
its own defect-register row and test — never new features, never front-running
W3.0-style contract waves. Ordinary branches off master, small PRs, merge on
green by hand (`gh pr merge <n> --squash`; repo auto-merge is DISABLED).
Contingency defaults (none is a stop): bytes beat every prior doc including
this one — record the correction; missing capture → `blocked-missing-capture`
row; census stale vs bytes → recount from bytes, note the delta; canon
ambiguity → file an X-2 delta row and disposition provisionally;
unattributable pre-existing test failure after ≤30 min → record and continue.

## Session protocol

1. Read this file, then `git log master --oneline -15`, then the ledger.
2. Take the first unchecked row. Refresh its inputs at the bytes (step 1 of
   the recipe). Execute the packet. One PR per packet (X-2 deltas may batch
   per owner file).
3. Tick the ledger row with the PR number in the same PR.
4. Before context runs out: land what's landable, note in-flight state in
   the ledger row, stop cleanly. Never leave the ledger claiming more than
   the bytes show.

## Run State ledger

| Packet | State | Handoff note |
|---|---|---|
| X-0 ODK canon expansion (DomainApp envelopes · composable-application journey · descriptor-expressibility rule) | ☑ | Three owner-scoped canon PRs, all landed. (a) DomainApp envelope family — **PR #176**: `DomainAppEnvelope` / `DomainAppRuntimeEnvelope` / `DomainAppMountReceiptEnvelope` in semantic-plane.md, the six-rung governed mount ladder as doctrine, non-negotiable 22, and two filed canon-to-code deltas (descriptor invariant-11 gap; five ladder divergences). (b) composable-application journey — **PR #173**: one ten-stage ladder with the owning surface named per stage, six rulings, cross-ref from core-clients-surfaces.md. (c) descriptor-expressibility rule — **PR #174**: non-negotiable 23 + four boundaries; the per-surface §N+2 ledgers are its enforcement surface |
| X-1 ODK extension-application program doc | ☑ | **PR #175** — `internal-docs/implementation/odk-extension-apps.md`. Finding: BOTH ENDS OF THE JOURNEY ARE BUILT, THE MIDDLE IS NOT. Authoring = 56 ODK route registrations across twelve families; mount/serve = a fully implemented six-rung governed ladder. Between them: no `/v1/hypervisor/packages/*` routes at all, zero `extension_application` registrations (all 15 are first-party and `include_str!` static), `system_interface_bindings: []`. That is why the implemented `DomainApp.status` is pinned to "draft" — there is nothing to advance to. Build consequence: the extension lane is gated on the Packages registry (W3), not on more ODK work |
| 1. work mesh | ☑ | PR #177. 52/52 T3 controls reconciled (missions 10, incidents 42; 0 governed — correct for a read model). 6 rehome · 2 rebind · 2 pattern-harvest · 7 retire-at-cutover · 0 blocked. Ontology wiring is honestly `none` throughout — Work subjects are platform objects, not ontology objects. Two X-2 findings filed: descriptor cannot bind platform object families (blocks expressibility for every read-model core workspace); D6 trace waterfall has no matching `composition_pattern`. §3 cite drift corrected (4 advertisement sites, not 5 — the `30-shell.js` tile is gone) |
| 2. provenance mesh | ☑ | PR #178. **0 of the 563** T3 controls (no registered surface — honest absence); T2 tier carries 217 controls, 0 disabled. 6 rehome · 1 rebind · 1 pattern-harvest · 1 retire-at-cutover · 1 **blocked-missing-capture** (`/__apps/vertex`). FIRST surface with real ontology wiring: the lineage/vertex lenses read 11 ODK semantic-plane routes directly, and the lineage + vertex graph panes are the run's first two **descriptor-expressible** rows. Recorded: `ProvenanceAssertion` — the canonically-named Provenance primitive — has NO route; the surface renders receipt edges, not admitted assertions. §3 T4/T5 tier conflation corrected (`ux-seeds/lineage` vs `/__apps/lineage`) |
| 3. environments mesh | ☑ | PR #179. **0 of 563** T3 controls (no registered surface); T2 readout 182 controls, 0 disabled — and zero-disabled is not completeness: there are no mutation forms, so the missing authority controls are ABSENT, not disabled. 8 rehome · 2 retire-at-cutover · 1 **blocked-missing-capture** (`/__apps/map` — no inspectable capture AND no canonical geospatial pane to mesh it against). Ontology wiring `none` across the whole surface: nine substrate reads, zero ODK routes. Platform-object blocking finding recurs (3rd surface) — filed once at X-2, referenced not re-filed. §3 cite conflated the adjacent `/__ioi/operations` handler (`:8838`) with `/__ioi/environments` (`:8858`) |
| 4. operations mesh | ☑ | PR #180. **0 of 563** T3 controls; T2 readout 40 controls, 0 disabled — only 3 cross authority and all 3 DELEGATE to Automations, so Operations' own governed count is zero BY DESIGN (it observes substrate, it does not command it). 12 rehome (one also rebinds to `scheduler/status`, landed by W0.6 after the brief was written) · 1 pattern-harvest · 1 retire-at-cutover · 0 blocked. Ontology wiring `none`; write side none twice over. 4th platform-object exemption — and the first where the shape match is exact (`monitoring_console` was written for this pane and still cannot be bound). §3 handler cite `:8802`→`:8838`; the "no scheduler read surface" correction is SUPERSEDED by W0.6 |
| 5. governance mesh | ☑ | PR #181. 40/40 T3 controls reconciled in 8 clusters — **3 of the estate's 24 governed-receipted controls sit on this one surface (12.5%)**. 7 rehome (2 also rebind) · 1 pattern-harvest · 4 retire-at-cutover · 0 blocked; 1 row recorded as BUILD-not-mesh (authority browsing: routes exist, no seed) and 1 carrying a named defect (approvals success banner links a proof stream that does not join approval-transition receipts). FIRST surface to OWN a journey stage: stage 10 admission (ApprovalRequest + ReleaseControl gate the Domain App mount rung; KillSwitch enforces through the same receipt family). New X-2 finding: `review_inbox` presumes a homogeneous object set, but canon's review inboxes are cross-owner BY DESIGN — the inbox's cross-owner nature is what makes it unbindable. §3 cite `:9901`→`:9938`; approvals census completed (§3's three buckets summed to 25 of 40) |
| 6. ontology mesh | ☑ | PR #182. 95/95 T3 controls reconciled (schema 60 in 12 clusters, explorer 35 in 6). **`schema` holds 13 of the estate's 24 governed-receipted controls — 54% on one surface**; with Governance's 3, two surfaces hold 16 of 24. 9 rehome · 2 pattern-harvest · 8 retire-at-cutover · 4 blocked-missing-route · 2 blocked-missing-capture — first surface where blocks outnumber pattern-harvests, each naming its missing route/capture. Owns journey stage 1; 4 descriptor-expressible panes (run's largest), all read-side. **CODE: D-1 unreceipted ontology DELETE FIXED** (receipt + restore-on-receipt-failure + test) — D-2 records that recipe/manifest/descriptor deletes stay unreceipted because those planes have NO receipt family at all, so receipting them is a plane build, not a repair. New X-2 finding: `object_editor` cannot express the estate's own ontology editor — the descriptor contract has NO WRITE SEMANTICS (no concurrency token, receipt obligation, or fail-closed admission). §3 censuses completed (schema listed 57 of 60, explorer 29 of 35) |
| 7. data mesh | ☑ | PR #183. 115/115 T3 controls reconciled (pipeline 84 in 6 clusters, sources 31 in 5). **Pipeline holds 40 of the estate's 172 disabled controls (23%); Data owns 51 (30%)** — and every one carries its reason at the bytes, with a malformed matrix failing serve boot. 8 rehome · 2 pattern-harvest · 5 retire-at-cutover · 3 blocked-missing-route · 1 blocked-missing-capture. Owns journey stage 2. Resolved the 83-vs-84 matrix/census delta (different taxonomies; the extra row is vendor chrome the matrix correctly scopes out). Resolved the "three recipe families" question: `/odk/data-recipes` + a GET-only compat ALIAS at `/data-recipes` are ONE plane; `/v1/hypervisor/recipes` is `DevelopmentEnvironmentRecipe` — an unqualified generic "recipe" name that `term-boundaries.md` calls a defect → X-2. Write-semantics finding gets instances 2 and 3: `data_recipe_builder` and `connector_mapping_editor` are named for panes NEITHER CAN EXPRESS |
| 8. automations mesh | ☐ | |
| 9. foundry mesh | ☐ | integrate with 2026-08-06 W3.0–W3.4 amendment |
| 10. developer-workspace mesh | ☐ | |
| 11. studio mesh | ☐ | includes agent-studio split-rehome map |
| 12. evaluations mesh | ☐ | |
| 13. improvement mesh | ☐ | |
| 14. packages mesh | ☐ | |
| 15. developer-console mesh | ☐ | |
| 16. home mesh | ☐ | |
| 17. systems mesh | ☐ | |
| 18. projects mesh | ☐ | |
| 19. applications mesh | ☐ | |
| 20. settings mesh | ☐ | |
| X-2 residual canon deltas (machinery ownership · filed gaps) | ☐ | file as found; this row closes when all filed deltas have PRs. FILED SO FAR: (a) machinery ownership (Studio vs Automations) — from the charter; (b) ODK contract-registry registration (M6 gap, record only); (c) descriptor cannot bind platform object families — `OntologySurfaceDescriptorEnvelope` requires ontology/object-model bindings, so no first-party read-model pane can satisfy invariant 11 (packet 1); (d) no `composition_pattern` matches a trace/replay span waterfall (packet 1); (e) `term-boundaries.md:10-12` names `scripts/check-architecture-docs.mjs` + `scripts/lib/architecture-docs-integrity.mjs` as implementation refs — neither file exists on master |
| X-3 unbound-seed disposition sweep | ☐ | after packets 1–20 |
| X-4 master-guide assembly (`_index.md` regeneration + build-ledger row) | ☐ | run exit |
