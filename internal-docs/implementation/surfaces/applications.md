# Applications — implementation brief

Canonical route: `/applications` · Owner: core workspace (Applications)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 19 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Applications is the catalog, launcher, and vertical surface layer; an
  Application is a registered specialized UI/work surface over Hypervisor
  Core that projects typed domain objects without owning their truth
  (core-clients-surfaces.md:1733-1747).
- Route rule: `/applications` — **"one catalog/compiler projection"**
  (core-clients-surfaces.md:888). An extension application's general route is
  compiled as `/applications/{surface_key}` (core-clients-surfaces.md:908-909).
- Registration contract: every durable surface has one discriminated
  registration (`owner_application` | `substrate_application` |
  `tool_surface` | `extension_application`); core workspaces use a sibling
  `HypervisorCoreWorkspaceRegistration` so one compiler serves navigation
  without pretending Home/Systems/Projects/Applications/Work is an
  application (core-clients-surfaces.md:1775-1794).
- Ten independent state dimensions (publisher, origin, creation method,
  distribution, availability, admission, installation, package disposition,
  enablement, capability depth, operational state); none derived from another
  (core-clients-surfaces.md:1804-1851).
- Six-record normalized family: `HypervisorApplicationSurfaceRegistration`,
  `HypervisorSurfaceReleaseRecord`, `HypervisorSurfaceInstallationBinding`,
  `HypervisorSystemInterfaceBinding`, `HypervisorSurfaceServingBinding`,
  `HypervisorProductSurfaceProjection` (core-clients-surfaces.md:1864-1876);
  registrations declare routes, contracts, authority posture, receipt
  obligations, placements, composition pattern (:1877-1911); tool
  registrations declare exactly one primary owner (:1913-1921); effectful
  System interfaces must bind admitted package + installation + System +
  allowed-action + authority-preview before launch (:1922-1929).
- Product-surface compiler: navigation, Applications, command palette,
  contextual launch, search, recents, favorites, recommendations all come
  from ONE compiler; policy filtering before aggregation and caching; drafts
  never launchable; disable/recall/revocation remove launch eligibility
  immediately; partial failure preserves safe static first-party inventory
  (core-clients-surfaces.md:1964-1988); stable groups without new
  registrations (:1990-2001); capture provenance/pixel certificates have zero
  authority over catalog membership (:2006-2008).
- First-party owner set: 12 owners + Environments/Operations substrate lane +
  conditional Embodied Systems, planned and nonlaunchable
  (core-clients-surfaces.md:1756-1765; :921-923).
- MCP Apps are sandboxed extension surfaces; UI actions still cross MCP
  Gateway/RuntimeToolContract/daemon/policy/authority/receipt boundaries
  (core-clients-surfaces.md:1796-1802).

## 2. Schema map

| Canon object / contract | Registry entry | Daemon route(s) today |
| --- | --- | --- |
| All six normalized records | ALL SIX registered: `hypervisor-application-surface-registration.v1.schema.json`, `hypervisor-surface-release-record.v1.schema.json`, `hypervisor-surface-installation-binding.v1.schema.json`, `hypervisor-system-interface-binding.v1.schema.json`, `hypervisor-surface-serving-binding.v1.schema.json`, `hypervisor-product-surface-projection.v1.schema.json` + entries in `architecture-contract-registry.v1.json` | POST `/v1/hypervisor/product-surface-projections` (hypervisor-daemon.rs:1060; handler lifecycle_routes.rs:6004-6123) over the static normalized record set `hypervisor_daemon_routes/hypervisor_surface_records.json` (15 registrations, 14 releases/installations/serving bindings, 0 system bindings; taxonomy names the six contracts in `normalized_record_contracts`) |
| `HypervisorCoreWorkspaceRegistration` | NO schema, NO registry entry (canon names it at :1791-1794) — the operative stand-in is the taxonomy's `core_workspaces` rows (six workspaces incl. Settings, hypervisor_core_taxonomy.json) | GET `/v1/hypervisor/core-taxonomy` (hypervisor-daemon.rs:1056); workspaces projected always-launchable by the compiler handler (lifecycle_routes.rs:6042-6057). Schema registration = small registry PR (rides the W4 canon-nit) |
| Compiler projection semantics | `hypervisor-product-surface-projection.v1.schema.json` | Handler joins registration → admitted+active release → installed+enabled installation matched to the REQUEST org → serving binding; `launchable` requires all three; else `disabled_reason_codes: ["no_eligible_release_installation_or_serving_binding"]` (lifecycle_routes.rs:6058-6103). Response = `workspace_entries` + `application_entries` + `request_context_hash` + `policy_decision_refs`, `read_model_only: true` (:6110-6123) |
| Compiler gaps vs canon | canon :1982-2001 | PARTIAL: policy filtering is caller-supplied `allowed_surface_refs` only; `requested_group_kinds` accepted but NO groups emitted; `system_interface_bindings` never joined; records are compiled-in static JSON (`include_str!`, lifecycle_routes.rs:6013, :6025-6027). **W3** |
| Surface descriptors (ODK input, "not a launchable application by itself" :1928-1929) | ODK plane | GET/POST `/v1/hypervisor/odk/surface-descriptors` (hypervisor-daemon.rs:1613), GET/PATCH/DELETE `:id` (:1618), top-level GET alias `/v1/hypervisor/surface-descriptors` (:1634) |
| Domain apps (generated extension surfaces) | draft plane over ODK `domain_app` descriptor | overview (:1854), GET/POST `/v1/hypervisor/domain-apps` (:1858), GET/PATCH/DELETE `:id` (:1863), governed mount/unmount — requires approved ApprovalRequest + open ReleaseControl, emits receipt + durable DomainAppRuntime (:1872, :1876 + comment block :1866-1871), serve/stop-serving (:1881, :1885), runtimes (:1889, :1893) |
| Favorites/recents/preferences substrate | admitted preferences | GET `/v1/hypervisor/preferences`, PUT `:id` (hypervisor-daemon.rs:1064, :1068; principal+org-scoped, lifecycle_routes.rs:6126-6150) |
| Dynamic registration admission (extension/tool CRUD, install/enable/disable/recall) | taxonomy declares `dynamic_registration_classes: [tool_surface, extension_application]` | `route-missing` — no route mutates the record set; install/recall verbs don't exist. Lands with/behind the Packages registry build. **W3** |
| Retired-route enforcement | taxonomy `retired_routes` (`/sessions`→`/work/sessions`, `/missions`→`/work`, `/__ioi/*`→null) | `/sessions`, `/missions`, `/__ioi/*path` already typed-410 at daemon level (hypervisor-daemon.rs:610-612) |

`route-missing` W3 build-list: dynamic registration/admission family
(extension + tool registration CRUD, installation/enablement/recall verbs,
durable record storage replacing `include_str!`), compiler grouping +
policy-filter + system-interface join. All other Applications needs ride
existing routes.

## 3. UI seed map

The three hand-maintained catalogs (the compiler's kill list), live
coordinates today:

1. **T1 shell grid** — `IOI_APPS`, 15 hand-written entries
   (apps/hypervisor/scripts/augmentation/30-shell.js:5-21). Retired taxonomy
   names still shipping: Missions → `/__ioi/sessions` (:11), Marketplace
   (:16), Workbench (:17); Evaluations → `/__ioi/feedback` (:13).
2. **T2 `/__ioi/applications` readout** — `SUITE` (13) + `SUBSTRATE` (2)
   arrays inside `renderApplications()`
   (apps/hypervisor/scripts/serve-product-ui.mjs:1450-1473; route handler
   :8533-8537). Diverges from catalog #1 on the same families the 07-30 audit
   flagged: Missions → `/__ioi/missions` (:1461), Evaluations →
   `/__ioi/evaluations` (:1463) — a user clicking the same tile name lands on
   different surfaces depending on which catalog rendered it.
3. **App catalog projection** — `app-catalog.mjs` (92 lines): membership =
   parity-matrix + atlas contract evidence, presentation from
   `surface-registry.mjs` `SURFACES` (14 slugs: missions, pipeline, sources,
   schema, explorer, approvals, incidents, models, listings, designer,
   machinery, monitors, changes, evalsuites — surface-registry.mjs:50-63);
   served at `/__ioi/api/applications` (serve-product-ui.mjs:8527-8532) and
   consumed by the readout's "Ported apps" band (:1479-1486, whose own
   comment says "never a hand list" — true only for this third band).
- census: `nat-applications` `/__ioi/applications` 200, 30 controls, 0
  disabled; 14 registered T3 applications; vendor SPA has no `/applications`
  route (`resolves: false`) (census: inventory.v1.json).
- **Daemon-side seed is ahead of the UI**: nothing in the UI consumes
  POST `/v1/hypervisor/product-surface-projections` yet — the compiler
  projection exists server-side with launchability joins and honest disabled
  reasons, while all three UI catalogs remain hand lists.
- Classification: catalogs #1/#2 = wired-but-hand-maintained (delete
  targets); catalog #3 = wired evidence-gated membership (survives as
  implementation evidence only, zero catalog authority per canon :2006-2008);
  compiler-fed grid/palette/search/recents = absent.

### Corrections vs v0

- The packet seed and census both call the six-record family absent:
  census `registration_contract_implementation_status` records
  `contract_registry: 0` and `crates: 0` for all six records (+ the
  core-workspace sibling) — **stale on both axes**. Bytes: all six schemas
  exist as files with registry entries (docs/architecture/_meta/schemas/),
  and crates carry a normalized record set + a working compiler projection
  route (hypervisor_surface_records.json; lifecycle_routes.rs:6004-6123).
  Still absent everywhere: `HypervisorCoreWorkspaceRegistration` (schema and
  registry only — the taxonomy rows exist in crates).
- v0 W0.2 says the three catalogs are killed by the compiler and that
  `surface-descriptors`, `product-surface-projections`, `domain-apps` routes
  exist — confirmed, but v0 undersells the daemon: the projection route is
  not a stub; it already computes per-org launchability with honest
  `disabled_reason_codes` and emits `workspace_entries` for all six core
  workspaces. W0.2 is mostly a UI-consumption task plus the W3 dynamic-record
  gap, not a backend build.
- v0 §5 and the memory note carry a "five-vs-six core-workspace count drift"
  — the drift is canon-doc-side only; the daemon taxonomy already registers
  SIX workspaces including Settings (hypervisor_core_taxonomy.json
  `core_workspaces`).
- Audit catalog cites have drifted: catalog #2 lived at
  serve-product-ui.mjs:1174-1191 on 2026-07-30; it is at :1450-1473 today
  (content divergences unchanged, spot-checked Missions/Evaluations rows).

## 4. Schema→UI binding table

Launch is navigation over a compiled projection (read); admission-class verbs
(mount/serve/install/recall) are authority-crossing and use the W0.3
CapabilityLease client (403 wallet challenge → 428 credential → receipted).
Contextual launch rows that reference Sessions bind through
`subject_attachments` context refs, never named app-family fields.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Shell rail + Applications grid | `HypervisorProductSurfaceProjection` — POST `/v1/hypervisor/product-surface-projections` (hypervisor-daemon.rs:1060) | hand catalog #1 (30-shell.js:5-21) | `wired-read` from the compiler; catalog #1 `delete` |
| `/applications` workspace page (catalog, groups, honest disabled reasons) | same projection; groups per canon :1990-2001 | absent at canonical route; hand catalog #2 at `/__ioi/applications` | `wired-read`; groups render client-side until the W3 handler grouping, then compiler-emitted |
| Command palette / search / contextual launch | same projection + typed context route resolvers (taxonomy `context_route_resolver_contract`) | absent (vendor palette only) | `wired-read` |
| Recents / favorites bands | preferences plane — GET/PUT `/v1/hypervisor/preferences` (hypervisor-daemon.rs:1064-1068) | absent | `wired-read` (admitted preferences only) |
| Application detail page (ten-dimension lifecycle strip, release/installation/serving identity kept distinct) | registration + release + installation + serving join (lifecycle_routes.rs:6058-6103) | absent | `wired-read` |
| Launch action per row | `resolved_launch_route` + `launchable` from the projection | partial (readout cards link hand-coded hrefs) | `wired-read` (navigation; disabled rows show `disabled_reason_codes` verbatim) |
| Extension app frame `/applications/{surface_key}` | domain-app serving + runtimes (hypervisor-daemon.rs:1881-1893) | absent (draft plane wired daemon-side only) | `wired-read` frame over serving records; empty state honest while no runtime serves |
| Domain-app mount/unmount/serve/stop controls | governed admission routes, receipted (hypervisor-daemon.rs:1872-1885) | absent in UI | `wired-action-receipted` via authority client (W2) |
| Install / enable / disable / recall controls | no routes (static record set) | absent | `disabled-named-gap` → W3 dynamic registration family (+ Packages registry hook so recall removes launches, v0 §3.10 seed) |
| Surface-descriptor library view (ODK inputs; "not launchable by itself") | odk/surface-descriptors routes (hypervisor-daemon.rs:1613-1634) | absent here (ODK readouts exist elsewhere) | `wired-read` reference pane linking into Studio/ODK owners |
| `/__ioi/applications` readout + `/__ioi/api/applications` | catalogs #2/#3 | serving | `delete` at W4 cutover (typed 410); parity-matrix evidence files remain as tool-registration implementation evidence (canon :2006-2008) |
| Retired tiles the catalogs still advertise (Missions, Marketplace-as-peer, Workbench naming) | taxonomy `retired_routes`; canon :1742-1747 | wired-to-wrong-target (30-shell.js:11-17) | `delete` with the catalog they live in (W0.2) |

## 5. Ordered PR list

1. **W0 (W0.2a)** — Shell launcher consumes POST
   `/v1/hypervisor/product-surface-projections` for the rail + Applications
   grid (`workspace_entries` + `application_entries`); delete `IOI_APPS`
   (catalog #1). Partial-failure path renders the static first-party set from
   the same response contract, never a hand list.
2. **W0 (W0.2b)** — `/__ioi/api/applications` and the readout's launcher
   bands re-render from the same projection; catalog #3 membership demoted to
   implementation evidence (no catalog authority); catalog #2's SUITE/
   SUBSTRATE arrays deleted.
3. **W0 (W0.2c)** — Palette/search/recents/favorites over the projection +
   preferences plane; policy filtering happens before any client-side
   aggregation or caching.
4. **W1** — `/applications` workspace page at the canonical route: compiled
   catalog with groups, honest `disabled_reason_codes`, and the application
   detail page with the ten-dimension lifecycle strip (release/installation/
   serving identities kept distinct per canon :1985-1988).
5. **W2** — Domain-app admission controls (mount/unmount/serve/stop) through
   the authority client; every enabled control receipted; extension frame
   `/applications/{surface_key}` renders serving runtimes read-first.
6. **W3** — Dynamic registration family, backend-first: durable six-record
   storage replacing `include_str!` + registration/installation/enablement/
   recall routes (sequenced with the Packages registry build — recall must
   remove launch eligibility immediately); compiler handler adds grouping,
   `system_interface_bindings` join, and daemon-side policy filtering; then
   the registration-management UI in the same wave.
7. **W3/W4 (canon+registry nit)** — Register
   `HypervisorCoreWorkspaceRegistration` in the schema registry and fix the
   five-vs-six workspace count drift in the 5 canon locations (one-line canon
   PR; daemon taxonomy already correct).
8. **W4** — Cutover: `/__ioi/applications` + `/__ioi/api/applications`
   deleted with typed 410s; extension routes live under
   `/applications/{surface_key}`; zero hand-maintained catalog bytes remain.
