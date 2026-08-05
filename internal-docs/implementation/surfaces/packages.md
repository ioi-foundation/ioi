# Packages — implementation brief

Canonical route: `/packages` · Owner: Packages (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted

## 1. Canon digest

- Packages is the **mandatory local lifecycle owner for reusable release
  material**: package candidates, immutable admitted releases, dependencies,
  installation bindings, serving eligibility, affected-System impact,
  deprecation, disable, recall, revocation, rollback inputs, and the receipts
  connecting those transitions (core-clients-surfaces.md:2536-2540). A package
  may carry an application, RuntimeToolContract, Worker, GoalRunProfile
  revision, WorkflowTemplate revision, HarnessProfile revision, SkillManifest
  revision, AutomationSpec revision, ontology/DataRecipe bundle, System
  profile, or generated interface without erasing that artifact's own
  canonical contract (:2540-2545).
- Packages contain immutable definitions, requirements, compatibility pins,
  templates — **never** SkillEntries, ActiveSkillSetSnapshots, concrete MCP
  gateway profiles, ContextLeases, RuntimeAssignments, authority grants,
  connector credentials, or subject/session/run-scoped bindings (:2547-2553).
- Package admission grants **no** runtime authority, live System, or
  launchability. Installation and serving are explicit bindings evaluated
  against org/Project/System/policy/capability/dependency/environment/
  authority context. Agentgres retains admitted package/install truth;
  daemon/Core executes admitted effects; wallet.network governs protected
  authority; Packages supplies the lifecycle projection and requests owners
  admit transitions (:2555-2561).
- **Marketplace is an optional Packages mode** and distribution channel; a
  private/air-gapped deployment retains complete package/release/install/
  disable/recall/revocation semantics without it; a `Marketplace` entry point
  resolves to `Packages / Marketplace` and never becomes a second package
  owner (:2563-2568; route rule :901 — Marketplace mode at
  `/packages/marketplace`; tool placement :1414).
- **Recall and revocation are not cosmetic**: the product-surface compiler
  must immediately remove ineligible launches, expose affected installs and
  Systems, and route protected stop/rollback/migration/remediation through
  their canonical owners; Packages must not silently mutate or terminate a
  live System because one release changes state (:2570-2574; compiler rule
  "Disable, recall, and revocation remove launch eligibility immediately"
  :1982-1985).
- Implementation status per canon itself: target owner; the unified Packages
  workspace, admitted install registry, compiler integration, and
  Marketplace-as-mode migration are **not yet shipped** (:2576-2579).
- The normalized surface record family Packages projects: registration →
  `HypervisorSurfaceReleaseRecord` (one immutable release; `package://.../release/...`)
  → `HypervisorSurfaceInstallationBinding` (`install://...`) →
  `HypervisorSystemInterfaceBinding` → `HypervisorSurfaceServingBinding`
  (:1865-1875; object shapes :3561-3584, :3586-3605, :3607-3624, :3626-3639).
  Ten independent state dimensions — a degraded install never becomes
  uninstalled/unadmitted/recalled by inference (:1842-1851).
- Adjacent ownership: extension applications are admitted and versioned by
  Packages, distributed possibly by Marketplace (:1436-1439); GoalRunProfile
  released revisions are versioned/distributed/recalled/revoked by Packages
  (:2647-2649); ODK manifests surface through Packages (:935-939); the
  Learning/Examples facet may appear inside Packages when a recipe can become
  governed work (:2230-2233).

## 2. Schema map

| Canon object / contract | Canon block | Daemon route(s) today |
|---|---|---|
| Package (candidate → admitted immutable release) | core-clients-surfaces.md:2536-2545 | `route-missing` — **W3** (`/v1/hypervisor/packages` family) |
| Release record (`package://.../release/...`, distribution, admission, disposition, capability depth) | :3561-3584 (HypervisorSurfaceReleaseRecord); census: 0 crates / 0 apps / 0 contract-registry (docs-only) | `route-missing` — **W3** |
| Installation binding (`install://...`, install/enablement states, audience, allowed objects/actions) | :3586-3605 | `route-missing` — **W3** (worker-package admission below is a planner, not a registry) |
| Deprecation / disable / recall / revocation transitions + receipts + affected-install/System impact | :2537-2540, :2570-2574 | `route-missing` — **W3** |
| Compiler hook: recall/disable/revocation removes launch eligibility immediately | :1982-1988 | GET /v1/hypervisor/product-surface-projections exists (hypervisor-daemon.rs:1059) but consumes no package state — hook is part of **W3** |
| Worker-package install **admission** (kernel planner: manifest/ontology/requirements/policy/receipt refs + wallet approval + gates; 202+record) | :2555-2558 | POST /v1/hypervisor/worker-package-install-admissions (hypervisor-daemon.rs:1099; lifecycle_routes.rs:6611-6631) |
| Managed-worker lifecycle admission (state machine + authority/archive/restore/deletion controls) | :2555-2561 | POST /v1/hypervisor/managed-worker-lifecycle-admissions (hypervisor-daemon.rs:1103) |
| MarketplaceListingDraft (kinds agent/domain_app/ontology_pack/data_recipe/foundry_capability) | :2563-2568 | hypervisor-daemon.rs:2027-2036 (list/create/get/patch/delete) |
| MarketplacePublishCandidate + publish (invariant: domain_app + admitted review + open ReleaseControl + serving DomainAppRuntime) | :2563-2568 | :2038-2052; invariant enforced in marketplace_routes.rs:4-9, 264-291 |
| MarketplaceAdmissionReview | :2570-2574 (admission before distribution) | :2053-2062 |
| ManagedInstanceOffer (runtime_posture instantiated:false — no instance lifecycle) | :2555-2556 | :2064-2073; marketplace_routes.rs:13-18,48 |
| Marketplace install/draft/job plane, product .zip upload/ingest, remote-store federation, cross-store search | :2563-2568 (distribution channel duties) | `route-missing` — **W3** (census `missing_authority_contracts`, 4 rows) |
| Domain-app substrate backing publishable listings (mount/serve ladder) | :1853-1859 context | hypervisor-daemon.rs:1853-1884 |
| ODK manifests (packaged through Packages) | :935-939 | hypervisor-daemon.rs:1602-1610 (reads); surface-descriptors :1633 |
| GoalRunProfile released revisions (Packages versions/recalls/revokes) | :2647-2649 | `route-missing` — **W3** (no goal-run-profile routes exist; lands as a package payload kind, not a parallel registry) |

`docs/architecture/_meta/schemas/` (158 files) contains **zero**
package/release/install/marketplace schemas; the census's
`registration_contract_implementation_status` shows all six surface-record
families at 0 in crates/apps/contract-registry. Every W3 row above ships its
JSON Schema + registry entry with the routes.

## 3. UI seed map

- **T3 registered surface `listings`** — surface-registry.mjs:58 (owner
  "Marketplace", title "Marketplace", route `/__ioi/marketplace/listings`,
  capabilities `["browse"]`). Storefront renderer serve-product-ui.mjs:
  5345-5400 (handler :8779): store row is daemon truth (listing count /
  published count); the install wizard band is reference chrome with the
  honest note "Installing from this surface is a reference-only lane (named
  gap)" (:5389). census: 33 controls — 16 implemented (4 daemon-read, 4
  local-view), **0 governed-receipted**, 15 disabled-missing-authority, 9
  reference-data-only — the estate's highest decorative ratio, confirmed.
  **partial** (reads wired, all install/upload/federation/search lanes dead).
- **T2 substrate readout `/__ioi/marketplace`** (renderer
  serve-product-ui.mjs:6180-6275; handlers :9989-10120): store facets +
  listing search (:6182-6189), listing draft create/edit/patch/delete
  (:10004-10047), publish-candidate create (:10067-10087, auto-create on
  publish-request :10037), admission-review create/delete (:10088-10095),
  runtime-backed Publish button rendered only when the daemon says
  `publishable` (:6247), managed-offer create/delete (:10096-…). All proxied
  to the daemon marketplace family. **wired** (the one governed publish
  ladder).
- **T4 seed**: `/__apps/listings` vendor capture (store→product→detail→
  Install ladder), preserved dormant; serve pins
  `isUploadFromMarketplaceEnabled=false` (census). Work-ledger backlinks
  resolve `marketplace-*` refs to `/__ioi/marketplace`
  (serve-product-ui.mjs:5844, :1518-1519).
- **No Packages UI exists at all**: no pane anywhere renders package,
  release, install, deprecation, or recall state (the words exist only as
  Foundry/worker admission copy). Canonical `/packages` and
  `/packages/marketplace` do not resolve (census `canonical_target_routes`:
  both `resolves: false`).
- Daemon-side marketplace substrate is empty in the live estate (census
  atlas: 0 listings / 0 published / 1 admitted review), so the storefront's
  real-data path shows the honest empty state.

### Corrections vs v0

- v0 said: "no package/release/install/recall registry — the biggest single
  backend build" — confirmed at the bytes (663-route sweep: no
  `/v1/hypervisor/packages/*`), with one sharpening: **an install-admission
  planner already exists** (POST /v1/hypervisor/worker-package-install-
  admissions, hypervisor-daemon.rs:1099 — pure kernel planner, 202 + record,
  wallet approval + policy gates, lifecycle_routes.rs:6611-6631). W3 must
  build the durable registry (packages/releases/installs/recall + reads)
  *around* this admission gate, not a second admission path.
- v0 said: "marketplace routes" flatly — bytes show the marketplace plane is
  10 routes with a **sharpened publish invariant already enforced**: a
  `domain_app` listing publishes only with an admitted MarketplaceAdmissionReview
  + an OPEN ReleaseControl + a backing DomainAppRuntime `mounted:true` and
  `serving:true`; published = read-only distribution metadata, never
  install/hire (marketplace_routes.rs:4-9, 264-291; hypervisor-daemon.rs:
  2047-2052). The rehome must carry this ladder intact — it is the estate's
  only working release-shaped flow and the seed for release-control wiring.
- v0 said: "inherits `listings` surface (highest decorative ratio)" — census
  bytes agree (15/33 disabled-missing-authority + 9/33 reference-data-only,
  0 governed), but the *substrate sibling* `/__ioi/marketplace` is the real
  inheritance: wired draft→candidate→review→publish→offer actions
  (serve-product-ui.mjs:9989-10120). Both move under `/packages/marketplace`.
- Packet said registered surfaces live at `apps/hypervisor/surfaces/<slug>/` —
  bytes: `listings` has no module dir; registration + renderer live in
  `scripts/surface-registry.mjs:58` and `scripts/serve-product-ui.mjs`.

## 4. Schema→UI binding table

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Packages catalog (all packages, disposition badges active/deprecated/superseded/recalled) | packages family · route-missing (W3) | absent | disabled-named-gap now → wired-read after W3 |
| Release detail + lifecycle strip (immutable release, pins, dependencies, capability depth, admission state) | HypervisorSurfaceReleaseRecord :3561-3584 · route-missing (W3) | absent | wired-read after W3; lifecycle strip per canon :1156-1256 |
| Installs view (org/project bindings, enablement, audience, affected Systems) | HypervisorSurfaceInstallationBinding :3586-3605 · route-missing (W3) | absent | wired-read after W3 |
| Install action (bind release into org/project) | worker-package-install-admissions :1099 today; full family W3 | invisible (POST-only, no UI, no read-back list) | wired-action-receipted via authority client (403 wallet challenge → 428 credential → receipted 202 record); read-back list is part of W3 |
| Deprecate / disable / recall / revoke verbs | recall transitions :2570-2574 · route-missing (W3) | absent | wired-action-receipted after W3; recall MUST drive the compiler hook (launch eligibility removed immediately, affected installs exposed; :1982-1985) — never silent System mutation (:2573-2574) |
| Rollback / remediation handoffs from a recalled release | :2572-2573 | absent | disabled-named-gap (actions route to canonical owners — Governance/Operations — not executed by Packages) |
| Marketplace mode `/packages/marketplace` · storefront browse + store facets + listing search | MarketplaceListingDraft · GET /v1/hypervisor/marketplace/listings, /overview (:2023-2036) | wired (storefront + substrate) | wired-read |
| Marketplace · draft listing create/edit/delete (5 kinds, subject_ref resolved against real substrate) | :2027-2036; kind validation marketplace_routes.rs:40-46,155-190 | wired | wired-action-receipted |
| Marketplace · publish candidate create + readiness reasons | :2038-2046; publishable computation marketplace_routes.rs:264-291 | wired | wired-action-receipted |
| Marketplace · Publish (runtime-backed, domain_app-only) | POST :id/publish (:2047-2052) + publish receipts (`marketplace-publish-receipts`, marketplace_routes.rs:35) | wired | wired-action-receipted (the ladder is the seed for release-control integration) |
| Marketplace · admission review create/decide | :2053-2062 | wired | wired-action-receipted (`reviewer_ref` becomes a principal per Governance brief) |
| Marketplace · managed-instance offers | :2064-2073; instantiated:false invariant marketplace_routes.rs:13-18 | wired (draft only) | wired-action-receipted; instantiation stays out (no instance lifecycle here) |
| Marketplace · Install-a-product flow (drafts/installed/jobs), .zip upload, remote stores, cross-store search | route-missing (census 4 missing-authority rows) | dead (reference chrome) | disabled-named-gap; install re-enters through the W3 packages install plane, not a marketplace-side install runtime |
| Package payload drill-ins (GoalRunProfile / WorkflowTemplate / HarnessProfile / SkillManifest / AutomationSpec revisions, ODK manifests) | :2540-2545; odk manifests reads :1602-1610 | absent | wired-read links to payload owners after W3 (a package never erases the payload's own contract) |
| Session/run-scoped rows (if any pane lists work serving a package) | C-1: `subject_attachments` only (:3971-3990) | n/a | any session-serving row binds through `subject_attachments`; packages never contain such bindings at rest (:2548-2553) |

## 5. Ordered PR list

1. **W0 (rides W0.2/W0.3)** — register Packages + the Marketplace-mode route
   in the v2 shell + compiler feed (`/packages`, `/packages/marketplace`).
2. **W1** — `/packages` read-first shell: honest-absence Packages catalog
   (named gap panel citing the missing registry), plus working reads that
   exist today — marketplace overview/listings, domain-apps, ODK manifests,
   admission-record raw views where readable. Zero fixture data.
3. **W1** — rehome the storefront + substrate under `/packages/marketplace`:
   one surface, storefront browse + governed ladder together (reads first;
   legacy `/__ioi/marketplace*` keeps serving until cutover).
4. **W2** — marketplace ladder actions through the authority client with
   receipts surfaced inline: draft/patch/delete, candidate create, review
   decide, publish, offer draft; every other control disabled-named-gap.
5. **W3.a (backend, serialized on hypervisor-daemon.rs)** — `packages/*`
   family cut 1: Package + Release CRUD (draft → admitted immutable release),
   JSON Schemas + contract-registry entries, receipts on every transition.
6. **W3.b** — install plane: durable install bindings with read-backs,
   fronted by the existing worker-package-install-admission planner as the
   admission gate; enablement + audience + affected-System projection.
7. **W3.c** — deprecation/disable/recall/revocation transitions + the
   **compiler hook**: product-surface-projections (:1059) consumes package
   state so recall removes launch eligibility immediately and exposes
   affected installs/Systems; remediation verbs route to owners.
8. **W3.d** — UI for W3.a-c in the same wave: catalog, release detail with
   lifecycle strip, installs view, recall cockpit (read-first, then verbs).
9. **W3.e** — Marketplace federation/install-visibility gaps re-filed over
   the new registry (marketplace install views project `install://` truth;
   upload/ingest lands as package-candidate intake, not a storefront `.zip`
   lane).
10. **W4** — package/release/install/recall event classes ride
    `/v1/event-streams` + `/v1/subscriptions` (no per-resource SSE).
11. **W4** — cutover: `/__ioi/marketplace` + `/__ioi/marketplace/listings`
    retire with typed 410s; `listings` row exits surface-registry.mjs;
    `/__apps/listings` capture stays dormant T4 evidence; Marketplace
    resolves only as `Packages / Marketplace` (:2567-2568).
