# Packages — implementation brief

Canonical route: `/packages` · Owner: Packages (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 14 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Packages is the gating owner
of the extension lane's missing middle — see `internal-docs/implementation/odk-extension-apps.md`
§1 and §7. Program docs: `internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`.

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

**Corrected 2026-08-06 (post-close audit — G-1 truth refresh).** This paragraph
first read "`docs/architecture/_meta/schemas/` (158 files) contains **zero**
package/release/install/marketplace schemas". Two of them exist:
`hypervisor-surface-release-record.v1.schema.json` and
`hypervisor-surface-installation-binding.v1.schema.json`. The accurate claim is
that the registry contains **no package-candidate, marketplace, dependency, or
recall schema, and no daemon route consumes the two surface-record schemas that
do exist**. `docs/architecture/_meta/schemas/` the census's
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
  Foundry/worker admission copy). **Corrected 2026-08-06:** canonical `/packages`
  **does** resolve — `apps/hypervisor/scripts/v2-route-shell.mjs:249` registers it
  (W0.1 landed after the census snapshot this row cited). `/packages/marketplace`
  still does not: it appears only inside that entry's `rule` string (`:252`), and
  route lookup is exact-root-only (`:328`). So the shell route exists and has no
  Packages body behind it — a different and more actionable state than "does not
  resolve".
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

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none** — no vault names Packages as owner. The captures and the registry
slug both still carry the **retired owner name "Marketplace"**; canon makes
Marketplace the optional mode at `/packages/marketplace`, never a peer application.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `listings`** — route `/__ioi/marketplace/listings` (serve `:8815`); protected seed, class `daemon_wired`; inventory owner "Marketplace", **`reboundLane: "daemon marketplace listing plane"`** (`harvest-seed-inventory.mjs:61`) | **33 controls, 0 governed**: 4 `daemon_read` · 4 `local_view_interaction` · **15 `disabled_missing_authority`** · 1 `unsupported_reference_session` · 9 `reference_data_only` | Packages owns package, release, install, dependency, impact, and recall lifecycle (:849); Marketplace is the optional discovery mode (:1383) | see cluster rows | — |
| ↳ real listing reads | 4 `daemon_read` (**Estate Marketplace store row** with product count, row-navigate affordance, product card, product detail with version + documentation) | listings over the daemon listing plane | **rehome** — these four are the whole of what works, and they work over real daemon rows | W1 |
| ↳ local navigation | 4 `local_view_interaction` (all-stores back link, breadcrumb, upload-modal cancel/close) | local | **rehome** | W1 |
| ↳ **install / upload / installations cluster — the extension lane's missing middle, rendered** | 10 of the 15 `disabled_missing_authority`: **"Install" (enabled in the reference)**, Upload primary CTA, upload dropzone, upload-to-store, Installations button, Installations **Drafts (0) / Installed (24) / Jobs (18)** tabs, delete-all-drafts | **there is no `/v1/hypervisor/packages/*` route family at all** (`odk-extension-apps.md` §1); §2's whole registry family is route-missing | **blocked-missing-route** — and this is the most consequential block in the run: journey stages **6 and 7** (admit-and-version, install-and-register) are exactly these controls, and they are disabled because the plane behind them does not exist. The reference's counts (24 installed, 18 jobs) are fixture numbers and must never render | W3 |
| ↳ search / sort cluster | 5 `disabled_missing_authority` (search products, search stores, search products in store, products-column sort, plus the store search) | no registry to search | **blocked-missing-route** — folds into the same W3 registry build | W3 |
| ↳ **8 remote stores** | 1 `disabled_missing_authority` counted above: "8 remote stores (AIP Now / Palantir Learning / Machinery / Reference…)" | federation/discovery is optional and never substitutes for local admission (:1383) | **retire-at-cutover** — eight named remote stores the estate has no relationship with. Rendering them, even disabled, advertises a federation that does not exist | W4 |
| ↳ reference marketing | 9 `reference_data_only` (store icon chip, header title, hero + decorative illustration, 3-step "install your first product", Stores heading, Name/Products column headers, store icon + name header) + 1 `unsupported_reference_session` (global session chrome incl. AIP Assist) | fixture data must not render as truth | **retire-at-cutover** | W4 |
| **T2 marketplace readout** — `/__ioi/marketplace` (serve `:10025`), listings GET (`:8815`), new-listing form (`:10035`), listing POST (`:10040`); candidates / reviews / offers lanes | T2 census `nat-marketplace`: **9 controls, 0 disabled** | draft listing → publish-candidate → admission-review is the implemented plane (`hypervisor-daemon.rs:2041-2090`) | **rehome** — the admission-review lane is the closest thing the estate has to journey stage 6, and it is **marketplace admission, not package admission**. The two must not be conflated at rehome | W1 |
| **T5 `/__apps/listings`** — capture, `reference_capture`, capture state `boots_graph`, grammar `catalog`, high_value, `reboundLane: "daemon marketplace listing plane"`, note "store browse + install wizard; drill-down = named gap" (`:61`) | not in the 563 | the registered surface above | **rebind** — third of the three captures with a declared rebound lane; its lane is live for browse and **not** for install | W1 |
| **T5 `/__apps/registry`** — capture, `reference_capture`, capture state **`blocked_missing_capture`**, grammar `table_list`, high_value, `reboundLane: null`, "versioned artifact registry; unbound" (`:62`) | not in the 563 | **the versioned registry is precisely what does not exist** | **blocked-missing-capture** — and the block is doubly unfortunate: the one capture whose grammar is the versioned artifact registry cannot be inspected, and the registry it depicts has no routes. Neither half of the evidence is available | — |
| **Retired owner name "Marketplace"** — registry slug owner, capture owner fields, and the `/__ioi/marketplace*` route family | — | Packages owns the surface; Marketplace is the **optional mode at `/packages/marketplace`** (:901) | **recorded + retire-at-cutover** — the name rehomes into Packages and is never revived as a peer application | W4 |

**Census reconciliation.** Packages' one T3 surface carries **33 of the 563**
baseline controls: 4 + 4 + 10 + 5 + 1 + 9 = 33, exact. Its T2 readout adds 9
controls, 0 disabled, outside the baseline.

**Zero governed controls, and 15 of 33 disabled** — the highest disabled *ratio* of
any T3 surface in the run (45%, against `pipeline`'s 48% by count but 84 controls).
The reason is singular and worth stating once: **Packages is the owner of the
extension lane's missing middle, and its surface is an honest rendering of that
absence.**

**Disposition summary.** 3 rehome · 1 **rebind** · 0 pattern-harvest ·
3 retire-at-cutover · **2 blocked-missing-route** · **1 blocked-missing-capture**.

## 7. Ontology wiring

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Listing catalog + product detail | **none — not object-bound** | `/v1/hypervisor/marketplace/listings` (+ `/:id`) | Read + draft write | listings are platform objects |
| **`ontology_pack` listing kind** | `OntologyDevelopmentKitManifest` (`OntologyDevelopmentKitManifestEnvelope`) + the ontology, object-model, recipe, view, projection, and descriptor refs it packages | ODK manifests at `/v1/hypervisor/odk/manifests` (+ `/:id`) — `hypervisor-daemon.rs:1612-1621`; **no route joins a manifest to a listing** | Read (separately) | canon names marketplace-ready **ontology packs** as ODK output. Both halves exist — manifests are real, listings are real — and **nothing binds them**. This is the ontology-side statement of the same missing middle |
| Worker-package install admission | `OntologyToWorkerPlan` refs carried on a worker package | install admission planner is POST-only (`hypervisor-daemon.rs:1099`) | Write (planner) | the admission carries ontology refs; there is no read projection over what was admitted |
| **Write side — semantic plane** | **none.** Packages admits packages; it never writes a semantic fact | — | — | an admitted ontology pack does not become the domain's canonical ontology — admission records distribution, and local canonicality stays with the domain (non-negotiable 13) |

The ruling this surface most needs, because it is the one place it could go wrong
silently: **installing an ontology pack must not make its ontology locally
canonical.** Canon is explicit that no network-wide ontology may silently override a
domain's local one; a pack install admits an *available* ontology version, and
adopting it is a separate, domain-owned act.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md). **Packages is
the gating owner of the entire lane** — §1 of that doc concludes that the extension
lane is blocked on this surface's registry family, not on more ODK work.

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Listing catalog + store browse | `list_detail` | **exempt — no bindable primitive** | listings are platform objects |
| Product detail | `object_view` | **exempt — no bindable primitive** | same |
| Install wizard (when built) | `wizard` | **exempt — authority-crossing** | install is an admission; a descriptor scaffolds views, never admission |
| Installations tabs (Drafts / Installed / Jobs) | `list_detail` | **exempt — route-missing and no bindable primitive** | doubly blocked |

Zero expressible, zero rendered.

### (b) This surface as primitive exposer

**Packages owns journey stages 5, 6, and 7 — more than any other surface — and
owns none of them in code.**

| Journey stage (`odk-extension-apps.md` §2) | What Packages contributes | State today |
|---|---|---|
| **5 — package it** | `OntologyDevelopmentKitManifest` + a package candidate | manifests exist (`/odk/manifests`); **no package candidate object** |
| **6 — admit and version** | local package admission; immutable release | **route-missing — zero `/v1/hypervisor/packages/*` routes.** Marketplace admission-reviews exist and are a *different* admission |
| **7 — install and register** | installation binding + the `extension_application` registration | **route-missing.** Registrations are `include_str!` static, and **zero `extension_application` rows exist** |

Three boundaries, all canon and all load-bearing for the lane:

- **Marketplace admission is not package admission.** Optional Marketplace
  discovery or commerce never substitutes for local package or installation
  admission. The estate has the optional one and not the required one, which is the
  inversion at the heart of §1's finding.
- **Admission does not grant runtime.** An admitted release is not an installed
  binding, an installed binding is not an exposed catalog row, and none of them is a
  System binding for effectful launch.
- **Recall runs backwards immediately.** Disable, recall, and revocation remove
  launch eligibility at once (:1984-1985) — the compiler hook §2 lists as W3. Until
  it exists, **the estate can admit nothing and therefore cannot yet get recall
  wrong**; the hook must land with the registry, not after it.

The whole-run consequence, stated here because this is the surface that gates it:
**every "route-missing" in stages 5–9 across the other nineteen briefs resolves to
work on this surface.** Packages is the biggest build in the estate (§5) for a
reason that is now visible from every direction.
