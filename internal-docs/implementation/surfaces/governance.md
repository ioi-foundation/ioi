# Governance — implementation brief

Canonical route: `/governance` · Owner: Governance (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 5 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended; §3 readout cite refreshed and
the approvals census completed (2026-08-06 addendum under Corrections). Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Governance is the authority and control surface: approvals inbox, authority
  scopes and capability leases, release gates, cohorts, kill switches, budgets,
  retention/marking policy, justification checkpoints; constitution and
  protected-amendment history, ordering/finality, oracle policy,
  successor/guardian paths, migration/fork/adoption, dissolution/decommission,
  and IOI Network enrollment/assurance are explicit high-assurance facets
  (core-clients-surfaces.md:1325-1331; rail summary :841).
- Canonical route `/governance`, no aliases; legacy paths die with typed
  refusals at cutover (core-clients-surfaces.md:896, :876-880).
- Lifecycle "Govern" verb: wallet.network, authority scopes, capability leases,
  approvals, secrets, policy gates, privacy, declassification, risk, semantic
  governance, registries (core-clients-surfaces.md:1128-1131); Governance also
  owns activation, canary/cohort, rollback, recall, and recovery decisions in
  the Improve verb (:1143).
- Release/change controls are a Governance facet — the primary cockpit for
  capability promotion, release, rollout, pause, rollback, recall, kill-switch,
  remote-config, release-target, gate, cohort, and deployment-risk
  coordination (core-clients-surfaces.md:1164-1168). They may appear as an
  Open Application view, panel, or detail drawer but never become a permanent
  shell rail item or separate peer product (:1176-1179). `Release Controls` /
  `Authority / Govern` are facet aliases, not products (:2143-2146).
- Approvals is a tool surface placed at Governance / Approvals; direct launch
  opens it under the owner and current context, never as a peer product
  identity (core-clients-surfaces.md:1412, :1428-1431).
- Enterprise Learning Boundary: Governance owns boundary policy, exceptions,
  declassification, export, deletion, revocation, incident, and system-upgrade
  review; boundary is primarily configured in Governance + settings
  (core-clients-surfaces.md:1077-1078, :1052-1053).
- Governance decides activation and effect recovery; Improvement coordinates;
  the lifecycle projection is never a new truth store — Agentgres admits truth,
  wallet.network authorizes, the daemon executes
  (core-clients-surfaces.md:1249-1254, :1354, :4808).
- May never: own runtime truth (application surfaces are governed projections
  over Core/daemon/Agentgres/wallet.network — core-clients-surfaces.md:1470-1473);
  execute enforcement from the UI without an existing daemon authority route;
  masquerade Work views (reviews/incidents) as Governance-owned tools (:1421-1426).
- Systems workspace "Govern" mode projects Governance authority, budgets,
  protected change, learning boundary, lifecycle, enrollment
  (core-clients-surfaces.md:1650).

## 2. Schema map

Daemon-local record schemas exist for every governance control object
(`ioi.hypervisor.governance.*.v1`, minted in governance_routes.rs — e.g. :585);
NONE of them are in the schema registry (`docs/architecture/_meta/schemas/
architecture-contract-registry.v1.json` carries no governance control-object
contracts — only authority-grant-envelope v1/v2, authority-effect-admission-
receipt v1, declassification-approval v1 among the related set). Registry
admission for the governance family is program debt, tracked here but not a
route gap.

| Canon object / contract | Canon block / registry | Daemon route(s) today | Wave |
| --- | --- | --- | --- |
| GovernanceOverview (read projection over authority/identity/lease/admission substrate, names missing controls) | core-clients-surfaces.md:1325-1331 | `GET /v1/hypervisor/governance/overview` hypervisor-daemon.rs:1955-1958 (comment :1953-1954) | — |
| ApprovalRequest (record-only transitions, receipted) | :1326 approvals inbox | `GET/POST /v1/hypervisor/governance/approval-requests` hypervisor-daemon.rs:1962-1966; `GET/PATCH/DELETE …/:id` :1967-1971 | — |
| ApprovalTransitionReceipt (`ioi.hypervisor.governance.approval-transition-receipt.v1`) | :2737-2749 receipts doctrine | **route-missing** — persisted write-only under `governance-approval-transition-receipts` (governance_routes.rs:372, :691-699); no read route anywhere | W3 |
| ReleaseControl | :1164-1168 | `GET/POST /v1/hypervisor/governance/release-controls` + `:id` GET/PATCH/DELETE hypervisor-daemon.rs:1984-1993 | — |
| KillSwitch (+ enforcement after trip, domain-app runtimes only) | :1327 | CRUD hypervisor-daemon.rs:1995-2003; `POST …/:id/enforce` :2006-2008 | — |
| ImprovementGate | :1327-1328 (release gates) | CRUD hypervisor-daemon.rs:2010-2018 | — |
| Cohort | :1327, :1143 | CRUD hypervisor-daemon.rs:1973-1982 | — |
| CapabilityLease (browser: every issued use-only lease, 9-field shape, never a credential) | :1327 | `GET /v1/hypervisor/capability-leases` hypervisor-daemon.rs:2975-2977 (lifecycle_routes.rs:12064-12070); list only — detail/revoke **route-missing** (scoped revokes exist: editor-access-leases :3179-3184, principal lease-grants DELETE :3383-3390) | W3 |
| AuthorityGrantEnvelope v1/v2 | registry `authority-grant-envelope.v1/v2.schema.json` | `POST /v1/hypervisor/authority/grant` :2736-2738, `POST …/revoke` :2740-2742, `GET …/grants` :2744-2746 | — |
| Authority posture / evaluate / preflight / providers | :1128-1131 | hypervisor-daemon.rs:2722-2724, :2726-2728, :2748-2750, :2732-2734 | — |
| AuthorityEffectAdmissionReceipt | registry `authority-effect-admission-receipt.v1.schema.json` | `GET /v1/hypervisor/authority/receipts` :2752-2754 (authority_routes.rs:882-886, `authority-receipts` dir) | — |
| Thread/tool-exec approvals (approval plane #2) | :2706-2710 authority gates in session view | `POST /v1/threads/:id/approvals` + `:approval_id/decision|approve|reject|revoke` hypervisor-daemon.rs:932-951 | — |
| ImprovementProposal decisions (approval plane #3; owner Improvement, inbox projects) | :1348-1354 | `…/improvement-proposals/:id/approve|reject|apply` hypervisor-daemon.rs:1716-1726 (list/get/simulate :1698-1713) | — |
| MemoryMutationProposal decisions (approval plane #4) | :949-1048 memory placement | `…/memory-mutation-proposals/:id/approve|reject` hypervisor-daemon.rs:1748-1759 | — |
| Marketplace AdmissionReview (decision-shaped, `reviewer_ref` free text) | :1380-1384 | `GET/POST /v1/hypervisor/marketplace/admission-reviews` + `:id` hypervisor-daemon.rs:2053-2062 (marketplace_routes.rs:861, :905) | — |
| Unified approvals-inbox projection (one queue over the four decision planes) | :1326; `ioi.hypervisor.governance.approvals-inbox.v1` | **LANDED W0.6**: `GET /v1/hypervisor/governance/approvals-inbox` hypervisor-daemon.rs:1987 (handler governance_routes.rs:778) — folds pending governance approval-requests, thread/tool-exec approvals (kernel approval-queue projection across agents, helper lifecycle_routes.rs:176), improvement proposals (`state=="pending"`), memory-mutation proposals (`review_state=="proposed"`); marketplace admission-reviews (`decision=="pending"`) are pending-decision rows; the POST-only `*-admissions` planners are a NAMED plane (pending 0, routes mechanically derived) — never silent absorption. Read-only: each row's `decide` points at the plane's existing mutation route | — |
| Rollout promote/rollback (policy canary) | :1143 | `POST /v1/goal-orchestration/ioi-agent/launch-policies/:id/rollout/promote|rollback` hypervisor-daemon.rs:1789-1795 | — |
| Budgets | :1327 | `GET/POST /v1/hypervisor/resource/budgets` :2762-2764; `/v1/hypervisor/budget` + `/reconcile` :3007-3013 | — |
| Retention/marking policy, justification checkpoints, constitution/amendment history, network enrollment | :1328-1331 | **route-missing** — zero daemon routes match constitution/enrollment/retention/justification (grep verified); constitution schemas exist registry-side only | W3 (file as named gaps; build only if ruled in) |

## 3. UI seed map

- **Registered T3 surface `approvals`** (`apps/hypervisor/surfaces/approvals/index.mjs`,
  272 lines; meta route `/__ioi/governance/approvals`, verifier + pixel
  certification, index.mjs:44-49). Wired read over
  `/v1/hypervisor/governance/approval-requests` (:51-54) plus the estate's
  action-runtime pilot: approve / reject / revoke declared with authority
  plane, expected receipt family, and confirm rules (:72-74); success without
  the declared `approval-transition-receipt.v1` FAILS CLOSED (:87-91).
  Classification: wired-read + 3 receipted actions. census: 40 controls, 35
  implemented, 9 daemon_read, 3 governed_receipted, 13 disabled_missing_authority.
- **Native readout `/__ioi/governance`** — control cockpit
  (serve-product-ui.mjs:9901-9932): reads all five governance control families
  + domain-apps + marketplace candidates/listings + foundry specs/plans in one
  page; tabbed. Record-only POST mutation forms per family at
  `/__ioi/governance/<fam>` (serve-product-ui.mjs:9937-9944). Classification:
  wired (reads + record-only transitions). census: 23 controls, 0 disabled.
- **Approvals deep links from other readouts**: home/ops surfaces link
  `/__ioi/governance?tab=approvals` (serve-product-ui.mjs:1062); agent-studio
  improvements embed approve/request-approval forms
  (serve-product-ui.mjs:2704-2705). Classification: wired.
- **Authority / lease browsing: absent.** No UI over
  `/v1/hypervisor/authority/{posture,grants,receipts,providers}` or
  `/v1/hypervisor/capability-leases` — daemon reads exist, zero panes serve
  them. Classification: dead (backend-live, UI-absent).
- **Shell SPA**: no governance route; census `/governance` `resolves: false`.
  The 97-RPC adapter carries no approvals/governance RPCs (approvals surfacing
  named only as future work, ioi-api-adapter.mjs:1294).

### Corrections vs v0

- v0 said: "the unified inbox (W0.6) … folds the 4 disjoint approval systems" —
  bytes show exactly four decision planes to fold (governance
  approval-requests hypervisor-daemon.rs:1962-1971; thread/tool-exec approvals
  :932-951; improvement-proposal approve/reject/apply :1716-1726;
  memory-mutation-proposal approve/reject :1748-1759) **plus** two more
  decision-shaped planes v0 didn't count: marketplace admission-reviews
  (:2053-2062) and the POST-only `*-admissions` planner family (:1076-1104).
  The inbox folds the four; the extras get named rows, not silent absorption.
- v0 said: "`reviewer_ref` becomes a principal, not free text" — verified at
  the bytes, and it is worse than free text: any JSON value is accepted
  verbatim on transition (governance_routes.rs:718, :644-654; created null
  :592) AND `reviewer_ref` is patchable after decision through the
  non-transition metadata lane with no receipt and no revision bump
  (governance_routes.rs:739-751) — a decided approval's reviewer can be
  silently rewritten. Two defects, not one. Principals routes exist to bind
  against (`/v1/hypervisor/principals` hypervisor-daemon.rs:3369-3374).
- v0 said: Governance backend families "all exist" — true for the six control
  families, but their transition receipts are write-only (no read route,
  governance_routes.rs:372) and the approvals surface's own success banner
  links "proof stream" → `/__ioi/work-ledger`
  (surfaces/approvals/index.mjs:186-187), whose backing aggregate does NOT
  join `governance-approval-transition-receipts`
  (orchestration_routes.rs:532-951 enumerates every joined family; grep
  confirms absence) — the receipt drilldown dangles.
- census said `/__ioi/governance` 23 controls / approvals 40 controls
  (2026-07-30) — spot-verified both surfaces still exist and bind the same
  routes at the live tree (serve-product-ui.mjs:9901-9932;
  surfaces/approvals/index.mjs:51-54); counts not re-measured.

#### Addendum 2026-08-06 (mesh packet 5 — cite refresh + full census at `ba9e2ea0a`)

**Readout cite.** §3 gave the cockpit as `serve-product-ui.mjs:9901-9932` with the
per-family POST forms at `:9937-9944`. At the bytes the GET handler is at
**`:9938`** and the family POST lane at **`:9974`** (`pathname.startsWith(
"/__ioi/governance/")`). The composed reads and the tab structure are unchanged.

**Approvals census completed.** §3 listed "40 controls, 35 implemented, 9
daemon_read, 3 governed_receipted, 13 disabled_missing_authority" — those three
outcome buckets sum to 25, not 40. Recounted from
`application-operational-depth.json`, the full six-bucket breakdown is:

| outcome | count |
|---|---|
| `daemon_read` | 9 |
| `local_view_interaction` | 9 |
| `governed_receipted_action` | **3** |
| `disabled_missing_authority` | 13 |
| `unsupported_reference_session` | 1 |
| `reference_data_only` | 5 |
| **total** | **40** |

The three governed actions are approve / reject / revoke — **3 of the estate's
24 governed-receipted controls, on a single surface.** §6 clusters all forty.

## 4. Schema→UI binding table

Authority-crossing actions run through the W0.3 CapabilityLease client (403
wallet challenge → 428 credential → receipt refs on completion). Reads use the
uniform read-projection client. Rows naming session-serving data bind through
`subject_attachments` (core-clients-surfaces.md:3971-3990), never a named app
field.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Governance overview header (posture, counts, named missing controls) | governance overview · hypervisor-daemon.rs:1955-1958 | wired at `/__ioi/governance` | wired-read |
| Approvals inbox — unified queue (4 planes, one list, policy-filtered) | W0.6 inbox projection · route-missing | absent | disabled-named-gap until W0.6 lands, then wired-read |
| Approvals inbox — governance ApprovalRequest rows + detail | approval-requests · :1962-1971 | wired (T3 surface) | wired-read |
| Approve / Reject / Revoke | PATCH transition · :1967-1971 · receipt `approval-transition-receipt.v1` | wired, receipted, fail-closed (index.mjs:87-91) | wired-action-receipted (via lease client) |
| Reviewer field | `reviewer_ref` (free text today) | wired, defective | wired-action-receipted — principal ref validated against :3369-3374; metadata-lane rewrite closed |
| Receipt drilldown from decision banner | transition receipts · route-missing | dangling link to work-ledger | wired-read after W3 receipt read route (Provenance coordinates) |
| Thread/tool-exec approval rows in inbox | thread approvals · :932-951 | absent from any inbox | wired-action-receipted (decide via each plane's own route) |
| Improvement-proposal rows in inbox (decide deep-links to Improvement) | :1716-1726 | wired only in agent-studio readout (serve:2704-2705) | wired-read + cross-owner deep link |
| Memory-mutation-proposal rows in inbox | :1748-1759 | absent | wired-action-receipted |
| Release cockpit — ReleaseControl list/detail + record transitions | :1984-1993 | wired (record-only forms, serve:9937-9944) | wired-action-receipted |
| Release cockpit — KillSwitch list/detail | :1995-2003 | wired | wired-read |
| Kill-switch Enforce | `POST …/enforce` :2006-2008 | wired (form) | wired-action-receipted (lease flow; blast-radius confirm) |
| Release cockpit — rollout promote/rollback | :1789-1795 | absent | wired-action-receipted |
| Release cockpit — Cohorts, ImprovementGates | :1973-1982, :2010-2018 | wired (cockpit tabs) | wired-read + record transitions receipted |
| Authority browser — posture / providers / grants / receipts | :2722-2754 | dead (no UI) | wired-read |
| Authority browser — grant / revoke | :2736-2742 | dead | wired-action-receipted |
| Authority browser — evaluate / preflight (what-would-happen) | :2726-2728, :2748-2750 | dead | wired-read (POST, non-effectful) |
| Lease browser — capability-leases list | :2975-2977 | dead | wired-read |
| Lease browser — lease detail / generic revoke | route-missing | absent | disabled-named-gap (+ W3 row if ruled in) |
| Budgets facet | :2762-2764, :3007-3013 | dead | wired-read |
| High-assurance facets (constitution history, enrollment, retention/marking, justification checkpoints) | route-missing | absent | disabled-named-gap |

## 5. Ordered PR list

Router-file PRs (#1, #7, #8) are serial — the central router is a merge
hotspot (master guide standing rule; not re-decided here).

1. **W0.6** — `GET /v1/hypervisor/governance/approvals-inbox`: one projection
   folding the four decision planes (each row: plane, subject_ref, status,
   decide-route ref); policy filter before counts. Backend-only.
2. **W1** — `/governance` canonical route in the v2 shell: overview +
   control-family read panes rehomed from `/__ioi/governance` (rehome, don't
   rebuild; seed stays serving until step 9).
3. **W1** — Approvals tool at `/governance` embedding the existing T3
   approvals surface content; inbox list switches to the W0.6 projection when
   present, else governance approval-requests only.
4. **W1** — Authority-scope + lease browser: read panes over
   posture/providers/grants/receipts/capability-leases + budgets facet.
5. **W2** — Approve/reject/revoke + thread-approval + memory-proposal
   decisions through the authority client (403/428/receipt); improvement rows
   deep-link to Improvement's own decide surface.
6. **W2** — Release cockpit verbs: kill-switch enforce, rollout
   promote/rollback, receipted record transitions for
   release-controls/cohorts/gates; everything without a route stays
   disabled-named-gap.
7. **W3** — `reviewer_ref` → principal: validate against
   `/v1/hypervisor/principals`, refuse non-principal values, delete
   `reviewer_ref` from the receiptless metadata-patch allowlist
   (governance_routes.rs:739-751).
8. **W3** — Approval-transition-receipt read route + fold into the unified
   receipt stream (joint PR with Provenance brief step 6).
9. **W4** — Cutover: `/__ioi/governance*` retired with typed 410s per the
   6-step per-app rule; shell stops advertising the legacy paths.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Governance gains admission + required-check policy, authority freshness,
policy version/revocation, override justification, reconciliation approval,
and witness policy over the transition chain; it owns the provider-neutral
state vocabulary (epic §3 C1, P1) and the policy/override/revocation/
authority-freshness objects (C8). Approval legs of reconciliation (C7) land
at P3 through the unified inbox this brief already plans.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none.** No vault names Governance as owner. **Tier 5: none** — no
`/__apps/*` capture is Governance-owned; the `approvals` capture was **rebound into
the registered T3 surface**, which is why it appears as a T3 row below rather than a
T5 one (`ported-seed-preservation.v1.json`: slug `approvals`, route
`/__ioi/governance/approvals`, class `daemon_wired`).

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `approvals`** — `apps/hypervisor/surfaces/approvals/index.mjs` (272 lines), route `/__ioi/governance/approvals`, verifier + pixel certification (`index.mjs:44-49`), reads `/v1/hypervisor/governance/approval-requests` (`:51-54`) | **40 controls**, clustered below | Governance owns the decision plane; the unified approvals inbox landed at W0.6 (`GET /v1/hypervisor/governance/approvals-inbox`) | see cluster rows | — |
| ↳ **governed transition cluster** — approve / reject / revoke, reviewer attribution input, confirmation checkbox, success banner, refusal banner | 7 controls: **3 `governed_receipted_action`** + 3 `local_view_interaction` + 1 `daemon_read`. Actions declare authority plane, expected receipt family, and confirm rules (`index.mjs:72-74`); **success without the declared `approval-transition-receipt.v1` FAILS CLOSED** (`:87-91`) | receipted decisions over governed subjects | **rehome** — this is the estate's action-runtime pilot and the fail-closed check is its most valuable byte; it must survive the rehome verbatim, not be re-derived | W1 · W2 |
| ↳ inbox filter cluster — working | 5 controls: 4 `daemon_read` (Your inbox, All requests, status multiselect, list heading + count) + 1 `local_view_interaction` (clear filters) | inbox over the W0.6 unified plane | **rehome** — and **rebind** onto `approvals-inbox`, which folds the four decision planes the current surface does not see | W1 |
| ↳ inbox filter cluster — no authority | 9 `disabled_missing_authority` (created-by-you, request-type multiselect, created-by picker, assigned-to-you, project-requested-to, users/groups pickers, groups-requested-to, search box, sort menu) | filters need principal identity; `reviewer_ref` accepts any JSON verbatim today (§3 correction) | **retire-at-cutover** for the identity-shaped filters until principals bind (`/v1/hypervisor/principals`, `hypervisor-daemon.rs:3369-3374`); **rehome** for search + sort, which need no authority | W3 (identity) · W1 (search/sort) |
| ↳ record inspection cluster | 6 controls: 3 `daemon_read` (row select, subject-ref link, record fields — request id / reason / blast radius / created) + 3 `local_view_interaction` (empty state, close detail, terminal-state note) | subject deep-links to the owner; a decision names its subject | **rehome** — the subject-ref link is the one control that makes this surface object-aware (§7) | W1 |
| ↳ app header cluster | 2 controls: 1 `daemon_read` (substrate table link ⇱) + 1 `local_view_interaction` (title + icon) | — | **rehome** | W1 |
| ↳ vendor shell chrome cluster | 4 controls: 1 `local_view_interaction` (workspace sidebar) + 3 `reference_data_only` (global search, notifications, What's New / AIP Assist / Support) | hidden-UX carve-out; AIP Assist is a vendor faculty (standing P2 gate) | **retire-at-cutover** | W4 |
| ↳ absent governance affordances cluster | 5 controls: 4 `disabled_missing_authority` (reviewer assignment, delegation, SLA/escalation, audit exports) + 1 `unsupported_reference_session` (threaded comments) | **no canon contract for any of the five.** Delegation in particular is authority-shaped and would need its own admission | **retire-at-cutover** — these are not named gaps awaiting wiring; canon gives this surface no delegation, SLA, or comment plane | W4 |
| ↳ reference taxonomy cluster | 2 `reference_data_only` (reference request-kind taxonomy, reference status taxonomy) | the daemon's own request kinds and states are the truth | **pattern-harvest** — vocabulary shape only; the reference taxonomies must never be rendered as if they were the daemon's | — |
| **T2 governance cockpit** — `/__ioi/governance` (serve `:9938`), per-family POST lane (`:9974`) | T2 census `nat-governance`: **23 controls, 0 disabled**. Reads all governance control families + domain-apps + marketplace candidates/listings + foundry specs/plans in one tabbed page; POST forms are **record-only** | Governance owns approval-requests, release-controls, kill-switches, improvement-gates, cohorts, and the overview (`hypervisor-daemon.rs`, thirteen registered paths) | **rehome** — the tabbed cockpit becomes the `/governance` body; the record-only POST forms are demoted to `disabled-named-gap` until they cross the CapabilityLease client, since a record-only transition over a governed control is exactly the mutation-over-projection pattern the Agentgres positioning constraints forbid | W1 · W2 |
| **Deep links from other readouts** — home/ops link `/__ioi/governance?tab=approvals` (serve `:1062`); agent-studio improvements embed approve / request-approval forms (`:2704-2705`) | not census controls | approvals surface through their owner | **rehome** (link targets follow the surface) · the agent-studio embedded forms **retire-at-cutover** with Agent Studio's split-rehome (`studio.md`) | W1 · W4 |
| **Authority / lease browsing — absent** | zero panes over `/v1/hypervisor/authority/{posture,grants,receipts,providers}` and `/v1/hypervisor/capability-leases`; the daemon reads exist | Governance owns the authority plane read (§1) | **blocked-missing-route: no** — this is the inverse: routes exist, panes do not. Recorded as **build, not mesh**: there is no seed to disposition, so §5's W1 rows own it | W1 |
| **Dangling receipt drilldown** — the approvals success banner links "proof stream" → `/__ioi/work-ledger` (`surfaces/approvals/index.mjs:186-187`), whose aggregate does **not** join `governance-approval-transition-receipts` (`orchestration_routes.rs:532-951`) | not a census control | receipts must be reachable from the decision that produced them | **rehome with a named defect** — the link rehomes, but it dangles today and must render a named gap rather than an empty stream until the W3 read route lands (§2) | W1 · W3 |

**Census reconciliation.** Governance's one T3 surface carries **40 of the 563**
baseline controls: 7 + 5 + 9 + 6 + 2 + 4 + 5 + 2 = 40, exact. It holds **3 of the
estate's 24 `governed_receipted_action` controls — 12.5% of every governed control
in the estate, on a single surface.** Its T2 cockpit adds 23 controls, 0 disabled,
outside the baseline.

**Disposition summary.** 7 rehome (two of which also rebind) · 1 pattern-harvest ·
4 retire-at-cutover · 0 blocked. One row is recorded as **build, not mesh** (authority
browsing: routes exist, no seed to disposition) and one carries a **named defect**
(the dangling receipt drilldown).

## 7. Ontology wiring

Governance is **object-aware without being object-bound**, and the distinction is
the whole of its wiring story. An approval names a subject; that subject may be an
ontology-governed object, a Domain App, a release, or a platform record. Governance
reads the ref and renders it — it never resolves the object, never reads its
ontology, and never writes a semantic fact.

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Approval record — subject-ref link | **none directly.** `subject_ref` is an opaque typed ref that *may* name an ontology-governed object | `/v1/hypervisor/governance/approval-requests` | Read (deep link only) | the one object-aware control on the surface; it hands off rather than resolving |
| Unified approvals inbox (W0.6) | **none** | `/v1/hypervisor/governance/approvals-inbox` | Read | folds four decision planes; still ref-level |
| Release controls · kill switches · improvement gates · cohorts · overview | **none — not object-bound** | five family routes | Read + record-only POST | governance controls are platform objects |
| **Domain App mount gate** | `DomainApp` (`DomainAppEnvelope`), `DomainAppRuntime`, `DomainAppMountReceipt` | approval-request + release-control refs consumed by `POST /v1/hypervisor/domain-apps/:id/{mount,serve}` (`domain_apps_routes.rs:498-529`) | **Read by the daemon; Governance writes only its own control records** | The one place Governance's records gate a *semantic-plane* object. An ApprovalRequest must be `approved` **and** target the app; a ReleaseControl must be `open` **and** target it. Governance never calls mount — it publishes the controls the mount rung reads |
| **Kill-switch enforcement over Domain App runtimes** | `DomainAppRuntime` | `POST …/kill-switches/:id/enforce` → `kill_enforce_runtime` (`domain_apps_routes.rs:992-1057`) | **Write (effectful), receipted** | enforcement drives the ordinary stop/unmount transitions and emits the ordinary receipt family under kill-specific action names — no private path, no thinner record |
| **Write side — semantic plane** | **none.** Governance admits no ontology write | — | — | its writes are its own control records and the enforcement transition above; approvals over ontology-governed objects remain read-only references |

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

`review_inbox` is the canonical `composition_pattern` for exactly this shape, and
the approvals surface is the closest thing the estate has to a first-party
descriptor candidate. It is still **exempt**, and the reason is narrower and more
interesting than the platform-object finding that blocked Work, Environments, and
Operations.

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Approvals inbox + record detail | `review_inbox` | **exempt — subject refs are opaque** | the shape is the pattern. But invariant 11 requires *owning* ontology and object-model refs, and an approval's subject is a heterogeneous typed ref that may name anything. A descriptor cannot declare ontology refs for a queue whose rows deliberately span owners — **the inbox's cross-owner nature is exactly what makes it unbindable** |
| Governance cockpit tabs (release controls, kill switches, improvement gates, cohorts) | `list_detail` | **exempt — no bindable primitive** | platform control objects (X-2 finding, 5th surface) |
| Governance overview | `dashboard` | **exempt — no bindable primitive** | same |
| Approve / reject / revoke actions | — | **exempt — authority-crossing** | a descriptor's `allowed_action_refs` can *declare* an action; it never carries the admission, the receipt obligation check, or the fail-closed rule (`index.mjs:87-91`) |

A finding worth separating from the platform-object one, because a future
`review_inbox` descriptor will hit it: **the pattern presumes a homogeneous
object set, and canon's own review inboxes are cross-owner by design**
(:4346-4369 — a policy-filtered cross-owner pointer). Filed to X-2 alongside the
platform-object row.

Zero expressible, zero rendered.

### (b) This surface as primitive exposer

**Not n/a — Governance owns a stage.** It is the first surface in this run to hold
one.

| Journey stage (`odk-extension-apps.md` §2) | What Governance contributes |
|---|---|
| **10 — mount and serve** | the ApprovalRequest and ReleaseControl that admit the mount rung, re-validated live at every serve transition, and the KillSwitch that enforces stop/unmount through the same receipt family |

Two boundaries this ledger must state so the stage is not over-read:

- Governance **admits**; it does not mount, serve, or launch. The mount rung reads
  its controls; it never delegates the transition to Governance.
- Governance's admission is **not** package admission. Stages 6–7 (admit and
  version, install and register) are Packages' and remain
  `route-missing` — no `/v1/hypervisor/packages/*` family exists. A Domain App can
  therefore be *mounted* under Governance's controls while remaining unadmitted as
  a package and unregistered as an `extension_application`, which is exactly the
  half-built middle `odk-extension-apps.md` §1 records.
