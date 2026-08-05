# Governance — implementation brief

Canonical route: `/governance` · Owner: Governance (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted

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
