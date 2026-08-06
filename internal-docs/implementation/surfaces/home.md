# Home — implementation brief

Canonical route: `/home` · Owner: core workspace Home
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 16 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

Canon cites are `docs/architecture/components/hypervisor/core-clients-surfaces.md` unless
prefixed (`api.md:` = `docs/architecture/components/daemon-runtime/api.md`), and resolve against
the blob at commit `21ae389fe` (branch `overhaul/bring-to-life-charter`); daemon and
`apps/hypervisor/` bytes are identical between `21ae389fe` and master `1ff32a1a3`. Daemon cites are
`crates/node/src/bin/hypervisor-daemon.rs`. UI cites are under `apps/hypervisor/`. Census cites
(`census:`) are the 2026-07-30 inventory and are seed only; bytes win.

## 1. Canon digest

- Home is the default command and resume surface (core-clients-surfaces.md:1545-1547) on
  canonical route `/home` (:884; workspace row with `canonical_route: "/home"` served in the
  core-taxonomy contract, api.md:1014).
- Home may accept goal prompts, show recent typed Work subjects, surface waiting approvals, and
  route the user into a System, Project, Automation, Application, GoalRun, OutcomeRoom, Session,
  receipt, or replay. Home may draft work but must NOT become the durable owner of systems,
  goals, automations, projects, or sessions (:1565-1569). Avoid: durable automation owner,
  ioi.ai chat replacement, default deploy-as-service funnel (:1584-1590); Home ≠ dense
  terminal/diff/file console — dense panes belong in Project / Developer Workspace / Session /
  Open Application contexts (:1571-1574; anti-pattern :4725).
- Correct behaviors: Home starts or resumes governed work; Home can ask Core to create a New
  Session; Home can draft an Automation or Foundry job for review (:1576-1582).
- Home registers as a core workspace, never an application (:4545-4546);
  `HypervisorCoreWorkspaceRegistration` is projection-only + writes-through-owners (:3468-3478);
  no second "Home" entry in the Applications launcher (:1562-1563).
- Canon's own implementation-status paragraph records today's Home: an owned EXPLORER over the
  shell at `/ai` (rail Home destination), built from shell design tokens
  (`renderExplorer`/`applyAiViews` in `apps/hypervisor/scripts/augmentation/`, "owns no truth"):
  welcome hero with live summary; get-started actions (New Session / Applications / Automations);
  first-class governed-work rows (approvals waiting, runs parked at a wallet gate incl.
  `awaiting_authority_*` failover runs, failed runs — each opening the OWNING surface, collapsing
  to one all-clear line, naming a daemon outage rather than papering over it); Recent tabs
  (sessions/projects/runs) with honest empty states; the Applications estate grid; expanding
  into the owned full readout `/__ioi/home` (:1549-1563).
- The composer is deliberately NOT the home page — it is New Session (:1562-1563). New Session
  is a one-click action whose canonical route is `/work/new-session` (:885, "remains a one-click
  action"); it may create only a bounded Session, never an implicit Goal/Automation/System
  (:1478-1482; conformance :4549-4551; anti-pattern :4765). The composer carries two explicit
  semantic acts: ordinary submission = New Session; a separately labelled **Activate Goal**
  affordance may draft/review/submit a `GoalRunActivationEnvelope` with
  `source_kind: ioi_goal_draft` — typing, submission, correlation, or attachment is never the
  activation act (:1530-1543).
- **Fallback-fixture rule (the canon cite):** "Client fallback fixtures may keep the UI usable
  while the daemon is offline, but the fixture source must be visible and must not be presented
  as admitted runtime truth" — api.md:167-169, stated inside the Home-cockpit projection
  contract. The projection contract itself: `GET /v1/hypervisor/home-cockpit` returns
  `ioi.hypervisor.home_cockpit_projection.v1` with `boundary_invariant: "Home renders daemon
  evidence projections; it does not become runtime truth."` and metrics whose `detail_route`
  targets canonical routes (example `/work/sessions/…`) (api.md:132-164). A sibling
  `GET /v1/hypervisor/session-operations` projection is specified at api.md:171-181.
- Home's client class: read models only; "these endpoints are read models for clients; they do
  not move runtime truth into the client" (api.md:127-129).

## 2. Schema map

| Canon object / contract | Registry / canon block | Daemon route(s) today | Gap wave |
|---|---|---|---|
| HypervisorCoreWorkspaceRegistration (home row) | canon :3468-3478; taxonomy row api.md:1014 | `GET /v1/hypervisor/core-taxonomy` hypervisor-daemon.rs:1056 | — |
| `ioi.hypervisor.home_cockpit_projection.v1` | api.md:132-169 (no JSON Schema in `_meta/schemas/`) | route-missing — zero `home-cockpit`/`home_cockpit` hits in `crates/` | **W3** (W0.6-class small route; serial on the router file) |
| `hypervisor_session_operations` projection | api.md:171-181 | route-missing — zero `session-operations` hits | **W3** |
| Product-surface projection (Applications grid) | `hypervisor-product-surface-projection.v1.schema.json`; canon :1964-2009 | `/v1/hypervisor/product-surface-projections` :1060; surface-descriptors :1634 | — (compiler wiring = W0.2) |
| Governed-work row sources | — | approval-requests :1963; failover runs :2630; operations :1314 | — |
| Recents sources | — | sessions :3190; projects :1128; work-ledger :1309; automations/:id/runs :1284 | — |
| Identity for the hero/summary | — | `/v1/hypervisor/auth/whoami` :3352 | — |
| New Session create | canon :1478-1521 | `POST /v1/hypervisor/sessions` :3190 | — |
| Activate Goal affordance | canon :1530-1543; `goal-run-activation.v1.schema.json` (+ receipt schema) | goal-run-activations :1809; `:id` :1813; `:id/submit` :1817 | — |
| Home event freshness | M5 plane | `/v1/event-streams/...` :2350-2360 + `/v1/subscriptions/...` :2363-2379 | — (W0.4 client) |
| Retired-route refusal (`/__ioi/*` at daemon) | `ioi.hypervisor.route_retirement_refusal.v1` | `/__ioi/*path` typed 410 at the daemon :612 (the UI serve process still serves `/__ioi/home` itself) | — |

## 3. UI seed map

- **`/home`: absent everywhere.** census: `/home` `resolves: false`; grep finds no `/home`
  handler in `scripts/serve-product-ui.mjs`, the augmentation modules, or `src/`. The Home graft
  has NOT moved to `/home` — it still lives at `/` + `/ai`.
- **Owned explorer Home (wired, read-first):** `augmentation/40-home-explorer.js` — identity
  comment "THE Home (rail Home, /ai with no hash) is an owned EXPLORER … The explorer owns no
  truth: every affordance routes to the owning surface, missing projections are named, nothing
  is fabricated" (:1-8). Composes SEVEN daemon reads client-side: approval-requests,
  failover/runs, operations, work-ledger, sessions, projects, whoami (:14-21, 15s cache :11).
  Governed-work rows: pending approvals → Governance, `awaiting_authority_*` failover runs →
  Operations, failed runs → Operations (:45-60). Honest degradation: "Projection unavailable —
  the daemon did not answer" (:94) and "Daemon unreachable — governed-work status unavailable.
  Nothing is shown rather than fixtures." (:119) — the fallback-fixture rule already implemented.
  Goal-prompt submit POSTs `/v1/hypervisor/sessions` (:328). "Sessions →" deep link still targets
  `/__ioi/sessions` (:303 — retirement site, see work.md). census: 87 controls, 1 disabled.
- **Full readout `/__ioi/home` (wired):** `renderHome` (serve-product-ui.mjs:1050; route
  :8675-8683) reads operations, work-ledger, sessions, approval-requests, failover-runs;
  "Fetches fail to null (NOT {}) so the renderer can distinguish daemon-down" (:8669-8671
  comment). census: 27 controls, 0 disabled. Standing verifier:
  `scripts/verify-hypervisor-home-surface.mjs`.
- **New Session composer:** the SPA's polished composer page at `/ai#new-session`; the rail's
  create-session button and Ctrl+O are intercepted and routed there
  (60-shell-wiring.js:18-22, `goComposer()`); the Advanced-launch affordance opens the owned
  governed launcher modal — registry-fed harness/model options DISABLED WITH THEIR REASON, launch
  preview naming admission/receipts/isolation/restore before the effectful call
  (50-new-session.js:1-24). census: composer 29 controls.
- **Home automations redirect (inherited BY Automations, carried in Home's shell):**
  `80-automations.js:4-18` — a capture-phase click handler hijacks every `a[href="/automations"]`
  and rewrites navigation to `/__ioi/automations` ("beat the SPA router" :16). `/automations` is
  one of only TWO canonical routes that resolve today (census: `/projects`, `/automations`).
- **Applications estate grid:** hand-maintained 15-tile list `IOI_APPS`
  (30-shell.js:5-20) still using the retired taxonomy — "Missions" → `/__ioi/sessions` (:11),
  "Marketplace" (:15), "Workbench" (:16) — one of the three hand-maintained catalogs the W0.2
  compiler kills.
- **Fixture lane:** `product-ui/server.cjs` mock branches exist estate-wide (deleted at W4 per
  the master ladder); the explorer/readout Home paths above do not read them.

### Corrections vs v0

- v0 treats the Home fallback-fixture rule as a standing generalization without a cite — bytes
  locate the canon rule at **api.md:167-169** (inside the home-cockpit projection contract), and
  it is already implemented verbatim in the live explorer (40-home-explorer.js:119 "Nothing is
  shown rather than fixtures."). It is NOT in core-clients-surfaces.md (grep: no Home-rule
  "fixture" hit there).
- The documented Home read surface is unimplemented: `GET /v1/hypervisor/home-cockpit`
  (api.md:132) and `GET /v1/hypervisor/session-operations` (api.md:172) have ZERO route hits in
  `crates/` — the live Home instead composes 7 per-family reads client-side
  (40-home-explorer.js:14-21). v0's W0 list does not name this route-missing pair; they feed the
  Wave 3 build list.
- The explorer-Home graft has not moved: it is still `/` + `/ai` via augmentation
  (40-home-explorer.js:1-8), `/home` resolves nowhere (census + grep), and canon's own Home
  implementation-status paragraph still names `/ai` (:1549-1550) while the route ledger demands
  `/home` (:884) — the brief's job is a rehome at W0.1, plus a one-line canon status refresh at
  cutover.
- v0 says Automations "inherits … the Home automations redirect" — bytes sharpen this: the
  redirect (80-automations.js:4-18) actively hijacks the CANONICAL `/automations` route (one of
  the only two resolving v2 routes, census) into `/__ioi/automations`. At the v2 cutover this
  augmentation must be deleted or it will fight the v2 shell's own router; recorded here because
  the code rides Home's shell augmentation stack.

## 4. Schema→UI binding table

Reads use the W0.3 read-projection client; the only effectful controls on Home are launches
routed to owners (New Session create; Activate Goal submit), which cross through the
CapabilityLease client (403 wallet challenge → 428 credential → receipted). Recent-session rows
are session-serving display: their subject chips bind through `subject_attachments` once the W3
C-1 row lands (see work.md) — never a named app field.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| `/home` route + workspace chrome | core-taxonomy workspace row :1056 / api.md:1014 | absent (`/ai` only) | wired-read (W0.1 rehome) |
| Welcome hero + live summary | whoami :3352 + composed counts | wired at `/ai` (40-home-explorer.js) | wired-read (keep; swap onto read client) |
| Home-cockpit metrics strip | `home_cockpit_projection.v1` api.md:143-164 | route-missing | disabled-named-gap → wired-read after W3 route |
| Get-started: New Session | :885, :1478-1482; composer + modal | wired to `/ai#new-session` (60-shell-wiring.js:18-22) | wired-read link → `/work/new-session` |
| Get-started: Applications | product-surface-projections :1060 | modal over hand list (30-shell.js:5-20) | wired-read (compiler projection, W0.2) |
| Get-started: Automations | `/automations` canonical | redirect hijack (80-automations.js:4-18) | wired-read link to canonical route; delete the hijack at Automations cutover |
| Governed row: approvals waiting | approval-requests :1963 | wired (:45-53), deep-link `/__ioi/governance` | wired-read; deep-link → `/governance` at cutover |
| Governed row: runs parked at wallet gate | failover runs :2630 (`awaiting_authority_*`) | wired (:48, :54-57) | wired-read; deep-link → `/operations` |
| Governed row: failed runs | operations :1314 | wired (:49, :58-60) | wired-read |
| All-clear line / daemon-outage line | fallback-fixture rule api.md:167-169 | wired (:94, :119) | wired-read (KEEP behavior; it is the canon rule) |
| Recent tabs: sessions / projects / runs | sessions :3190; projects :1128; work-ledger :1309 | wired with honest empties; "Sessions →" → `/__ioi/sessions` (:303) | wired-read; deep-links → `/work/sessions`, `/projects`, `/work/history` |
| Goal prompt (ordinary submit) | POST sessions :3190 (bounded Session only :1478-1482) | wired (:328) | wired-action-receipted (lease client; provision receipt exists) |
| Activate Goal affordance | :1530-1543; goal-run-activations :1809-1817 | absent (explorer has no activation act) | wired-action-receipted (W2; must show normalized intent, profile revision/hash, principal, authority posture, review requirement, source binding BEFORE submit :1536-1540) |
| Applications estate grid | product-surface projection :1060; canon :1964-2009 | hand list w/ retired names, "Missions" tile → `/__ioi/sessions` (30-shell.js:11) | delete hand list; wired-read from compiler (W0.2); retired-name tiles die with it |
| `/__ioi/home` strips (decisions/blocked/resume/newest-proof) | renderHome :1050, :8675-8683 | wired | wired-read rehomed into `/home` body; readout retired at W4 |
| Live freshness (row updates) | event plane :2350-2379 | absent (15s poll cache, 40-home-explorer.js:11) | wired-read via W0.4 event client |
| Session-operations pane | api.md:171-181 | route-missing | disabled-named-gap → W3 |

## 5. Ordered PR list

1. **W0.1** — v2 shell serves `/home` rendering the owned explorer body (rehome from `/ai`;
   `/ai` keeps serving until cutover per the seed-preservation invariant). Honest
   empty/degraded states carry over unchanged.
2. **W0.2** — Applications grid + get-started tiles read the product-surface compiler projection
   (`/v1/hypervisor/product-surface-projections` :1060); delete the `IOI_APPS` hand list
   (30-shell.js:5-20) — this also removes the "Missions" tile advertising `/__ioi/sessions`.
3. **W1** — Governed-work rows + Recent tabs onto the W0.3 read client with canonical deep-links
   (`/governance`, `/operations`, `/work/sessions`, `/projects`, `/work/history`); the
   `/__ioi/*` deep-links die per-app as each owner cuts over.
4. **W1** — Rehome the `/__ioi/home` readout strips (decisions / blocked / resume / newest-proof,
   renderHome :1050) into the `/home` body as a second read-first band; keep the readout
   serving until W4.
5. **W0.4 rider** — Home rows subscribe on `/v1/event-streams` + `/v1/subscriptions`
   (:2350-2379) replacing the 15s poll; per-resource SSE not extended.
6. **W2** — New Session one-click: `/home` action routes to `/work/new-session` (:885); launch
   crosses via the CapabilityLease client; Advanced-launch keeps the owned governed modal
   (50-new-session.js) as the single daemon-backed launch lane.
7. **W2** — Activate Goal affordance over goal-run-activations :1809-1817 with the full
   pre-submission disclosure contract (:1536-1540); receipted; never triggered by ordinary
   submission.
8. **W3** — Backend: `GET /v1/hypervisor/home-cockpit` per api.md:132-169 (+ optional
   `session-operations` api.md:171-181); then wire the metrics strip. Serial on
   hypervisor-daemon.rs (router hotspot). Register the projection schema in `_meta/schemas/`.
9. **W4** — Cutover: `/ai` alias retired with the typed refusal pattern; `/__ioi/home` retired
   after parity + no-fallback proof (6-step rule); delete the `/automations` click hijack
   (80-automations.js:4-18) in the same wave as the Automations cutover; refresh the canon Home
   implementation-status paragraph (:1549-1563) to name `/home`.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 3: none · Tier 4: none · Tier 5: none.** Home has **no registered surface, no
dormant vault, and no harvest capture** — the only surface in the run with an empty
seed footprint across all three tiers. It holds **0 of the 563 baseline controls**.
Its entire seed estate is the T1 shell plus four T2 lanes, and the mesh below is
correspondingly short. That is the honest state, not an incomplete sweep.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T1 Home (explorer)** — routes `/` and `/ai` | T1 shell census: **87 controls, 1 disabled**, HTTP 200 — the largest T1 shell surface | `/home` is the canonical estate cockpit; Home advertises New Session and the separate Activate Goal affordance (:1523-1543) | **rehome** — `/` and `/ai` become `/home`; the explorer body is the seed | W0.1 · W1 |
| **T1 New Session (composer)** — `/ai#new-session` | T1 shell census: **29 controls, 1 disabled** | New Session is a one-click action at **`/work/new-session`** (:885) and may create **only a bounded Session** (:1478-1482) | **rehome → Work** — the composer is Work's affordance advertised from Home. `work.md` §4 carries the mirror row; the two must not both claim it | W0.1 · W2 |
| **T2 home readout** — `/__ioi/home` (serve `:8708`) | T2 census `nat-home`: **27 controls, 0 disabled**. §3 records Home composing **7 per-family reads client-side** | `home-cockpit` + `session-operations` projections are documented in `daemon-runtime/api.md` and **absent from the daemon** (§5) | **rehome** — with the client-side composition preserved as-is until the two projections land; a 7-read fan-out is honest, a fabricated rollup would not be | W1 · W3 |
| **T2 new-session lanes** — context `GET /__ioi/api/new-session/context` (serve `:8964`), launch `POST …/launch` (`:9019`) | part of the T1 composer's 29 | bounded Session creation with a provision receipt | **rehome → Work** (with the composer) | W2 |
| **T2 goal-space** — `/__ioi/goal-space` (serve `:8724`) | not separately censused | Activate Goal is a **separate affordance** from New Session (:1523-1543) | **rehome** — and the separation is the point: one control creates a Session, the other activates a GoalRun, and collapsing them would make Home mint the wrong object | W1 |
| **T2 search** — `/__ioi/search` (serve `:8649`) | T2 census `nat-search`: **2 controls, 0 disabled** | search is a **compiler projection** (W0.2), policy-filtered **before** aggregation | **rehome** — search rows come from the compiler, never from a per-surface index | W1 |
| **Live `/automations` redirect** — the shell redirects the canonical v2 route into `/__ioi/automations` | T1 shell census for `/automations`: 70 controls, 0 disabled | `/automations` is Automations' canonical route | **retire-at-cutover** — recorded here because Home's shell owns the redirect; `automations.md` §6 records the same hijack from the receiving side, and the two rows are the same defect seen from both ends | W4 |

**Census reconciliation.** Home holds **0 of the 563** T3 baseline controls. Its T1
shell surfaces carry **116 controls, 2 disabled** (87 + 29) and its T2 lanes **29
controls, 0 disabled** (27 + 2), all outside the baseline.

**Disposition summary.** 5 rehome (two of them **to Work**) · 0 rebind ·
0 pattern-harvest · 1 retire-at-cutover · 0 blocked.

## 7. Ontology wiring

**None — not object-bound, and `n/a` is the honest answer the packet table
predicted.**

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Explorer cockpit, recents, launch tiles | **none** | 7 per-family reads | Read | Home launches; it owns no object |
| Search | **none** | compiler projection | Read | rows are registrations, not ontology objects |
| Goal-space / Activate Goal | **none** | goal-run activation | Read + launch | a GoalRun is a platform object |
| **Write side** | **none** | — | — | Home creates nothing itself: New Session is Work's affordance, Activate Goal is GoalRun's. Home advertises both |

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Explorer cockpit + recents | `dashboard` | **exempt — no bindable primitive** | platform objects (X-2 finding) |
| Search results | `list_detail` | **exempt — cross-owner** | search spans every owner by design; the same cross-owner blocker `governance.md` §8 filed, third instance |
| New Session composer | `wizard` | **exempt — authority-crossing, and not this surface's** | Work owns it |

Zero expressible, zero rendered.

### (b) This surface as primitive exposer

**n/a**, exactly as the packet table predicted, and confirmed at the bytes.

One adjacency worth a line because Home is where users will first meet the
extension lane: **an installed extension application appears in Home's launch
surfaces only through the compiler projection**, with the same policy filtering and
the same `launchable` / `disabled_reason_codes` honesty every first-party row gets
(`surface-compiler.mjs` header). Home never special-cases an extension app, and a
recalled release must stop appearing here immediately — which is the compiler recall
hook `packages.md` §8 rules must land with the registry.
