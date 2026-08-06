# Improvement — implementation brief

Canonical route: `/improvement` · Owner: Improvement (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 13 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Improvement is the **safe-change cockpit**: it helps an accountable owner
  decide what should improve, coordinate bounded work, compare immutable
  candidates, and hand a supported change to the target owner's ordinary
  governance path. It does not execute work, decide evaluation truth, possess
  target authority, or activate a candidate (improvement.md:21-28). Suite-level
  summary: core-clients-surfaces.md:2477-2492, :1348-1354; route ledger row
  `/improvement` core-clients-surfaces.md:899; tool-surface row "Change Inbox
  (legacy Upgrade Assistant) → Improvement / Changes"
  core-clients-surfaces.md:1418.
- Two proportionate paths, both canonical: **ordinary direct change** (evidence
  → `UpgradeProposal` → `UpgradeDecision` → target-owner activation) and
  **adaptive/multi-epoch improvement** (released `ImprovementAgenda` revision →
  admitted `ImprovementCampaign` → GoalRuns → frozen `EvaluationEpoch`s →
  attributable nomination → `UpgradeProposal`) (improvement.md:38-57). A
  campaign is optional; the product must not force one around a one-shot patch
  (improvement.md:59-64, :361-362).
- Owns: immutable-by-revision agenda portfolios; campaign admission drafts and
  workspaces; target/order graphs (seven non-collapsible coordinates,
  improvement.md:194-208); candidate ancestry incl. rejected/inconclusive/
  exploit attempts and negative knowledge; nomination bound to one frozen
  epoch; `ImprovementOrderCutoffReceipt` synchronization; `UpgradeProposal`
  construction; qualified `ImprovementEvidenceClaim`s; background-work
  visibility (improvement.md:95-126).
- Does not own: GoalRun/Session execution, candidate assets, evaluation truth,
  wallet authority, Governance admission/activation/rollback/recall, Agentgres
  truth, package release truth, or "a universal optimizer, recursive harness,
  new runtime, new authority plane, or generic self-rewriting object"
  (improvement.md:132-153).
- Search/Judgment/Authority are separated rings: Search proposes, Judgment
  freezes/applies contracts, Authority admits and activates; no coalition may
  control the evaluator, meter, promotion authority, and recovery path that
  canonicalize it (improvement.md:257-279).
- Recommended IA: Overview · Agendas · Campaigns · Targets/Order Graph ·
  Candidate Map · Plateaus/Negative Knowledge · Evaluation Posture (projection
  from Evaluations) · Cutoffs/Synchronization Waves · Changes/Proposal Handoff ·
  Release And Effect Recovery (projection from Governance) ·
  Claims/Reproductions · History/Receipts (projection from Provenance)
  (improvement.md:288-303).
- **"Do not ship a universal Self-improve button."** Advanced views may expose
  epochs, exposure, ancestry, order, and qualified claims "without presenting
  them as ambient power" (improvement.md:317-319). Product copy must never
  collapse the claim ladder into unqualified `RSI`/`self-improving` language
  (improvement.md:349-353).
- Implementation status per canon: a "narrow transitional improvement-proposal
  and simulation/rollout slice" that must not be described as a general
  recursive-improvement substrate (improvement.md:14-17).
- Effectful-tooling gate applies to every cockpit verb
  (core-clients-surfaces.md:4610-4612).

## 2. Schema map

| Canon object / contract | Canon block | Registry entry | Daemon route(s) today | Status |
|---|---|---|---|---|
| `ImprovementAgenda` (immutable revisions) | improvement.md:98-100, :408 | none | `route-missing` (grep clean for agenda/campaign) | **W3** |
| `ImprovementCampaign` (frozen contract, owner, ceilings, coordinating GoalRun) | improvement.md:101, :155-183, :357-360 | none | `route-missing` | **W3** |
| `UpgradeProposal` handoff (freezes campaign/epoch/candidate/diff/recovery) | improvement.md:120-122 | none | `route-missing` | **W3** |
| `ImprovementOrderCutoffReceipt` | improvement.md:117-119, :245 | none | `route-missing` | **W3** (campaign family) |
| `ImprovementEvidenceClaim` | improvement.md:123-125 | none | `route-missing` | **W3** |
| ImprovementProposal (transitional slice, `ioi.hypervisor.improvement-proposal.v1`) | improvement.md:14-17 sanctions the slice | none | `/v1/hypervisor/intelligence/improvement-proposals` GET/POST (daemon:1699), `/:id` GET/PATCH (:1704), `/:id/approve` (:1717), `/:id/reject` (:1721), `/:id/apply` (:1725) | exists — approve/reject are **receiptless** state changes (ioi_intelligence_routes.rs:2531-2565, :2568-2601); apply mints `receipt://hypervisor/improvement/{id}` (:3170-3208) |
| What-if simulation + report | improvement cockpit "what-if simulations" core-clients-surfaces.md:1352 | none | `/:id/simulate` (daemon:1709), `/simulation-reports/:id` (:1713); deterministic replay, `save:true` persists a receipted report (ioi_intelligence_routes.rs:3210-3217) | exists |
| Apply gate (fresh simulation + approved ApprovalRequest + open ReleaseControl) | Governance gates and decides, core-clients-surfaces.md:1353-1354 | none | enforced inside apply via live-loaded gate inputs + proposal fingerprint (ioi_intelligence_routes.rs:2603-2625, :2940-2948) | exists — enforced |
| `ImprovementGate` governance records | Governance owns admission (improvement.md:83-85) | none | `/v1/hypervisor/governance/improvement-gates` GET/POST, `/:id` GET/PATCH/DELETE (daemon:2011-2019) | exists — **records only, bounds not enforced** (governance_routes.rs:321) |
| Candidate ancestry substrate (Attempt/Finding/WorkResult/OutcomeDelta) | improvement.md:106-111, :169-173, :211-216 | attempt.v3, finding fixtures (registry:191, :981) | attempts (daemon:2540-2553), findings (:2557-2570), work-results (:2328-2337), outcome-deltas (:2341-2346, per-goal-run :1834) | exists — read-first Candidate Map needs **no new backend** |
| Outcome mining / review queue / intelligence graph | cockpit inputs; "background-work visibility" improvement.md:126 | none | `/v1/hypervisor/intelligence/outcome-mining` (:1695), `/review-queue` (:1729), `/graph` (:1733) | exists |
| Release/effect-recovery projection | improvement.md:300, :329 | none | governance release-controls/approval-requests/kill-switches (daemon:2010 region; used by UI :9209, :9214) | exists — projection from Governance, never owned here |
| Receipts on approve/reject transitions | core-clients-surfaces.md:4610-4612 | none | absent (only apply is receipted) | **W3** (small daemon addition; blocks W2 rehome of those verbs) |

## 3. UI seed map

- **T3 registered surface `changes`**, registry title "Upgrade Assistant",
  owner Improvement, route `/__ioi/improvement/changes`
  (surface-registry.mjs:62; GET handler serve-product-ui.mjs:8423-8431;
  renderChangesPort :4215-4310). Pixel-faithful Upgrade Assistant inbox whose
  DATA region is real improvement-proposal truth: one row per proposal with
  kind pill, state + gate posture, and approval/release/simulation refs as the
  proof trail (:4222-4228, :4282). Lanes Active/Past-due/Archived are live
  `?lane=` links; Past-due is **honestly empty** — no due-date concept on the
  plane (:4271-4275); UPGRADE-PROGRESS filter radios wired to `?filter=`
  (:4227 comment block). **Read-only by design**: "no apply, no approve/reject,
  no deploy, no release-gate mutation" (:4226-4228). Dead/named-gap chrome:
  organization scoping, Admin/Assignee view toggles, search, sort
  (:4291-4298). Census: 47 controls, 39 implemented, 12 daemon_read, 1
  governed_receipted_action, 0 disabled_missing_authority (census:
  control_census).
- **The action lane lives in the wrong owner today**: Agent Studio's
  `#improvement-proposals` panel (renderImprovementProposals :2677-2727)
  carries Propose-from-mining (:2683), Simulate impact (:2689), Approve/Reject
  (:2694), Apply (:2692), and the high-impact governance lanes
  request-approval/open-release/attach (:2702-2710). POST handlers: propose
  :9156-9178, simulate :9105-9110 (sends `save:true`), approve/reject/apply
  :9251-9260, governance lanes :9198-9231 — all plain daemon fetches, fail
  closed on refusal. Governance PATCH hardcodes
  `reviewer_ref: "principal://operator"` (:9238) — free text, not a principal.
- **Home tile** "Improvement" links into Agent Studio, not an Improvement route
  (:1464).
- **v2 SPA shell**: no `/improvement` route in `apps/hypervisor/src` (grep
  clean); census agrees (census: `{"route": "/improvement", "resolves":
  false}`).
- Seed-preservation: `changes` is a protected route classed `daemon_wired`
  (ported-seed-preservation.v1.json:37) — rehome, never rebuild.

### Corrections vs v0

- v0 said: backend = "improvement-proposals + approve/reject/apply/simulate,
  improvement-gates, intelligence graph/review-queue/outcome-mining exist."
  Bytes confirm, but v0 flattens **two distinct gate planes**: the
  governance `improvement-gates` family is records-only — "bounds are
  captured, not enforced" (governance_routes.rs:321) — while the *enforced*
  gate is the intelligence apply path (fresh simulation fingerprint + approved
  ApprovalRequest + open ReleaseControl, live-loaded at apply,
  ioi_intelligence_routes.rs:2603-2625, :2940-2948). The cockpit must render
  the enforced gate and not present the records plane as enforcement.
- v0 said: "agenda/campaign objects are backend gaps (file family); wire
  proposals inbox + what-if simulation views now." Confirmed for agendas/
  campaigns (no routes, grep clean), but v0 omits that the **candidate-map/
  negative-knowledge substrate already exists**: attempts, findings,
  work-results, and outcome-deltas are live daemon planes
  (hypervisor-daemon.rs:2540-2570, :2328-2346), so the Candidate Map and
  Plateaus/Negative Knowledge IA sections are W1 read views, not W3 builds.
- v0 implied the proposal verbs are ready to rehome as-is. Bytes: **approve and
  reject are receiptless** state mutations (ioi_intelligence_routes.rs:
  2531-2565, :2568-2601) — only apply mints a receipt (:3170-3208) and only
  simulate persists a receipted report (:3210-3217). Rehoming approve/reject
  under the effectful-tooling gate (core-clients-surfaces.md:4610-4612) needs
  the small receipt addition first. Related census-vs-bytes note: the census
  claim "every route + receipt already exists" (census:
  missing_authority_contracts[0] for changes) is correct for routes, stale for
  approve/reject receipts.

## 4. Schema→UI binding table

Reads use the W0.3 read-projection client; authority-crossing verbs use the
CapabilityLease client (403 wallet challenge → 428 credential → receipted).
Coordinating/child GoalRun and Session rows are projections; any
session-serving row binds through `subject_attachments[]`
(core-clients-surfaces.md:2683-2687, :3971-3990) — the improvement plane's own
refs (`proposal_ref`, `target_ref`, evidence refs) stay on proposal records.

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Changes/Proposal-handoff inbox (rows, lanes, gate posture, proof-trail refs) | improvement-proposals list w/ `gate` projection (daemon:1699; gate merge ioi_intelligence_routes.rs:2464-2474) | wired-read at `/__ioi/improvement/changes` (:8423-8431) | `wired-read` at `/improvement` |
| Lane tabs + progress filter | query params, local | wired local view (:4301-4306) | local UI state (stays client-local) |
| Past-due lane | due-date concept | honestly empty named gap (:4271-4275) | `disabled-named-gap` (no canon requirement; do not invent the field) |
| Org / Admin / Assignee toggles, search, sort | principal-assignment + org planes | dead named-gap chrome (:4291-4298) | `disabled-named-gap` (principal plane is a separate program) |
| Propose from mined candidate | POST improvement-proposals (daemon:1699; evidence_refs required, ioi_intelligence_routes.rs:2493-2500) | wired via Agent Studio (:9156-9178), unreceipted create | `wired-action-receipted` at `/improvement` via lease client |
| Simulate impact | POST `/:id/simulate` `save:true` (daemon:1709) | wired via Agent Studio (:9105-9110); receipted report | `wired-action-receipted` (rehome) |
| Simulation report drilldown | `/simulation-reports/:id` (daemon:1713) | not rendered | `wired-read` |
| Approve / Reject | POST `/:id/approve`, `/:id/reject` (daemon:1717, :1721) | wired via Agent Studio (:9251-9260); **receiptless transitions** | `wired-action-receipted` after the W3 receipt row lands; until then `disabled-named-gap` on `/improvement` (defect named visibly) |
| Apply | POST `/:id/apply` (daemon:1725; gate-enforced :2940-2948; receipt :3170-3208; protected seeds cloned never mutated :2996-3000, :3091-3113; canary/cohort variant + rollout provenance :3002-3075) | wired via Agent Studio | `wired-action-receipted` (rehome; render the gate decision and receipt ref) |
| High-impact gate lanes (request approval / open release / attach refs) | POST governance approval-requests + release-controls + proposal PATCH (:9209, :9214, :9225) | wired via Agent Studio (:9198-9231) | `wired-action-receipted`; `reviewer_ref` becomes a real principal (today hardcoded `principal://operator`, :9238) |
| Candidate Map + Plateaus/Negative Knowledge | attempts/findings/work-results/outcome-deltas (daemon:2540-2570, :2328-2346, :1834) | not rendered by any Improvement surface | `wired-read` (immutable DAG projection; archive never erased per improvement.md:365-366) |
| Review queue pane | `/review-queue` (daemon:1729) | rendered inside Agent Studio panel data | `wired-read` (rehome) |
| Outcome-mining pane | `/outcome-mining` (daemon:1695) | wired via Agent Studio (:2683) | `wired-read` + propose action per above |
| Intelligence graph (proposal↔evidence↔receipt edges) | `/graph` (daemon:1733) | not rendered on an Improvement route | `wired-read` (shared plane; Improvement shows its slice) |
| Agendas pane | `ImprovementAgenda` family | absent | `disabled-named-gap` until W3, then `wired-read` + authoring via lease client |
| Campaigns pane (posture, ceilings, coordinating GoalRun, cutoffs) | `ImprovementCampaign` + `ImprovementOrderCutoffReceipt` | absent | `disabled-named-gap` until W3 |
| Targets/Order graph | campaign order-assignment receipts (improvement.md:206-209) | absent | `disabled-named-gap` until W3 |
| Evaluation Posture pane | projection from Evaluations (improvement.md:297; epoch family missing — see evaluations brief §2) | absent | `wired-read` over verifier-challenges projection now; epoch posture `disabled-named-gap` until the Evaluations W3 epoch family |
| Release And Effect Recovery pane | governance release-controls/kill-switches reads | absent here (routes exist) | `wired-read` projection + deep link to `/governance`; never mutation from this pane |
| Claims/Reproductions pane | `ImprovementEvidenceClaim` | absent | `disabled-named-gap` until W3 |
| History/Receipts pane | receipts read surfaces (Provenance) | absent here | `wired-read` projection (proposal receipt refs already on records, :3193-3199) |
| "Self-improve" affordance | improvement.md:317-319 | absent | never — `delete` on sight; no PR may add an ambient-power verb |

New event consumption (proposal/gate state changes) rides `/v1/event-streams` +
`/v1/subscriptions` (daemon:2350-2379); legacy per-resource SSE wrapped, not
extended.

## 5. Ordered PR list

1. **W1** — `/improvement` read-first shell: Overview + Changes/Proposal-handoff
   inbox rehoming the `renderChangesPort` truth (rows, lanes, gate posture,
   proof-trail refs); IA panes for absent families rendered as named gaps; Home
   tile retargeted from Agent Studio to `/improvement`.
2. **W1** — Candidate Map + Plateaus/Negative Knowledge read views over
   attempts/findings/work-results/outcome-deltas (immutable DAG projection,
   archive preserved).
3. **W1** — Review-queue, outcome-mining, graph-slice, and simulation-report
   read views on `/improvement`; Release And Effect Recovery + History/Receipts
   projection panes (governance + receipts reads, deep links out).
4. **W3 (small daemon, serial on router)** — receipts on approve/reject
   transitions (and proposal create), matching the apply receipt pattern
   (ioi_intelligence_routes.rs:3170-3208); closes the effectful-tooling-gate
   gap for those verbs.
5. **W2** — action rehome via the CapabilityLease client: propose, simulate,
   approve, reject, apply, and the high-impact governance lanes move from
   `/__ioi/agent-studio` to `/improvement`; `reviewer_ref` becomes a principal;
   every completed verb shows its receipt ref; Agent Studio panel reduced to a
   link.
6. **W3** — `ImprovementAgenda` family (immutable revisions), backend first,
   then the Agendas pane.
7. **W3** — `ImprovementCampaign` family (frozen contract, inherited ceilings,
   coordinating-GoalRun ref, order-assignment receipt) +
   `ImprovementOrderCutoffReceipt` + `UpgradeProposal` handoff object; then
   Campaigns, Targets/Order Graph, and Cutoffs panes. Nomination must bind one
   frozen `EvaluationEpoch` — sequence after the Evaluations epoch family.
8. **W3** — `ImprovementEvidenceClaim` authoring + Claims/Reproductions pane
   (qualified-claim language rules, improvement.md:338-353).
9. **W4** — cutover per the 6-step rule: `/__ioi/improvement/changes` and the
   Agent Studio improvement panels retire with typed 410s (pattern:
   hypervisor-daemon.rs:610-612); release the seed-preservation row
   (ported-seed-preservation.v1.json:37).

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none** — no vault names Improvement as owner.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `changes` — Upgrade Assistant** — route `/__ioi/improvement/changes` (serve `:8455`); protected seed, class `daemon_wired`; **REBOUND** — the inventory records `reboundLane: "daemon improvement-proposals"` (`harvest-seed-inventory.mjs:88`) | **47 controls**: 12 `daemon_read` · 6 `local_view_interaction` · **1 `governed_receipted_action`** · 0 `disabled_missing_authority` · 16 `unsupported_reference_session` · 12 `reference_data_only` | Improvement owns proposals, what-if simulation, and apply-under-gates — a change inbox over daemon truth | see cluster rows | — |
| ↳ **the governed action** | 1 `governed_receipted_action`: the pending-action control (`"1 of 1 pending"` / confirm · override · opt-out) — the reference surface's PRIMARY action | apply-under-gates; **Governance owns activation decisions** | **rehome with a named defect** — §2 records approve/reject as **receiptless today**. A confirm/override/opt-out that changes a proposal's fate without a receipt is an unreceipted effectful mutation; the control rehomes, and until the receipt family lands (W3) it must not present as governed | W2 · W3 |
| ↳ proposal lane + progress reads | 5 `daemon_read` (Active / Past due / Archived tabs, "All upgrades", "Upgrades requiring my action") | change inbox over real proposals | **rehome** | W1 |
| ↳ row + detail reads | 3 `daemon_read` (resource row, row select → Resource Context panel, **state pill + proof trail**) | every proposal deep-links its proof | **rehome** — the state-pill-plus-proof-trail pairing is the honest core: a state claim that carries its evidence | W1 |
| ↳ rail reads | 4 `daemon_read` (Home, Ontology, Applications, active-app slot) | carve-out adjacency | **rehome** the estate links · the vendor rail itself retires | W1 · W4 |
| ↳ local filter cluster | 6 `local_view_interaction` (collapse rail, collapse filters, search by name, upgrade-type checkboxes, pre-published + published group headers) | local | **rehome** | W1 |
| ↳ **org / admin / assignee cluster** | 7 controls: 5 `unsupported_reference_session` (org popover, admin-view toggle, assignee-view toggle, help menu, contact maintenance operators) + 2 `reference_data_only` (assignment info banner, banner help) | **no assignment plane exists** — proposals have no assignee, and "contact maintenance operators" names a vendor support relationship the estate does not have | **retire-at-cutover** — all seven. An assignee view over records with no assignee would be an empty pane pretending to be a filter | W4 |
| ↳ sort / attribution chrome | 4 controls: 1 `unsupported_reference_session` (SORT radios by due date / remaining actions) + 1 (`DUE DATE` sort icon) + 3 `reference_data_only` column headers (NAME, TYPE, MY ACTIONS / PENDING ACTIONS) | proposals carry no due date and no per-principal action count | **retire-at-cutover** — sorting by a field the records do not carry is the same class of defect as `work.md`'s facets over absent fields | W4 |
| ↳ due-date + context-menu | 2 `unsupported_reference_session` (due-date cell "45 days remaining", row right-click menu) | same | **retire-at-cutover** | W4 |
| ↳ **What's-new modal cluster** | 4 `reference_data_only` (modal, **subscribe-to-newsletter toggle**, "go to all platform updates", close) | fixture data must not render as truth | **retire-at-cutover** — a newsletter subscription toggle inside a governed change inbox is the clearest single case in the run of reference chrome that must not survive | W4 |
| ↳ vendor session chrome | 7 `unsupported_reference_session` (search palette, notifications, Recent, Files, **AIP Assist**, Support, Account) + 3 `reference_data_only` (What's New, app tile chip, title) | carve-out; AIP Assist is a vendor faculty (standing P2 gate) | **retire-at-cutover** | W4 |
| **T2 Agent Studio propose lane** — `POST /__ioi/agent-studio/improvements/propose` (serve `:9192`) + the embedded approve / request-approval forms (`:2704-2705`) | part of Agent Studio's 1,050 (`studio.md` §6.1) | proposals are Improvement's; approvals are Governance's | **rehome → Improvement** for propose · the embedded approval form **retires** and is reached through Governance | W1 · W4 |
| **T5 `/__apps/changes`** — capture, owner Improvement, `reference_capture`, capture state `boots_editor_canvas`, grammar `table_list`, high_value, **`reboundLane: "daemon improvement-proposals"`** (`harvest-seed-inventory.mjs:88`) | not in the 563 | the registered surface above already answers with daemon truth | **rebind** — one of only three captures in the estate with a declared rebound lane (`designer`, `listings`, `changes`); this one's lane is already live | W1 |

**Census reconciliation.** Improvement's one T3 surface carries **47 of the 563**
baseline controls: 15 + 7 + 9 + 4 + 7 + 1 + 4 = 47, exact.

**Zero `disabled_missing_authority` controls** — the only T3 surface in the run with
none. That is not completeness: this surface's gaps show up as
`unsupported_reference_session` (16) and `reference_data_only` (12) instead, i.e. **28
of its 47 controls are reference chrome for a product the estate is not building.**
Its single governed control is the one that matters, and it is receiptless.

**Disposition summary.** 5 rehome (one with a named defect) · 1 **rebind** ·
0 pattern-harvest · 6 retire-at-cutover · 0 blocked.

## 7. Ontology wiring

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Proposal inbox rows | **none — not object-bound** | improvement-proposal routes (`hypervisor-daemon.rs:1716-1726`) | Read | proposals are platform objects |
| Proposal subjects | **none directly** — a proposal's subject *may* be an ontology-governed object | subject refs on the proposal record | Read (deep link) | the same object-aware-not-object-bound shape as `governance.md` §7 |
| Resource Context panel + proof trail | receipts | work-ledger deep links | Read | evidence, not assertions |
| **Write side — semantic plane** | **none** | — | — | Improvement writes proposals and (once receipted) decisions. A proposal to change an ontology is a **proposal**; the ontology write belongs to Ontology's receipted authoring path (`ontology.md` §7) |

The boundary worth stating because Improvement is where it would be violated most
naturally: **an approved proposal is not an applied change.** Canon separates the
proposal, the gate, and the apply; a surface that renders "approved" as "done" would
collapse three admissions into one.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Change inbox (lanes, rows, filters) | `review_inbox` | **exempt — cross-owner** | proposals span every owner's objects; the same cross-owner blocker `governance.md` §8 filed. Second instance, and it confirms the finding is about the *pattern*, not about Governance |
| Resource Context panel | `object_view` | **exempt — no bindable primitive** | proposals are platform objects |
| Upgrade-progress rollups | `dashboard` | **exempt — no bindable primitive** | same |
| Confirm / override / opt-out | — | **exempt — authority-crossing** | a descriptor declares actions; it carries no gate |

Zero expressible, zero rendered.

### (b) This surface as primitive exposer

**n/a.** Improvement owns no stage of the composable-application journey
(`odk-extension-apps.md` §2), exposes no ODK primitive, and holds no descriptor.

One adjacency recorded because the extension lane will need it: when a generated
application's package release is superseded, the **upgrade** of installed bindings is
a proposal-shaped change. That path runs Packages (release) → Improvement (proposal)
→ Governance (gate) → compiler (exposure), and **the generated app has no say in
it** — an installed extension is upgraded *to* it, not *by* it.
