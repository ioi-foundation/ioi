# Evaluations — implementation brief

Canonical route: `/evaluations` · Owner: Evaluations (owner application)
Brief status: authored 2026-08-05 from bytes at 21ae389fe · v0 seed corrected where noted
Amended 2026-08-06: seed-mesh + ODK wiring packet 12 — seed mesh ledger (§6), ontology
wiring (§7), ODK descriptor and extension lane (§8) appended. Program docs:
`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`,
`internal-docs/implementation/odk-extension-apps.md`.

## 1. Canon digest

- Evaluations is the **independent judgment surface**: it defines what evidence is
  admissible for a declared decision, freezes that contract per epoch, accounts
  for what adaptive search learned from protected tests, and keeps dependent
  claims honest when an evaluator fails (evaluations.md:21-32). It does not
  build the capability under test, execute effects, select campaign targets, or
  authorize release (evaluations.md:31-32, :93-114).
- Owns: suite definitions + **immutable released revisions**; portfolio lanes
  (visible/sealed/transfer/adversarial/cross-play/external-reality/production/
  reproduction); `EvaluationEpoch` lifecycle; holdout/evaluator custody posture;
  `EvaluationExposureLedger`; evaluator dependency/validity graphs;
  `VerifierChallenge` intake→disposition; re-verification plans; scorecards that
  preserve uncertainty; feedback intake with evidence-eligibility posture
  (evaluations.md:50-87). Summary registration in the suite tree:
  core-clients-surfaces.md:1341-1346; route ledger row `/evaluations`
  core-clients-surfaces.md:898; tool-surface row "Evaluation Suites (legacy AIP
  Evals) → Evaluations / Suites" core-clients-surfaces.md:1419.
- Epoch discipline: an epoch must never float on a mutable `latest` suite/judge/
  dataset; lifecycle state appends around a frozen root; changed judgment ⇒
  successor epoch (evaluations.md:203-212). Exposure/contamination must be
  derived from an admitted append-only ledger head, never an unreceipted mutable
  counter (evaluations.md:255-260, :419-420).
- Every `VerifierPath`/acceptance profile declares a `verification_cost_class`
  from the closed set negligible/sublinear/comparable/superlinear/
  unverifiable_at_price; downward reclassification is a judgment-contract
  mutation ⇒ successor epoch (evaluations.md:126-171).
- Recommended 12-section IA: Overview · Suites/Revisions · Epochs ·
  Runs/Scorecards · Sealed Holdouts · Exposure/Contamination ·
  Evaluators/Dependencies · Challenges · Re-verification · Feedback/Evidence
  Eligibility · Quality/Drift · Claims And Release Impact
  (evaluations.md:350-363).
- May never: nominate a campaign winner, issue an UpgradeDecision, activate/
  roll back/recall production state (evaluations.md:433-434); treat a receipt as
  evaluator correctness or a benchmark average as production fitness
  (evaluations.md:449-451); treat feedback capture as learning permission — the
  `InstitutionalLearningBoundaryProfile` and most-restrictive-boundary rule
  govern eligibility (evaluations.md:378-394; core-clients-surfaces.md:1084-1097).
- Effectful-tooling gate (the fix target for the inherited defect): "No
  Hypervisor application surface may expose effectful operator tooling without
  RuntimeToolContract or MCP contract refs, wallet authority posture, Agentgres
  refs, and receipt obligations" (core-clients-surfaces.md:4610-4612).
- Foundry boundary: Foundry builds/executes eval assets and admitted jobs;
  Evaluations owns admissibility, exposure accounting, challenges, and never the
  release decision (evaluations.md:325-339; core-clients-surfaces.md:2461-2475).

## 2. Schema map

| Canon object / contract | Canon block | Registry entry | Daemon route(s) today | Status |
|---|---|---|---|---|
| Eval-suite declaration (transitional draft object `ioi.hypervisor.eval-suite.v1`) | evaluations.md:55-58, :188-190 | none | `/v1/hypervisor/eval-suites` GET/POST, `/:id` GET/PATCH/DELETE, `/overview` (hypervisor-daemon.rs:1920-1933; handlers eval_suite_routes.rs:143-398) | exists — draft-only, receiptless (defect, §3/§4) |
| **Released suite revision** (immutable) | evaluations.md:55-58, :203-206 | none | `route-missing` — bytes pin `status: "draft"` always (eval_suite_routes.rs:268-269) | **W3** (release/revision lifecycle) |
| `EvaluationEpoch` (draft/freeze/activate/challenge/close/invalidate/successor) | evaluations.md:63-68, :191-212 | none | `route-missing` (no epoch route in the 663; grep clean) | **W3** |
| Sealed-holdout custody contract | evaluations.md:239-253 | none | `route-missing` | **W3** |
| `EvaluationExposureLedger` (append-only, chained entries) | evaluations.md:72-74, :255-266, :419-420 | none | `route-missing` | **W3** |
| `VerifierChallenge` | evaluations.md:78-79, :268-301 | `verifier-challenge.v3` + envelope v1 (architecture-contract-registry.v1.json:819-871; schemas dir) | `/v1/goal-orchestration/verifier-challenges` GET/POST, `/overview`, `/:id`, `/:id/transition` (hypervisor-daemon.rs:2574-2588); hosted, receipted, lease-governed plane (verifier_challenge_routes.rs:1-5, :27-32, :69-70; governed completer hypervisor-daemon.rs:3578-3585) | exists — **rehome as projection**, not a rebuild |
| Re-verification plan / affected-result discovery | evaluations.md:80-82, :288-299 | none | `route-missing` (challenge statuses include `reverifying`, verifier_challenge_routes.rs:50-60, but no epoch/claim impact walk) | **W3** (rides the epoch family) |
| Evaluation run / Finding / scorecard | evaluations.md:197-201, :83-85 | none (Finding/Attempt v3 exist for goal-orchestration: registry:191, :981) | `route-missing` for eval execution — "no run/scoring/judge here" is the plane's own doctrine (eval_suite_routes.rs:13-18; hypervisor-daemon.rs:1915-1918) | **W3** (admitted-job read views only; execution is daemon/Foundry) |
| Evaluator dependency/validity graph | evaluations.md:75-77, :270-281 | none | `route-missing` | **W3** |
| `verification_cost_class` declaration | evaluations.md:126-144 | none | `route-missing` (declared on VerifierPath/acceptance profiles) | **W3** (field on suite-revision/epoch families) |
| Feedback entry + evidence-eligibility consent | evaluations.md:87, :378-394 | none | `/v1/hypervisor/feedback/overview`, `/v1/hypervisor/feedback-entries` GET/POST, `/:id` GET/PATCH/DELETE (hypervisor-daemon.rs:1901-1914) | exists — consent ladder shared with eval-suites (eval_suite_routes.rs:53-59) |
| Eval-suite mutation **receipt family** | required by core-clients-surfaces.md:4610-4612 | none | absent — create/patch/delete persist with no receipt (eval_suite_routes.rs:274, :388, :396-397); feedback plane likewise mints none (feedback_routes.rs — zero receipt records, 286 lines) | **W3** (small daemon addition; blocks W2 actions) |

## 3. UI seed map

Traversable today (bytes; census 2026-07-30 used as seed, labeled):

- **T2 owner surface `/__ioi/evaluations`** (GET serve-product-ui.mjs:8569-8589;
  renderEvaluations :1299-1372). Panes: stat banner (suites/declared/empty/
  subjects, :1317-1319) — **wired-read**; "Declare an eval suite" form posting
  to the daemon (:1323-1331 → POST handler :8590-8605) — **wired mutation,
  receiptless** (the defect); suite library table with per-row Delete
  (:1335-1347 → :8606-8611, which also swallows daemon errors via
  `.catch(() => {})` at :8608) — **wired mutation, receiptless**; assessment
  subjects pane over `/v1/hypervisor/operations` + goal-runs (:1349-1360,
  fetches :8571-8577) — **wired-read**; consent-ladder + feedback + Foundry
  `model_eval` drafts pane (:1362-1367) — **wired-read**; named-gaps note
  (:1369) — honest absence.
- **T2 sublane `/__ioi/feedback`** (renderFeedbackQueue :1252-1287): feedback
  CRUD + consent-gated conversion PATCH (:8555-8564) — **wired mutation,
  receiptless at the daemon**.
- **T3 registered surface `evalsuites`**, registry title "AIP Evals", owner
  Evaluations, route `/__ioi/evaluations/evalsuites`
  (surface-registry.mjs:63; GET handler :8415-8420; renderEvalsuitesPort
  :4045-4131). Pixel-faithful AIP Evals shell; Recents rows are real suites —
  **wired-read**; Creator/Last-edited/Last-viewed columns render gap dashes (no
  principal/view metadata on the plane, :4076-4078) — **dead (named gap)**;
  "New evaluation suite" + "Help" header buttons disabled as named gaps
  (:4105-4106) — **dead**; suite-library truth section (:4089-4097) —
  **wired-read**. Census: 32 controls, 24 implemented, 3 daemon_read, 1
  disabled_missing_authority (census: control_census).
- **Vendor capture `/__apps/evalsuites`** (proxy fold of `/workspace/evals/`,
  :7430) — renders no data, documented insufficient (#44 sweep note, :4048,
  :4096). Keep as dormant seed only.
- **v2 SPA shell**: no `/evaluations` route exists in `apps/hypervisor/src`
  (grep clean); census agrees (census: `{"route": "/evaluations", "resolves":
  false}`).
- Seed-preservation: `evalsuites` is a protected route classed `daemon_wired`
  (ported-seed-preservation.v1.json:30) — rehome, never rebuild.

### Corrections vs v0

- v0 said: "epochs/holdouts/challenges absent." Bytes show **challenges are not
  absent**: a hosted, receipted, lease-governed VerifierChallenge plane exists
  at `/v1/goal-orchestration/verifier-challenges` (hypervisor-daemon.rs:
  2574-2588; verifier_challenge_routes.rs:1-5, :27-32) with a registered v3
  schema contract (architecture-contract-registry.v1.json:819-871). Epochs,
  sealed-holdout custody, and the exposure ledger remain route-missing.
  Challenges become a rehome/projection, not a W3 from-scratch build — only the
  epoch-linked affected-result discovery is new.
- v0/census said: "the surface simply leaves the create button disabled"
  (census: evalsuites primary_workflow). Bytes show the **create authority is
  exercised today**: the owner surface `/__ioi/evaluations` posts create and
  delete straight to the daemon (serve-product-ui.mjs:8590-8611). Only the AIP
  Evals landing's "New evaluation suite" button is disabled (:4105). The
  receiptless-mutation defect is therefore **live**, not latent.
- v0 said: "eval-suites CRUD exists" — confirmed, but with a canon-relevant
  narrowing v0 omits: the object is a **permanently draft, mutable declaration**
  (`status: "draft"` unconditionally, eval_suite_routes.rs:268-269; PATCH edits
  in place :291-390), so canon's immutable released revisions and "no mutable
  `latest` supplies promotion evidence" rule (evaluations.md:203-212, :415-416)
  have no substrate yet — a distinct W3 row from the epoch family.
- Census counted 3 `governed_receipted_action` controls on evalsuites (census:
  control_census); bytes show all eval-suite mutations emit no receipt
  (eval_suite_routes.rs:274, :388, :396-397) — the census's own
  `missing_authority_contracts[0]` names the receipt-family gap; the counter is
  the stale side.

## 4. Schema→UI binding table

Reads use the W0.3 read-projection client; authority-crossing actions use the
CapabilityLease client (403 wallet challenge → 428 credential → receipted).
Suite `subject_scope` may name `session` subjects (eval_suite_routes.rs:38);
any session-serving detail row binds through the session's
`subject_attachments[]`, never a named app field (core-clients-surfaces.md:
2683-2687, :3971-3990).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
|---|---|---|---|
| Overview stat banner | eval-suites `/overview` + list (daemon:1920-1927) | wired-read on T2 (:1317-1319) | `wired-read` at `/evaluations` Overview |
| Suites/Revisions table + detail | eval-suite records (list/get) | wired-read (:1335-1347, :4068-4079) | `wired-read`; revision/release strip `disabled-named-gap` until W3 revision family |
| Declare-suite form | POST `/v1/hypervisor/eval-suites` (daemon:1924-1927) | wired, receiptless (:8590-8605) | `wired-action-receipted` — blocked on receipt family (W3 row); until then keep enabled only with visible "no receipt" defect banner, or gate behind the fix PR |
| Suite edit (PATCH) | `/:id` PATCH (daemon:1929-1932) | no UI control (daemon-only) | `wired-action-receipted` after receipt family |
| Suite delete | `/:id` DELETE | wired, receiptless, error-swallowing (:8606-8611) | `wired-action-receipted`; surface daemon refusals |
| AIP Evals "New evaluation suite" | same create route | disabled named gap (:4105) | `wired-action-receipted` (same lease flow as declare) |
| Recents Creator/Last-edited/Last-viewed | principal/view metadata | dead gap-dashes (:4076-4078) | `disabled-named-gap` (principal attribution = W3 backlog row, census: missing_authority_contracts[1]) |
| Epochs pane | `EvaluationEpoch` family | absent | `disabled-named-gap` until W3 epoch family, then `wired-read` + freeze/close via lease client |
| Sealed Holdouts + Exposure/Contamination panes | custody + `EvaluationExposureLedger` | absent | `disabled-named-gap` until W3; ledger head is read-only projection, never a counter (evaluations.md:419-420) |
| Challenges list/detail | verifier-challenges GET/`/overview`/`/:id` (daemon:2574-2586) | not rendered by any Evaluations surface | `wired-read` projection (W1) |
| Challenge intake + transition | POST + `/:id/transition` (daemon:2574-2588; already governed, verifier_challenge_routes.rs:69-70) | no UI | `wired-action-receipted` via lease client (W2) |
| Re-verification view | challenge `reverifying` status + epoch impact | absent | `disabled-named-gap` until epoch family; interim: status filter on challenge projection |
| Runs/Scorecards pane | eval execution family | absent by doctrine (eval_suite_routes.rs:13-18) | `disabled-named-gap` (W3 family; render admitted-job truth only, never scores computed UI-side) |
| Feedback/Evidence Eligibility pane | feedback overview/entries (daemon:1901-1914) | wired on T2 feedback lane (:1252-1287) | `wired-read` + conversion as `wired-action-receipted` once feedback mutations mint receipts (same W3 receipt row) |
| Consent-ladder chips | overview `consent_ladder` (eval_suite_routes.rs:151-159) | wired-read (:1364-1366) | `wired-read` |
| Assessment-subjects pane | operations runs + goal-run blockers (daemon:1314, :1821) | wired-read (:1349-1360) | `wired-read`; session-subject rows bind via `subject_attachments` |
| Foundry `model_eval` drafts chips | `/v1/hypervisor/foundry/specs` (daemon:1325) | wired-read (:1367) | `wired-read` link-out to `/foundry` (Foundry boundary, evaluations.md:330-339) |
| Quality/Drift, Claims And Release Impact panes | scorecard/claim families | absent | `disabled-named-gap` (W3; claims depend on epoch family) |
| `/__apps/evalsuites` proxy lane | vendor capture | dead (renders no data, :4048) | `delete` at cutover (W4) |

New event consumption (suite/epoch/challenge updates) rides `/v1/event-streams`
+ `/v1/subscriptions` (daemon:2350-2379); per-resource SSE is legacy, wrapped
not extended.

## 5. Ordered PR list

1. **W1** — `/evaluations` read-first shell: Overview + Suites/Revisions over
   eval-suites overview/list/get; 12-section IA rendered with honest
   `disabled-named-gap` panes for the absent families; rehome the T2 subjects/
   consent panes. No mutations exposed.
2. **W1** — Challenges pane: read projection over
   `/v1/goal-orchestration/verifier-challenges` (+overview, detail, status
   filters incl. `reverifying`).
3. **W1** — Feedback/Evidence Eligibility pane: read views over feedback
   overview/entries with consent posture rendered per entry.
4. **W3 (small daemon, serial on router)** — eval-suite + feedback mutation
   receipt family: create/patch/delete/convert mint durable receipts and fail
   closed without one; closes the inherited receiptless-mutation defect against
   core-clients-surfaces.md:4610-4612.
5. **W2** — suite mutations via the CapabilityLease client: declare/edit/delete
   receipted end-to-end; enable AIP Evals "New evaluation suite"; delete stops
   swallowing errors; every completed action displays its receipt ref.
6. **W2** — challenge intake/transition actions through the lease client (the
   daemon side is already governed).
7. **W3** — released suite-revision lifecycle (immutability + revision roots +
   `verification_cost_class` declaration field), backend first, then the
   Revisions strip.
8. **W3** — `EvaluationEpoch` family (draft/freeze/activate/challenge/close/
   invalidate/successor; frozen roots per evaluations.md:63-68), then the
   Epochs pane and challenge→affected-epoch discovery.
9. **W3** — sealed-holdout custody + `EvaluationExposureLedger` (append-only,
   chained, derived head), then Sealed Holdouts + Exposure/Contamination panes.
10. **W3** — evaluator dependency/validity graph + re-verification projections;
    Quality/Drift and Claims panes over scorecard/claim reads as those families
    land.
11. **W4** — cutover per the 6-step rule: `/__ioi/evaluations`,
    `/__ioi/feedback`, `/__ioi/evaluations/evalsuites` retire with typed 410s
    (pattern: hypervisor-daemon.rs:610-612); delete the `/__apps/evalsuites`
    proxy fold; release the seed-preservation rows
    (ported-seed-preservation.v1.json:30).

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 4: none** — no vault names Evaluations as owner.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T3 `evalsuites` — Eval-suite library** — route `/__ioi/evaluations/evalsuites`; protected seed, class `daemon_wired`, pixel-certified | **32 controls**: 3 `daemon_read` · 7 `local_view_interaction` · **3 `governed_receipted_action`** · 1 `disabled_missing_authority` · 9 `unsupported_reference_session` · 9 `reference_data_only` | Evaluations owns the judgment contract, exposure, validity, and re-verification posture (`foundry.md:235-241`) | see cluster rows | — |
| ↳ **suite creation cluster — governed** | 3 `governed_receipted_action`: **New evaluation suite (PRIMARY)**, create-suite modal container, **Create (submit)** | receipted suite authoring | **rehome with a named defect** — §2 records the estate's **live receiptless creates/deletes** on the eval-suite family. These three are counted `governed_receipted_action` by the census, but the mutation-receipt family is a W3 build; until it lands the controls must present as draft CRUD, not as governed actions. The census bucket and the byte state disagree, and the byte state wins | W2 · W3 |
| ↳ suite catalog reads | 3 `daemon_read` (Ontology rail entry, AIP Evals active-app slot, Recents rows) | suite library over real subjects | **rehome** | W1 |
| ↳ local view cluster | 7 `local_view_interaction` (Home/Foundry logo, Recent, Files, collapse sidebar, Recents pill, Files column sort, Cancel modal) | local | **rehome** | W1 |
| ↳ **evaluation-target selector** | 1 `unsupported_reference_session`: "Select evaluation target (Logic / Function radios + Select-Logic dropdown)" | a suite declares **what** it would assess and **under what admissibility**; the target vocabulary must be the estate's subjects, not the reference's Logic/Function taxonomy | **retire-at-cutover** — the reference's target taxonomy is foreign. The functional selector binds real subjects (models, workers, ontology-aware packs), which is a different control, not a rewiring of this one | W4 |
| ↳ per-user favorites + attribution | 1 `disabled_missing_authority` (creator / last-edited-by / last-viewed columns) + 3 `unsupported_reference_session` (favorites view pill, per-row add-to-favorites, app add-to-favorites) | no principal or edit-tracking plane exists on these records | **retire-at-cutover** — the same honest em-dash ruling the T4 workspaces vault made for sessions (`developer-workspace.md` §6) applies: absent attribution renders as absent, and the columns go | W4 |
| ↳ **reference marketing cluster** | 9 `reference_data_only` (What's New, Applications, View-all-applications, Support, app tile glyph, Help, hero band, **Explore reference examples band**, **Marketplace example cards — Cipher ×2**) | fixture data must not render as truth; Cipher is a **vendor faculty** (standing P2 gate) | **retire-at-cutover** | W4 |
| ↳ vendor shell chrome | 5 `unsupported_reference_session` (search palette, notifications, **AIP Assist**, Account, batch/installations badge) | carve-out | **retire-at-cutover** | W4 |
| **T2 `/__ioi/evaluations`** — GET (serve `:8605`), POST (`:8626`) | T2 census `nat-evaluations`: **44 controls, 0 disabled** | the eval-suite library over daemon truth; the surface states plainly that **"nothing scores or executes here"** and that converting an entry into an eval/training candidate is a **named handoff the daemon gates on consent** (serve `:1281`, `:1316`) | **rehome** — those two statements are the surface's honest core and must survive | W1 |
| **T2 `/__ioi/feedback`** — feedback & annotations lane | T2 census `nat-feedback`: **8 controls, 0 disabled** | durable operator feedback over real subjects, each carrying its evidence-eligibility consent **from the moment it is recorded** (serve `:1281`) | **rehome** — consent-at-capture is the property that makes this lane usable as evidence later; it must not be relaxed into a post-hoc flag | W1 |
| **T5 `/__apps/evalsuites`** — capture, owner Evaluations, `reference_capture`, capture state `boots_editor_canvas`, grammar `table_list`, high_value, `reboundLane: null` (`harvest-seed-inventory.mjs:51`); §3 records it as having **no data** | not in the 563 | the registered surface above is functional | **pattern-harvest** — table grammar only | — |
| **T5 `/__apps/analysis`** — capture, `reference_capture`, capture state `shell_only`, grammar `editor_canvas`, high_value, `reboundLane: null`, "object-set-first analysis canvas" (`:52`) | not in the 563; §3 names it a gap | **object-set analysis binds `MaterializedObjectSet`** (§7) | **pattern-harvest** — and the most interesting of Evaluations' captures: an object-set-first analysis canvas is a real `graph`/`dashboard` shape over primitives that already exist. Harvesting the grammar costs nothing; building it needs the analysis plane, which has no route | — |
| **T5 `/__apps/quiver`** — capture, `reference_capture`, capture state `shell_only`, grammar `editor_canvas`, high_value, `reboundLane: null`, "time-series analysis canvas" (`:53`) | not in the 563 | the datasets/time-series/media-sets plane needs the **Data-vs-Foundry-vs-Evaluations owner ruling** (`data.md` §6) | **blocked-missing-route** — blocked on a ruling before a route, same as `/__apps/dataset` | W3 |

**Census reconciliation.** Evaluations' one T3 surface carries **32 of the 563**
baseline controls: 3 + 3 + 7 + 1 + 4 + 9 + 5 = 32, exact. Its two T2 readouts add
52 controls, 0 disabled (44 + 8), outside the baseline.

The `governed_receipted_action` count deserves the caveat above rather than a clean
number: **the census says 3, and §2 says the family's creates and deletes are
receiptless today.** Recorded as a disagreement, resolved in favour of the bytes.

**Disposition summary.** 4 rehome (one with a named defect) · 2 pattern-harvest ·
4 retire-at-cutover · **1 blocked-missing-route** · 0 blocked-missing-capture.

## 7. Ontology wiring

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Suite subjects | **none — not object-bound** today | eval-suites CRUD (`hypervisor-daemon.rs:1919-1930`) | Read + Write | subjects are models, workers, and runs — platform objects |
| **Ontology-aware eval packs** | `EvaluationDataset` bound to ontology refs; **ODK-generatable** via `OntologyDevelopmentKitManifestEnvelope.evaluation_dataset_refs` | **route-missing** for the dataset family | — | canon requires an `EvaluationDataset` to bind ontology refs, rubric refs, benchmark refs, source commitments, and policy (non-negotiable 7). None of that can be recorded today |
| **Object-set analysis** | `MaterializedObjectSet` | `/v1/hypervisor/odk/materialized-object-sets` **exists**; no Evaluations pane reads it | — | the `/__apps/analysis` capture's grammar over a primitive that is already live — a build with no route on the analysis side, not a missing primitive |
| Feedback entries as evidence | `PolicyBoundDataView` + `LearningEvidenceEligibility` | PBV read exists; the eligibility object is **route-missing** | — | consent is captured at record time on this surface, and the eligibility decision belongs to the learning-boundary plane |
| **Write side — semantic plane** | **none** | — | — | Evaluations writes suites and verdicts, never ontology facts. A verdict about an ontology-bound subject is an evaluation result, not a `ProvenanceAssertion` |

The boundary this surface must keep: **a passing evaluation is not an admitted
assertion.** Canon keeps operational truth and semantic belief distinct; an eval
verdict is evidence that may *support* an assertion, and the assertion still needs
its own admission.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Suite library table | `list_detail` | **exempt — no bindable primitive** | suites are platform objects |
| Suite create modal | `wizard` | **exempt — no write semantics in the descriptor** | seventh instance |
| Object-set analysis canvas (the `/__apps/analysis` shape) | `graph` / `dashboard` | **expressible once built** — like `automations.md` §8's wizard, the exemption here is **temporary and dated** | the primitive (`MaterializedObjectSet`) is live; the pane does not exist. When it is built, it should be built descriptor-shaped |
| Feedback lane | `review_inbox` | **exempt — cross-owner** | feedback entries point at subjects across owners; the same cross-owner blocker `governance.md` §8 filed |

Zero expressible today. The analysis row is the **second dated exemption** in the
run — worth the X-4 rollup, because two panes now have a defined moment at which
they become expressible.

### (b) This surface as primitive exposer

**n/a for the journey stages.** Evaluations owns none of the ten.

Its contribution is the same non-stage shape `foundry.md` §9 recorded: an ODK
manifest names `evaluation_dataset_refs` and `benchmark_profile_refs`, and those
artifacts are **Evaluations'** to validate even when Foundry produces them. A
user-tailored application shipping with an eval pack draws the pack through Packages
admission; **Evaluations owns whether its verdicts mean anything**, which is a
judgment contract, not a journey stage.

One boundary: **shipping an eval pack with a generated app grants no evaluation
authority.** The pack declares what would be assessed; running it against real
subjects still needs the subjects' own consent and eligibility.
