# Improvement Governance Gates

Status: canonical architecture authority with an implemented initial contract (`ioi_intelligence_routes.rs` + `governance_routes.rs`)
Doctrine status: canonical
Implementation status: mixed (current improvement apply/simulation/approval/release gates and deterministic 409s built; OutcomeRoom finding/evaluator-challenge promotion and derived-artifact recall extensions planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs`
Last alignment pass: 2026-07-11.
Last implementation audit: 2026-07-05
Canonical owner: this file for the apply-time gate rule, freshness rule, reason codes, epistemic promotion ladder, evaluator-rule change/reverification gate, and no-automatic-promotion boundary.
Object authority remains `docs/architecture/foundations/common-objects-and-envelopes.md`
(improvement proposals, simulation reports) and the governance control objects
(`approval-request://`, `release-control://`).

## Doctrine

Evidence suggests, simulation previews, **governance decides**, and receipts
bind the policy/version/decision facts evaluated at the gate. A receipt does
not prove that a learned improvement is universally correct or valuable. A
learned improvement whose saved what-if simulation is high-impact cannot become
behavior without an APPROVED `ApprovalRequest` and an OPEN `ReleaseControl`
targeting the proposal or that simulation report—validated live at apply time,
never trusted from stale stamped refs.

The canonical improvement ladder is:

```text
cheap observation or participant input
  -> tainted branch-local hypothesis / Finding
  -> evaluated capability, policy, route, ontology, or verifier candidate
  -> shadow / simulation / adversarial and regression evidence
  -> governed canary or cohort promotion
  -> monitored production promotion with rollback and recall
```

OutcomeRoom messages, artifacts, attempts, findings, ontology mappings,
leaderboard movements, model judgments, and evaluator suggestions are evidence
inputs only. They never promote themselves into durable memory, an ontology,
route priors, authority policy, an evaluator rule, a worker/package, or
production behavior. Participant consensus is evidence, not governance.

Verifier/evaluator changes are versioned proposals. A successful
`VerifierChallenge` names the prior and replacement rule, adjudicator, affected
attempts, and required re-verification. History is not silently re-scored or
deleted; old verdicts remain bound to their original rule versions while new
verdicts state the replacement version.

## Gate rule (evaluated at apply; same evaluation feeds the UI posture)

1. `launch_policy_suggestion` proposals must carry a saved simulation → else
   `simulation_required`. Other kinds without a simulation keep existing behavior
   (`no_simulation` posture, apply allowed).
2. Any cited simulation must be FRESH: the report records a
   `proposal_fingerprint = sha256(proposal_kind, target_ref, suggested, evidence_refs)`;
   the live proposal must still fingerprint identically → else `simulation_stale`.
   Freshness is content identity — restoring the exact simulated payload restores freshness;
   no clock is consulted.
3. If the fresh report's `governance.high_impact` is true:
   - a bound `approval_request_ref` must resolve, target the proposal or the simulation
     report, and be `approved` → else `approval_required` / `approval_not_approved`;
   - a bound `release_control_ref` must resolve, target the proposal or the simulation
     report, and be `open` → else `release_control_required` / `release_control_not_open`.
4. Low-impact fresh simulations apply without controls.
5. A proposal derived from an external/room participant must bind source,
   affiliation, attempt/finding lineage, taint state, license/export policy,
   independent evaluation, and admission receipt before it can enter the
   existing apply path. Missing lineage or unresolved taint fails closed.
6. A verifier/evaluator-rule proposal must bind a `VerifierChallenge`, prior
   rule version, proposed rule version, adjudication decision, affected-attempt
   set, and re-verification plan. The new rule cannot overwrite prior verdicts
   or become active solely because it improves its own leaderboard score.
7. Promotion candidates must carry evaluator-integrity, correlated-verifier,
   adversarial-holdout, regression, rollback, and recall posture appropriate to
   risk. Authority widening is never an improvement side effect.

The implemented first four rules block with deterministic HTTP 409 reason
codes. Rules 5–7 are the target admission contract; their route/schema and
reason-code implementation remains planned and must not be described as built.

## Binding

`PATCH /v1/hypervisor/intelligence/improvement-proposals/:id` (pending/approved only)
binds `approval_request_ref` / `release_control_ref` — the control must exist at bind time
(`governance_ref_unresolved`) and target the proposal or its simulation report
(`governance_subject_mismatch`). Content patches (`suggested`, `evidence_refs`,
`target_ref`) do not reset anything; the fingerprint makes prior simulations stale
automatically. Governance controls targeting the PROPOSAL survive re-simulation; controls
targeting a specific REPORT bind to exactly that preview.

## Impact semantics

A simulation's `changed` counters isolate the PROPOSAL's counterfactual effect: replay
compares recompute-with-base vs recompute-with-overlay under today's probed posture
(ambient drift vs stored projections is reported as `recorded_counts` reference, never
counted as impact). `high_impact = changed >= 3 || blockers_introduced > 0 ||
privacy_loosened`; the report's `governance.satisfiable_target_refs` names exactly which
refs an ApprovalRequest / ReleaseControl may target.

## Receipts

Apply mints `receipt://hypervisor/improvement/*` citing `simulation_ref`, `report_hash`,
`approval_request_ref`, and `release_control_ref`; the Work Ledger `improvement_applied`
entry carries and backlinks the full chain.

## Canary release + rollback (learned-policy rollouts)

A canary/cohort `ReleaseControl` bounds WHO sees a high-impact learned policy before full
rollout. `rollout_mode: canary | cohort | full` with `canary_percent` (deterministic
sha256(context:release_id) → 0..99 bucketing), `cohort_refs`, `starts_at`/`ends_at`,
`rollback_state`, `promoted_at`/`rolled_back_at`.

- **Apply under canary/cohort** creates a rollout-bound VARIANT (clone of the target base +
  suggested patch + rollout provenance: base/release/proposal/simulation/approval refs).
  The base policy — often a protected seed — is NEVER replaced.
- **Selection** happens at launch plan time: an eligible context (matched via
  `project_ref` / `principal_ref` / `rollout_context_ref` on preview/launch) is silently
  upgraded to the variant, recorded and explained (`policy_rollout` note with reason codes
  `rollout_cohort_match:* | rollout_canary_bucket:* | rollout_full | rollout_promoted_full`)
  on the preview response and the launch record. Everyone else keeps base behavior.
- **The ReleaseControl stays the LIVE gate**: closing it switches every context back to
  base immediately; the time window is honored.
- **Promote** (`POST …/launch-policies/:id/rollout/promote`): the variant becomes normal
  behavior for every context using the base (still overlay-selected — the base record is
  never mutated); ReleaseControl flips to `rollout_mode: full` + `promoted_at`.
- **Rollback** (`POST …/rollout/rollback`): the overlay stops selecting the variant
  anywhere; the variant is retained (`rollout.state: rolled_back`, status disabled so
  explicit selection fails closed); ReleaseControl records `rollback_state`. No
  proposal/simulation/approval/release evidence is deleted.
- Both lanes mint `receipt://hypervisor/policy-rollout/*` receipts citing the full chain;
  the Work Ledger indexes them as `policy_rollout` entries with backlinks.

## Principal-derived rollout context + cohort objects

Rollout eligibility derives from DAEMON-KNOWN truth, never arbitrary caller text:

- Context priority: **authenticated principal** (real login session via the identity ring)
  → **daemon-known project** (a named project counts only when it resolves to a project
  record) → **explicit override** (`rollout_context_ref` — kept for test/dev, but labeled
  `override: true` and sourced `explicit_override`; it can never masquerade as
  authenticated identity) → **anonymous** (deterministic `principal://local-operator`
  posture, honestly noted when identity enforcement is inactive).
- Preview/launch expose `rollout_context_source` + `rollout_context` (refs with sources,
  seed, posture note); applied overlays name `matched_ref`, source, and the matched
  cohort; non-applied variants are explained via `policy_rollout_skipped` reason codes
  (`rollout_cohort_no_match | rollout_cohort_disabled | rollout_canary_bucket_miss:* |
  rollout_window_inactive | release_control_not_open`).
- **Cohorts** are durable governance objects (`cohort://coh_*`: display_name, scope
  personal|project|org, validated member refs principal://project://org://environment://
  ioi-agent-policy://, status active|disabled, evidence refs). ReleaseControl
  `cohort_refs` must resolve to cohort objects; raw member refs remain honored for
  backward compatibility but are recorded in `deprecated_raw_cohort_refs` with an explicit
  deprecation note. Disabled cohorts never match.
- Canary bucketing hashes the DERIVED stable seed (`sha256(derived_ref:release_id)`), so a
  principal's bucket is stable across calls and cannot be steered by request text.
- Rollout receipts and Work Ledger `policy_rollout` entries cite `cohort_refs` +
  `rollout_mode` alongside the proposal/simulation/approval/release chain.

## Deployment auth posture + high-trust rollout enforcement

The daemon declares which world it runs in — `deployment_auth_posture` on
`/v1/hypervisor/auth/policy`, the governance overview identity section, launch
preview/launch responses, Operations, and the New Session preview:

- **local_development** — loopback, enforcement inactive. Deterministic local-operator
  posture; explicit `rollout_context_ref` overrides remain usable and are LABELED.
- **exposed_untrusted** — reachable from outside (non-loopback bind or forwarded request)
  with enforcement explicitly off. Honest warning; high-trust rollout rules apply.
- **authenticated_managed** — auth enforcement active (mode `always`, or `auto` while
  exposed — the fail-safe default). Sensitive endpoints (launch preview/launch,
  improvement apply, cohorts, release controls, memory vault export/import) return 401
  unauthenticated; only login/bootstrap lanes are exempt.

Outside `local_development`, learned-rollout eligibility accepts ONLY high-trust derived
sources (authenticated principal, daemon-known project/org): explicit overrides fail
closed with `rollout_explicit_override_disallowed`, anonymous contexts fail closed with
`rollout_requires_authenticated_context` (cohort membership, canary bucketing, full and
promoted overlays alike). A rollout blocked by POSTURE (not mere non-membership) at launch
time is a receipted security decision — `receipt://hypervisor/rollout-enforcement/*`,
indexed in the Work Ledger as `rollout_enforcement` entries carrying the posture, the
context source, and the blocked variants with reasons.
