# Improvement Governance Gates

Status: canonical architecture authority with an implemented initial contract (`ioi_intelligence_routes.rs` + `governance_routes.rs`)
Doctrine status: canonical
Implementation status: mixed (the older direct proposal, simulation, approval, and release-control path is an implementation precursor. Deployment-aware waiver admission, exact target-base freshness, versioned impact assessment, repeated-proposal campaign decomposition pressure, application-chain receipts, full campaign/epoch/exposure, OutcomeRoom finding/evaluator-challenge promotion, and derived-artifact recall extensions remain target contracts.)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs`
Last alignment pass: 2026-07-16.
Last implementation audit: 2026-07-16 (scoped audit of `ioi_intelligence_routes.rs` direct-proposal gate)
Canonical owner: this file for direct-proposal and campaign apply-time gate rules, freshness and exact-base rules, deterministic reason codes, epistemic promotion ladder, evaluator-rule change/reverification gate, and no-automatic-promotion boundary.
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

Every improvement kind requires a saved simulation outside
`local_development`, unless an approved and transition-receipted
`ApprovalRequest` waives exactly the `saved_simulation` requirement for the
current proposal ref, proposal kind, and proposal fingerprint. Local
development retains a narrow unsimulated path for `skill_improvement` and
`automation_readiness`; `launch_policy_suggestion` has no ordinary local
bypass. The exact receipted waiver remains the only exception to either rule.

The direct proposal path and campaign path are both canonical. A bounded
one-shot change may use the existing proposal/simulation gate directly. The
target decomposition guard refuses a fourth or later non-rejected proposal
against the same normalized target family within 24 hours unless its
`improvement_campaign_ref` resolves to an `ImprovementCampaign` record. This is
an initial anti-decomposition boundary, not campaign conformance: adaptive
repeated search, sealed evaluation, multi-epoch work, or a recursive claim still
additionally binds the active `EvaluationEpoch`, evaluation-exposure posture,
and exact pursuit/component resolution. Those objects supply evidence and
lineage; they do not bypass this target-owner gate.

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

1. Outside `local_development`, every proposal kind must carry a saved
   simulation or an exact simulation waiver → else `simulation_required`.
   The waiver is an `approval-request://` record whose subject is the exact
   proposal, whose `request_kind` is `improvement_simulation_waiver`, whose
   `enforcement_preview` binds `requirement: saved_simulation`, the proposal
   kind, and the current proposal fingerprint, whose status is `approved`, and
   whose `receipt_refs` contains the receipt minted by the governed approval-
   transition path. Missing, stale, unreceipted, foreign-subject, wrong-kind,
   or wrong-fingerprint waivers fail with `simulation_waiver_invalid`. This is
   governed record linkage; portable cryptographic proof requires the portable
   ReceiptEnvelope and Agentgres admission contract.
2. In `local_development`, an unsimulated `skill_improvement` or
   `automation_readiness` proposal may use the explicit
   `local_development_no_simulation` posture. A `launch_policy_suggestion` still
   returns `simulation_required` unless it carries the exact waiver above.
3. Any cited simulation must be FRESH: the report records a
   `proposal_fingerprint = sha256(proposal_kind, target_ref, suggested, evidence_refs)`;
   the live proposal must still fingerprint identically → else `simulation_stale`.
   The report additionally binds the exact `target_base_ref` and the current
   target-base record hash; target replacement or mutation fails with
   `simulation_target_base_stale`. Freshness is content and base identity—no
   clock is consulted.
4. The saved report must contain a known `ioi.improvement-impact.v1`
   assessment. Missing or unknown classification fails with
   `improvement_impact_unknown` rather than defaulting to low impact.
5. If the fresh report's `governance.high_impact` is true:
   - a bound `approval_request_ref` must resolve, target the proposal or the simulation
     report, and be `approved` → else `approval_required` / `approval_not_approved`;
   - a bound `release_control_ref` must resolve, target the proposal or the simulation
     report, and be `open` → else `release_control_required` / `release_control_not_open`.
6. Low-impact fresh simulations apply without approval/release controls.
7. A proposal derived from an external/room participant must bind source,
   affiliation, attempt/finding lineage, taint state, license/export policy,
   independent evaluation, and admission receipt before it can enter the
   existing apply path. Missing lineage or unresolved taint fails closed.
8. A verifier/evaluator-rule proposal must bind a `VerifierChallenge`, prior
   rule version, proposed rule version, adjudication decision, affected-attempt
   set, and re-verification plan. The new rule cannot overwrite prior verdicts
   or become active solely because it improves its own leaderboard score.
9. Promotion candidates must carry evaluator-integrity, correlated-verifier,
   adversarial-holdout, regression, rollback, and recall posture appropriate to
   risk. Authority widening is never an improvement side effect.

The current master implements only the older direct-proposal precursor for a
subset of Rules 1–6. Deployment-aware waiver, target-base freshness, versioned
impact, application-chain receipt, repeated-proposal decomposition, and
campaign bindings are target admission contracts, as are Rules 7–9; their
route/schema and reason-code implementation remains planned and must not be
described as built.

## Campaign-grade gate extension (planned)

Campaign-grade promotion evaluates the same direct gate plus these bindings:

1. the campaign admission decision, immutable campaign-contract root,
   coordinating GoalRun, selected `GoalRunProfile` revision, and exact resolved
   component snapshot must agree;
2. the active `EvaluationEpoch` must be frozen, unexpired, unchallenged or
   explicitly adjudicated, and bound to the same target/incumbent roots;
3. the candidate must bind one exact predecessor target root, conflict set,
   immutable candidate root, Attempt ancestry, and confirmatory disposition;
4. campaign and ancestor resource, statistical-risk, and sealed-evaluation
   exposure reservations must be valid and unexhausted;
5. every upward Finding, OutcomeDelta, production observation, or synchronization
   signal must have `LearningEvidenceEligibility`; institutional-boundary
   crossings additionally require the applicable `LearningEgressReceipt`;
6. candidate, evaluator, and controller or agenda successors may not be selected
   and activated at the same cutoff; an evaluator successor begins in a fresh
   epoch and never rewrites old verdicts;
7. the `ImprovementOrderCutoffReceipt` must bind the frozen source roots,
   eligible and denied evidence classes, target-order edge, destination base
   root, and previous cutoff root without claiming later evaluation or release;
8. the promotion bundle must satisfy hard safety, privacy, authority, security,
   rights, maintainability, monitorability, trace-quality, migration, and
   target-specific effect-recovery gates;
9. recursive claim classes additionally require their declared fresh descendant
   portfolio, transfer, causal-ablation, equal-budget, and reproduction evidence;
10. approval activates only through the target owner's future scope. A profile
    successor applies to future daemon-admitted GoalRuns; an evaluator successor
    applies to a fresh epoch; other targets use their own release or migration
    cohort.

The planned deterministic failure family includes:

```text
campaign_binding_mismatch
evaluation_epoch_not_frozen
evaluation_epoch_invalid
target_base_stale
candidate_conflict_unresolved
resource_reservation_exhausted
statistical_risk_budget_exhausted
evaluation_exposure_exhausted
learning_evidence_ineligible
learning_egress_denied
same_cutoff_mutual_validation
improvement_order_cutoff_invalid
hard_constraint_regression
monitorability_regression
reproduction_required
recursive_claim_unsupported
effect_recovery_posture_missing
```

These reason codes are target contract only until implemented and tested. The
daemon must not synthesize campaign truth from a caller-supplied claim or from
copied receipt fields.

## Binding

`PATCH /v1/hypervisor/intelligence/improvement-proposals/:id` (pending/approved only)
binds `approval_request_ref` / `release_control_ref` — the control must exist at bind time
(`governance_ref_unresolved`) and target the proposal or its simulation report
(`governance_subject_mismatch`). Content patches (`suggested`, `evidence_refs`,
`target_ref`) do not reset anything; the fingerprint makes prior simulations stale
automatically. Governance controls targeting the PROPOSAL survive re-simulation; controls
targeting a specific REPORT bind to exactly that preview.

The same patch route may bind `simulation_waiver_ref`. Bind-time validation
requires a resolvable ApprovalRequest with the exact proposal subject,
`improvement_simulation_waiver` request kind, `saved_simulation` requirement,
proposal kind, and current proposal fingerprint. Apply-time validation then
requires that request to be approved and carry its approval-transition receipt;
changing any fingerprint-bearing proposal field invalidates the waiver.

## Impact semantics

A simulation's `changed` counters isolate the proposal's counterfactual effect:
replay compares recompute-with-base versus recompute-with-overlay under the
current probed posture. Ambient drift versus stored projections is reported as
`recorded_counts` reference and is not counted as proposal impact.

`ioi.improvement-impact.v1` reports `severity`, changed-scenario and introduced-
blocker counts, and explicit `authority`, `privacy`, `physical`, `financial`,
`security`, and `constitutional` dimensions. Any named dimension, three or more
changed scenarios, or an introduced blocker makes the current assessment high
impact. Non-object suggestions classify as `unknown` and block. The dimension
classifier is a deterministic conservative field/value-fragment detector, not
proof of external-world effect; future classifiers require a version change.
The report's `governance.satisfiable_target_refs` names exactly which refs an
ApprovalRequest or ReleaseControl may target.

## Receipts

Apply mints `receipt://hypervisor/improvement/*` citing `simulation_ref`,
`report_hash`, `simulation_waiver_ref`, `approval_request_ref`, and
`release_control_ref`. The receipt therefore retains either the saved-
simulation path or its exact waiver and the applicable governance chain. The
Work Ledger record family (protocol terminology—the Provenance application
renders these views) indexes an `improvement_applied` entry carrying and
backlinking the full chain.

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
