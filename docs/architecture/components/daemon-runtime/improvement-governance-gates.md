# Improvement Governance Gates

Status: implemented contract (daemon `ioi_intelligence_routes.rs` + `governance_routes.rs`)
Canonical owner: this file for the apply-time gate rule, freshness rule, and reason codes.
Object authority remains `docs/architecture/foundations/common-objects-and-envelopes.md`
(improvement proposals, simulation reports) and the governance control objects
(`approval-request://`, `release-control://`).

## Doctrine

Evidence suggests, simulation previews, **governance decides**, receipts prove. A learned
improvement whose saved what-if simulation is high-impact cannot become behavior without an
APPROVED `ApprovalRequest` and an OPEN `ReleaseControl` targeting the proposal or that
simulation report — validated LIVE at apply time, never trusted from stale stamped refs.

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

All blocks are HTTP 409 with the deterministic reason codes above.

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
