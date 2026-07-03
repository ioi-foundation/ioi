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
