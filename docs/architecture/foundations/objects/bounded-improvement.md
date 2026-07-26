# Bounded Improvement Campaign Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of the bounded-improvement governance profile, agenda, campaign, evaluation epoch, exposure, evidence, and cutoff families.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-26.
Doctrine status: canonical
Implementation status: planned (the bounded-improvement Agenda/Campaign/Epoch/exposure/claim spine is not started)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../bounded-recursive-improvement.md`](../bounded-recursive-improvement.md);
this module does not restate them.

## Bounded Improvement Campaign Envelopes

These objects add the optional multi-epoch state missing between bounded
pursuit and target-owner promotion. They do not add an RSI engine, runtime,
authority plane, evaluator, or product application. A direct one-shot change
may still proceed through `UpgradeProposalEnvelope` without a Campaign.

### ImprovementAgendaEnvelope

An Agenda is an immutable-by-revision governed portfolio of questions worth
investigating. It requests targets and evidence; it is not executable and
cannot choose current-epoch truth or authorize target mutation.

```yaml
ImprovementAgendaEnvelope:
  schema_version: ioi.improvement-agenda.v1
  improvement_agenda_id: improvement-agenda://...
  revision_ref: improvement-agenda://.../revision/...
  revision: positive_integer
  predecessor_revision_ref: improvement-agenda://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://...
  system_id: system://... | null
  constitution_and_policy_refs: []
  governance_policy_refs: []
  release_decision_ref: decision://... | null
  target_graph_ref: artifact://...
  portfolio_allocation_policy_ref: policy://...
  items:
    - agenda_item_id: string
      target_ref: string
      target_class: string
      requested_target_improvement_order: nonnegative_integer
      requested_target_order_path_ref: artifact://...
      mechanism_hypothesis_ref: artifact://...
      causal_prediction_and_falsifier_ref: artifact://...
      minimum_decisive_test_ref: policy://... | artifact://...
      evidence_gap_and_uncertainty_ref: artifact://...
      transfer_and_reproduction_requirement_refs: []
      hard_constraint_and_risk_refs: []
      protected_exclusion_refs: []
      dependency_and_readiness_refs: []
      requested_budget_ref: budget://...
      effect_recovery_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | decision://... | null
  registry_status: draft | evaluable | released | superseded | retired
```

Lifecycle/status fields are registry projections excluded from `content_hash`.
Only a released revision is campaign-admission eligible. The requested order
and budget are hypotheses; Governance resolves the effective target path,
order, authority, and ceilings at admission. An `improvement_agenda_patch`
UpgradeProposal creates a successor revision and affects only future campaign
admissions.

### ImprovementCampaignEnvelope

A Campaign owns the optional multi-epoch candidate, evaluation,
synchronization, and promotion lineage for one mutable target or exceptional
same-owner atomic bundle. Typed work subjects coordinate its work — Sessions and WorkRuns generically, GoalRuns and OutcomeRooms optionally where the goal-orchestration application is present (ADR 0023); the Campaign is not a
second goal, pursuit profile, execution identity, evaluator, or authority.

```yaml
ImprovementCampaignEnvelope:
  schema_version: ioi.improvement-campaign.v1
  improvement_campaign_id: improvement-campaign://...
  campaign_contract_revision_ref: improvement-campaign://.../revision/...
  campaign_contract_revision: positive_integer
  predecessor_contract_revision_ref:
    improvement-campaign://.../revision/... | null
  campaign_contract_root: hash
  owner_ref: org://... | project://... | system://... | user://...
  system_id: system://... | null
  improvement_governance_profile_revision_ref:
    improvement-governance-profile://.../revision/...
  effective_governance_snapshot_ref: artifact://...
  campaign_admission_decision_ref: decision://...
  campaign_admission_receipt_ref: receipt://...
  admission_authority_and_constitution_snapshot_refs: []
  coordinating_work_subject_ref: goal://... | session://... | work_run://... | null
  child_work_subject_refs: []
  coordinating_pursuit:
    goal_run_profile_revision_ref: goal-run-profile://.../revision/... | null
    goal_run_profile_resolution_receipt_ref: receipt://... | null
  improvement_assurance_profile:
    local_lightweight | independent_review | protected_build |
    adversarial_control | threshold_recovery | failure_domain_independent
  resolved_component_snapshot_ref: artifact://...
  outcome_room_ref: outcome-room://... | null
  agenda_revision_ref: improvement-agenda://.../revision/...
  agenda_item_refs: []
  campaign_mode:
    optimization | recursive_seat_test | transfer_test |
    independent_reproduction | evaluator_campaign
  target_class: string
  mutable_target_ref: string | null
  atomic_target_bundle_ref: artifact://... | null
  target_base_root: hash
  protected_boundary_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  target_to_pursuit_method_edge_ref: artifact://... | receipt://...
  target_order_path_ref: artifact://...
  target_order_assignment_receipt_ref: receipt://...
  base_target_generation_index: nonnegative_integer
  effective_target_order_ceiling: nonnegative_integer
  effective_target_order_ceiling_ref: policy://... | decision://...
  max_active_nested_campaign_depth: positive_integer
  parent_execution_campaign_ref: improvement-campaign://... | null
  predecessor_target_generation_campaign_ref: improvement-campaign://... | null
  source_lower_order_campaign_refs: []
  deployment_incumbent_ref: string
  deployment_incumbent_root: hash
  candidate_archive_ref: artifact://... | null
  candidate_resolved_component_snapshot_refs: []
  active_evaluation_epoch_ref: evaluation-epoch://... | null
  historical_evaluation_epoch_refs: []
  search_and_candidate_archive_policy_refs: []
  synchronization_policy_ref: policy://...
  improvement_order_cutoff_receipt_refs: []
  ancestor_resource_budget_ledger_ref: ledger://...
  resource_reservation_refs: []
  ancestor_statistical_risk_budget_ledger_ref: ledger://...
  statistical_risk_reservation_refs: []
  inherited_evaluation_exposure_ledger_refs: []
  evaluation_exposure_reservation_refs: []
  learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  stop_policy_ref: policy://...
  rollback_recall_containment_compensation_and_reconciliation_policy_refs: []
  operation_head_sequence: nonnegative_integer
  operation_head_root: hash
  derived_state_projection_ref: agentgres://projection/...
```

Exactly one of `mutable_target_ref` or `atomic_target_bundle_ref` is present.
Every atomic-bundle member must share one admitted target order, activation
owner, evaluator, conflict set, and recovery path; otherwise use separate
Campaigns with explicit dependencies. Contract fields are frozen by
`campaign_contract_root`; candidates, epochs, reservations, cutoffs, and state
advance through append-only Agentgres operations and rebuildable projections.
The child-run list, candidate/archive refs, active and historical Epoch refs,
cutoff refs, reservation refs, operation head, and derived-state ref are
operation projections excluded from that contract root. A governed successor
contract revision applies only to future operations/Epochs and never
reinterprets evidence already frozen under a predecessor root.
Parallel descendants reserve disjoint ancestor resource, statistical-risk, and
exposure allowances. Creating a child or relabeling order never copies or
resets an allowance.
Target order is path-relative and revision-bound, never an intrinsic property
of a component. `pursuit_method_order` is recorded only with the frozen target-
to-method edge and is normally the target order plus one; generation indexes,
active nesting depth, transfer tier, and evidence claim class remain orthogonal.

### EvaluationEpochEnvelope

An Evaluation Epoch freezes one Campaign utility, verifier, holdout,
statistical, and acceptance contract. Changing any frozen evaluator or metric
creates a successor epoch and cannot select a candidate against the old epoch.

```yaml
EvaluationEpochEnvelope:
  schema_version: ioi.evaluation-epoch.v1
  evaluation_epoch_id: evaluation-epoch://...
  campaign_ref: improvement-campaign://...
  campaign_contract_revision_ref: improvement-campaign://.../revision/...
  campaign_contract_root: hash
  predecessor_epoch_ref: evaluation-epoch://... | null
  pursuit_goal_run_profile_revision_ref: goal-run-profile://.../revision/... | null
  pursuit_profile_resolution_and_component_snapshot_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  base_target_generation_index: nonnegative_integer
  target_graph_and_order_path_roots: []
  deployment_incumbent_ref: string
  deployment_incumbent_root: hash
  synchronization_cutoff_receipt_ref: receipt://... | null
  visible_eval_refs: []
  sealed_holdout_commitment_refs: []
  transfer_ood_and_adversarial_eval_refs: []
  recursive_seat_and_metaproductivity_metric_refs: []
  cross_play_and_causal_ablation_policy_ref: policy://...
  transfer_non_regression_and_hard_constraint_gate_refs: []
  metric_and_selection_policy_ref: policy://...
  cost_normalization_ref: policy://...
  confirmatory_estimand_and_minimum_effect_refs: []
  statistical_test_and_winner_adjustment_refs: []
  risk_wealth_allocation_ref: policy://...
  power_and_inconclusive_stop_policy_ref: policy://...
  campaign_false_promotion_budget_ref: policy://...
  ancestor_statistical_risk_budget_ledger_ref: ledger://...
  inherited_evaluation_exposure_ledger_refs: []
  sealed_feedback_release_and_exposure_spend_policy_refs: []
  evaluator_version_and_affiliation_refs: []
  holdout_custodian_refs: []
  external_reality_anchor_refs: []
  operational_acceptance_owner_refs: []
  leakage_rotation_and_challenge_policy_refs: []
  frozen_root: hash
  lifecycle_ref: agentgres://object/... | decision://... | null
  lifecycle_status: draft | frozen | active | challenged | closed | invalidated
```

Lifecycle state is a projection excluded from `frozen_root`. A challenge or
invalidation appends linked evidence rather than rewriting the epoch. The
deployment incumbent root is the frozen comparison baseline, not ownership of
the live Systems/ReleaseControl incumbent projection.

### EvaluationExposureLedgerEnvelope

```yaml
EvaluationExposureLedgerEnvelope:
  schema_version: ioi.evaluation-exposure-ledger.v1
  evaluation_exposure_ledger_id: evaluation-exposure://...
  evaluation_epoch_ref: evaluation-epoch://...
  ancestor_exposure_ledger_refs: []
  steward_refs: []
  sealed_suite_and_world_commitment_refs: []
  exposure_budget_ref: policy://...
  admitted_entry_refs: []
  ledger_head_sequence: nonnegative_integer
  ledger_head_root: hash
  derived_exposure_and_contamination_projection_ref: agentgres://projection/...
  lifecycle_decision_refs: []
```

Each immutable entry binds the candidate/family/ancestry commitments, selected
case commitments, information-return class, evaluator versions, execution and
access receipts, contamination flags, charged exposure, and previous root.
Reservation, spend, return, contamination, rotation, and invalidation are
append-only entry kinds. Remaining exposure and contamination posture are
derived from the admitted head; child Campaigns inherit effective ancestor
spend and cannot reset it by changing identity or order.

### ImprovementEvidenceClaimEnvelope

This immutable artifact states only the bounded evidence actually established.
It is not an authority object, promotion decision, or promise of open-ended
recursive improvement.
Its `claim_class` uses the cross-component member set owned by
[`canonical-enums.md`](../canonical-enums.md#improvement-evidence-claim-classes-claim_class).

```yaml
ImprovementEvidenceClaimEnvelope:
  schema_version: ioi.improvement-evidence-claim.v1
  improvement_evidence_claim_id: improvement-evidence://...
  evidence_revision: positive_integer
  predecessor_evidence_claim_ref: improvement-evidence://... | null
  campaign_refs: []
  target_chain_refs: []
  target_improvement_order: nonnegative_integer
  pursuit_method_order: positive_integer
  target_generation_range: string
  transfer_tiers_claimed: []
  claim_class:
    bounded_optimization | self_targeted_improvement |
    net_positive_recursive_improvement | ignition_evidence |
    inflection_evidence
  claim_methodology_ref: policy://...
  baseline_incumbent_and_candidate_snapshot_refs: []
  fixed_budget_environment_and_cost_refs: []
  visible_sealed_transfer_and_production_eval_refs: []
  synchronization_cutoff_and_downstream_lineage_refs: []
  descendant_campaign_archive_and_distribution_refs: []
  transfer_matrix_ref: artifact://...
  causal_ablation_falsifier_and_statistical_analysis_refs: []
  recursive_seat_test_ref: improvement-campaign://... | null
  independent_reproduction_refs: []
  complexity_operability_monitorability_and_workgraph_refs: []
  evaluator_change_and_challenge_refs: []
  outer_release_and_effect_recovery_refs: []
  limitations_ref: artifact://...
  evidence_root: hash
  claim_lifecycle_ref: agentgres://object/... | decision://... | null
```

Support, dispute, supersession, withdrawal, evaluator invalidation, and claim
downgrade append lifecycle or successor records. They never mutate the claim
body or let a later looser methodology inflate an earlier claim.

### ImprovementOrderCutoffReceiptEnvelope

This receipt is a typed evidence/learning cutoff between adjacent target
orders. It is neither a live synchronization object nor later promotion proof.

```yaml
ImprovementOrderCutoffReceiptEnvelope:
  receipt_id: receipt://...
  receipt_profile: improvement_order_cutoff
  receipt_profile_ref: schema://ioi/improvement-order-cutoff-receipt/v1
  synchronization_wave_ref: artifact://...
  source_campaign_epoch_and_archive_roots: []
  source_target_improvement_order: nonnegative_integer
  source_target_generation_cutoff: nonnegative_integer
  intended_destination_target_order: nonnegative_integer
  per_order_source_version_and_cutoff_vector_ref: artifact://...
  destination_base_root: hash
  agenda_and_task_distribution_roots: []
  eligible_finding_and_outcome_refs: []
  learning_evidence_eligibility_refs: []
  learning_egress_receipt_refs: []
  boundary_enforcement_access_and_custody_receipt_refs: []
  effective_learning_policy_hash: hash
  denied_or_quarantined_information_class_refs: []
  source_incumbent_resolved_component_snapshot_ref: artifact://...
  inherited_budget_risk_and_exposure_reservation_roots: []
  dependency_and_statistical_assumption_delta_ref: artifact://...
  signal_bundle_ref: artifact://... | null
  terminal_disposition: evidence_ready | no_change | blocked
  previous_cutoff_receipt_root: hash | null
  receipt_root: hash
```

The destination order must equal the source order plus one; skipped edges need
their own later cutoff. Same-boundary use may have no learning-egress receipt,
but still requires learning eligibility and applicable access/custody evidence.
Fresh cross-play/ablation, UpgradeDecision, activation, monitoring, and effect
recovery remain with their existing owners.
