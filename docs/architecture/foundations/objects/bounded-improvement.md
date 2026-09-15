# Bounded Improvement Campaign Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of the bounded-improvement governance profile, agenda, campaign, evaluation epoch, exposure, evidence, and cutoff families.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-09-15.
Doctrine status: canonical
Implementation status: partial (the six-family governance spine — governance profile, agenda, campaign, evaluation epoch, exposure ledger and order-cutoff receipt — is admitted as registered contracts on the shared owner-scoped mutation chain by `crates/node/src/bin/hypervisor_daemon_routes/improvement_campaign_routes.rs` (M10.1, 2026-09-15), with the campaign's only exit an ordinary pending `UpgradeProposal`. The evidence-claim family, candidate/attempt/finding objects, atomic target bundles, System-scoped admission under a constitution, governed successor contract revisions, profile revocation and epoch adjudication remain target.)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/improvement_campaign_routes.rs`
Last implementation audit: 2026-09-15 (M10.1 spine)

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

Every family here is admitted on the shared owner-scoped mutation chain as a
registered contract: identity (`<scheme>://<family>` and its
`/revision/<n>`) is derived from the durable stream, never chosen; a
successor names the exact current head; every record is validated against its
registered contract before it becomes durable; `content_hash` is committed
under a per-family domain separator and re-derived on every read; and
`admitted_at` is the stamp of the admitting chain operation, refused on read
when it is not. Each shape below states which members the daemon resolves,
which are lifecycle projections outside the family's immutable commitment, and
which second commitment (the canon root) freezes the subset doctrine names.

### ImprovementGovernanceProfileEnvelope

An accountable owner binds one immutable, owner-qualified policy profile for
bounded improvement. For a System, its constitution protects the selected
profile and change path. A user, project, or organization may bind the same
profile family for a non-System research Campaign, but that does not create a
System, constitution, or bounded-DAS conformance claim. The profile controls
whether the owner scope may admit Campaign work; it is not a campaign,
evaluator, authority grant, or promotion decision.

```yaml
ImprovementGovernanceProfileEnvelope:
  schema_version: ioi.improvement-governance-profile.v1
  improvement_governance_profile_id: improvement-governance-profile://...
  revision_ref: improvement-governance-profile://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref:
    improvement-governance-profile://.../revision/... | null
  content_hash: hash
  owner_ref: user://... | org://... | project://... | system://...
  system_id: system://... | null
  mutable_target_allowlist_refs: []
  protected_target_refs: []
  protected_target_change_decision_profile_refs: []
  max_target_improvement_order: nonnegative_integer
  max_active_nested_campaign_depth: positive_integer
  max_unattended_target_generations: nonnegative_integer
  ancestor_reservation_policy_refs:
    resource_budget: policy://...
    statistical_risk_budget: policy://...
    evaluation_exposure_budget: policy://...
  campaign_admission_policy_ref: policy://...
  campaign_stop_policy_ref: policy://...
  evaluator_firewall_policy_ref: policy://...
  evaluator_independence_policy_ref: policy://...
  promotion_authority_policy_ref: policy://...
  irreversible_effect_recovery_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | decision://... | null
  registry_status: draft | active | superseded | revoked
  admitted_at: timestamp
```

The revision body and `content_hash` are immutable; registry lifecycle and
status are projections outside that hash. Descendants reserve disjoint
resource, statistical-risk, and evaluation-exposure allowances from their
ancestors. Naming a higher target order or creating another GoalRun never
duplicates or resets those allowances. For a System-scoped profile,
replacement follows the constitution's protected change path; otherwise it
follows the owner scope's declared governance path. Either applies only to
newly admitted work unless an explicit pause, quarantine, or migration decision
says otherwise.

Server-resolved members: `schema_version`, the id, `revision_ref`,
`predecessor_revision_ref`, `content_hash`, `owner_ref`,
`registry_lifecycle_ref`, `registry_status` and `admitted_at`. `content_hash`
commits every member except itself, `registry_lifecycle_ref`,
`registry_status` and `admitted_at` under
`ioi.improvement-governance-profile-content-commitment-jcs-sha256.v1`.
`registry_status` is `active` on the family's newest admitted revision and
`superseded` on every earlier one, derived on read. Revocation and the
System-scoped protected change path are not built; a non-null `system_id` is
refused typed until the constitution's protected profile binding exists.

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
  admitted_at: timestamp
```

Lifecycle/status fields are registry projections excluded from `content_hash`.
Only a released revision is campaign-admission eligible. The requested order
and budget are hypotheses; Governance resolves the effective target path,
order, authority, and ceilings at admission. An `improvement_agenda_patch`
UpgradeProposal creates a successor revision and affects only future campaign
admissions.

Server-resolved members: `schema_version`, the id, `revision_ref`, `revision`,
`predecessor_revision_ref`, `content_hash`, `owner_ref`,
`registry_lifecycle_ref`, `registry_status` and `admitted_at`;
`release_decision_ref` is the releasing caller's decision. `content_hash`
commits every member except itself, `registry_lifecycle_ref`,
`registry_status`, `release_decision_ref` and `admitted_at` under
`ioi.improvement-agenda-content-commitment-jcs-sha256.v1`, so a release is a
successor admission of the SAME revision on the family's stream carrying the
identical `content_hash` with `registry_status: released`; a released revision
reads as `superseded` once a later revision of the family is released.
`evaluable` and `retired` are declared and unreached on this basis.

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
  coordinating_work_subject_ref: goal://... | session://... | work-run://... | null
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
  lifecycle_status: proposed | admitted | active | paused | stopped | closed
  content_hash: hash
  admitted_at: timestamp
```

Three tiers, each with its own commitment. (1) THE CONTRACT: every member the
campaign declares at creation plus the four the daemon resolves then —
`target_base_root` and `deployment_incumbent_root` (read from the mutable
target through its owner's reader, never declared), `pursuit_method_order`
with `target_to_pursuit_method_edge_ref`, and `effective_learning_policy_hash`
(read from the bound learning-boundary profile revision through that plane's
published reader) — committed as `campaign_contract_root` under
`ioi.improvement-campaign-contract-root-jcs-sha256.v1`. (2) ADMISSION FACTS,
written once by `admit` and immutable after it: `campaign_admission_decision_ref`,
`campaign_admission_receipt_ref`, `admission_authority_and_constitution_snapshot_refs`,
`effective_governance_snapshot_ref`, `effective_target_order_ceiling`,
`effective_target_order_ceiling_ref`, `max_active_nested_campaign_depth` and
`target_order_assignment_receipt_ref`; they are null or empty while proposed.
(3) PROJECTIONS, advanced by later operations: `child_work_subject_refs`,
`candidate_archive_ref`, `candidate_resolved_component_snapshot_refs`,
`active_evaluation_epoch_ref`, `historical_evaluation_epoch_refs`,
`improvement_order_cutoff_receipt_refs`, `resource_reservation_refs`,
`statistical_risk_reservation_refs`, `evaluation_exposure_reservation_refs`,
`operation_head_sequence`, `operation_head_root`,
`derived_state_projection_ref` and `lifecycle_status`. `content_hash` commits
the whole entry except itself, `operation_head_root` and `admitted_at` under
`ioi.improvement-campaign-content-commitment-jcs-sha256.v1`;
`operation_head_root` chains the predecessor entry's root with this entry's
`content_hash` under `ioi.improvement-campaign-operation-head-jcs-sha256.v1`
(genesis predecessor `null`). A lifecycle successor whose contract root differs
from its predecessor's is refused `campaign_binding_mismatch`. A governed
successor contract revision is not built, so `campaign_contract_revision` is
`1` and `predecessor_contract_revision_ref` is `null`. A non-null `system_id`
is refused `improvement_campaign_system_scope_not_admitted` until the
constitution's protected profile binding exists; an `atomic_target_bundle_ref`
is refused typed for the same reason.

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

### ImprovementRoleBindingEnvelope

Search, Judgment and Authority are logical trust functions of one campaign
([`../bounded-recursive-improvement.md`](../bounded-recursive-improvement.md)
§ Search, Judgment, And Authority). A role binding makes them SEPARATELY
IDENTIFIABLE: it names, for one campaign, which admitted deployment principals
hold each function, so every role-separated seam is keyed on the RESOLVED
caller principal against the campaign's current binding and never on a role a
request body declares. The campaign's declared `improvement_assurance_profile`
is copied at admission and decides the checkable independence obligation the
daemon derives into `independence`: `local_lightweight` permits one
accountable principal to hold all three (`separately_identifiable`);
`independent_review` and every tier above require judgment and authority under
distinct principals and search disjoint from judgment
(`distinct_principals`) — a binding that violates the declared tier is refused
`role_independence_violated`, and a tier the deployment cannot evidence fails
closed at admission. A campaign starts only once a binding is admitted
(`role_bindings_required`); a successor revision names the exact current head.
Registered as `schema://ioi/foundations/objects/improvement-role-binding/v1`
(2026-09-15, M10.2).

```yaml
ImprovementRoleBindingEnvelope:
  schema_version: ioi.improvement-role-binding.v1
  improvement_role_binding_id: improvement-role-binding://...   # the campaign's family token
  revision_ref: improvement-role-binding://.../revision/...
  revision: positive_integer
  predecessor_revision_ref: improvement-role-binding://.../revision/... | null
  content_hash: hash                      # every member except itself and admitted_at
  owner_ref: org://... | project://... | system://... | user://...
  campaign_ref: improvement-campaign://...
  improvement_assurance_profile: local_lightweight | independent_review | protected_build |
    adversarial_control | threshold_recovery | failure_domain_independent   # copied from the campaign contract
  bindings:
    search: [user://...]                  # propose candidates and investigations; request evaluation
    judgment: [user://...]                # freeze and apply evaluation contracts; account for exposure
    authority: [user://...]               # admit, approve, activate, stop, recover
  independence: separately_identifiable | distinct_principals   # derived from the profile, never authored
  binding_decision_ref: decision://...
  admitted_at: timestamp
```

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
  evaluation_exposure_budget_policy_ref: policy://...
  evaluation_exposure_budget_units: nonnegative_integer
  evaluator_version_and_affiliation_refs: []
  holdout_custodian_refs: []
  external_reality_anchor_refs: []
  operational_acceptance_owner_refs: []
  leakage_rotation_and_challenge_policy_refs: []
  frozen_root: hash
  lifecycle_ref: agentgres://object/... | decision://... | null
  lifecycle_status: draft | frozen | active | challenged | closed | invalidated
  challenge_evidence_refs: []
  content_hash: hash
  admitted_at: timestamp
```

Lifecycle state is a projection excluded from `frozen_root`. A challenge or
invalidation appends linked evidence rather than rewriting the epoch. The
deployment incumbent root is the frozen comparison baseline, not ownership of
the live Systems/ReleaseControl incumbent projection.

An epoch is created under an ACTIVE campaign and copies its coordinates from
that campaign's contract — `campaign_ref`, `campaign_contract_revision_ref`,
`campaign_contract_root`, the pursuit profile and snapshot refs, both orders,
the generation index, the incumbent ref and root, the statistical-risk ledger
ref and the inherited exposure ledger refs — while `predecessor_epoch_ref` is
the campaign's previous epoch and `synchronization_cutoff_receipt_ref` its
latest order-cutoff receipt, or null. `evaluation_exposure_budget_units` is
the sealed-evaluation exposure the epoch's ledger may reserve, in units, and
is frozen with the rest. `frozen_root` commits every member except itself,
`lifecycle_ref`, `lifecycle_status`, `challenge_evidence_refs`, `content_hash`
and `admitted_at` under `ioi.evaluation-epoch-frozen-root-jcs-sha256.v1`; it
is computed on every entry and BINDING from `freeze` onward, so a successor
whose frozen root moved is refused `campaign_binding_mismatch`. `content_hash`
commits the entry except itself and `admitted_at`. The lifecycle is
`draft → frozen → active → closed`, with `challenged` reachable from `active`
and `invalidated` reachable from `frozen`, `active` or `challenged`; a
campaign has at most one active epoch (`evaluation_epoch_already_active`).
Exposure, nomination and a campaign-bound apply require an active frozen epoch:
a draft answers `evaluation_epoch_not_frozen`; a challenged, closed or
invalidated epoch answers `evaluation_epoch_invalid`. Adjudication of a
challenge is not built, so a challenged epoch stays invalid until it is closed
or invalidated.

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
  exposure_budget_units: nonnegative_integer
  reserved_units: nonnegative_integer
  spent_units: nonnegative_integer
  returned_units: nonnegative_integer
  remaining_units: nonnegative_integer
  contaminated: boolean
  entries:
    - entry_seq: positive_integer
      entry_ref: evaluation-exposure://.../entry/...
      entry_kind: reservation | spend | return | contamination | rotation | invalidation
      units: nonnegative_integer
      candidate_family_commitment: hash
      selected_case_commitment: hash | null
      information_return_class: none | aggregate | per_case | labels | internals
      evaluator_version_refs: []
      access_receipt_refs: []
      contamination_flag: boolean
      previous_entry_root: hash | null
      entry_root: hash
  admitted_entry_refs: []
  ledger_head_sequence: nonnegative_integer
  ledger_head_root: hash
  derived_exposure_and_contamination_projection_ref: agentgres://projection/...
  lifecycle_decision_refs: []
  content_hash: hash
  admitted_at: timestamp
```

Each immutable entry binds the candidate/family/ancestry commitments, selected
case commitments, information-return class, evaluator versions, execution and
access receipts, contamination flags, charged exposure, and previous root.
Reservation, spend, return, contamination, rotation, and invalidation are
append-only entry kinds. Remaining exposure and contamination posture are
derived from the admitted head; child Campaigns inherit effective ancestor
spend and cannot reset it by changing identity or order.

The ledger is created by the epoch's `freeze`, one per epoch, with
`exposure_budget_units` copied from the frozen epoch and `exposure_budget_ref`
its `evaluation_exposure_budget_policy_ref`; every member except an entry's
caller-declared commitments (`candidate_family_commitment`,
`selected_case_commitment`, `information_return_class`,
`evaluator_version_refs`, `access_receipt_refs`, `units`) is the daemon's.
Accounting is a subtraction: `reserved_units` is the sum of every reservation
admitted, `returned_units` the sum returned, `spent_units` the sum spent, and
`remaining_units = exposure_budget_units − (reserved_units − returned_units)`.
A reservation that would make `reserved_units − returned_units` exceed the
budget, or a spend or return larger than the outstanding reservation
(`reserved − returned − spent`), is refused `evaluation_exposure_exhausted`;
reservation, spend and return carry positive units, the other kinds zero. A
contamination entry sets `contaminated` for the rest of the ledger's life.
`entry_root` chains the previous entry's root with the entry's other members
under `ioi.evaluation-exposure-entry-root-jcs-sha256.v1`; `ledger_head_root`
is the last entry's root, or the genesis root over the ledger id when there
are no entries. Bounded domains: units and budgets in `0..=1000000000`,
sequences in `0..=1000000`, at most 4096 entries per ledger
(`evaluation_exposure_ledger_full` beyond it). Every exposure operation names
the exact current head of the ledger's stream.

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
  schema_version: ioi.improvement-order-cutoff-receipt.v1
  receipt_id: receipt://improvement-order-cutoff/...
  receipt_profile: improvement_order_cutoff
  receipt_profile_ref: schema://ioi/foundations/objects/improvement-order-cutoff-receipt/v1
  source_campaign_ref: improvement-campaign://...
  source_evaluation_epoch_ref: evaluation-epoch://...
  synchronization_wave_ref: artifact://...
  source_campaign_epoch_and_archive_roots: []
  source_target_improvement_order: nonnegative_integer
  source_target_generation_cutoff: nonnegative_integer
  intended_destination_target_order: nonnegative_integer
  per_order_source_version_and_cutoff_vector_ref: artifact://...
  destination_base_root: hash
  agenda_revision_ref: improvement-agenda://.../revision/...
  agenda_and_task_distribution_roots: []
  boundary_crossing: same_boundary | institutional_boundary
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
  content_hash: hash
  admitted_at: timestamp
```

The destination order must equal the source order plus one; skipped edges need
their own later cutoff. Same-boundary use may have no learning-egress receipt,
but still requires learning eligibility and applicable access/custody evidence.
Fresh cross-play/ablation, UpgradeDecision, activation, monitoring, and effect
recovery remain with their existing owners.

A cutoff is emitted on the source campaign's own cutoff stream
(`receipt://improvement-order-cutoff/<campaign family>/<n>`) while that campaign
is active, and its source epoch must be CLOSED — a cutoff happens at epoch
close (`improvement_order_cutoff_invalid` otherwise, `evaluation_epoch_invalid`
for an invalidated epoch); a destination order other than source plus one is
`improvement_order_cutoff_invalid`. `agenda_revision_ref` must be the campaign's
admitted agenda revision: a released successor of that family named at the same
cutoff is `same_cutoff_mutual_validation`, because the agenda successor would
be selected on the evidence it is about to govern. Every eligible finding must
be a subject of a cited `LearningEvidenceEligibility` revision that resolves
under the owner through that plane's published reader and reads `eligible`
(`learning_evidence_ineligible`); an `institutional_boundary` crossing must cite
at least one `LearningEgressReceipt` resolving under the owner as an admitted
crossing (`learning_egress_denied`). The daemon writes the source roots
(`[campaign_contract_root, frozen_root]`), `denied_or_quarantined_information_class_refs`
(the source epoch's sealed commitments — sealed material is denied by rule — and
the subjects every cited eligibility excluded), `effective_learning_policy_hash`,
the incumbent snapshot, the reservation roots (`[ledger_head_root]`),
`terminal_disposition` (`evidence_ready` when any eligible ref survives, else
`no_change`; `blocked` names what a refused cutoff would have been and is never
written), `previous_cutoff_receipt_root`, `receipt_root` (every member except
itself, `content_hash` and `admitted_at`, under
`ioi.improvement-order-cutoff-receipt-root-jcs-sha256.v1`), `content_hash` and
`admitted_at`.
