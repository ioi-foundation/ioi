//! M10.1 — the bounded improvement campaign spine: six registered families on the shared
//! owner-scoped mutation chain.
//!
//! `ImprovementGovernanceProfile`, `ImprovementAgenda`, `ImprovementCampaign`, `EvaluationEpoch`,
//! `EvaluationExposureLedger` and `ImprovementOrderCutoffReceipt` (canon:
//! `foundations/objects/bounded-improvement.md`) become revision families through the estate's
//! existing `FamilySpec` machinery — the same spine M10.3 runs its four learning-boundary families
//! through — so identity is derived from the durable stream, every record is validated against its
//! REGISTERED contract before it becomes durable, `content_hash` is committed under a per-family
//! domain and re-derived on read, a successor names the exact current head, and a retried key
//! replays. Nothing here is a second mutation contract.
//!
//! THREE TIERS, THREE COMMITMENTS. Canon's own roots (`campaign_contract_root`, `frozen_root`,
//! `ledger_head_root`, `receipt_root`) are SECOND commitments over the contract / frozen SUBSET, so
//! a lifecycle transition is a successor whose subset must hash identically
//! (`campaign_binding_mismatch` otherwise) while `content_hash` moves with the projection fields.
//! That is canon's "lifecycle state is a projection excluded from the root" made checkable.
//!
//! ADMISSION RESOLVES, IT DOES NOT COPY. Campaign admission reads the owner's CURRENT governance
//! profile revision, the RELEASED agenda revision and its items, the mutable target's root through
//! the target's own owner (`ioi_intelligence_routes::resolve_core_mutable_target_root`, CORE
//! families only) and the learning-boundary profile through that plane's published reader. A cutoff
//! resolves every cited eligibility and egress receipt through the learning-boundary plane's own
//! readers. The daemon never synthesizes campaign truth from a caller-supplied claim.
//!
//! THE LAYER LAW, APPLIED (register R-155). A coordinating pursuit — a `GoalRunProfile` revision and
//! its resolution receipt — is the ioi.ai orchestration application's own declaration: core
//! publishes no reader for that family and this module RECORDS the pair (both or neither) without
//! resolving it. Core's own coordinating subjects are `session://` and `work-run://`. This module
//! imports nothing from the application's goal-orchestration modules.
//!
//! THE CAMPAIGN OWNS NO PRODUCTION MUTATION. Its only route toward production is the upgrade-
//! proposal handoff, which writes an ordinary PENDING improvement proposal through the direct
//! path's own create function (never a second writer) bound to the campaign, its active frozen
//! epoch and the frozen contract root; that proposal is subject to the direct path's unchanged
//! gate, plus the campaign-grade bindings `campaign_grade_bindings` evaluates at apply. Every
//! other route here writes only inside the six families.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::institutional_learning_boundary_routes::{
    resolve_admitted_boundary_profile, resolve_admitted_evidence_eligibility,
    resolve_admitted_learning_egress_receipt,
};
use super::ioi_intelligence_routes::{create_improvement_proposal, resolve_core_mutable_target_root};
use super::model_route_rights_routes::{
    authorized_stream, bad, body_str, digest_over, family_token, finish_admission, head_assertion,
    parse_revision_ref, project_stream, projection_cache_state, read_stream, ref_list,
    reject_authored, replay_for_key, require_exact_head, AdmittedRecord, FamilySpec, Reply,
    StreamQuery,
};
use super::mutation_event_foundation::{
    admitted_stamp, require_write_caller, scope_refusal_reply, stream_tail, WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

// ================================================================================ commitment domains

const PROFILE_DOMAIN: &str = "ioi.improvement-governance-profile-content-commitment-jcs-sha256.v1";
const AGENDA_DOMAIN: &str = "ioi.improvement-agenda-content-commitment-jcs-sha256.v1";
const CAMPAIGN_CONTRACT_DOMAIN: &str = "ioi.improvement-campaign-contract-root-jcs-sha256.v1";
const CAMPAIGN_DOMAIN: &str = "ioi.improvement-campaign-content-commitment-jcs-sha256.v1";
const CAMPAIGN_HEAD_DOMAIN: &str = "ioi.improvement-campaign-operation-head-jcs-sha256.v1";
const EPOCH_FROZEN_DOMAIN: &str = "ioi.evaluation-epoch-frozen-root-jcs-sha256.v1";
const EPOCH_DOMAIN: &str = "ioi.evaluation-epoch-content-commitment-jcs-sha256.v1";
const LEDGER_DOMAIN: &str = "ioi.evaluation-exposure-ledger-content-commitment-jcs-sha256.v1";
const ENTRY_DOMAIN: &str = "ioi.evaluation-exposure-entry-root-jcs-sha256.v1";
const CUTOFF_RECEIPT_DOMAIN: &str = "ioi.improvement-order-cutoff-receipt-root-jcs-sha256.v1";
const CUTOFF_DOMAIN: &str = "ioi.improvement-order-cutoff-receipt-content-commitment-jcs-sha256.v1";
const ADMISSION_RECEIPT_DOMAIN: &str = "ioi.improvement-campaign-admission-receipt-jcs-sha256.v1";

/// The exposure ledger's bounded domains, verbatim from the registered contract.
const MAX_UNITS: u64 = 1_000_000_000;
const MAX_LEDGER_ENTRIES: usize = 4096;
const MAX_ORDER: u64 = 1000;

/// The reason codes this spine EMITS from canon's seventeen-member campaign-grade family
/// (improvement-governance-gates.md § Campaign-grade gate extension). Each is driven live by
/// `check:improvement-governance-spine`, which also asserts that no member of the TARGET subset
/// appears anywhere in this module's source.
pub(crate) const IMPLEMENTED_CAMPAIGN_GATE_CODES: &[&str] = &[
    "campaign_binding_mismatch",
    "evaluation_epoch_not_frozen",
    "evaluation_epoch_invalid",
    "target_base_stale",
    "evaluation_exposure_exhausted",
    "learning_evidence_ineligible",
    "learning_egress_denied",
    "same_cutoff_mutual_validation",
    "improvement_order_cutoff_invalid",
    "effect_recovery_posture_missing",
];

// ======================================================================================== families

static PROFILE: FamilySpec = FamilySpec {
    owner_namespace: "improvement-governance-profiles",
    resource_kind: "improvement_governance_profile",
    admit_op: "event_stream.improvement_governance_profile_revision_admitted",
    payload_schema: "ioi.hypervisor.improvement-governance-profile-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/improvement-governance-profile/v1",
    schema_version: "ioi.improvement-governance-profile.v1",
    record_key: "improvement_governance_profile_record",
    code_prefix: "improvement_governance_profile",
    commitment_domain: PROFILE_DOMAIN,
    material_fields: &[
        "schema_version",
        "improvement_governance_profile_id",
        "revision_ref",
        "version",
        "predecessor_revision_ref",
        "owner_ref",
        "system_id",
        "mutable_target_allowlist_refs",
        "protected_target_refs",
        "protected_target_change_decision_profile_refs",
        "max_target_improvement_order",
        "max_active_nested_campaign_depth",
        "max_unattended_target_generations",
        "ancestor_reservation_policy_refs",
        "campaign_admission_policy_ref",
        "campaign_stop_policy_ref",
        "evaluator_firewall_policy_ref",
        "evaluator_independence_policy_ref",
        "promotion_authority_policy_ref",
        "irreversible_effect_recovery_policy_ref",
    ],
    identity_field: "revision_ref",
    ref_scheme: "improvement-governance-profile://",
    stamp_field: "admitted_at",
};

static AGENDA: FamilySpec = FamilySpec {
    owner_namespace: "improvement-agendas",
    resource_kind: "improvement_agenda",
    admit_op: "event_stream.improvement_agenda_revision_admitted",
    payload_schema: "ioi.hypervisor.improvement-agenda-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/improvement-agenda/v1",
    schema_version: "ioi.improvement-agenda.v1",
    record_key: "improvement_agenda_record",
    code_prefix: "improvement_agenda",
    commitment_domain: AGENDA_DOMAIN,
    material_fields: &[
        "schema_version",
        "improvement_agenda_id",
        "revision_ref",
        "revision",
        "predecessor_revision_ref",
        "owner_ref",
        "system_id",
        "constitution_and_policy_refs",
        "governance_policy_refs",
        "target_graph_ref",
        "portfolio_allocation_policy_ref",
        "items",
    ],
    identity_field: "revision_ref",
    ref_scheme: "improvement-agenda://",
    stamp_field: "admitted_at",
};

/// THE CONTRACT subset: every member declared at creation plus the four the daemon resolves then.
const CAMPAIGN_CONTRACT_FIELDS: &[&str] = &[
    "schema_version",
    "improvement_campaign_id",
    "campaign_contract_revision_ref",
    "campaign_contract_revision",
    "predecessor_contract_revision_ref",
    "owner_ref",
    "system_id",
    "improvement_governance_profile_revision_ref",
    "coordinating_work_subject_ref",
    "coordinating_pursuit",
    "improvement_assurance_profile",
    "resolved_component_snapshot_ref",
    "outcome_room_ref",
    "agenda_revision_ref",
    "agenda_item_refs",
    "campaign_mode",
    "target_class",
    "mutable_target_ref",
    "atomic_target_bundle_ref",
    "target_base_root",
    "protected_boundary_refs",
    "target_improvement_order",
    "pursuit_method_order",
    "target_to_pursuit_method_edge_ref",
    "target_order_path_ref",
    "base_target_generation_index",
    "parent_execution_campaign_ref",
    "predecessor_target_generation_campaign_ref",
    "source_lower_order_campaign_refs",
    "deployment_incumbent_ref",
    "deployment_incumbent_root",
    "search_and_candidate_archive_policy_refs",
    "synchronization_policy_ref",
    "ancestor_resource_budget_ledger_ref",
    "ancestor_statistical_risk_budget_ledger_ref",
    "inherited_evaluation_exposure_ledger_refs",
    "learning_boundary_profile_ref",
    "effective_learning_policy_hash",
    "stop_policy_ref",
    "rollback_recall_containment_compensation_and_reconciliation_policy_refs",
];

static CAMPAIGN: FamilySpec = FamilySpec {
    owner_namespace: "improvement-campaigns",
    resource_kind: "improvement_campaign",
    admit_op: "event_stream.improvement_campaign_operation_admitted",
    payload_schema: "ioi.hypervisor.improvement-campaign-operation-admission.v1",
    contract_id: "schema://ioi/foundations/objects/improvement-campaign/v1",
    schema_version: "ioi.improvement-campaign.v1",
    record_key: "improvement_campaign_record",
    code_prefix: "improvement_campaign",
    commitment_domain: CAMPAIGN_DOMAIN,
    // The whole entry except `content_hash`, the chained `operation_head_root` and `admitted_at`.
    material_fields: &[
        "schema_version",
        "improvement_campaign_id",
        "campaign_contract_revision_ref",
        "campaign_contract_revision",
        "predecessor_contract_revision_ref",
        "owner_ref",
        "system_id",
        "improvement_governance_profile_revision_ref",
        "coordinating_work_subject_ref",
        "coordinating_pursuit",
        "improvement_assurance_profile",
        "resolved_component_snapshot_ref",
        "outcome_room_ref",
        "agenda_revision_ref",
        "agenda_item_refs",
        "campaign_mode",
        "target_class",
        "mutable_target_ref",
        "atomic_target_bundle_ref",
        "target_base_root",
        "protected_boundary_refs",
        "target_improvement_order",
        "pursuit_method_order",
        "target_to_pursuit_method_edge_ref",
        "target_order_path_ref",
        "base_target_generation_index",
        "parent_execution_campaign_ref",
        "predecessor_target_generation_campaign_ref",
        "source_lower_order_campaign_refs",
        "deployment_incumbent_ref",
        "deployment_incumbent_root",
        "search_and_candidate_archive_policy_refs",
        "synchronization_policy_ref",
        "ancestor_resource_budget_ledger_ref",
        "ancestor_statistical_risk_budget_ledger_ref",
        "inherited_evaluation_exposure_ledger_refs",
        "learning_boundary_profile_ref",
        "effective_learning_policy_hash",
        "stop_policy_ref",
        "rollback_recall_containment_compensation_and_reconciliation_policy_refs",
        "campaign_contract_root",
        "effective_governance_snapshot_ref",
        "campaign_admission_decision_ref",
        "campaign_admission_receipt_ref",
        "admission_authority_and_constitution_snapshot_refs",
        "target_order_assignment_receipt_ref",
        "effective_target_order_ceiling",
        "effective_target_order_ceiling_ref",
        "max_active_nested_campaign_depth",
        "child_work_subject_refs",
        "candidate_archive_ref",
        "candidate_resolved_component_snapshot_refs",
        "active_evaluation_epoch_ref",
        "historical_evaluation_epoch_refs",
        "improvement_order_cutoff_receipt_refs",
        "resource_reservation_refs",
        "statistical_risk_reservation_refs",
        "evaluation_exposure_reservation_refs",
        "operation_head_sequence",
        "derived_state_projection_ref",
        "lifecycle_status",
    ],
    identity_field: "campaign_contract_revision_ref",
    ref_scheme: "improvement-campaign://",
    stamp_field: "admitted_at",
};

/// THE FROZEN subset: every member except the root itself, the lifecycle projections, the
/// challenge evidence, `content_hash` and `admitted_at`.
const EPOCH_FROZEN_FIELDS: &[&str] = &[
    "schema_version",
    "evaluation_epoch_id",
    "campaign_ref",
    "campaign_contract_revision_ref",
    "campaign_contract_root",
    "predecessor_epoch_ref",
    "pursuit_goal_run_profile_revision_ref",
    "pursuit_profile_resolution_and_component_snapshot_refs",
    "target_improvement_order",
    "pursuit_method_order",
    "base_target_generation_index",
    "target_graph_and_order_path_roots",
    "deployment_incumbent_ref",
    "deployment_incumbent_root",
    "synchronization_cutoff_receipt_ref",
    "visible_eval_refs",
    "sealed_holdout_commitment_refs",
    "transfer_ood_and_adversarial_eval_refs",
    "recursive_seat_and_metaproductivity_metric_refs",
    "cross_play_and_causal_ablation_policy_ref",
    "transfer_non_regression_and_hard_constraint_gate_refs",
    "metric_and_selection_policy_ref",
    "cost_normalization_ref",
    "confirmatory_estimand_and_minimum_effect_refs",
    "statistical_test_and_winner_adjustment_refs",
    "risk_wealth_allocation_ref",
    "power_and_inconclusive_stop_policy_ref",
    "campaign_false_promotion_budget_ref",
    "ancestor_statistical_risk_budget_ledger_ref",
    "inherited_evaluation_exposure_ledger_refs",
    "sealed_feedback_release_and_exposure_spend_policy_refs",
    "evaluation_exposure_budget_policy_ref",
    "evaluation_exposure_budget_units",
    "evaluator_version_and_affiliation_refs",
    "holdout_custodian_refs",
    "external_reality_anchor_refs",
    "operational_acceptance_owner_refs",
    "leakage_rotation_and_challenge_policy_refs",
];

static EPOCH: FamilySpec = FamilySpec {
    owner_namespace: "evaluation-epochs",
    resource_kind: "evaluation_epoch",
    admit_op: "event_stream.evaluation_epoch_operation_admitted",
    payload_schema: "ioi.hypervisor.evaluation-epoch-operation-admission.v1",
    contract_id: "schema://ioi/foundations/objects/evaluation-epoch/v1",
    schema_version: "ioi.evaluation-epoch.v1",
    record_key: "evaluation_epoch_record",
    code_prefix: "evaluation_epoch",
    commitment_domain: EPOCH_DOMAIN,
    material_fields: &[
        "schema_version",
        "evaluation_epoch_id",
        "campaign_ref",
        "campaign_contract_revision_ref",
        "campaign_contract_root",
        "predecessor_epoch_ref",
        "pursuit_goal_run_profile_revision_ref",
        "pursuit_profile_resolution_and_component_snapshot_refs",
        "target_improvement_order",
        "pursuit_method_order",
        "base_target_generation_index",
        "target_graph_and_order_path_roots",
        "deployment_incumbent_ref",
        "deployment_incumbent_root",
        "synchronization_cutoff_receipt_ref",
        "visible_eval_refs",
        "sealed_holdout_commitment_refs",
        "transfer_ood_and_adversarial_eval_refs",
        "recursive_seat_and_metaproductivity_metric_refs",
        "cross_play_and_causal_ablation_policy_ref",
        "transfer_non_regression_and_hard_constraint_gate_refs",
        "metric_and_selection_policy_ref",
        "cost_normalization_ref",
        "confirmatory_estimand_and_minimum_effect_refs",
        "statistical_test_and_winner_adjustment_refs",
        "risk_wealth_allocation_ref",
        "power_and_inconclusive_stop_policy_ref",
        "campaign_false_promotion_budget_ref",
        "ancestor_statistical_risk_budget_ledger_ref",
        "inherited_evaluation_exposure_ledger_refs",
        "sealed_feedback_release_and_exposure_spend_policy_refs",
        "evaluation_exposure_budget_policy_ref",
        "evaluation_exposure_budget_units",
        "evaluator_version_and_affiliation_refs",
        "holdout_custodian_refs",
        "external_reality_anchor_refs",
        "operational_acceptance_owner_refs",
        "leakage_rotation_and_challenge_policy_refs",
        "frozen_root",
        "lifecycle_ref",
        "lifecycle_status",
        "challenge_evidence_refs",
    ],
    identity_field: "evaluation_epoch_id",
    ref_scheme: "evaluation-epoch://",
    stamp_field: "admitted_at",
};

static LEDGER: FamilySpec = FamilySpec {
    owner_namespace: "evaluation-exposure-ledgers",
    resource_kind: "evaluation_exposure_ledger",
    admit_op: "event_stream.evaluation_exposure_ledger_entry_admitted",
    payload_schema: "ioi.hypervisor.evaluation-exposure-ledger-entry-admission.v1",
    contract_id: "schema://ioi/foundations/objects/evaluation-exposure-ledger/v1",
    schema_version: "ioi.evaluation-exposure-ledger.v1",
    record_key: "evaluation_exposure_ledger_record",
    code_prefix: "evaluation_exposure_ledger",
    commitment_domain: LEDGER_DOMAIN,
    material_fields: &[
        "schema_version",
        "evaluation_exposure_ledger_id",
        "evaluation_epoch_ref",
        "ancestor_exposure_ledger_refs",
        "steward_refs",
        "sealed_suite_and_world_commitment_refs",
        "exposure_budget_ref",
        "exposure_budget_units",
        "reserved_units",
        "spent_units",
        "returned_units",
        "remaining_units",
        "contaminated",
        "entries",
        "admitted_entry_refs",
        "ledger_head_sequence",
        "ledger_head_root",
        "derived_exposure_and_contamination_projection_ref",
        "lifecycle_decision_refs",
    ],
    identity_field: "evaluation_exposure_ledger_id",
    ref_scheme: "evaluation-exposure://",
    stamp_field: "admitted_at",
};

const ENTRY_ROOT_FIELDS: &[&str] = &[
    "entry_seq",
    "entry_ref",
    "entry_kind",
    "units",
    "candidate_family_commitment",
    "selected_case_commitment",
    "information_return_class",
    "evaluator_version_refs",
    "access_receipt_refs",
    "contamination_flag",
    "previous_entry_root",
];

/// THE RECEIPT subset: every member except `receipt_root`, `content_hash` and `admitted_at`.
const CUTOFF_RECEIPT_FIELDS: &[&str] = &[
    "schema_version",
    "receipt_id",
    "receipt_profile",
    "receipt_profile_ref",
    "source_campaign_ref",
    "source_evaluation_epoch_ref",
    "synchronization_wave_ref",
    "source_campaign_epoch_and_archive_roots",
    "source_target_improvement_order",
    "source_target_generation_cutoff",
    "intended_destination_target_order",
    "per_order_source_version_and_cutoff_vector_ref",
    "destination_base_root",
    "agenda_revision_ref",
    "agenda_and_task_distribution_roots",
    "boundary_crossing",
    "eligible_finding_and_outcome_refs",
    "learning_evidence_eligibility_refs",
    "learning_egress_receipt_refs",
    "boundary_enforcement_access_and_custody_receipt_refs",
    "effective_learning_policy_hash",
    "denied_or_quarantined_information_class_refs",
    "source_incumbent_resolved_component_snapshot_ref",
    "inherited_budget_risk_and_exposure_reservation_roots",
    "dependency_and_statistical_assumption_delta_ref",
    "signal_bundle_ref",
    "terminal_disposition",
    "previous_cutoff_receipt_root",
];

static CUTOFF: FamilySpec = FamilySpec {
    owner_namespace: "improvement-order-cutoffs",
    resource_kind: "improvement_order_cutoff",
    admit_op: "event_stream.improvement_order_cutoff_receipt_emitted",
    payload_schema: "ioi.hypervisor.improvement-order-cutoff-receipt-emission.v1",
    contract_id: "schema://ioi/foundations/objects/improvement-order-cutoff-receipt/v1",
    schema_version: "ioi.improvement-order-cutoff-receipt.v1",
    record_key: "improvement_order_cutoff_receipt_record",
    code_prefix: "improvement_order_cutoff",
    commitment_domain: CUTOFF_DOMAIN,
    material_fields: &[
        "schema_version",
        "receipt_id",
        "receipt_profile",
        "receipt_profile_ref",
        "source_campaign_ref",
        "source_evaluation_epoch_ref",
        "synchronization_wave_ref",
        "source_campaign_epoch_and_archive_roots",
        "source_target_improvement_order",
        "source_target_generation_cutoff",
        "intended_destination_target_order",
        "per_order_source_version_and_cutoff_vector_ref",
        "destination_base_root",
        "agenda_revision_ref",
        "agenda_and_task_distribution_roots",
        "boundary_crossing",
        "eligible_finding_and_outcome_refs",
        "learning_evidence_eligibility_refs",
        "learning_egress_receipt_refs",
        "boundary_enforcement_access_and_custody_receipt_refs",
        "effective_learning_policy_hash",
        "denied_or_quarantined_information_class_refs",
        "source_incumbent_resolved_component_snapshot_ref",
        "inherited_budget_risk_and_exposure_reservation_roots",
        "dependency_and_statistical_assumption_delta_ref",
        "signal_bundle_ref",
        "terminal_disposition",
        "previous_cutoff_receipt_root",
        "receipt_root",
    ],
    identity_field: "receipt_id",
    ref_scheme: "receipt://improvement-order-cutoff/",
    stamp_field: "admitted_at",
};

// ======================================================================================== helpers

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn integer(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

/// The code and message of a `bad(...)` reply body, which nests them under `error`.
fn refusal_code(reply: &Value) -> String {
    reply
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn refusal_message(reply: &Value) -> String {
    reply
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|item| Value::from(item.as_str())).collect())
}

/// The four owner schemes canon names for this family; the substrate has ALREADY authorized the
/// tenant, so this refuses only a scheme the contract cannot express.
fn owner_scheme_supported(owner_ref: &str) -> bool {
    ["org://", "user://", "project://", "system://"]
        .iter()
        .any(|scheme| owner_ref.starts_with(scheme))
        && owner_ref.len() <= 200
}

/// A closed request-field fence: a member this route does not read is refused by name rather than
/// dropped, so a caller cannot believe it authored something the daemon ignored.
fn refuse_unknown_fields(body: &Value, spec: &FamilySpec, allowed: &[&str]) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &spec.code("request_body_not_object"),
            "the request body must be a JSON object",
        ));
    };
    let permitted: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(bad(
        StatusCode::BAD_REQUEST,
        &spec.code("request_unknown_field"),
        format!(
            "this route does not admit field(s): {}; a server-resolved member is asserted through its expected_* twin, never authored",
            unknown.join(", ")
        ),
    ))
}

/// The common preamble of every write on a family: authenticate, fence the body, refuse authored
/// server members, bind or authorize the resource scope, read the stream, replay by key, and read
/// the head assertion. `genesis` binds a NEW resource; otherwise the resource must already be the
/// caller's.
struct WriteContext {
    caller: WriteCaller,
    scope: RequestResourceScope,
    resource: String,
    stream: Vec<AdmittedRecord>,
    expected_head: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn open_write(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    spec: &'static FamilySpec,
    resource: String,
    allowed: &[&str],
    authored: &[&str],
    genesis: bool,
    reply_key: &'static str,
) -> Result<WriteContext, Reply> {
    let caller = require_write_caller(&st.data_dir, headers, body)?;
    if !owner_scheme_supported(&caller.owner_ref) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &spec.code("owner_scheme_unsupported"),
            "this family admits an owner in org://, user://, project:// or system://; an owner this build cannot express is a typed refusal, never a rewritten one",
        ));
    }
    // An AUTHORED server member is refused by its own name before the closed fence answers, so a
    // caller learns it wrote what the daemon resolves rather than merely a field the route ignores.
    reject_authored(body, spec, authored)?;
    refuse_unknown_fields(body, spec, allowed)?;
    let scope = if genesis {
        bind_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            spec.resource_kind,
            &resource,
            &caller.owner_ref,
            &caller.owner_ref,
            &caller.idempotency_key,
        )
        .map_err(scope_refusal_reply)?
    } else {
        authorize_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            spec.resource_kind,
            &resource,
            Some(caller.owner_ref.as_str()),
        )
        .map_err(scope_refusal_reply)?
    };
    let stream = read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource)?;
    if let Some(reply) = replay_for_key(spec, st, &caller, &scope, &resource, &stream, reply_key)? {
        return Err(reply);
    }
    let expected_head = head_assertion(body, spec.code_prefix)?;
    require_exact_head(&stream, &expected_head, spec.code_prefix)?;
    Ok(WriteContext {
        caller,
        scope,
        resource,
        stream,
        expected_head,
    })
}

/// A read of one family resource under the caller's identity, or the caller's inventory of that
/// family when no resource is named.
fn read_family(
    st: &DaemonState,
    headers: &HeaderMap,
    spec: &'static FamilySpec,
    resource: &str,
) -> Result<(RequestIdentity, Vec<AdmittedRecord>), Reply> {
    let identity =
        resolve_request_identity(&st.data_dir, headers).map_err(scope_refusal_reply)?;
    let stream = authorized_stream(spec, &st.data_dir, &identity, resource)?;
    Ok((identity, stream))
}

fn inventory(st: &DaemonState, headers: &HeaderMap, spec: &'static FamilySpec, key: &str) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    match authorized_request_resource_refs(&st.data_dir, &identity, spec.resource_kind) {
        Ok(refs) => (
            StatusCode::OK,
            Json(json!({ "ok": true, key: refs.into_iter().collect::<Vec<_>>() })),
        ),
        Err(error) => scope_refusal_reply(error),
    }
}

fn family_resource(spec: &FamilySpec, family: &str) -> Result<String, Reply> {
    if !family_token(family) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &spec.code("family_not_canonical"),
            "the family is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        ));
    }
    Ok(format!("{}{family}", spec.ref_scheme))
}

fn chain_root(domain: &str, previous: Option<&str>, content_hash: &str) -> Result<String, Reply> {
    let material = json!({
        "previous_operation_head_root": previous,
        "content_hash": content_hash,
    });
    digest_over(
        &material,
        domain,
        &["previous_operation_head_root", "content_hash"],
    )
    .map_err(|reason| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "improvement_campaign_operation_head_failed",
            reason,
        )
    })
}

// ============================================================================ governance profiles

const PROFILE_REQUEST_FIELDS: &[&str] = &[
    "family",
    "version",
    "system_id",
    "mutable_target_allowlist_refs",
    "protected_target_refs",
    "protected_target_change_decision_profile_refs",
    "max_target_improvement_order",
    "max_active_nested_campaign_depth",
    "max_unattended_target_generations",
    "ancestor_reservation_policy_refs",
    "campaign_admission_policy_ref",
    "campaign_stop_policy_ref",
    "evaluator_firewall_policy_ref",
    "evaluator_independence_policy_ref",
    "promotion_authority_policy_ref",
    "irreversible_effect_recovery_policy_ref",
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
];
const PROFILE_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "improvement_governance_profile_id",
    "revision_ref",
    "predecessor_revision_ref",
    "content_hash",
    "registry_lifecycle_ref",
    "registry_status",
    "admitted_at",
];

/// The served status of a profile revision is DERIVED: the family's newest revision is `active`,
/// every earlier one `superseded`.
fn project_profile(stream: &[AdmittedRecord], index: usize) -> Value {
    let mut record = stream[index].record.clone();
    let status = if index + 1 == stream.len() {
        "active"
    } else {
        "superseded"
    };
    record["registry_status"] = json!(status);
    record
}

pub(crate) async fn handle_governance_profile_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    let resource = match family_resource(&PROFILE, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    // Bind the family on its first admission; a successor authorizes the existing binding.
    let genesis = body.get("expected_head").map_or(true, Value::is_null);
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &PROFILE,
        resource,
        PROFILE_REQUEST_FIELDS,
        PROFILE_SERVER_RESOLVED,
        genesis,
        "improvement_governance_profile",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if body.get("system_id").is_some_and(|value| !value.is_null()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &PROFILE.code("system_scope_not_admitted"),
            "a System-scoped governance profile binds through the constitution's protected change path, which this build does not implement; the owner-scoped profile is admitted with system_id null",
        );
    }
    let ordinal = ctx.stream.len() as u64 + 1;
    let revision_ref = format!("{}/revision/{ordinal}", ctx.resource);
    let predecessor = ctx
        .stream
        .last()
        .and_then(|entry| entry.record.get("revision_ref").cloned())
        .unwrap_or(Value::Null);
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": PROFILE.schema_version,
        "improvement_governance_profile_id": ctx.resource,
        "revision_ref": revision_ref,
        "version": body_str(&body, "version"),
        "predecessor_revision_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "system_id": Value::Null,
        "mutable_target_allowlist_refs": strings(&list(&body, "mutable_target_allowlist_refs")),
        "protected_target_refs": strings(&list(&body, "protected_target_refs")),
        "protected_target_change_decision_profile_refs": strings(&list(&body, "protected_target_change_decision_profile_refs")),
        "max_target_improvement_order": body.get("max_target_improvement_order").cloned().unwrap_or(Value::Null),
        "max_active_nested_campaign_depth": body.get("max_active_nested_campaign_depth").cloned().unwrap_or(Value::Null),
        "max_unattended_target_generations": body.get("max_unattended_target_generations").cloned().unwrap_or(Value::Null),
        "ancestor_reservation_policy_refs": body.get("ancestor_reservation_policy_refs").cloned().unwrap_or(Value::Null),
        "campaign_admission_policy_ref": body_str(&body, "campaign_admission_policy_ref"),
        "campaign_stop_policy_ref": body_str(&body, "campaign_stop_policy_ref"),
        "evaluator_firewall_policy_ref": body_str(&body, "evaluator_firewall_policy_ref"),
        "evaluator_independence_policy_ref": body_str(&body, "evaluator_independence_policy_ref"),
        "promotion_authority_policy_ref": body_str(&body, "promotion_authority_policy_ref"),
        "irreversible_effect_recovery_policy_ref": body_str(&body, "irreversible_effect_recovery_policy_ref"),
        "registry_lifecycle_ref": Value::Null,
        "registry_status": "active",
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &PROFILE,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_governance_profile",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_governance_profile_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    let Some(family) = query.family.clone() else {
        return inventory(&st, &headers, &PROFILE, "improvement_governance_profile_refs");
    };
    profile_read(&st, &headers, &family, query.revision)
}

pub(crate) async fn handle_governance_profile_revision_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((family, revision)): Path<(String, u64)>,
) -> Reply {
    profile_read(&st, &headers, &family, Some(revision))
}

fn profile_read(st: &DaemonState, headers: &HeaderMap, family: &str, revision: Option<u64>) -> Reply {
    let resource = match family_resource(&PROFILE, family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (_, stream) = match read_family(st, headers, &PROFILE, &resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    if let Some(ordinal) = revision {
        let wanted = format!("{resource}/revision/{ordinal}");
        let Some(index) = stream
            .iter()
            .position(|entry| text(&entry.record, "revision_ref") == wanted)
        else {
            return bad(
                StatusCode::NOT_FOUND,
                &PROFILE.code("revision_absent"),
                format!("this family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"),
            );
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "resolved": project_profile(&stream, index),
                "admission": stream[index].admission,
                "index_state": index_state,
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "family": resource,
            "revisions": (0..stream.len()).map(|index| project_profile(&stream, index)).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

/// The owner's CURRENT governance profile revision, resolved for campaign admission: the cited
/// revision must exist under the owner and must be the family's newest, because a superseded
/// profile is not the owner's governance any more.
enum ProfileResolution {
    Current(Value),
    Superseded,
    Absent,
}

fn resolve_profile_for_admission(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    revision_ref: &str,
) -> Result<ProfileResolution, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(PROFILE.ref_scheme, revision_ref) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &PROFILE.code("revision_ref_not_canonical"),
            "a campaign binds improvement-governance-profile://<family>/revision/<n>; a family head is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", PROFILE.ref_scheme);
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        identity,
        PROFILE.resource_kind,
        &resource,
        Some(owner_ref),
    ) {
        Ok(scope) => scope,
        Err(_) => return Ok(ProfileResolution::Absent),
    };
    let stream = read_stream(&PROFILE, &st.data_dir, identity, &scope, &resource)?;
    if stream.is_empty() || ordinal > stream.len() as u64 {
        return Ok(ProfileResolution::Absent);
    }
    if ordinal != stream.len() as u64 {
        return Ok(ProfileResolution::Superseded);
    }
    Ok(ProfileResolution::Current(project_profile(&stream, stream.len() - 1)))
}

// ========================================================================================= agendas

const AGENDA_REQUEST_FIELDS: &[&str] = &[
    "family",
    "system_id",
    "constitution_and_policy_refs",
    "governance_policy_refs",
    "target_graph_ref",
    "portfolio_allocation_policy_ref",
    "items",
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
];
const AGENDA_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "improvement_agenda_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "content_hash",
    "release_decision_ref",
    "registry_lifecycle_ref",
    "registry_status",
    "admitted_at",
];
const AGENDA_RELEASE_FIELDS: &[&str] = &[
    "release_decision_ref",
    "owner_ref",
    "idempotency_key",
    "expected_head",
];
/// On release the decision ref is the CALLER's; every other member stays the server's.
const AGENDA_RELEASE_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "improvement_agenda_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "content_hash",
    "registry_lifecycle_ref",
    "registry_status",
    "admitted_at",
];

/// The CURRENT entry of each agenda revision (a release is a successor entry of the same
/// revision), by maximum position on the stream.
fn agenda_revisions(stream: &[AdmittedRecord]) -> Vec<(u64, Value)> {
    let mut current: Vec<(u64, Value)> = Vec::new();
    for entry in stream {
        let Some(revision) = integer(&entry.record, "revision") else {
            continue;
        };
        if let Some(slot) = current.iter_mut().find(|(held, _)| *held == revision) {
            slot.1 = entry.record.clone();
        } else {
            current.push((revision, entry.record.clone()));
        }
    }
    current
}

/// A released revision reads as `superseded` once a later revision of the family is released.
fn project_agendas(stream: &[AdmittedRecord]) -> Vec<Value> {
    let current = agenda_revisions(stream);
    let newest_released = current
        .iter()
        .filter(|(_, record)| text(record, "registry_status") == "released")
        .map(|(revision, _)| *revision)
        .max();
    current
        .into_iter()
        .map(|(revision, mut record)| {
            if text(&record, "registry_status") == "released"
                && newest_released.is_some_and(|newest| newest > revision)
            {
                record["registry_status"] = json!("superseded");
            }
            record
        })
        .collect()
}

pub(crate) async fn handle_agenda_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    let resource = match family_resource(&AGENDA, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let genesis = body.get("expected_head").map_or(true, Value::is_null);
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &AGENDA,
        resource,
        AGENDA_REQUEST_FIELDS,
        AGENDA_SERVER_RESOLVED,
        genesis,
        "improvement_agenda",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if body.get("system_id").is_some_and(|value| !value.is_null()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &AGENDA.code("system_scope_not_admitted"),
            "a System-scoped agenda binds through the constitution, which this build does not implement; the owner-scoped agenda is admitted with system_id null",
        );
    }
    let current = agenda_revisions(&ctx.stream);
    let revision = current.iter().map(|(held, _)| *held).max().unwrap_or(0) + 1;
    if revision > MAX_ORDER {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &AGENDA.code("revision_domain_exhausted"),
            "an agenda family carries at most 1000 revisions",
        );
    }
    let predecessor = current
        .iter()
        .max_by_key(|(held, _)| *held)
        .map(|(_, record)| record.get("revision_ref").cloned().unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": AGENDA.schema_version,
        "improvement_agenda_id": ctx.resource,
        "revision_ref": format!("{}/revision/{revision}", ctx.resource),
        "revision": revision,
        "predecessor_revision_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "system_id": Value::Null,
        "constitution_and_policy_refs": strings(&list(&body, "constitution_and_policy_refs")),
        "governance_policy_refs": strings(&list(&body, "governance_policy_refs")),
        "release_decision_ref": Value::Null,
        "target_graph_ref": body_str(&body, "target_graph_ref"),
        "portfolio_allocation_policy_ref": body_str(&body, "portfolio_allocation_policy_ref"),
        "items": body.get("items").cloned().unwrap_or(Value::Null),
        "registry_lifecycle_ref": Value::Null,
        "registry_status": "draft",
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &AGENDA,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_agenda",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_agenda_release(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((family, revision)): Path<(String, u64)>,
    Json(body): Json<Value>,
) -> Reply {
    let resource = match family_resource(&AGENDA, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &AGENDA,
        resource,
        AGENDA_RELEASE_FIELDS,
        AGENDA_RELEASE_SERVER_RESOLVED,
        false,
        "improvement_agenda",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some((_, prior)) = agenda_revisions(&ctx.stream)
        .into_iter()
        .find(|(held, _)| *held == revision)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            &AGENDA.code("revision_absent"),
            format!("this agenda family has no revision {revision}"),
        );
    };
    if text(&prior, "registry_status") == "released" {
        return bad(
            StatusCode::CONFLICT,
            &AGENDA.code("already_released"),
            "this revision is already released; a release is not repeated",
        );
    }
    let decision = body_str(&body, "release_decision_ref");
    if decision.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &AGENDA.code("release_decision_required"),
            "a release names the decision:// that released it; a status nobody decided is a projection nobody made",
        );
    }
    let recorded_at_ms = now_ms();
    let mut record = prior;
    record["release_decision_ref"] = json!(decision);
    record["registry_status"] = json!("released");
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    finish_admission(
        &AGENDA,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_agenda",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_agenda_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    let Some(family) = query.family.clone() else {
        return inventory(&st, &headers, &AGENDA, "improvement_agenda_refs");
    };
    agenda_read(&st, &headers, &family, query.revision)
}

pub(crate) async fn handle_agenda_revision_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((family, revision)): Path<(String, u64)>,
) -> Reply {
    agenda_read(&st, &headers, &family, Some(revision))
}

fn agenda_read(st: &DaemonState, headers: &HeaderMap, family: &str, revision: Option<u64>) -> Reply {
    let resource = match family_resource(&AGENDA, family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (_, stream) = match read_family(st, headers, &AGENDA, &resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    let projected = project_agendas(&stream);
    if let Some(ordinal) = revision {
        let Some(record) = projected
            .into_iter()
            .find(|record| integer(record, "revision") == Some(ordinal))
        else {
            return bad(
                StatusCode::NOT_FOUND,
                &AGENDA.code("revision_absent"),
                format!("this agenda family has no revision {ordinal}"),
            );
        };
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "resolved": record, "head": stream.last().map(|last| last.head.clone()), "index_state": index_state })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "family": resource,
            "revisions": projected,
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

enum AgendaResolution {
    Released(Value),
    NotReleased,
    Absent,
}

fn resolve_agenda_revision(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    revision_ref: &str,
) -> Result<AgendaResolution, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(AGENDA.ref_scheme, revision_ref) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &AGENDA.code("revision_ref_not_canonical"),
            "a campaign binds improvement-agenda://<family>/revision/<n>; a family head is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", AGENDA.ref_scheme);
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        identity,
        AGENDA.resource_kind,
        &resource,
        Some(owner_ref),
    ) {
        Ok(scope) => scope,
        Err(_) => return Ok(AgendaResolution::Absent),
    };
    let stream = read_stream(&AGENDA, &st.data_dir, identity, &scope, &resource)?;
    let Some(record) = project_agendas(&stream)
        .into_iter()
        .find(|record| integer(record, "revision") == Some(ordinal))
    else {
        return Ok(AgendaResolution::Absent);
    };
    if matches!(text(&record, "registry_status").as_str(), "released" | "superseded") {
        return Ok(AgendaResolution::Released(record));
    }
    Ok(AgendaResolution::NotReleased)
}

// ======================================================================================= campaigns

const CAMPAIGN_CREATE_FIELDS: &[&str] = &[
    "family",
    "system_id",
    "improvement_governance_profile_revision_ref",
    "coordinating_work_subject_ref",
    "coordinating_pursuit",
    "improvement_assurance_profile",
    "resolved_component_snapshot_ref",
    "outcome_room_ref",
    "agenda_revision_ref",
    "agenda_item_refs",
    "campaign_mode",
    "target_class",
    "mutable_target_ref",
    "atomic_target_bundle_ref",
    "protected_boundary_refs",
    "target_improvement_order",
    "target_order_path_ref",
    "base_target_generation_index",
    "parent_execution_campaign_ref",
    "predecessor_target_generation_campaign_ref",
    "source_lower_order_campaign_refs",
    "deployment_incumbent_ref",
    "search_and_candidate_archive_policy_refs",
    "synchronization_policy_ref",
    "ancestor_resource_budget_ledger_ref",
    "ancestor_statistical_risk_budget_ledger_ref",
    "inherited_evaluation_exposure_ledger_refs",
    "learning_boundary_profile_ref",
    "stop_policy_ref",
    "rollback_recall_containment_compensation_and_reconciliation_policy_refs",
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "expected_target_base_root",
];
const CAMPAIGN_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "improvement_campaign_id",
    "campaign_contract_revision_ref",
    "campaign_contract_revision",
    "predecessor_contract_revision_ref",
    "campaign_contract_root",
    "content_hash",
    "effective_governance_snapshot_ref",
    "campaign_admission_receipt_ref",
    "admission_authority_and_constitution_snapshot_refs",
    "target_base_root",
    "deployment_incumbent_root",
    "pursuit_method_order",
    "target_to_pursuit_method_edge_ref",
    "target_order_assignment_receipt_ref",
    "effective_target_order_ceiling",
    "effective_target_order_ceiling_ref",
    "max_active_nested_campaign_depth",
    "effective_learning_policy_hash",
    "operation_head_sequence",
    "operation_head_root",
    "derived_state_projection_ref",
    "lifecycle_status",
    "admitted_at",
];
const CAMPAIGN_ADMIT_FIELDS: &[&str] = &[
    "campaign_admission_decision_ref",
    "owner_ref",
    "idempotency_key",
    "expected_head",
];
const CAMPAIGN_TRANSITION_FIELDS: &[&str] = &["owner_ref", "idempotency_key", "expected_head"];

fn contract_root(record: &Value) -> Result<String, Reply> {
    digest_over(record, CAMPAIGN_CONTRACT_DOMAIN, CAMPAIGN_CONTRACT_FIELDS).map_err(|reason| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CAMPAIGN.code("contract_root_failed"),
            reason,
        )
    })
}

/// A campaign successor: the predecessor's entry with the projections advanced. The contract
/// subset is re-hashed and must equal the predecessor's root, which is what makes a moved
/// contract member `campaign_binding_mismatch` rather than a silent rewrite.
fn campaign_successor(
    prior: &AdmittedRecord,
    sequence: u64,
    mutate: impl FnOnce(&mut Value),
) -> Result<(Value, u64), Reply> {
    let mut record = prior.record.clone();
    mutate(&mut record);
    let root = contract_root(&record)?;
    if root != text(&prior.record, "campaign_contract_root") {
        return Err(bad(
            StatusCode::CONFLICT,
            "campaign_binding_mismatch",
            "this operation would move the campaign's contract root; the contract is frozen at creation and a lifecycle operation advances projections only",
        ));
    }
    record["campaign_contract_root"] = json!(root);
    record["operation_head_sequence"] = json!(sequence);
    let recorded_at_ms = now_ms();
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    let content_hash = CAMPAIGN.content_hash(&record).map_err(|reason| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CAMPAIGN.code("content_hash_failed"),
            reason,
        )
    })?;
    let previous = text(&prior.record, "operation_head_root");
    record["operation_head_root"] = json!(chain_root(
        CAMPAIGN_HEAD_DOMAIN,
        Some(previous.as_str()),
        &content_hash
    )?);
    Ok((record, recorded_at_ms))
}

/// The mutable target's current root, read through the target's OWN owner. Only core-owned
/// families resolve here; a target this module cannot read is a typed refusal, never a copied
/// claim.
fn resolve_target_root(st: &DaemonState, target_ref: &str) -> Result<String, Reply> {
    resolve_core_mutable_target_root(st, target_ref).ok_or_else(|| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "mutable_target_unresolvable",
            format!(
                "'{target_ref}' is not a mutable target this build can read through its owner (skill-entry:// or automation-affinity://); the daemon does not freeze a root it cannot derive"
            ),
        )
    })
}

pub(crate) async fn handle_campaign_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    let resource = match family_resource(&CAMPAIGN, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &CAMPAIGN,
        resource,
        CAMPAIGN_CREATE_FIELDS,
        CAMPAIGN_SERVER_RESOLVED,
        true,
        "improvement_campaign",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if ctx.expected_head.is_some() || !ctx.stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("family_already_exists"),
            "a campaign family is created once; its lifecycle advances through admit, start, pause and stop",
        );
    }
    if body.get("system_id").is_some_and(|value| !value.is_null()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("system_scope_not_admitted"),
            "a System-scoped campaign is admitted under the constitution's protected profile binding, which this build does not implement",
        );
    }
    if body.get("atomic_target_bundle_ref").is_some_and(|value| !value.is_null()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("atomic_bundle_not_admitted"),
            "an atomic target bundle needs one attributable activation owner, one admitted order, declared conflicts and all-or-nothing recovery, none of which this build resolves; name one mutable target",
        );
    }
    let target_ref = body_str(&body, "mutable_target_ref");
    if target_ref.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("mutable_target_required"),
            "a campaign names exactly one mutable target",
        );
    }
    let pursuit = body
        .get("coordinating_pursuit")
        .cloned()
        .unwrap_or_else(|| json!({ "goal_run_profile_revision_ref": Value::Null, "goal_run_profile_resolution_receipt_ref": Value::Null }));
    let pursuit_profile = pursuit
        .get("goal_run_profile_revision_ref")
        .map_or(false, |value| !value.is_null());
    let pursuit_receipt = pursuit
        .get("goal_run_profile_resolution_receipt_ref")
        .map_or(false, |value| !value.is_null());
    if pursuit_profile != pursuit_receipt {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("pursuit_binding_incomplete"),
            "a coordinating pursuit is the goal-orchestration application's own declaration — a GoalRunProfile revision AND its resolution receipt, together or not at all; core records the pair and never resolves it",
        );
    }
    let Some(order) = integer(&body, "target_improvement_order") else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("target_order_required"),
            "target_improvement_order is a bounded integer 0..=1000",
        );
    };
    if order > MAX_ORDER {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("target_order_out_of_domain"),
            "target_improvement_order is a bounded integer 0..=1000",
        );
    }
    let target_root = match resolve_target_root(&st, &target_ref) {
        Ok(root) => root,
        Err(response) => return response,
    };
    if let Some(asserted) = body.get("expected_target_base_root").and_then(Value::as_str) {
        if asserted != target_root {
            return bad(
                StatusCode::CONFLICT,
                "target_base_stale",
                "expected_target_base_root does not equal the mutable target's current root; re-read the target and re-derive the contract",
            );
        }
    }
    let incumbent_ref = {
        let declared = body_str(&body, "deployment_incumbent_ref");
        if declared.is_empty() {
            target_ref.clone()
        } else {
            declared
        }
    };
    let incumbent_root = if incumbent_ref == target_ref {
        target_root.clone()
    } else {
        match resolve_target_root(&st, &incumbent_ref) {
            Ok(root) => root,
            Err(response) => return response,
        }
    };
    let boundary = match resolve_admitted_boundary_profile(
        &st.data_dir,
        &ctx.caller.identity,
        Some(ctx.caller.owner_ref.as_str()),
        &body_str(&body, "learning_boundary_profile_ref"),
    ) {
        Ok(boundary) => boundary,
        Err(response) => return response,
    };
    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": CAMPAIGN.schema_version,
        "improvement_campaign_id": ctx.resource,
        "campaign_contract_revision_ref": format!("{}/revision/1", ctx.resource),
        "campaign_contract_revision": 1,
        "predecessor_contract_revision_ref": Value::Null,
        "owner_ref": ctx.caller.owner_ref,
        "system_id": Value::Null,
        "improvement_governance_profile_revision_ref": body_str(&body, "improvement_governance_profile_revision_ref"),
        "effective_governance_snapshot_ref": Value::Null,
        "campaign_admission_decision_ref": Value::Null,
        "campaign_admission_receipt_ref": Value::Null,
        "admission_authority_and_constitution_snapshot_refs": [],
        "coordinating_work_subject_ref": body.get("coordinating_work_subject_ref").cloned().unwrap_or(Value::Null),
        "child_work_subject_refs": [],
        "coordinating_pursuit": pursuit,
        "improvement_assurance_profile": body_str(&body, "improvement_assurance_profile"),
        "resolved_component_snapshot_ref": body_str(&body, "resolved_component_snapshot_ref"),
        "outcome_room_ref": body.get("outcome_room_ref").cloned().unwrap_or(Value::Null),
        "agenda_revision_ref": body_str(&body, "agenda_revision_ref"),
        "agenda_item_refs": strings(&list(&body, "agenda_item_refs")),
        "campaign_mode": body_str(&body, "campaign_mode"),
        "target_class": body_str(&body, "target_class"),
        "mutable_target_ref": target_ref,
        "atomic_target_bundle_ref": Value::Null,
        "target_base_root": target_root,
        "protected_boundary_refs": strings(&list(&body, "protected_boundary_refs")),
        "target_improvement_order": order,
        "pursuit_method_order": order + 1,
        "target_to_pursuit_method_edge_ref": format!("artifact://improvement-campaign/{family}/target-order-edge/{order}-{}", order + 1),
        "target_order_path_ref": body_str(&body, "target_order_path_ref"),
        "target_order_assignment_receipt_ref": Value::Null,
        "base_target_generation_index": body.get("base_target_generation_index").cloned().unwrap_or(json!(0)),
        "effective_target_order_ceiling": Value::Null,
        "effective_target_order_ceiling_ref": Value::Null,
        "max_active_nested_campaign_depth": Value::Null,
        "parent_execution_campaign_ref": body.get("parent_execution_campaign_ref").cloned().unwrap_or(Value::Null),
        "predecessor_target_generation_campaign_ref": body.get("predecessor_target_generation_campaign_ref").cloned().unwrap_or(Value::Null),
        "source_lower_order_campaign_refs": strings(&list(&body, "source_lower_order_campaign_refs")),
        "deployment_incumbent_ref": incumbent_ref,
        "deployment_incumbent_root": incumbent_root,
        "candidate_archive_ref": Value::Null,
        "candidate_resolved_component_snapshot_refs": [],
        "active_evaluation_epoch_ref": Value::Null,
        "historical_evaluation_epoch_refs": [],
        "search_and_candidate_archive_policy_refs": strings(&list(&body, "search_and_candidate_archive_policy_refs")),
        "synchronization_policy_ref": body_str(&body, "synchronization_policy_ref"),
        "improvement_order_cutoff_receipt_refs": [],
        "ancestor_resource_budget_ledger_ref": body_str(&body, "ancestor_resource_budget_ledger_ref"),
        "resource_reservation_refs": [],
        "ancestor_statistical_risk_budget_ledger_ref": body_str(&body, "ancestor_statistical_risk_budget_ledger_ref"),
        "statistical_risk_reservation_refs": [],
        "inherited_evaluation_exposure_ledger_refs": strings(&list(&body, "inherited_evaluation_exposure_ledger_refs")),
        "evaluation_exposure_reservation_refs": [],
        "learning_boundary_profile_ref": boundary.revision_ref,
        "effective_learning_policy_hash": boundary.compiled_policy_hash,
        "stop_policy_ref": body_str(&body, "stop_policy_ref"),
        "rollback_recall_containment_compensation_and_reconciliation_policy_refs": strings(&list(&body, "rollback_recall_containment_compensation_and_reconciliation_policy_refs")),
        "operation_head_sequence": 1,
        "derived_state_projection_ref": format!("agentgres://projection/improvement-campaign/{family}"),
        "lifecycle_status": "proposed",
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let root = match contract_root(&record) {
        Ok(root) => root,
        Err(response) => return response,
    };
    record["campaign_contract_root"] = json!(root);
    let content_hash = match CAMPAIGN.content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CAMPAIGN.code("content_hash_failed"),
                reason,
            )
        }
    };
    record["operation_head_root"] = match chain_root(CAMPAIGN_HEAD_DOMAIN, None, &content_hash) {
        Ok(head) => json!(head),
        Err(response) => return response,
    };
    finish_admission(
        &CAMPAIGN,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_campaign",
        record,
        None,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

/// The nesting depth of a campaign counted through its parent chain, or a typed refusal when a
/// parent does not resolve under the owner. A root campaign has depth 1.
fn nesting_depth(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    parent_ref: &str,
) -> Result<u64, Reply> {
    let mut depth = 1u64;
    let mut cursor = parent_ref.to_string();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    while !cursor.is_empty() {
        if !seen.insert(cursor.clone()) || depth > MAX_ORDER {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &CAMPAIGN.code("parent_chain_cyclic"),
                "the parent campaign chain does not terminate",
            ));
        }
        let scope = authorize_request_resource_scope(
            &st.data_dir,
            identity,
            CAMPAIGN.resource_kind,
            &cursor,
            Some(owner_ref),
        )
        .map_err(|_| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &CAMPAIGN.code("parent_unresolvable"),
                format!("parent campaign '{cursor}' does not resolve under this owner"),
            )
        })?;
        let stream = read_stream(&CAMPAIGN, &st.data_dir, identity, &scope, &cursor)?;
        let Some(parent) = stream.last() else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &CAMPAIGN.code("parent_unresolvable"),
                format!("parent campaign '{cursor}' has no admitted contract"),
            ));
        };
        depth += 1;
        cursor = text(&parent.record, "parent_execution_campaign_ref");
    }
    Ok(depth)
}

pub(crate) async fn handle_campaign_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let resource = match family_resource(&CAMPAIGN, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &CAMPAIGN,
        resource,
        CAMPAIGN_ADMIT_FIELDS,
        CAMPAIGN_SERVER_RESOLVED,
        false,
        "improvement_campaign",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some(prior) = ctx.stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CAMPAIGN.code("absent"),
            "no campaign answers to that family",
        );
    };
    if text(&prior.record, "lifecycle_status") != "proposed" {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("lifecycle_invalid"),
            format!(
                "admission requires a proposed campaign; this one is {}",
                text(&prior.record, "lifecycle_status")
            ),
        );
    }
    let decision = body_str(&body, "campaign_admission_decision_ref");
    if decision.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("admission_decision_required"),
            "admission names the decision:// that admitted it; a runnable campaign nobody admitted is the campaign-truth-from-a-claim canon forbids",
        );
    }
    let identity = &ctx.caller.identity;
    let owner_ref = ctx.caller.owner_ref.as_str();

    // -- the owner's CURRENT governance --------------------------------------------------------
    let profile_ref = text(&prior.record, "improvement_governance_profile_revision_ref");
    let profile = match resolve_profile_for_admission(&st, identity, owner_ref, &profile_ref) {
        Ok(ProfileResolution::Current(profile)) => profile,
        Ok(ProfileResolution::Superseded) => {
            return bad(
                StatusCode::CONFLICT,
                "campaign_binding_mismatch",
                "the cited governance profile revision is superseded; a campaign is admitted under the owner's CURRENT governance, never a profile that is no longer it",
            )
        }
        Ok(ProfileResolution::Absent) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "improvement_governance_profile_required",
                "no governance profile revision resolves under this owner; a null profile disables campaign admission",
            )
        }
        Err(response) => return response,
    };
    let target_ref = text(&prior.record, "mutable_target_ref");
    if list(&profile, "protected_target_refs").contains(&target_ref) {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("target_protected"),
            "the governance profile protects this target; a protected target changes only through its declared decision profile",
        );
    }
    let allowlist = list(&profile, "mutable_target_allowlist_refs");
    if !allowlist.is_empty() && !allowlist.contains(&target_ref) {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("target_protected"),
            "the governance profile's mutable-target allowlist does not name this target",
        );
    }
    let order = integer(&prior.record, "target_improvement_order").unwrap_or(0);
    let ceiling = integer(&profile, "max_target_improvement_order").unwrap_or(0);
    if order > ceiling {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("order_ceiling_exceeded"),
            format!("target order {order} exceeds the profile's ceiling {ceiling}"),
        );
    }
    let max_depth = integer(&profile, "max_active_nested_campaign_depth").unwrap_or(1);
    let parent = text(&prior.record, "parent_execution_campaign_ref");
    if !parent.is_empty() {
        let depth = match nesting_depth(&st, identity, owner_ref, &parent) {
            Ok(depth) => depth,
            Err(response) => return response,
        };
        if depth > max_depth {
            return bad(
                StatusCode::CONFLICT,
                &CAMPAIGN.code("nesting_depth_exceeded"),
                format!("nesting depth {depth} exceeds the profile's ceiling {max_depth}"),
            );
        }
    }

    // -- the RELEASED agenda and its items ------------------------------------------------------
    let agenda_ref = text(&prior.record, "agenda_revision_ref");
    let agenda = match resolve_agenda_revision(&st, identity, owner_ref, &agenda_ref) {
        Ok(AgendaResolution::Released(agenda)) => agenda,
        Ok(AgendaResolution::NotReleased) => {
            return bad(
                StatusCode::CONFLICT,
                &AGENDA.code("revision_not_released"),
                "only a released agenda revision is campaign-admission eligible",
            )
        }
        Ok(AgendaResolution::Absent) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &AGENDA.code("revision_absent"),
                "the cited agenda revision does not resolve under this owner",
            )
        }
        Err(response) => return response,
    };
    let item_ids: BTreeSet<String> = agenda
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(|item| text(item, "agenda_item_id")).collect())
        .unwrap_or_default();
    for item in list(&prior.record, "agenda_item_refs") {
        if !item_ids.contains(&item) {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &AGENDA.code("item_unknown"),
                format!("agenda item '{item}' is not an item of the cited revision"),
            );
        }
    }

    // -- recovery posture, and the target has not moved -------------------------------------------
    if list(
        &prior.record,
        "rollback_recall_containment_compensation_and_reconciliation_policy_refs",
    )
    .is_empty()
    {
        return bad(
            StatusCode::CONFLICT,
            "effect_recovery_posture_missing",
            "admission freezes the rollback, recall, containment, compensation and reconciliation posture; a campaign with none bound cannot be admitted",
        );
    }
    let current_root = match resolve_target_root(&st, &target_ref) {
        Ok(root) => root,
        Err(response) => return response,
    };
    if current_root != text(&prior.record, "target_base_root") {
        return bad(
            StatusCode::CONFLICT,
            "target_base_stale",
            "the mutable target changed since the contract froze its root; a stale base fails admission and needs a new campaign contract",
        );
    }

    let profile_hash = text(&profile, "content_hash");
    let campaign_root = text(&prior.record, "campaign_contract_root");
    let receipt_material = json!({ "campaign_contract_root": campaign_root, "decision_ref": decision });
    let receipt_digest = match digest_over(
        &receipt_material,
        ADMISSION_RECEIPT_DOMAIN,
        &["campaign_contract_root", "decision_ref"],
    ) {
        Ok(digest) => digest,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CAMPAIGN.code("admission_receipt_failed"),
                reason,
            )
        }
    };
    let order_material = json!({ "campaign_contract_root": campaign_root, "target_improvement_order": order });
    let order_digest = match digest_over(
        &order_material,
        ADMISSION_RECEIPT_DOMAIN,
        &["campaign_contract_root", "target_improvement_order"],
    ) {
        Ok(digest) => digest,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CAMPAIGN.code("admission_receipt_failed"),
                reason,
            )
        }
    };
    let boundary_ref = text(&prior.record, "learning_boundary_profile_ref");
    let admission_policy = text(&profile, "campaign_admission_policy_ref");
    let sequence = ctx.stream.len() as u64 + 1;
    let (record, recorded_at_ms) = match campaign_successor(prior, sequence, |record| {
        record["effective_governance_snapshot_ref"] = json!(format!("artifact://improvement-governance-profile/{}/{profile_hash}", profile_ref.trim_start_matches(PROFILE.ref_scheme)));
        record["campaign_admission_decision_ref"] = json!(decision);
        record["campaign_admission_receipt_ref"] = json!(format!("receipt://improvement-campaign/{family}/admission/{receipt_digest}"));
        record["admission_authority_and_constitution_snapshot_refs"] = json!([profile_ref, agenda_ref, boundary_ref]);
        record["target_order_assignment_receipt_ref"] = json!(format!("receipt://improvement-campaign/{family}/target-order/{order_digest}"));
        record["effective_target_order_ceiling"] = json!(ceiling);
        record["effective_target_order_ceiling_ref"] = json!(admission_policy);
        record["max_active_nested_campaign_depth"] = json!(max_depth);
        record["lifecycle_status"] = json!("admitted");
    }) {
        Ok(next) => next,
        Err(response) => return response,
    };
    finish_admission(
        &CAMPAIGN,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_campaign",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

async fn campaign_transition(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    family: String,
    body: Value,
    from: &[&str],
    to: &str,
) -> Reply {
    let resource = match family_resource(&CAMPAIGN, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &CAMPAIGN,
        resource,
        CAMPAIGN_TRANSITION_FIELDS,
        CAMPAIGN_SERVER_RESOLVED,
        false,
        "improvement_campaign",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some(prior) = ctx.stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CAMPAIGN.code("absent"),
            "no campaign answers to that family",
        );
    };
    let status = text(&prior.record, "lifecycle_status");
    if !from.contains(&status.as_str()) {
        return bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("lifecycle_invalid"),
            format!("'{to}' requires one of {from:?}; this campaign is {status}"),
        );
    }
    let sequence = ctx.stream.len() as u64 + 1;
    let (record, recorded_at_ms) = match campaign_successor(prior, sequence, |record| {
        record["lifecycle_status"] = json!(to);
    }) {
        Ok(next) => next,
        Err(response) => return response,
    };
    finish_admission(
        &CAMPAIGN,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_campaign",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_campaign_start(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    campaign_transition(st, headers, family, body, &["admitted", "paused"], "active").await
}

pub(crate) async fn handle_campaign_pause(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    campaign_transition(st, headers, family, body, &["active"], "paused").await
}

pub(crate) async fn handle_campaign_stop(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    campaign_transition(st, headers, family, body, &["admitted", "active", "paused"], "stopped").await
}

/// The campaign's epochs, DERIVED from the epoch streams the caller may read rather than kept as a
/// second pointer on the campaign: a rebuildable projection, reproduced identically after a restart.
fn campaign_epochs(
    st: &DaemonState,
    identity: &RequestIdentity,
    campaign_ref: &str,
) -> Result<Vec<Value>, Reply> {
    let refs = authorized_request_resource_refs(&st.data_dir, identity, EPOCH.resource_kind)
        .map_err(scope_refusal_reply)?;
    let mut epochs = Vec::new();
    for epoch_ref in refs {
        let stream = authorized_stream(&EPOCH, &st.data_dir, identity, &epoch_ref)?;
        if let Some(entry) = stream.last() {
            if text(&entry.record, "campaign_ref") == campaign_ref {
                epochs.push(entry.record.clone());
            }
        }
    }
    epochs.sort_by(|a, b| text(a, "evaluation_epoch_id").cmp(&text(b, "evaluation_epoch_id")));
    Ok(epochs)
}

fn derived_state(
    st: &DaemonState,
    identity: &RequestIdentity,
    campaign_ref: &str,
) -> Result<Value, Reply> {
    let epochs = campaign_epochs(st, identity, campaign_ref)?;
    let active: Vec<String> = epochs
        .iter()
        .filter(|epoch| text(epoch, "lifecycle_status") == "active")
        .map(|epoch| text(epoch, "evaluation_epoch_id"))
        .collect();
    let cutoff_resource = format!(
        "{}{}",
        CUTOFF.ref_scheme,
        campaign_ref.trim_start_matches(CAMPAIGN.ref_scheme)
    );
    let cutoffs = match authorize_request_resource_scope(
        &st.data_dir,
        identity,
        CUTOFF.resource_kind,
        &cutoff_resource,
        None,
    ) {
        Ok(scope) => read_stream(&CUTOFF, &st.data_dir, identity, &scope, &cutoff_resource)?
            .iter()
            .map(|entry| text(&entry.record, "receipt_id"))
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    Ok(json!({
        "rebuilt_from": "the epoch and cutoff streams under the caller's identity",
        "active_evaluation_epoch_ref": active.first().cloned(),
        "epochs": epochs.iter().map(|epoch| json!({
            "evaluation_epoch_id": text(epoch, "evaluation_epoch_id"),
            "lifecycle_status": text(epoch, "lifecycle_status"),
        })).collect::<Vec<_>>(),
        "improvement_order_cutoff_receipt_refs": cutoffs,
    }))
}

pub(crate) async fn handle_campaign_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    let Some(family) = query.family.clone() else {
        return inventory(&st, &headers, &CAMPAIGN, "improvement_campaign_refs");
    };
    campaign_read(&st, &headers, &family)
}

pub(crate) async fn handle_campaign_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    campaign_read(&st, &headers, &family)
}

fn campaign_read(st: &DaemonState, headers: &HeaderMap, family: &str) -> Reply {
    let resource = match family_resource(&CAMPAIGN, family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (identity, stream) = match read_family(st, headers, &CAMPAIGN, &resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let Some(current) = stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &CAMPAIGN.code("absent"),
            "no campaign answers to that family",
        );
    };
    let derived = match derived_state(st, &identity, &resource) {
        Ok(derived) => derived,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "improvement_campaign": current.record,
            "admission": current.admission,
            "operations": stream.iter().map(|entry| json!({
                "operation_head_sequence": entry.record.get("operation_head_sequence"),
                "lifecycle_status": entry.record.get("lifecycle_status"),
                "operation_head_root": entry.record.get("operation_head_root"),
                "content_hash": entry.record.get("content_hash"),
            })).collect::<Vec<_>>(),
            "derived_state": derived,
            "head": current.head,
            "index_state": projection_cache_state(&resource, &stream),
        })),
    )
}

/// The campaign's current entry under the caller, for a plane operation that requires it active.
fn require_active_campaign(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    campaign_ref: &str,
) -> Result<AdmittedRecord, Reply> {
    let scope = authorize_request_resource_scope(
        &st.data_dir,
        identity,
        CAMPAIGN.resource_kind,
        campaign_ref,
        Some(owner_ref),
    )
    .map_err(|_| {
        bad(
            StatusCode::NOT_FOUND,
            &CAMPAIGN.code("absent"),
            "no campaign answers to that family under this owner",
        )
    })?;
    let stream = read_stream(&CAMPAIGN, &st.data_dir, identity, &scope, campaign_ref)?;
    let Some(current) = stream.into_iter().last() else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &CAMPAIGN.code("absent"),
            "no campaign answers to that family",
        ));
    };
    if text(&current.record, "lifecycle_status") != "active" {
        return Err(bad(
            StatusCode::CONFLICT,
            &CAMPAIGN.code("not_active"),
            format!(
                "this operation needs an active campaign; the campaign is {}",
                text(&current.record, "lifecycle_status")
            ),
        ));
    }
    Ok(current)
}

// ========================================================================================== epochs

const EPOCH_CREATE_FIELDS: &[&str] = &[
    "family",
    "target_graph_and_order_path_roots",
    "visible_eval_refs",
    "sealed_holdout_commitment_refs",
    "transfer_ood_and_adversarial_eval_refs",
    "recursive_seat_and_metaproductivity_metric_refs",
    "cross_play_and_causal_ablation_policy_ref",
    "transfer_non_regression_and_hard_constraint_gate_refs",
    "metric_and_selection_policy_ref",
    "cost_normalization_ref",
    "confirmatory_estimand_and_minimum_effect_refs",
    "statistical_test_and_winner_adjustment_refs",
    "risk_wealth_allocation_ref",
    "power_and_inconclusive_stop_policy_ref",
    "campaign_false_promotion_budget_ref",
    "sealed_feedback_release_and_exposure_spend_policy_refs",
    "evaluation_exposure_budget_policy_ref",
    "evaluation_exposure_budget_units",
    "evaluator_version_and_affiliation_refs",
    "holdout_custodian_refs",
    "external_reality_anchor_refs",
    "operational_acceptance_owner_refs",
    "leakage_rotation_and_challenge_policy_refs",
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
];
const EPOCH_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluation_epoch_id",
    "campaign_ref",
    "campaign_contract_revision_ref",
    "campaign_contract_root",
    "predecessor_epoch_ref",
    "pursuit_goal_run_profile_revision_ref",
    "pursuit_profile_resolution_and_component_snapshot_refs",
    "target_improvement_order",
    "pursuit_method_order",
    "base_target_generation_index",
    "deployment_incumbent_ref",
    "deployment_incumbent_root",
    "synchronization_cutoff_receipt_ref",
    "ancestor_statistical_risk_budget_ledger_ref",
    "inherited_evaluation_exposure_ledger_refs",
    "frozen_root",
    "lifecycle_ref",
    "lifecycle_status",
    "content_hash",
    "admitted_at",
];
const EPOCH_TRANSITION_FIELDS: &[&str] = &["owner_ref", "idempotency_key", "expected_head"];
const EPOCH_CHALLENGE_FIELDS: &[&str] = &[
    "challenge_evidence_refs",
    "owner_ref",
    "idempotency_key",
    "expected_head",
];

fn frozen_root(record: &Value) -> Result<String, Reply> {
    digest_over(record, EPOCH_FROZEN_DOMAIN, EPOCH_FROZEN_FIELDS).map_err(|reason| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &EPOCH.code("frozen_root_failed"),
            reason,
        )
    })
}

pub(crate) async fn handle_epoch_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(campaign_family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let campaign_ref = match family_resource(&CAMPAIGN, &campaign_family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let family = body_str(&body, "family");
    let resource = match family_resource(&EPOCH, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &EPOCH,
        resource,
        EPOCH_CREATE_FIELDS,
        EPOCH_SERVER_RESOLVED,
        true,
        "evaluation_epoch",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if ctx.expected_head.is_some() || !ctx.stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &EPOCH.code("family_already_exists"),
            "an epoch family is created once; its lifecycle advances through freeze, activate, challenge, close and invalidate",
        );
    }
    let campaign = match require_active_campaign(
        &st,
        &ctx.caller.identity,
        &ctx.caller.owner_ref,
        &campaign_ref,
    ) {
        Ok(campaign) => campaign,
        Err(response) => return response,
    };
    let Some(budget) = integer(&body, "evaluation_exposure_budget_units") else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EPOCH.code("exposure_budget_required"),
            "evaluation_exposure_budget_units is a bounded integer 0..=1000000000, the sealed-evaluation exposure the epoch's ledger may reserve",
        );
    };
    if budget > MAX_UNITS {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EPOCH.code("exposure_budget_out_of_domain"),
            "evaluation_exposure_budget_units is a bounded integer 0..=1000000000",
        );
    }
    let siblings = match campaign_epochs(&st, &ctx.caller.identity, &campaign_ref) {
        Ok(epochs) => epochs,
        Err(response) => return response,
    };
    let predecessor = siblings
        .last()
        .map(|epoch| epoch.get("evaluation_epoch_id").cloned().unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let derived = match derived_state(&st, &ctx.caller.identity, &campaign_ref) {
        Ok(derived) => derived,
        Err(response) => return response,
    };
    let latest_cutoff = derived
        .get("improvement_order_cutoff_receipt_refs")
        .and_then(Value::as_array)
        .and_then(|refs| refs.last().cloned())
        .unwrap_or(Value::Null);
    let c = &campaign.record;
    let pursuit = c.get("coordinating_pursuit").cloned().unwrap_or(Value::Null);
    let mut snapshot_refs = vec![text(c, "resolved_component_snapshot_ref")];
    if let Some(receipt) = pursuit
        .get("goal_run_profile_resolution_receipt_ref")
        .and_then(Value::as_str)
    {
        snapshot_refs.push(receipt.to_string());
    }
    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": EPOCH.schema_version,
        "evaluation_epoch_id": ctx.resource,
        "campaign_ref": campaign_ref,
        "campaign_contract_revision_ref": text(c, "campaign_contract_revision_ref"),
        "campaign_contract_root": text(c, "campaign_contract_root"),
        "predecessor_epoch_ref": predecessor,
        "pursuit_goal_run_profile_revision_ref": pursuit.get("goal_run_profile_revision_ref").cloned().unwrap_or(Value::Null),
        "pursuit_profile_resolution_and_component_snapshot_refs": strings(&snapshot_refs),
        "target_improvement_order": integer(c, "target_improvement_order").unwrap_or(0),
        "pursuit_method_order": integer(c, "pursuit_method_order").unwrap_or(1),
        "base_target_generation_index": integer(c, "base_target_generation_index").unwrap_or(0),
        "target_graph_and_order_path_roots": strings(&list(&body, "target_graph_and_order_path_roots")),
        "deployment_incumbent_ref": text(c, "deployment_incumbent_ref"),
        "deployment_incumbent_root": text(c, "deployment_incumbent_root"),
        "synchronization_cutoff_receipt_ref": latest_cutoff,
        "visible_eval_refs": strings(&list(&body, "visible_eval_refs")),
        "sealed_holdout_commitment_refs": strings(&list(&body, "sealed_holdout_commitment_refs")),
        "transfer_ood_and_adversarial_eval_refs": strings(&list(&body, "transfer_ood_and_adversarial_eval_refs")),
        "recursive_seat_and_metaproductivity_metric_refs": strings(&list(&body, "recursive_seat_and_metaproductivity_metric_refs")),
        "cross_play_and_causal_ablation_policy_ref": body_str(&body, "cross_play_and_causal_ablation_policy_ref"),
        "transfer_non_regression_and_hard_constraint_gate_refs": strings(&list(&body, "transfer_non_regression_and_hard_constraint_gate_refs")),
        "metric_and_selection_policy_ref": body_str(&body, "metric_and_selection_policy_ref"),
        "cost_normalization_ref": body_str(&body, "cost_normalization_ref"),
        "confirmatory_estimand_and_minimum_effect_refs": strings(&list(&body, "confirmatory_estimand_and_minimum_effect_refs")),
        "statistical_test_and_winner_adjustment_refs": strings(&list(&body, "statistical_test_and_winner_adjustment_refs")),
        "risk_wealth_allocation_ref": body_str(&body, "risk_wealth_allocation_ref"),
        "power_and_inconclusive_stop_policy_ref": body_str(&body, "power_and_inconclusive_stop_policy_ref"),
        "campaign_false_promotion_budget_ref": body_str(&body, "campaign_false_promotion_budget_ref"),
        "ancestor_statistical_risk_budget_ledger_ref": text(c, "ancestor_statistical_risk_budget_ledger_ref"),
        "inherited_evaluation_exposure_ledger_refs": c.get("inherited_evaluation_exposure_ledger_refs").cloned().unwrap_or(json!([])),
        "sealed_feedback_release_and_exposure_spend_policy_refs": strings(&list(&body, "sealed_feedback_release_and_exposure_spend_policy_refs")),
        "evaluation_exposure_budget_policy_ref": body_str(&body, "evaluation_exposure_budget_policy_ref"),
        "evaluation_exposure_budget_units": budget,
        "evaluator_version_and_affiliation_refs": strings(&list(&body, "evaluator_version_and_affiliation_refs")),
        "holdout_custodian_refs": strings(&list(&body, "holdout_custodian_refs")),
        "external_reality_anchor_refs": strings(&list(&body, "external_reality_anchor_refs")),
        "operational_acceptance_owner_refs": strings(&list(&body, "operational_acceptance_owner_refs")),
        "leakage_rotation_and_challenge_policy_refs": strings(&list(&body, "leakage_rotation_and_challenge_policy_refs")),
        "lifecycle_ref": Value::Null,
        "lifecycle_status": "draft",
        "challenge_evidence_refs": [],
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    record["frozen_root"] = match frozen_root(&record) {
        Ok(root) => json!(root),
        Err(response) => return response,
    };
    finish_admission(
        &EPOCH,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_epoch",
        record,
        None,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

/// An epoch successor: the same frozen contract with the lifecycle projections advanced. From
/// `freeze` onward the frozen root is BINDING, so a moved frozen member is refused rather than
/// re-hashed.
fn epoch_successor(
    prior: &AdmittedRecord,
    mutate: impl FnOnce(&mut Value),
) -> Result<(Value, u64), Reply> {
    let mut record = prior.record.clone();
    mutate(&mut record);
    let root = frozen_root(&record)?;
    if text(&prior.record, "lifecycle_status") != "draft" && root != text(&prior.record, "frozen_root") {
        return Err(bad(
            StatusCode::CONFLICT,
            "campaign_binding_mismatch",
            "this operation would move the epoch's frozen root; a frozen epoch admits lifecycle projections only, and a changed evaluator or metric is a successor epoch",
        ));
    }
    record["frozen_root"] = json!(root);
    let recorded_at_ms = now_ms();
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    Ok((record, recorded_at_ms))
}

/// Where an epoch operation requires an epoch that can still be used: a draft answers
/// `evaluation_epoch_not_frozen`; a challenged, closed or invalidated epoch answers
/// `evaluation_epoch_invalid`.
fn require_usable_epoch(record: &Value, require_active: bool) -> Result<(), Reply> {
    match text(record, "lifecycle_status").as_str() {
        "draft" => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "this operation needs a frozen epoch; freeze commits the evaluator contract before any confirmatory access",
        )),
        "frozen" if require_active => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "this operation needs the campaign's ACTIVE frozen epoch; this epoch is frozen but not active",
        )),
        "frozen" | "active" => Ok(()),
        other => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_invalid",
            format!("this epoch is {other}; a challenged, closed or invalidated epoch admits no exposure, nomination or promotion"),
        )),
    }
}

async fn epoch_transition(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    family: String,
    body: Value,
    verb: &'static str,
) -> Reply {
    let resource = match family_resource(&EPOCH, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let allowed = if verb == "challenge" {
        EPOCH_CHALLENGE_FIELDS
    } else {
        EPOCH_TRANSITION_FIELDS
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &EPOCH,
        resource,
        allowed,
        EPOCH_SERVER_RESOLVED,
        false,
        "evaluation_epoch",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some(prior) = ctx.stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &EPOCH.code("absent"),
            "no epoch answers to that family",
        );
    };
    let status = text(&prior.record, "lifecycle_status");
    let (from, to): (&[&str], &str) = match verb {
        "freeze" => (&["draft"], "frozen"),
        "activate" => (&["frozen"], "active"),
        "challenge" => (&["active"], "challenged"),
        "close" => (&["active", "challenged"], "closed"),
        _ => (&["frozen", "active", "challenged"], "invalidated"),
    };
    if !from.contains(&status.as_str()) {
        // Name the CANON code where canon names one, the lifecycle code otherwise.
        let (code, message) = match (verb, status.as_str()) {
            ("activate", "draft") => (
                "evaluation_epoch_not_frozen".to_string(),
                "an epoch activates only after freeze commits its evaluator contract".to_string(),
            ),
            (_, "closed" | "invalidated") => (
                "evaluation_epoch_invalid".to_string(),
                format!("this epoch is {status} and admits no further lifecycle operation"),
            ),
            _ => (
                EPOCH.code("lifecycle_invalid"),
                format!("'{verb}' requires one of {from:?}; this epoch is {status}"),
            ),
        };
        return bad(StatusCode::CONFLICT, &code, message);
    }
    let campaign_ref = text(&prior.record, "campaign_ref");
    let mut evidence: Vec<String> = Vec::new();
    if verb == "challenge" {
        evidence = list(&body, "challenge_evidence_refs");
        if evidence.is_empty() {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &EPOCH.code("challenge_evidence_required"),
                "a challenge appends linked evidence; a challenge with none would be a status somebody asserted",
            );
        }
    }
    if verb == "activate" {
        let siblings = match campaign_epochs(&st, &ctx.caller.identity, &campaign_ref) {
            Ok(epochs) => epochs,
            Err(response) => return response,
        };
        if siblings
            .iter()
            .any(|epoch| text(epoch, "lifecycle_status") == "active")
        {
            return bad(
                StatusCode::CONFLICT,
                &EPOCH.code("already_active"),
                "a campaign references exactly one active frozen epoch; close or invalidate the active one first",
            );
        }
        if let Err(response) = require_active_campaign(
            &st,
            &ctx.caller.identity,
            &ctx.caller.owner_ref,
            &campaign_ref,
        ) {
            return response;
        }
    }
    let (record, recorded_at_ms) = match epoch_successor(prior, |record| {
        record["lifecycle_status"] = json!(to);
        if verb == "challenge" {
            let mut held = list(record, "challenge_evidence_refs");
            for item in &evidence {
                if !held.contains(item) {
                    held.push(item.clone());
                }
            }
            record["challenge_evidence_refs"] = strings(&held);
        }
    }) {
        Ok(next) => next,
        Err(response) => return response,
    };
    let reply = finish_admission(
        &EPOCH,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_epoch",
        record.clone(),
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    );
    if verb == "freeze" && reply.0 == StatusCode::CREATED {
        // Freeze creates the epoch's ledger. The write is idempotent under a derived key and the
        // exposure routes re-ensure it, so a failure here heals rather than strands the epoch.
        if let Err(response) = ensure_ledger(&st, &ctx.caller, &family, &record) {
            return response;
        }
    }
    reply
}

pub(crate) async fn handle_epoch_freeze(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    epoch_transition(st, headers, family, body, "freeze").await
}

pub(crate) async fn handle_epoch_activate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    epoch_transition(st, headers, family, body, "activate").await
}

pub(crate) async fn handle_epoch_challenge(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    epoch_transition(st, headers, family, body, "challenge").await
}

pub(crate) async fn handle_epoch_close(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    epoch_transition(st, headers, family, body, "close").await
}

pub(crate) async fn handle_epoch_invalidate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    epoch_transition(st, headers, family, body, "invalidate").await
}

pub(crate) async fn handle_epoch_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&EPOCH, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (identity, stream) = match read_family(&st, &headers, &EPOCH, &resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let Some(current) = stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &EPOCH.code("absent"),
            "no epoch answers to that family",
        );
    };
    let ledger_resource = format!("{}{family}", LEDGER.ref_scheme);
    let ledger = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        LEDGER.resource_kind,
        &ledger_resource,
        None,
    ) {
        Ok(scope) => match read_stream(&LEDGER, &st.data_dir, &identity, &scope, &ledger_resource) {
            Ok(stream) => stream.last().map(|entry| entry.record.clone()),
            Err(response) => return response,
        },
        Err(_) => None,
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "evaluation_epoch": current.record,
            "admission": current.admission,
            "lifecycle": stream.iter().map(|entry| json!({
                "lifecycle_status": entry.record.get("lifecycle_status"),
                "frozen_root": entry.record.get("frozen_root"),
                "content_hash": entry.record.get("content_hash"),
            })).collect::<Vec<_>>(),
            "exposure_ledger": ledger,
            "head": current.head,
            "index_state": projection_cache_state(&resource, &stream),
        })),
    )
}

// ================================================================================ exposure ledgers

const EXPOSURE_REQUEST_FIELDS: &[&str] = &[
    "units",
    "candidate_family_commitment",
    "selected_case_commitment",
    "information_return_class",
    "evaluator_version_refs",
    "access_receipt_refs",
    "contamination_flag",
    "owner_ref",
    "idempotency_key",
    "expected_head",
];
const LEDGER_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluation_exposure_ledger_id",
    "evaluation_epoch_ref",
    "exposure_budget_units",
    "reserved_units",
    "spent_units",
    "returned_units",
    "remaining_units",
    "contaminated",
    "entries",
    "admitted_entry_refs",
    "ledger_head_sequence",
    "ledger_head_root",
    "content_hash",
    "admitted_at",
];
const INFORMATION_RETURN_CLASSES: &[&str] = &["none", "aggregate", "per_case", "labels", "internals"];

fn genesis_ledger_root(ledger_id: &str) -> Result<String, Reply> {
    digest_over(
        &json!({ "evaluation_exposure_ledger_id": ledger_id }),
        ENTRY_DOMAIN,
        &["evaluation_exposure_ledger_id"],
    )
    .map_err(|reason| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            &LEDGER.code("head_root_failed"),
            reason,
        )
    })
}

/// The ledger the epoch's freeze creates, written once under a key derived from the epoch family
/// so a retried freeze or a later exposure operation reaches the same genesis.
fn ensure_ledger(
    st: &DaemonState,
    caller: &WriteCaller,
    epoch_family: &str,
    epoch: &Value,
) -> Result<Vec<AdmittedRecord>, Reply> {
    let resource = format!("{}{epoch_family}", LEDGER.ref_scheme);
    let key = format!("exposure-ledger-genesis:{epoch_family}");
    let scope = bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        LEDGER.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &key,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&LEDGER, &st.data_dir, &caller.identity, &scope, &resource)?;
    if !stream.is_empty() {
        return Ok(stream);
    }
    let genesis_caller = WriteCaller {
        identity: caller.identity.clone(),
        owner_ref: caller.owner_ref.clone(),
        idempotency_key: key,
    };
    let budget = integer(epoch, "evaluation_exposure_budget_units").unwrap_or(0);
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": LEDGER.schema_version,
        "evaluation_exposure_ledger_id": resource,
        "evaluation_epoch_ref": text(epoch, "evaluation_epoch_id"),
        "ancestor_exposure_ledger_refs": epoch.get("inherited_evaluation_exposure_ledger_refs").cloned().unwrap_or(json!([])),
        "steward_refs": epoch.get("holdout_custodian_refs").cloned().unwrap_or(json!([])),
        "sealed_suite_and_world_commitment_refs": epoch.get("sealed_holdout_commitment_refs").cloned().unwrap_or(json!([])),
        "exposure_budget_ref": text(epoch, "evaluation_exposure_budget_policy_ref"),
        "exposure_budget_units": budget,
        "reserved_units": 0,
        "spent_units": 0,
        "returned_units": 0,
        "remaining_units": budget,
        "contaminated": false,
        "entries": [],
        "admitted_entry_refs": [],
        "ledger_head_sequence": 0,
        "ledger_head_root": genesis_ledger_root(&resource)?,
        "derived_exposure_and_contamination_projection_ref": format!("agentgres://projection/evaluation-exposure/{epoch_family}"),
        "lifecycle_decision_refs": [],
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let reply = finish_admission(
        &LEDGER,
        st,
        &genesis_caller,
        &scope,
        &resource,
        "evaluation_exposure_ledger",
        record,
        None,
        recorded_at_ms,
        &json!({}),
        json!({}),
    );
    if reply.0 != StatusCode::CREATED && reply.0 != StatusCode::OK {
        return Err(reply);
    }
    read_stream(&LEDGER, &st.data_dir, &caller.identity, &scope, &resource)
}

async fn exposure_operation(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    epoch_family: String,
    body: Value,
    entry_kind: &'static str,
) -> Reply {
    let epoch_resource = match family_resource(&EPOCH, &epoch_family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ledger_resource = format!("{}{epoch_family}", LEDGER.ref_scheme);
    // The write context is the LEDGER's: the exposure head named by the caller is the ledger's head.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = refuse_unknown_fields(&body, &LEDGER, EXPOSURE_REQUEST_FIELDS) {
        return response;
    }
    let epoch_scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        EPOCH.resource_kind,
        &epoch_resource,
        Some(caller.owner_ref.as_str()),
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let epoch_stream = match read_stream(&EPOCH, &st.data_dir, &caller.identity, &epoch_scope, &epoch_resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(epoch) = epoch_stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &EPOCH.code("absent"),
            "no epoch answers to that family",
        );
    };
    if let Err(response) = require_usable_epoch(&epoch.record, false) {
        return response;
    }
    let ledger_stream = match ensure_ledger(&st, &caller, &epoch_family, &epoch.record) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        LEDGER.resource_kind,
        &ledger_resource,
        Some(caller.owner_ref.as_str()),
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    match replay_for_key(&LEDGER, &st, &caller, &scope, &ledger_resource, &ledger_stream, "evaluation_exposure_ledger") {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, LEDGER.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&ledger_stream, &expected_head, LEDGER.code_prefix) {
        return response;
    }
    let Some(prior) = ledger_stream.last() else {
        return bad(
            StatusCode::BAD_GATEWAY,
            &LEDGER.code("genesis_absent"),
            "the epoch's ledger has no genesis entry",
        );
    };
    let ledger = &prior.record;
    let entries = ledger.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    if entries.len() >= MAX_LEDGER_ENTRIES {
        return bad(
            StatusCode::CONFLICT,
            &LEDGER.code("ledger_full"),
            "this ledger holds its bounded maximum of 4096 entries",
        );
    }
    let units = integer(&body, "units").unwrap_or(0);
    let positive_kind = matches!(entry_kind, "reservation" | "spend" | "return");
    if (positive_kind && units == 0) || (!positive_kind && units != 0) || units > MAX_UNITS {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &LEDGER.code("units_invalid"),
            "reservation, spend and return carry positive units up to 1000000000; rotation carries zero",
        );
    }
    let commitment = body_str(&body, "candidate_family_commitment");
    if commitment.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &LEDGER.code("candidate_commitment_required"),
            "every entry binds the candidate family commitment it charges exposure to",
        );
    }
    let return_class = {
        let raw = body_str(&body, "information_return_class");
        if raw.is_empty() { "none".to_string() } else { raw }
    };
    if !INFORMATION_RETURN_CLASSES.contains(&return_class.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &LEDGER.code("information_return_class_outside_vocabulary"),
            "information_return_class is one of none | aggregate | per_case | labels | internals",
        );
    }
    let budget = integer(ledger, "exposure_budget_units").unwrap_or(0);
    let mut reserved = integer(ledger, "reserved_units").unwrap_or(0);
    let mut spent = integer(ledger, "spent_units").unwrap_or(0);
    let mut returned = integer(ledger, "returned_units").unwrap_or(0);
    let outstanding = reserved.saturating_sub(returned).saturating_sub(spent);
    match entry_kind {
        "reservation" => {
            if reserved.saturating_sub(returned).saturating_add(units) > budget {
                return bad(
                    StatusCode::CONFLICT,
                    "evaluation_exposure_exhausted",
                    format!("reserving {units} would exceed the frozen exposure budget: {budget} budgeted, {} committed", reserved.saturating_sub(returned)),
                );
            }
            reserved += units;
        }
        "spend" => {
            if units > outstanding {
                return bad(
                    StatusCode::CONFLICT,
                    "evaluation_exposure_exhausted",
                    format!("spending {units} exceeds the outstanding reservation of {outstanding}; exposure is spent from a reservation, never minted"),
                );
            }
            spent += units;
        }
        "return" => {
            if units > outstanding {
                return bad(
                    StatusCode::CONFLICT,
                    "evaluation_exposure_exhausted",
                    format!("returning {units} exceeds the outstanding reservation of {outstanding}"),
                );
            }
            returned += units;
        }
        _ => {}
    }
    let remaining = budget.saturating_sub(reserved.saturating_sub(returned));
    let contamination_flag = body
        .get("contamination_flag")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let seq = entries.len() as u64 + 1;
    let previous_root = text(ledger, "ledger_head_root");
    let mut entry = json!({
        "entry_seq": seq,
        "entry_ref": format!("{ledger_resource}/entry/{seq}"),
        "entry_kind": entry_kind,
        "units": units,
        "candidate_family_commitment": commitment,
        "selected_case_commitment": body.get("selected_case_commitment").cloned().unwrap_or(Value::Null),
        "information_return_class": return_class,
        "evaluator_version_refs": strings(&list(&body, "evaluator_version_refs")),
        "access_receipt_refs": strings(&list(&body, "access_receipt_refs")),
        "contamination_flag": contamination_flag,
        "previous_entry_root": if entries.is_empty() { Value::Null } else { json!(previous_root) },
    });
    let entry_root = match digest_over(&entry, ENTRY_DOMAIN, ENTRY_ROOT_FIELDS) {
        Ok(root) => root,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &LEDGER.code("entry_root_failed"),
                reason,
            )
        }
    };
    entry["entry_root"] = json!(entry_root);
    let mut next_entries = entries;
    next_entries.push(entry);
    let mut refs = list(ledger, "admitted_entry_refs");
    refs.push(format!("{ledger_resource}/entry/{seq}"));
    let recorded_at_ms = now_ms();
    let mut record = ledger.clone();
    record["reserved_units"] = json!(reserved);
    record["spent_units"] = json!(spent);
    record["returned_units"] = json!(returned);
    record["remaining_units"] = json!(remaining);
    record["contaminated"] = json!(ledger.get("contaminated").and_then(Value::as_bool).unwrap_or(false) || contamination_flag);
    record["entries"] = Value::Array(next_entries);
    record["admitted_entry_refs"] = strings(&refs);
    record["ledger_head_sequence"] = json!(seq);
    record["ledger_head_root"] = json!(entry_root);
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    finish_admission(
        &LEDGER,
        &st,
        &caller,
        &scope,
        &ledger_resource,
        "evaluation_exposure_ledger",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_exposure_reserve(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    exposure_operation(st, headers, family, body, "reservation").await
}

pub(crate) async fn handle_exposure_spend(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    exposure_operation(st, headers, family, body, "spend").await
}

pub(crate) async fn handle_exposure_release(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    exposure_operation(st, headers, family, body, "return").await
}

pub(crate) async fn handle_exposure_rotate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    exposure_operation(st, headers, family, body, "rotation").await
}

pub(crate) async fn handle_exposure_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let epoch_resource = match family_resource(&EPOCH, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (identity, epoch_stream) = match read_family(&st, &headers, &EPOCH, &epoch_resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let Some(epoch) = epoch_stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &EPOCH.code("absent"),
            "no epoch answers to that family",
        );
    };
    if text(&epoch.record, "lifecycle_status") == "draft" {
        return bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "a draft epoch has no exposure ledger; freeze creates it",
        );
    }
    let ledger_resource = format!("{}{family}", LEDGER.ref_scheme);
    let stream = match authorized_stream(&LEDGER, &st.data_dir, &identity, &ledger_resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(current) = stream.last() else {
        return bad(
            StatusCode::NOT_FOUND,
            &LEDGER.code("genesis_absent"),
            "the epoch's ledger has no genesis entry yet; the next exposure operation creates it",
        );
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "evaluation_exposure_ledger": current.record,
            "admission": current.admission,
            "head": current.head,
            "index_state": projection_cache_state(&ledger_resource, &stream),
        })),
    )
}

// ========================================================================================= cutoffs

const CUTOFF_REQUEST_FIELDS: &[&str] = &[
    "source_evaluation_epoch_ref",
    "synchronization_wave_ref",
    "source_target_generation_cutoff",
    "intended_destination_target_order",
    "per_order_source_version_and_cutoff_vector_ref",
    "destination_base_root",
    "agenda_revision_ref",
    "boundary_crossing",
    "eligible_finding_and_outcome_refs",
    "learning_evidence_eligibility_refs",
    "learning_egress_receipt_refs",
    "boundary_enforcement_access_and_custody_receipt_refs",
    "denied_or_quarantined_information_class_refs",
    "dependency_and_statistical_assumption_delta_ref",
    "signal_bundle_ref",
    "owner_ref",
    "idempotency_key",
    "expected_head",
];
const CUTOFF_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "receipt_id",
    "receipt_profile",
    "receipt_profile_ref",
    "source_campaign_ref",
    "source_campaign_epoch_and_archive_roots",
    "source_target_improvement_order",
    "agenda_and_task_distribution_roots",
    "effective_learning_policy_hash",
    "source_incumbent_resolved_component_snapshot_ref",
    "inherited_budget_risk_and_exposure_reservation_roots",
    "terminal_disposition",
    "previous_cutoff_receipt_root",
    "receipt_root",
    "content_hash",
    "admitted_at",
];

pub(crate) async fn handle_cutoff_emit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(campaign_family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let campaign_ref = match family_resource(&CAMPAIGN, &campaign_family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let resource = format!("{}{campaign_family}", CUTOFF.ref_scheme);
    // The cutoff stream is bound on its first receipt and authorized after; both are the caller's.
    let caller_probe = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let genesis = authorize_request_resource_scope(
        &st.data_dir,
        &caller_probe.identity,
        CUTOFF.resource_kind,
        &resource,
        Some(caller_probe.owner_ref.as_str()),
    )
    .is_err();
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &CUTOFF,
        resource,
        CUTOFF_REQUEST_FIELDS,
        CUTOFF_SERVER_RESOLVED,
        genesis,
        "improvement_order_cutoff_receipt",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let identity = &ctx.caller.identity;
    let owner_ref = ctx.caller.owner_ref.as_str();
    let campaign = match require_active_campaign(&st, identity, owner_ref, &campaign_ref) {
        Ok(campaign) => campaign,
        Err(response) => return response,
    };
    let c = &campaign.record;

    // -- the source epoch: this campaign's, and CLOSED ---------------------------------------------
    let epoch_ref = body_str(&body, "source_evaluation_epoch_ref");
    let epoch_scope = match authorize_request_resource_scope(
        &st.data_dir,
        identity,
        EPOCH.resource_kind,
        &epoch_ref,
        Some(owner_ref),
    ) {
        Ok(scope) => scope,
        Err(_) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &EPOCH.code("absent"),
                "the source epoch does not resolve under this owner",
            )
        }
    };
    let epoch_stream = match read_stream(&EPOCH, &st.data_dir, identity, &epoch_scope, &epoch_ref) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(epoch) = epoch_stream.last() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EPOCH.code("absent"),
            "the source epoch has no admitted entry",
        );
    };
    let e = &epoch.record;
    if text(e, "campaign_ref") != campaign_ref {
        return bad(
            StatusCode::CONFLICT,
            "improvement_order_cutoff_invalid",
            "the source epoch belongs to a different campaign",
        );
    }
    match text(e, "lifecycle_status").as_str() {
        "closed" => {}
        "invalidated" => {
            return bad(
                StatusCode::CONFLICT,
                "evaluation_epoch_invalid",
                "an invalidated epoch is not a cutoff source; its evidence is not evidence about a valid judgment contract",
            )
        }
        other => {
            return bad(
                StatusCode::CONFLICT,
                "improvement_order_cutoff_invalid",
                format!("a cutoff happens at epoch close; the source epoch is {other}"),
            )
        }
    }

    // -- the adjacent edge ------------------------------------------------------------------------
    let source_order = integer(c, "target_improvement_order").unwrap_or(0);
    let Some(destination) = integer(&body, "intended_destination_target_order") else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "improvement_order_cutoff_invalid",
            "intended_destination_target_order is a bounded integer naming the adjacent order above the source",
        );
    };
    if destination != source_order + 1 {
        return bad(
            StatusCode::CONFLICT,
            "improvement_order_cutoff_invalid",
            format!("evidence moves one adjacent edge per cutoff: source order {source_order} reaches only {}", source_order + 1),
        );
    }

    // -- rule 6 at this plane: no agenda successor at the same cutoff -----------------------------
    let admitted_agenda = text(c, "agenda_revision_ref");
    let cited_agenda = body_str(&body, "agenda_revision_ref");
    let Some((cited_family, cited_ordinal)) = parse_revision_ref(AGENDA.ref_scheme, &cited_agenda) else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &AGENDA.code("revision_ref_not_canonical"),
            "a cutoff names the agenda revision the destination order will use: improvement-agenda://<family>/revision/<n>",
        );
    };
    let (admitted_family, admitted_ordinal) =
        parse_revision_ref(AGENDA.ref_scheme, &admitted_agenda).unwrap_or_default();
    if cited_family != admitted_family || cited_ordinal != admitted_ordinal {
        if cited_family == admitted_family && cited_ordinal > admitted_ordinal {
            return bad(
                StatusCode::CONFLICT,
                "same_cutoff_mutual_validation",
                "the cutoff names a released successor of the campaign's admitted agenda; an agenda successor may not be selected on the evidence it is about to govern — release it, then admit a successor campaign under it",
            );
        }
        return bad(
            StatusCode::CONFLICT,
            "campaign_binding_mismatch",
            "the cutoff's agenda revision is not the campaign's admitted agenda revision",
        );
    }
    let agenda = match resolve_agenda_revision(&st, identity, owner_ref, &admitted_agenda) {
        Ok(AgendaResolution::Released(agenda)) => agenda,
        Ok(_) => {
            return bad(
                StatusCode::CONFLICT,
                "campaign_binding_mismatch",
                "the campaign's admitted agenda revision no longer resolves as released",
            )
        }
        Err(response) => return response,
    };

    // -- eligibility: every finding admitted by a cited decision that reads eligible --------------
    let findings = match ref_list(&body, "eligible_finding_and_outcome_refs", 64, &CUTOFF) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let eligibility_refs = match ref_list(&body, "learning_evidence_eligibility_refs", 64, &CUTOFF) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let mut admitted_subjects: BTreeSet<String> = BTreeSet::new();
    let mut denied: Vec<String> = list(e, "sealed_holdout_commitment_refs");
    for eligibility_ref in &eligibility_refs {
        let resolved = match resolve_admitted_evidence_eligibility(
            &st.data_dir,
            identity,
            Some(owner_ref),
            eligibility_ref,
        ) {
            Ok(resolved) => resolved,
            Err(_) => {
                return bad(
                    StatusCode::CONFLICT,
                    "learning_evidence_ineligible",
                    format!("eligibility '{eligibility_ref}' does not resolve under this owner through the learning-boundary plane"),
                )
            }
        };
        let subjects = list(&resolved.record, "subject_refs");
        if resolved.is_eligible() {
            admitted_subjects.extend(subjects);
        } else {
            for subject in subjects {
                if !denied.contains(&subject) {
                    denied.push(subject);
                }
            }
        }
    }
    for finding in &findings {
        if !admitted_subjects.contains(finding) {
            return bad(
                StatusCode::CONFLICT,
                "learning_evidence_ineligible",
                format!("'{finding}' is admitted by no cited eligibility revision that reads eligible; observed work is not improvement evidence until a LearningEvidenceEligibility says so"),
            );
        }
    }
    for extra in list(&body, "denied_or_quarantined_information_class_refs") {
        if !denied.contains(&extra) {
            denied.push(extra);
        }
    }

    // -- egress: an institutional crossing needs an admitted receipt ------------------------------
    let crossing = {
        let raw = body_str(&body, "boundary_crossing");
        if raw.is_empty() { "same_boundary".to_string() } else { raw }
    };
    if !matches!(crossing.as_str(), "same_boundary" | "institutional_boundary") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CUTOFF.code("boundary_crossing_outside_vocabulary"),
            "boundary_crossing is same_boundary | institutional_boundary",
        );
    }
    let egress_refs = match ref_list(&body, "learning_egress_receipt_refs", 64, &CUTOFF) {
        Ok(list) => list,
        Err(response) => return response,
    };
    if crossing == "institutional_boundary" {
        let mut admitted_crossing = false;
        for receipt_ref in &egress_refs {
            match resolve_admitted_learning_egress_receipt(&st.data_dir, identity, Some(owner_ref), receipt_ref) {
                Ok(receipt) if text(&receipt, "decision") == "admitted" => admitted_crossing = true,
                Ok(_) => {}
                Err(_) => {
                    return bad(
                        StatusCode::CONFLICT,
                        "learning_egress_denied",
                        format!("egress receipt '{receipt_ref}' does not resolve under this owner through the learning-boundary plane"),
                    )
                }
            }
        }
        if !admitted_crossing {
            return bad(
                StatusCode::CONFLICT,
                "learning_egress_denied",
                "an institutional-boundary crossing requires at least one LearningEgressReceipt that resolves under this owner and records an admitted crossing",
            );
        }
    }

    // -- the ledger head this cutoff inherits --------------------------------------------------------
    let epoch_family = epoch_ref.trim_start_matches(EPOCH.ref_scheme).to_string();
    let ledger_resource = format!("{}{epoch_family}", LEDGER.ref_scheme);
    let ledger_head = match authorize_request_resource_scope(
        &st.data_dir,
        identity,
        LEDGER.resource_kind,
        &ledger_resource,
        Some(owner_ref),
    ) {
        Ok(scope) => match read_stream(&LEDGER, &st.data_dir, identity, &scope, &ledger_resource) {
            Ok(stream) => stream
                .last()
                .map(|entry| text(&entry.record, "ledger_head_root"))
                .unwrap_or_default(),
            Err(response) => return response,
        },
        Err(_) => String::new(),
    };
    if ledger_head.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            "improvement_order_cutoff_invalid",
            "the source epoch has no exposure ledger head to freeze; a cutoff binds the inherited exposure posture",
        );
    }

    let ordinal = ctx.stream.len() as u64 + 1;
    let previous_root = ctx
        .stream
        .last()
        .map(|entry| json!(text(&entry.record, "receipt_root")))
        .unwrap_or(Value::Null);
    let generation_cutoff = integer(&body, "source_target_generation_cutoff").unwrap_or(0);
    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": CUTOFF.schema_version,
        "receipt_id": format!("{}/{ordinal}", ctx.resource),
        "receipt_profile": "improvement_order_cutoff",
        "receipt_profile_ref": CUTOFF.contract_id,
        "source_campaign_ref": campaign_ref,
        "source_evaluation_epoch_ref": epoch_ref,
        "synchronization_wave_ref": body_str(&body, "synchronization_wave_ref"),
        "source_campaign_epoch_and_archive_roots": [text(c, "campaign_contract_root"), text(e, "frozen_root")],
        "source_target_improvement_order": source_order,
        "source_target_generation_cutoff": generation_cutoff,
        "intended_destination_target_order": destination,
        "per_order_source_version_and_cutoff_vector_ref": body_str(&body, "per_order_source_version_and_cutoff_vector_ref"),
        "destination_base_root": body_str(&body, "destination_base_root"),
        "agenda_revision_ref": admitted_agenda,
        "agenda_and_task_distribution_roots": [text(&agenda, "content_hash")],
        "boundary_crossing": crossing,
        "eligible_finding_and_outcome_refs": strings(&findings),
        "learning_evidence_eligibility_refs": strings(&eligibility_refs),
        "learning_egress_receipt_refs": strings(&egress_refs),
        "boundary_enforcement_access_and_custody_receipt_refs": strings(&list(&body, "boundary_enforcement_access_and_custody_receipt_refs")),
        "effective_learning_policy_hash": text(c, "effective_learning_policy_hash"),
        "denied_or_quarantined_information_class_refs": strings(&denied),
        "source_incumbent_resolved_component_snapshot_ref": text(c, "resolved_component_snapshot_ref"),
        "inherited_budget_risk_and_exposure_reservation_roots": [ledger_head],
        "dependency_and_statistical_assumption_delta_ref": body_str(&body, "dependency_and_statistical_assumption_delta_ref"),
        "signal_bundle_ref": body.get("signal_bundle_ref").cloned().unwrap_or(Value::Null),
        "terminal_disposition": if findings.is_empty() { "no_change" } else { "evidence_ready" },
        "previous_cutoff_receipt_root": previous_root,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    record["receipt_root"] = match digest_over(&record, CUTOFF_RECEIPT_DOMAIN, CUTOFF_RECEIPT_FIELDS) {
        Ok(root) => json!(root),
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CUTOFF.code("receipt_root_failed"),
                reason,
            )
        }
    };
    finish_admission(
        &CUTOFF,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "improvement_order_cutoff_receipt",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_cutoff_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(campaign_family): Path<String>,
) -> Reply {
    if let Err(response) = family_resource(&CAMPAIGN, &campaign_family) {
        return response;
    }
    let resource = format!("{}{campaign_family}", CUTOFF.ref_scheme);
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        CUTOFF.resource_kind,
        &resource,
        None,
    ) {
        Ok(scope) => match read_stream(&CUTOFF, &st.data_dir, &identity, &scope, &resource) {
            Ok(stream) => stream,
            Err(response) => return response,
        },
        Err(_) => Vec::new(),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "improvement_campaign_ref": format!("{}{campaign_family}", CAMPAIGN.ref_scheme),
            "receipts": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": projection_cache_state(&resource, &stream),
        })),
    )
}

// ================================================================== the handoff, and apply-time

const HANDOFF_REQUEST_FIELDS: &[&str] = &[
    "candidate_ref",
    "signal",
    "suggested",
    "evidence_refs",
    "reason",
    "confidence",
    "owner_ref",
];

/// Nominate a candidate under the campaign's active frozen epoch by writing an ORDINARY PENDING
/// improvement proposal through the direct path's own create function. The campaign's only exit.
pub(crate) async fn handle_campaign_upgrade_proposal(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(campaign_family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let campaign_ref = match family_resource(&CAMPAIGN, &campaign_family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    if let Err(response) = refuse_unknown_fields(&body, &CAMPAIGN, HANDOFF_REQUEST_FIELDS) {
        return response;
    }
    let owner_ref = body_str(&body, "owner_ref");
    if owner_ref.is_empty() || !identity.authorizes_tenant(&owner_ref) {
        return bad(
            StatusCode::FORBIDDEN,
            &CAMPAIGN.code("owner_required"),
            "a nomination names the campaign's owner_ref, which the caller must hold",
        );
    }
    let campaign = match require_active_campaign(&st, &identity, &owner_ref, &campaign_ref) {
        Ok(campaign) => campaign,
        Err(response) => return response,
    };
    let c = &campaign.record;
    let epochs = match campaign_epochs(&st, &identity, &campaign_ref) {
        Ok(epochs) => epochs,
        Err(response) => return response,
    };
    let Some(epoch) = epochs
        .iter()
        .find(|epoch| text(epoch, "lifecycle_status") == "active")
    else {
        return bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "a candidate is nominated only under the campaign's ACTIVE frozen epoch; this campaign has none",
        );
    };
    let candidate_ref = body_str(&body, "candidate_ref");
    if candidate_ref.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CAMPAIGN.code("candidate_required"),
            "a nomination names the immutable candidate it proposes",
        );
    }
    let target_ref = text(c, "mutable_target_ref");
    let current_root = match resolve_target_root(&st, &target_ref) {
        Ok(root) => root,
        Err(response) => return response,
    };
    if current_root != text(c, "target_base_root") {
        return bad(
            StatusCode::CONFLICT,
            "target_base_stale",
            "the mutable target changed since the campaign froze its root; a nomination against a stale base needs a new campaign contract",
        );
    }
    let proposal_kind = if target_ref.starts_with("skill-entry://") {
        "skill_improvement"
    } else {
        "automation_readiness"
    };
    let mut evidence = vec![candidate_ref.clone(), text(epoch, "evaluation_epoch_id")];
    evidence.extend(list(&body, "evidence_refs"));
    let signal = {
        let raw = body_str(&body, "signal");
        if raw.is_empty() {
            "campaign_candidate_nomination".to_string()
        } else {
            raw
        }
    };
    let proposal_body = json!({
        "proposal_kind": proposal_kind,
        "signal": signal,
        "target_ref": target_ref,
        "suggested": body.get("suggested").cloned().unwrap_or(json!({})),
        "evidence_refs": evidence,
        "reason": body_str(&body, "reason"),
        "confidence": body.get("confidence").cloned().unwrap_or(Value::Null),
    });
    let binding = json!({
        "improvement_campaign_ref": campaign_ref,
        "evaluation_epoch_ref": text(epoch, "evaluation_epoch_id"),
        "campaign_contract_root": text(c, "campaign_contract_root"),
        "campaign_owner_ref": owner_ref,
        "candidate_ref": candidate_ref,
    });
    create_improvement_proposal(&st, &proposal_body, Some(binding))
}

/// The current entry of one family resource read RAW from the substrate — this module's own
/// streams, for the direct path's apply lane, which carries no caller identity of its own.
fn raw_current(st: &DaemonState, spec: &'static FamilySpec, resource: &str) -> Option<Value> {
    let history = super::substrate_store::read_event_stream_history(
        &st.data_dir,
        spec.owner_namespace,
        &stream_tail(spec.resource_kind, resource),
    )
    .ok()?;
    let stream = project_stream(spec, &history).ok()?;
    stream.last().map(|entry| entry.record.clone())
}

/// The campaign-grade bindings a campaign-bound proposal must still satisfy at apply, evaluated
/// beside the direct gate: the campaign active and its contract root unmoved, the bound epoch
/// active and frozen, the target unmoved. Returns the canon reason code and message on refusal.
pub(crate) fn campaign_grade_bindings(
    st: &DaemonState,
    proposal: &Value,
) -> Result<(), (&'static str, String)> {
    let campaign_ref = text(proposal, "improvement_campaign_ref");
    if campaign_ref.is_empty() {
        return Ok(());
    }
    let Some(campaign) = raw_current(st, &CAMPAIGN, &campaign_ref) else {
        return Err(("campaign_binding_mismatch", "the bound campaign no longer resolves".to_string()));
    };
    if text(&campaign, "lifecycle_status") != "active" {
        return Err((
            "campaign_binding_mismatch",
            format!("the bound campaign is {}; a campaign-bound proposal applies only while its campaign is active", text(&campaign, "lifecycle_status")),
        ));
    }
    if text(&campaign, "owner_ref") != text(proposal, "campaign_owner_ref")
        || text(&campaign, "campaign_contract_root") != text(proposal, "campaign_contract_root")
    {
        return Err((
            "campaign_binding_mismatch",
            "the bound campaign's owner or contract root no longer matches the binding frozen on the proposal".to_string(),
        ));
    }
    let epoch_ref = text(proposal, "evaluation_epoch_ref");
    let Some(epoch) = raw_current(st, &EPOCH, &epoch_ref) else {
        return Err(("evaluation_epoch_invalid", "the bound epoch no longer resolves".to_string()));
    };
    if text(&epoch, "campaign_ref") != campaign_ref
        || text(&epoch, "campaign_contract_root") != text(&campaign, "campaign_contract_root")
    {
        return Err(("campaign_binding_mismatch", "the bound epoch is not this campaign's".to_string()));
    }
    if let Err((_, Json(reply))) = require_usable_epoch(&epoch, true) {
        // `bad` nests the code under `error`; reading the top level would silently turn every
        // not-frozen refusal into an invalid one with an empty message.
        let code: &'static str = if refusal_code(&reply) == "evaluation_epoch_not_frozen" {
            "evaluation_epoch_not_frozen"
        } else {
            "evaluation_epoch_invalid"
        };
        return Err((code, refusal_message(&reply)));
    }
    let target_ref = text(&campaign, "mutable_target_ref");
    let Some(root) = resolve_core_mutable_target_root(st, &target_ref) else {
        return Err(("target_base_stale", "the campaign's mutable target no longer resolves".to_string()));
    };
    if root != text(&campaign, "target_base_root") {
        return Err((
            "target_base_stale",
            "the mutable target changed since the campaign froze its root; promotion against a stale base fails".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_implemented_family_is_a_subset_of_canon_and_named_once_each() {
        let mut seen = BTreeSet::new();
        for code in IMPLEMENTED_CAMPAIGN_GATE_CODES {
            assert!(seen.insert(*code), "duplicate code {code}");
            assert!(!code.is_empty());
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn the_operation_head_chains_from_a_null_genesis() {
        let genesis = chain_root(CAMPAIGN_HEAD_DOMAIN, None, "sha256:aa").expect("genesis");
        let next = chain_root(CAMPAIGN_HEAD_DOMAIN, Some(&genesis), "sha256:bb").expect("next");
        assert_ne!(genesis, next);
        assert!(genesis.starts_with("sha256:"));
    }

    #[test]
    fn a_draft_epoch_answers_not_frozen_and_a_closed_one_answers_invalid() {
        let draft = json!({ "lifecycle_status": "draft" });
        let closed = json!({ "lifecycle_status": "closed" });
        let frozen = json!({ "lifecycle_status": "frozen" });
        assert_eq!(refusal_code(&require_usable_epoch(&draft, false).unwrap_err().1 .0), "evaluation_epoch_not_frozen");
        assert_eq!(refusal_code(&require_usable_epoch(&closed, false).unwrap_err().1 .0), "evaluation_epoch_invalid");
        assert!(require_usable_epoch(&frozen, false).is_ok());
        assert_eq!(refusal_code(&require_usable_epoch(&frozen, true).unwrap_err().1 .0), "evaluation_epoch_not_frozen");
        assert!(!refusal_message(&require_usable_epoch(&frozen, true).unwrap_err().1 .0).is_empty());
    }
}
