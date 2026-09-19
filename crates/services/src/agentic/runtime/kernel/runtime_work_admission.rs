//! Work admission primitives (R-192, S5-1: renamed from `runtime_goal_pursuit`). Harness- and
//! application-agnostic: WorkRun isolation binding, the generic WorkResult/OutcomeDelta seam
//! over `work_subject_ref`, declassification consumption, authority effects, information-flow
//! decisions and receipt checkpoints. It names no goal, room or orchestration object.
//!
//! This module owns no product route and grants no authority.  It provides the
//! daemon's fail-closed, source-neutral mechanics for immutable definition
//! resolution, generic result admission, lifecycle compare-and-swap,
//! information-flow decisions, receipt checkpoints, and branch effects.  The
//! HTTP plane supplies current owner facts and persists the returned records.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use ioi_types::app::generated::architecture_contracts::{
    HypervisorWorkloadIsolationBindingV1, HypervisorWorkloadIsolationRequirementsV1,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// R-195 (S5-3): two constants stood here, `DEFINITION_RESOLUTION_SCHEMA_VERSION` and
// `PROFILE_RESOLUTION_RECEIPT_SCHEMA_VERSION`, both naming `applications.ioi-ai.*` contracts. They
// were `resolve_definitions`' vocabulary and lost their only user when it left in S5-1. The
// compiler could not say so — a `pub const` in a library is never dead-code-flagged, so they
// survived a cut that removed everything around them and a rename that made this module
// platform-neutral, still spelling the application's name. Found by grepping for the receipt's
// producers while adding that receipt's closure invariant, not by any gate.
pub const WORK_RESULT_SCHEMA_VERSION: &str = "ioi.foundations.work-result.v3";
pub const OUTCOME_DELTA_SCHEMA_VERSION: &str = "ioi.foundations.outcome-delta.v3";
// The GoalRun-local WorkLifecycle mechanics were removed in M04.6: the shared
// `runtime_work_lifecycle_log::WorkLifecycleLogCore` and its durable
// `work_lifecycle_routes::WorkLifecycleStore` owner are now the ONLY lifecycle
// integrity/replay mechanism. This module no longer mints lifecycle records or
// its own legal-edge table.
pub const IFC_DECISION_SCHEMA_VERSION: &str =
    "ioi.components.daemon-runtime.information-flow-decision-receipt.v1";
pub const RECEIPT_CHECKPOINT_SCHEMA_VERSION: &str = "ioi.foundations.receipt-checkpoint.v1";
pub const WORKLOAD_ISOLATION_REQUIREMENTS_SCHEMA_VERSION: &str =
    "ioi.components.hypervisor.workload-isolation-requirements.v1";
pub const WORKLOAD_ISOLATION_BINDING_SCHEMA_VERSION: &str =
    "ioi.components.hypervisor.workload-isolation-binding.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAdmissionError {
    code: &'static str,
    message: String,
}

impl WorkAdmissionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

type AdmissionResult<T> = Result<T, WorkAdmissionError>;

fn required_text<'a>(value: &'a Value, field: &str) -> AdmissionResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            WorkAdmissionError::new(
                "goal_pursuit_field_required",
                format!("{field} is required"),
            )
        })
}

fn required_ref<'a>(value: &'a Value, field: &str, prefix: &str) -> AdmissionResult<&'a str> {
    let found = required_text(value, field)?;
    if !found.starts_with(prefix) || found.chars().any(char::is_whitespace) {
        return Err(WorkAdmissionError::new(
            "goal_pursuit_ref_invalid",
            format!("{field} must be a bounded {prefix} reference"),
        ));
    }
    Ok(found)
}

fn required_hash<'a>(value: &'a Value, field: &str) -> AdmissionResult<&'a str> {
    let found = required_text(value, field)?;
    if found.len() != 71
        || !found.starts_with("sha256:")
        || !found[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(WorkAdmissionError::new(
            "goal_pursuit_hash_invalid",
            format!("{field} must be a lowercase sha256 digest"),
        ));
    }
    Ok(found)
}

fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => serde_json::to_string(v).expect("string serialization"),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).expect("key serialization"),
                            canonical(&values[key])
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn hash(value: &Value) -> String {
    format!("sha256:{:x}", Sha256::digest(canonical(value).as_bytes()))
}

fn hash_without(value: &Value, field: &str) -> AdmissionResult<String> {
    let mut hashable = value.clone();
    hashable
        .as_object_mut()
        .ok_or_else(|| {
            WorkAdmissionError::new(
                "workload_isolation_object_required",
                "workload isolation contracts must be objects",
            )
        })?
        .remove(field);
    Ok(hash(&hashable))
}

fn unique_refs(
    value: &Value,
    field: &str,
    prefix: &str,
    allow_empty: bool,
) -> AdmissionResult<Vec<String>> {
    let refs = value.get(field).and_then(Value::as_array).ok_or_else(|| {
        WorkAdmissionError::new(
            "goal_pursuit_refs_required",
            format!("{field} must be an array"),
        )
    })?;
    if refs.is_empty() && !allow_empty {
        return Err(WorkAdmissionError::new(
            "goal_pursuit_refs_required",
            format!("{field} must not be empty"),
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in refs {
        let reference = entry
            .as_str()
            .map(str::trim)
            .filter(|v| v.starts_with(prefix) && !v.chars().any(char::is_whitespace))
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "goal_pursuit_ref_invalid",
                    format!("{field} contains an invalid {prefix} reference"),
                )
            })?;
        if !seen.insert(reference.to_string()) {
            return Err(WorkAdmissionError::new(
                "goal_pursuit_ref_duplicate",
                format!("{field} contains duplicate {reference}"),
            ));
        }
    }
    Ok(seen.into_iter().collect())
}

// R-192 (S5-1): `is_canonical_ref` and `requirement_refs` stood here. Both existed only to read a
// GoalRunProfile's declared requirement families during definition resolution, which left this
// module with `resolve_definitions`, so both had zero callers. Their refusal codes said so out
// loud — `goal_pursuit_refs_required`, `goal_pursuit_ref_invalid` — which is the tell that they
// were never platform helpers. Deleted rather than kept: slice S5-3 re-establishes requirement
// resolution where the profile lives, in the composing application.

#[derive(Debug, Clone, Default)]
pub struct WorkAdmissionCore;

impl WorkAdmissionCore {
    /// Admit the compiled isolation requirements and mint the immutable binding
    /// for one WorkRun before any workspace, backend, or final-invoker effect.
    /// The caller supplies current owner facts; the daemon supplies the WorkRun
    /// identity and computes both content commitments.
    pub fn admit_workrun_isolation(
        &self,
        compiled_requirements: &Value,
        binding_inputs: &Value,
        workrun_ref: &str,
        admitted_at: &str,
    ) -> AdmissionResult<Value> {
        if !workrun_ref.starts_with("workrun://") || workrun_ref.chars().any(char::is_whitespace) {
            return Err(WorkAdmissionError::new(
                "workrun_isolation_workrun_ref_invalid",
                "the daemon-assigned WorkRun reference is required",
            ));
        }
        let mut requirements = compiled_requirements.clone();
        let requirements_object = requirements.as_object_mut().ok_or_else(|| {
            WorkAdmissionError::new(
                "workload_isolation_requirements_required",
                "compiled workload isolation requirements are required",
            )
        })?;
        if requirements_object
            .get("schema_version")
            .and_then(Value::as_str)
            != Some(WORKLOAD_ISOLATION_REQUIREMENTS_SCHEMA_VERSION)
        {
            return Err(WorkAdmissionError::new(
                "workload_isolation_requirements_schema_invalid",
                "compiled workload isolation requirements use an unsupported schema",
            ));
        }
        requirements_object.remove("requirements_hash");
        let requirements_hash = hash(&requirements);
        requirements["requirements_hash"] = json!(requirements_hash);
        serde_json::from_value::<HypervisorWorkloadIsolationRequirementsV1>(requirements.clone())
            .map_err(|error| {
            WorkAdmissionError::new(
                "workload_isolation_requirements_invalid",
                format!("compiled workload isolation requirements are invalid: {error}"),
            )
        })?;

        let inputs = binding_inputs.as_object().ok_or_else(|| {
            WorkAdmissionError::new(
                "workload_isolation_binding_inputs_required",
                "current runtime binding inputs are required",
            )
        })?;
        let take = |field: &str| {
            inputs.get(field).cloned().ok_or_else(|| {
                WorkAdmissionError::new(
                    "workload_isolation_binding_input_missing",
                    format!("runtime binding input {field} is required"),
                )
            })
        };
        let binding_ref = format!("workload-isolation-binding://{}", &workrun_ref[10..]);
        let mut binding = json!({
            "schema_version": WORKLOAD_ISOLATION_BINDING_SCHEMA_VERSION,
            "binding_ref": binding_ref,
            "requirements_ref": requirements["requirements_ref"],
            "requirements_hash": requirements_hash,
            "workrun_ref": workrun_ref,
            "runtime_assignment_ref": take("runtime_assignment_ref")?,
            "environment_ref": take("environment_ref")?,
            "startup_plan_ref": take("startup_plan_ref")?,
            "startup_plan_hash": take("startup_plan_hash")?,
            "boundary_instance_ref": take("boundary_instance_ref")?,
            "compute_host_ref": take("compute_host_ref")?,
            "failure_domain_ref": take("failure_domain_ref")?,
            "backend_capability_declaration_ref": take("backend_capability_declaration_ref")?,
            "backend_capability_declaration_hash": take("backend_capability_declaration_hash")?,
            "enforcement_coverage_refs_and_hashes": take("enforcement_coverage_refs_and_hashes")?,
            "immutable_component_refs_and_hashes": take("immutable_component_refs_and_hashes")?,
            "exact_input_and_mount_closure_hash": take("exact_input_and_mount_closure_hash")?,
            "guest_network_identity_ref": take("guest_network_identity_ref")?,
            "route_policy_ref": take("route_policy_ref")?,
            "dependency_broker_ref": take("dependency_broker_ref")?,
            "dependency_broker_policy_hash": take("dependency_broker_policy_hash")?,
            "brokered_lease_refs": take("brokered_lease_refs")?,
            "pep_ref": take("pep_ref")?,
            "final_invoker_ref": take("final_invoker_ref")?,
            "governed_action_classes": take("governed_action_classes")?,
            "output_quarantine_ref": take("output_quarantine_ref")?,
            "output_policy_ref": take("output_policy_ref")?,
            "cleanup_obligation_ref": take("cleanup_obligation_ref")?,
            "required_terminal_disposition": take("required_terminal_disposition")?,
            "readiness_evidence_refs": take("readiness_evidence_refs")?,
            "currentness_evaluation_refs": take("currentness_evaluation_refs")?,
        });
        let binding_hash = hash(&binding);
        binding["binding_hash"] = json!(binding_hash);
        serde_json::from_value::<HypervisorWorkloadIsolationBindingV1>(binding.clone()).map_err(
            |error| {
                WorkAdmissionError::new(
                    "workload_isolation_binding_invalid",
                    format!("workload isolation binding is invalid: {error}"),
                )
            },
        )?;
        Ok(json!({
            "schema_version": "ioi.components.hypervisor.workrun-isolation-admission.v1",
            "workrun_ref": workrun_ref,
            "requirements": requirements,
            "binding": binding,
            "binding_commitment": binding_hash,
            "admitted_at": admitted_at,
            "claim_boundary": "A valid immutable binding proves admitted contract propagation, not live containment or escape resistance."
        }))
    }

    /// Re-validate a persisted binding at replay, execute, cancel, replacement,
    /// or terminal admission. Lifecycle state may advance beside the binding;
    /// no lifecycle actor may rewrite the binding itself.
    pub fn preserve_workrun_isolation(
        &self,
        admitted: &Value,
        candidate_binding: &Value,
        workrun_ref: &str,
        transition: &str,
    ) -> AdmissionResult<Value> {
        let binding = admitted.get("binding").ok_or_else(|| {
            WorkAdmissionError::new(
                "workload_isolation_binding_missing",
                "the WorkRun has no admitted isolation binding",
            )
        })?;
        serde_json::from_value::<HypervisorWorkloadIsolationBindingV1>(binding.clone()).map_err(
            |error| {
                WorkAdmissionError::new(
                    "workload_isolation_binding_invalid",
                    format!("persisted workload isolation binding is invalid: {error}"),
                )
            },
        )?;
        if required_text(binding, "workrun_ref")? != workrun_ref {
            return Err(WorkAdmissionError::new(
                "workload_isolation_workrun_mismatch",
                "the isolation binding belongs to a different WorkRun",
            ));
        }
        let declared = required_hash(binding, "binding_hash")?;
        if hash_without(binding, "binding_hash")? != declared {
            return Err(WorkAdmissionError::new(
                "workload_isolation_binding_hash_mismatch",
                "the persisted isolation binding does not reproduce its commitment",
            ));
        }
        if candidate_binding != binding {
            return Err(WorkAdmissionError::new(
                "workload_isolation_binding_substitution_refused",
                format!("{transition} cannot weaken or replace the admitted isolation binding"),
            ));
        }
        Ok(json!({
            "schema_version": "ioi.components.hypervisor.workrun-isolation-preservation.v1",
            "workrun_ref": workrun_ref,
            "transition": transition,
            "binding_ref": binding["binding_ref"],
            "binding_hash": declared,
            "preserved": true
        }))
    }

    /// Freeze the exact reusable-definition closure for one GoalRun. Definitions
    /// remain inert data: resolution emits a snapshot and receipt, never an
    /// execution instruction or authority decision.
    // R-192 (S5-1): `resolve_definitions` stood here — 487 lines resolving a GoalRunProfile
    // revision, its execution ceiling and its declared invocation budget into a definition
    // closure. That is the ioi.ai application's vocabulary, and it left with the GoalRun plane.
    // What remains in this module is platform: WorkRun isolation, the generic WorkResult and
    // OutcomeDelta admission over `work_subject_ref`, declassification, authority effects,
    // information-flow decisions and receipt checkpoints.

    pub fn admit_work_result(&self, request: &Value, now: &str) -> AdmissionResult<Value> {
        const STATUSES: &[&str] = &[
            "completed",
            "failed",
            "blocked",
            "partial",
            "challenged",
            "superseded",
        ];
        const OUTCOMES: &[&str] = &[
            "positive",
            "negative",
            "inconclusive",
            "invalid",
            "exploit_found",
            "superseded",
        ];
        let result_ref = required_ref(request, "work_result_id", "work-result://")?;
        let goal_ref = required_ref(request, "work_subject_ref", "goal://")?;
        let profile = required_text(request, "result_profile")?;
        if profile != "research" {
            return Err(WorkAdmissionError::new(
                "work_result_profile_not_selected",
                "M3 proof admits the research result profile",
            ));
        }
        let status = required_text(request, "status")?;
        if !STATUSES.contains(&status) {
            return Err(WorkAdmissionError::new(
                "work_result_status_invalid",
                format!("unsupported status {status}"),
            ));
        }
        let outcome = required_text(request, "outcome_class")?;
        if !OUTCOMES.contains(&outcome) {
            return Err(WorkAdmissionError::new(
                "work_result_outcome_invalid",
                format!("unsupported outcome {outcome}"),
            ));
        }
        let payload_ref = required_ref(request, "result_payload_ref", "artifact://")?;
        let produced_by_ref = required_text(request, "produced_by_ref")?;
        let submitted_by_ref = required_text(request, "submitted_by_ref")?;
        let resolution = request
            .get("producer_component_resolution")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "work_result_component_resolution_required",
                    "producer_component_resolution is required",
                )
            })?;
        let resolution_value = Value::Object(resolution.clone());
        let component_ref = required_ref(
            &resolution_value,
            "resolved_component_set_snapshot_ref",
            "artifact://",
        )?;
        let component_hash = required_hash(&resolution_value, "resolved_component_set_hash")?;
        let resolution_receipt = required_ref(
            &resolution_value,
            "component_resolution_receipt_ref",
            "receipt://",
        )?;
        let resolver_kind = resolution
            .get("resolver_kind")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !matches!(resolver_kind, "harness_profile" | "agent_harness_adapter") {
            return Err(WorkAdmissionError::new(
                "work_result_resolver_kind_invalid",
                "runtime-produced results require a typed resolver",
            ));
        }
        let supporting = request
            .get("supporting_evidence_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let contradicting_refs = request
            .get("contradicting_evidence_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let claims = request
            .get("claim_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let uncertainty = request.get("uncertainty").cloned().unwrap_or(Value::Null);
        if outcome == "positive" && claims.is_empty() {
            return Err(WorkAdmissionError::new(
                "work_result_claims_required",
                "a positive research result requires at least one bounded claim",
            ));
        }
        let uncertainty_is_empty = match &uncertainty {
            Value::Null => true,
            Value::String(value) => value.trim().is_empty(),
            Value::Array(values) => values.is_empty(),
            Value::Object(values) => values.is_empty(),
            _ => false,
        };
        if outcome == "inconclusive" && uncertainty_is_empty {
            return Err(WorkAdmissionError::new(
                "work_result_uncertainty_required",
                "an inconclusive research result requires retained uncertainty",
            ));
        }
        let result = json!({
            "schema_version": WORK_RESULT_SCHEMA_VERSION,
            "work_result_id": result_ref,
            "work_subject_ref": goal_ref,
            "system_binding": Value::Null,
            "produced_by_ref": produced_by_ref,
            "submitted_by_ref": submitted_by_ref,
            "operator_and_affiliation_refs": request.get("operator_and_affiliation_refs").cloned().unwrap_or_else(|| json!([])),
            "invocation_or_run_ref": request.get("invocation_or_run_ref").cloned().unwrap_or(Value::Null),
            "result_profile": profile,
            "result_profile_ref": request.get("result_profile_ref").cloned().unwrap_or(Value::Null),
            "result_payload_ref": payload_ref,
            "producer_component_resolution": {
                "resolved_component_set_snapshot_ref": component_ref,
                "resolved_component_set_hash": component_hash,
                "component_resolution_receipt_ref": resolution_receipt,
                "resolver_kind": resolver_kind,
                "resolver_revision_ref": resolution.get("resolver_revision_ref").cloned().unwrap_or(Value::Null),
                "resolver_content_hash": resolution.get("resolver_content_hash").cloned().unwrap_or(Value::Null)
            },
            "declared_method_and_lineage_refs": request.get("declared_method_and_lineage_refs").cloned().unwrap_or_else(|| json!([])),
            "information_flow_label_refs": request.get("information_flow_label_refs").cloned().unwrap_or_else(|| json!([])),
            "outcome_class": outcome,
            "status": status,
            "outcome_delta_refs": request.get("outcome_delta_refs").cloned().unwrap_or_else(|| json!([])),
            "observation_refs": request.get("observation_refs").cloned().unwrap_or_else(|| json!([])),
            "claim_refs": claims,
            "uncertainty": uncertainty,
            "supporting_evidence_refs": supporting,
            "contradicting_evidence_refs": contradicting_refs,
            "artifact_receipt_and_trace_refs": request.get("artifact_receipt_and_trace_refs").cloned().unwrap_or_else(|| json!([])),
            "resource_and_cost_refs": request.get("resource_and_cost_refs").cloned().unwrap_or_else(|| json!([])),
            "authority_and_policy_refs": request.get("authority_and_policy_refs").cloned().unwrap_or_else(|| json!([])),
            "blocker_and_decision_request_refs": request.get("blocker_and_decision_request_refs").cloned().unwrap_or_else(|| json!([])),
            "verifier_refs": request.get("verifier_refs").cloned().unwrap_or_else(|| json!([])),
            "license_disclosure_retention_and_export_refs": request.get("license_disclosure_retention_and_export_refs").cloned().unwrap_or_else(|| json!([])),
            "reproduction_state": request.get("reproduction_state").cloned().unwrap_or(Value::Null),
            "reproduction_refs": request.get("reproduction_refs").cloned().unwrap_or_else(|| json!([])),
            "acceptance_ref": request.get("acceptance_ref").cloned().unwrap_or(Value::Null),
            "review_refs": request.get("review_refs").cloned().unwrap_or_else(|| json!([])),
            "supersedes_work_result_ref": request.get("supersedes_work_result_ref").cloned().unwrap_or(Value::Null),
            "superseded_by_ref": request.get("superseded_by_ref").cloned().unwrap_or(Value::Null),
            "summary_ref": request.get("summary_ref").cloned().unwrap_or(Value::Null),
            "next_action": request.get("next_action").cloned().unwrap_or_else(|| json!("none")),
        });
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            "schema://ioi/foundations/work-result/v3",
            &result,
        )
        .map_err(|error| {
            WorkAdmissionError::new(
                "work_result_contract_invalid",
                format!("the admitted WorkResult does not satisfy the current contract: {error}"),
            )
        })?;
        Ok(json!({
            "work_result": result,
            "work_result_hash": hash(&result),
            "admission_receipt_ref": format!("receipt://work-result/{}/admission", result_ref.trim_start_matches("work-result://")),
            "admitted_at": now,
            "retention_disposition": "retained"
        }))
    }

    /// Admit a proposed delta without granting acceptance or executing its
    /// expected effect. The delta inherits every influencing label from its
    /// proposer; a caller may add labels but cannot remove inherited lineage.
    pub fn admit_outcome_delta(
        &self,
        request: &Value,
        inherited_information_flow_label_refs: &[String],
    ) -> AdmissionResult<Value> {
        let delta_ref = required_ref(request, "outcome_delta_id", "outcome-delta://")?;
        let work_subject_ref = required_text(request, "work_subject_ref")?;
        let proposed_by_ref = required_text(request, "proposed_by_ref")?;
        let target_ref = required_text(request, "target_ref")?;
        let payload_ref = required_text(request, "payload_ref")?;
        let kind = required_text(request, "delta_kind")?;
        if !matches!(
            kind,
            "create"
                | "update"
                | "supersede"
                | "reject"
                | "merge"
                | "promote"
                | "rollback"
                | "course_correct"
                | "close"
        ) {
            return Err(WorkAdmissionError::new(
                "outcome_delta_kind_invalid",
                "delta_kind is not canonical",
            ));
        }
        let inherited = inherited_information_flow_label_refs
            .iter()
            .map(|label| {
                let label = label.trim();
                if !label.starts_with("ifc-label://") || label.chars().any(char::is_whitespace) {
                    return Err(WorkAdmissionError::new(
                        "goal_pursuit_ref_invalid",
                        "the inherited parent label set contains an invalid ifc-label:// reference",
                    ));
                }
                Ok(label.to_string())
            })
            .collect::<AdmissionResult<BTreeSet<_>>>()?;
        if inherited.len() != inherited_information_flow_label_refs.len() {
            return Err(WorkAdmissionError::new(
                "goal_pursuit_ref_duplicate",
                "the inherited parent label set contains a duplicate reference",
            ));
        }
        let declared = unique_refs(request, "information_flow_label_refs", "ifc-label://", true)?;
        if inherited.iter().any(|label| !declared.contains(label)) {
            return Err(WorkAdmissionError::new(
                "outcome_delta_label_loss",
                "a delta cannot remove an inherited information-flow label",
            ));
        }
        let record = json!({
            "schema_version":OUTCOME_DELTA_SCHEMA_VERSION,
            "outcome_delta_id":delta_ref,
            "work_subject_ref":work_subject_ref,
            "system_binding":request.get("system_binding").cloned().unwrap_or(Value::Null),
            "proposed_by_ref":proposed_by_ref,
            "target_ref":target_ref,
            "delta_kind":kind,
            "payload_ref":payload_ref,
            "precondition_and_invariant_refs":request.get("precondition_and_invariant_refs").cloned().unwrap_or_else(|| json!([])),
            "expected_effect_ref":request.get("expected_effect_ref").cloned().unwrap_or(Value::Null),
            "verifier_and_acceptance_refs":request.get("verifier_and_acceptance_refs").cloned().unwrap_or_else(|| json!([])),
            "information_flow_label_refs":declared,
            "status":"proposed"
        });
        let outcome_delta_hash = hash(&record);
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            "schema://ioi/foundations/outcome-delta/v3",
            &record,
        )
        .map_err(|error| {
            WorkAdmissionError::new(
                "outcome_delta_contract_invalid",
                format!("the admitted OutcomeDelta does not satisfy the current contract: {error}"),
            )
        })?;
        Ok(json!({
            "outcome_delta":record,
            "outcome_delta_hash":outcome_delta_hash,
            "effect_executed":false,
            "acceptance_granted":false
        }))
    }

    /// Consume one exact declassification approval at the server-side effect
    /// boundary. Invalid/revoked approvals produce durable refusal truth and
    /// never call the external invoker.
    pub fn consume_declassification(&self, request: &Value, now: &str) -> AdmissionResult<Value> {
        let approval_ref = required_ref(request, "approval_ref", "declassification-approval://")?;
        let effect_ref = required_ref(request, "effect_ref", "effect://")?;
        let effect_hash = required_hash(request, "effect_hash")?;
        let grant_ref = required_ref(request, "authority_grant_ref", "grant://")?;
        let labels = unique_refs(
            request,
            "information_flow_label_refs",
            "ifc-label://",
            false,
        )?;
        let status = required_text(request, "status_at_use")?;
        if status != "valid" {
            return Err(WorkAdmissionError::new(
                "declassification_approval_not_current",
                format!("approval status at use is {status}"),
            ));
        }
        Ok(json!({
            "schema_version":"ioi.components.daemon-runtime.declassification-receipt.v1",
            "receipt_id":format!("receipt://declassification/{:x}", Sha256::digest(format!("{approval_ref}\0{effect_hash}").as_bytes())),
            "approval_ref":approval_ref,
            "information_flow_label_refs":labels,
            "runtime_tool_contract_revision_ref":request.get("runtime_tool_contract_revision_ref").cloned().unwrap_or(Value::Null),
            "effect_ref":effect_ref,
            "effect_hash":effect_hash,
            "request_hash":request.get("request_hash").cloned().unwrap_or(Value::Null),
            "reviewed_representation_hash":request.get("reviewed_representation_hash").cloned().unwrap_or(Value::Null),
            "destination":required_text(request,"destination")?,
            "resulting_data_class":required_text(request,"resulting_data_class")?,
            "authority_grant_ref":grant_ref,
            "status_at_use":"valid",
            "decided_at":now
        }))
    }

    /// Bind review evidence to the exact effect at the final invoker. A hash
    /// mismatch is a retained refusal, never a best-effort authorization.
    pub fn admit_authority_effect(&self, request: &Value, now: &str) -> AdmissionResult<Value> {
        let effect_ref = required_ref(request, "actual_effect_ref", "effect://")?;
        let subject_ref = required_ref(request, "subject_ref", "effect://")?;
        let effect_hash = required_hash(request, "actual_effect_hash")?;
        let subject_hash = required_hash(request, "subject_hash")?;
        let current = request.get("authority_current").and_then(Value::as_bool) == Some(true);
        let admitted = current && effect_ref == subject_ref && effect_hash == subject_hash;
        let mut receipt = json!({
            "schema_version":"ioi.components.daemon-runtime.authority-effect-admission-receipt.v1",
            "receipt_id":format!("receipt://authority-effect/{:x}", Sha256::digest(format!("{effect_ref}\0{effect_hash}").as_bytes())),
            "policy_enforcement_point_ref":"runtime://hypervisor-daemon/final-invoker",
            "authorization_subject":{
                "kind":"exact_effect",
                "subject_ref":subject_ref,
                "subject_hash":subject_hash,
                "validation_profile_ref":request.get("validation_profile_ref").cloned().unwrap_or_else(|| json!("schema://ioi/effect/v1"))
            },
            "authority_grant_ref":required_ref(request,"authority_grant_ref","grant://")?,
            "authority_grant_hash":required_hash(request,"authority_grant_hash")?,
            "actual_effect_ref":effect_ref,
            "actual_effect_hash":effect_hash,
            "decision_profile_ref":request.get("decision_profile_ref").cloned().unwrap_or_else(|| json!("policy://effect-admission")),
            "policy_hash":required_hash(request,"policy_hash")?,
            "proof_kind":"exact_equality",
            "decision":if admitted {"admitted"} else {"refused"},
            "refusal_code":if admitted {Value::Null} else if !current {json!("authority_not_current")} else {json!("effect_mismatch")},
            "invoker_called":admitted,
            "decided_at":now
        });
        let body_hash = hash(&receipt);
        receipt
            .as_object_mut()
            .expect("receipt object")
            .insert("body_hash".into(), json!(body_hash));
        let receipt_hash = hash(&receipt);
        receipt
            .as_object_mut()
            .expect("receipt object")
            .insert("receipt_hash".into(), json!(receipt_hash));
        Ok(receipt)
    }

    /// Join labels at an effect boundary. Declassification is explicit,
    /// authority-bound, and can remove only the labels named by an approval.
    pub fn decide_information_flow(&self, request: &Value, now: &str) -> AdmissionResult<Value> {
        let effect_ref = required_ref(request, "effect_ref", "effect://")?;
        let input_labels = unique_refs(request, "input_label_refs", "ifc-label://", false)?;
        let allowed_labels = unique_refs(request, "allowed_label_refs", "ifc-label://", true)?;
        let declassified_labels =
            unique_refs(request, "declassified_label_refs", "ifc-label://", true)?;
        let approval_ref = request
            .get("declassification_approval_ref")
            .and_then(Value::as_str);
        if !declassified_labels.is_empty()
            && !approval_ref.is_some_and(|v| v.starts_with("declassification-approval://"))
        {
            return Err(WorkAdmissionError::new(
                "declassification_approval_required",
                "removing a label requires an exact declassification approval",
            ));
        }
        let declassified: BTreeSet<_> = declassified_labels.iter().cloned().collect();
        if declassified
            .iter()
            .any(|label| !input_labels.contains(label))
        {
            return Err(WorkAdmissionError::new(
                "declassification_label_not_in_input",
                "declassification cannot remove a label that did not influence the input",
            ));
        }
        let effective: Vec<_> = input_labels
            .iter()
            .filter(|label| !declassified.contains(*label))
            .cloned()
            .collect();
        let allowed: BTreeSet<_> = allowed_labels.into_iter().collect();
        let blocked: Vec<_> = effective
            .iter()
            .filter(|label| !allowed.contains(*label))
            .cloned()
            .collect();
        let decision = if blocked.is_empty() {
            "allowed"
        } else {
            "denied"
        };
        Ok(json!({
            "schema_version": IFC_DECISION_SCHEMA_VERSION,
            "receipt_id": format!("receipt://information-flow/{:x}", Sha256::digest(effect_ref.as_bytes())),
            "receipt_profile_ref": "schema://ioi/receipt/information-flow-decision/v1",
            "effect_ref": effect_ref,
            "information_flow_label_refs": input_labels,
            "information_flow_label_content_hashes": request.get("information_flow_label_content_hashes").cloned().unwrap_or_else(|| json!([])),
            "runtime_tool_contract_revision_ref": request.get("runtime_tool_contract_revision_ref").cloned().unwrap_or(Value::Null),
            "destination": request.get("destination").cloned().unwrap_or(Value::Null),
            "request_hash": request.get("request_hash").cloned().unwrap_or(Value::Null),
            "reviewed_representation_hash": request.get("reviewed_representation_hash").cloned().unwrap_or(Value::Null),
            "effective_label_refs": effective,
            "blocked_label_refs": blocked,
            "declassification_approval_ref": approval_ref,
            "declassification_receipt_ref": if declassified_labels.is_empty() { Value::Null } else { json!(format!("receipt://declassification/{:x}", Sha256::digest(effect_ref.as_bytes()))) },
            "decision": decision,
            "reason": if decision == "allowed" { "label_set_permitted_for_destination" } else { "label_set_not_permitted_for_destination" },
            "blocked_before_egress": decision == "denied",
            "enforcement_boundary_ref": "runtime://hypervisor-daemon/pre-effect-ifc",
            "enforcement_owner": "hypervisor_daemon",
            "decided_at": now,
        }))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReceiptCheckpointCore {
    receipts: Vec<Value>,
    leaves: Vec<String>,
    root: String,
}

impl ReceiptCheckpointCore {
    pub fn append(&mut self, receipt: &Value) -> AdmissionResult<String> {
        if receipt.get("schema_version").and_then(Value::as_str)
            != Some("ioi.foundations.receipt-envelope.v1")
        {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_receipt_contract_invalid",
                "only a closed ReceiptEnvelope v1 can enter the v1 accumulator",
            ));
        }
        required_ref(receipt, "receipt_id", "receipt://")?;
        let body_hash = hash(receipt);
        let leaf = hash_bytes(format!(
            "IOI-RECEIPT-ACCUMULATOR-LEAF-V1\0{}",
            canonical(&json!({
                "receipt_contract_id":"schema://ioi/foundations/receipt-envelope/v1",
                "receipt_schema_hash":receipt.get("schema_hash").cloned().unwrap_or(Value::Null),
                "receipt_body_hash":body_hash,
                "signature_domain":"ioi.receipt-accumulator-leaf.v1",
                "index":self.leaves.len()
            }))
        ));
        let prior = if self.leaves.is_empty() {
            empty_receipt_root()
        } else {
            self.root.clone()
        };
        self.root = hash_bytes(format!(
            "IOI-RECEIPT-ACCUMULATOR-STEP-V1\0{}",
            canonical(&json!({"previous_root":prior,"leaf_hash":leaf}))
        ));
        self.receipts.push(receipt.clone());
        self.leaves.push(leaf.clone());
        Ok(leaf)
    }

    pub fn checkpoint(&self, metadata: &Value, keypair: &Ed25519KeyPair) -> AdmissionResult<Value> {
        if self.leaves.is_empty() {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_empty",
                "a checkpoint requires at least one receipt",
            ));
        }
        let checkpoint_id = required_ref(metadata, "checkpoint_id", "receipt-checkpoint://")?;
        let receipt_log_id = required_ref(metadata, "receipt_log_id", "receipt-log://")?;
        let schema_hash = required_hash(metadata, "schema_hash")?;
        let receipt_schema_hash = required_hash(metadata, "receipt_schema_hash")?;
        let issuer_id = required_text(metadata, "issuer_id")?;
        let key_set_ref = required_ref(metadata, "issuer_key_set_ref", "keyset://")?;
        let key_id = required_ref(metadata, "issuer_key_id", "key://")?;
        let build_ref = required_ref(metadata, "build_identity_ref", "build://")?;
        let policy_ref = required_ref(metadata, "policy_posture_ref", "policy://")?;
        let key_set_version = metadata
            .get("issuer_key_set_version")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "receipt_checkpoint_key_set_version_invalid",
                    "issuer_key_set_version must be positive",
                )
            })?;
        let issued_at = metadata
            .get("issued_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "receipt_checkpoint_issued_at_invalid",
                    "issued_at must be an integer timestamp",
                )
            })?;
        let mut checkpoint = json!({
            "schema_version": RECEIPT_CHECKPOINT_SCHEMA_VERSION,
            "checkpoint_type":"ioi.receipt-checkpoint",
            "signature_domain":"ioi.receipt-checkpoint.v1",
            "schema_hash":schema_hash,
            "checkpoint_id":checkpoint_id,
            "receipt_log_id":receipt_log_id,
            "accumulator_algorithm":"ioi.receipt-hash-chain-jcs-sha256.v1",
            "receipt_body_hash_profile":"ioi.receipt-envelope-jcs-sha256.v1",
            "receipt_contract_id":"schema://ioi/foundations/receipt-envelope/v1",
            "receipt_schema_hash":receipt_schema_hash,
            "accumulator_size":self.leaves.len(),
            "accumulator_root":self.root,
            "previous_checkpoint_ref":metadata.get("previous_checkpoint_ref").cloned().unwrap_or(Value::Null),
            "previous_checkpoint_hash":metadata.get("previous_checkpoint_hash").cloned().unwrap_or(Value::Null),
            "previous_accumulator_size":metadata.get("previous_accumulator_size").cloned().unwrap_or(Value::Null),
            "previous_accumulator_root":metadata.get("previous_accumulator_root").cloned().unwrap_or(Value::Null),
            "issuer_id":issuer_id,
            "issuer_key_set_ref":key_set_ref,
            "issuer_key_set_version":key_set_version,
            "issuer_key_id":key_id,
            "issued_at":issued_at,
            "build_identity_ref":build_ref,
            "policy_posture_ref":policy_ref
        });
        let body_hash = hash(&checkpoint);
        checkpoint
            .as_object_mut()
            .expect("checkpoint object")
            .insert("body_hash".into(), json!(body_hash));
        checkpoint
            .as_object_mut()
            .expect("checkpoint object")
            .insert("signature_suite".into(), json!("ed25519"));
        checkpoint
            .as_object_mut()
            .expect("checkpoint object")
            .insert("signature_key_id".into(), json!(key_id));
        let preimage = checkpoint_signature_preimage(&checkpoint)?;
        let signature = keypair.sign(preimage.as_bytes()).map_err(|error| {
            WorkAdmissionError::new("receipt_checkpoint_signing_failed", error.to_string())
        })?;
        checkpoint
            .as_object_mut()
            .expect("checkpoint object")
            .insert(
                "signature".into(),
                json!(URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            );
        Ok(checkpoint)
    }

    pub fn verify_offline(
        checkpoint: &Value,
        receipts: &[Value],
        expected_schema_hash: &str,
        trusted_keys: &BTreeMap<String, Vec<u8>>,
        revoked_keys: &BTreeSet<String>,
    ) -> AdmissionResult<()> {
        if checkpoint.get("schema_hash").and_then(Value::as_str) != Some(expected_schema_hash) {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_schema_hash_stale",
                "checkpoint schema hash is not the locally trusted contract hash",
            ));
        }
        let signer = required_ref(checkpoint, "issuer_key_id", "key://")?;
        let signature_key = required_ref(checkpoint, "signature_key_id", "key://")?;
        if signer != signature_key {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_signature_key_mismatch",
                "signature key does not equal issuer key",
            ));
        }
        let Some(public_key_bytes) = trusted_keys.get(signer) else {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_key_untrusted",
                "checkpoint signer is absent",
            ));
        };
        if revoked_keys.contains(signer) {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_key_untrusted",
                "checkpoint signer is absent or revoked",
            ));
        }
        if checkpoint.get("accumulator_size").and_then(Value::as_u64) != Some(receipts.len() as u64)
        {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_omission",
                "receipt count does not match checkpoint",
            ));
        }
        let mut replay = ReceiptCheckpointCore::default();
        for receipt in receipts {
            replay.append(receipt)?;
        }
        if checkpoint.get("accumulator_root").and_then(Value::as_str) != Some(replay.root.as_str())
        {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_root_mismatch",
                "receipt bytes do not reconstruct the checkpoint root",
            ));
        }
        let mut unsigned = checkpoint.clone();
        let signature_text = unsigned
            .as_object_mut()
            .and_then(|object| object.remove("signature"))
            .and_then(|value| value.as_str().map(str::to_string))
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "receipt_checkpoint_signature_invalid",
                    "checkpoint signature is absent",
                )
            })?;
        unsigned
            .as_object_mut()
            .expect("checkpoint object")
            .remove("signature_suite");
        unsigned
            .as_object_mut()
            .expect("checkpoint object")
            .remove("signature_key_id");
        let claimed_body_hash = unsigned
            .as_object_mut()
            .expect("checkpoint object")
            .remove("body_hash")
            .and_then(|value| value.as_str().map(str::to_string))
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "receipt_checkpoint_body_hash_invalid",
                    "body hash is absent",
                )
            })?;
        if hash(&unsigned) != claimed_body_hash {
            return Err(WorkAdmissionError::new(
                "receipt_checkpoint_body_hash_invalid",
                "checkpoint body hash does not match bytes",
            ));
        }
        let public_key = Ed25519PublicKey::from_bytes(public_key_bytes).map_err(|error| {
            WorkAdmissionError::new("receipt_checkpoint_key_invalid", error.to_string())
        })?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_text).map_err(|error| {
            WorkAdmissionError::new("receipt_checkpoint_signature_invalid", error.to_string())
        })?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes).map_err(|error| {
            WorkAdmissionError::new("receipt_checkpoint_signature_invalid", error.to_string())
        })?;
        public_key
            .verify(
                checkpoint_signature_preimage(checkpoint)?.as_bytes(),
                &signature,
            )
            .map_err(|_| {
                WorkAdmissionError::new(
                    "receipt_checkpoint_signature_invalid",
                    "Ed25519 verification failed",
                )
            })?;
        Ok(())
    }
}

fn empty_receipt_root() -> String {
    hash_bytes("IOI-RECEIPT-ACCUMULATOR-EMPTY-V1\0")
}

fn hash_bytes(bytes: impl AsRef<[u8]>) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes.as_ref()))
}

fn checkpoint_signature_preimage(checkpoint: &Value) -> AdmissionResult<String> {
    Ok(format!(
        "IOI-RECEIPT-CHECKPOINT-V1\0{}",
        canonical(&json!({
            "body_hash":required_hash(checkpoint,"body_hash")?,
            "schema_hash":required_hash(checkpoint,"schema_hash")?,
            "signature_domain":required_text(checkpoint,"signature_domain")?,
            "accumulator_algorithm":required_text(checkpoint,"accumulator_algorithm")?,
            "accumulator_size":checkpoint.get("accumulator_size").and_then(Value::as_u64).ok_or_else(|| WorkAdmissionError::new("receipt_checkpoint_size_invalid","accumulator_size is required"))?,
            "accumulator_root":required_hash(checkpoint,"accumulator_root")?
        }))
    ))
}

#[derive(Debug, Clone, Default)]
pub struct AgentgresBranchCore {
    main_head: String,
    branches: BTreeMap<String, BranchState>,
}

#[derive(Debug, Clone)]
struct BranchState {
    base_head: String,
    branch_head: String,
    staged_effects: Vec<Value>,
    checkpoint_ref: Option<String>,
    merged: bool,
}

impl AgentgresBranchCore {
    pub fn new(main_head: impl Into<String>) -> Self {
        Self {
            main_head: main_head.into(),
            branches: BTreeMap::new(),
        }
    }

    pub fn create_branch(
        &mut self,
        branch_ref: &str,
        expected_main_head: &str,
    ) -> AdmissionResult<Value> {
        if !branch_ref.starts_with("execution-branch://") {
            return Err(WorkAdmissionError::new(
                "agentgres_branch_ref_invalid",
                "branch ref must be typed",
            ));
        }
        if expected_main_head != self.main_head {
            return Err(WorkAdmissionError::new(
                "agentgres_exact_head_conflict",
                "branch base is not the current main head",
            ));
        }
        if self.branches.contains_key(branch_ref) {
            return Err(WorkAdmissionError::new(
                "agentgres_branch_exists",
                "branch identity already exists",
            ));
        }
        let branch_head = hash(&json!({"branch_ref": branch_ref, "base_head": expected_main_head}));
        self.branches.insert(
            branch_ref.into(),
            BranchState {
                base_head: expected_main_head.into(),
                branch_head: branch_head.clone(),
                staged_effects: vec![],
                checkpoint_ref: None,
                merged: false,
            },
        );
        Ok(json!({
            "schema_version":"ioi.agentgres.agent-execution-branch.v1",
            "object_class":"AgentExecutionBranch",
            "execution_branch_ref":branch_ref,
            "run_id":"run://m3-selected-profile",
            "parent_branch_ref":"execution-branch://m3/main",
            "git_ref":Value::Null,
            "workspace_snapshot_ref":"snapshot://m3/branch",
            "worktree_ref":"worktree://m3/branch",
            "memory_projection_refs":[],
            "harness_invocation_refs":[],
            "model_route_refs":[],
            "context_lease_refs":[],
            "authority_refs":[],
            "trace_ref":"trace://m3/branch",
            "head_checkpoint_ref":Value::Null,
            "staged_effect_refs":[],
            "receipt_root":expected_main_head,
            "branch_purpose":"research_attempt",
            "status":"open",
            "branch_head":branch_head
        }))
    }

    pub fn stage_effect(&mut self, branch_ref: &str, effect: &Value) -> AdmissionResult<Value> {
        let branch = self.branches.get_mut(branch_ref).ok_or_else(|| {
            WorkAdmissionError::new("agentgres_branch_missing", "branch is unknown")
        })?;
        if branch.merged {
            return Err(WorkAdmissionError::new(
                "agentgres_branch_closed",
                "merged branches reject new effects",
            ));
        }
        required_ref(effect, "staged_effect_ref", "staged-effect://")?;
        if effect
            .get("information_flow_decision_ref")
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(WorkAdmissionError::new(
                "agentgres_effect_ifc_decision_required",
                "a staged effect requires an information-flow decision",
            ));
        }
        let effect_hash = hash(effect);
        branch.staged_effects.push(effect.clone());
        branch.branch_head = hash(&json!({"prior":branch.branch_head,"effect_hash":effect_hash}));
        Ok(json!({
            "schema_version":"ioi.agentgres.staged-effect.v1",
            "object_class":"StagedEffect",
            "staged_effect_ref":effect.get("staged_effect_ref"),
            "execution_branch_ref":branch_ref,
            "trace_ref":effect.get("trace_ref").cloned().unwrap_or_else(|| json!("trace://m3/branch")),
            "effect_kind":effect.get("effect_kind").cloned().unwrap_or_else(|| json!("custom")),
            "intent_ref":effect.get("intent_ref").cloned().unwrap_or_else(|| json!("artifact://m3/intent")),
            "policy_decision_ref":effect.get("policy_decision_ref").cloned().unwrap_or(Value::Null),
            "authority_decision_ref":effect.get("authority_decision_ref").cloned().unwrap_or(Value::Null),
            "information_flow_decision_ref":effect.get("information_flow_decision_ref"),
            "outcome_ref":effect.get("outcome_ref").cloned().unwrap_or(Value::Null),
            "affected_ref_patterns":effect.get("affected_ref_patterns").cloned().unwrap_or_else(|| json!([])),
            "pre_state_root":effect.get("pre_state_root").cloned().unwrap_or_else(|| json!(branch.base_head)),
            "post_state_root":Value::Null,
            "receipt_refs":effect.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
            "settlement_status":"proposed",
            "effect_hash":effect_hash,
            "branch_head":branch.branch_head,
            "applied":false
        }))
    }

    pub fn checkpoint(&mut self, branch_ref: &str) -> AdmissionResult<Value> {
        let branch = self.branches.get_mut(branch_ref).ok_or_else(|| {
            WorkAdmissionError::new("agentgres_branch_missing", "branch is unknown")
        })?;
        if branch.staged_effects.is_empty() {
            return Err(WorkAdmissionError::new(
                "agentgres_checkpoint_empty",
                "a branch checkpoint requires staged effects",
            ));
        }
        let checkpoint_ref = format!(
            "branch-checkpoint://{:x}",
            Sha256::digest(branch.branch_head.as_bytes())
        );
        branch.checkpoint_ref = Some(checkpoint_ref.clone());
        Ok(json!({
            "schema_version":"ioi.agentgres.branch-checkpoint.v1",
            "object_class":"BranchCheckpoint",
            "branch_checkpoint_ref":checkpoint_ref,
            "execution_branch_ref":branch_ref,
            "trace_ref":"trace://m3/branch",
            "workspace_snapshot_ref":"snapshot://m3/branch",
            "object_heads":{"branch":branch.branch_head},
            "memory_projection_heads":[],
            "lease_heads":[],
            "artifact_refs":[],
            "receipt_root":branch.branch_head,
            "created_for":"verifier",
            "status":"active",
            "staged_effect_count":branch.staged_effects.len()
        }))
    }

    pub fn merge_branch(
        &mut self,
        branch_ref: &str,
        expected_main_head: &str,
    ) -> AdmissionResult<Value> {
        if expected_main_head != self.main_head {
            return Err(WorkAdmissionError::new(
                "agentgres_exact_head_conflict",
                "merge expected head is stale",
            ));
        }
        let branch = self.branches.get_mut(branch_ref).ok_or_else(|| {
            WorkAdmissionError::new("agentgres_branch_missing", "branch is unknown")
        })?;
        if branch.base_head != expected_main_head {
            return Err(WorkAdmissionError::new(
                "agentgres_branch_base_conflict",
                "branch does not descend from the merge head",
            ));
        }
        let checkpoint = branch.checkpoint_ref.clone().ok_or_else(|| {
            WorkAdmissionError::new(
                "agentgres_branch_checkpoint_required",
                "merge requires a branch checkpoint",
            )
        })?;
        if branch.merged {
            return Err(WorkAdmissionError::new(
                "agentgres_branch_already_merged",
                "branch was already merged",
            ));
        }
        let resulting_head = hash(
            &json!({"main_head":self.main_head,"branch_head":branch.branch_head,"checkpoint_ref":checkpoint}),
        );
        branch.merged = true;
        self.main_head = resulting_head.clone();
        Ok(json!({
            "schema_version":"ioi.agentgres.branch-merge-plan.v1",
            "object_class":"BranchMergePlan",
            "branch_merge_ref":format!("branch-merge://{:x}", Sha256::digest(branch_ref.as_bytes())),
            "target_branch_ref":"execution-branch://m3/main",
            "candidate_branch_refs":[branch_ref],
            "diff_refs":[],
            "memory_diff_refs":[],
            "authority_diff_refs":[],
            "receipt_diff_refs":[],
            "verification_refs":[checkpoint],
            "admission_policy_ref":"policy://m3/exact-head-merge",
            "expected_head_ref":checkpoint,
            "authority_revalidation":{"revocation_epoch_checked":"epoch:current","revalidated_at":"2026-07-30T00:00:00Z","stale_or_revoked_effects":[]},
            "decision":"admit",
            "decision_receipt_ref":format!("receipt://agentgres/branch-merge/{:x}", Sha256::digest(branch_ref.as_bytes())),
            "status":"admitted",
            "resulting_main_head":resulting_head,
            "staged_effect_count":branch.staged_effects.len()
        }))
    }

    pub fn append_operation(&mut self, request: &Value) -> AdmissionResult<Value> {
        let operation_id = required_ref(request, "operation_id", "agentgres://operation/")?;
        let expected = request.get("expected_head").and_then(Value::as_str);
        if expected != Some(self.main_head.as_str()) {
            return Err(WorkAdmissionError::new(
                "agentgres_exact_head_conflict",
                "operation expected_head is stale",
            ));
        }
        let body = json!({
            "schema_version":"ioi.agentgres.operation-log-entry.v1",
            "operation_id":operation_id,
            "domain_id":required_ref(request,"domain_id","agentgres://domain/")?,
            "actor_id":required_text(request,"actor_id")?,
            "operation_type":required_text(request,"operation_type")?,
            "object_class":required_text(request,"object_class")?,
            "object_id":required_text(request,"object_id")?,
            "expected_head":expected,
            "expected_heads":request.get("expected_heads").cloned().unwrap_or_else(|| json!({})),
            "base_state_root":request.get("base_state_root").cloned().unwrap_or(Value::Null),
            "policy_hash":required_hash(request,"policy_hash")?,
            "authority_grant_refs":request.get("authority_grant_refs").cloned().unwrap_or_else(|| json!([])),
            "payload":request.get("payload").cloned().unwrap_or_else(|| json!({})),
            "payload_refs":request.get("payload_refs").cloned().unwrap_or_else(|| json!([])),
            "receipt_refs":request.get("receipt_refs").cloned().unwrap_or_else(|| json!([]))
        });
        let resulting_head = hash(&body);
        self.main_head = resulting_head.clone();
        let mut operation = body.as_object().cloned().expect("operation object");
        operation.insert("resulting_head".into(), json!(resulting_head));
        operation.insert(
            "state_root".into(),
            json!(hash(&Value::Object(operation.clone()))),
        );
        Ok(Value::Object(operation))
    }

    pub fn projection_definition(request: &Value) -> AdmissionResult<Value> {
        let projection_id = required_text(request, "projection_id")?;
        let sources = request
            .get("source_objects")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty())
            .ok_or_else(|| {
                WorkAdmissionError::new(
                    "projection_sources_required",
                    "projection sources must be non-empty",
                )
            })?;
        Ok(json!({
            "schema_version":"ioi.agentgres.projection-definition.v1",
            "projection_id":projection_id,
            "source_objects":sources,
            "output_relation":required_text(request,"output_relation")?,
            "refresh_mode":required_text(request,"refresh_mode")?,
            "freshness_slo_ms":request.get("freshness_slo_ms").and_then(Value::as_u64).ok_or_else(|| WorkAdmissionError::new("projection_freshness_required","freshness_slo_ms is required"))?,
            "checkpoint_interval_ops":request.get("checkpoint_interval_ops").and_then(Value::as_u64).filter(|value| *value > 0).ok_or_else(|| WorkAdmissionError::new("projection_checkpoint_interval_invalid","checkpoint interval must be positive"))?
        }))
    }

    pub fn admit_artifact_ref(request: &Value) -> AdmissionResult<Value> {
        required_ref(request, "artifact_id", "artifact://")?;
        required_ref(request, "domain_id", "agentgres://domain/")?;
        required_ref(request, "producing_operation_ref", "agentgres://operation/")?;
        let content = request.get("content").ok_or_else(|| {
            WorkAdmissionError::new(
                "artifact_content_required",
                "artifact content commitment is required",
            )
        })?;
        required_hash(content, "sha256")?;
        let mut artifact = request.clone();
        artifact
            .as_object_mut()
            .ok_or_else(|| {
                WorkAdmissionError::new("artifact_object_required", "artifact must be an object")
            })?
            .insert(
                "schema_version".into(),
                json!("ioi.agentgres.artifact-ref.v1"),
            );
        Ok(artifact)
    }

    pub fn main_head(&self) -> &str {
        &self.main_head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    // R-192 (S5-1): the definition-resolution fixture and the six tests over it stood here, and
    // they went with `resolve_definitions` itself. What they proved is real and is not being
    // dropped as a claim: immutable resolution is stable and inert, a mutable or unhashed
    // definition is refused, and a declared requirement freezes as a LATE BINDING that is never
    // called resolved. All three are statements about resolving a GoalRunProfile's component
    // closure — a profile is the composing application's object, so the code and its tests move
    // to the application with slice S5-3 rather than being re-hosted here under a neutral name.
    // Nothing in this module resolves definitions now, so nothing here tests that it does.

    fn result(outcome: &str, status: &str) -> Value {
        json!({
            "work_result_id":"work-result://research-1",
            "work_subject_ref":"goal://research-1",
            "result_profile":"research",
            "outcome_class":outcome,
            "status":status,
            "result_payload_ref":"artifact://research/report-1",
            "produced_by_ref":"worker://research-1",
            "submitted_by_ref":"worker://research-1",
            "claim_refs":["evidence://claim/1"],
            "uncertainty":"remaining uncertainty",
            "supporting_evidence_refs":["evidence://paper/1"],
            "contradicting_evidence_refs":["evidence://paper/2"],
            "producer_component_resolution":{
                "resolved_component_set_snapshot_ref":"artifact://goal-run/research-1/components",
                "resolved_component_set_hash":H1,
                "component_resolution_receipt_ref":"receipt://goal-run/research-1/profile-resolution",
                "resolver_kind":"harness_profile",
                "resolver_revision_ref":"harness-profile://research/revision/3",
                "resolver_content_hash":H2
            }
        })
    }

    #[test]
    fn research_results_preserve_positive_negative_and_inconclusive_truth() {
        for (outcome, status) in [
            ("positive", "completed"),
            ("negative", "failed"),
            ("inconclusive", "challenged"),
        ] {
            let admitted = WorkAdmissionCore
                .admit_work_result(&result(outcome, status), "2026-07-30T12:00:00Z")
                .unwrap();
            assert_eq!(admitted["work_result"]["outcome_class"], outcome);
            assert_eq!(admitted["retention_disposition"], "retained");
        }
    }

    #[test]
    fn invalid_result_profile_or_missing_provenance_is_refused() {
        let mut request = result("positive", "completed");
        request["result_profile"] = json!("software_implementation");
        assert_eq!(
            WorkAdmissionCore
                .admit_work_result(&request, "now")
                .unwrap_err()
                .code(),
            "work_result_profile_not_selected"
        );
        let mut request = result("positive", "completed");
        request["producer_component_resolution"]
            .as_object_mut()
            .unwrap()
            .remove("component_resolution_receipt_ref");
        assert_eq!(
            WorkAdmissionCore
                .admit_work_result(&request, "now")
                .unwrap_err()
                .code(),
            "goal_pursuit_field_required"
        );
    }

    #[test]
    fn outcome_delta_preserves_inherited_labels_and_grants_no_acceptance() {
        let request = json!({
            "outcome_delta_id":"outcome-delta://research/1","work_subject_ref":"goal://research-1",
            "proposed_by_ref":"work-result://research-1","target_ref":"state://research",
            "delta_kind":"update","payload_ref":"state-delta://research/1",
            "information_flow_label_refs":["ifc-label://internal","ifc-label://research"]
        });
        let inherited = vec!["ifc-label://internal".to_string()];
        let admitted = WorkAdmissionCore
            .admit_outcome_delta(&request, &inherited)
            .unwrap();
        assert_eq!(admitted["effect_executed"], false);
        assert_eq!(admitted["acceptance_granted"], false);
        assert!(admitted["outcome_delta"]
            .get("inherited_information_flow_label_refs")
            .is_none());
        let mut invalid = request;
        invalid["information_flow_label_refs"] = json!([]);
        assert_eq!(
            WorkAdmissionCore
                .admit_outcome_delta(&invalid, &inherited)
                .unwrap_err()
                .code(),
            "outcome_delta_label_loss"
        );
    }

    #[test]
    fn information_flow_denies_unapproved_label_and_permits_explicit_declassification() {
        let denied = json!({"effect_ref":"effect://egress/1","input_label_refs":["ifc-label://private"],"allowed_label_refs":[],"declassified_label_refs":[]});
        assert_eq!(
            WorkAdmissionCore
                .decide_information_flow(&denied, "now")
                .unwrap()["decision"],
            "denied"
        );
        let allowed = json!({"effect_ref":"effect://egress/1","input_label_refs":["ifc-label://private"],"allowed_label_refs":[],"declassified_label_refs":["ifc-label://private"],"declassification_approval_ref":"declassification-approval://review/1"});
        assert_eq!(
            WorkAdmissionCore
                .decide_information_flow(&allowed, "now")
                .unwrap()["decision"],
            "allowed"
        );
    }

    #[test]
    fn implicit_or_foreign_declassification_is_refused() {
        let missing = json!({"effect_ref":"effect://egress/1","input_label_refs":["ifc-label://private"],"allowed_label_refs":[],"declassified_label_refs":["ifc-label://private"]});
        assert_eq!(
            WorkAdmissionCore
                .decide_information_flow(&missing, "now")
                .unwrap_err()
                .code(),
            "declassification_approval_required"
        );
        let foreign = json!({"effect_ref":"effect://egress/1","input_label_refs":["ifc-label://private"],"allowed_label_refs":[],"declassified_label_refs":["ifc-label://secret"],"declassification_approval_ref":"declassification-approval://review/1"});
        assert_eq!(
            WorkAdmissionCore
                .decide_information_flow(&foreign, "now")
                .unwrap_err()
                .code(),
            "declassification_label_not_in_input"
        );
    }

    #[test]
    fn declassification_and_authority_effect_receipts_fail_closed() {
        let declassification = json!({"approval_ref":"declassification-approval://review/1","effect_ref":"effect://egress/1","effect_hash":H1,"authority_grant_ref":"grant://declassify","information_flow_label_refs":["ifc-label://private"],"status_at_use":"valid","destination":"research.example","resulting_data_class":"internal"});
        assert_eq!(
            WorkAdmissionCore
                .consume_declassification(&declassification, "2026-07-30T12:00:00Z")
                .unwrap()["status_at_use"],
            "valid"
        );
        let mut revoked = declassification;
        revoked["status_at_use"] = json!("revoked");
        assert_eq!(
            WorkAdmissionCore
                .consume_declassification(&revoked, "now")
                .unwrap_err()
                .code(),
            "declassification_approval_not_current"
        );

        let request = json!({"actual_effect_ref":"effect://egress/1","actual_effect_hash":H1,"subject_ref":"effect://egress/1","subject_hash":H1,"authority_grant_ref":"grant://egress","authority_grant_hash":H2,"policy_hash":H1,"authority_current":true});
        assert_eq!(
            WorkAdmissionCore
                .admit_authority_effect(&request, "2026-07-30T12:00:00Z")
                .unwrap()["invoker_called"],
            true
        );
        let mut stale = request;
        stale["authority_current"] = json!(false);
        let refused = WorkAdmissionCore
            .admit_authority_effect(&stale, "2026-07-30T12:00:00Z")
            .unwrap();
        assert_eq!(refused["decision"], "refused");
        assert_eq!(refused["invoker_called"], false);
    }

    fn receipt(id: u8) -> Value {
        json!({"schema_version":"ioi.foundations.receipt-envelope.v1","schema_hash":H2,"receipt_id":format!("receipt://r/{id}"),"payload_hash":H1})
    }

    fn checkpoint_metadata() -> Value {
        json!({
            "schema_hash":H1,
            "checkpoint_id":"receipt-checkpoint://c1",
            "receipt_log_id":"receipt-log://m3",
            "receipt_schema_hash":H2,
            "previous_checkpoint_ref":null,
            "previous_checkpoint_hash":null,
            "previous_accumulator_size":null,
            "previous_accumulator_root":null,
            "issuer_id":"system://m3",
            "issuer_key_set_ref":"keyset://m3/1",
            "issuer_key_set_version":1,
            "issuer_key_id":"key://m3/checkpoint",
            "issued_at":1,
            "build_identity_ref":"build://m3/test",
            "policy_posture_ref":"policy://m3/checkpoint"
        })
    }

    #[test]
    fn receipt_checkpoint_reconstructs_offline() {
        let mut core = ReceiptCheckpointCore::default();
        let receipts = vec![receipt(1), receipt(2), receipt(3)];
        for receipt in &receipts {
            core.append(receipt).unwrap();
        }
        let keypair = Ed25519KeyPair::generate().unwrap();
        let checkpoint = core.checkpoint(&checkpoint_metadata(), &keypair).unwrap();
        let trusted = BTreeMap::from([(
            "key://m3/checkpoint".into(),
            keypair.public_key().to_bytes(),
        )]);
        ReceiptCheckpointCore::verify_offline(
            &checkpoint,
            &receipts,
            H1,
            &trusted,
            &BTreeSet::new(),
        )
        .unwrap();
    }

    #[test]
    fn receipt_checkpoint_detects_tamper_omission_and_revocation() {
        let mut core = ReceiptCheckpointCore::default();
        let receipts = vec![receipt(1), receipt(2)];
        for receipt in &receipts {
            core.append(receipt).unwrap();
        }
        let keypair = Ed25519KeyPair::generate().unwrap();
        let checkpoint = core.checkpoint(&checkpoint_metadata(), &keypair).unwrap();
        let trusted = BTreeMap::from([(
            "key://m3/checkpoint".into(),
            keypair.public_key().to_bytes(),
        )]);
        assert_eq!(
            ReceiptCheckpointCore::verify_offline(
                &checkpoint,
                &receipts[..1],
                H1,
                &trusted,
                &BTreeSet::new()
            )
            .unwrap_err()
            .code(),
            "receipt_checkpoint_omission"
        );
        assert_eq!(
            ReceiptCheckpointCore::verify_offline(
                &checkpoint,
                &receipts,
                H1,
                &trusted,
                &BTreeSet::from(["key://m3/checkpoint".into()])
            )
            .unwrap_err()
            .code(),
            "receipt_checkpoint_key_untrusted"
        );
        let mut tampered = receipts.clone();
        tampered[0]["payload_hash"] = json!(H2);
        assert_eq!(
            ReceiptCheckpointCore::verify_offline(
                &checkpoint,
                &tampered,
                H1,
                &trusted,
                &BTreeSet::new()
            )
            .unwrap_err()
            .code(),
            "receipt_checkpoint_root_mismatch"
        );
    }

    #[test]
    fn branch_effects_do_not_apply_before_exact_head_merge() {
        let mut core = AgentgresBranchCore::new(H1);
        core.create_branch("execution-branch://b1", H1).unwrap();
        let staged = core.stage_effect("execution-branch://b1",&json!({"staged_effect_ref":"staged-effect://e1","information_flow_decision_ref":"receipt://ifc/1","outcome_ref":"artifact://a1"})).unwrap();
        assert_eq!(staged["applied"], false);
        assert_eq!(core.main_head(), H1);
        core.checkpoint("execution-branch://b1").unwrap();
        let merged = core.merge_branch("execution-branch://b1", H1).unwrap();
        assert_eq!(merged["status"], "admitted");
        assert_ne!(core.main_head(), H1);
    }

    #[test]
    fn branch_merge_refuses_split_head_and_unlabeled_effect() {
        let mut core = AgentgresBranchCore::new(H1);
        core.create_branch("execution-branch://b1", H1).unwrap();
        assert_eq!(
            core.stage_effect(
                "execution-branch://b1",
                &json!({"staged_effect_ref":"staged-effect://e1"})
            )
            .unwrap_err()
            .code(),
            "agentgres_effect_ifc_decision_required"
        );
        core.stage_effect("execution-branch://b1",&json!({"staged_effect_ref":"staged-effect://e1","information_flow_decision_ref":"receipt://ifc/1"})).unwrap();
        core.checkpoint("execution-branch://b1").unwrap();
        assert_eq!(
            core.merge_branch("execution-branch://b1", H2)
                .unwrap_err()
                .code(),
            "agentgres_exact_head_conflict"
        );
    }

    #[test]
    fn operation_append_is_exact_head_and_projection_is_never_truth() {
        let mut core = AgentgresBranchCore::new(H1);
        let operation = json!({"operation_id":"agentgres://operation/1","domain_id":"agentgres://domain/research","actor_id":"runtime://hypervisor-daemon","operation_type":"RunCreated","object_class":"Run","object_id":"run://research","expected_head":H1,"policy_hash":H2,"authority_grant_refs":["grant://research"],"payload":{},"payload_refs":[],"receipt_refs":[]});
        let admitted = core.append_operation(&operation).unwrap();
        assert_eq!(admitted["resulting_head"], core.main_head());
        assert_eq!(
            core.append_operation(&operation).unwrap_err().code(),
            "agentgres_exact_head_conflict"
        );
        let projection = AgentgresBranchCore::projection_definition(&json!({"projection_id":"research_results","source_objects":["WorkResult"],"output_relation":"research_results","refresh_mode":"nearline_incremental","freshness_slo_ms":500,"checkpoint_interval_ops":100})).unwrap();
        assert_eq!(projection["projection_id"], "research_results");
        assert!(projection.get("state_root").is_none());
    }

    fn isolation_contracts() -> (Value, Value) {
        let requirements: Value = serde_json::from_str(include_str!(
            "../../../../../../docs/architecture/_meta/schemas/fixtures/hypervisor-workload-isolation-requirements-v1/positive-high-risk.json"
        ))
        .unwrap();
        let mut inputs: Value = serde_json::from_str(include_str!(
            "../../../../../../docs/architecture/_meta/schemas/fixtures/hypervisor-workload-isolation-binding-v1/positive-bound.json"
        ))
        .unwrap();
        let object = inputs.as_object_mut().unwrap();
        for daemon_owned in [
            "schema_version",
            "binding_ref",
            "binding_hash",
            "requirements_ref",
            "requirements_hash",
            "workrun_ref",
        ] {
            object.remove(daemon_owned);
        }
        (requirements, inputs)
    }

    #[test]
    fn workrun_isolation_binding_is_daemon_minted_and_lifecycle_stable() {
        let (requirements, inputs) = isolation_contracts();
        let admitted = WorkAdmissionCore
            .admit_workrun_isolation(
                &requirements,
                &inputs,
                "workrun://run-1",
                "2026-07-30T12:00:00Z",
            )
            .unwrap();
        assert_eq!(
            admitted["requirements"]["requirements_hash"],
            admitted["binding"]["requirements_hash"]
        );
        assert_eq!(admitted["binding"]["workrun_ref"], "workrun://run-1");
        assert_eq!(
            admitted["binding"]["runtime_assignment_ref"],
            "runtime-assignment://run-1"
        );
        for transition in ["replay", "cancel", "replacement", "terminal"] {
            assert_eq!(
                WorkAdmissionCore
                    .preserve_workrun_isolation(
                        &admitted,
                        &admitted["binding"],
                        "workrun://run-1",
                        transition,
                    )
                    .unwrap()["preserved"],
                true
            );
        }
    }

    #[test]
    fn workrun_isolation_refuses_downgrade_cross_run_replay_and_tamper() {
        let (requirements, inputs) = isolation_contracts();
        let admitted = WorkAdmissionCore
            .admit_workrun_isolation(
                &requirements,
                &inputs,
                "workrun://run-1",
                "2026-07-30T12:00:00Z",
            )
            .unwrap();
        let mut downgraded = admitted["binding"].clone();
        downgraded["route_policy_ref"] = json!("policy://network/allow-all");
        assert_eq!(
            WorkAdmissionCore
                .preserve_workrun_isolation(
                    &admitted,
                    &downgraded,
                    "workrun://run-1",
                    "replacement",
                )
                .unwrap_err()
                .code(),
            "workload_isolation_binding_substitution_refused"
        );
        assert_eq!(
            WorkAdmissionCore
                .preserve_workrun_isolation(
                    &admitted,
                    &admitted["binding"],
                    "workrun://run-2",
                    "replay",
                )
                .unwrap_err()
                .code(),
            "workload_isolation_workrun_mismatch"
        );
        let mut tampered = admitted;
        tampered["binding"]["output_policy_ref"] = json!("policy://output/unscanned");
        assert_eq!(
            WorkAdmissionCore
                .preserve_workrun_isolation(
                    &tampered,
                    &tampered["binding"],
                    "workrun://run-1",
                    "replay",
                )
                .unwrap_err()
                .code(),
            "workload_isolation_binding_hash_mismatch"
        );
    }
}
