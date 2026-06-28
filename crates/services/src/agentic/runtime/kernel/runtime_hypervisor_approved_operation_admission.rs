//! Hypervisor approved-operation admission planner.
//!
//! A faithful Rust port of the retired JS `admitHypervisorApprovedOperation`
//! (`packages/runtime-daemon/src/runtime-hypervisor-approved-operation-admission.mjs`). Pure
//! validation + canonicalization (no IO): asserts a daemon-authored operation proposal carries the
//! wallet approval/lease + required scopes + Agentgres/receipt/state-root refs and family-specific
//! targets, then emits the admission record + a daemon-owned execution plan. wallet.network
//! approval and Agentgres admission are required before the Hypervisor executes.
//!
//! STATUS: most field-shape errors are 400, but the wallet approval/lease prefixes, required-scope
//! refs, and the proposal-source mismatch reject 403. `uniqueStrings` is the SHARED no-trim variant
//! (but `refsFrom`'s singular goes through optionalString, which trims).

use serde_json::{json, Map, Value};

pub const HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.hypervisor_approved_operation_admission.v1";
pub const HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION: &str =
    "ioi.runtime.hypervisor_approved_operation_execution_plan.v1";

const OPERATION_FAMILIES: &[&str] = &["session", "provider", "project", "automation"];

fn proposal_schema_for_family(family: &str) -> Option<&'static str> {
    match family {
        "session" => Some("ioi.hypervisor.session_operation_proposal.v1"),
        "provider" => Some("ioi.hypervisor.provider_operation_proposal.v1"),
        "project" => Some("ioi.hypervisor.project_operation_proposal.v1"),
        "automation" => Some("ioi.hypervisor.automation_run_proposal.v1"),
        _ => None,
    }
}

fn proposal_source_for_family(family: &str) -> Option<&'static str> {
    match family {
        "session" => Some("daemon-session-operation-proposal"),
        "provider" => Some("daemon-provider-operation-proposal"),
        "project" => Some("daemon-project-operation-proposal"),
        "automation" => Some("daemon-automation-run-proposal"),
        _ => None,
    }
}

const ARCHIVE_REQUIRED_OPERATIONS: &[&str] = &[
    "archive",
    "archive_session",
    "restore",
    "restore_session",
    "zero_to_idle",
];
const RESTORE_REQUIRED_OPERATIONS: &[&str] = &["restore", "restore_session"];

const RETIRED_ALIASES: &[&str] = &[
    "operationFamily",
    "proposalRef",
    "proposalSchemaVersion",
    "proposalSource",
    "walletApprovalRef",
    "walletLeaseRef",
    "requiredScopeRefs",
    "agentgresOperationRefs",
    "receiptRefs",
    "stateRootRef",
    "archiveRef",
    "restoreRef",
];

#[derive(Debug, Clone)]
pub struct RuntimeHypervisorApprovedOperationAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHypervisorApprovedOperationAdmissionError {
    fn new(status: u16, code: &str, message: String, details: Value) -> Self {
        Self {
            status,
            code: code.to_string(),
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimeHypervisorApprovedOperationAdmissionError>;

#[derive(Default)]
pub struct RuntimeHypervisorApprovedOperationAdmissionCore;

impl RuntimeHypervisorApprovedOperationAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let operation_family = enum_value(
            request.get("operation_family"),
            "operation_family",
            OPERATION_FAMILIES,
        )?;
        let proposal_schema_version = required_string(
            request.get("proposal_schema_version"),
            "proposal_schema_version",
            400,
        )?;
        // proposal_source ?? source
        let proposal_source_input = request
            .get("proposal_source")
            .or_else(|| request.get("source"));
        let proposal_source = required_string(proposal_source_input, "proposal_source", 400)?;

        // assertDaemonProposalBoundary
        let expected_schema = proposal_schema_for_family(&operation_family);
        if Some(proposal_schema_version.as_str()) != expected_schema {
            return Err(error_400(
                "hypervisor_approved_operation_schema_mismatch",
                "Approved Hypervisor operation admission requires the proposal schema for its operation family.".to_string(),
                json!({
                    "operation_family": operation_family,
                    "expected_schema_version": expected_schema,
                    "proposal_schema_version": proposal_schema_version,
                }),
            ));
        }
        let expected_source = proposal_source_for_family(&operation_family);
        if Some(proposal_source.as_str()) != expected_source {
            return Err(RuntimeHypervisorApprovedOperationAdmissionError::new(
                403,
                "hypervisor_approved_operation_proposal_source_not_admissible",
                "Approved Hypervisor operation admission only accepts daemon-authored proposals, not fixtures or unverified local projections.".to_string(),
                json!({
                    "operation_family": operation_family,
                    "expected_proposal_source": expected_source,
                    "proposal_source": proposal_source,
                }),
            ));
        }

        let proposal_ref = required_string(request.get("proposal_ref"), "proposal_ref", 400)?;
        let project_ref = required_string(request.get("project_ref"), "project_ref", 400)?;
        let operation_kind = required_string(request.get("operation_kind"), "operation_kind", 400)?;
        let wallet_approval_ref = prefixed_string(
            request.get("wallet_approval_ref"),
            "wallet_approval_ref",
            "approval://wallet/",
            403,
        )?;
        let wallet_lease_ref = prefixed_string(
            request.get("wallet_lease_ref"),
            "wallet_lease_ref",
            "lease:",
            403,
        )?;
        let required_scope_refs = prefixed_refs(
            unique_strings_raw(request.get("required_scope_refs")),
            "required_scope_refs",
            "scope:",
            false,
            403,
        )?;
        let authority_receipt_refs = prefixed_refs(
            unique_strings_raw(request.get("authority_receipt_refs")),
            "authority_receipt_refs",
            "receipt://",
            true,
            400,
        )?;
        let agentgres_operation_refs = prefixed_refs(
            refs_from(
                request.get("agentgres_operation_refs"),
                request.get("agentgres_operation_ref"),
            ),
            "agentgres_operation_refs",
            "agentgres://operation/",
            false,
            400,
        )?;
        let receipt_refs = prefixed_refs(
            refs_from(request.get("receipt_refs"), request.get("receipt_ref")),
            "receipt_refs",
            "receipt://",
            false,
            400,
        )?;
        let state_root_ref = prefixed_string(
            request.get("state_root_ref"),
            "state_root_ref",
            "agentgres://state-root/",
            400,
        )?;
        let artifact_refs = prefixed_refs(
            unique_strings_raw(request.get("artifact_refs")),
            "artifact_refs",
            "artifact://",
            true,
            400,
        )?;
        let archive_ref = optional_value(request.get("archive_ref"));
        let restore_ref = optional_value(request.get("restore_ref"));

        assert_operation_specific_refs(
            &operation_kind,
            archive_ref.as_deref(),
            restore_ref.as_deref(),
        )?;

        let family_targets = family_target_refs(&operation_family, request)?;
        let family_target_ref = family_targets
            .iter()
            .find(|(k, _)| k == "target_ref")
            .map(|(_, v)| v.clone())
            .unwrap_or(Value::Null);
        let target_ref = match optional_value(request.get("target_ref")) {
            Some(value) => Value::String(value),
            None => family_target_ref,
        };

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!(
                "hypervisor-approved-operation:{}:{}",
                safe_id(&operation_family),
                safe_id(&proposal_ref)
            )
        });
        let executor_kind = executor_kind_for(&operation_family);

        let execution_plan = build_execution_plan(BuildExecutionPlan {
            admission_id: &admission_id,
            operation_family: &operation_family,
            proposal_ref: &proposal_ref,
            project_ref: &project_ref,
            family_targets: &family_targets,
            operation_kind: &operation_kind,
            target_ref: &target_ref,
            executor_kind,
            wallet_lease_ref: &wallet_lease_ref,
            required_scope_refs: &required_scope_refs,
            authority_receipt_refs: &authority_receipt_refs,
            agentgres_operation_refs: &agentgres_operation_refs,
            artifact_refs: &artifact_refs,
            receipt_refs: &receipt_refs,
            state_root_ref: &state_root_ref,
            archive_ref: &archive_ref,
            restore_ref: &restore_ref,
        });

        let custody_invariant = optional_value(request.get("custody_invariant")).unwrap_or_else(|| {
            "wallet.network approval and Agentgres admission are required before Hypervisor executes this operation.".to_string()
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        let mut out = Map::new();
        out.insert(
            "schema_version".to_string(),
            json!(HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION),
        );
        out.insert("admission_id".to_string(), json!(admission_id));
        out.insert("operation_family".to_string(), json!(operation_family));
        out.insert("proposal_ref".to_string(), json!(proposal_ref));
        out.insert(
            "proposal_schema_version".to_string(),
            json!(proposal_schema_version),
        );
        out.insert("proposal_source".to_string(), json!(proposal_source));
        out.insert("project_ref".to_string(), json!(project_ref));
        for (key, value) in &family_targets {
            out.insert(key.clone(), value.clone());
        }
        out.insert("operation_kind".to_string(), json!(operation_kind));
        out.insert("target_ref".to_string(), target_ref);
        out.insert("decision".to_string(), json!("admitted"));
        out.insert(
            "execution_status".to_string(),
            json!("admitted_for_execution"),
        );
        out.insert("executor_kind".to_string(), json!(executor_kind));
        out.insert(
            "execution_plan_ref".to_string(),
            execution_plan
                .get("execution_plan_ref")
                .cloned()
                .unwrap_or(Value::Null),
        );
        out.insert(
            "execution_dispatch_ref".to_string(),
            execution_plan
                .get("dispatch_ref")
                .cloned()
                .unwrap_or(Value::Null),
        );
        out.insert("execution_plan".to_string(), execution_plan);
        out.insert(
            "wallet_approval_ref".to_string(),
            json!(wallet_approval_ref),
        );
        out.insert("wallet_lease_ref".to_string(), json!(wallet_lease_ref));
        out.insert(
            "required_scope_refs".to_string(),
            json!(required_scope_refs),
        );
        out.insert(
            "authority_receipt_refs".to_string(),
            json!(authority_receipt_refs),
        );
        out.insert(
            "agentgres_operation_refs".to_string(),
            json!(agentgres_operation_refs),
        );
        out.insert("artifact_refs".to_string(), json!(artifact_refs));
        out.insert("receipt_refs".to_string(), json!(receipt_refs));
        out.insert("state_root_ref".to_string(), json!(state_root_ref));
        out.insert("archive_ref".to_string(), value_or_null(&archive_ref));
        out.insert("restore_ref".to_string(), value_or_null(&restore_ref));
        out.insert("custody_invariant".to_string(), json!(custody_invariant));
        out.insert("admitted_at".to_string(), json!(admitted_at));
        out.insert("runtimeTruthSource".to_string(), json!("daemon-runtime"));

        Ok(Value::Object(out))
    }
}

struct BuildExecutionPlan<'a> {
    admission_id: &'a str,
    operation_family: &'a str,
    proposal_ref: &'a str,
    project_ref: &'a str,
    family_targets: &'a [(String, Value)],
    operation_kind: &'a str,
    target_ref: &'a Value,
    executor_kind: &'a str,
    wallet_lease_ref: &'a str,
    required_scope_refs: &'a [String],
    authority_receipt_refs: &'a [String],
    agentgres_operation_refs: &'a [String],
    artifact_refs: &'a [String],
    receipt_refs: &'a [String],
    state_root_ref: &'a str,
    archive_ref: &'a Option<String>,
    restore_ref: &'a Option<String>,
}

fn build_execution_plan(plan: BuildExecutionPlan) -> Value {
    let plan_ref = format!(
        "execution-plan://hypervisor/{}/{}",
        safe_id(plan.operation_family),
        safe_id(plan.admission_id)
    );
    let dispatch_ref = format!(
        "dispatch://hypervisor/{}/{}",
        safe_id(plan.operation_family),
        safe_id(plan.admission_id)
    );
    let mut out = Map::new();
    out.insert(
        "schema_version".to_string(),
        json!(HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION),
    );
    out.insert("execution_plan_ref".to_string(), json!(plan_ref));
    out.insert("dispatch_ref".to_string(), json!(dispatch_ref));
    out.insert("executor_kind".to_string(), json!(plan.executor_kind));
    out.insert("dispatch_status".to_string(), json!("awaiting_executor"));
    out.insert("operation_family".to_string(), json!(plan.operation_family));
    out.insert("operation_kind".to_string(), json!(plan.operation_kind));
    out.insert("proposal_ref".to_string(), json!(plan.proposal_ref));
    out.insert("admission_id".to_string(), json!(plan.admission_id));
    out.insert("project_ref".to_string(), json!(plan.project_ref));
    for (key, value) in plan.family_targets {
        out.insert(key.clone(), value.clone());
    }
    out.insert("target_ref".to_string(), plan.target_ref.clone());
    out.insert("wallet_lease_ref".to_string(), json!(plan.wallet_lease_ref));
    out.insert(
        "required_scope_refs".to_string(),
        json!(plan.required_scope_refs),
    );
    out.insert(
        "authority_receipt_refs".to_string(),
        json!(plan.authority_receipt_refs),
    );
    out.insert(
        "agentgres_operation_refs".to_string(),
        json!(plan.agentgres_operation_refs),
    );
    out.insert("artifact_refs".to_string(), json!(plan.artifact_refs));
    out.insert("receipt_refs".to_string(), json!(plan.receipt_refs));
    out.insert("state_root_ref".to_string(), json!(plan.state_root_ref));
    out.insert("archive_ref".to_string(), value_or_null(plan.archive_ref));
    out.insert("restore_ref".to_string(), value_or_null(plan.restore_ref));
    out.insert(
        "execution_boundary_invariant".to_string(),
        json!("Approved Hypervisor operations produce daemon-owned execution plans; adapters execute only after wallet authority and Agentgres truth refs are bound."),
    );
    out.insert("runtimeTruthSource".to_string(), json!("daemon-runtime"));
    Value::Object(out)
}

fn executor_kind_for(operation_family: &str) -> &'static str {
    match operation_family {
        "session" => "session_lifecycle_adapter",
        "provider" => "provider_lifecycle_adapter",
        "project" => "project_lifecycle_adapter",
        "automation" => "workflow_compositor_runner",
        _ => "", // unreachable: operation_family is enum-validated
    }
}

fn family_target_refs(
    operation_family: &str,
    request: &Value,
) -> AdmitResult<Vec<(String, Value)>> {
    let opt = |field: &str| -> Value { value_or_null(&optional_value(request.get(field))) };
    let pair = |key: &str, value: Value| (key.to_string(), value);
    match operation_family {
        "session" => Ok(vec![
            pair(
                "session_ref",
                json!(required_string(
                    request.get("session_ref"),
                    "session_ref",
                    400
                )?),
            ),
            pair(
                "environment_ref",
                json!(required_string(
                    request.get("environment_ref"),
                    "environment_ref",
                    400
                )?),
            ),
            pair(
                "provider_candidate_ref",
                json!(required_string(
                    request.get("provider_candidate_ref"),
                    "provider_candidate_ref",
                    400
                )?),
            ),
            pair("candidate_ref", Value::Null),
            pair("direct_provider_ref", Value::Null),
            pair(
                "target_ref",
                json!(required_string(
                    request.get("target_ref"),
                    "target_ref",
                    400
                )?),
            ),
        ]),
        "provider" => {
            let provider_candidate = optional_value(request.get("provider_candidate_ref"))
                .or_else(|| optional_value(request.get("candidate_ref")));
            let target = optional_value(request.get("target_ref"))
                .or_else(|| optional_value(request.get("candidate_ref")));
            Ok(vec![
                pair("session_ref", opt("session_ref")),
                pair("environment_ref", opt("environment_ref")),
                pair("provider_candidate_ref", value_or_null(&provider_candidate)),
                pair(
                    "candidate_ref",
                    json!(required_string(
                        request.get("candidate_ref"),
                        "candidate_ref",
                        400
                    )?),
                ),
                pair(
                    "direct_provider_ref",
                    json!(required_string(
                        request.get("direct_provider_ref"),
                        "direct_provider_ref",
                        400
                    )?),
                ),
                pair("target_ref", value_or_null(&target)),
            ])
        }
        "project" => {
            let target = optional_value(request.get("target_ref"))
                .or_else(|| optional_value(request.get("workspace_ref")));
            Ok(vec![
                pair("session_ref", opt("session_ref")),
                pair("environment_ref", opt("environment_ref")),
                pair("provider_candidate_ref", opt("provider_candidate_ref")),
                pair("candidate_ref", Value::Null),
                pair("direct_provider_ref", Value::Null),
                pair(
                    "workspace_ref",
                    json!(required_string(
                        request.get("workspace_ref"),
                        "workspace_ref",
                        400
                    )?),
                ),
                pair("target_ref", value_or_null(&target)),
            ])
        }
        "automation" => {
            let launch_action_input = request
                .get("launch_action_ref")
                .or_else(|| request.get("action_proposal_ref"));
            let launch_action_ref = required_string(launch_action_input, "launch_action_ref", 400)?;
            let target = optional_value(request.get("target_ref"))
                .unwrap_or_else(|| launch_action_ref.clone());
            Ok(vec![
                pair("session_ref", opt("session_ref")),
                pair("environment_ref", opt("environment_ref")),
                pair("provider_candidate_ref", opt("provider_candidate_ref")),
                pair("candidate_ref", Value::Null),
                pair("direct_provider_ref", Value::Null),
                pair(
                    "template_ref",
                    json!(required_string(
                        request.get("template_ref"),
                        "template_ref",
                        400
                    )?),
                ),
                pair(
                    "run_recipe_ref",
                    json!(required_string(
                        request.get("run_recipe_ref"),
                        "run_recipe_ref",
                        400
                    )?),
                ),
                pair("graph_ref", opt("graph_ref")),
                pair("launch_action_ref", json!(launch_action_ref)),
                pair("action_proposal_ref", json!(launch_action_ref)),
                pair(
                    "context_chamber_refs",
                    json!(unique_strings_raw(request.get("context_chamber_refs"))),
                ),
                pair("target_ref", json!(target)),
            ])
        }
        _ => Err(required_field_error("operation_family", 400)),
    }
}

fn assert_operation_specific_refs(
    operation_kind: &str,
    archive_ref: Option<&str>,
    restore_ref: Option<&str>,
) -> AdmitResult<()> {
    if ARCHIVE_REQUIRED_OPERATIONS.contains(&operation_kind) && archive_ref.is_none() {
        return Err(error_400(
            "hypervisor_approved_operation_archive_ref_required",
            "Archive, restore, and zero-to-idle Hypervisor operations require an Agentgres-governed archive ref.".to_string(),
            json!({ "operation_kind": operation_kind, "required": "archive_ref" }),
        ));
    }
    if let Some(archive_ref) = archive_ref {
        if !archive_ref.starts_with("artifact://") {
            return Err(error_400(
                "hypervisor_approved_operation_archive_ref_prefix_invalid",
                "Archive refs for approved Hypervisor operations must be Agentgres-governed artifact refs.".to_string(),
                json!({ "operation_kind": operation_kind, "archive_ref": archive_ref, "expected_prefix": "artifact://" }),
            ));
        }
    }
    if RESTORE_REQUIRED_OPERATIONS.contains(&operation_kind) && restore_ref.is_none() {
        return Err(error_400(
            "hypervisor_approved_operation_restore_ref_required",
            "Restore Hypervisor operations require an Agentgres restore ref before execution admission.".to_string(),
            json!({ "operation_kind": operation_kind, "required": "restore_ref" }),
        ));
    }
    if let Some(restore_ref) = restore_ref {
        if !restore_ref.starts_with("agentgres://restore/") {
            return Err(error_400(
                "hypervisor_approved_operation_restore_ref_prefix_invalid",
                "Restore refs for approved Hypervisor operations must be Agentgres restore refs."
                    .to_string(),
                json!({ "operation_kind": operation_kind, "restore_ref": restore_ref, "expected_prefix": "agentgres://restore/" }),
            ));
        }
    }
    Ok(())
}

/// Mirror JS `refsFrom(plural, singular)`: normalizeArray(plural) raw + optionalString(singular)
/// (trimmed, if non-empty), then uniqueStrings (no-trim String() coerce + dedup).
fn refs_from(plural: Option<&Value>, singular: Option<&Value>) -> Vec<String> {
    let mut combined: Vec<Value> = normalize_array_raw(plural);
    if let Some(singular) = optional_value(singular) {
        combined.push(Value::String(singular));
    }
    unique_strings_from_values(&combined)
}

fn prefixed_refs(
    refs: Vec<String>,
    field: &str,
    prefix: &str,
    allow_empty: bool,
    status: u16,
) -> AdmitResult<Vec<String>> {
    if !allow_empty && refs.is_empty() {
        return Err(RuntimeHypervisorApprovedOperationAdmissionError::new(
            status,
            "hypervisor_approved_operation_required_refs_missing",
            format!("Approved Hypervisor operation admission requires {field}."),
            json!({ "field": field }),
        ));
    }
    for reference in &refs {
        if !reference.starts_with(prefix) {
            return Err(RuntimeHypervisorApprovedOperationAdmissionError::new(
                status,
                "hypervisor_approved_operation_ref_prefix_invalid",
                format!("{field} must use {prefix} refs."),
                json!({ "field": field, "ref": reference, "expected_prefix": prefix }),
            ));
        }
    }
    Ok(refs)
}

fn prefixed_string(
    value: Option<&Value>,
    field: &str,
    prefix: &str,
    status: u16,
) -> AdmitResult<String> {
    let text = required_string(value, field, status)?;
    if !text.starts_with(prefix) {
        return Err(RuntimeHypervisorApprovedOperationAdmissionError::new(
            status,
            "hypervisor_approved_operation_ref_prefix_invalid",
            format!("{field} must use a {prefix} ref."),
            json!({ "field": field, "ref": text, "expected_prefix": prefix }),
        ));
    }
    Ok(text)
}

fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let text = required_string(value, field, 400)?;
    if !allowed.contains(&text.as_str()) {
        return Err(error_400(
            "hypervisor_approved_operation_enum_invalid",
            format!("{field} is not a supported Hypervisor approved-operation value."),
            json!({ "field": field, "value": text, "allowed": allowed }),
        ));
    }
    Ok(text)
}

fn required_string(value: Option<&Value>, field: &str, status: u16) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| required_field_error(field, status))
}

fn required_field_error(
    field: &str,
    status: u16,
) -> RuntimeHypervisorApprovedOperationAdmissionError {
    RuntimeHypervisorApprovedOperationAdmissionError::new(
        status,
        "hypervisor_approved_operation_required_field_missing",
        format!("Approved Hypervisor operation admission requires {field}."),
        json!({ "field": field }),
    )
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let present: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(error_400(
        "hypervisor_approved_operation_retired_alias",
        "Approved Hypervisor operation admission accepts snake_case fields only.".to_string(),
        json!({ "retired_aliases": present }),
    ))
}

fn error_400(
    code: &str,
    message: String,
    details: Value,
) -> RuntimeHypervisorApprovedOperationAdmissionError {
    RuntimeHypervisorApprovedOperationAdmissionError::new(400, code, message, details)
}

fn value_or_null(value: &Option<String>) -> Value {
    match value {
        Some(value) => Value::String(value.clone()),
        None => Value::Null,
    }
}

fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => {
            let coerced = js_string_coerce(value);
            let trimmed = js_trim(&coerced);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

/// Mirror the SHARED `uniqueStrings(normalizeArray(value))` (NO trim).
fn unique_strings_raw(value: Option<&Value>) -> Vec<String> {
    unique_strings_from_values(&normalize_array_raw(value))
}

/// Mirror the SHARED `uniqueStrings(values)`: String()-coerce (no trim), drop blanks, first-seen.
fn unique_strings_from_values(values: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in values {
        if !is_truthy(item) {
            continue;
        }
        let coerced = js_string_coerce(item);
        if coerced.is_empty() {
            continue;
        }
        if !out.contains(&coerced) {
            out.push(coerced);
        }
    }
    out
}

fn normalize_array_raw(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| is_truthy(item))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn js_string_coerce(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => js_number_to_string(number.as_f64().unwrap_or(0.0)),
        Value::String(string) => string.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string_coerce(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    let exp_form = format!("{magnitude:e}");
    let (mantissa, exp_str) = exp_form.split_once('e').unwrap_or((exp_form.as_str(), "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;

    let body = if k <= n && n <= 21 {
        let mut out = digits;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        let (head, tail) = digits.split_at(n as usize);
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
        out
    } else {
        let mut chars = digits.chars();
        let first = chars.next().unwrap_or('0');
        let rest: String = chars.collect();
        let mut out = String::new();
        out.push(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
            out.push_str(&e.to_string());
        } else {
            out.push('-');
            out.push_str(&(-e).to_string());
        }
        out
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_request() -> Value {
        json!({
            "operation_family": "session",
            "proposal_schema_version": "ioi.hypervisor.session_operation_proposal.v1",
            "proposal_source": "daemon-session-operation-proposal",
            "proposal_ref": "proposal:session/1",
            "project_ref": "project:ioi",
            "operation_kind": "start_session",
            "wallet_approval_ref": "approval://wallet/session/1",
            "wallet_lease_ref": "lease:wallet/session/1",
            "required_scope_refs": ["scope:session.start"],
            "agentgres_operation_refs": ["agentgres://operation/session/1"],
            "receipt_refs": ["receipt://session/1"],
            "state_root_ref": "agentgres://state-root/session/1",
            "session_ref": "session:1",
            "environment_ref": "environment:1",
            "provider_candidate_ref": "provider-candidate:1",
            "target_ref": "session:1",
        })
    }

    #[test]
    fn admits_session_operation() {
        let admission = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&session_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["executor_kind"], "session_lifecycle_adapter");
        assert_eq!(admission["candidate_ref"], Value::Null);
        assert_eq!(
            admission["admission_id"],
            "hypervisor-approved-operation:session:proposal_session_1"
        );
        let plan = &admission["execution_plan"];
        assert_eq!(
            plan["schema_version"],
            HYPERVISOR_APPROVED_OPERATION_EXECUTION_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan["dispatch_status"], "awaiting_executor");
        assert_eq!(admission["execution_plan_ref"], plan["execution_plan_ref"]);
        assert_eq!(admission["execution_dispatch_ref"], plan["dispatch_ref"]);
    }

    #[test]
    fn rejects_proposal_source_mismatch() {
        let mut request = session_request();
        request["proposal_source"] = json!("local-fixture");
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "hypervisor_approved_operation_proposal_source_not_admissible"
        );
    }

    #[test]
    fn rejects_schema_mismatch() {
        let mut request = session_request();
        request["proposal_schema_version"] = json!("ioi.hypervisor.provider_operation_proposal.v1");
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "hypervisor_approved_operation_schema_mismatch");
    }

    #[test]
    fn wallet_approval_prefix_is_403() {
        let mut request = session_request();
        request["wallet_approval_ref"] = json!("approval://other/1");
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "hypervisor_approved_operation_ref_prefix_invalid"
        );
    }

    #[test]
    fn required_scope_missing_is_403() {
        let mut request = session_request();
        request["required_scope_refs"] = json!([]);
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "hypervisor_approved_operation_required_refs_missing"
        );
    }

    #[test]
    fn admits_automation_with_launch_action_alias() {
        let admission = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(
                &json!({
                    "operation_family": "automation",
                    "proposal_schema_version": "ioi.hypervisor.automation_run_proposal.v1",
                    "proposal_source": "daemon-automation-run-proposal",
                    "proposal_ref": "proposal:auto/1",
                    "project_ref": "project:ioi",
                    "operation_kind": "run_automation",
                    "wallet_approval_ref": "approval://wallet/auto/1",
                    "wallet_lease_ref": "lease:wallet/auto/1",
                    "required_scope_refs": ["scope:automation.run"],
                    "agentgres_operation_refs": ["agentgres://operation/auto/1"],
                    "receipt_refs": ["receipt://auto/1"],
                    "state_root_ref": "agentgres://state-root/auto/1",
                    "template_ref": "template:1",
                    "run_recipe_ref": "run-recipe:1",
                    "action_proposal_ref": "action:1",
                }),
                "now",
            )
            .expect("admitted");
        assert_eq!(admission["executor_kind"], "workflow_compositor_runner");
        assert_eq!(admission["launch_action_ref"], "action:1");
        assert_eq!(admission["action_proposal_ref"], "action:1");
        assert_eq!(admission["target_ref"], "action:1");
    }

    #[test]
    fn archive_required_for_zero_to_idle() {
        let mut request = session_request();
        request["operation_kind"] = json!("zero_to_idle");
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(
            error.code,
            "hypervisor_approved_operation_archive_ref_required"
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = session_request();
        request["proposalRef"] = json!("legacy");
        let error = RuntimeHypervisorApprovedOperationAdmissionCore
            .admit(&request, "now")
            .expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "hypervisor_approved_operation_retired_alias");
    }
}
