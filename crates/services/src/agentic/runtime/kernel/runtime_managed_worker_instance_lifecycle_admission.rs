//! Managed-worker-instance-lifecycle admission planner.
//!
//! A faithful Rust port of the retired JS `admitManagedWorkerInstanceLifecycleTransition`
//! (`packages/runtime-daemon/src/runtime-managed-worker-instance-lifecycle-admission.mjs`). Pure
//! validation: a managed worker instance state transition is admitted only when it is permitted by
//! the canonical lifecycle state machine and its per-target-state authority / archive / restore /
//! export / deletion / payment-lapse controls + policies + receipts are bound.
//!
//! HELPER NOTE: this module's LOCAL `uniqueStrings` TRIMS each item (`String(v).trim()`), unlike
//! worker-package-install's no-trim variant — so unique_strings_trim uses js_trim. STATUS: field-
//! shape helpers (required/enum/prefix/scope) reject 400; lifecycle/policy assertions reject 403.

use serde_json::{json, Map, Value};

pub const MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.managed_worker_instance_lifecycle_admission.v1";

const LIFECYCLE_STATES: &[&str] = &[
    "discover",
    "installed",
    "initializing",
    "active",
    "idle",
    "zero_to_idle",
    "suspended",
    "payment_past_due",
    "archived",
    "restoring",
    "migrated",
    "exported",
    "deleted",
    "forgotten",
];

const PERSISTENCE_PROFILES: &[&str] = &["ephemeral", "session", "zero_to_idle", "persistent"];

const PAYMENT_STATUSES: &[&str] =
    &["current", "past_due", "canceled", "settled", "not_applicable"];

/// The canonical lifecycle state machine: the set of states each from-state may transition to.
fn allowed_transitions(from_state: &str) -> Option<&'static [&'static str]> {
    Some(match from_state {
        "discover" => &["installed"],
        "installed" => &["initializing", "deleted"],
        "initializing" => &["active", "suspended", "deleted"],
        "active" => &["idle", "suspended", "payment_past_due", "archived", "migrated", "exported", "deleted"],
        "idle" => &["active", "zero_to_idle", "suspended", "payment_past_due", "archived", "migrated", "exported", "deleted"],
        "zero_to_idle" => &["active", "suspended", "payment_past_due", "archived", "migrated", "exported", "deleted"],
        "suspended" => &["active", "payment_past_due", "archived", "exported", "deleted"],
        "payment_past_due" => &["active", "suspended", "zero_to_idle", "archived", "exported", "deleted"],
        "archived" => &["restoring", "exported", "deleted", "forgotten"],
        "restoring" => &["active", "archived"],
        "migrated" => &["active", "archived", "exported", "deleted"],
        "exported" => &["active", "archived", "deleted", "forgotten"],
        "deleted" => &["forgotten"],
        "forgotten" => &[],
        _ => return None,
    })
}

const RETIRED_ALIASES: &[&str] = &[
    "lifecycleId",
    "workerInstanceId",
    "ownerRef",
    "fromState",
    "toState",
    "archiveRefs",
    "receiptRefs",
    "agentgresOperationRefs",
];

#[derive(Debug, Clone)]
pub struct RuntimeManagedWorkerInstanceLifecycleAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeManagedWorkerInstanceLifecycleAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self { status, code, message, details }
    }
}

type AdmitResult<T> = Result<T, RuntimeManagedWorkerInstanceLifecycleAdmissionError>;

#[derive(Default)]
pub struct RuntimeManagedWorkerInstanceLifecycleAdmissionCore;

impl RuntimeManagedWorkerInstanceLifecycleAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let lifecycle_id = required_string(request.get("lifecycle_id"), "lifecycle_id")?;
        let worker_instance_id = required_string(request.get("worker_instance_id"), "worker_instance_id")?;
        let worker_package_ref = optional_value(request.get("worker_package_ref"));
        let owner_ref = required_string(request.get("owner_ref"), "owner_ref")?;
        let from_state = enum_value(request.get("from_state"), "from_state", LIFECYCLE_STATES)?;
        let to_state = enum_value(request.get("to_state"), "to_state", LIFECYCLE_STATES)?;
        let persistence_profile =
            enum_value(request.get("persistence_profile"), "persistence_profile", PERSISTENCE_PROFILES)?;
        let payment_status = enum_value(
            Some(&default_value(request.get("payment_status"), "not_applicable")),
            "payment_status",
            PAYMENT_STATUSES,
        )?;
        let transition_reason =
            optional_value(request.get("transition_reason")).unwrap_or_else(|| "operator_request".to_string());
        let authority_scope_refs = unique_scope_refs(request.get("authority_scope_refs"))?;
        let authority_grant_refs = unique_strings_trim(request.get("authority_grant_refs"));
        let policy_refs = unique_strings_trim(request.get("policy_refs"));
        let archive_refs = unique_strings_trim(request.get("archive_refs"));
        let artifact_refs = unique_strings_trim(request.get("artifact_refs"));
        let receipt_refs = unique_strings_trim(request.get("receipt_refs"));
        let agentgres_operation_refs = unique_strings_trim(request.get("agentgres_operation_refs"));
        let required_controls = unique_strings_trim(request.get("required_controls"));
        let latest_state_root = optional_value(request.get("latest_state_root"));
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let restore_import_ref = optional_value(request.get("restore_import_ref"));
        let migration_target_ref = optional_value(request.get("migration_target_ref"));
        let archive_policy = object_record(request.get("archive_policy"));
        let restore_policy = object_record(request.get("restore_policy"));
        let export_policy = object_record(request.get("export_policy"));
        let deletion_policy = object_record(request.get("deletion_policy"));
        let high_risk_orders_paused = boolean_value(request.get("high_risk_orders_paused")).unwrap_or(false);
        let new_billable_work_blocked = boolean_value(request.get("new_billable_work_blocked")).unwrap_or(false);

        // assertLifecycleTransition.
        let allowed = allowed_transitions(&from_state);
        if !allowed.map(|states| states.contains(&to_state.as_str())).unwrap_or(false) {
            return Err(authority_error(
                "managed_worker_lifecycle_transition_invalid",
                "Managed worker lifecycle transition is not permitted by the canonical state machine.",
                json!({ "from_state": from_state, "to_state": to_state }),
            ));
        }
        require_prefix(&lifecycle_id, "lifecycle:", "lifecycle_id")?;
        require_prefix(&worker_instance_id, "agent://", "worker_instance_id")?;
        require_prefix(&owner_ref, "wallet://", "owner_ref")?;
        require_agentgres_and_receipt(&agentgres_operation_refs, &receipt_refs, &to_state)?;

        if to_state == "payment_past_due" {
            if payment_status != "past_due" {
                return Err(authority_error(
                    "managed_worker_lifecycle_payment_status_invalid",
                    "Payment-past-due transitions must carry payment_status=past_due.",
                    json!({ "payment_status": payment_status }),
                ));
            }
            require_control(&required_controls, "freeze_new_billable_work", &to_state)?;
            require_control(&required_controls, "pause_high_risk_standing_orders", &to_state)?;
            if !new_billable_work_blocked || !high_risk_orders_paused {
                return Err(authority_error(
                    "managed_worker_lifecycle_lapse_freeze_required",
                    "Payment lapse must freeze new billable work and pause high-risk standing orders.",
                    json!({
                        "new_billable_work_blocked": new_billable_work_blocked,
                        "high_risk_orders_paused": high_risk_orders_paused,
                    }),
                ));
            }
        }

        if transition_reason == "payment_lapse" && matches!(to_state.as_str(), "deleted" | "forgotten") {
            return Err(authority_error(
                "managed_worker_lifecycle_lapse_delete_blocked",
                "Payment lapse cannot silently delete or forget user-owned worker context.",
                json!({ "from_state": from_state, "to_state": to_state }),
            ));
        }

        if to_state == "zero_to_idle" {
            if persistence_profile != "zero_to_idle" && persistence_profile != "persistent" {
                return Err(authority_error(
                    "managed_worker_lifecycle_zero_to_idle_profile_invalid",
                    "Zero-to-idle transitions require zero_to_idle or persistent persistence profile.",
                    json!({ "persistence_profile": persistence_profile }),
                ));
            }
            require_state_root(latest_state_root.as_deref(), &to_state)?;
        }

        if to_state == "archived" {
            require_archive_refs(&archive_refs, &to_state)?;
            if artifact_refs.is_empty() {
                return Err(authority_error(
                    "managed_worker_lifecycle_artifact_ref_required",
                    "Archive transitions require Agentgres artifact refs.",
                    json!({ "to_state": to_state }),
                ));
            }
            require_state_root(latest_state_root.as_deref(), &to_state)?;
            if !policy_field_truthy(archive_policy, "storage_policy_ref") {
                return Err(authority_error(
                    "managed_worker_lifecycle_archive_policy_required",
                    "Archive transitions require archive_policy.storage_policy_ref.",
                    json!({ "archive_policy": policy_or_null(archive_policy) }),
                ));
            }
            require_control(&required_controls, "agentgres_archive_ref", &to_state)?;
        }

        if to_state == "restoring" {
            require_archive_refs(&archive_refs, &to_state)?;
            require_scope(&authority_scope_refs, "scope:worker.restore", &to_state)?;
            require_wallet_approval(wallet_approval_ref.as_deref(), &to_state)?;
            if restore_import_ref.is_none() {
                return Err(authority_error(
                    "managed_worker_lifecycle_restore_import_ref_required",
                    "Restore transitions require an Agentgres-backed restore import ref.",
                    json!({ "to_state": to_state }),
                ));
            }
            if !policy_field_is_true(restore_policy, "restore_receipt_required") {
                return Err(authority_error(
                    "managed_worker_lifecycle_restore_receipt_policy_required",
                    "Restore policy must require restore receipts.",
                    json!({ "restore_policy": policy_or_null(restore_policy) }),
                ));
            }
        }

        if to_state == "migrated" {
            require_archive_refs(&archive_refs, &to_state)?;
            require_scope(&authority_scope_refs, "scope:worker.migrate", &to_state)?;
            if migration_target_ref.is_none() {
                return Err(authority_error(
                    "managed_worker_lifecycle_migration_target_required",
                    "Migration transitions require a migration target ref.",
                    json!({ "to_state": to_state }),
                ));
            }
        }

        if to_state == "exported" {
            require_scope(&authority_scope_refs, "scope:worker.export", &to_state)?;
            require_wallet_approval(wallet_approval_ref.as_deref(), &to_state)?;
            if !policy_field_truthy(export_policy, "export_requires") {
                return Err(authority_error(
                    "managed_worker_lifecycle_export_policy_required",
                    "Export transitions require an explicit export policy.",
                    json!({ "export_policy": policy_or_null(export_policy) }),
                ));
            }
        }

        if to_state == "deleted" {
            require_scope(&authority_scope_refs, "scope:worker.delete", &to_state)?;
            require_wallet_approval(wallet_approval_ref.as_deref(), &to_state)?;
            if deletion_policy.is_none() {
                return Err(authority_error(
                    "managed_worker_lifecycle_deletion_policy_required",
                    "Delete transitions require explicit deletion policy.",
                    json!({ "to_state": to_state }),
                ));
            }
        }

        if to_state == "forgotten" {
            require_scope(&authority_scope_refs, "scope:worker.forget", &to_state)?;
            require_wallet_approval(wallet_approval_ref.as_deref(), &to_state)?;
            if !policy_field_is_true(deletion_policy, "forget_semantic_memory") {
                return Err(authority_error(
                    "managed_worker_lifecycle_forget_policy_required",
                    "Forget transitions require deletion_policy.forget_semantic_memory=true.",
                    json!({ "deletion_policy": policy_or_null(deletion_policy) }),
                ));
            }
        }

        let transition_id = optional_value(request.get("transition_id")).unwrap_or_else(|| {
            format!(
                "managed-worker-lifecycle:{}:{}-{}",
                safe_id(&lifecycle_id),
                safe_id(&from_state),
                safe_id(&to_state)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "schema_version": MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION,
            "transition_id": transition_id,
            "lifecycle_id": lifecycle_id,
            "worker_instance_id": worker_instance_id,
            "worker_package_ref": worker_package_ref,
            "owner_ref": owner_ref,
            "from_state": from_state,
            "to_state": to_state,
            "state": to_state,
            "persistence_profile": persistence_profile,
            "payment_status": payment_status,
            "transition_reason": transition_reason,
            "freezes_new_billable_work": to_state == "payment_past_due" || new_billable_work_blocked,
            "pauses_high_risk_standing_orders": to_state == "payment_past_due" || high_risk_orders_paused,
            "latest_state_root": latest_state_root,
            "archive_policy": policy_or_null(archive_policy),
            "restore_policy": policy_or_null(restore_policy),
            "export_policy": policy_or_null(export_policy),
            "deletion_policy": policy_or_null(deletion_policy),
            "archive_refs": archive_refs,
            "artifact_refs": artifact_refs,
            "authority_scope_refs": authority_scope_refs,
            "authority_grant_refs": authority_grant_refs,
            "policy_refs": policy_refs,
            "wallet_approval_ref": wallet_approval_ref,
            "restore_import_ref": restore_import_ref,
            "migration_target_ref": migration_target_ref,
            "agentgres_operation_refs": agentgres_operation_refs,
            "receipt_refs": receipt_refs,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        }))
    }
}

fn require_agentgres_and_receipt(
    agentgres_operation_refs: &[String],
    receipt_refs: &[String],
    to_state: &str,
) -> AdmitResult<()> {
    if agentgres_operation_refs.is_empty() {
        return Err(authority_error(
            "managed_worker_lifecycle_agentgres_operation_required",
            "Managed worker lifecycle transitions require Agentgres operation refs.",
            json!({ "to_state": to_state }),
        ));
    }
    if receipt_refs.is_empty() {
        return Err(authority_error(
            "managed_worker_lifecycle_receipt_required",
            "Managed worker lifecycle transitions require receipts.",
            json!({ "to_state": to_state }),
        ));
    }
    Ok(())
}

fn require_archive_refs(archive_refs: &[String], to_state: &str) -> AdmitResult<()> {
    if !archive_refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        "managed_worker_lifecycle_archive_ref_required",
        "Managed worker lifecycle transition requires archive refs.",
        json!({ "to_state": to_state }),
    ))
}

fn require_state_root(latest_state_root: Option<&str>, to_state: &str) -> AdmitResult<()> {
    if latest_state_root.is_some() {
        return Ok(());
    }
    Err(authority_error(
        "managed_worker_lifecycle_state_root_required",
        "Managed worker lifecycle transition requires a latest state root.",
        json!({ "to_state": to_state }),
    ))
}

fn require_wallet_approval(wallet_approval_ref: Option<&str>, to_state: &str) -> AdmitResult<()> {
    if wallet_approval_ref.is_some() {
        return Ok(());
    }
    Err(authority_error(
        "managed_worker_lifecycle_wallet_approval_required",
        "Managed worker lifecycle transition requires wallet approval.",
        json!({ "to_state": to_state }),
    ))
}

fn require_control(required_controls: &[String], control: &str, to_state: &str) -> AdmitResult<()> {
    if required_controls.iter().any(|value| value == control) {
        return Ok(());
    }
    Err(authority_error(
        "managed_worker_lifecycle_required_control_missing",
        "Managed worker lifecycle transition is missing a required control.",
        json!({ "to_state": to_state, "required_control": control }),
    ))
}

fn require_scope(authority_scope_refs: &[String], scope: &str, to_state: &str) -> AdmitResult<()> {
    if authority_scope_refs.iter().any(|value| value == scope) {
        return Ok(());
    }
    Err(authority_error(
        "managed_worker_lifecycle_required_scope_missing",
        "Managed worker lifecycle transition is missing a required authority scope.",
        json!({ "to_state": to_state, "required_scope": scope }),
    ))
}

fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(
        400,
        format!("managed_worker_lifecycle_{field}_invalid"),
        format!("Managed worker lifecycle {field} must start with {prefix}."),
        Value::Object(details),
    ))
}

fn unique_scope_refs(value: Option<&Value>) -> AdmitResult<Vec<String>> {
    let scopes = unique_strings_trim(value);
    for scope in &scopes {
        if !scope.starts_with("scope:") {
            return Err(RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(
                400,
                "managed_worker_lifecycle_scope_invalid".to_string(),
                "Managed worker lifecycle authority scopes must use scope:* refs.".to_string(),
                json!({ "scope": scope }),
            ));
        }
    }
    Ok(scopes)
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let retired: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if retired.is_empty() {
        return Ok(());
    }
    Err(RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(
        400,
        "managed_worker_lifecycle_request_aliases_retired".to_string(),
        "Managed worker lifecycle admission accepts only canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": retired }),
    ))
}

fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(field.to_string(), normalized.map(Value::String).unwrap_or(Value::Null));
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(
                400,
                format!("managed_worker_lifecycle_{field}_invalid"),
                format!("Managed worker lifecycle admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(
            400,
            format!("managed_worker_lifecycle_{field}_required"),
            format!("Managed worker lifecycle admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimeManagedWorkerInstanceLifecycleAdmissionError {
    RuntimeManagedWorkerInstanceLifecycleAdmissionError::new(403, code.to_string(), message.to_string(), details)
}

fn default_value(value: Option<&Value>, fallback: &str) -> Value {
    match value {
        None | Some(Value::Null) => Value::String(fallback.to_string()),
        Some(value) => value.clone(),
    }
}

/// Mirror JS `objectRecord`: a non-null, non-array object, else None.
fn object_record(value: Option<&Value>) -> Option<&Value> {
    match value {
        Some(value @ Value::Object(_)) => Some(value),
        _ => None,
    }
}

/// Echo a policy object back as the object or JSON null (matches `policy ?? null`).
fn policy_or_null(policy: Option<&Value>) -> Value {
    policy.cloned().unwrap_or(Value::Null)
}

/// `!policy?.field` requires the policy be an object AND its field be JS-truthy.
fn policy_field_truthy(policy: Option<&Value>, field: &str) -> bool {
    policy.and_then(|object| object.get(field)).map(is_truthy).unwrap_or(false)
}

/// `policy?.field !== true` requires the policy be an object AND its field be the boolean true.
fn policy_field_is_true(policy: Option<&Value>, field: &str) -> bool {
    policy.and_then(|object| object.get(field)) == Some(&Value::Bool(true))
}

/// Mirror JS `optionalString`: String(value).trim() (ECMAScript trim set), None when null/blank.
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

fn boolean_value(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mirror this module's LOCAL `uniqueStrings(normalizeArray(value))`: truthy raw items,
/// `String(v).trim()` (TRIMS, via js_trim), drop blanks, first-seen dedup. Non-array → empty.
fn unique_strings_trim(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        let trimmed = js_trim(&js_string_coerce(item)).to_string();
        if trimmed.is_empty() {
            continue;
        }
        if !out.contains(&trimmed) {
            out.push(trimmed);
        }
    }
    out
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
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
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
            | '\u{2000}'..='\u{200A}'
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

    fn base_request() -> Value {
        json!({
            "lifecycle_id": "lifecycle:carwash/heath",
            "worker_instance_id": "agent://carwash-prep/heath/default",
            "owner_ref": "wallet://user/heath",
            "from_state": "active",
            "to_state": "idle",
            "persistence_profile": "persistent",
            "agentgres_operation_refs": ["agentgres://operation/lifecycle"],
            "receipt_refs": ["receipt://lifecycle"],
        })
    }

    #[test]
    fn admits_simple_transition() {
        let admission = RuntimeManagedWorkerInstanceLifecycleAdmissionCore
            .admit(&base_request(), "2026-06-18T00:00:00.000Z")
            .expect("admitted");
        assert_eq!(admission["schema_version"], MANAGED_WORKER_INSTANCE_LIFECYCLE_ADMISSION_SCHEMA_VERSION);
        assert_eq!(admission["to_state"], "idle");
        assert_eq!(admission["state"], "idle");
        assert_eq!(
            admission["transition_id"],
            "managed-worker-lifecycle:lifecycle_carwash_heath:active-idle"
        );
        assert_eq!(admission["runtimeTruthSource"], "daemon-runtime");
    }

    #[test]
    fn blocks_invalid_transition() {
        let mut request = base_request();
        request["from_state"] = json!("active");
        request["to_state"] = json!("discover");
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "managed_worker_lifecycle_transition_invalid");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn payment_past_due_requires_freeze() {
        let mut request = base_request();
        request["to_state"] = json!("payment_past_due");
        request["payment_status"] = json!("past_due");
        request["required_controls"] = json!(["freeze_new_billable_work", "pause_high_risk_standing_orders"]);
        // missing the freeze booleans
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "managed_worker_lifecycle_lapse_freeze_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn forget_requires_policy_flag() {
        let mut request = base_request();
        request["from_state"] = json!("archived");
        request["to_state"] = json!("forgotten");
        request["authority_scope_refs"] = json!(["scope:worker.forget"]);
        request["wallet_approval_ref"] = json!("approval://wallet/x");
        request["deletion_policy"] = json!({ "forget_semantic_memory": false });
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.code, "managed_worker_lifecycle_forget_policy_required");
    }

    #[test]
    fn admits_forget_with_policy() {
        let mut request = base_request();
        request["from_state"] = json!("archived");
        request["to_state"] = json!("forgotten");
        request["authority_scope_refs"] = json!(["scope:worker.forget"]);
        request["wallet_approval_ref"] = json!("approval://wallet/x");
        request["deletion_policy"] = json!({ "forget_semantic_memory": true });
        let admission = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect("admitted");
        assert_eq!(admission["to_state"], "forgotten");
    }

    #[test]
    fn scope_refs_must_use_scope_prefix() {
        let mut request = base_request();
        request["authority_scope_refs"] = json!(["worker.restore"]);
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("bad scope");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "managed_worker_lifecycle_scope_invalid");
    }

    #[test]
    fn bad_lifecycle_prefix_is_400() {
        let mut request = base_request();
        request["lifecycle_id"] = json!("nope:x");
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "managed_worker_lifecycle_lifecycle_id_invalid");
    }

    #[test]
    fn unique_strings_trims() {
        assert_eq!(
            unique_strings_trim(Some(&json!(["  a  ", "a", "b"]))),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["lifecycleId"] = json!("legacy");
        let error = RuntimeManagedWorkerInstanceLifecycleAdmissionCore.admit(&request, "now").expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "managed_worker_lifecycle_request_aliases_retired");
    }
}
