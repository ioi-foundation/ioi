use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-policy-projection-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_POLICY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_policy_projection.v1";
const DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-rollback-repair-policy.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDiagnosticsRepairPolicyRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub injection_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub diagnostic_status: Option<String>,
    #[serde(default)]
    pub diagnostic_count: Option<u64>,
    #[serde(default)]
    pub workspace_snapshot_refs: Vec<String>,
    #[serde(default)]
    pub rollback_refs: Vec<String>,
    #[serde(default)]
    pub source_tool_call_ids: Vec<String>,
    #[serde(default)]
    pub diagnostics_repair_contexts: Vec<Value>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiagnosticsRepairPolicyCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeDiagnosticsRepairPolicyCommandError {
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

#[derive(Debug, Clone, Default)]
pub struct RuntimeDiagnosticsRepairPolicyCore;

#[derive(Debug, Clone)]
pub struct RuntimeDiagnosticsRepairPolicyRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub injection_id: String,
    pub mode: String,
    pub diagnostic_status: String,
    pub diagnostic_count: u64,
    pub policy: Value,
    pub repair_policy_config: Value,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub projection_hash: String,
}

pub fn project_runtime_diagnostics_repair_policy_response(
    request: RuntimeDiagnosticsRepairPolicyRequest,
) -> Result<Value, RuntimeDiagnosticsRepairPolicyCommandError> {
    let record = RuntimeDiagnosticsRepairPolicyCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_diagnostics_repair_policy_command",
        "backend": "rust_policy",
        "projected": true,
        "record": record.to_value(),
        "policy": record.policy,
        "repair_policy": record.policy,
        "repair_policy_config": record.repair_policy_config,
        "receipt_refs": record.receipt_refs,
        "evidence_refs": record.evidence_refs,
        "projection_hash": record.projection_hash,
    }))
}

impl RuntimeDiagnosticsRepairPolicyCore {
    pub fn project(
        &self,
        request: &RuntimeDiagnosticsRepairPolicyRequest,
    ) -> Result<RuntimeDiagnosticsRepairPolicyRecord, RuntimeDiagnosticsRepairPolicyCommandError>
    {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeDiagnosticsRepairPolicyCommandError::new(
                    "runtime_diagnostics_repair_policy_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_thread_id_required",
                "diagnostics repair policy projection requires thread_id",
            )
        })?;
        let injection_id = optional_trimmed(request.injection_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_injection_id_required",
                "diagnostics repair policy projection requires injection_id",
            )
        })?;
        let mode =
            optional_trimmed(request.mode.as_deref()).unwrap_or_else(|| "blocking".to_string());
        let diagnostic_status = optional_trimmed(request.diagnostic_status.as_deref())
            .unwrap_or_else(|| "findings".to_string());
        let diagnostic_count = request.diagnostic_count.unwrap_or(0);
        let workspace_snapshot_refs = unique_strings(request.workspace_snapshot_refs.clone());
        let rollback_refs = unique_strings(request.rollback_refs.clone());
        let source_tool_call_ids = unique_strings(request.source_tool_call_ids.clone());
        let config = repair_policy_config_for_contexts(&request.diagnostics_repair_contexts);
        let policy = diagnostics_rollback_repair_policy(PolicyInput {
            thread_id: thread_id.clone(),
            injection_id: injection_id.clone(),
            mode: mode.clone(),
            diagnostic_status: diagnostic_status.clone(),
            diagnostic_count,
            workspace_snapshot_refs,
            rollback_refs,
            source_tool_call_ids,
            restore_policy: config.restore_policy.clone(),
            restore_conflict_policy: config.restore_conflict_policy.clone(),
            diagnostics_repair_default: config.diagnostics_repair_default.clone(),
            operator_override_requires_approval: config.operator_override_requires_approval,
        });
        let repair_policy_config = config.to_value();
        let receipt_refs = if request.receipt_refs.is_empty() {
            vec!["receipt_runtime_diagnostics_repair_policy_projection".to_string()]
        } else {
            unique_strings(
                request
                    .receipt_refs
                    .clone()
                    .into_iter()
                    .chain(std::iter::once(
                        "receipt_runtime_diagnostics_repair_policy_projection".to_string(),
                    ))
                    .collect(),
            )
        };
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_diagnostics_repair_policy_projection_rust_owned".to_string(),
                "rust_daemon_core_diagnostics_repair_policy_required".to_string(),
                "agentgres_diagnostics_repair_policy_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "project_runtime_diagnostics_repair_policy".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| "runtime.diagnostics_repair_policy.projection".to_string());
        let projection_hash = value_hash(&json!({
            "policy": policy,
            "repair_policy_config": repair_policy_config,
            "receipt_refs": receipt_refs,
            "evidence_refs": evidence_refs,
        }))?;

        Ok(RuntimeDiagnosticsRepairPolicyRecord {
            operation,
            operation_kind,
            thread_id,
            injection_id,
            mode,
            diagnostic_status,
            diagnostic_count,
            policy,
            repair_policy_config,
            evidence_refs,
            receipt_refs,
            projection_hash,
        })
    }
}

impl RuntimeDiagnosticsRepairPolicyRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_DIAGNOSTICS_REPAIR_POLICY_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_diagnostics_repair_policy_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "injection_id": self.injection_id,
            "mode": self.mode,
            "diagnostic_status": self.diagnostic_status,
            "diagnostic_count": self.diagnostic_count,
            "policy": self.policy,
            "repair_policy": self.policy,
            "repair_policy_config": self.repair_policy_config,
            "receipt_refs": self.receipt_refs,
            "evidence_refs": self.evidence_refs,
            "projection_hash": self.projection_hash,
        })
    }
}

#[derive(Debug, Clone)]
struct RepairPolicyConfig {
    restore_policy: String,
    restore_conflict_policy: String,
    diagnostics_repair_default: String,
    operator_override_requires_approval: bool,
}

impl RepairPolicyConfig {
    fn to_value(&self) -> Value {
        json!({
            "restore_policy": self.restore_policy,
            "restore_conflict_policy": self.restore_conflict_policy,
            "diagnostics_repair_default": self.diagnostics_repair_default,
            "operator_override_requires_approval": self.operator_override_requires_approval,
        })
    }
}

struct PolicyInput {
    thread_id: String,
    injection_id: String,
    mode: String,
    diagnostic_status: String,
    diagnostic_count: u64,
    workspace_snapshot_refs: Vec<String>,
    rollback_refs: Vec<String>,
    source_tool_call_ids: Vec<String>,
    restore_policy: String,
    restore_conflict_policy: String,
    diagnostics_repair_default: String,
    operator_override_requires_approval: bool,
}

fn repair_policy_config_for_contexts(contexts: &[Value]) -> RepairPolicyConfig {
    RepairPolicyConfig {
        restore_policy: normalize_restore_policy(first_context_string(
            contexts,
            &["restore_policy"],
        )),
        restore_conflict_policy: normalize_restore_conflict_policy(first_context_string(
            contexts,
            &["restore_conflict_policy"],
        )),
        diagnostics_repair_default: normalize_diagnostics_repair_default(first_context_string(
            contexts,
            &["diagnostics_repair_default", "default_repair_decision"],
        )),
        operator_override_requires_approval: first_context_bool(
            contexts,
            &["operator_override_requires_approval"],
        )
        .unwrap_or(true),
    }
}

fn diagnostics_rollback_repair_policy(input: PolicyInput) -> Value {
    let policy_id = format!(
        "policy_lsp_diagnostics_rollback_repair_{}",
        short_hash(
            &format!(
                "{}:{}:{}",
                input.thread_id,
                input.injection_id,
                input.workspace_snapshot_refs.join(",")
            ),
            16,
        )
    );
    let has_snapshot = !input.workspace_snapshot_refs.is_empty();
    let workspace_snapshot_refs = input.workspace_snapshot_refs.clone();
    let rollback_refs = input.rollback_refs.clone();
    let source_tool_call_ids = input.source_tool_call_ids.clone();
    let normalized_restore_policy = normalize_restore_policy(Some(input.restore_policy));
    let normalized_restore_conflict_policy =
        normalize_restore_conflict_policy(Some(input.restore_conflict_policy));
    let normalized_repair_default =
        normalize_diagnostics_repair_default(Some(input.diagnostics_repair_default));
    let restore_preview_status = if normalized_restore_policy == "disabled" {
        "unavailable"
    } else if has_snapshot {
        "available"
    } else {
        "unavailable"
    };
    let restore_apply_status = if normalized_restore_policy == "apply_with_approval" && has_snapshot
    {
        "requires_approval"
    } else {
        "unavailable"
    };
    let decision_base = format!("{policy_id}_decision");
    let decisions = vec![
        json!({
            "decision_id": format!("{decision_base}_repair_retry"),
            "action": "repair_retry",
            "status": "available",
            "requires_approval": false,
            "summary": "Retry with diagnostics context and repair the reported findings.",
        }),
        json!({
            "decision_id": format!("{decision_base}_restore_preview"),
            "action": "restore_preview",
            "status": restore_preview_status,
            "requires_approval": false,
            "rollback_refs": rollback_refs,
            "workspace_snapshot_refs": workspace_snapshot_refs,
            "summary": if normalized_restore_policy == "disabled" {
                "Workflow restore policy disables snapshot restore preview."
            } else if has_snapshot {
                "Preview restoring the snapshot captured before the patch."
            } else {
                "No content-backed workspace snapshot is available for restore preview."
            },
        }),
        json!({
            "decision_id": format!("{decision_base}_restore_apply"),
            "action": "restore_apply",
            "status": restore_apply_status,
            "requires_approval": normalized_restore_policy == "apply_with_approval",
            "rollback_refs": rollback_refs,
            "workspace_snapshot_refs": workspace_snapshot_refs,
            "restore_conflict_policy": normalized_restore_conflict_policy,
            "summary": if normalized_restore_policy == "disabled" {
                "Workflow restore policy disables snapshot restore apply."
            } else if normalized_restore_policy == "preview_only" {
                "Workflow restore policy allows preview only; apply is unavailable."
            } else if has_snapshot {
                "Apply snapshot restore after explicit operator approval."
            } else {
                "No content-backed workspace snapshot is available for restore apply."
            },
        }),
        json!({
            "decision_id": format!("{decision_base}_operator_override"),
            "action": "operator_override",
            "status": if input.operator_override_requires_approval {
                "requires_approval"
            } else {
                "available"
            },
            "requires_approval": input.operator_override_requires_approval,
            "summary": if input.operator_override_requires_approval {
                "Continue despite blocking diagnostics after explicit operator override."
            } else {
                "Continue despite blocking diagnostics under workflow-configured operator override policy."
            },
        }),
    ];
    let default_decision =
        diagnostics_repair_default_for_decisions(&decisions, &normalized_repair_default);
    let decision_refs = decisions
        .iter()
        .filter_map(|decision| string_field(decision, "decision_id"))
        .collect::<Vec<_>>();

    json!({
        "schema_version": DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION,
        "object": "ioi.runtime_diagnostics_rollback_repair_policy",
        "policy_id": policy_id,
        "thread_id": input.thread_id,
        "injection_id": input.injection_id,
        "mode": input.mode,
        "diagnostic_status": input.diagnostic_status,
        "diagnostic_count": input.diagnostic_count,
        "workspace_snapshot_refs": workspace_snapshot_refs,
        "rollback_refs": rollback_refs,
        "source_tool_call_ids": source_tool_call_ids,
        "restore_policy": normalized_restore_policy,
        "restore_conflict_policy": normalized_restore_conflict_policy,
        "diagnostics_repair_default": default_decision,
        "operator_override_requires_approval": input.operator_override_requires_approval,
        "default_decision": default_decision,
        "decisions": decisions,
        "decision_refs": decision_refs,
    })
}

fn diagnostics_repair_default_for_decisions(decisions: &[Value], preferred_action: &str) -> String {
    let preferred = normalize_diagnostics_repair_default(Some(preferred_action.to_string()));
    let available = decisions.iter().any(|decision| {
        string_field(decision, "action").as_deref() == Some(preferred.as_str())
            && matches!(
                string_field(decision, "status").as_deref(),
                Some("available" | "requires_approval")
            )
    });
    if available {
        preferred
    } else {
        "repair_retry".to_string()
    }
}

fn first_context_string(contexts: &[Value], keys: &[&str]) -> Option<String> {
    for context in contexts {
        for key in keys {
            if let Some(value) = string_field(context, key) {
                return Some(value);
            }
        }
    }
    None
}

fn first_context_bool(contexts: &[Value], keys: &[&str]) -> Option<bool> {
    for context in contexts {
        for key in keys {
            if let Some(value) = context.get(*key) {
                if let Some(value) = bool_value(value) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn normalize_restore_policy(value: Option<String>) -> String {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("disabled" | "disable" | "off" | "none" | "blocked") => "disabled".to_string(),
        Some("preview" | "preview_only" | "restore_preview" | "preview-only") => {
            "preview_only".to_string()
        }
        _ => "apply_with_approval".to_string(),
    }
}

fn normalize_restore_conflict_policy(value: Option<String>) -> String {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some(
            "allow_override" | "override" | "override_conflicts" | "force" | "apply_with_conflicts",
        ) => "allow_override".to_string(),
        Some("require_approval" | "approval" | "approval_required") => {
            "require_approval".to_string()
        }
        _ => "block".to_string(),
    }
}

fn normalize_diagnostics_repair_default(value: Option<String>) -> String {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("restore_preview" | "preview" | "preview_restore") => "restore_preview".to_string(),
        Some("restore_apply" | "apply" | "apply_restore" | "restore_apply_with_approval") => {
            "restore_apply".to_string()
        }
        Some("operator_override" | "override" | "continue") => "operator_override".to_string(),
        _ => "repair_retry".to_string(),
    }
}

fn string_field(record: &Value, key: &str) -> Option<String> {
    optional_trimmed(record.get(key)?.as_str())
}

fn bool_value(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        Value::Number(value) => value.as_u64().and_then(|value| match value {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }),
        _ => None,
    }
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        let Some(value) = optional_trimmed(Some(value.as_str())) else {
            continue;
        };
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn short_hash(value: &str, length: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex_prefix(&digest, length)
}

fn value_hash(value: &Value) -> Result<String, RuntimeDiagnosticsRepairPolicyCommandError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_hash_failed",
            error.to_string(),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex_prefix(&digest, 64)))
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
        if out.len() >= length {
            out.truncate(length);
            return out;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_request() -> RuntimeDiagnosticsRepairPolicyRequest {
        RuntimeDiagnosticsRepairPolicyRequest {
            schema_version: Some(
                RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            thread_id: Some("thread_alpha".to_string()),
            injection_id: Some("injection_alpha".to_string()),
            mode: Some("blocking".to_string()),
            diagnostic_status: Some("findings".to_string()),
            diagnostic_count: Some(2),
            workspace_snapshot_refs: vec!["snapshot_alpha".to_string()],
            rollback_refs: vec!["rollback_alpha".to_string(), "snapshot_alpha".to_string()],
            source_tool_call_ids: vec!["tool_call_alpha".to_string()],
            diagnostics_repair_contexts: vec![json!({
                "restore_policy": "preview",
                "restore_conflict_policy": "approval",
                "default_repair_decision": "apply",
                "operator_override_requires_approval": "false",
            })],
            ..Default::default()
        }
    }

    #[test]
    fn rust_projects_runtime_diagnostics_repair_policy() {
        let record = RuntimeDiagnosticsRepairPolicyCore
            .project(&policy_request())
            .expect("diagnostics repair policy projection");

        assert_eq!(
            record.operation,
            "project_runtime_diagnostics_repair_policy"
        );
        assert_eq!(
            record.operation_kind,
            "runtime.diagnostics_repair_policy.projection"
        );
        assert_eq!(
            record.policy["object"],
            "ioi.runtime_diagnostics_rollback_repair_policy"
        );
        assert_eq!(record.policy["thread_id"], "thread_alpha");
        assert_eq!(record.policy["restore_policy"], "preview_only");
        assert_eq!(record.policy["restore_conflict_policy"], "require_approval");
        assert_eq!(record.policy["diagnostics_repair_default"], "repair_retry");
        assert_eq!(record.policy["operator_override_requires_approval"], false);
        assert_eq!(record.policy["decision_refs"].as_array().unwrap().len(), 4);
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_policy_projection_rust_owned".to_string()));
        assert!(record.projection_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_shapes_runtime_diagnostics_repair_policy_command_response() {
        let response = project_runtime_diagnostics_repair_policy_response(policy_request())
            .expect("policy command response");

        assert_eq!(
            response["source"],
            "rust_runtime_diagnostics_repair_policy_command"
        );
        assert_eq!(response["projected"], true);
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_DIAGNOSTICS_REPAIR_POLICY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            response["repair_policy"]["object"],
            "ioi.runtime_diagnostics_rollback_repair_policy"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_policy_without_thread_id() {
        let mut request = policy_request();
        request.thread_id = None;

        let error = RuntimeDiagnosticsRepairPolicyCore
            .project(&request)
            .expect_err("missing thread_id must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_policy_thread_id_required"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_policy_bad_schema() {
        let mut request = policy_request();
        request.schema_version = Some("retired.schema".to_string());

        let error = RuntimeDiagnosticsRepairPolicyCore
            .project(&request)
            .expect_err("bad schema must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_policy_schema_version_invalid"
        );
    }
}
