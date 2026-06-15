use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub const RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-policy-projection-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_POLICY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_policy_projection.v1";
const DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-rollback-repair-policy.v1";
const DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-rollback-repair-context.v1";

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
    pub state_dir: Option<String>,
    #[serde(default)]
    pub diagnostic_event_ids: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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
    pub diagnostic_event_ids: Vec<String>,
    pub diagnostic_status: String,
    pub diagnostic_count: u64,
    pub workspace_snapshot_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub source_tool_call_ids: Vec<String>,
    pub diagnostics_repair_contexts: Vec<Value>,
    pub policy: Value,
    pub repair_policy_config: Value,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub projection_hash: String,
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
        reject_policy_candidate_transport(request)?;
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_thread_id_required",
                "diagnostics repair policy projection requires thread_id",
            )
        })?;
        let mode =
            optional_trimmed(request.mode.as_deref()).unwrap_or_else(|| "blocking".to_string());
        let replay = replay_diagnostics_repair_policy_inputs(request, &thread_id, &mode)?;
        let injection_id = optional_trimmed(request.injection_id.as_deref()).unwrap_or_else(|| {
            diagnostics_policy_injection_id(&thread_id, &replay.diagnostic_event_ids, &mode)
        });
        let diagnostic_status = replay.diagnostic_status.clone();
        let diagnostic_count = replay.diagnostic_count;
        let workspace_snapshot_refs = replay.workspace_snapshot_refs.clone();
        let rollback_refs = replay.rollback_refs.clone();
        let source_tool_call_ids = replay.source_tool_call_ids.clone();
        let config = repair_policy_config_for_contexts(&replay.diagnostics_repair_contexts);
        let policy = diagnostics_rollback_repair_policy(PolicyInput {
            thread_id: thread_id.clone(),
            injection_id: injection_id.clone(),
            mode: mode.clone(),
            diagnostic_status: diagnostic_status.clone(),
            diagnostic_count,
            workspace_snapshot_refs: workspace_snapshot_refs.clone(),
            rollback_refs: rollback_refs.clone(),
            source_tool_call_ids: source_tool_call_ids.clone(),
            restore_policy: config.restore_policy.clone(),
            restore_conflict_policy: config.restore_conflict_policy.clone(),
            diagnostics_repair_default: config.diagnostics_repair_default.clone(),
            operator_override_requires_approval: config.operator_override_requires_approval,
        });
        let repair_policy_config = config.to_value();
        let receipt_refs = if replay.receipt_refs.is_empty() {
            vec!["receipt_runtime_diagnostics_repair_policy_projection".to_string()]
        } else {
            unique_strings(
                replay
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
                "rust_daemon_core_diagnostics_repair_policy_replay_required".to_string(),
                "agentgres_diagnostics_repair_policy_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_diagnostics_repair_policy_projection".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| "runtime.diagnostics_repair_policy.projection".to_string());
        let projection_hash = value_hash(&json!({
            "policy": policy,
            "repair_policy_config": repair_policy_config,
            "diagnostic_event_ids": replay.diagnostic_event_ids,
            "receipt_refs": receipt_refs,
            "evidence_refs": evidence_refs,
        }))?;

        Ok(RuntimeDiagnosticsRepairPolicyRecord {
            operation,
            operation_kind,
            thread_id,
            injection_id,
            mode,
            diagnostic_event_ids: replay.diagnostic_event_ids,
            diagnostic_status,
            diagnostic_count,
            workspace_snapshot_refs,
            rollback_refs,
            source_tool_call_ids,
            diagnostics_repair_contexts: replay.diagnostics_repair_contexts,
            policy,
            repair_policy_config,
            evidence_refs,
            receipt_refs,
            projection_hash,
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

struct ReplayPolicyInputs {
    diagnostic_event_ids: Vec<String>,
    diagnostic_status: String,
    diagnostic_count: u64,
    workspace_snapshot_refs: Vec<String>,
    rollback_refs: Vec<String>,
    source_tool_call_ids: Vec<String>,
    diagnostics_repair_contexts: Vec<Value>,
    receipt_refs: Vec<String>,
}

fn reject_policy_candidate_transport(
    request: &RuntimeDiagnosticsRepairPolicyRequest,
) -> Result<(), RuntimeDiagnosticsRepairPolicyCommandError> {
    for key in [
        "diagnostic_status",
        "diagnostic_count",
        "workspace_snapshot_refs",
        "rollback_refs",
        "source_tool_call_ids",
        "diagnostics_repair_contexts",
        "receipt_refs",
    ] {
        if request.extra.contains_key(key) {
            return Err(RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_candidate_transport_retired",
                format!(
                    "diagnostics repair policy projection rejects retired JS policy input transport {key}"
                ),
            ));
        }
    }
    Ok(())
}

fn replay_diagnostics_repair_policy_inputs(
    request: &RuntimeDiagnosticsRepairPolicyRequest,
    thread_id: &str,
    mode: &str,
) -> Result<ReplayPolicyInputs, RuntimeDiagnosticsRepairPolicyCommandError> {
    let diagnostic_event_ids = unique_strings(request.diagnostic_event_ids.clone());
    if diagnostic_event_ids.is_empty() {
        return Err(RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_diagnostic_event_ids_required",
            "diagnostics repair policy projection requires diagnostic_event_ids for Agentgres replay",
        ));
    }
    let state_dir = optional_trimmed(request.state_dir.as_deref()).ok_or_else(|| {
        RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_state_dir_required",
            "diagnostics repair policy projection requires runtime state_dir for Agentgres event replay",
        )
    })?;
    let events_dir = Path::new(&state_dir).join("events");
    if !events_dir.exists() {
        return Err(RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_replay_event_not_found",
            "diagnostics repair policy projection found no Agentgres runtime events",
        ));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(&events_dir).map_err(|error| {
        RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_replay_read_failed",
            format!(
                "diagnostics repair policy projection could not read Agentgres events: {error}"
            ),
        )
    })? {
        let entry = entry.map_err(|error| {
            RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_replay_read_failed",
                format!(
                    "diagnostics repair policy projection could not inspect Agentgres event entry: {error}"
                ),
            )
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut events_by_id = BTreeMap::new();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeDiagnosticsRepairPolicyCommandError::new(
                "runtime_diagnostics_repair_policy_replay_read_failed",
                format!(
                    "diagnostics repair policy projection could not read Agentgres event record {}: {error}",
                    path.display()
                ),
            )
        })?;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).map_err(|error| {
                RuntimeDiagnosticsRepairPolicyCommandError::new(
                    "runtime_diagnostics_repair_policy_replay_record_invalid",
                    format!(
                        "diagnostics repair policy projection found invalid Agentgres event record {}:{}: {error}",
                        path.display(),
                        index + 1
                    ),
                )
            })?;
            let Some(event_id) = string_field(&event, "event_id") else {
                continue;
            };
            if diagnostic_event_ids.contains(&event_id)
                && event_thread_id(&event).as_deref() == Some(thread_id)
            {
                events_by_id.insert(event_id, event);
            }
        }
    }

    let mut selected_events = Vec::new();
    let mut missing = Vec::new();
    for event_id in &diagnostic_event_ids {
        if let Some(event) = events_by_id.remove(event_id) {
            selected_events.push(event);
        } else {
            missing.push(event_id.clone());
        }
    }
    if !missing.is_empty() {
        return Err(RuntimeDiagnosticsRepairPolicyCommandError::new(
            "runtime_diagnostics_repair_policy_replay_event_not_found",
            format!(
                "diagnostics repair policy projection could not replay diagnostic events {}",
                missing.join(",")
            ),
        ));
    }

    Ok(project_policy_inputs_from_events(
        diagnostic_event_ids,
        selected_events,
        mode,
    ))
}

fn project_policy_inputs_from_events(
    diagnostic_event_ids: Vec<String>,
    selected_events: Vec<Value>,
    _mode: &str,
) -> ReplayPolicyInputs {
    let mut statuses = Vec::new();
    let mut diagnostic_count = 0_u64;
    let mut rollback_refs = Vec::new();
    let mut source_tool_call_ids = Vec::new();
    let mut diagnostics_repair_contexts = Vec::new();
    let mut receipt_refs = Vec::new();

    for event in selected_events {
        let payload = event_payload(&event);
        let result = event_result(&payload);
        let result_summary = event_result_summary(&payload);
        statuses.push(
            string_field(&result, "diagnostic_status")
                .or_else(|| string_field(&result_summary, "diagnostic_status"))
                .unwrap_or_else(|| "clean".to_string()),
        );
        diagnostic_count += result
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(|values| values.len() as u64)
            .unwrap_or(0);
        receipt_refs.extend(string_array_field(&event, "receipt_refs"));
        rollback_refs.extend(string_array_field(&event, "rollback_refs"));
        if let Some(context) = diagnostics_repair_context_from_payload(&payload) {
            rollback_refs.extend(string_array_field(&context, "rollback_refs"));
            if let Some(snapshot_id) = string_field(&context, "workspace_snapshot_id") {
                rollback_refs.push(snapshot_id);
            }
            if let Some(tool_call_id) = string_field(&context, "source_tool_call_id") {
                source_tool_call_ids.push(tool_call_id);
            }
            diagnostics_repair_contexts.push(context);
        }
    }

    let diagnostic_status = if statuses.iter().any(|value| value == "findings") {
        "findings".to_string()
    } else if statuses.iter().any(|value| value == "degraded") {
        "degraded".to_string()
    } else {
        "clean".to_string()
    };
    let rollback_refs = unique_strings(rollback_refs);
    let workspace_snapshot_refs = unique_strings(
        rollback_refs
            .iter()
            .cloned()
            .chain(
                diagnostics_repair_contexts
                    .iter()
                    .filter_map(|context| string_field(context, "workspace_snapshot_id")),
            )
            .collect(),
    );

    ReplayPolicyInputs {
        diagnostic_event_ids,
        diagnostic_status,
        diagnostic_count,
        workspace_snapshot_refs,
        rollback_refs,
        source_tool_call_ids: unique_strings(source_tool_call_ids),
        diagnostics_repair_contexts,
        receipt_refs: unique_strings(receipt_refs),
    }
}

fn diagnostics_repair_context_from_payload(payload: &Value) -> Option<Value> {
    let context = payload
        .get("diagnostics_repair_context")
        .filter(|value| value.is_object())
        .or_else(|| {
            payload
                .get("result")
                .and_then(|result| result.get("diagnostics_repair_context"))
                .filter(|value| value.is_object())
        })?;
    let workspace_snapshot_id = string_field(context, "workspace_snapshot_id");
    let rollback_refs = unique_strings(
        string_array_field(context, "rollback_refs")
            .into_iter()
            .chain(workspace_snapshot_id.clone())
            .collect(),
    );
    Some(json!({
        "schema_version": string_field(context, "schema_version")
            .unwrap_or_else(|| DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION.to_string()),
        "object": string_field(context, "object")
            .unwrap_or_else(|| "ioi.runtime_diagnostics_rollback_repair_context".to_string()),
        "source_tool_name": string_field(context, "source_tool_name"),
        "source_tool_call_id": string_field(context, "source_tool_call_id"),
        "source_workflow_graph_id": string_field(context, "source_workflow_graph_id"),
        "source_workflow_node_id": string_field(context, "source_workflow_node_id"),
        "workspace_snapshot_id": workspace_snapshot_id,
        "restore_policy": normalize_restore_policy(string_field(context, "restore_policy")),
        "restore_conflict_policy": normalize_restore_conflict_policy(
            string_field(context, "restore_conflict_policy"),
        ),
        "diagnostics_repair_default": normalize_diagnostics_repair_default(
            string_field(context, "diagnostics_repair_default")
                .or_else(|| string_field(context, "default_repair_decision")),
        ),
        "operator_override_requires_approval": context
            .get("operator_override_requires_approval")
            .and_then(bool_value)
            .unwrap_or(true),
        "rollback_refs": rollback_refs,
    }))
}

fn event_payload(event: &Value) -> Value {
    event
        .get("payload_summary")
        .filter(|value| value.is_object())
        .or_else(|| event.get("payload").filter(|value| value.is_object()))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn event_result(payload: &Value) -> Value {
    payload
        .get("result")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn event_result_summary(payload: &Value) -> Value {
    payload
        .get("result_summary")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn event_thread_id(event: &Value) -> Option<String> {
    string_field(event, "thread_id").or_else(|| string_field(&event_payload(event), "thread_id"))
}

fn diagnostics_policy_injection_id(
    thread_id: &str,
    diagnostic_event_ids: &[String],
    mode: &str,
) -> String {
    format!(
        "lsp_diagnostics_injection_{}",
        short_hash(
            &format!("{thread_id}:{}:{mode}", diagnostic_event_ids.join(",")),
            16
        )
    )
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

fn string_array_field(record: &Value, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| optional_trimmed(value.as_str()))
                .collect()
        })
        .unwrap_or_default()
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
    use std::{fs, path::Path};

    fn write_runtime_event(state_dir: &Path, event: Value) {
        let event_dir = state_dir.join("events");
        fs::create_dir_all(&event_dir).expect("event dir");
        fs::write(
            event_dir.join("thread_alpha.jsonl"),
            format!("{}\n", serde_json::to_string(&event).expect("event json")),
        )
        .expect("write event");
    }

    fn diagnostics_event() -> Value {
        json!({
            "event_id": "event_diagnostics_alpha",
            "event_stream_id": "thread_alpha:events",
            "thread_id": "thread_alpha",
            "event_kind": "tool.completed",
            "source": "runtime_auto",
            "seq": 7,
            "receipt_refs": ["receipt_diagnostics_alpha"],
            "rollback_refs": ["rollback_alpha"],
            "payload_summary": {
                "tool_name": "lsp.diagnostics",
                "result": {
                    "diagnostic_status": "findings",
                    "diagnostics": [
                        { "path": "src/a.rs", "message": "broken" },
                        { "path": "src/b.rs", "message": "also broken" }
                    ]
                },
                "diagnostics_repair_context": {
                    "source_tool_call_id": "tool_call_alpha",
                    "workspace_snapshot_id": "snapshot_alpha",
                    "rollback_refs": ["rollback_context_alpha"],
                    "restore_policy": "preview",
                    "restore_conflict_policy": "approval",
                    "default_repair_decision": "apply",
                    "operator_override_requires_approval": "false"
                }
            }
        })
    }

    fn policy_request(state_dir: &Path) -> RuntimeDiagnosticsRepairPolicyRequest {
        RuntimeDiagnosticsRepairPolicyRequest {
            schema_version: Some(
                RUNTIME_DIAGNOSTICS_REPAIR_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            thread_id: Some("thread_alpha".to_string()),
            mode: Some("blocking".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            diagnostic_event_ids: vec!["event_diagnostics_alpha".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn rust_replays_runtime_diagnostics_repair_policy_from_state_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), diagnostics_event());
        let record = RuntimeDiagnosticsRepairPolicyCore
            .project(&policy_request(temp.path()))
            .expect("diagnostics repair policy projection");

        assert_eq!(
            record.operation,
            "runtime_diagnostics_repair_policy_projection"
        );
        assert_eq!(
            record.operation_kind,
            "runtime.diagnostics_repair_policy.projection"
        );
        assert_eq!(
            record.injection_id,
            "lsp_diagnostics_injection_02ed0f9a0ab4452c"
        );
        assert_eq!(
            record.diagnostic_event_ids,
            vec!["event_diagnostics_alpha".to_string()]
        );
        assert_eq!(record.diagnostic_status, "findings");
        assert_eq!(record.diagnostic_count, 2);
        assert_eq!(
            record.rollback_refs,
            vec![
                "rollback_alpha".to_string(),
                "rollback_context_alpha".to_string(),
                "snapshot_alpha".to_string()
            ]
        );
        assert_eq!(
            record.workspace_snapshot_refs,
            vec![
                "rollback_alpha".to_string(),
                "rollback_context_alpha".to_string(),
                "snapshot_alpha".to_string()
            ]
        );
        assert_eq!(
            record.source_tool_call_ids,
            vec!["tool_call_alpha".to_string()]
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
    fn rust_rejects_runtime_diagnostics_repair_policy_without_thread_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), diagnostics_event());
        let mut request = policy_request(temp.path());
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
    fn rust_rejects_runtime_diagnostics_repair_policy_candidate_transport() {
        let request: RuntimeDiagnosticsRepairPolicyRequest = serde_json::from_value(json!({
            "thread_id": "thread_alpha",
            "state_dir": "/tmp/runtime-state",
            "diagnostic_event_ids": ["event_diagnostics_alpha"],
            "diagnostic_status": "findings"
        }))
        .expect("request");

        let error = RuntimeDiagnosticsRepairPolicyCore
            .project(&request)
            .expect_err("candidate transport must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_policy_candidate_transport_retired"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_policy_without_state_dir() {
        let error = RuntimeDiagnosticsRepairPolicyCore
            .project(&RuntimeDiagnosticsRepairPolicyRequest {
                thread_id: Some("thread_alpha".to_string()),
                mode: Some("blocking".to_string()),
                diagnostic_event_ids: vec!["event_diagnostics_alpha".to_string()],
                ..Default::default()
            })
            .expect_err("missing state_dir must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_policy_state_dir_required"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_policy_without_event_ids() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), diagnostics_event());
        let error = RuntimeDiagnosticsRepairPolicyCore
            .project(&RuntimeDiagnosticsRepairPolicyRequest {
                thread_id: Some("thread_alpha".to_string()),
                mode: Some("blocking".to_string()),
                state_dir: Some(temp.path().to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect_err("missing event selectors must fail closed");

        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_policy_diagnostic_event_ids_required"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_policy_bad_schema() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_event(temp.path(), diagnostics_event());
        let mut request = policy_request(temp.path());
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
