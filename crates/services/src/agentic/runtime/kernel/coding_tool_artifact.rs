use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const RUNTIME_CODING_TOOL_ARTIFACT_DRAFT_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-artifact-draft-plan-request.v1";
pub const RUNTIME_CODING_TOOL_ARTIFACT_READ_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-artifact-read-projection-request.v1";
pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
pub const CODING_TOOL_ARTIFACT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-artifact.v1";
const CODING_TOOL_DATA_PLANE_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-data-plane.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeCodingToolArtifactDraftPlanRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub artifact_drafts: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeCodingToolArtifactReadProjectionRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifact_ref: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub range: Value,
    #[serde(default)]
    pub query: Value,
    #[serde(default)]
    pub artifact_records: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCodingToolArtifactDraftPlanCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeCodingToolArtifactDraftPlanCommandError {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCodingToolArtifactReadProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeCodingToolArtifactReadProjectionCommandError {
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

pub fn plan_runtime_coding_tool_artifact_drafts_response(
    request: RuntimeCodingToolArtifactDraftPlanRequest,
) -> Result<Value, RuntimeCodingToolArtifactDraftPlanCommandError> {
    let record = plan_runtime_coding_tool_artifact_drafts(&request)?;
    Ok(json!({
        "source": "rust_runtime_coding_tool_artifact_draft_plan_command",
        "backend": "rust_policy",
        "record": record,
    }))
}

fn plan_runtime_coding_tool_artifact_drafts(
    request: &RuntimeCodingToolArtifactDraftPlanRequest,
) -> Result<Value, RuntimeCodingToolArtifactDraftPlanCommandError> {
    if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
        if schema_version != RUNTIME_CODING_TOOL_ARTIFACT_DRAFT_PLAN_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
                "runtime_coding_tool_artifact_draft_schema_version_invalid",
                "coding-tool artifact draft planning request schema_version is not owned by this Rust core",
            ));
        }
    }

    if request.result.get("artifactDrafts").is_some() {
        return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_alias_retired",
            "coding-tool artifact draft planning accepts canonical artifact_drafts only",
        ));
    }

    let operation_kind = optional_trimmed(request.operation_kind.as_deref())
        .unwrap_or_else(|| "artifact.coding_tool_draft".to_string());
    if operation_kind != "artifact.coding_tool_draft" {
        return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_operation_kind_invalid",
            "coding-tool artifact draft planning requires operation_kind artifact.coding_tool_draft",
        ));
    }
    let operation = optional_trimmed(request.operation.as_deref())
        .unwrap_or_else(|| "coding_tool_artifact_draft_materialization".to_string());
    let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
        RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_thread_id_required",
            "coding-tool artifact draft planning requires thread_id",
        )
    })?;
    let tool_name = optional_trimmed(request.tool_id.as_deref())
        .or_else(|| optional_trimmed(request.tool_name.as_deref()))
        .ok_or_else(|| {
            RuntimeCodingToolArtifactDraftPlanCommandError::new(
                "runtime_coding_tool_artifact_draft_tool_required",
                "coding-tool artifact draft planning requires tool_id",
            )
        })?;
    let tool_call_id = optional_trimmed(request.tool_call_id.as_deref()).ok_or_else(|| {
        RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_tool_call_id_required",
            "coding-tool artifact draft planning requires tool_call_id",
        )
    })?;
    let workspace_root = optional_trimmed(request.workspace_root.as_deref());
    let receipt_id = optional_trimmed(request.receipt_id.as_deref());
    let mut receipt_refs = string_vec(&request.receipt_refs);
    if let Some(receipt_id) = &receipt_id {
        if !receipt_refs.iter().any(|value| value == receipt_id) {
            receipt_refs.push(receipt_id.clone());
        }
    }
    if receipt_refs.is_empty() {
        return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_receipt_refs_required",
            "coding-tool artifact draft planning requires Rust-owned receipt refs",
        ));
    }

    let drafts = artifact_draft_values(request);
    if drafts.is_empty() {
        return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_records_required",
            "coding-tool artifact draft planning requires artifact_drafts",
        ));
    }

    let mut evidence_refs = string_vec(&request.evidence_refs);
    if evidence_refs.is_empty() {
        evidence_refs = vec![
            "coding_tool_artifact_draft_rust_owned".to_string(),
            "rust_daemon_core_artifact_admission_required".to_string(),
            "agentgres_artifact_state_truth_required".to_string(),
        ];
    }

    let mut artifact_records = Vec::new();
    for (index, draft) in drafts.iter().enumerate() {
        artifact_records.push(coding_tool_artifact_record(
            draft,
            index,
            &thread_id,
            &tool_name,
            &tool_call_id,
            workspace_root.as_deref(),
            receipt_id.as_deref(),
            &receipt_refs,
            &evidence_refs,
            &operation_kind,
        )?);
    }
    let artifact_refs = artifact_records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let plan_hash = format!(
        "sha256:{}",
        short_hash(
            &serde_json::to_string(&artifact_records).unwrap_or_default(),
            64
        )
    );

    Ok(json!({
        "schema_version": RUNTIME_CODING_TOOL_ARTIFACT_DRAFT_PLAN_REQUEST_SCHEMA_VERSION,
        "object": "ioi.runtime_coding_tool_artifact_draft_plan",
        "status": "planned",
        "operation": operation,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "workspace_root": workspace_root,
        "receipt_id": receipt_id,
        "artifact_records": artifact_records,
        "artifact_refs": artifact_refs,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "plan_hash": plan_hash,
    }))
}

pub fn project_runtime_coding_tool_artifact_read_response(
    request: RuntimeCodingToolArtifactReadProjectionRequest,
) -> Result<Value, RuntimeCodingToolArtifactReadProjectionCommandError> {
    let record = project_runtime_coding_tool_artifact_read(&request)?;
    Ok(json!({
        "source": "rust_runtime_coding_tool_artifact_read_projection_command",
        "backend": "rust_policy",
        "record": record,
    }))
}

fn project_runtime_coding_tool_artifact_read(
    request: &RuntimeCodingToolArtifactReadProjectionRequest,
) -> Result<Value, RuntimeCodingToolArtifactReadProjectionCommandError> {
    if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
        if schema_version != RUNTIME_CODING_TOOL_ARTIFACT_READ_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeCodingToolArtifactReadProjectionCommandError::new(
                "runtime_coding_tool_artifact_read_projection_schema_version_invalid",
                "coding-tool artifact read projection request schema_version is not owned by this Rust core",
            ));
        }
    }
    reject_read_projection_aliases(request)?;

    let operation = optional_trimmed(request.operation.as_deref())
        .unwrap_or_else(|| "artifact.read".to_string());
    if operation != "artifact.read" && operation != "tool.retrieve_result" {
        return Err(RuntimeCodingToolArtifactReadProjectionCommandError::new(
            "runtime_coding_tool_artifact_read_projection_operation_invalid",
            "coding-tool artifact read projection requires artifact.read or tool.retrieve_result",
        ));
    }
    let default_operation_kind = if operation == "artifact.read" {
        "artifact.read_projection"
    } else {
        "tool.retrieve_result_projection"
    };
    let operation_kind = optional_trimmed(request.operation_kind.as_deref())
        .unwrap_or_else(|| default_operation_kind.to_string());
    if operation_kind != default_operation_kind {
        return Err(RuntimeCodingToolArtifactReadProjectionCommandError::new(
            "runtime_coding_tool_artifact_read_projection_operation_kind_invalid",
            format!("coding-tool artifact read projection requires operation_kind {default_operation_kind}"),
        ));
    }
    let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
        RuntimeCodingToolArtifactReadProjectionCommandError::new(
            "runtime_coding_tool_artifact_read_projection_thread_id_required",
            "coding-tool artifact read projection requires thread_id",
        )
    })?;
    let artifact_records = artifact_record_values(&request.artifact_records);
    let mut evidence_refs = string_vec(&request.evidence_refs);
    if evidence_refs.is_empty() {
        evidence_refs = vec![
            "coding_tool_artifact_read_projection_rust_owned".to_string(),
            "artifact_projection_cache_transport_only".to_string(),
            "agentgres_artifact_state_truth_required".to_string(),
        ];
    }

    let projection = if operation == "artifact.read" {
        let artifact_id = read_projection_artifact_id(request).ok_or_else(|| {
            RuntimeCodingToolArtifactReadProjectionCommandError::new(
                "artifact_read_id_required",
                "artifact.read requires artifact_id or artifact_ref",
            )
        })?;
        let range = read_projection_range(&request.range, &request.query);
        let artifact = find_artifact_record(&artifact_records, &artifact_id).ok_or_else(|| {
            RuntimeCodingToolArtifactReadProjectionCommandError::new(
                "runtime_coding_tool_artifact_read_not_found",
                format!("Artifact not found: {artifact_id}"),
            )
        })?;
        assert_artifact_thread(&thread_id, artifact)?;
        let result = coding_tool_artifact_read_projection_result(artifact, &range);
        json!({
            "query": {
                "artifact_id": artifact_id,
                "range": range.to_json(),
            },
            "result": result,
        })
    } else {
        let range = read_projection_range(&request.range, &request.query);
        if let Some(artifact_id) = read_projection_artifact_id(request) {
            let artifact =
                find_artifact_record(&artifact_records, &artifact_id).ok_or_else(|| {
                    RuntimeCodingToolArtifactReadProjectionCommandError::new(
                        "runtime_coding_tool_artifact_read_not_found",
                        format!("Artifact not found: {artifact_id}"),
                    )
                })?;
            assert_artifact_thread(&thread_id, artifact)?;
            let result = coding_tool_artifact_read_projection_result(artifact, &range);
            json!({
                "query": {
                    "artifact_id": artifact_id,
                    "range": range.to_json(),
                },
                "result": result,
            })
        } else {
            let tool_call_id = read_projection_tool_call_id(request).ok_or_else(|| {
                RuntimeCodingToolArtifactReadProjectionCommandError::new(
                    "tool_retrieve_result_target_required",
                    "tool.retrieve_result requires tool_call_id or artifact_id",
                )
            })?;
            let mut artifacts = artifact_records
                .iter()
                .filter(|record| {
                    artifact_string(record, "thread_id").as_deref() == Some(thread_id.as_str())
                        && artifact_string(record, "tool_call_id").as_deref()
                            == Some(tool_call_id.as_str())
                })
                .collect::<Vec<_>>();
            artifacts.sort_by(|left, right| {
                artifact_string(left, "channel").cmp(&artifact_string(right, "channel"))
            });
            if artifacts.is_empty() {
                return Err(RuntimeCodingToolArtifactReadProjectionCommandError::new(
                    "runtime_coding_tool_result_artifact_not_found",
                    format!("Tool result artifact not found: {tool_call_id}"),
                ));
            }
            let channel = read_projection_channel(request);
            let artifact = channel
                .as_ref()
                .and_then(|channel| {
                    artifacts.iter().copied().find(|record| {
                        artifact_string(record, "channel").as_deref() == Some(channel.as_str())
                    })
                })
                .unwrap_or(artifacts[0]);
            let mut result = coding_tool_artifact_read_projection_result(artifact, &range);
            if let Some(object) = result.as_object_mut() {
                object.insert("tool_call_id".to_string(), json!(tool_call_id));
                object.insert(
                    "available_artifacts".to_string(),
                    Value::Array(
                        artifacts
                            .iter()
                            .map(|record| coding_tool_artifact_metadata(record))
                            .collect(),
                    ),
                );
            }
            json!({
                "query": {
                    "tool_call_id": tool_call_id,
                    "channel": channel,
                    "range": range.to_json(),
                },
                "result": result,
            })
        }
    };

    let result = projection
        .get("result")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let artifact_refs = json_string_refs(&result, &["artifact_refs"]);
    let receipt_refs = json_string_refs(&result, &["receipt_refs"]);
    let projection_hash = format!(
        "sha256:{}",
        short_hash(&serde_json::to_string(&projection).unwrap_or_default(), 64)
    );

    Ok(json!({
        "schema_version": RUNTIME_CODING_TOOL_ARTIFACT_READ_PROJECTION_REQUEST_SCHEMA_VERSION,
        "object": "ioi.runtime_coding_tool_artifact_read_projection",
        "status": "projected",
        "operation": operation,
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "query": projection.get("query").cloned().unwrap_or_else(|| json!({})),
        "result": result,
        "artifact_refs": artifact_refs,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "projection_hash": projection_hash,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolArtifactError {
    code: &'static str,
    message: String,
}

impl CodingToolArtifactError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolArtifactObservation {
    pub observation: Value,
    pub artifact_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub evidence_ref: String,
}

pub fn normalize_artifact_read(
    input: &Value,
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    normalize_prefetched_artifact_result(
        "artifact.read",
        input,
        "rust_artifact_read",
        &["artifact_id", "artifact_ref"],
    )
}

pub fn normalize_tool_retrieve_result(
    input: &Value,
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    normalize_prefetched_artifact_result(
        "tool.retrieve_result",
        input,
        "rust_tool_result_retrieve",
        &["tool_call_id", "artifact_id"],
    )
}

fn normalize_prefetched_artifact_result(
    tool_id: &str,
    input: &Value,
    backend: &str,
    evidence_keys: &[&str],
) -> Result<CodingToolArtifactObservation, CodingToolArtifactError> {
    if input.get("rustWorkloadDataPlane").is_some() {
        return Err(CodingToolArtifactError::new(
            "data_plane_payload_alias_retired",
            format!("{tool_id} requires canonical rust_workload_data_plane"),
        ));
    }
    let envelope = input
        .get("rust_workload_data_plane")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_payload_required",
                format!("{tool_id} requires a daemon-provided data-plane payload"),
            )
        })?;
    if envelope.get("schemaVersion").is_some() {
        return Err(CodingToolArtifactError::new(
            "data_plane_schema_alias_retired",
            format!("{tool_id} requires canonical data-plane schema_version"),
        ));
    }
    let schema_version = envelope
        .get("schema_version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_schema_version_required",
                format!("{tool_id} requires a data-plane schema_version"),
            )
        })?;
    if schema_version != CODING_TOOL_DATA_PLANE_SCHEMA_VERSION {
        return Err(CodingToolArtifactError::new(
            "data_plane_schema_version_unsupported",
            format!("{tool_id} does not accept data-plane schema {schema_version}"),
        ));
    }
    let source = envelope
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_source_required",
                format!("{tool_id} requires a data-plane source"),
            )
        })?;
    if source != "daemon_artifact_store" {
        return Err(CodingToolArtifactError::new(
            "data_plane_source_unsupported",
            format!("{tool_id} does not accept data-plane source {source}"),
        ));
    }
    let operation = envelope
        .get("operation")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_operation_required",
                format!("{tool_id} requires a data-plane operation"),
            )
        })?;
    if operation != tool_id {
        return Err(CodingToolArtifactError::new(
            "data_plane_operation_mismatch",
            format!("{tool_id} received data-plane operation {operation}"),
        ));
    }
    let mut normalized = envelope.get("result").cloned().ok_or_else(|| {
        CodingToolArtifactError::new(
            "data_plane_result_required",
            format!("{tool_id} requires a data-plane result"),
        )
    })?;
    let fallback_artifact_ref = optional_json_string(&normalized, &["artifact_id", "artifact_ref"]);
    let object = normalized.as_object_mut().ok_or_else(|| {
        CodingToolArtifactError::new(
            "data_plane_result_invalid",
            format!("{tool_id} data-plane result must be an object"),
        )
    })?;
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CodingToolArtifactError::new(
                "data_plane_content_required",
                format!("{tool_id} data-plane result must include content"),
            )
        })?
        .to_string();
    let content_hash = sha256_hex(content.as_bytes())?;

    remove_retired_result_aliases(object);
    object.insert(
        "schema_version".to_string(),
        json!(CODING_TOOL_RESULT_SCHEMA_VERSION),
    );
    object.insert("backend".to_string(), json!(backend));
    object.insert("data_plane_source".to_string(), json!(source));
    object.insert("rust_workload_data_plane".to_string(), json!(true));
    object.insert("content_hash".to_string(), json!(content_hash));
    object.insert("shell_fallback_used".to_string(), json!(false));
    if !object.contains_key("artifact_refs") {
        if let Some(artifact_id) = fallback_artifact_ref {
            object.insert("artifact_refs".to_string(), json!([artifact_id]));
        }
    }

    let artifact_refs = json_string_refs(&normalized, &["artifact_refs"]);
    let receipt_refs = json_string_refs(&normalized, &["receipt_refs"]);
    let evidence_ref = optional_json_string(&normalized, evidence_keys)
        .map(|value| safe_ref_path(&value))
        .unwrap_or_else(|| "unknown".to_string());

    Ok(CodingToolArtifactObservation {
        observation: normalized,
        artifact_refs,
        receipt_refs,
        evidence_ref,
    })
}

fn remove_retired_result_aliases(object: &mut serde_json::Map<String, Value>) {
    for key in [
        "schemaVersion",
        "dataPlaneSource",
        "rustWorkloadDataPlane",
        "contentHash",
        "shellFallbackUsed",
        "artifactRefs",
        "receiptRefs",
    ] {
        object.remove(key);
    }
}

fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = sanitize_string_array(value.get(*key));
        if !refs.is_empty() {
            return refs;
        }
    }
    Vec::new()
}

fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .take(100)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn safe_ref_path(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    if safe.is_empty() {
        "artifact".to_string()
    } else {
        safe
    }
}

fn artifact_draft_values(request: &RuntimeCodingToolArtifactDraftPlanRequest) -> Vec<Value> {
    let direct = request
        .artifact_drafts
        .as_array()
        .filter(|items| !items.is_empty());
    direct
        .or_else(|| {
            request
                .result
                .get("artifact_drafts")
                .and_then(Value::as_array)
        })
        .map(|items| items.iter().take(100).cloned().collect())
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn coding_tool_artifact_record(
    draft: &Value,
    index: usize,
    thread_id: &str,
    tool_name: &str,
    tool_call_id: &str,
    workspace_root: Option<&str>,
    receipt_id: Option<&str>,
    receipt_refs: &[String],
    evidence_refs: &[String],
    operation_kind: &str,
) -> Result<Value, RuntimeCodingToolArtifactDraftPlanCommandError> {
    let object = draft.as_object().ok_or_else(|| {
        RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_invalid",
            "coding-tool artifact draft must be an object",
        )
    })?;
    for retired_alias in [
        "artifactId",
        "contentHash",
        "mediaType",
        "receiptId",
        "receiptRefs",
        "threadId",
        "toolCallId",
        "toolName",
    ] {
        if object.contains_key(retired_alias) {
            return Err(RuntimeCodingToolArtifactDraftPlanCommandError::new(
                "runtime_coding_tool_artifact_draft_alias_retired",
                format!("coding-tool artifact draft uses retired field alias {retired_alias}"),
            ));
        }
    }

    let content = optional_json_string(draft, &["content"]).ok_or_else(|| {
        RuntimeCodingToolArtifactDraftPlanCommandError::new(
            "runtime_coding_tool_artifact_draft_content_required",
            "coding-tool artifact draft requires content",
        )
    })?;
    let channel =
        optional_json_string(draft, &["channel"]).unwrap_or_else(|| format!("artifact_{index}"));
    let media_type =
        optional_json_string(draft, &["media_type"]).unwrap_or_else(|| "text/plain".to_string());
    let name = optional_json_string(draft, &["name"])
        .unwrap_or_else(|| format!("{}.txt", safe_ref_path(&channel)));
    let redaction =
        optional_json_string(draft, &["redaction"]).unwrap_or_else(|| "none".to_string());
    let content_bytes = content.as_bytes().len();
    let content_hash = format!("sha256:{}", short_hash(&content, 64));
    let artifact_id = format!(
        "artifact_{}",
        short_hash(
            &format!("{thread_id}:{tool_name}:{tool_call_id}:{channel}:{index}:{content_hash}"),
            24,
        )
    );
    let artifact_hash = format!(
        "sha256:{}",
        short_hash(
            &format!("{artifact_id}:{operation_kind}:{media_type}:{redaction}:{content_hash}"),
            64,
        )
    );

    Ok(json!({
        "schema_version": CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        "id": artifact_id,
        "artifact_id": artifact_id,
        "object": "ioi.runtime_coding_tool_artifact",
        "source": "rust_runtime_coding_tool_artifact_draft_plan",
        "backend": "rust_daemon_core",
        "operation_kind": operation_kind,
        "thread_id": thread_id,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "workspace_root": workspace_root,
        "name": name,
        "channel": channel,
        "media_type": media_type,
        "redaction": redaction,
        "content": content,
        "content_bytes": content_bytes,
        "content_hash": content_hash,
        "artifact_hash": artifact_hash,
        "receipt_id": receipt_id,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
    }))
}

#[derive(Debug, Clone, Copy)]
struct ArtifactReadRange {
    offset_bytes: usize,
    length_bytes: usize,
}

impl ArtifactReadRange {
    fn to_json(self) -> Value {
        json!({
            "offset_bytes": self.offset_bytes,
            "length_bytes": self.length_bytes,
        })
    }
}

fn reject_read_projection_aliases(
    request: &RuntimeCodingToolArtifactReadProjectionRequest,
) -> Result<(), RuntimeCodingToolArtifactReadProjectionCommandError> {
    for alias in [
        "artifactId",
        "artifactRef",
        "toolCallId",
        "offsetBytes",
        "lengthBytes",
        "maxBytes",
    ] {
        if request.extra.contains_key(alias) {
            return Err(read_projection_alias_error(alias));
        }
    }
    for value in [&request.query, &request.range] {
        if let Some(object) = value.as_object() {
            for alias in [
                "artifactId",
                "artifactRef",
                "toolCallId",
                "offsetBytes",
                "lengthBytes",
                "maxBytes",
            ] {
                if object.contains_key(alias) {
                    return Err(read_projection_alias_error(alias));
                }
            }
            if let Some(range_object) = object.get("range").and_then(Value::as_object) {
                for alias in ["offsetBytes", "lengthBytes", "maxBytes"] {
                    if range_object.contains_key(alias) {
                        return Err(read_projection_alias_error(alias));
                    }
                }
            }
        }
    }
    Ok(())
}

fn read_projection_alias_error(alias: &str) -> RuntimeCodingToolArtifactReadProjectionCommandError {
    let code = if matches!(alias, "offsetBytes" | "lengthBytes" | "maxBytes") {
        "artifact_read_range_aliases_retired"
    } else {
        "runtime_coding_tool_artifact_read_target_alias_retired"
    };
    RuntimeCodingToolArtifactReadProjectionCommandError::new(
        code,
        format!("coding-tool artifact read projection rejects retired alias {alias}"),
    )
}

fn artifact_record_values(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item.as_object().is_some())
                .take(500)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn read_projection_artifact_id(
    request: &RuntimeCodingToolArtifactReadProjectionRequest,
) -> Option<String> {
    optional_trimmed(request.artifact_id.as_deref())
        .or_else(|| optional_trimmed(request.artifact_ref.as_deref()))
        .or_else(|| optional_json_string(&request.query, &["artifact_id", "artifact_ref"]))
}

fn read_projection_tool_call_id(
    request: &RuntimeCodingToolArtifactReadProjectionRequest,
) -> Option<String> {
    optional_trimmed(request.tool_call_id.as_deref())
        .or_else(|| optional_json_string(&request.query, &["tool_call_id"]))
}

fn read_projection_channel(
    request: &RuntimeCodingToolArtifactReadProjectionRequest,
) -> Option<String> {
    optional_trimmed(request.channel.as_deref())
        .or_else(|| optional_json_string(&request.query, &["channel"]))
}

fn read_projection_range(range: &Value, query: &Value) -> ArtifactReadRange {
    let range_object = range.as_object();
    let query_object = query.as_object();
    let query_range_object = query_object
        .and_then(|object| object.get("range"))
        .and_then(Value::as_object);
    let offset_bytes =
        numeric_json_value(range_object.and_then(|object| object.get("offset_bytes")))
            .or_else(|| {
                numeric_json_value(query_object.and_then(|object| object.get("offset_bytes")))
            })
            .or_else(|| {
                numeric_json_value(query_range_object.and_then(|object| object.get("offset_bytes")))
            })
            .unwrap_or(0)
            .max(0) as usize;
    let length_bytes =
        numeric_json_value(range_object.and_then(|object| object.get("length_bytes")))
            .or_else(|| numeric_json_value(range_object.and_then(|object| object.get("max_bytes"))))
            .or_else(|| {
                numeric_json_value(query_object.and_then(|object| object.get("length_bytes")))
            })
            .or_else(|| numeric_json_value(query_object.and_then(|object| object.get("max_bytes"))))
            .or_else(|| {
                numeric_json_value(query_range_object.and_then(|object| object.get("length_bytes")))
            })
            .or_else(|| {
                numeric_json_value(query_range_object.and_then(|object| object.get("max_bytes")))
            })
            .unwrap_or(64 * 1024)
            .max(1) as usize;
    ArtifactReadRange {
        offset_bytes,
        length_bytes,
    }
}

fn numeric_json_value(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
            .or_else(|| value.as_f64().map(|number| number as i64))
    })
}

fn find_artifact_record<'a>(records: &'a [Value], artifact_id: &str) -> Option<&'a Value> {
    records.iter().find(|record| {
        artifact_string(record, "id").as_deref() == Some(artifact_id)
            || artifact_string(record, "artifact_id").as_deref() == Some(artifact_id)
    })
}

fn assert_artifact_thread(
    thread_id: &str,
    artifact: &Value,
) -> Result<(), RuntimeCodingToolArtifactReadProjectionCommandError> {
    if let Some(owner_thread_id) = artifact_string(artifact, "thread_id") {
        if owner_thread_id != thread_id {
            return Err(RuntimeCodingToolArtifactReadProjectionCommandError::new(
                "runtime_coding_tool_artifact_read_cross_thread_blocked",
                format!("Artifact read blocked outside owning runtime thread {owner_thread_id}"),
            ));
        }
    }
    Ok(())
}

fn coding_tool_artifact_read_projection_result(
    artifact: &Value,
    range: &ArtifactReadRange,
) -> Value {
    let content = artifact_string(artifact, "content").unwrap_or_default();
    let bytes = content.as_bytes();
    let offset = range.offset_bytes.min(bytes.len());
    let end = bytes.len().min(offset.saturating_add(range.length_bytes));
    let chunk = String::from_utf8_lossy(&bytes[offset..end]).to_string();
    let mut metadata = coding_tool_artifact_metadata(artifact);
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "artifact_refs".to_string(),
            Value::Array(
                artifact_string(artifact, "id")
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        object.insert("offset_bytes".to_string(), json!(offset));
        object.insert("length_bytes".to_string(), json!(end - offset));
        object.insert("total_bytes".to_string(), json!(bytes.len()));
        object.insert("content".to_string(), json!(chunk));
        object.insert("content_hash".to_string(), json!(short_hash(&chunk, 64)));
        object.insert(
            "full_content_hash".to_string(),
            artifact.get("content_hash").cloned().unwrap_or(Value::Null),
        );
        object.insert("truncated".to_string(), json!(end < bytes.len()));
        object.insert(
            "receipt_refs".to_string(),
            Value::Array(
                sanitize_string_array(artifact.get("receipt_refs"))
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        object.insert("shell_fallback_used".to_string(), json!(false));
    }
    metadata
}

fn coding_tool_artifact_metadata(artifact: &Value) -> Value {
    let artifact_id = artifact_string(artifact, "id")
        .or_else(|| artifact_string(artifact, "artifact_id"))
        .unwrap_or_default();
    let content_bytes = numeric_json_value(artifact.get("content_bytes"))
        .unwrap_or_else(|| {
            artifact_string(artifact, "content")
                .unwrap_or_default()
                .as_bytes()
                .len() as i64
        })
        .max(0);
    json!({
        "schema_version": CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        "artifact_id": artifact_id,
        "thread_id": artifact_string(artifact, "thread_id"),
        "tool_name": artifact_string(artifact, "tool_name"),
        "tool_call_id": artifact_string(artifact, "tool_call_id"),
        "name": artifact_string(artifact, "name"),
        "channel": artifact_string(artifact, "channel"),
        "media_type": artifact_string(artifact, "media_type").unwrap_or_else(|| "text/plain".to_string()),
        "content_bytes": content_bytes,
        "content_hash": artifact.get("content_hash").cloned().unwrap_or(Value::Null),
        "receipt_id": artifact_string(artifact, "receipt_id"),
        "redaction": artifact_string(artifact, "redaction").unwrap_or_else(|| "none".to_string()),
        "created_at": artifact_string(artifact, "created_at"),
    })
}

fn artifact_string(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn string_vec(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if let Some(value) = optional_trimmed(Some(value)) {
            if !out.iter().any(|existing| existing == &value) {
                out.push(value);
            }
        }
    }
    out
}

fn short_hash(value: &str, len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = hex::encode(hasher.finalize());
    hash.chars().take(len).collect()
}

fn sha256_hex(bytes: &[u8]) -> Result<String, CodingToolArtifactError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| CodingToolArtifactError::new("sha256_failed", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn artifact_draft_planner_authors_rust_artifact_records() {
        let request: RuntimeCodingToolArtifactDraftPlanRequest = serde_json::from_value(json!({
            "schema_version": "ioi.runtime.coding-tool-artifact-draft-plan-request.v1",
            "operation": "coding_tool_artifact_draft_materialization",
            "operation_kind": "artifact.coding_tool_draft",
            "thread_id": "thread_alpha",
            "tool_id": "git.diff",
            "tool_call_id": "tool_call_alpha",
            "workspace_root": "/workspace",
            "receipt_id": "receipt_alpha",
            "result": {
                "artifact_drafts": [
                    {
                        "channel": "stdout",
                        "name": "stdout.txt",
                        "media_type": "text/plain",
                        "content": "hello artifact",
                        "redaction": "none"
                    }
                ]
            }
        }))
        .expect("request");

        let response =
            plan_runtime_coding_tool_artifact_drafts_response(request).expect("draft plan");
        let record = response["record"].as_object().expect("record");
        let artifact_records = record["artifact_records"]
            .as_array()
            .expect("artifact records");
        let artifact = artifact_records[0].as_object().expect("artifact");

        assert_eq!(
            record["operation_kind"].as_str(),
            Some("artifact.coding_tool_draft")
        );
        assert_eq!(
            artifact["schema_version"],
            CODING_TOOL_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(
            artifact["source"],
            "rust_runtime_coding_tool_artifact_draft_plan"
        );
        assert_eq!(artifact["thread_id"], "thread_alpha");
        assert_eq!(artifact["tool_name"], "git.diff");
        assert_eq!(artifact["tool_call_id"], "tool_call_alpha");
        assert_eq!(artifact["receipt_refs"], json!(["receipt_alpha"]));
        assert!(artifact["id"]
            .as_str()
            .expect("artifact id")
            .starts_with("artifact_"));
        assert!(artifact["content_hash"]
            .as_str()
            .expect("content hash")
            .starts_with("sha256:"));
        assert_eq!(record["artifact_refs"][0], artifact["id"]);
    }

    #[test]
    fn artifact_draft_planner_rejects_retired_artifact_drafts_alias() {
        let request: RuntimeCodingToolArtifactDraftPlanRequest = serde_json::from_value(json!({
            "schema_version": "ioi.runtime.coding-tool-artifact-draft-plan-request.v1",
            "thread_id": "thread_alpha",
            "tool_id": "git.diff",
            "tool_call_id": "tool_call_alpha",
            "receipt_id": "receipt_alpha",
            "result": {
                "artifactDrafts": [{"content": "retired"}],
                "artifact_drafts": [{"content": "canonical"}]
            }
        }))
        .expect("request");

        let error = plan_runtime_coding_tool_artifact_drafts_response(request)
            .expect_err("retired alias should fail");

        assert_eq!(
            error.code(),
            "runtime_coding_tool_artifact_draft_alias_retired"
        );
    }

    #[test]
    fn artifact_read_projection_selects_record_and_range_in_rust() {
        let request: RuntimeCodingToolArtifactReadProjectionRequest =
            serde_json::from_value(json!({
                "schema_version": "ioi.runtime.coding-tool-artifact-read-projection-request.v1",
                "operation": "artifact.read",
                "operation_kind": "artifact.read_projection",
                "thread_id": "thread_alpha",
                "artifact_id": "artifact_alpha",
                "range": { "offset_bytes": 1, "length_bytes": 3 },
                "artifact_records": [
                    {
                        "id": "artifact_alpha",
                        "thread_id": "thread_alpha",
                        "tool_name": "git.diff",
                        "tool_call_id": "tool_call_alpha",
                        "channel": "stdout",
                        "media_type": "text/plain",
                        "content": "abcdef",
                        "content_bytes": 6,
                        "content_hash": "sha256:full",
                        "receipt_refs": ["receipt_alpha"]
                    }
                ]
            }))
            .expect("request");

        let response =
            project_runtime_coding_tool_artifact_read_response(request).expect("projection");
        let record = response["record"].as_object().expect("record");
        let result = record["result"].as_object().expect("result");

        assert_eq!(record["operation"], "artifact.read");
        assert_eq!(record["operation_kind"], "artifact.read_projection");
        assert_eq!(
            result["schema_version"],
            CODING_TOOL_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(result["artifact_id"], "artifact_alpha");
        assert_eq!(result["content"], "bcd");
        assert_eq!(result["offset_bytes"], 1);
        assert_eq!(result["length_bytes"], 3);
        assert_eq!(result["total_bytes"], 6);
        assert_eq!(result["truncated"], true);
        assert_eq!(result["artifact_refs"], json!(["artifact_alpha"]));
        assert_eq!(result["receipt_refs"], json!(["receipt_alpha"]));
    }

    #[test]
    fn tool_retrieve_projection_selects_channel_and_available_artifacts_in_rust() {
        let request: RuntimeCodingToolArtifactReadProjectionRequest =
            serde_json::from_value(json!({
                "schema_version": "ioi.runtime.coding-tool-artifact-read-projection-request.v1",
                "operation": "tool.retrieve_result",
                "operation_kind": "tool.retrieve_result_projection",
                "thread_id": "thread_alpha",
                "query": {
                    "tool_call_id": "tool_call_alpha",
                    "channel": "stderr",
                    "range": { "max_bytes": 64 }
                },
                "artifact_records": [
                    {
                        "id": "artifact_stdout",
                        "thread_id": "thread_alpha",
                        "tool_call_id": "tool_call_alpha",
                        "channel": "stdout",
                        "content": "out"
                    },
                    {
                        "id": "artifact_stderr",
                        "thread_id": "thread_alpha",
                        "tool_call_id": "tool_call_alpha",
                        "channel": "stderr",
                        "content": "err"
                    }
                ]
            }))
            .expect("request");

        let response =
            project_runtime_coding_tool_artifact_read_response(request).expect("projection");
        let result = response["record"]["result"].as_object().expect("result");
        let available = result["available_artifacts"].as_array().expect("available");

        assert_eq!(result["artifact_id"], "artifact_stderr");
        assert_eq!(result["content"], "err");
        assert_eq!(result["tool_call_id"], "tool_call_alpha");
        assert_eq!(available[0]["artifact_id"], "artifact_stderr");
        assert_eq!(available[1]["artifact_id"], "artifact_stdout");
    }

    #[test]
    fn artifact_read_projection_rejects_retired_target_alias_in_rust() {
        let request: RuntimeCodingToolArtifactReadProjectionRequest =
            serde_json::from_value(json!({
                "schema_version": "ioi.runtime.coding-tool-artifact-read-projection-request.v1",
                "operation": "artifact.read",
                "thread_id": "thread_alpha",
                "artifactId": "artifact_alpha",
                "artifact_records": []
            }))
            .expect("request");

        let error = project_runtime_coding_tool_artifact_read_response(request)
            .expect_err("retired target alias should fail");

        assert_eq!(
            error.code(),
            "runtime_coding_tool_artifact_read_target_alias_retired"
        );
    }

    #[test]
    fn artifact_read_projection_rejects_retired_range_alias_in_rust() {
        let request: RuntimeCodingToolArtifactReadProjectionRequest =
            serde_json::from_value(json!({
                "schema_version": "ioi.runtime.coding-tool-artifact-read-projection-request.v1",
                "operation": "artifact.read",
                "thread_id": "thread_alpha",
                "artifact_id": "artifact_alpha",
                "range": { "offsetBytes": 1 },
                "artifact_records": [
                    {
                        "id": "artifact_alpha",
                        "thread_id": "thread_alpha",
                        "content": "abcdef"
                    }
                ]
            }))
            .expect("request");

        let error = project_runtime_coding_tool_artifact_read_response(request)
            .expect_err("retired range alias should fail");

        assert_eq!(error.code(), "artifact_read_range_aliases_retired");
    }

    #[test]
    fn artifact_read_projection_blocks_cross_thread_in_rust() {
        let request: RuntimeCodingToolArtifactReadProjectionRequest =
            serde_json::from_value(json!({
                "schema_version": "ioi.runtime.coding-tool-artifact-read-projection-request.v1",
                "operation": "artifact.read",
                "thread_id": "thread_beta",
                "artifact_id": "artifact_alpha",
                "artifact_records": [
                    {
                        "id": "artifact_alpha",
                        "thread_id": "thread_alpha",
                        "content": "secret"
                    }
                ]
            }))
            .expect("request");

        let error = project_runtime_coding_tool_artifact_read_response(request)
            .expect_err("cross-thread read should fail");

        assert_eq!(
            error.code(),
            "runtime_coding_tool_artifact_read_cross_thread_blocked"
        );
    }

    #[test]
    fn artifact_read_requires_canonical_data_plane_and_emits_canonical_result() {
        let normalized = normalize_artifact_read(&json!({
            "artifact_id": "artifact_alpha",
            "rust_workload_data_plane": {
                "schema_version": "ioi.runtime.coding-tool-data-plane.v1",
                "source": "daemon_artifact_store",
                "operation": "artifact.read",
                "result": {
                    "schemaVersion": "retired",
                    "artifact_id": "artifact_alpha",
                    "artifact_ref": "artifact_alpha",
                    "artifact_refs": ["artifact_alpha"],
                    "artifactRefs": ["retired_artifact"],
                    "content": "hello artifact\n",
                    "contentHash": "prefetch-hash",
                    "receipt_refs": ["receipt_artifact_prefetch"],
                    "receiptRefs": ["receipt_retired"],
                    "shellFallbackUsed": true
                }
            }
        }))
        .expect("canonical artifact data plane");

        assert_eq!(normalized.artifact_refs, vec!["artifact_alpha"]);
        assert_eq!(normalized.receipt_refs, vec!["receipt_artifact_prefetch"]);
        assert_eq!(normalized.evidence_ref, "artifact_alpha");
        assert_eq!(
            normalized.observation["schema_version"],
            CODING_TOOL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(normalized.observation["backend"], "rust_artifact_read");
        assert_eq!(
            normalized.observation["data_plane_source"],
            "daemon_artifact_store"
        );
        assert_eq!(normalized.observation["shell_fallback_used"], false);
        assert_eq!(
            normalized.observation["content_hash"]
                .as_str()
                .expect("content hash")
                .len(),
            64
        );
        for key in [
            "schemaVersion",
            "artifactRefs",
            "contentHash",
            "receiptRefs",
            "shellFallbackUsed",
        ] {
            assert!(normalized.observation.get(key).is_none());
        }
    }

    #[test]
    fn tool_retrieve_result_rejects_retired_data_plane_alias() {
        let error = normalize_tool_retrieve_result(&json!({
            "tool_call_id": "tool_patch",
            "rustWorkloadDataPlane": {
                "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1"
            }
        }))
        .expect_err("retired envelope alias should fail");

        assert_eq!(error.code(), "data_plane_payload_alias_retired");
    }

    #[test]
    fn artifact_read_rejects_retired_schema_alias() {
        let error = normalize_artifact_read(&json!({
            "artifact_id": "artifact_alpha",
            "rust_workload_data_plane": {
                "schemaVersion": "ioi.runtime.coding-tool-data-plane.v1",
                "source": "daemon_artifact_store",
                "operation": "artifact.read",
                "result": {
                    "artifact_id": "artifact_alpha",
                    "content": "hello"
                }
            }
        }))
        .expect_err("retired schema alias should fail");

        assert_eq!(error.code(), "data_plane_schema_alias_retired");
    }
}
