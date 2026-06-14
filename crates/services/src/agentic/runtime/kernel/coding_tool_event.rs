use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, StorageBackendWriteAdmissionRecord,
    StorageBackendWriteProposal, STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION,
};

pub const CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-result-event-admission-request.v1";
pub const CODING_TOOL_RESULT_EVENT_ADMISSION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-result-event-admission.v1";
pub const CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-command-stream-admission-request.v1";
pub const CODING_TOOL_COMMAND_STREAM_ADMISSION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-command-stream-admission.v1";
pub const CODING_TOOL_COMMAND_STREAM_PAYLOAD_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-command-stream.v1";
pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
pub const CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-result-envelope-plan-request.v1";
pub const CODING_TOOL_RESULT_ENVELOPE_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-result-envelope-plan.v1";
pub const POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.post-edit-diagnostics-feedback-plan-request.v1";
pub const POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.post-edit-diagnostics-feedback-plan.v1";
pub const DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-rollback-repair-context.v1";
pub const LSP_DIAGNOSTICS_AUTO_NODE_ID: &str = "runtime.coding-tool.lsp-diagnostics.auto";

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolResultEventAdmissionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingReceiptRefs,
    Agentgres(AgentgresAdmissionError),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolCommandStreamAdmissionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingReceiptRefs,
    Agentgres(AgentgresAdmissionError),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolResultEnvelopePlanError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PostEditDiagnosticsFeedbackPlanError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

impl From<AgentgresAdmissionError> for CodingToolCommandStreamAdmissionError {
    fn from(error: AgentgresAdmissionError) -> Self {
        Self::Agentgres(error)
    }
}

impl From<AgentgresAdmissionError> for CodingToolResultEventAdmissionError {
    fn from(error: AgentgresAdmissionError) -> Self {
        Self::Agentgres(error)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolResultEventAdmissionRequest {
    pub schema_version: String,
    pub event: Value,
    #[serde(default)]
    pub latest_seq: Option<u64>,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolResultEventAdmissionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub event_id: String,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub tool_call_id: String,
    pub event_kind: String,
    pub event_status: String,
    pub seq: u64,
    pub latest_seq: u64,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub operation_ref: String,
    pub projection_watermark: String,
    pub payload_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub storage_admission: StorageBackendWriteAdmissionRecord,
    pub event: Value,
    pub admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolCommandStreamAdmissionRequest {
    pub schema_version: String,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub latest_seq: Option<u64>,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolCommandStreamAdmissionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    pub latest_seq: u64,
    pub event_count: usize,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub projection_watermark: String,
    pub payload_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub storage_admissions: Vec<StorageBackendWriteAdmissionRecord>,
    pub events: Vec<Value>,
    pub admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolResultEnvelopePlanRequest {
    pub schema_version: String,
    #[serde(default)]
    pub phase: Option<String>,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub input_summary: Value,
    #[serde(default)]
    pub result_summary: Value,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Value,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub rollback_refs: Vec<String>,
    #[serde(default)]
    pub diagnostics_repair_context: Value,
    #[serde(default)]
    pub approval_required: Option<bool>,
    #[serde(default)]
    pub approval_satisfied: Option<bool>,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub approval_manifest: Value,
    #[serde(default)]
    pub approval_decision_event_id: Option<String>,
    #[serde(default)]
    pub approval_receipt_refs: Vec<String>,
    #[serde(default)]
    pub approval_policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub step_module_backend: Option<String>,
    #[serde(default)]
    pub step_module: Value,
    #[serde(default)]
    pub step_module_error: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolResultEnvelopePlanRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub phase: String,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub step_module_context: Value,
    #[serde(default)]
    pub payload_summary: Value,
    #[serde(default)]
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostEditDiagnosticsFeedbackPlanRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub patch_tool_call_id: String,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub patch_result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostEditDiagnosticsFeedbackPlanRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub patch_tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub tool_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub workflow_node_id: String,
    pub paths: Vec<String>,
    pub rollback_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub diagnostics_repair_context: Value,
    pub plan_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingToolResultEventAdmissionProtocolRequest {
    pub request: CodingToolResultEventAdmissionRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingToolCommandStreamAdmissionProtocolRequest {
    pub request: CodingToolCommandStreamAdmissionRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolResultEnvelopePlanBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: CodingToolResultEnvelopePlanRequest,
}

#[derive(Debug, Deserialize)]
pub struct PostEditDiagnosticsFeedbackPlanBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: PostEditDiagnosticsFeedbackPlanRequest,
}

#[derive(Debug, Default, Clone)]
pub struct CodingToolResultEventAdmissionCore;

#[derive(Debug, Default, Clone)]
pub struct CodingToolCommandStreamAdmissionCore;

#[derive(Debug, Default, Clone)]
pub struct CodingToolResultEnvelopePlanCore;

#[derive(Debug, Default, Clone)]
pub struct PostEditDiagnosticsFeedbackPlanCore;

impl CodingToolResultEventAdmissionCore {
    pub fn admit(
        &self,
        request: &CodingToolResultEventAdmissionRequest,
    ) -> Result<CodingToolResultEventAdmissionRecord, CodingToolResultEventAdmissionError> {
        request.validate()?;
        let event = request.event.as_object().expect("validated event object");
        let event_stream_id = required_event_string(event, "event_stream_id")?;
        let thread_id = required_event_string(event, "thread_id")?;
        let tool_call_id = required_event_string(event, "tool_call_id")?;
        let idempotency_key = required_event_string(event, "idempotency_key")?;
        let event_kind = required_event_string(event, "event_kind")?;
        let event_status = required_event_string(event, "status")?;
        let payload_summary = event
            .get("payload_summary")
            .and_then(Value::as_object)
            .ok_or(CodingToolResultEventAdmissionError::MissingField(
                "payload_summary",
            ))?;
        let payload_schema_version = event
            .get("payload_schema_version")
            .and_then(Value::as_str)
            .or_else(|| {
                payload_summary
                    .get("schema_version")
                    .and_then(Value::as_str)
            })
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CodingToolResultEventAdmissionError::MissingField(
                "payload_schema_version",
            ))?;
        if payload_schema_version != CODING_TOOL_RESULT_SCHEMA_VERSION {
            return Err(CodingToolResultEventAdmissionError::MissingField(
                "payload_schema_version",
            ));
        }
        let latest_seq = request
            .latest_seq
            .or_else(|| event.get("latest_seq").and_then(Value::as_u64))
            .unwrap_or(0);
        let seq = latest_seq + 1;
        let event_id = optional_event_string(event, "event_id").unwrap_or_else(|| {
            format!(
                "event_coding_tool_{}",
                short_hash(&format!("{event_stream_id}:{idempotency_key}:{seq}"), 16)
            )
        });
        let created_at =
            optional_event_string(event, "created_at").unwrap_or_else(|| "rust_daemon_core".into());
        let expected_heads =
            unique_trimmed_strings(vec![request.expected_head.clone().unwrap_or_else(|| {
                format!(
                    "agentgres://runtime-events/{}/head/{}",
                    safe_component(&event_stream_id),
                    latest_seq
                )
            })]);
        let state_root_before = request.state_root_before.clone().unwrap_or_else(|| {
            format!(
                "sha256:{}",
                sha256_hex(
                    format!("runtime-event-before:{event_stream_id}:{latest_seq}").as_bytes()
                )
            )
        });
        let mut admitted_event = event.clone();
        admitted_event.insert("event_id".to_string(), Value::String(event_id.clone()));
        admitted_event.insert("seq".to_string(), json!(seq));
        admitted_event.insert("created_at".to_string(), Value::String(created_at));
        admitted_event.insert(
            "payload_schema_version".to_string(),
            Value::String(CODING_TOOL_RESULT_SCHEMA_VERSION.to_string()),
        );
        let receipt_refs = unique_trimmed_strings(
            json_string_array_from_map(&admitted_event, "receipt_refs")
                .into_iter()
                .chain(json_string_array_from_map(payload_summary, "receipt_refs"))
                .collect(),
        );
        if receipt_refs.is_empty() {
            return Err(CodingToolResultEventAdmissionError::MissingReceiptRefs);
        }
        let artifact_refs =
            unique_trimmed_strings(json_string_array_from_map(&admitted_event, "artifact_refs"));
        let rollback_refs =
            unique_trimmed_strings(json_string_array_from_map(&admitted_event, "rollback_refs"));
        let event_stream_ref = safe_component(&event_stream_id);
        let payload_ref = format!("payload://runtime-events/{event_stream_ref}/events/{event_id}");
        let payload_refs = unique_trimmed_strings(
            json_string_array_from_map(&admitted_event, "payload_refs")
                .into_iter()
                .chain(std::iter::once(payload_ref.clone()))
                .collect(),
        );
        admitted_event.insert("receipt_refs".to_string(), json!(receipt_refs.clone()));
        admitted_event.insert("artifact_refs".to_string(), json!(artifact_refs.clone()));
        admitted_event.insert("rollback_refs".to_string(), json!(rollback_refs.clone()));
        admitted_event.insert("payload_refs".to_string(), json!(payload_refs.clone()));
        let event_value = Value::Object(admitted_event.clone());
        let content_hash = value_hash(&event_value)?;
        let object_ref = format!("agentgres://runtime-events/{event_stream_ref}/events/{event_id}");
        let storage_admission =
            AgentgresAdmissionCore.admit_storage_backend_write(&StorageBackendWriteProposal {
                schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
                storage_backend_ref: "agentgres://runtime-events".to_string(),
                object_ref: object_ref.clone(),
                content_hash: content_hash.clone(),
                artifact_refs: artifact_refs.clone(),
                payload_refs: payload_refs.clone(),
                receipt_refs: receipt_refs.clone(),
            })?;
        let state_root_after = format!(
            "sha256:{}",
            sha256_hex(
                serde_json::to_vec(&json!({
                    "state_root_before": state_root_before,
                    "event_id": event_id,
                    "seq": seq,
                    "content_hash": content_hash,
                    "storage_admission_hash": storage_admission.admission_hash,
                    "receipt_refs": receipt_refs,
                    "artifact_refs": artifact_refs,
                    "payload_refs": payload_refs,
                }))
                .map_err(|error| CodingToolResultEventAdmissionError::HashFailed(
                    error.to_string()
                ))?
                .as_slice(),
            )
        );
        let head_suffix = state_root_after
            .trim_start_matches("sha256:")
            .chars()
            .take(24)
            .collect::<String>();
        let resulting_head =
            format!("agentgres://runtime-events/{event_stream_ref}/head/{head_suffix}");
        let operation_ref =
            format!("agentgres://runtime-events/{event_stream_ref}/operations/{event_id}");
        let projection_watermark = format!("runtime-events:{event_stream_id}:{seq}");
        admitted_event.insert(
            "agentgres_operation_ref".to_string(),
            Value::String(operation_ref.clone()),
        );
        admitted_event.insert(
            "agentgres_storage_object_ref".to_string(),
            Value::String(object_ref),
        );
        admitted_event.insert(
            "agentgres_storage_admission_hash".to_string(),
            Value::String(storage_admission.admission_hash.clone()),
        );
        admitted_event.insert(
            "expected_heads".to_string(),
            Value::Array(expected_heads.iter().cloned().map(Value::String).collect()),
        );
        admitted_event.insert(
            "state_root_before".to_string(),
            Value::String(state_root_before.clone()),
        );
        admitted_event.insert(
            "state_root_after".to_string(),
            Value::String(state_root_after.clone()),
        );
        admitted_event.insert(
            "resulting_head".to_string(),
            Value::String(resulting_head.clone()),
        );
        admitted_event.insert(
            "projection_watermark".to_string(),
            Value::String(projection_watermark.clone()),
        );
        let event_value = Value::Object(admitted_event);
        let mut record = CodingToolResultEventAdmissionRecord {
            schema_version: CODING_TOOL_RESULT_EVENT_ADMISSION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_result_event_admission".to_string(),
            status: "admitted".to_string(),
            operation_kind: "runtime.coding_tool_result_event".to_string(),
            event_id,
            event_stream_id,
            thread_id,
            turn_id: optional_event_string(event, "turn_id"),
            tool_call_id,
            event_kind,
            event_status,
            seq,
            latest_seq,
            expected_heads,
            state_root_before,
            state_root_after,
            resulting_head,
            operation_ref,
            projection_watermark,
            payload_refs,
            receipt_refs,
            artifact_refs,
            rollback_refs,
            storage_admission,
            event: event_value,
            admission_hash: String::new(),
        };
        record.admission_hash = value_hash(&serde_json::to_value(&record).map_err(|error| {
            CodingToolResultEventAdmissionError::HashFailed(error.to_string())
        })?)?;
        Ok(record)
    }
}

impl CodingToolCommandStreamAdmissionCore {
    pub fn admit(
        &self,
        request: &CodingToolCommandStreamAdmissionRequest,
    ) -> Result<CodingToolCommandStreamAdmissionRecord, CodingToolCommandStreamAdmissionError> {
        request.validate()?;
        let event_stream_id = required_trimmed(
            &request.event_stream_id,
            "event_stream_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        let thread_id = required_trimmed(
            &request.thread_id,
            "thread_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        let tool_id = required_trimmed(
            &request.tool_id,
            "tool_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        let tool_call_id = required_trimmed(
            &request.tool_call_id,
            "tool_call_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        let turn_id = request
            .turn_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let workspace_root = request
            .workspace_root
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let workflow_graph_id = request
            .workflow_graph_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let workflow_node_id = request
            .workflow_node_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let source = request
            .source
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("runtime_auto")
            .to_string();
        let status = request
            .status
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("completed")
            .to_string();
        let latest_seq = request.latest_seq.unwrap_or(0);
        let event_stream_ref = safe_component(&event_stream_id);
        let expected_heads =
            unique_trimmed_strings(vec![request.expected_head.clone().unwrap_or_else(|| {
                format!("agentgres://runtime-events/{event_stream_ref}/head/{latest_seq}")
            })]);
        let mut current_state_root = request.state_root_before.clone().unwrap_or_else(|| {
            format!(
                "sha256:{}",
                sha256_hex(
                    format!("runtime-command-stream-before:{event_stream_id}:{latest_seq}")
                        .as_bytes()
                )
            )
        });
        let chunks = if coding_tool_command_stream_requested(&request.request) {
            coding_tool_command_stream_chunks(&request.result)
        } else {
            Vec::new()
        };
        let receipt_refs = unique_trimmed_strings(request.receipt_refs.clone());
        let artifact_refs = unique_trimmed_strings(request.artifact_refs.clone());
        if !chunks.is_empty() && receipt_refs.is_empty() {
            return Err(CodingToolCommandStreamAdmissionError::MissingReceiptRefs);
        }
        let mut events = Vec::new();
        let mut payload_refs = Vec::new();
        let mut storage_admissions = Vec::new();
        let turn_or_thread = turn_id.as_deref().unwrap_or(thread_id.as_str());
        for (index, chunk) in chunks.iter().enumerate() {
            let seq = latest_seq + index as u64 + 1;
            let event_id = format!(
                "event_command_stream_{}",
                short_hash(
                    &format!(
                        "{event_stream_id}:{tool_call_id}:{}:{index}:{seq}",
                        chunk.channel
                    ),
                    16,
                )
            );
            let payload_ref =
                format!("payload://runtime-events/{event_stream_ref}/command-stream/{event_id}");
            let chunk_payload_refs = unique_trimmed_strings(vec![payload_ref.clone()]);
            payload_refs.push(payload_ref);
            let chunk_hash = format!("sha256:{}", sha256_hex(chunk.text.as_bytes()));
            let payload_summary = json!({
                "schema_version": CODING_TOOL_COMMAND_STREAM_PAYLOAD_SCHEMA_VERSION,
                "event_kind": "CodingToolCommandStream",
                "tool_name": tool_id,
                "tool_call_id": tool_call_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "workspace_root": workspace_root,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "status": status,
                "channel": chunk.channel,
                "chunk_index": index,
                "chunk_count": chunks.len(),
                "text": chunk.text,
                "text_hash": chunk_hash,
                "receipt_refs": receipt_refs,
                "artifact_refs": artifact_refs,
            });
            let mut event = json!({
                "event_stream_id": event_stream_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "item_id": format!("{turn_or_thread}:item:coding-tool-command-stream:{}:{index}", safe_component(&tool_id)),
                "idempotency_key": format!("thread:{thread_id}:coding-tool-command-stream:{tool_call_id}:{index}"),
                "source": source,
                "source_event_kind": "coding_tool.command_stream",
                "event_kind": "artifact.command_stream",
                "status": status,
                "actor": "runtime",
                "workspace_root": workspace_root,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "component_kind": "coding_tool",
                "tool_call_id": tool_call_id,
                "artifact_refs": artifact_refs,
                "receipt_refs": receipt_refs,
                "payload_refs": chunk_payload_refs,
                "payload_schema_version": CODING_TOOL_COMMAND_STREAM_PAYLOAD_SCHEMA_VERSION,
                "payload_summary": payload_summary,
                "event_id": event_id,
                "seq": seq,
                "created_at": "rust_daemon_core",
            });
            let content_hash = value_hash_for_command_stream(&event)?;
            let object_ref =
                format!("agentgres://runtime-events/{event_stream_ref}/command-stream/{event_id}");
            let storage_admission = AgentgresAdmissionCore.admit_storage_backend_write(
                &StorageBackendWriteProposal {
                    schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
                    storage_backend_ref: "agentgres://runtime-events".to_string(),
                    object_ref: object_ref.clone(),
                    content_hash: content_hash.clone(),
                    artifact_refs: artifact_refs.clone(),
                    payload_refs: chunk_payload_refs.clone(),
                    receipt_refs: receipt_refs.clone(),
                },
            )?;
            let state_root_before = current_state_root.clone();
            let state_root_after = format!(
                "sha256:{}",
                sha256_hex(
                    serde_json::to_vec(&json!({
                        "state_root_before": state_root_before,
                        "event_id": event_id,
                        "seq": seq,
                        "content_hash": content_hash,
                        "storage_admission_hash": storage_admission.admission_hash,
                        "receipt_refs": receipt_refs,
                        "artifact_refs": artifact_refs,
                        "payload_refs": chunk_payload_refs,
                    }))
                    .map_err(|error| CodingToolCommandStreamAdmissionError::HashFailed(
                        error.to_string()
                    ))?
                    .as_slice(),
                )
            );
            let head_suffix = state_root_after
                .trim_start_matches("sha256:")
                .chars()
                .take(24)
                .collect::<String>();
            let resulting_head =
                format!("agentgres://runtime-events/{event_stream_ref}/head/{head_suffix}");
            let operation_ref =
                format!("agentgres://runtime-events/{event_stream_ref}/command-stream/operations/{event_id}");
            let projection_watermark = format!("runtime-events:{event_stream_id}:{seq}");
            if let Some(event_object) = event.as_object_mut() {
                event_object.insert(
                    "agentgres_operation_ref".to_string(),
                    Value::String(operation_ref),
                );
                event_object.insert(
                    "agentgres_storage_object_ref".to_string(),
                    Value::String(object_ref),
                );
                event_object.insert(
                    "agentgres_storage_admission_hash".to_string(),
                    Value::String(storage_admission.admission_hash.clone()),
                );
                event_object.insert(
                    "expected_heads".to_string(),
                    Value::Array(expected_heads.iter().cloned().map(Value::String).collect()),
                );
                event_object.insert(
                    "state_root_before".to_string(),
                    Value::String(state_root_before.clone()),
                );
                event_object.insert(
                    "state_root_after".to_string(),
                    Value::String(state_root_after.clone()),
                );
                event_object.insert(
                    "resulting_head".to_string(),
                    Value::String(resulting_head.clone()),
                );
                event_object.insert(
                    "projection_watermark".to_string(),
                    Value::String(projection_watermark),
                );
            }
            current_state_root = state_root_after;
            storage_admissions.push(storage_admission);
            events.push(event);
        }
        let resulting_head = if events.is_empty() {
            expected_heads.first().cloned().unwrap_or_else(|| {
                format!("agentgres://runtime-events/{event_stream_ref}/head/{latest_seq}")
            })
        } else {
            events
                .last()
                .and_then(|event| event.get("resulting_head"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let projection_watermark = format!(
            "runtime-events:{event_stream_id}:{}",
            latest_seq + events.len() as u64
        );
        let mut record = CodingToolCommandStreamAdmissionRecord {
            schema_version: CODING_TOOL_COMMAND_STREAM_ADMISSION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_command_stream_admission".to_string(),
            status: if events.is_empty() {
                "skipped".to_string()
            } else {
                "admitted".to_string()
            },
            operation_kind: "runtime.coding_tool_command_stream".to_string(),
            event_stream_id,
            thread_id,
            turn_id,
            tool_id,
            tool_call_id,
            latest_seq,
            event_count: events.len(),
            expected_heads,
            state_root_before: request.state_root_before.clone().unwrap_or_else(|| {
                format!(
                    "sha256:{}",
                    sha256_hex(
                        format!(
                            "runtime-command-stream-before:{}:{}",
                            request.event_stream_id, latest_seq
                        )
                        .as_bytes()
                    )
                )
            }),
            state_root_after: current_state_root,
            resulting_head,
            projection_watermark,
            payload_refs: unique_trimmed_strings(payload_refs),
            receipt_refs,
            artifact_refs,
            storage_admissions,
            events,
            admission_hash: String::new(),
        };
        record.admission_hash =
            value_hash_for_command_stream(&serde_json::to_value(&record).map_err(|error| {
                CodingToolCommandStreamAdmissionError::HashFailed(error.to_string())
            })?)?;
        Ok(record)
    }
}

impl CodingToolResultEnvelopePlanCore {
    pub fn plan(
        &self,
        request: &CodingToolResultEnvelopePlanRequest,
    ) -> Result<CodingToolResultEnvelopePlanRecord, CodingToolResultEnvelopePlanError> {
        request.validate()?;
        let event_stream_id = required_trimmed(
            &request.event_stream_id,
            "event_stream_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let thread_id = required_trimmed(
            &request.thread_id,
            "thread_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let tool_id = required_trimmed(
            &request.tool_id,
            "tool_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let tool_call_id = required_trimmed(
            &request.tool_call_id,
            "tool_call_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let workflow_node_id = required_trimmed(
            &request.workflow_node_id,
            "workflow_node_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let idempotency_key = required_trimmed(
            &request.idempotency_key,
            "idempotency_key",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        let phase = request
            .phase
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("result_event")
            .to_string();
        let turn_id = request
            .turn_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let turn_or_thread = turn_id.as_deref().unwrap_or(thread_id.as_str());
        let workspace_root = request
            .workspace_root
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let workflow_graph_id = request
            .workflow_graph_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let source = request
            .source
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("runtime_auto")
            .to_string();
        let status = request
            .status
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("completed")
            .to_string();
        let receipt_refs = unique_trimmed_strings(request.receipt_refs.clone());
        let artifact_refs = unique_trimmed_strings(request.artifact_refs.clone());
        let rollback_refs = unique_trimmed_strings(request.rollback_refs.clone());
        let approval_ref = request
            .approval_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("approval:{value}"));
        let step_module_context = json!({
            "run_id": format!("run:{thread_id}"),
            "task_id": format!("task:{turn_or_thread}"),
            "thread_id": thread_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "action_proposal_ref": format!("action:coding-tool:{tool_call_id}"),
            "gate_result_ref": format!("gate:coding-tool:{tool_call_id}"),
            "approval_ref": approval_ref,
            "idempotency_key": idempotency_key,
            "status": if status == "failed" { "failure" } else { "success" },
            "workflow_projection_status": "live",
            "receipt_refs": receipt_refs,
            "artifact_refs": artifact_refs,
            "workspace_root": workspace_root,
        });
        let mut payload_summary = Value::Null;
        let mut event = Value::Null;
        if phase == "result_event" {
            let summary = request
                .summary
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("{tool_id} {status}."));
            let step_module = request
                .step_module
                .as_object()
                .cloned()
                .unwrap_or_else(Map::new);
            let step_module_backend = request
                .step_module_backend
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| optional_json_string_from_map(&step_module, "backend"));
            let step_module_invocation = step_module
                .get("invocation")
                .cloned()
                .unwrap_or(Value::Null);
            let step_module_result = step_module.get("result").cloned().unwrap_or(Value::Null);
            let approval_receipt_refs =
                unique_trimmed_strings(request.approval_receipt_refs.clone());
            let approval_policy_decision_refs =
                unique_trimmed_strings(request.approval_policy_decision_refs.clone());
            payload_summary = json!({
                "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
                "event_kind": "CodingToolResult",
                "tool_pack": "coding",
                "tool_name": tool_id,
                "tool_call_id": tool_call_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "workspace_root": workspace_root,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "status": status,
                "summary": summary,
                "shell_fallback_used": false,
                "input_summary": request.input_summary.clone(),
                "result_summary": request.result_summary.clone(),
                "result": request.result.clone(),
                "error": request.error.clone(),
                "rollback_refs": rollback_refs,
                "diagnostics_repair_context": request.diagnostics_repair_context.clone(),
                "approval_required": request.approval_required.unwrap_or(false),
                "approval_satisfied": request.approval_satisfied.unwrap_or(false),
                "approval_id": request.approval_id.clone(),
                "approval_manifest": request.approval_manifest.clone(),
                "approval_decision_event_id": request.approval_decision_event_id.clone(),
                "approval_receipt_refs": approval_receipt_refs,
                "approval_policy_decision_refs": approval_policy_decision_refs,
                "receipt_id": request.receipt_id.clone(),
                "receipt_count": receipt_refs.len(),
                "artifact_count": artifact_refs.len(),
                "step_module_backend": step_module_backend,
                "step_module_invocation": step_module_invocation,
                "step_module_result": step_module_result,
                "step_module_error": request.step_module_error.clone(),
            });
            event = json!({
                "event_stream_id": event_stream_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "item_id": format!(
                    "{turn_or_thread}:item:coding-tool:{}:{}",
                    safe_component(&tool_id),
                    short_hash(&tool_call_id, 12)
                ),
                "idempotency_key": idempotency_key,
                "source": source,
                "source_event_kind": coding_tool_source_event_kind(&tool_id),
                "event_kind": if status == "failed" { "tool.failed" } else { "tool.completed" },
                "status": status,
                "actor": "runtime",
                "workspace_root": workspace_root,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "component_kind": "coding_tool",
                "tool_call_id": tool_call_id,
                "artifact_refs": artifact_refs,
                "receipt_refs": receipt_refs,
                "rollback_refs": rollback_refs,
                "payload_schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
                "payload_summary": payload_summary,
            });
        }
        let mut record = CodingToolResultEnvelopePlanRecord {
            schema_version: CODING_TOOL_RESULT_ENVELOPE_PLAN_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_result_envelope_plan".to_string(),
            status: "planned".to_string(),
            operation_kind: "runtime.coding_tool.result_envelope".to_string(),
            phase,
            event_stream_id,
            thread_id,
            turn_id,
            tool_id,
            tool_call_id,
            workflow_graph_id,
            workflow_node_id,
            step_module_context,
            payload_summary,
            event,
            receipt_refs,
            artifact_refs,
            rollback_refs,
            envelope_hash: String::new(),
        };
        record.envelope_hash = value_hash_for_coding_tool_result_envelope_plan(
            &serde_json::to_value(&record).map_err(|error| {
                CodingToolResultEnvelopePlanError::HashFailed(error.to_string())
            })?,
        )?;
        Ok(record)
    }
}

impl PostEditDiagnosticsFeedbackPlanCore {
    pub fn plan(
        &self,
        request: &PostEditDiagnosticsFeedbackPlanRequest,
    ) -> Result<PostEditDiagnosticsFeedbackPlanRecord, PostEditDiagnosticsFeedbackPlanError> {
        request.validate()?;
        let thread_id = required_trimmed(
            &request.thread_id,
            "thread_id",
            PostEditDiagnosticsFeedbackPlanError::MissingField,
        )?;
        let patch_tool_call_id = required_trimmed(
            &request.patch_tool_call_id,
            "patch_tool_call_id",
            PostEditDiagnosticsFeedbackPlanError::MissingField,
        )?;
        let turn_id = optional_trimmed_string(request.turn_id.as_deref());
        let workflow_graph_id = optional_trimmed_string(request.workflow_graph_id.as_deref());
        let config = post_edit_diagnostics_config(&request.request, &request.input);
        let changed_files = post_edit_changed_files(&request.patch_result);
        let paths = changed_files
            .iter()
            .filter(|entry| entry.diagnostics_recommended)
            .filter_map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        let workspace_snapshot = request
            .patch_result
            .get("workspace_snapshot")
            .and_then(Value::as_object);
        let workspace_snapshot_id =
            optional_json_string(&request.patch_result, "workspace_snapshot_id").or_else(|| {
                workspace_snapshot
                    .and_then(|value| optional_json_string_from_map(value, "snapshot_id"))
            });
        let rollback_refs = unique_trimmed_strings(
            workspace_snapshot_id
                .iter()
                .cloned()
                .chain(json_string_array_from_value(
                    &request.patch_result,
                    "rollback_refs",
                ))
                .collect(),
        );
        let skip_reason = if config.mode == "skip" {
            Some("diagnostics_mode_skip".to_string())
        } else if paths.is_empty() {
            Some("no_changed_files".to_string())
        } else {
            None
        };
        let status = if skip_reason.is_some() {
            "skipped"
        } else {
            "planned"
        };
        let workflow_node_id = LSP_DIAGNOSTICS_AUTO_NODE_ID.to_string();
        let tool_call_id = if status == "planned" {
            Some(format!(
                "coding_tool_lsp_diagnostics_auto_{}",
                short_hash(&format!("{patch_tool_call_id}:{}", paths.join(",")), 16)
            ))
        } else {
            None
        };
        let changed_files_value = Value::Array(
            changed_files
                .iter()
                .map(|entry| {
                    json!({
                        "path": entry.path.clone(),
                        "before_hash": entry.before_hash.clone(),
                        "after_hash": entry.after_hash.clone(),
                        "diagnostics_recommended": entry.diagnostics_recommended,
                    })
                })
                .collect(),
        );
        let source_workflow_node_id = optional_json_string(&request.request, "workflow_node_id");
        let restore = workspace_snapshot
            .and_then(|value| value.get("restore"))
            .cloned()
            .unwrap_or(Value::Null);
        let diagnostics_repair_context = if status == "planned" {
            json!({
                "schema_version": DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
                "object": "ioi.runtime_diagnostics_rollback_repair_context",
                "source_tool_name": "file.apply_patch",
                "source_tool_call_id": patch_tool_call_id.clone(),
                "source_workflow_graph_id": workflow_graph_id.clone(),
                "source_workflow_node_id": source_workflow_node_id.clone(),
                "workspace_snapshot_id": workspace_snapshot_id.clone(),
                "restore_policy": config.restore_policy.clone(),
                "restore_conflict_policy": config.restore_conflict_policy.clone(),
                "diagnostics_repair_default": config.diagnostics_repair_default.clone(),
                "operator_override_requires_approval": config.operator_override_requires_approval,
                "rollback_refs": rollback_refs.clone(),
                "restore": restore,
                "changed_files": changed_files_value.clone(),
            })
        } else {
            Value::Null
        };
        let planned_request = if status == "planned" {
            json!({
                "source": "runtime_auto",
                "turn_id": turn_id.clone(),
                "workflow_graph_id": workflow_graph_id.clone(),
                "workflow_node_id": workflow_node_id.clone(),
                "tool_call_id": tool_call_id.clone(),
                "rollback_refs": rollback_refs.clone(),
                "diagnostics_repair_context": diagnostics_repair_context.clone(),
                "input": {
                    "commandId": config.command_id.clone(),
                    "paths": paths.clone(),
                    "cwd": config.cwd.clone(),
                    "timeoutMs": config.timeout_ms,
                    "maxOutputBytes": config.max_output_bytes,
                },
            })
        } else {
            Value::Null
        };
        let mut record = PostEditDiagnosticsFeedbackPlanRecord {
            schema_version: POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_post_edit_diagnostics_feedback_plan".to_string(),
            status: status.to_string(),
            operation_kind: "runtime.post_edit_diagnostics_feedback".to_string(),
            thread_id,
            turn_id,
            patch_tool_call_id,
            workflow_graph_id,
            tool_id: "lsp.diagnostics".to_string(),
            tool_call_id,
            workflow_node_id,
            paths,
            rollback_refs,
            workspace_snapshot_id,
            skip_reason,
            request: planned_request,
            diagnostics_repair_context,
            plan_hash: String::new(),
        };
        record.plan_hash =
            value_hash_for_post_edit_diagnostics_plan(&serde_json::to_value(&record).map_err(
                |error| PostEditDiagnosticsFeedbackPlanError::HashFailed(error.to_string()),
            )?)?;
        Ok(record)
    }
}

pub fn admit_coding_tool_result_event_response(
    request: CodingToolResultEventAdmissionProtocolRequest,
) -> Result<Value, CodingToolResultEventAdmissionError> {
    let record = CodingToolResultEventAdmissionCore.admit(&request.request)?;
    Ok(json!({
        "source": "rust_coding_tool_result_event_admission_protocol",
        "backend": "rust_runtime_agentgres",
        "admitted": true,
        "record": record,
        "event": record.event,
        "event_id": record.event_id,
        "seq": record.seq,
        "operation_kind": record.operation_kind,
        "operation_ref": record.operation_ref,
        "state_root_before": record.state_root_before,
        "state_root_after": record.state_root_after,
        "resulting_head": record.resulting_head,
        "projection_watermark": record.projection_watermark,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "artifact_refs": record.artifact_refs,
        "rollback_refs": record.rollback_refs,
        "admission_hash": record.admission_hash,
        "storage_admission": record.storage_admission,
    }))
}

pub fn admit_coding_tool_command_stream_events_response(
    request: CodingToolCommandStreamAdmissionProtocolRequest,
) -> Result<Value, CodingToolCommandStreamAdmissionError> {
    let record = CodingToolCommandStreamAdmissionCore.admit(&request.request)?;
    Ok(json!({
        "source": "rust_coding_tool_command_stream_admission_protocol",
        "backend": "rust_runtime_agentgres",
        "admitted": record.status == "admitted",
        "record": record,
        "events": record.events,
        "event_count": record.event_count,
        "operation_kind": record.operation_kind,
        "state_root_before": record.state_root_before,
        "state_root_after": record.state_root_after,
        "resulting_head": record.resulting_head,
        "projection_watermark": record.projection_watermark,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "artifact_refs": record.artifact_refs,
        "storage_admissions": record.storage_admissions,
        "admission_hash": record.admission_hash,
    }))
}

pub fn plan_coding_tool_result_envelope_response(
    request: CodingToolResultEnvelopePlanBridgeRequest,
) -> Result<Value, CodingToolResultEnvelopePlanError> {
    let record = CodingToolResultEnvelopePlanCore.plan(&request.request)?;
    Ok(json!({
        "source": "rust_coding_tool_result_envelope_plan_command",
        "backend": request.backend.unwrap_or_else(|| "rust_runtime_coding_tool_event".to_string()),
        "planned": true,
        "record": record.clone(),
        "phase": record.phase.clone(),
        "operation_kind": record.operation_kind.clone(),
        "step_module_context": record.step_module_context.clone(),
        "payload_summary": record.payload_summary.clone(),
        "event": record.event.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "rollback_refs": record.rollback_refs.clone(),
        "envelope_hash": record.envelope_hash.clone(),
    }))
}

pub fn plan_post_edit_diagnostics_feedback_response(
    request: PostEditDiagnosticsFeedbackPlanBridgeRequest,
) -> Result<Value, PostEditDiagnosticsFeedbackPlanError> {
    let record = PostEditDiagnosticsFeedbackPlanCore.plan(&request.request)?;
    let planned = record.status == "planned";
    let skipped = record.status == "skipped";
    Ok(json!({
        "source": "rust_post_edit_diagnostics_feedback_plan_command",
        "backend": request.backend.unwrap_or_else(|| "rust_runtime_diagnostics_feedback".to_string()),
        "planned": planned,
        "skipped": skipped,
        "record": record.clone(),
        "request": record.request.clone(),
        "diagnostics_repair_context": record.diagnostics_repair_context.clone(),
        "tool_id": record.tool_id.clone(),
        "tool_call_id": record.tool_call_id.clone(),
        "paths": record.paths.clone(),
        "rollback_refs": record.rollback_refs.clone(),
        "workspace_snapshot_id": record.workspace_snapshot_id.clone(),
        "plan_hash": record.plan_hash.clone(),
    }))
}

impl CodingToolResultEventAdmissionRequest {
    pub fn validate(&self) -> Result<(), CodingToolResultEventAdmissionError> {
        if self.schema_version != CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolResultEventAdmissionError::InvalidSchemaVersion {
                expected: CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let event = self
            .event
            .as_object()
            .ok_or(CodingToolResultEventAdmissionError::MissingField("event"))?;
        for field in [
            "event_stream_id",
            "thread_id",
            "idempotency_key",
            "event_kind",
            "status",
            "tool_call_id",
            "payload_summary",
        ] {
            if field == "payload_summary" {
                if !event.get(field).is_some_and(Value::is_object) {
                    return Err(CodingToolResultEventAdmissionError::MissingField(field));
                }
            } else {
                required_event_string(event, field)?;
            }
        }
        Ok(())
    }
}

impl CodingToolCommandStreamAdmissionRequest {
    pub fn validate(&self) -> Result<(), CodingToolCommandStreamAdmissionError> {
        if self.schema_version != CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION {
            return Err(
                CodingToolCommandStreamAdmissionError::InvalidSchemaVersion {
                    expected: CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        required_trimmed(
            &self.event_stream_id,
            "event_stream_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        required_trimmed(
            &self.thread_id,
            "thread_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        required_trimmed(
            &self.tool_id,
            "tool_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        required_trimmed(
            &self.tool_call_id,
            "tool_call_id",
            CodingToolCommandStreamAdmissionError::MissingField,
        )?;
        Ok(())
    }
}

impl CodingToolResultEnvelopePlanRequest {
    pub fn validate(&self) -> Result<(), CodingToolResultEnvelopePlanError> {
        if self.schema_version != CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolResultEnvelopePlanError::InvalidSchemaVersion {
                expected: CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        required_trimmed(
            &self.event_stream_id,
            "event_stream_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        required_trimmed(
            &self.thread_id,
            "thread_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        required_trimmed(
            &self.tool_id,
            "tool_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        required_trimmed(
            &self.tool_call_id,
            "tool_call_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        required_trimmed(
            &self.workflow_node_id,
            "workflow_node_id",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        required_trimmed(
            &self.idempotency_key,
            "idempotency_key",
            CodingToolResultEnvelopePlanError::MissingField,
        )?;
        Ok(())
    }
}

impl PostEditDiagnosticsFeedbackPlanRequest {
    pub fn validate(&self) -> Result<(), PostEditDiagnosticsFeedbackPlanError> {
        if self.schema_version != POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION {
            return Err(PostEditDiagnosticsFeedbackPlanError::InvalidSchemaVersion {
                expected: POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        required_trimmed(
            &self.thread_id,
            "thread_id",
            PostEditDiagnosticsFeedbackPlanError::MissingField,
        )?;
        required_trimmed(
            &self.patch_tool_call_id,
            "patch_tool_call_id",
            PostEditDiagnosticsFeedbackPlanError::MissingField,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostEditChangedFile {
    path: Option<String>,
    before_hash: Option<String>,
    after_hash: Option<String>,
    diagnostics_recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostEditDiagnosticsConfig {
    mode: String,
    command_id: String,
    cwd: String,
    timeout_ms: i64,
    max_output_bytes: i64,
    restore_policy: String,
    restore_conflict_policy: String,
    diagnostics_repair_default: String,
    operator_override_requires_approval: bool,
}

fn post_edit_diagnostics_config(request: &Value, input: &Value) -> PostEditDiagnosticsConfig {
    let pack = coding_tool_pack_config(request);
    let mode = normalize_diagnostics_mode(first_json_string(&[
        request.get("diagnostics_mode"),
        input.get("diagnostics_mode"),
        pack.and_then(|value| value.get("diagnostics_mode")),
        pack.and_then(|value| value.get("diagnostic_mode")),
    ]));
    let command_id = first_json_string(&[
        request.get("diagnostic_command_id"),
        input.get("diagnostic_command_id"),
        pack.and_then(|value| value.get("default_diagnostic_command_id")),
    ])
    .unwrap_or_else(|| "auto".to_string());
    let cwd = first_json_string(&[input.get("cwd"), request.get("cwd")])
        .unwrap_or_else(|| ".".to_string());
    let timeout_ms = first_json_i64(&[
        input.get("diagnostic_timeout_ms"),
        request.get("diagnostic_timeout_ms"),
        pack.and_then(|value| value.get("timeout_ms")),
    ])
    .unwrap_or(30000);
    let max_output_bytes = first_json_i64(&[
        input.get("diagnostic_max_output_bytes"),
        request.get("diagnostic_max_output_bytes"),
    ])
    .or_else(|| {
        pack.and_then(|value| value.get("max_output_bytes"))
            .and_then(json_i64)
    })
    .unwrap_or(4096);
    let restore_policy = normalize_restore_policy(first_json_string(&[
        request.get("restore_policy"),
        input.get("restore_policy"),
        pack.and_then(|value| value.get("restore_policy")),
    ]));
    let restore_conflict_policy = normalize_restore_conflict_policy(first_json_string(&[
        request.get("restore_conflict_policy"),
        input.get("restore_conflict_policy"),
        pack.and_then(|value| value.get("restore_conflict_policy")),
        pack.and_then(|value| value.get("conflict_policy")),
    ]));
    let diagnostics_repair_default = normalize_diagnostics_repair_default(first_json_string(&[
        request.get("diagnostics_repair_default"),
        request.get("default_repair_decision"),
        input.get("diagnostics_repair_default"),
        input.get("default_repair_decision"),
        pack.and_then(|value| value.get("diagnostics_repair_default")),
        pack.and_then(|value| value.get("default_repair_decision")),
    ]));
    let operator_override_requires_approval = first_json_bool(&[
        request.get("operator_override_requires_approval"),
        input.get("operator_override_requires_approval"),
        pack.and_then(|value| value.get("operator_override_requires_approval")),
    ])
    .unwrap_or(true);
    PostEditDiagnosticsConfig {
        mode,
        command_id,
        cwd,
        timeout_ms,
        max_output_bytes,
        restore_policy,
        restore_conflict_policy,
        diagnostics_repair_default,
        operator_override_requires_approval,
    }
}

fn post_edit_changed_files(patch_result: &Value) -> Vec<PostEditChangedFile> {
    patch_result
        .get("changed_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .map(|entry| PostEditChangedFile {
                    path: optional_json_string_from_map(entry, "path"),
                    before_hash: optional_json_string_from_map(entry, "before_hash"),
                    after_hash: optional_json_string_from_map(entry, "after_hash"),
                    diagnostics_recommended: !matches!(
                        entry.get("diagnostics_recommended"),
                        Some(Value::Bool(false))
                    ),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn coding_tool_pack_config(request: &Value) -> Option<&Map<String, Value>> {
    let pack_root = request.get("tool_pack").or_else(|| {
        request
            .get("options")
            .and_then(|options| options.get("tool_pack"))
    })?;
    let pack_root = pack_root.as_object()?;
    pack_root
        .get("coding")
        .and_then(Value::as_object)
        .or(Some(pack_root))
}

fn normalize_diagnostics_mode(value: Option<String>) -> String {
    match value
        .as_deref()
        .unwrap_or("advisory")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "skip" | "off" | "disabled" | "none" => "skip".to_string(),
        "block" | "blocking" | "required" | "fail" => "blocking".to_string(),
        _ => "advisory".to_string(),
    }
}

fn normalize_restore_policy(value: Option<String>) -> String {
    match value
        .as_deref()
        .unwrap_or("apply_with_approval")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "disabled" | "disable" | "off" | "none" | "blocked" => "disabled".to_string(),
        "preview" | "preview_only" | "restore_preview" | "preview-only" => {
            "preview_only".to_string()
        }
        _ => "apply_with_approval".to_string(),
    }
}

fn normalize_restore_conflict_policy(value: Option<String>) -> String {
    match value
        .as_deref()
        .unwrap_or("block")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "allow_override" | "override" | "override_conflicts" | "force" | "apply_with_conflicts" => {
            "allow_override".to_string()
        }
        "require_approval" | "approval" | "approval_required" => "require_approval".to_string(),
        _ => "block".to_string(),
    }
}

fn normalize_diagnostics_repair_default(value: Option<String>) -> String {
    match value
        .as_deref()
        .unwrap_or("repair_retry")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "restore_preview" | "preview" | "preview_restore" => "restore_preview".to_string(),
        "restore_apply" | "apply" | "apply_restore" | "restore_apply_with_approval" => {
            "restore_apply".to_string()
        }
        "operator_override" | "override" | "continue" => "operator_override".to_string(),
        _ => "repair_retry".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandStreamChunk {
    channel: String,
    text: String,
}

fn coding_tool_command_stream_requested(request: &Value) -> bool {
    json_bool(request, "stream_output")
        || json_bool(request, "command_stream")
        || request
            .get("input")
            .is_some_and(|input| json_bool(input, "stream_output"))
}

fn coding_tool_command_stream_chunks(result: &Value) -> Vec<CommandStreamChunk> {
    let mut chunks = Vec::new();
    for channel in ["stdout", "stderr"] {
        let Some(text) = value_string_from_value(result, channel) else {
            continue;
        };
        for chunk in split_command_stream_text(&text) {
            chunks.push(CommandStreamChunk {
                channel: channel.to_string(),
                text: chunk,
            });
        }
    }
    chunks
}

fn split_command_stream_text(text: &str) -> Vec<String> {
    const MAX_CHARS: usize = 800;
    let chars = text.chars().collect::<Vec<_>>();
    chars
        .chunks(MAX_CHARS)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

fn json_bool(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn value_string_from_value(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_trimmed<E>(
    value: &str,
    field: &'static str,
    missing: fn(&'static str) -> E,
) -> Result<String, E> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(missing(field))
    } else {
        Ok(trimmed.to_string())
    }
}

fn optional_trimmed_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_json_string(values: &[Option<&Value>]) -> Option<String> {
    values.iter().find_map(|value| value.and_then(json_string))
}

fn first_json_i64(values: &[Option<&Value>]) -> Option<i64> {
    values.iter().find_map(|value| value.and_then(json_i64))
}

fn first_json_bool(values: &[Option<&Value>]) -> Option<bool> {
    values
        .iter()
        .find_map(|value| value.and_then(json_bool_value))
}

fn json_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| {
            value
                .as_str()
                .map(str::trim)
                .and_then(|value| value.parse::<i64>().ok())
        })
}

fn json_bool_value(value: &Value) -> Option<bool> {
    value.as_bool().or_else(|| match value.as_str()?.trim() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    })
}

fn optional_json_string(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(json_string)
}

fn optional_json_string_from_map(value: &Map<String, Value>, field: &str) -> Option<String> {
    value.get(field).and_then(json_string)
}

fn json_string_array_from_value(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(json_string).collect())
        .unwrap_or_default()
}

fn required_event_string(
    event: &Map<String, Value>,
    field: &'static str,
) -> Result<String, CodingToolResultEventAdmissionError> {
    optional_event_string(event, field)
        .ok_or(CodingToolResultEventAdmissionError::MissingField(field))
}

fn optional_event_string(event: &Map<String, Value>, field: &str) -> Option<String> {
    event
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_string_array_from_map(event: &Map<String, Value>, field: &str) -> Vec<String> {
    event
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn unique_trimmed_strings(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing == trimmed) {
            unique.push(trimmed.to_string());
        }
        unique
    })
}

fn safe_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "runtime".to_string()
    } else {
        safe
    }
}

fn short_hash(value: &str, chars: usize) -> String {
    sha256_hex(value.as_bytes()).chars().take(chars).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn value_hash(value: &Value) -> Result<String, CodingToolResultEventAdmissionError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("sha256:{}", sha256_hex(&bytes)))
        .map_err(|error| CodingToolResultEventAdmissionError::HashFailed(error.to_string()))
}

fn value_hash_for_command_stream(
    value: &Value,
) -> Result<String, CodingToolCommandStreamAdmissionError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("sha256:{}", sha256_hex(&bytes)))
        .map_err(|error| CodingToolCommandStreamAdmissionError::HashFailed(error.to_string()))
}

fn value_hash_for_post_edit_diagnostics_plan(
    value: &Value,
) -> Result<String, PostEditDiagnosticsFeedbackPlanError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("sha256:{}", sha256_hex(&bytes)))
        .map_err(|error| PostEditDiagnosticsFeedbackPlanError::HashFailed(error.to_string()))
}

fn value_hash_for_coding_tool_result_envelope_plan(
    value: &Value,
) -> Result<String, CodingToolResultEnvelopePlanError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("sha256:{}", sha256_hex(&bytes)))
        .map_err(|error| CodingToolResultEnvelopePlanError::HashFailed(error.to_string()))
}

fn coding_tool_source_event_kind(tool_id: &str) -> String {
    let parts = tool_id
        .split(['.', '_', '-'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<String>();
    format!("CodingTool.{parts}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission_request() -> CodingToolResultEventAdmissionRequest {
        CodingToolResultEventAdmissionRequest {
            schema_version: CODING_TOOL_RESULT_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION.to_string(),
            latest_seq: Some(2),
            expected_head: Some("agentgres://runtime-events/thread_1_events/head/2".to_string()),
            state_root_before: Some("sha256:before".to_string()),
            event: json!({
                "event_stream_id": "thread_1:events",
                "thread_id": "thread_1",
                "turn_id": "turn_1",
                "item_id": "turn_1:item:coding-tool:file.inspect:abc",
                "idempotency_key": "thread:thread_1:coding-tool:call_1",
                "source": "runtime_auto",
                "source_event_kind": "coding_tool.file.inspect",
                "event_kind": "tool.completed",
                "status": "completed",
                "actor": "runtime",
                "workspace_root": "/workspace/project",
                "workflow_graph_id": "graph_1",
                "workflow_node_id": "node_1",
                "component_kind": "coding_tool",
                "tool_call_id": "call_1",
                "artifact_refs": ["artifact_1"],
                "receipt_refs": ["receipt_1"],
                "rollback_refs": ["rollback_1"],
                "payload_schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
                "payload_summary": {
                    "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
                    "event_kind": "CodingToolResult",
                    "tool_name": "file.inspect",
                    "tool_call_id": "call_1",
                    "status": "completed",
                    "receipt_refs": ["receipt_payload"]
                }
            }),
        }
    }

    fn command_stream_request() -> CodingToolCommandStreamAdmissionRequest {
        CodingToolCommandStreamAdmissionRequest {
            schema_version: CODING_TOOL_COMMAND_STREAM_ADMISSION_REQUEST_SCHEMA_VERSION.to_string(),
            event_stream_id: "thread_1:events".to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: Some("turn_1".to_string()),
            tool_id: "test.run".to_string(),
            tool_call_id: "call_1".to_string(),
            workspace_root: Some("/workspace/project".to_string()),
            workflow_graph_id: Some("graph_1".to_string()),
            workflow_node_id: Some("node_1".to_string()),
            source: Some("runtime_auto".to_string()),
            status: Some("completed".to_string()),
            request: json!({
                "stream_output": true
            }),
            result: json!({
                "stdout": "ok",
                "stderr": "warn",
            }),
            receipt_refs: vec!["receipt_1".to_string()],
            artifact_refs: vec!["artifact_1".to_string()],
            latest_seq: Some(3),
            expected_head: Some("agentgres://runtime-events/thread_1_events/head/3".to_string()),
            state_root_before: Some("sha256:before-stream".to_string()),
        }
    }

    fn result_envelope_request(phase: &str) -> CodingToolResultEnvelopePlanRequest {
        CodingToolResultEnvelopePlanRequest {
            schema_version: CODING_TOOL_RESULT_ENVELOPE_PLAN_REQUEST_SCHEMA_VERSION.to_string(),
            phase: Some(phase.to_string()),
            event_stream_id: "thread_1:events".to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: Some("turn_1".to_string()),
            tool_id: "workspace.status".to_string(),
            tool_call_id: "call_1".to_string(),
            workspace_root: Some("/workspace/project".to_string()),
            workflow_graph_id: Some("graph_1".to_string()),
            workflow_node_id: "node_1".to_string(),
            idempotency_key: "thread:thread_1:coding-tool:call_1".to_string(),
            source: Some("runtime_auto".to_string()),
            status: Some("completed".to_string()),
            summary: Some("Workspace status inspected 0 changed file(s).".to_string()),
            input_summary: json!({ "include_ignored": false }),
            result_summary: json!({ "changed": 0, "git_available": true }),
            result: json!({
                "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
                "tool_name": "workspace.status",
                "status": "completed",
                "rust_workload": true,
                "git": { "available": true },
                "changed_files": [],
                "receipt_refs": ["receipt_step"]
            }),
            error: Value::Null,
            receipt_id: Some("receipt_call_1".to_string()),
            receipt_refs: vec!["receipt_call_1".to_string(), "receipt_step".to_string()],
            artifact_refs: vec![],
            rollback_refs: vec!["rollback_1".to_string()],
            diagnostics_repair_context: Value::Null,
            approval_required: Some(false),
            approval_satisfied: Some(false),
            approval_id: None,
            approval_manifest: Value::Null,
            approval_decision_event_id: None,
            approval_receipt_refs: vec![],
            approval_policy_decision_refs: vec![],
            step_module_backend: Some("rust_workload_live".to_string()),
            step_module: json!({
                "backend": "rust_workload_live",
                "invocation": {
                    "schema_version": "ioi.step_module_invocation.v1",
                    "invocation_id": "invocation://rust-live/workspace.status"
                },
                "result": {
                    "schema_version": "ioi.step_module_result.v1",
                    "status": "success",
                    "receipt_refs": ["receipt_step"],
                    "workflow_projection": { "status": "live" }
                }
            }),
            step_module_error: Value::Null,
        }
    }

    fn post_edit_diagnostics_request() -> PostEditDiagnosticsFeedbackPlanRequest {
        PostEditDiagnosticsFeedbackPlanRequest {
            schema_version: POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: Some("turn_1".to_string()),
            patch_tool_call_id: "patch_1".to_string(),
            workflow_graph_id: Some("graph_1".to_string()),
            request: json!({
                "workflow_node_id": "patch_node",
                "diagnostics_mode": "blocking",
                "diagnostic_command_id": "tsc",
                "diagnostic_timeout_ms": 1000,
                "restore_policy": "preview",
                "restore_conflict_policy": "approval",
                "diagnostics_repair_default": "restore_apply",
                "operator_override_requires_approval": false
            }),
            input: json!({
                "cwd": "/workspace/project",
                "diagnostic_max_output_bytes": 4096
            }),
            patch_result: json!({
                "changed_files": [
                    {
                        "path": "src/app.js",
                        "before_hash": "sha256:before",
                        "after_hash": "sha256:after"
                    },
                    {
                        "path": "README.md",
                        "diagnostics_recommended": false
                    }
                ],
                "workspace_snapshot_id": "snapshot_1",
                "workspace_snapshot": {
                    "snapshot_id": "snapshot_nested",
                    "restore": { "preview_supported": true }
                },
                "rollback_refs": ["rollback_1"]
            }),
        }
    }

    #[test]
    fn rust_admits_coding_tool_result_event_with_agentgres_refs() {
        let record = CodingToolResultEventAdmissionCore
            .admit(&admission_request())
            .expect("admitted event");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_RESULT_EVENT_ADMISSION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "admitted");
        assert_eq!(record.operation_kind, "runtime.coding_tool_result_event");
        assert_eq!(record.seq, 3);
        assert_eq!(record.latest_seq, 2);
        assert_eq!(record.event["seq"], 3);
        assert_eq!(record.event["event_kind"], "tool.completed");
        assert_eq!(
            record.event["agentgres_operation_ref"],
            record.operation_ref
        );
        assert_eq!(record.event["state_root_before"], "sha256:before");
        assert_eq!(record.event["state_root_after"], record.state_root_after);
        assert_eq!(record.event["resulting_head"], record.resulting_head);
        assert!(record.payload_refs.contains(&format!(
            "payload://runtime-events/{}/events/{}",
            "thread_1_events", record.event_id
        )));
        assert!(record.receipt_refs.contains(&"receipt_1".to_string()));
        assert!(record.receipt_refs.contains(&"receipt_payload".to_string()));
        assert_eq!(
            record.storage_admission.storage_backend_ref,
            "agentgres://runtime-events"
        );
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_rejects_coding_tool_result_event_without_receipts() {
        let mut request = admission_request();
        request.event["receipt_refs"] = Value::Array(vec![]);
        request.event["payload_summary"]["receipt_refs"] = Value::Array(vec![]);

        let error = CodingToolResultEventAdmissionCore
            .admit(&request)
            .expect_err("missing receipts");

        assert_eq!(
            error,
            CodingToolResultEventAdmissionError::MissingReceiptRefs
        );
    }

    #[test]
    fn rust_core_shapes_coding_tool_result_event_admission_protocol_response() {
        let response = admit_coding_tool_result_event_response(
            CodingToolResultEventAdmissionProtocolRequest {
                request: admission_request(),
            },
        )
        .expect("admission response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_result_event_admission_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["admitted"], true);
        assert_eq!(response["event"]["seq"], 3);
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_RESULT_EVENT_ADMISSION_RESULT_SCHEMA_VERSION
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn rust_plans_coding_tool_result_step_module_context() {
        let record = CodingToolResultEnvelopePlanCore
            .plan(&result_envelope_request("step_module_context"))
            .expect("result envelope context");

        assert_eq!(record.operation_kind, "runtime.coding_tool.result_envelope");
        assert_eq!(record.phase, "step_module_context");
        assert_eq!(record.step_module_context["run_id"], "run:thread_1");
        assert_eq!(record.step_module_context["task_id"], "task:turn_1");
        assert_eq!(record.step_module_context["workflow_node_id"], "node_1");
        assert_eq!(
            record.step_module_context["workflow_projection_status"],
            "live"
        );
        assert_eq!(
            record.step_module_context["receipt_refs"][0],
            "receipt_call_1"
        );
        assert!(record.event.is_null());
        assert!(record.payload_summary.is_null());
        assert!(record.envelope_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_plans_coding_tool_result_event_envelope() {
        let record = CodingToolResultEnvelopePlanCore
            .plan(&result_envelope_request("result_event"))
            .expect("result event envelope");

        assert_eq!(record.operation_kind, "runtime.coding_tool.result_envelope");
        assert_eq!(record.phase, "result_event");
        assert_eq!(record.event["event_stream_id"], "thread_1:events");
        assert_eq!(record.event["event_kind"], "tool.completed");
        assert_eq!(
            record.event["source_event_kind"],
            "CodingTool.WorkspaceStatus"
        );
        assert_eq!(
            record.event["payload_schema_version"],
            CODING_TOOL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            record.event["payload_summary"]["tool_name"],
            "workspace.status"
        );
        assert_eq!(
            record.event["payload_summary"]["step_module_backend"],
            "rust_workload_live"
        );
        assert_eq!(
            record.event["payload_summary"]["step_module_invocation"]["invocation_id"],
            "invocation://rust-live/workspace.status"
        );
        assert_eq!(record.event["receipt_refs"][0], "receipt_call_1");
        assert_eq!(record.event["rollback_refs"][0], "rollback_1");
        assert!(record.envelope_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_shapes_coding_tool_result_envelope_command_response() {
        let response =
            plan_coding_tool_result_envelope_response(CodingToolResultEnvelopePlanBridgeRequest {
                backend: Some("rust_runtime_coding_tool_event".to_string()),
                request: result_envelope_request("result_event"),
            })
            .expect("result envelope command response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_result_envelope_plan_command"
        );
        assert_eq!(
            response["operation_kind"],
            "runtime.coding_tool.result_envelope"
        );
        assert_eq!(response["planned"], true);
        assert_eq!(
            response["event"]["payload_summary"]["tool_name"],
            "workspace.status"
        );
        assert_eq!(
            response["step_module_context"]["workflow_projection_status"],
            "live"
        );
    }

    #[test]
    fn rust_admits_coding_tool_command_stream_events_with_agentgres_refs() {
        let record = CodingToolCommandStreamAdmissionCore
            .admit(&command_stream_request())
            .expect("admitted command stream");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_COMMAND_STREAM_ADMISSION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "admitted");
        assert_eq!(record.operation_kind, "runtime.coding_tool_command_stream");
        assert_eq!(record.latest_seq, 3);
        assert_eq!(record.event_count, 2);
        assert_eq!(record.events[0]["event_kind"], "artifact.command_stream");
        assert_eq!(
            record.events[0]["payload_schema_version"],
            CODING_TOOL_COMMAND_STREAM_PAYLOAD_SCHEMA_VERSION
        );
        assert_eq!(record.events[0]["payload_summary"]["channel"], "stdout");
        assert_eq!(record.events[1]["payload_summary"]["channel"], "stderr");
        assert_eq!(record.events[0]["seq"], 4);
        assert_eq!(record.events[1]["seq"], 5);
        assert_eq!(
            record.events[0]["state_root_before"],
            "sha256:before-stream"
        );
        assert_eq!(
            record.events[1]["state_root_after"],
            record.state_root_after
        );
        assert_eq!(record.storage_admissions.len(), 2);
        assert!(record.payload_refs.iter().all(|payload_ref| payload_ref
            .starts_with("payload://runtime-events/thread_1_events/command-stream/")));
        assert_eq!(record.receipt_refs, vec!["receipt_1".to_string()]);
        assert_eq!(record.artifact_refs, vec!["artifact_1".to_string()]);
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_skips_coding_tool_command_stream_when_not_requested() {
        let mut request = command_stream_request();
        request.request = json!({ "stream_output": false });

        let record = CodingToolCommandStreamAdmissionCore
            .admit(&request)
            .expect("skipped command stream");

        assert_eq!(record.status, "skipped");
        assert_eq!(record.event_count, 0);
        assert!(record.events.is_empty());
        assert_eq!(record.state_root_before, record.state_root_after);
    }

    #[test]
    fn rust_rejects_coding_tool_command_stream_without_receipts() {
        let mut request = command_stream_request();
        request.receipt_refs = vec![];

        let error = CodingToolCommandStreamAdmissionCore
            .admit(&request)
            .expect_err("missing receipts");

        assert_eq!(
            error,
            CodingToolCommandStreamAdmissionError::MissingReceiptRefs
        );
    }

    #[test]
    fn rust_core_shapes_coding_tool_command_stream_admission_protocol_response() {
        let response = admit_coding_tool_command_stream_events_response(
            CodingToolCommandStreamAdmissionProtocolRequest {
                request: command_stream_request(),
            },
        )
        .expect("command stream admission response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_command_stream_admission_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["admitted"], true);
        assert_eq!(response["event_count"], 2);
        assert_eq!(
            response["events"][0]["event_kind"],
            "artifact.command_stream"
        );
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_COMMAND_STREAM_ADMISSION_RESULT_SCHEMA_VERSION
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn rust_plans_post_edit_diagnostics_feedback_request() {
        let record = PostEditDiagnosticsFeedbackPlanCore
            .plan(&post_edit_diagnostics_request())
            .expect("planned diagnostics feedback");

        assert_eq!(
            record.schema_version,
            POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(
            record.operation_kind,
            "runtime.post_edit_diagnostics_feedback"
        );
        assert_eq!(record.tool_id, "lsp.diagnostics");
        assert_eq!(record.workflow_node_id, LSP_DIAGNOSTICS_AUTO_NODE_ID);
        assert_eq!(record.paths, vec!["src/app.js".to_string()]);
        assert_eq!(
            record.rollback_refs,
            vec!["snapshot_1".to_string(), "rollback_1".to_string()]
        );
        assert_eq!(
            record.request["workflow_node_id"],
            json!(LSP_DIAGNOSTICS_AUTO_NODE_ID)
        );
        assert_eq!(record.request["input"]["paths"], json!(["src/app.js"]));
        assert_eq!(record.request["input"]["commandId"], "tsc");
        assert_eq!(record.request["input"]["cwd"], "/workspace/project");
        assert_eq!(record.request["input"]["timeoutMs"], 1000);
        assert_eq!(record.request["input"]["maxOutputBytes"], 4096);
        assert_eq!(
            record.diagnostics_repair_context["schema_version"],
            DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION
        );
        assert_eq!(
            record.diagnostics_repair_context["source_tool_call_id"],
            "patch_1"
        );
        assert_eq!(
            record.diagnostics_repair_context["source_workflow_node_id"],
            "patch_node"
        );
        assert_eq!(
            record.diagnostics_repair_context["workspace_snapshot_id"],
            "snapshot_1"
        );
        assert_eq!(
            record.diagnostics_repair_context["restore_policy"],
            "preview_only"
        );
        assert_eq!(
            record.diagnostics_repair_context["restore_conflict_policy"],
            "require_approval"
        );
        assert_eq!(
            record.diagnostics_repair_context["diagnostics_repair_default"],
            "restore_apply"
        );
        assert_eq!(
            record.diagnostics_repair_context["operator_override_requires_approval"],
            false
        );
        assert_eq!(
            record.diagnostics_repair_context["changed_files"][0]["before_hash"],
            "sha256:before"
        );
        assert!(record
            .diagnostics_repair_context
            .get("sourceWorkflowNodeId")
            .is_none());
        assert!(record.plan_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_skips_post_edit_diagnostics_feedback_for_skip_or_pathless() {
        let mut skip_request = post_edit_diagnostics_request();
        skip_request.request["diagnostics_mode"] = json!("skip");
        let skipped = PostEditDiagnosticsFeedbackPlanCore
            .plan(&skip_request)
            .expect("skip planned");
        assert_eq!(skipped.status, "skipped");
        assert_eq!(
            skipped.skip_reason.as_deref(),
            Some("diagnostics_mode_skip")
        );
        assert!(skipped.request.is_null());

        let mut pathless_request = post_edit_diagnostics_request();
        pathless_request.patch_result = json!({
            "changed_files": [{ "diagnostics_recommended": true }]
        });
        let pathless = PostEditDiagnosticsFeedbackPlanCore
            .plan(&pathless_request)
            .expect("pathless skip planned");
        assert_eq!(pathless.status, "skipped");
        assert_eq!(pathless.skip_reason.as_deref(), Some("no_changed_files"));
    }

    #[test]
    fn rust_ignores_retired_post_edit_diagnostics_aliases() {
        let mut request = post_edit_diagnostics_request();
        request.request = json!({
            "workflowNodeId": "retired_patch_node",
            "diagnosticsMode": "skip",
            "restorePolicy": "disabled"
        });
        request.patch_result = json!({
            "changed_files": [{ "path": "src/app.js" }],
            "changedFiles": [{ "path": "src/retired.js" }],
            "workspace_snapshot_id": "snapshot_canonical",
            "workspaceSnapshotId": "snapshot_retired",
            "rollback_refs": ["rollback_canonical"],
            "rollbackRefs": ["rollback_retired"]
        });

        let record = PostEditDiagnosticsFeedbackPlanCore
            .plan(&request)
            .expect("canonical plan");

        assert_eq!(record.status, "planned");
        assert_eq!(record.paths, vec!["src/app.js".to_string()]);
        assert_eq!(
            record.workspace_snapshot_id.as_deref(),
            Some("snapshot_canonical")
        );
        assert_eq!(
            record.rollback_refs,
            vec![
                "snapshot_canonical".to_string(),
                "rollback_canonical".to_string()
            ]
        );
        assert!(record.diagnostics_repair_context["source_workflow_node_id"].is_null());
        assert_eq!(
            record.diagnostics_repair_context["restore_policy"],
            "apply_with_approval"
        );
    }

    #[test]
    fn rust_core_shapes_post_edit_diagnostics_feedback_plan_command_response() {
        let response = plan_post_edit_diagnostics_feedback_response(
            PostEditDiagnosticsFeedbackPlanBridgeRequest {
                backend: Some("rust_runtime_diagnostics_feedback".to_string()),
                request: post_edit_diagnostics_request(),
            },
        )
        .expect("plan response");

        assert_eq!(
            response["source"],
            "rust_post_edit_diagnostics_feedback_plan_command"
        );
        assert_eq!(response["backend"], "rust_runtime_diagnostics_feedback");
        assert_eq!(response["planned"], true);
        assert_eq!(response["tool_id"], "lsp.diagnostics");
        assert_eq!(
            response["request"]["workflow_node_id"],
            LSP_DIAGNOSTICS_AUTO_NODE_ID
        );
        assert_eq!(
            response["record"]["schema_version"],
            POST_EDIT_DIAGNOSTICS_FEEDBACK_PLAN_RESULT_SCHEMA_VERSION
        );
        assert!(response["plan_hash"]
            .as_str()
            .expect("plan hash")
            .starts_with("sha256:"));
    }
}
