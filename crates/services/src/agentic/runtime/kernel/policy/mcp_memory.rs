use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{
    MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION, MCP_LIVE_RESULT_REPLAY_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION,
    MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION, MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION,
    MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_TOOL_FETCH_PROJECTION_RESULT_SCHEMA_VERSION,
    MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
    MCP_TOOL_SEARCH_PROJECTION_RESULT_SCHEMA_VERSION,
    MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
    MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
    MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
    MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION,
    THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum McpControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    AgentCandidateTransportRetired,
    StateDirRequired,
    AgentReplayRequired(String),
    StateDirReadFailed(String),
    StateDirRecordInvalid(String),
    WalletAuthorityRequired(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpLiveResultReplayError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    StateDirRequired,
    StateDirReadFailed(String),
    StateDirRecordInvalid(String),
    ResultReplayRequired(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationInputError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    AgentCandidateTransportRetired,
    StateDirRequired,
    AgentReplayRequired(String),
    StateDirReadFailed(String),
    StateDirRecordInvalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogSummaryProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpToolProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    CatalogProjectionFailed(String),
    CatalogSummaryProjectionFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadMemoryAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    #[serde(default)]
    pub request: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpLiveResultReplayRequest {
    pub schema_version: String,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub result_id: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub control_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpLiveResultReplayRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub result_count: usize,
    pub results: Vec<Value>,
    pub result_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_result: Option<Value>,
    pub replay_hash: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRequest {
    pub schema_version: String,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub ok: bool,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRequest {
    pub schema_version: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub workspace_root: Option<String>,
    pub server_count: usize,
    pub servers: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub enabled_tools: Vec<Value>,
    #[serde(default)]
    pub routes: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_server_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_tool_count: Option<usize>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub issue_count: usize,
    pub warning_count: usize,
    pub record_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub disabled: bool,
    pub injection_enabled: bool,
    pub read_only: bool,
    pub write_requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_blocked_reason: Option<String>,
    pub record_count: usize,
    pub scope_count: usize,
    pub memory_key_count: usize,
    pub scopes: Vec<String>,
    pub memory_keys: Vec<String>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_tool_count: usize,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub enabled_tools: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub server: Value,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub live_mode: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub preview_limit: Option<usize>,
    #[serde(default)]
    pub deferred: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolSearchProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub exact: Option<bool>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub preview_limit: Option<usize>,
    #[serde(default)]
    pub live_discovery: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolSearchProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub query: String,
    pub q: String,
    pub exact: bool,
    pub live_discovery: bool,
    pub rust_mcp_live_discovery_deferred: bool,
    pub server_count: usize,
    pub tool_count: usize,
    pub returned_count: usize,
    pub limit: usize,
    pub deferred: bool,
    pub tools: Vec<Value>,
    pub catalog_summaries: Vec<Value>,
    pub failures: Vec<Value>,
    pub routes: Value,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolFetchProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub preview_limit: Option<usize>,
    #[serde(default)]
    pub live_discovery: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolFetchProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<Value>,
    pub tools: Vec<Value>,
    pub returned_count: usize,
    pub search_projection: Value,
    pub catalog_summaries: Vec<Value>,
    pub routes: Value,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_id: Option<String>,
    pub server_label: Option<String>,
    pub transport: Option<String>,
    pub execution_mode: Option<String>,
    pub catalog_hash: String,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub namespace_count: usize,
    pub namespaces: Vec<String>,
    pub preview_limit: usize,
    pub preview_tool_names: Vec<String>,
    pub deferred: bool,
    pub full_catalog_included: bool,
    pub error_code: Option<String>,
    pub search_route: String,
    pub fetch_route: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpMemoryCommandError {
    code: &'static str,
    message: String,
}

impl McpMemoryCommandError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    fn from_debug<E: std::fmt::Debug>(code: &'static str, error: E) -> Self {
        Self {
            code,
            message: format!("{error:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct MemoryManagerStatusProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerStatusProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct MemoryManagerValidationProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: MemoryManagerValidationProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadMemoryAgentStateUpdateRequest,
}

pub fn plan_memory_manager_status_projection_response(
    request: MemoryManagerStatusProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = MemoryManagerStatusProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("memory_manager_status_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_memory_manager_status_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "status": record.status.clone(),
        "disabled": record.disabled,
        "injection_enabled": record.injection_enabled,
        "read_only": record.read_only,
        "write_requires_approval": record.write_requires_approval,
        "write_blocked_reason": record.write_blocked_reason.clone(),
        "record_count": record.record_count,
        "scope_count": record.scope_count,
        "memory_key_count": record.memory_key_count,
        "scopes": record.scopes.clone(),
        "memory_keys": record.memory_keys.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
        "validation": record.validation.clone(),
        "routes": record.routes.clone(),
        "evidence_refs": record.evidence_refs.clone(),
    }))
}

pub fn plan_memory_manager_validation_projection_response(
    request: MemoryManagerValidationProjectionBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = MemoryManagerValidationProjectionCore
        .project(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("memory_manager_validation_projection_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_memory_manager_validation_projection_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "schema_version": record.schema_version.clone(),
        "object": record.object.clone(),
        "ok": record.ok,
        "status": record.status.clone(),
        "issue_count": record.issue_count,
        "warning_count": record.warning_count,
        "record_count": record.record_count,
        "issues": record.issues.clone(),
        "warnings": record.warnings.clone(),
        "policy": record.policy.clone(),
        "paths": record.paths.clone(),
        "filters": record.filters.clone(),
        "records": record.records.clone(),
    }))
}

pub fn plan_thread_memory_agent_state_update_response(
    request: ThreadMemoryAgentStateUpdateBridgeRequest,
) -> Result<Value, McpMemoryCommandError> {
    let record = ThreadMemoryAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            McpMemoryCommandError::from_debug("thread_memory_agent_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_thread_memory_agent_state_update_command",
        "backend": mcp_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

fn mcp_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
}

#[derive(Debug, Default, Clone)]
pub struct McpLiveResultReplayCore;

impl McpLiveResultReplayCore {
    pub fn project(
        &self,
        request: &McpLiveResultReplayRequest,
    ) -> Result<McpLiveResultReplayRecord, McpLiveResultReplayError> {
        request.validate()?;
        let state_dir = optional_trimmed(request.state_dir.as_deref())
            .ok_or(McpLiveResultReplayError::StateDirRequired)?;
        let results_dir = PathBuf::from(state_dir).join("mcp-live-results");
        let mut results = Vec::new();

        if results_dir.exists() {
            for entry in fs::read_dir(&results_dir).map_err(|error| {
                McpLiveResultReplayError::StateDirReadFailed(format!(
                    "could not inspect Agentgres MCP live-results directory: {error}"
                ))
            })? {
                let entry = entry.map_err(|error| {
                    McpLiveResultReplayError::StateDirReadFailed(format!(
                        "could not inspect Agentgres MCP live-result entry: {error}"
                    ))
                })?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let result = read_mcp_live_result_record(&path)?;
                if mcp_live_result_matches_request(&result, request) {
                    results.push(result);
                }
            }
        }

        results.sort_by(|left, right| {
            mcp_live_result_sort_key(left).cmp(&mcp_live_result_sort_key(right))
        });
        let result_ids = results
            .iter()
            .filter_map(|result| optional_json_string(result, "id"))
            .collect::<Vec<_>>();
        if results.is_empty() {
            return Err(McpLiveResultReplayError::ResultReplayRequired(
                request
                    .result_id
                    .clone()
                    .unwrap_or_else(|| "latest".to_string()),
            ));
        }
        let latest_result = results.last().cloned();
        let replay_hash = mcp_live_result_replay_hash(&results);

        Ok(McpLiveResultReplayRecord {
            schema_version: MCP_LIVE_RESULT_REPLAY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_live_result_replay".to_string(),
            status: "projected".to_string(),
            result_count: results.len(),
            results,
            result_ids,
            latest_result,
            replay_hash,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpControlAgentStateUpdateCore;

impl McpControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &McpControlAgentStateUpdateRequest,
    ) -> Result<McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str()))
            .ok_or(McpControlAgentStateUpdateError::MissingField("thread_id"))?;
        let mut agent = mcp_control_agent_from_state_dir(
            request.state_dir.as_deref(),
            thread_id.as_str(),
            request.agent_id.as_deref(),
        )?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(McpControlAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            McpControlAgentStateUpdateError::MissingField("control_kind"),
        )?;
        let agent_state_root_before = mcp_control_agent_state_root(&Value::Object(agent.clone()));
        let registry =
            mcp_control_registry_update(&agent, control_kind.as_str(), &request.request)?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        agent.insert("mcpRegistry".to_string(), registry.registry.clone());
        let tool_id = optional_json_string(&request.request, "tool_id");
        let tool_name = optional_json_string(&request.request, "tool_name");
        let live_transport = optional_json_string(&request.request, "live_transport");
        let execution_mode = optional_json_string(&request.request, "execution_mode");
        let timeout_ms = request.request.get("timeout_ms").and_then(Value::as_u64);
        let transport_admission_required =
            matches!(control_kind.as_str(), "mcp_invoke" | "mcp_live_discovery");
        let authority = if transport_admission_required {
            Some(mcp_control_external_exit_authority(
                control_kind.as_str(),
                &request.request,
                registry.server_id.as_deref(),
                tool_id.as_deref().or(tool_name.as_deref()),
            )?)
        } else {
            None
        };
        let authority_grant_refs = authority
            .as_ref()
            .map(|authority| authority.authority_grant_refs.clone())
            .unwrap_or_default();
        let authority_receipt_refs = authority
            .as_ref()
            .map(|authority| authority.authority_receipt_refs.clone())
            .unwrap_or_default();
        let authority_hash = authority
            .as_ref()
            .map(|authority| authority.authority_hash.clone());
        let custody_ref = authority
            .as_ref()
            .map(|authority| authority.custody_ref.clone());
        let containment_ref = authority
            .as_ref()
            .map(|authority| authority.containment_ref.clone());
        let mut evidence_refs = vec![
            "runtime_mcp_control_rust_owned".to_string(),
            "runtime_mcp_control_js_facade_retired".to_string(),
            "agentgres_runtime_agent_state_truth_required".to_string(),
        ];
        if transport_admission_required {
            evidence_refs.push("wallet_network_mcp_external_exit_authority_required".to_string());
            evidence_refs.push("ctee_mcp_external_exit_custody_required".to_string());
            evidence_refs.push("mcp_transport_containment_required".to_string());
            evidence_refs.push("runtime_mcp_live_exit_rust_receipt".to_string());
            evidence_refs.push("agentgres_runtime_mcp_live_receipt_truth_required".to_string());
            evidence_refs.push("runtime_mcp_live_result_rust_projection".to_string());
            evidence_refs.push("agentgres_runtime_mcp_live_result_truth_required".to_string());
            evidence_refs.push("receipt_state_root_binding_required".to_string());
        }
        let live_receipt_id = if transport_admission_required {
            Some(mcp_control_live_exit_receipt_id(
                &agent_id,
                control_kind.as_str(),
                &request.event_id,
            ))
        } else {
            None
        };
        if let Some(receipt_id) = live_receipt_id.as_deref() {
            mcp_control_push_agent_receipt_ref(&mut agent, receipt_id);
        }
        let live_result_id = if transport_admission_required {
            Some(mcp_control_live_exit_result_id(
                &agent_id,
                control_kind.as_str(),
                &request.event_id,
            ))
        } else {
            None
        };
        if let Some(result_id) = live_result_id.as_deref() {
            mcp_control_push_agent_result_ref(&mut agent, result_id);
        }
        let agent_state_root_after = mcp_control_agent_state_root(&Value::Object(agent.clone()));
        let live_agentgres_operation_ref = if transport_admission_required {
            Some(mcp_control_live_exit_agentgres_operation_ref(
                &agent_id,
                control_kind.as_str(),
                &request.event_id,
            ))
        } else {
            None
        };
        let live_resulting_head = if transport_admission_required {
            Some(mcp_control_live_exit_resulting_head(
                &agent_id,
                &agent_state_root_after,
            ))
        } else {
            None
        };
        let receipt = if transport_admission_required {
            Some(mcp_control_live_exit_receipt(
                live_receipt_id.as_deref().unwrap_or_default(),
                &request.created_at,
                control_kind.as_str(),
                &request.event_id,
                &request.thread_id,
                &agent_id,
                registry.server_id.as_deref(),
                tool_id.as_deref().or(tool_name.as_deref()),
                live_transport.as_deref(),
                execution_mode.as_deref(),
                timeout_ms,
                authority_hash.as_deref(),
                &authority_grant_refs,
                &authority_receipt_refs,
                custody_ref.as_deref(),
                containment_ref.as_deref(),
                &agent_state_root_before,
                &agent_state_root_after,
                live_agentgres_operation_ref.as_deref().unwrap_or_default(),
                live_resulting_head.as_deref().unwrap_or_default(),
            ))
        } else {
            None
        };
        let result = if transport_admission_required {
            Some(mcp_control_live_exit_result(
                live_result_id.as_deref().unwrap_or_default(),
                live_receipt_id.as_deref().unwrap_or_default(),
                &request.created_at,
                control_kind.as_str(),
                &request.event_id,
                &request.thread_id,
                &agent_id,
                registry.server_id.as_deref(),
                tool_id.as_deref().or(tool_name.as_deref()),
                live_transport.as_deref(),
                execution_mode.as_deref(),
                timeout_ms,
                &agent_state_root_before,
                &agent_state_root_after,
                live_agentgres_operation_ref.as_deref().unwrap_or_default(),
                live_resulting_head.as_deref().unwrap_or_default(),
            ))
        } else {
            None
        };
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
            "server_id": registry.server_id,
            "tool_id": tool_id,
            "tool_name": tool_name,
            "live_transport": live_transport,
            "execution_mode": execution_mode,
            "timeout_ms": timeout_ms,
            "transport_admission_required": transport_admission_required,
            "wallet_authority_required": transport_admission_required,
            "wallet_authority_boundary": if transport_admission_required { Some("wallet.network.mcp_external_exit") } else { None },
            "ctee_custody_required": transport_admission_required,
            "transport_containment_required": transport_admission_required,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
            "authority_hash": authority_hash,
            "custody_ref": custody_ref,
            "containment_ref": containment_ref,
            "content_receipt_id": live_receipt_id,
            "result_receipt_id": live_receipt_id,
            "result_record_id": live_result_id,
            "runtime_mcp_live_receipt_required": transport_admission_required,
            "runtime_mcp_live_result_required": transport_admission_required,
            "runtime_mcp_live_result_status": if transport_admission_required { Some("admitted_pending_rust_transport") } else { None },
            "runtime_mcp_agentgres_operation_ref": live_agentgres_operation_ref,
            "runtime_mcp_agent_state_root_before": if transport_admission_required { Some(agent_state_root_before.as_str()) } else { None },
            "runtime_mcp_agent_state_root_after": if transport_admission_required { Some(agent_state_root_after.as_str()) } else { None },
            "runtime_mcp_resulting_head": live_resulting_head,
            "server_count": registry.server_count,
            "enabled_server_count": registry.enabled_server_count,
            "registry_hash": registry.registry_hash,
            "mutation_applied": registry.mutation_applied,
            "evidence_refs": evidence_refs,
        });

        Ok(McpControlAgentStateUpdateRecord {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id,
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            receipt,
            result,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

struct McpControlExternalExitAuthority {
    authority_grant_refs: Vec<String>,
    authority_receipt_refs: Vec<String>,
    authority_hash: String,
    custody_ref: String,
    containment_ref: String,
}

fn mcp_control_external_exit_authority(
    control_kind: &str,
    request: &Value,
    server_id: Option<&str>,
    tool_ref: Option<&str>,
) -> Result<McpControlExternalExitAuthority, McpControlAgentStateUpdateError> {
    let server_id = optional_trimmed(server_id).ok_or(
        McpControlAgentStateUpdateError::MissingField("request.server_id"),
    )?;
    if control_kind == "mcp_invoke" && optional_trimmed(tool_ref).is_none() {
        return Err(McpControlAgentStateUpdateError::MissingField(
            "request.tool_id_or_tool_name",
        ));
    }
    let authority_grant_refs = mcp_control_string_array(request, "authority_grant_refs");
    if authority_grant_refs.is_empty() {
        return Err(McpControlAgentStateUpdateError::WalletAuthorityRequired(
            "request.authority_grant_refs",
        ));
    }
    let authority_receipt_refs = mcp_control_string_array(request, "authority_receipt_refs");
    if authority_receipt_refs.is_empty() {
        return Err(McpControlAgentStateUpdateError::WalletAuthorityRequired(
            "request.authority_receipt_refs",
        ));
    }
    let custody_ref = json_string_value(request, "custody_ref").ok_or(
        McpControlAgentStateUpdateError::MissingField("request.custody_ref"),
    )?;
    let containment_ref = json_string_value(request, "containment_ref").ok_or(
        McpControlAgentStateUpdateError::MissingField("request.containment_ref"),
    )?;
    let authority_hash = mcp_control_authority_hash(
        control_kind,
        &server_id,
        tool_ref,
        &authority_grant_refs,
        &authority_receipt_refs,
        Some(custody_ref.as_str()),
        Some(containment_ref.as_str()),
    );
    Ok(McpControlExternalExitAuthority {
        authority_grant_refs,
        authority_receipt_refs,
        authority_hash,
        custody_ref,
        containment_ref,
    })
}

fn mcp_control_string_array(request: &Value, key: &str) -> Vec<String> {
    let mut values = request
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| optional_trimmed(Some(value)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    values.sort();
    values.dedup();
    values
}

fn mcp_control_authority_hash(
    control_kind: &str,
    server_id: &str,
    tool_ref: Option<&str>,
    authority_grant_refs: &[String],
    authority_receipt_refs: &[String],
    custody_ref: Option<&str>,
    containment_ref: Option<&str>,
) -> String {
    let material = json!({
        "control_kind": control_kind,
        "server_id": server_id,
        "tool_ref": tool_ref,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": custody_ref,
        "containment_ref": containment_ref,
    });
    let bytes = serde_json::to_vec(&material).unwrap_or_else(|_| material.to_string().into_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn mcp_control_live_exit_receipt_id(agent_id: &str, control_kind: &str, event_id: &str) -> String {
    format!(
        "receipt_runtime_mcp_live_exit_{}_{}_{}",
        safe_mcp_control_ref(agent_id),
        safe_mcp_control_ref(control_kind),
        safe_mcp_control_ref(event_id)
    )
}

fn mcp_control_live_exit_result_id(agent_id: &str, control_kind: &str, event_id: &str) -> String {
    format!(
        "result_runtime_mcp_live_exit_{}_{}_{}",
        safe_mcp_control_ref(agent_id),
        safe_mcp_control_ref(control_kind),
        safe_mcp_control_ref(event_id)
    )
}

fn mcp_control_live_exit_agentgres_operation_ref(
    agent_id: &str,
    control_kind: &str,
    event_id: &str,
) -> String {
    format!(
        "agentgres://runtime-state/agents/{}/operations/{}/{}",
        safe_mcp_control_ref(agent_id),
        safe_mcp_control_ref(control_kind),
        safe_mcp_control_ref(event_id)
    )
}

fn mcp_control_live_exit_resulting_head(agent_id: &str, state_root_after: &str) -> String {
    format!(
        "agentgres://runtime-state/agents/{}/head/{}",
        safe_mcp_control_ref(agent_id),
        safe_mcp_control_ref(state_root_after)
    )
}

fn mcp_control_agent_state_root(agent: &Value) -> String {
    let bytes = serde_json::to_vec(agent).unwrap_or_else(|_| agent.to_string().into_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn mcp_control_push_agent_receipt_ref(
    agent: &mut serde_json::Map<String, Value>,
    receipt_id: &str,
) {
    mcp_control_push_agent_array_ref(agent, "receipt_refs", receipt_id);
}

fn mcp_control_push_agent_result_ref(agent: &mut serde_json::Map<String, Value>, result_id: &str) {
    mcp_control_push_agent_array_ref(agent, "result_refs", result_id);
}

fn mcp_control_push_agent_array_ref(
    agent: &mut serde_json::Map<String, Value>,
    key: &str,
    entry: &str,
) {
    let mut refs = agent
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|entry| optional_trimmed(Some(entry)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    refs.push(entry.to_string());
    refs.sort();
    refs.dedup();
    agent.insert(
        key.to_string(),
        Value::Array(refs.into_iter().map(Value::String).collect()),
    );
}

fn mcp_control_live_exit_receipt(
    receipt_id: &str,
    created_at: &str,
    control_kind: &str,
    event_id: &str,
    thread_id: &str,
    agent_id: &str,
    server_id: Option<&str>,
    tool_ref: Option<&str>,
    live_transport: Option<&str>,
    execution_mode: Option<&str>,
    timeout_ms: Option<u64>,
    authority_hash: Option<&str>,
    authority_grant_refs: &[String],
    authority_receipt_refs: &[String],
    custody_ref: Option<&str>,
    containment_ref: Option<&str>,
    agent_state_root_before: &str,
    agent_state_root_after: &str,
    agentgres_operation_ref: &str,
    resulting_head: &str,
) -> Value {
    json!({
        "schema_version": "ioi.runtime.mcp-live-exit-receipt.v1",
        "object": "ioi.runtime_mcp_live_exit_receipt",
        "id": receipt_id,
        "kind": "runtime_mcp_live_exit",
        "redaction": "redacted",
        "created_at": created_at,
        "receipt_refs": [receipt_id],
        "evidence_refs": [
            "runtime_mcp_control_rust_owned",
            "runtime_mcp_live_exit_rust_receipt",
            "agentgres_runtime_mcp_live_receipt_truth_required",
            "wallet_network_mcp_external_exit_authority_required",
            "ctee_mcp_external_exit_custody_required",
            "mcp_transport_containment_required",
            "receipt_state_root_binding_required"
        ],
        "details": {
            "rust_daemon_core_receipt_author": "runtime.mcp_control",
            "control_kind": control_kind,
            "event_id": event_id,
            "thread_id": thread_id,
            "agent_id": agent_id,
            "server_id": server_id,
            "tool_ref": tool_ref,
            "live_transport": live_transport,
            "execution_mode": execution_mode,
            "timeout_ms": timeout_ms,
            "wallet_authority_boundary": "wallet.network.mcp_external_exit",
            "authority_hash": authority_hash,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
            "custody_ref": custody_ref,
            "containment_ref": containment_ref,
            "runtime_mcp_agentgres_operation_ref": agentgres_operation_ref,
            "runtime_mcp_agent_state_root_before": agent_state_root_before,
            "runtime_mcp_agent_state_root_after": agent_state_root_after,
            "runtime_mcp_resulting_head": resulting_head,
            "result_materialized": false,
            "js_transport_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false
        }
    })
}

fn mcp_control_live_exit_result(
    result_id: &str,
    receipt_id: &str,
    created_at: &str,
    control_kind: &str,
    event_id: &str,
    thread_id: &str,
    agent_id: &str,
    server_id: Option<&str>,
    tool_ref: Option<&str>,
    live_transport: Option<&str>,
    execution_mode: Option<&str>,
    timeout_ms: Option<u64>,
    agent_state_root_before: &str,
    agent_state_root_after: &str,
    agentgres_operation_ref: &str,
    resulting_head: &str,
) -> Value {
    json!({
        "schema_version": "ioi.runtime.mcp-live-result.v1",
        "object": "ioi.runtime_mcp_live_result",
        "id": result_id,
        "kind": "runtime_mcp_live_result",
        "status": "admitted_pending_rust_transport",
        "redaction": "redacted",
        "created_at": created_at,
        "receipt_id": receipt_id,
        "receipt_refs": [receipt_id],
        "evidence_refs": [
            "runtime_mcp_control_rust_owned",
            "runtime_mcp_live_result_rust_projection",
            "agentgres_runtime_mcp_live_result_truth_required",
            "runtime_mcp_transport_backend_pending",
            "runtime_mcp_no_js_transport_result",
            "receipt_state_root_binding_required"
        ],
        "details": {
            "rust_daemon_core_result_author": "runtime.mcp_control",
            "control_kind": control_kind,
            "event_id": event_id,
            "thread_id": thread_id,
            "agent_id": agent_id,
            "server_id": server_id,
            "tool_ref": tool_ref,
            "live_transport": live_transport,
            "execution_mode": execution_mode,
            "timeout_ms": timeout_ms,
            "runtime_mcp_agentgres_operation_ref": agentgres_operation_ref,
            "runtime_mcp_agent_state_root_before": agent_state_root_before,
            "runtime_mcp_agent_state_root_after": agent_state_root_after,
            "runtime_mcp_resulting_head": resulting_head,
            "receipt_id": receipt_id,
            "result_materialized": false,
            "backend_materialization_status": "pending_rust_transport_backend",
            "payload_ref": null,
            "payload_hash": null,
            "js_transport_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false
        }
    })
}

fn read_mcp_live_result_record(path: &Path) -> Result<Value, McpLiveResultReplayError> {
    let body = fs::read_to_string(path).map_err(|error| {
        McpLiveResultReplayError::StateDirReadFailed(format!(
            "could not read Agentgres MCP live-result record {}: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&body).map_err(|error| {
        McpLiveResultReplayError::StateDirRecordInvalid(format!(
            "invalid Agentgres MCP live-result record {}: {error}",
            path.display()
        ))
    })?;
    if !value.is_object() {
        return Err(McpLiveResultReplayError::StateDirRecordInvalid(format!(
            "Agentgres MCP live-result record {} is not an object",
            path.display()
        )));
    }
    Ok(value)
}

fn mcp_live_result_matches_request(result: &Value, request: &McpLiveResultReplayRequest) -> bool {
    if !mcp_live_result_is_rust_owned(result) {
        return false;
    }
    if !mcp_live_result_field_matches(result, "id", request.result_id.as_deref()) {
        return false;
    }
    if !mcp_live_result_field_matches(result, "receipt_id", request.receipt_id.as_deref()) {
        return false;
    }
    let details = result.get("details").unwrap_or(&Value::Null);
    for (key, expected) in [
        ("thread_id", request.thread_id.as_deref()),
        ("agent_id", request.agent_id.as_deref()),
        ("control_kind", request.control_kind.as_deref()),
    ] {
        if !mcp_live_result_field_matches(details, key, expected) {
            return false;
        }
    }
    true
}

fn mcp_live_result_is_rust_owned(result: &Value) -> bool {
    if optional_json_string(result, "schema_version").as_deref()
        != Some("ioi.runtime.mcp-live-result.v1")
    {
        return false;
    }
    if optional_json_string(result, "kind").as_deref() != Some("runtime_mcp_live_result") {
        return false;
    }
    let details = result.get("details").unwrap_or(&Value::Null);
    if optional_json_string(details, "rust_daemon_core_result_author").as_deref()
        != Some("runtime.mcp_control")
    {
        return false;
    }
    if result
        .get("details")
        .and_then(|details| details.get("js_transport_invocation"))
        .and_then(Value::as_bool)
        != Some(false)
    {
        return false;
    }
    if result
        .get("details")
        .and_then(|details| details.get("command_transport_fallback"))
        .and_then(Value::as_bool)
        != Some(false)
    {
        return false;
    }
    for required_ref in [
        "runtime_mcp_live_result_rust_projection",
        "agentgres_runtime_mcp_live_result_truth_required",
    ] {
        if !json_string_array_contains(result.get("evidence_refs"), required_ref) {
            return false;
        }
    }
    true
}

fn mcp_live_result_field_matches(result: &Value, key: &str, expected: Option<&str>) -> bool {
    match optional_trimmed(expected) {
        Some(expected) => optional_json_string(result, key).as_deref() == Some(expected.as_str()),
        None => true,
    }
}

fn mcp_live_result_sort_key(result: &Value) -> (String, String) {
    (
        optional_json_string(result, "created_at").unwrap_or_default(),
        optional_json_string(result, "id").unwrap_or_default(),
    )
}

fn mcp_live_result_replay_hash(results: &[Value]) -> String {
    let material = json!({ "results": results });
    let bytes = serde_json::to_vec(&material).unwrap_or_else(|_| material.to_string().into_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn json_string_array_contains(value: Option<&Value>, expected: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
}

fn safe_mcp_control_ref(input: &str) -> String {
    let safe = input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let safe = safe.trim_matches('_');
    if safe.is_empty() {
        "unknown".to_string()
    } else {
        safe.to_string()
    }
}

fn mcp_control_agent_from_state_dir(
    state_dir: Option<&str>,
    thread_id: &str,
    agent_id: Option<&str>,
) -> Result<serde_json::Map<String, Value>, McpControlAgentStateUpdateError> {
    let state_root =
        optional_trimmed(state_dir).ok_or(McpControlAgentStateUpdateError::StateDirRequired)?;
    let agents_dir = PathBuf::from(state_root).join("agents");
    let mut candidate_ids = Vec::new();
    if let Some(id) = optional_trimmed(agent_id) {
        candidate_ids.push(id);
    }
    if let Some(derived) = mcp_control_agent_id_for_thread(thread_id) {
        candidate_ids.push(derived);
    }
    candidate_ids.push(thread_id.to_string());
    candidate_ids.dedup();

    for candidate_id in &candidate_ids {
        let path = agents_dir.join(format!("{}.json", mcp_control_safe_component(candidate_id)));
        if path.exists() {
            let record = read_mcp_control_agent_record(&path)?;
            if mcp_control_agent_matches_thread(&record, thread_id, Some(candidate_id.as_str())) {
                return Ok(record);
            }
        }
    }

    if agents_dir.exists() {
        for entry in fs::read_dir(&agents_dir).map_err(|error| {
            McpControlAgentStateUpdateError::StateDirReadFailed(format!(
                "could not inspect Agentgres agents directory: {error}"
            ))
        })? {
            let entry = entry.map_err(|error| {
                McpControlAgentStateUpdateError::StateDirReadFailed(format!(
                    "could not inspect Agentgres agent entry: {error}"
                ))
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record = read_mcp_control_agent_record(&path)?;
            if mcp_control_agent_matches_thread(&record, thread_id, agent_id) {
                return Ok(record);
            }
        }
    }

    Err(McpControlAgentStateUpdateError::AgentReplayRequired(
        thread_id.to_string(),
    ))
}

fn read_mcp_control_agent_record(
    path: &Path,
) -> Result<serde_json::Map<String, Value>, McpControlAgentStateUpdateError> {
    let body = fs::read_to_string(path).map_err(|error| {
        McpControlAgentStateUpdateError::StateDirReadFailed(format!(
            "could not read Agentgres agent record {}: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&body).map_err(|error| {
        McpControlAgentStateUpdateError::StateDirRecordInvalid(format!(
            "invalid Agentgres agent record {}: {error}",
            path.display()
        ))
    })?;
    object_value(&value).ok_or_else(|| {
        McpControlAgentStateUpdateError::StateDirRecordInvalid(format!(
            "Agentgres agent record {} is not an object",
            path.display()
        ))
    })
}

fn mcp_control_agent_matches_thread(
    agent: &serde_json::Map<String, Value>,
    thread_id: &str,
    agent_id: Option<&str>,
) -> bool {
    let value = Value::Object(agent.clone());
    let record_agent_id = optional_json_string(&value, "id");
    if let Some(expected_agent_id) = optional_trimmed(agent_id) {
        if record_agent_id.as_deref() == Some(expected_agent_id.as_str()) {
            return true;
        }
    }
    if let Some(derived_agent_id) = mcp_control_agent_id_for_thread(thread_id) {
        if record_agent_id.as_deref() == Some(derived_agent_id.as_str()) {
            return true;
        }
    }
    [
        optional_json_string(&value, "thread_id"),
        json_path_string(&value, &["thread", "thread_id"]),
    ]
    .into_iter()
    .flatten()
    .any(|candidate| candidate == thread_id)
}

fn mcp_control_agent_id_for_thread(thread_id: &str) -> Option<String> {
    optional_trimmed(Some(thread_id)).map(|id| {
        id.strip_prefix("thread_")
            .map(|suffix| format!("agent_{suffix}"))
            .unwrap_or(id)
    })
}

fn mcp_control_safe_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
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

struct McpControlRegistryUpdate {
    registry: Value,
    server_id: Option<String>,
    server_count: usize,
    enabled_server_count: usize,
    registry_hash: String,
    mutation_applied: bool,
}

fn mcp_control_registry_update(
    agent: &serde_json::Map<String, Value>,
    control_kind: &str,
    request: &Value,
) -> Result<McpControlRegistryUpdate, McpControlAgentStateUpdateError> {
    let mut servers = mcp_control_agent_servers(agent);
    let mut server_id = mcp_control_request_server_id(request);
    let mut mutation_applied = false;

    match control_kind {
        "mcp_import" => {
            servers = mcp_control_request_servers(request)?;
            server_id = match servers.as_slice() {
                [server] => json_string_value(server, "id"),
                _ => server_id,
            };
            mutation_applied = true;
        }
        "mcp_add" => {
            let server = mcp_control_request_server_record(request)?;
            server_id = json_string_value(&server, "id");
            mcp_control_upsert_server(&mut servers, server);
            mutation_applied = true;
        }
        "mcp_remove" => {
            let requested =
                server_id
                    .clone()
                    .ok_or(McpControlAgentStateUpdateError::MissingField(
                        "request.server_id",
                    ))?;
            servers.retain(|server| {
                json_string_value(server, "id").as_deref() != Some(requested.as_str())
            });
            mutation_applied = true;
        }
        "mcp_enable" | "mcp_disable" => {
            let requested =
                server_id
                    .clone()
                    .ok_or(McpControlAgentStateUpdateError::MissingField(
                        "request.server_id",
                    ))?;
            let enabled = control_kind == "mcp_enable";
            let mut matched = false;
            for server in servers.iter_mut() {
                if json_string_value(server, "id").as_deref() == Some(requested.as_str()) {
                    let mut object = object_value(server).unwrap_or_default();
                    object.insert("enabled".to_string(), Value::Bool(enabled));
                    object.insert(
                        "status".to_string(),
                        Value::String(if enabled { "configured" } else { "disabled" }.to_string()),
                    );
                    *server = Value::Object(object);
                    matched = true;
                }
            }
            if !matched {
                return Err(McpControlAgentStateUpdateError::MissingField(
                    "request.server_id.matching_server",
                ));
            }
            mutation_applied = true;
        }
        _ => {}
    }

    let server_count = servers.len();
    let enabled_server_count = servers
        .iter()
        .filter(|server| server.get("enabled").and_then(Value::as_bool) != Some(false))
        .count();
    let registry = json!({ "servers": servers });
    let registry_hash = mcp_control_registry_hash(&registry);
    Ok(McpControlRegistryUpdate {
        registry,
        server_id,
        server_count,
        enabled_server_count,
        registry_hash,
        mutation_applied,
    })
}

fn mcp_control_agent_servers(agent: &serde_json::Map<String, Value>) -> Vec<Value> {
    agent
        .get("mcpRegistry")
        .and_then(|registry| registry.get("servers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(Value::is_object)
        .collect()
}

fn mcp_control_request_servers(
    request: &Value,
) -> Result<Vec<Value>, McpControlAgentStateUpdateError> {
    request
        .get("servers")
        .and_then(Value::as_array)
        .ok_or(McpControlAgentStateUpdateError::MissingField(
            "request.servers",
        ))?
        .iter()
        .map(mcp_control_canonical_server_record)
        .collect()
}

fn mcp_control_request_server_record(
    request: &Value,
) -> Result<Value, McpControlAgentStateUpdateError> {
    let server = request
        .get("server")
        .filter(|value| value.is_object())
        .unwrap_or(request);
    mcp_control_canonical_server_record(server)
}

fn mcp_control_request_server_id(request: &Value) -> Option<String> {
    json_string_value(request, "server_id")
        .or_else(|| json_string_value(request, "id"))
        .or_else(|| {
            request
                .get("server")
                .and_then(|server| json_string_value(server, "id"))
        })
}

fn mcp_control_upsert_server(servers: &mut Vec<Value>, server: Value) {
    let Some(server_id) = json_string_value(&server, "id") else {
        return;
    };
    if let Some(existing) = servers
        .iter_mut()
        .find(|candidate| json_string_value(candidate, "id").as_deref() == Some(server_id.as_str()))
    {
        *existing = server;
    } else {
        servers.push(server);
    }
}

fn mcp_control_canonical_server_record(
    server: &Value,
) -> Result<Value, McpControlAgentStateUpdateError> {
    let id = json_string_value(server, "id").ok_or(
        McpControlAgentStateUpdateError::MissingField("request.server.id"),
    )?;
    let label = json_string_value(server, "label")
        .or_else(|| json_string_value(server, "name"))
        .unwrap_or_else(|| id.clone());
    let server_url = json_string_value(server, "server_url")
        .or_else(|| json_string_value(server, "url"))
        .or_else(|| json_string_value(server, "endpoint"));
    let transport = normalize_mcp_transport(json_string_value(server, "transport").or_else(|| {
        server_url.as_ref().map(|url| {
            if url.contains("/sse") {
                "sse".to_string()
            } else {
                "http".to_string()
            }
        })
    }));
    let enabled = server.get("enabled").and_then(Value::as_bool) != Some(false);
    let tools = mcp_catalog_items(server.get("allowed_tools").or_else(|| server.get("tools")));
    let resources = mcp_catalog_items(
        server
            .get("resources")
            .or_else(|| server.get("allowed_resources")),
    );
    let prompts = mcp_catalog_items(
        server
            .get("prompts")
            .or_else(|| server.get("allowed_prompts")),
    );

    let mut record = serde_json::Map::new();
    record.insert("id".to_string(), Value::String(id));
    record.insert("label".to_string(), Value::String(label.clone()));
    record.insert("name".to_string(), Value::String(label));
    record.insert("enabled".to_string(), Value::Bool(enabled));
    record.insert(
        "status".to_string(),
        Value::String(json_string_value(server, "status").unwrap_or_else(|| {
            if enabled {
                "configured".to_string()
            } else {
                "disabled".to_string()
            }
        })),
    );
    record.insert("transport".to_string(), Value::String(transport));
    record.insert("allowed_tools".to_string(), Value::Array(tools.clone()));
    record.insert("tools".to_string(), Value::Array(tools));
    record.insert("resources".to_string(), Value::Array(resources));
    record.insert("prompts".to_string(), Value::Array(prompts));

    for key in [
        "command",
        "server_url",
        "endpoint",
        "source",
        "source_path",
        "source_scope",
        "config_compatibility",
        "workspace_root",
    ] {
        if let Some(value) = json_string_value(server, key) {
            record.insert(key.to_string(), Value::String(value));
        }
    }
    if let Some(url) = server_url {
        record
            .entry("server_url".to_string())
            .or_insert_with(|| Value::String(url.clone()));
        record
            .entry("endpoint".to_string())
            .or_insert_with(|| Value::String(url));
    }
    for key in ["args"] {
        if let Some(items) = server.get(key).and_then(Value::as_array) {
            record.insert(
                key.to_string(),
                Value::Array(
                    items
                        .iter()
                        .filter(|item| !item.is_null())
                        .cloned()
                        .collect(),
                ),
            );
        }
    }
    for key in [
        "env",
        "headers",
        "containment",
        "secret_refs",
        "vault_boundary",
    ] {
        if let Some(object) = server.get(key).and_then(Value::as_object) {
            record.insert(key.to_string(), Value::Object(object.clone()));
        }
    }

    Ok(Value::Object(record))
}

fn mcp_control_registry_hash(registry: &Value) -> String {
    let bytes = serde_json::to_vec(registry).unwrap_or_else(|_| registry.to_string().into_bytes());
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationCore;

impl McpServerValidationCore {
    pub fn validate(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        request.validate()?;
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        for server in &request.servers {
            let transport = normalize_mcp_transport(json_string_value(server, "transport"));
            let server_id = json_string_value(server, "id");
            let server_url = json_string_value(server, "server_url")
                .or_else(|| json_string_value(server, "endpoint"));

            if !matches!(transport.as_str(), "stdio" | "http" | "sse") {
                issues.push(mcp_validation_diagnostic(
                    "mcp_transport_unsupported",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "transport": transport,
                        "message": "MCP server transport must be stdio, http, or sse."
                    }),
                ));
            }
            if transport == "stdio" && json_string_value(server, "command").is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP stdio server must declare a command."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse") && server_url.is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server must declare a remote URL."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && server_url.as_deref().is_some_and(|url| !is_http_url(url))
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_url_invalid",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server URL must use http:// or https://."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && json_bool_path(server, &["containment", "allow_network_egress"]) == Some(false)
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_network_blocked",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server requires network egress in containment policy."
                    }),
                ));
            }

            if let Some(secret_refs) = server.get("secret_refs").and_then(Value::as_object) {
                for (key, value) in secret_refs {
                    if value.get("invalidVaultRef").and_then(Value::as_bool) == Some(true) {
                        issues.push(mcp_validation_diagnostic(
                            "mcp_secret_not_vault_ref",
                            "error",
                            server_id.as_deref(),
                            json!({
                                "key": key,
                                "message": "MCP env/header secrets must be represented as vault:// refs before activation."
                            }),
                        ));
                    }
                }
            }

            let allowed_tool_count = server
                .get("allowed_tools")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if allowed_tool_count == 0 {
                warnings.push(mcp_validation_diagnostic(
                    "mcp_allowed_tools_empty",
                    "warning",
                    server_id.as_deref(),
                    json!({
                        "message": "No allowed_tools list is declared; invocation remains unavailable until tools are narrowed."
                    }),
                ));
            }
        }

        let ok = issues.is_empty();
        Ok(McpServerValidationRecord {
            schema_version: MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation".to_string(),
            status: if ok { "pass" } else { "blocked" }.to_string(),
            ok,
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationInputCore;

impl McpServerValidationInputCore {
    pub fn project(
        &self,
        request: &McpServerValidationInputRequest,
    ) -> Result<McpServerValidationInputRecord, McpServerValidationInputError> {
        request.validate()?;
        let workspace_root = request
            .workspace_root
            .as_deref()
            .and_then(|value| optional_trimmed(Some(value)));
        let input_source = json_string_value(&request.input, "source")
            .unwrap_or_else(|| "validation_input".to_string());
        let input_source_scope = json_string_value(&request.input, "source_scope")
            .unwrap_or_else(|| "validation".to_string());
        let input_source_path = json_string_value(&request.input, "source_path");
        let input_config_compatibility = json_string_value(&request.input, "config_compatibility");
        let input_status =
            json_string_value(&request.input, "status").unwrap_or_else(|| "configured".to_string());
        let raw = request.input.get("mcp_json").unwrap_or(&request.input);
        let servers = raw
            .get("mcp_servers")
            .or_else(|| raw.get("servers"))
            .or_else(|| if raw.is_array() { Some(raw) } else { None });
        let records = match servers {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, server)| {
                    let label = mcp_validation_server_label(server)
                        .unwrap_or_else(|| format!("server_{}", index + 1));
                    let config = enrich_mcp_validation_source_metadata(
                        server,
                        input_source_path.as_deref(),
                        input_config_compatibility.as_deref(),
                    );
                    let source = json_string_value(&config, "source")
                        .unwrap_or_else(|| input_source.clone());
                    let source_scope = json_string_value(&config, "source_scope")
                        .unwrap_or_else(|| input_source_scope.clone());
                    let status = json_string_value(&config, "status")
                        .unwrap_or_else(|| input_status.clone());
                    normalize_mcp_validation_server_record(
                        &label,
                        &config,
                        workspace_root.as_deref(),
                        &source,
                        &source_scope,
                        &status,
                    )
                })
                .collect::<Vec<_>>(),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(label, config)| {
                    let config = enrich_mcp_validation_source_metadata(
                        config,
                        input_source_path.as_deref(),
                        input_config_compatibility.as_deref(),
                    );
                    normalize_mcp_validation_server_record(
                        label,
                        &config,
                        workspace_root.as_deref(),
                        &input_source,
                        &input_source_scope,
                        &input_status,
                    )
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };

        Ok(McpServerValidationInputRecord {
            schema_version: MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation_input".to_string(),
            status: "projected".to_string(),
            workspace_root,
            server_count: records.len(),
            servers: records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerValidationProjectionCore;

impl McpManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerValidationProjectionRequest,
    ) -> Result<McpManagerValidationProjectionRecord, McpManagerValidationProjectionError> {
        request.validate()?;

        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let issues = request
            .validation
            .get("issues")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let warnings = request
            .validation
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        Ok(McpManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_mcp_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            server_count: request.servers.len(),
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogProjectionCore;

impl McpManagerCatalogProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogProjectionRequest,
    ) -> Result<McpManagerCatalogProjectionRecord, McpManagerCatalogProjectionError> {
        request.validate()?;

        let servers = mcp_catalog_projection_servers(request)?;
        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut prompts = Vec::new();
        let mut enabled_tools = Vec::new();

        for server in &servers {
            let server_tools = mcp_catalog_tools_for_server(server);
            if server.get("enabled").and_then(Value::as_bool) != Some(false) {
                enabled_tools.extend(server_tools.clone());
            }
            tools.extend(server_tools);
            resources.extend(mcp_catalog_resources_for_server(server));
            prompts.extend(mcp_catalog_prompts_for_server(server));
        }

        resources.sort_by(|left, right| {
            mcp_catalog_resource_key(left).cmp(&mcp_catalog_resource_key(right))
        });
        prompts.sort_by(|left, right| {
            mcp_catalog_prompt_key(left).cmp(&mcp_catalog_prompt_key(right))
        });

        Ok(McpManagerCatalogProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_manager_catalog_projection".to_string(),
            status: "projected".to_string(),
            server_count: servers.len(),
            tool_count: tools.len(),
            resource_count: resources.len(),
            prompt_count: prompts.len(),
            enabled_tool_count: enabled_tools.len(),
            servers,
            tools,
            resources,
            prompts,
            enabled_tools,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

fn mcp_catalog_projection_servers(
    request: &McpManagerCatalogProjectionRequest,
) -> Result<Vec<Value>, McpManagerCatalogProjectionError> {
    let thread_id = optional_trimmed(request.thread_id.as_deref());
    let agent_id = optional_trimmed(request.agent_id.as_deref());
    let state_dir = optional_trimmed(request.state_dir.as_deref());
    let mut servers = request
        .servers
        .iter()
        .filter(|server| server.is_object())
        .cloned()
        .collect::<Vec<_>>();

    if thread_id.is_some() || agent_id.is_some() {
        let state_root = state_dir
            .as_deref()
            .ok_or(McpManagerCatalogProjectionError::StateDirRequired)?;
        let agent = mcp_catalog_agent_from_state_dir(
            state_root,
            thread_id.as_deref(),
            agent_id.as_deref(),
        )?;
        servers.extend(mcp_control_agent_servers(&agent));
    } else if let Some(state_root) = state_dir.as_deref() {
        for agent in mcp_catalog_agents_from_state_dir(state_root)? {
            servers.extend(mcp_control_agent_servers(&agent));
        }
    }

    Ok(mcp_catalog_dedup_servers(servers))
}

fn mcp_catalog_agent_from_state_dir(
    state_dir: &str,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
) -> Result<serde_json::Map<String, Value>, McpManagerCatalogProjectionError> {
    let agents_dir = PathBuf::from(state_dir).join("agents");
    let mut candidate_ids = Vec::new();
    if let Some(id) = optional_trimmed(agent_id) {
        candidate_ids.push(id);
    }
    if let Some(thread_id) = optional_trimmed(thread_id) {
        if let Some(derived) = mcp_control_agent_id_for_thread(thread_id.as_str()) {
            candidate_ids.push(derived);
        }
        candidate_ids.push(thread_id);
    }
    candidate_ids.dedup();

    for candidate_id in &candidate_ids {
        let path = agents_dir.join(format!("{}.json", mcp_control_safe_component(candidate_id)));
        if path.exists() {
            let record = read_mcp_catalog_agent_record(&path)?;
            if mcp_control_agent_matches_thread(
                &record,
                thread_id.unwrap_or(""),
                Some(candidate_id.as_str()),
            ) || agent_id.is_some_and(|expected| {
                optional_json_string(&Value::Object(record.clone()), "id").as_deref()
                    == Some(expected)
            }) {
                return Ok(record);
            }
        }
    }

    if agents_dir.exists() {
        for entry in fs::read_dir(&agents_dir).map_err(|error| {
            McpManagerCatalogProjectionError::StateDirReadFailed(format!(
                "could not inspect Agentgres agents directory: {error}"
            ))
        })? {
            let entry = entry.map_err(|error| {
                McpManagerCatalogProjectionError::StateDirReadFailed(format!(
                    "could not inspect Agentgres agent entry: {error}"
                ))
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record = read_mcp_catalog_agent_record(&path)?;
            let thread_matches = thread_id.is_some_and(|expected| {
                mcp_control_agent_matches_thread(&record, expected, agent_id)
            });
            let agent_matches = agent_id.is_some_and(|expected| {
                optional_json_string(&Value::Object(record.clone()), "id").as_deref()
                    == Some(expected)
            });
            if thread_matches || agent_matches {
                return Ok(record);
            }
        }
    }

    Err(McpManagerCatalogProjectionError::AgentReplayRequired(
        thread_id
            .and_then(|value| optional_trimmed(Some(value)))
            .or_else(|| agent_id.and_then(|value| optional_trimmed(Some(value))))
            .unwrap_or_else(|| "mcp_catalog_context".to_string()),
    ))
}

fn mcp_catalog_agents_from_state_dir(
    state_dir: &str,
) -> Result<Vec<serde_json::Map<String, Value>>, McpManagerCatalogProjectionError> {
    let agents_dir = PathBuf::from(state_dir).join("agents");
    if !agents_dir.exists() {
        return Ok(Vec::new());
    }
    let mut agents = Vec::new();
    for entry in fs::read_dir(&agents_dir).map_err(|error| {
        McpManagerCatalogProjectionError::StateDirReadFailed(format!(
            "could not inspect Agentgres agents directory: {error}"
        ))
    })? {
        let entry = entry.map_err(|error| {
            McpManagerCatalogProjectionError::StateDirReadFailed(format!(
                "could not inspect Agentgres agent entry: {error}"
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        agents.push(read_mcp_catalog_agent_record(&path)?);
    }
    Ok(agents)
}

fn read_mcp_catalog_agent_record(
    path: &Path,
) -> Result<serde_json::Map<String, Value>, McpManagerCatalogProjectionError> {
    let body = fs::read_to_string(path).map_err(|error| {
        McpManagerCatalogProjectionError::StateDirReadFailed(format!(
            "could not read Agentgres agent record {}: {error}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&body).map_err(|error| {
        McpManagerCatalogProjectionError::StateDirRecordInvalid(format!(
            "invalid Agentgres agent record {}: {error}",
            path.display()
        ))
    })?;
    object_value(&value).ok_or_else(|| {
        McpManagerCatalogProjectionError::StateDirRecordInvalid(format!(
            "Agentgres agent record {} is not an object",
            path.display()
        ))
    })
}

fn mcp_catalog_dedup_servers(servers: Vec<Value>) -> Vec<Value> {
    let mut seen = Vec::new();
    let mut deduped = Vec::new();
    for server in servers {
        let key = json_string_value(&server, "id").unwrap_or_else(|| server.to_string());
        if seen.iter().any(|candidate: &String| candidate == &key) {
            continue;
        }
        seen.push(key);
        deduped.push(server);
    }
    deduped
}

fn mcp_tool_search_catalog_projection(
    request: &McpToolSearchProjectionRequest,
) -> Result<McpManagerCatalogProjectionRecord, McpToolProjectionError> {
    McpManagerCatalogProjectionCore
        .project(&McpManagerCatalogProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            state_dir: request.state_dir.clone(),
            thread_id: request.thread_id.clone(),
            agent_id: request.agent_id.clone(),
            agent: Value::Null,
            servers: request.servers.clone(),
        })
        .map_err(|error| McpToolProjectionError::CatalogProjectionFailed(format!("{error:?}")))
}

fn mcp_tool_catalog_summaries(
    servers: &[Value],
    tools: &[Value],
    resources: &[Value],
    prompts: &[Value],
    live_discovery: bool,
    preview_limit: usize,
) -> Result<Vec<Value>, McpToolProjectionError> {
    let mut summaries = Vec::new();
    for server in servers {
        let server_id = json_string_value(server, "id");
        let server_tools = mcp_tool_rows_for_server(tools, server_id.as_deref());
        let server_resources =
            mcp_catalog_rows_for_server(resources, server_id.as_deref(), "server_id");
        let server_prompts =
            mcp_catalog_rows_for_server(prompts, server_id.as_deref(), "server_id");
        let deferred_live_discovery =
            live_discovery && server.get("enabled").and_then(Value::as_bool) != Some(false);
        let summary = McpManagerCatalogSummaryProjectionCore
            .project(&McpManagerCatalogSummaryProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                status_schema_version: None,
                server: server.clone(),
                tools: server_tools,
                resources: server_resources,
                prompts: server_prompts,
                live_mode: if deferred_live_discovery {
                    Some("rust_mcp_live_discovery_deferred".to_string())
                } else {
                    None
                },
                status: if deferred_live_discovery {
                    Some("deferred".to_string())
                } else {
                    None
                },
                error_code: None,
                preview_limit: Some(preview_limit),
                deferred: Some(deferred_live_discovery),
            })
            .map_err(|error| {
                McpToolProjectionError::CatalogSummaryProjectionFailed(format!("{error:?}"))
            })?;
        summaries.push(serde_json::to_value(summary).unwrap_or(Value::Null));
    }
    Ok(summaries)
}

fn mcp_tool_rows_for_server(tools: &[Value], server_id: Option<&str>) -> Vec<Value> {
    mcp_catalog_rows_for_server(tools, server_id, "server_id")
}

fn mcp_catalog_rows_for_server(rows: &[Value], server_id: Option<&str>, key: &str) -> Vec<Value> {
    rows.iter()
        .filter(|row| {
            server_id
                .and_then(|expected| json_string_value(row, key).map(|actual| actual == expected))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn mcp_catalog_tool_key(tool: &Value) -> String {
    mcp_catalog_field_string(tool, &["stable_tool_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(tool, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(tool, &["tool_name", "name"])
                .unwrap_or_else(|| "tool".to_string())
        )
    })
}

fn mcp_tool_identity_matches(tool: &Value, requested: &str) -> bool {
    let requested = requested.trim();
    if requested.is_empty() {
        return false;
    }
    let stable = mcp_catalog_field_string(tool, &["stable_tool_id"]);
    if stable.as_deref() == Some(requested) {
        return true;
    }
    let server_id = mcp_catalog_field_string(tool, &["server_id"]);
    let tool_name = mcp_catalog_field_string(tool, &["tool_name", "name"]);
    match (server_id, tool_name) {
        (Some(server_id), Some(tool_name)) => format!("{server_id}.{tool_name}") == requested,
        _ => false,
    }
}

fn mcp_tool_matches_query(tool: &Value, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }
    [
        "stable_tool_id",
        "display_name",
        "server_id",
        "server_label",
        "tool_name",
        "name",
        "description",
    ]
    .iter()
    .filter_map(|key| json_string_value(tool, key))
    .any(|value| value.to_ascii_lowercase().contains(&query))
}

fn mcp_tool_projection_routes() -> Value {
    json!({
        "search": "/v1/mcp/tools/search",
        "get_tool": "/v1/mcp/tools/{tool_id}",
        "invoke_tool": "/v1/mcp/tools/{tool_id}/invoke",
    })
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogSummaryProjectionCore;

impl McpManagerCatalogSummaryProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogSummaryProjectionRequest,
    ) -> Result<McpManagerCatalogSummaryProjectionRecord, McpManagerCatalogSummaryProjectionError>
    {
        request.validate()?;

        let mut tool_names = request
            .tools
            .iter()
            .filter_map(|tool| mcp_catalog_field_string(tool, &["tool_name", "name"]))
            .collect::<Vec<_>>();
        tool_names.sort();

        let namespaces = mcp_tool_namespaces(&tool_names);
        let preview_limit = request.preview_limit.unwrap_or(25).clamp(1, 100);
        let deferred = request
            .deferred
            .unwrap_or_else(|| request.tools.len() > preview_limit);
        let preview_tool_names = tool_names
            .iter()
            .take(preview_limit.min(20))
            .cloned()
            .collect::<Vec<_>>();
        let catalog_hash = mcp_catalog_summary_hash(
            &request.server,
            &request.tools,
            &request.resources,
            &request.prompts,
        );

        Ok(McpManagerCatalogSummaryProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_catalog_summary".to_string(),
            status: request
                .status
                .clone()
                .unwrap_or_else(|| "completed".to_string()),
            server_id: json_string_value(&request.server, "id"),
            server_label: json_string_value(&request.server, "label")
                .or_else(|| json_string_value(&request.server, "name"))
                .or_else(|| json_string_value(&request.server, "id")),
            transport: json_string_value(&request.server, "transport"),
            execution_mode: request.live_mode.clone(),
            catalog_hash,
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            namespace_count: namespaces.len(),
            namespaces,
            preview_limit,
            preview_tool_names,
            deferred,
            full_catalog_included: !deferred,
            error_code: request.error_code.clone(),
            search_route: "/v1/mcp/tools/search".to_string(),
            fetch_route: "/v1/mcp/tools/{tool_id}".to_string(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpToolSearchProjectionCore;

impl McpToolSearchProjectionCore {
    pub fn project(
        &self,
        request: &McpToolSearchProjectionRequest,
    ) -> Result<McpToolSearchProjectionRecord, McpToolProjectionError> {
        request.validate()?;

        let catalog = mcp_tool_search_catalog_projection(request)?;
        let query = optional_trimmed(request.query.as_deref()).unwrap_or_default();
        let requested_tool_id = optional_trimmed(request.tool_id.as_deref());
        let requested_server_id = optional_trimmed(request.server_id.as_deref());
        let exact = request.exact.unwrap_or(false);
        let live_discovery = request.live_discovery.unwrap_or(true);
        let limit = request.limit.unwrap_or(25).clamp(1, 100);
        let preview_limit = request.preview_limit.unwrap_or(25).clamp(1, 100);
        let servers = catalog
            .servers
            .iter()
            .filter(|server| {
                requested_server_id
                    .as_deref()
                    .map(|expected| json_string_value(server, "id").as_deref() == Some(expected))
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut filtered = catalog
            .tools
            .iter()
            .filter(|tool| {
                requested_server_id
                    .as_deref()
                    .map(|expected| {
                        json_string_value(tool, "server_id").as_deref() == Some(expected)
                    })
                    .unwrap_or(true)
            })
            .filter(|tool| {
                if let Some(tool_id) = requested_tool_id.as_deref() {
                    mcp_tool_identity_matches(tool, tool_id)
                        || (!exact && mcp_tool_matches_query(tool, tool_id))
                } else {
                    mcp_tool_matches_query(tool, &query)
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        filtered
            .sort_by(|left, right| mcp_catalog_tool_key(left).cmp(&mcp_catalog_tool_key(right)));
        let returned = filtered.iter().take(limit).cloned().collect::<Vec<_>>();
        let summary_tools = catalog
            .tools
            .iter()
            .filter(|tool| {
                requested_server_id
                    .as_deref()
                    .map(|expected| {
                        json_string_value(tool, "server_id").as_deref() == Some(expected)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let summary_resources = catalog
            .resources
            .iter()
            .filter(|resource| {
                requested_server_id
                    .as_deref()
                    .map(|expected| {
                        json_string_value(resource, "server_id").as_deref() == Some(expected)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let summary_prompts = catalog
            .prompts
            .iter()
            .filter(|prompt| {
                requested_server_id
                    .as_deref()
                    .map(|expected| {
                        json_string_value(prompt, "server_id").as_deref() == Some(expected)
                    })
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        let catalog_summaries = mcp_tool_catalog_summaries(
            &servers,
            &summary_tools,
            &summary_resources,
            &summary_prompts,
            live_discovery,
            preview_limit,
        )?;
        let rust_mcp_live_discovery_deferred = catalog_summaries.iter().any(|summary| {
            json_string_value(summary, "execution_mode").as_deref()
                == Some("rust_mcp_live_discovery_deferred")
        });

        Ok(McpToolSearchProjectionRecord {
            schema_version: MCP_TOOL_SEARCH_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_tool_search".to_string(),
            status: "completed".to_string(),
            query: query.clone(),
            q: query,
            exact,
            live_discovery,
            rust_mcp_live_discovery_deferred,
            server_count: servers.len(),
            tool_count: filtered.len(),
            returned_count: returned.len(),
            limit,
            deferred: filtered.len() > returned.len(),
            tools: returned,
            catalog_summaries,
            failures: Vec::new(),
            routes: mcp_tool_projection_routes(),
            evidence_refs: vec![
                "runtime_mcp_tool_search_rust_projection".to_string(),
                "runtime_mcp_catalog_js_search_filter_retired".to_string(),
                "runtime_mcp_catalog_fetch_js_shape_retired".to_string(),
            ],
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpToolFetchProjectionCore;

impl McpToolFetchProjectionCore {
    pub fn project(
        &self,
        request: &McpToolFetchProjectionRequest,
    ) -> Result<McpToolFetchProjectionRecord, McpToolProjectionError> {
        request.validate()?;
        let requested_tool_id = optional_trimmed(request.tool_id.as_deref());
        let search = McpToolSearchProjectionCore.project(&McpToolSearchProjectionRequest {
            schema_version: MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: request.status_schema_version.clone(),
            state_dir: request.state_dir.clone(),
            thread_id: request.thread_id.clone(),
            agent_id: request.agent_id.clone(),
            server_id: request.server_id.clone(),
            servers: request.servers.clone(),
            query: requested_tool_id.clone(),
            tool_id: requested_tool_id.clone(),
            exact: Some(true),
            limit: Some(request.limit.unwrap_or(25).max(1)),
            preview_limit: request.preview_limit,
            live_discovery: request.live_discovery,
        })?;
        let tool = search.tools.iter().find(|tool| {
            requested_tool_id
                .as_deref()
                .is_some_and(|tool_id| mcp_tool_identity_matches(tool, tool_id))
        });
        let tool = tool.cloned();
        let status = if tool.is_some() {
            "completed".to_string()
        } else {
            "not_found".to_string()
        };
        let tools = tool.iter().cloned().collect::<Vec<_>>();
        let returned_count = tools.len();
        let tool_id = requested_tool_id.or_else(|| {
            tool.as_ref()
                .and_then(|tool| json_string_value(tool, "stable_tool_id"))
        });
        let server_id = tool
            .as_ref()
            .and_then(|tool| json_string_value(tool, "server_id"));
        let tool_name = tool
            .as_ref()
            .and_then(|tool| json_string_value(tool, "tool_name"));

        Ok(McpToolFetchProjectionRecord {
            schema_version: MCP_TOOL_FETCH_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_tool_fetch".to_string(),
            status,
            tool_id,
            server_id,
            tool_name,
            tool,
            tools,
            returned_count,
            search_projection: serde_json::to_value(search).unwrap_or(Value::Null),
            catalog_summaries: Vec::new(),
            routes: mcp_tool_projection_routes(),
            evidence_refs: vec![
                "runtime_mcp_tool_fetch_rust_projection".to_string(),
                "runtime_mcp_catalog_fetch_js_shape_retired".to_string(),
            ],
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerStatusProjectionCore;

impl McpManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerStatusProjectionRequest,
    ) -> Result<McpManagerStatusProjectionRecord, McpManagerStatusProjectionError> {
        request.validate()?;

        let server_count = request.servers.len();
        let tool_count = request.tools.len();
        let resource_count = request.resources.len();
        let prompt_count = request.prompts.len();
        let enabled_server_count = request
            .servers
            .iter()
            .filter(|server| server.get("enabled").and_then(Value::as_bool) != Some(false))
            .count();
        let enabled_tool_count = if request.enabled_tools.is_empty() {
            None
        } else {
            Some(request.enabled_tools.len())
        };
        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let validation = extend_json_object(
            request.validation.clone(),
            json!({
                "server_count": server_count,
                "tool_count": tool_count,
                "resource_count": resource_count,
                "prompt_count": prompt_count,
                "servers": request.servers.clone(),
                "tools": request.tools.clone(),
                "resources": request.resources.clone(),
                "prompts": request.prompts.clone(),
            }),
        );

        Ok(McpManagerStatusProjectionRecord {
            schema_version: request
                .status_schema_version
                .clone()
                .unwrap_or_else(|| MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()),
            object: "ioi.runtime_mcp_manager_status".to_string(),
            status: if ok { "ready" } else { "needs_review" }.to_string(),
            server_count,
            tool_count,
            resource_count,
            prompt_count,
            enabled_server_count,
            enabled_tool_count,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            validation,
            routes: request.routes.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerValidationProjectionCore;

impl MemoryManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerValidationProjectionRequest,
    ) -> Result<MemoryManagerValidationProjectionRecord, MemoryManagerValidationProjectionError>
    {
        request.validate()?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        validate_memory_manager_policy(&policy, &mut issues, &mut warnings);
        validate_memory_manager_paths(&paths, &mut issues, &mut warnings);
        for record in &records {
            validate_memory_manager_record(record, &mut issues, &mut warnings);
        }

        let ok = issues.is_empty();
        Ok(MemoryManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_memory_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            record_count: records.len(),
            issues,
            warnings,
            policy,
            paths,
            filters,
            records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerStatusProjectionCore;

impl MemoryManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerStatusProjectionRequest,
    ) -> Result<MemoryManagerStatusProjectionRecord, MemoryManagerStatusProjectionError> {
        request.validate()?;
        let validation = MemoryManagerValidationProjectionCore
            .project(&MemoryManagerValidationProjectionRequest {
                schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                validation_schema_version: request.validation_schema_version.clone(),
                projection: request.projection.clone(),
            })
            .map_err(|error| match error {
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected,
                    actual,
                } => MemoryManagerStatusProjectionError::InvalidSchemaVersion { expected, actual },
            })?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let disabled = json_bool_value(&policy, "disabled").unwrap_or(false);
        let injection_enabled = json_bool_value(&policy, "injection_enabled").unwrap_or(true);
        let read_only = json_bool_value(&policy, "read_only").unwrap_or(false);
        let write_requires_approval =
            json_bool_value(&policy, "write_requires_approval").unwrap_or(false);
        let scopes = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "scope"))
                .collect(),
        );
        let memory_keys = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "memory_key"))
                .collect(),
        );
        let write_blocked_reason = if disabled {
            Some("memory_disabled".to_string())
        } else if read_only {
            Some("memory_read_only".to_string())
        } else if write_requires_approval {
            Some("memory_write_requires_approval".to_string())
        } else {
            None
        };
        let status = if validation.ok {
            if disabled {
                "disabled"
            } else {
                "ready"
            }
        } else {
            "needs_review"
        };
        let validation_value =
            serde_json::to_value(&validation).unwrap_or_else(|_| Value::Object(Default::default()));

        Ok(MemoryManagerStatusProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_memory_manager_status".to_string(),
            status: status.to_string(),
            disabled,
            injection_enabled,
            read_only,
            write_requires_approval,
            write_blocked_reason,
            record_count: records.len(),
            scope_count: scopes.len(),
            memory_key_count: memory_keys.len(),
            scopes,
            memory_keys,
            policy: policy.clone(),
            paths: paths.clone(),
            filters,
            records: records.clone(),
            validation: validation_value,
            routes: json!({
                "records": "/v1/threads/{thread_id}/memory",
                "status": "/v1/threads/{thread_id}/memory/status",
                "validate": "/v1/threads/{thread_id}/memory/validate",
                "policy": "/v1/threads/{thread_id}/memory/policy",
                "path": "/v1/threads/{thread_id}/memory/path",
                "remember": "/v1/threads/{thread_id}/memory",
                "edit": "/v1/threads/{thread_id}/memory/{memory_id}",
                "delete": "/v1/threads/{thread_id}/memory/{memory_id}",
            }),
            evidence_refs: memory_status_evidence_refs(&policy, &paths, &records),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadMemoryAgentStateUpdateCore;

impl ThreadMemoryAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadMemoryAgentStateUpdateRequest,
    ) -> Result<ThreadMemoryAgentStateUpdateRecord, ThreadMemoryAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            ThreadMemoryAgentStateUpdateError::MissingField("control_kind"),
        )?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });

        Ok(ThreadMemoryAgentStateUpdateRecord {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_memory_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl McpControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), McpControlAgentStateUpdateError> {
        if self.schema_version != MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("thread_id"));
        }
        if self.agent.is_object() {
            return Err(McpControlAgentStateUpdateError::AgentCandidateTransportRetired);
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(McpControlAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("created_at"));
        }
        Ok(())
    }
}

impl McpLiveResultReplayRequest {
    pub fn validate(&self) -> Result<(), McpLiveResultReplayError> {
        if self.schema_version != MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION {
            return Err(McpLiveResultReplayError::InvalidSchemaVersion {
                expected: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(McpLiveResultReplayError::StateDirRequired);
        }
        Ok(())
    }
}

impl McpServerValidationRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationError> {
        if self.schema_version != MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpServerValidationInputRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationInputError> {
        if self.schema_version != MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationInputError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerStatusProjectionError> {
        if self.schema_version != MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerValidationProjectionError> {
        if self.schema_version != MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerValidationProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl MemoryManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerValidationProjectionError> {
        if self.schema_version != MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl MemoryManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerStatusProjectionError> {
        if self.schema_version != MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(MemoryManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerCatalogProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerCatalogProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.agent.is_object() {
            return Err(McpManagerCatalogProjectionError::AgentCandidateTransportRetired);
        }
        if (optional_trimmed(self.thread_id.as_deref()).is_some()
            || optional_trimmed(self.agent_id.as_deref()).is_some())
            && optional_trimmed(self.state_dir.as_deref()).is_none()
        {
            return Err(McpManagerCatalogProjectionError::StateDirRequired);
        }
        Ok(())
    }
}

impl McpManagerCatalogSummaryProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogSummaryProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                McpManagerCatalogSummaryProjectionError::InvalidSchemaVersion {
                    expected: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl McpToolSearchProjectionRequest {
    pub fn validate(&self) -> Result<(), McpToolProjectionError> {
        if self.schema_version != MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpToolProjectionError::InvalidSchemaVersion {
                expected: MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpToolFetchProjectionRequest {
    pub fn validate(&self) -> Result<(), McpToolProjectionError> {
        if self.schema_version != MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpToolProjectionError::InvalidSchemaVersion {
                expected: MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl ThreadMemoryAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadMemoryAgentStateUpdateError> {
        if self.schema_version != THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("thread_id"));
        }
        if !self.agent.is_object() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent"));
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "created_at",
            ));
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"));
        }
        Ok(())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while output.contains("__") {
        output = output.replace("__", "_");
    }
    output.trim_matches('_').to_string()
}

fn mcp_catalog_server_label(server: &Value) -> String {
    optional_trimmed(server.get("label").and_then(Value::as_str))
        .or_else(|| optional_trimmed(server.get("name").and_then(Value::as_str)))
        .or_else(|| optional_trimmed(server.get("id").and_then(Value::as_str)))
        .unwrap_or_else(|| "mcp".to_string())
}

fn mcp_catalog_server_status(server: &Value) -> String {
    if server.get("enabled").and_then(Value::as_bool) == Some(false) {
        "disabled".to_string()
    } else {
        optional_trimmed(server.get("status").and_then(Value::as_str))
            .unwrap_or_else(|| "configured".to_string())
    }
}

fn mcp_catalog_server_transport(server: &Value) -> String {
    optional_trimmed(server.get("transport").and_then(Value::as_str))
        .unwrap_or_else(|| "stdio".to_string())
}

fn mcp_catalog_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| !item.is_null())
            .cloned()
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, entry)| {
                if let Value::Object(entry_map) = entry {
                    let mut item = serde_json::Map::new();
                    item.insert("name".to_string(), Value::String(name.clone()));
                    item.extend(entry_map.clone());
                    Value::Object(item)
                } else {
                    json!({
                        "name": name,
                        "uri": match entry {
                            Value::Null => name.clone(),
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        },
                    })
                }
            })
            .collect(),
        Some(value) if !value.is_null() => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn mcp_catalog_value_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .and_then(|text| optional_trimmed(Some(text)))
        .or_else(|| match value {
            Value::Null | Value::Array(_) | Value::Object(_) => None,
            other => optional_trimmed(Some(other.to_string().as_str())),
        })
}

fn mcp_catalog_field_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|text| optional_trimmed(Some(text)))
    })
}

fn mcp_catalog_tools_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(server.get("allowed_tools"))
        .into_iter()
        .map(|tool| {
            let tool_name = mcp_catalog_field_string(&tool, &["name", "tool_name", "toolName"])
                .or_else(|| mcp_catalog_value_string(&tool))
                .unwrap_or_else(|| "tool".to_string());
            let safe_tool = safe_id(&tool_name);
            json!({
                "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
                "stable_tool_id": format!("mcp.{safe_server}.{safe_tool}"),
                "display_name": format!("{server_label}.{tool_name}"),
                "pack": "mcp",
                "server_id": server_id.clone(),
                "server_label": server_label,
                "tool_name": tool_name,
                "description": mcp_catalog_field_string(&tool, &["description"]),
                "status": status,
                "transport": transport,
                "primitive_capabilities": ["prim:connector.invoke"],
                "authority_scope_requirements": ["scope:mcp.invoke"],
                "effect_class": "connector_call",
                "risk_domain": "connector",
                "input_schema": tool.get("input_schema").or_else(|| tool.get("inputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "output_schema": tool.get("output_schema").or_else(|| tool.get("outputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "evidence_requirements": ["mcp_containment_receipt"],
                "workflow_node_type": "McpToolNode",
                "workflow_config_fields": ["server_id", "tool_name", "allowed_tools", "containment"],
                "workflow_node_id": format!("runtime.mcp-tool.{safe_server}.{safe_tool}"),
                "receipt_refs": [],
            })
        })
        .collect()
}

fn mcp_catalog_resources_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("resources")
            .or_else(|| server.get("allowed_resources")),
    )
    .into_iter()
    .map(|resource| {
        let uri = mcp_catalog_field_string(&resource, &["uri", "url", "resource_uri"])
            .or_else(|| mcp_catalog_value_string(&resource))
            .unwrap_or_else(|| format!("resource://{safe_server}/unknown"));
        let name =
            mcp_catalog_field_string(&resource, &["name", "title"]).unwrap_or_else(|| uri.clone());
        let safe_uri = safe_id(&uri);
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_resource_id": format!("mcp.{safe_server}.resource.{safe_uri}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "uri": uri,
            "name": name,
            "description": mcp_catalog_field_string(&resource, &["description"]),
            "mime_type": mcp_catalog_field_string(&resource, &["mime_type", "mimeType"]),
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.resource.read"],
            "authority_scope_requirements": ["scope:mcp.resource.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_resource_catalog_receipt"],
            "workflow_node_type": "McpResourceNode",
            "workflow_config_fields": ["server_id", "uri", "containment"],
            "workflow_node_id": format!("runtime.mcp-resource.{safe_server}.{safe_uri}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_prompts_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("prompts")
            .or_else(|| server.get("allowed_prompts")),
    )
    .into_iter()
    .map(|prompt| {
        let name = mcp_catalog_field_string(&prompt, &["name", "title"])
            .or_else(|| mcp_catalog_value_string(&prompt))
            .unwrap_or_else(|| "prompt".to_string());
        let safe_prompt = safe_id(&name);
        let arguments = prompt
            .get("arguments")
            .filter(|value| value.is_array())
            .cloned()
            .unwrap_or_else(|| json!([]));
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_prompt_id": format!("mcp.{safe_server}.prompt.{safe_prompt}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "name": name,
            "description": mcp_catalog_field_string(&prompt, &["description"]),
            "arguments": arguments.clone(),
            "prompt_arguments": arguments,
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.prompt.read"],
            "authority_scope_requirements": ["scope:mcp.prompt.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_prompt_catalog_receipt"],
            "workflow_node_type": "McpPromptNode",
            "workflow_config_fields": ["server_id", "prompt_name", "containment"],
            "workflow_node_id": format!("runtime.mcp-prompt.{safe_server}.{safe_prompt}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_resource_key(resource: &Value) -> String {
    mcp_catalog_field_string(resource, &["stable_resource_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(resource, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(resource, &["uri"]).unwrap_or_else(|| "resource".to_string())
        )
    })
}

fn mcp_catalog_prompt_key(prompt: &Value) -> String {
    mcp_catalog_field_string(prompt, &["stable_prompt_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(prompt, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(prompt, &["name"]).unwrap_or_else(|| "prompt".to_string())
        )
    })
}

fn mcp_catalog_summary_hash(
    server: &Value,
    tools: &[Value],
    resources: &[Value],
    prompts: &[Value],
) -> String {
    let payload = json!({
        "server_id": json_string_value(server, "id"),
        "tools": tools.iter().map(|tool| {
            json!({
                "stable_tool_id": json_string_value(tool, "stable_tool_id"),
                "tool_name": json_string_value(tool, "tool_name"),
                "description": json_string_value(tool, "description"),
                "input_schema": tool.get("input_schema").cloned().unwrap_or(Value::Null),
            })
        }).collect::<Vec<_>>(),
        "resources": resources.iter().map(|resource| {
            json!({
                "stable_resource_id": json_string_value(resource, "stable_resource_id"),
                "uri": json_string_value(resource, "uri"),
                "name": json_string_value(resource, "name"),
            })
        }).collect::<Vec<_>>(),
        "prompts": prompts.iter().map(|prompt| {
            json!({
                "stable_prompt_id": json_string_value(prompt, "stable_prompt_id"),
                "name": json_string_value(prompt, "name"),
            })
        }).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| payload.to_string().into_bytes());
    hex::encode(Sha256::digest(bytes))
}

fn mcp_tool_namespaces(tool_names: &[String]) -> Vec<String> {
    let mut namespaces = tool_names
        .iter()
        .filter_map(|name| {
            let namespace = name
                .split("__")
                .next()
                .unwrap_or(name)
                .split(['.', ':', '/', '-'])
                .next()
                .unwrap_or(name);
            optional_trimmed(Some(namespace))
        })
        .collect::<Vec<_>>();
    namespaces.sort();
    namespaces.dedup();
    namespaces.truncate(25);
    namespaces
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn json_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    json_string_value(value, key)
}

fn json_bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn extend_json_object(base: Value, extension: Value) -> Value {
    let mut object = match base {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(extension) = extension {
        object.extend(extension);
    }
    Value::Object(object)
}

fn memory_projection_object(projection: &Value, key: &str) -> Value {
    projection
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn memory_projection_records(projection: &Value) -> Vec<Value> {
    projection
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn validate_memory_manager_policy(
    policy: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !policy.is_object() {
        issues.push(memory_diagnostic(
            "memory_policy_missing",
            "error",
            "Memory status requires an effective policy.",
            json!({}),
        ));
        return;
    }
    if json_string_value(policy, "id").is_none() {
        issues.push(memory_diagnostic(
            "memory_policy_id_missing",
            "error",
            "Memory policy must have a stable id.",
            json!({}),
        ));
    }
    if let Some(scope) = json_string_value(policy, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_policy_scope_invalid",
                "error",
                "Memory policy scope is not supported.",
                json!({ "memory_scope": scope }),
            ));
        }
    }
    if let Some(redaction) = json_string_value(policy, "redaction") {
        if !matches!(redaction.as_str(), "none" | "redacted") {
            issues.push(memory_diagnostic(
                "memory_policy_redaction_invalid",
                "error",
                "Memory policy redaction must be none or redacted.",
                json!({}),
            ));
        }
    }
    if let Some(retention) = json_string_value(policy, "retention") {
        if !matches!(retention.as_str(), "persistent" | "session" | "ephemeral") {
            warnings.push(memory_diagnostic(
                "memory_policy_retention_unknown",
                "warning",
                "Memory retention is not one of the governed presets.",
                json!({}),
            ));
        }
    }
    if let Some(inheritance) = json_string_value(policy, "subagent_inheritance") {
        if !matches!(
            inheritance.as_str(),
            "none" | "explicit" | "read_only" | "full"
        ) {
            issues.push(memory_diagnostic(
                "memory_subagent_inheritance_invalid",
                "error",
                "Subagent memory inheritance mode is not supported.",
                json!({}),
            ));
        }
    }
    let disabled = json_bool_value(policy, "disabled").unwrap_or(false);
    let injection_enabled = json_bool_value(policy, "injection_enabled").unwrap_or(true);
    let read_only = json_bool_value(policy, "read_only").unwrap_or(false);
    let write_requires_approval =
        json_bool_value(policy, "write_requires_approval").unwrap_or(false);
    if disabled && injection_enabled {
        warnings.push(memory_diagnostic(
            "memory_disabled_with_injection_enabled",
            "warning",
            "Disabled memory should also disable prompt injection.",
            json!({}),
        ));
    }
    if read_only && write_requires_approval {
        warnings.push(memory_diagnostic(
            "memory_read_only_with_approval_required",
            "warning",
            "Read-only memory makes write approval unreachable.",
            json!({}),
        ));
    }
}

fn validate_memory_manager_paths(
    paths: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    for (canonical, label) in [("records_path", "records"), ("policies_path", "policies")] {
        let value = json_string_value(paths, canonical);
        if value.is_none() {
            issues.push(memory_diagnostic(
                &format!("memory_{label}_path_missing"),
                "error",
                &format!("Memory {label} path is missing."),
                json!({}),
            ));
            continue;
        }
        warnings.push(memory_diagnostic(
            &format!("memory_{label}_path_unverified_by_rust_core"),
            "warning",
            &format!("Memory {label} path is projected by Rust but disk access remains outside this pure projection core."),
            json!({ "path": value }),
        ));
    }
}

fn validate_memory_manager_record(
    record: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !record.is_object() {
        issues.push(memory_diagnostic(
            "memory_record_invalid",
            "error",
            "Memory record must be an object.",
            json!({}),
        ));
        return;
    }
    let record_id = json_string_value(record, "id");
    if record_id.is_none() {
        issues.push(memory_diagnostic(
            "memory_record_id_missing",
            "error",
            "Memory record id is required.",
            json!({}),
        ));
    }
    if json_string_value(record, "fact").is_none() {
        issues.push(memory_diagnostic(
            "memory_record_fact_missing",
            "error",
            "Memory record fact text is required.",
            json!({ "memory_record_id": record_id.clone() }),
        ));
    }
    if let Some(scope) = json_string_value(record, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_record_scope_invalid",
                "error",
                "Memory record scope is not supported.",
                json!({
                    "memory_record_id": record_id.clone(),
                    "memory_scope": scope,
                }),
            ));
        }
    }
    let fact_hash = json_string_value(record, "fact_hash");
    if json_string_value(record, "redaction").as_deref() == Some("redacted") && fact_hash.is_none()
    {
        warnings.push(memory_diagnostic(
            "memory_record_redacted_hash_missing",
            "warning",
            "Redacted memory records should include a fact hash.",
            json!({ "memory_record_id": record_id }),
        ));
    }
}

fn memory_diagnostic(code: &str, severity: &str, message: &str, extra: Value) -> Value {
    extend_json_object(
        json!({
            "code": code,
            "severity": severity,
            "message": message,
        }),
        extra,
    )
}

fn memory_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .filter_map(|value| optional_trimmed(Some(value.as_str())))
        .collect();
    values.sort();
    values.dedup();
    values
}

fn memory_status_evidence_refs(policy: &Value, paths: &Value, records: &[Value]) -> Vec<String> {
    let mut refs = vec![
        "runtime_memory_manager",
        "memory.status",
        "rust_memory_manager_status_projection_command",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    if let Some(policy_id) = json_string_value(policy, "id") {
        refs.push(policy_id);
    }
    if let Some(effective_policy_id) = json_string_value(paths, "effective_policy_id") {
        refs.push(effective_policy_id);
    }
    for record in records {
        if let Some(record_id) = json_string_value(record, "id") {
            refs.push(record_id);
        }
    }
    memory_unique_strings(refs)
}

fn json_bool_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn normalize_mcp_transport(value: Option<String>) -> String {
    match value
        .unwrap_or_else(|| "stdio".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "streamable_http" | "streamable-http" | "http-json-rpc" => "http".to_string(),
        "server-sent-events" | "eventsource" => "sse".to_string(),
        other => other.to_string(),
    }
}

fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn mcp_validation_diagnostic(
    code: &str,
    severity: &str,
    server_id: Option<&str>,
    detail: Value,
) -> Value {
    let mut diagnostic = object_value(&detail).unwrap_or_default();
    diagnostic.insert("code".to_string(), Value::String(code.to_string()));
    diagnostic.insert("severity".to_string(), Value::String(severity.to_string()));
    diagnostic.insert(
        "server_id".to_string(),
        server_id
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    Value::Object(diagnostic)
}

fn mcp_validation_server_label(server: &Value) -> Option<String> {
    json_string_value(server, "label")
        .or_else(|| json_string_value(server, "name"))
        .or_else(|| json_string_value(server, "id"))
}

fn enrich_mcp_validation_source_metadata(
    config: &Value,
    source_path: Option<&str>,
    config_compatibility: Option<&str>,
) -> Value {
    let mut enriched = object_value(config).unwrap_or_default();
    if let Some(path) = source_path.and_then(|value| optional_trimmed(Some(value))) {
        enriched.insert("source_path".to_string(), Value::String(path));
    }
    if let Some(compatibility) =
        config_compatibility.and_then(|value| optional_trimmed(Some(value)))
    {
        enriched.insert(
            "config_compatibility".to_string(),
            Value::String(compatibility),
        );
    }
    Value::Object(enriched)
}

fn normalize_mcp_validation_server_record(
    label: &str,
    config: &Value,
    workspace_root: Option<&str>,
    source: &str,
    source_scope: &str,
    status: &str,
) -> Value {
    let name = optional_trimmed(Some(label))
        .or_else(|| json_string_value(config, "label"))
        .or_else(|| json_string_value(config, "name"))
        .unwrap_or_else(|| "mcp".to_string());
    let id = json_string_value(config, "id").unwrap_or_else(|| format!("mcp.{}", safe_id(&name)));
    let server_url = json_string_value(config, "server_url")
        .or_else(|| json_string_value(config, "url"))
        .or_else(|| json_string_value(config, "endpoint"));
    let transport = normalize_mcp_transport(json_string_value(config, "transport").or_else(|| {
        server_url.as_ref().map(|url| {
            if url.contains("/sse") {
                "sse".to_string()
            } else {
                "http".to_string()
            }
        })
    }));
    let enabled = config.get("enabled").and_then(Value::as_bool) != Some(false)
        && config.get("disabled").and_then(Value::as_bool) != Some(true);
    let allowed_tools = normalize_mcp_allowed_tools(config);
    let resources = normalize_mcp_catalog_items_for_validation(
        config
            .get("resources")
            .or_else(|| config.get("allowed_resources")),
        "resource",
    );
    let prompts = normalize_mcp_catalog_items_for_validation(
        config
            .get("prompts")
            .or_else(|| config.get("allowed_prompts")),
        "prompt",
    );
    let headers = config
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let env = config
        .get("env")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let header_secret_refs = public_mcp_secret_refs(&headers, "header");
    let env_secret_refs = public_mcp_secret_refs(&env, "env");
    let secret_refs = merge_json_objects(&env_secret_refs, &header_secret_refs);
    let header_names = {
        let mut names = headers.keys().cloned().collect::<Vec<_>>();
        names.sort();
        names
    };
    let containment_mode = json_string_value(config, "containment_mode")
        .or_else(|| json_path_string(config, &["containment", "mode"]))
        .unwrap_or_else(|| "sandboxed".to_string());
    let allow_network_egress = config
        .get("allow_network_egress")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_network_egress"]))
        .unwrap_or(server_url.is_some());
    let allow_child_processes = config
        .get("allow_child_processes")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_child_processes"]))
        .unwrap_or_else(|| json_string_value(config, "command").is_some());
    let source_path = json_string_value(config, "source_path");
    let config_source = json_string_value(config, "source").unwrap_or_else(|| source.to_string());
    let config_source_scope =
        json_string_value(config, "source_scope").unwrap_or_else(|| source_scope.to_string());
    let config_compatibility = json_string_value(config, "config_compatibility");
    let mut evidence_refs = vec![
        "mcp.manager.validation_input".to_string(),
        config_source.clone(),
        config_source_scope.clone(),
        id.clone(),
    ];
    if let Some(path) = &source_path {
        evidence_refs.push(path.clone());
    }
    if let Some(compatibility) = &config_compatibility {
        evidence_refs.push(compatibility.clone());
    }
    evidence_refs.sort();
    evidence_refs.dedup();

    json!({
        "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
        "id": id,
        "label": name,
        "name": name,
        "enabled": enabled,
        "status": json_string_value(config, "status").unwrap_or_else(|| status.to_string()),
        "transport": transport,
        "command": json_string_value(config, "command"),
        "args": config.get("args").and_then(Value::as_array).map(|items| {
            items.iter().map(|item| {
                item.as_str().map(ToString::to_string).unwrap_or_else(|| item.to_string())
            }).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "server_url": server_url,
        "endpoint": server_url,
        "header_names": header_names,
        "header_secret_refs": header_secret_refs,
        "env_secret_refs": env_secret_refs,
        "source": config_source,
        "source_path": source_path,
        "source_scope": config_source_scope,
        "config_compatibility": config_compatibility,
        "workspace_root": workspace_root,
        "allowed_tools": allowed_tools,
        "tool_count": allowed_tools.len(),
        "resources": resources,
        "resource_count": resources.len(),
        "prompts": prompts,
        "prompt_count": prompts.len(),
        "containment": {
            "mode": containment_mode,
            "allow_network_egress": allow_network_egress,
            "allow_child_processes": allow_child_processes,
            "workspace_root": workspace_root,
        },
        "secret_refs": secret_refs,
        "vault_boundary": {
            "required": !secret_refs.as_object().unwrap_or(&serde_json::Map::new()).is_empty(),
            "header_ref_count": header_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "env_ref_count": env_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "secret_values_included": false,
            "runtime_resolution": "execution_time_only",
        },
        "health": {
            "status": if json_string_value(config, "status").as_deref() == Some("connected") { "connected" } else { "not_connected" },
            "live_probe": false,
            "reason": "read_only_catalog_status",
        },
        "evidence_refs": evidence_refs,
    })
}

fn normalize_mcp_allowed_tools(config: &Value) -> Vec<String> {
    let mut tools = Vec::new();
    if let Some(items) = config.get("allowed_tools").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str().and_then(|text| optional_trimmed(Some(text))) {
                tools.push(text);
            } else if let Some(name) = mcp_catalog_field_string(item, &["name", "tool_name"]) {
                tools.push(name);
            }
        }
    }
    if let Some(map) = config.get("tools").and_then(Value::as_object) {
        tools.extend(map.keys().cloned());
    }
    tools.sort();
    tools.dedup();
    tools
}

fn normalize_mcp_catalog_items_for_validation(
    value: Option<&Value>,
    fallback_key: &str,
) -> Vec<Value> {
    mcp_catalog_items(value)
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            if item.is_object() {
                item
            } else {
                json!({ fallback_key: mcp_catalog_value_string(&item).unwrap_or_else(|| format!("{fallback_key}_{index}")) })
            }
        })
        .collect()
}

fn public_mcp_secret_refs(source: &serde_json::Map<String, Value>, prefix: &str) -> Value {
    let mut refs = serde_json::Map::new();
    for (key, value) in source {
        match value {
            Value::String(text) if text.starts_with("vault://") => {
                refs.insert(key.clone(), Value::String(text.clone()));
            }
            Value::Object(object) if object.contains_key("secret_ref") => {
                refs.insert(
                    key.clone(),
                    object.get("secret_ref").cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(object) if object.contains_key("invalidVaultRef") => {
                refs.insert(key.clone(), Value::Object(object.clone()));
            }
            Value::Null => {}
            _ => {
                refs.insert(
                    key.clone(),
                    json!({
                        "invalidVaultRef": true,
                        "source": prefix,
                    }),
                );
            }
        }
    }
    Value::Object(refs)
}

fn merge_json_objects(left: &Value, right: &Value) -> Value {
    let mut merged = left.as_object().cloned().unwrap_or_default();
    if let Some(right) = right.as_object() {
        merged.extend(right.clone());
    }
    Value::Object(merged)
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .and_then(|entry| optional_trimmed(Some(entry)))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_mcp_state_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ioi-mcp-control-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join("agents")).expect("create temp Agentgres agents dir");
        path
    }

    fn seed_mcp_agent_state(state_dir: &Path, agent: &Value) {
        let agent_id = optional_json_string(agent, "id").expect("agent id");
        let path = state_dir
            .join("agents")
            .join(format!("{}.json", mcp_control_safe_component(&agent_id)));
        fs::write(
            path,
            serde_json::to_vec_pretty(agent).expect("serialize agent record"),
        )
        .expect("write temp Agentgres agent record");
    }

    fn seed_mcp_live_result_state(state_dir: &Path, result: &Value) {
        let result_id = optional_json_string(result, "id").expect("result id");
        let results_dir = state_dir.join("mcp-live-results");
        fs::create_dir_all(&results_dir).expect("create temp MCP live-results dir");
        fs::write(
            results_dir.join(format!("{}.json", mcp_control_safe_component(&result_id))),
            serde_json::to_vec_pretty(result).expect("serialize MCP live-result record"),
        )
        .expect("write temp Agentgres MCP live-result record");
    }

    fn mcp_control_agent_state_update_request() -> McpControlAgentStateUpdateRequest {
        let state_dir = temp_mcp_state_dir("state-update");
        let agent = json!({
            "id": "agent_1",
            "cwd": "/workspace",
            "mcpRegistry": {
                "servers": [
                    { "id": "mcp.docs", "enabled": true }
                ]
            },
            "updatedAt": "2026-06-06T05:00:00.000Z"
        });
        seed_mcp_agent_state(&state_dir, &agent);
        McpControlAgentStateUpdateRequest {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent_id: Some("agent_1".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            agent: Value::Null,
            control_kind: "mcp_add".to_string(),
            event_id: "event_mcp_add".to_string(),
            seq: 4,
            created_at: "2026-06-06T05:45:00.000Z".to_string(),
            request: json!({
                "server": {
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "transport": "stdio",
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-filesystem"],
                    "tools": [{ "name": "search" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                }
            }),
        }
    }

    fn mcp_server_validation_request() -> McpServerValidationRequest {
        McpServerValidationRequest {
            schema_version: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION.to_string(),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "transport": "stdio",
                    "command": "npx",
                    "allowed_tools": ["search"]
                }),
                json!({
                    "id": "mcp.remote",
                    "transport": "http",
                    "server_url": "https://mcp.example.test",
                    "allowed_tools": ["fetch"],
                    "containment": {
                        "allow_network_egress": true
                    }
                }),
            ],
        }
    }

    fn mcp_server_validation_input_request() -> McpServerValidationInputRequest {
        McpServerValidationInputRequest {
            schema_version: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: Some("/workspace".to_string()),
            input: json!({
                "mcp_json": {
                    "mcp_servers": {
                        "docs": {
                            "transport": "stdio",
                            "command": "npx",
                            "tools": {
                                "search": { "description": "Search docs" }
                            },
                            "sourcePath": "/retired/mcp.json",
                            "source_scope": "validation"
                        }
                    }
                },
                "mcpJson": {
                    "mcpServers": {
                        "retired": { "transport": "stdio", "command": "retired" }
                    }
                }
            }),
        }
    }

    fn thread_memory_agent_state_update_request() -> ThreadMemoryAgentStateUpdateRequest {
        ThreadMemoryAgentStateUpdateRequest {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            control_kind: "memory_status".to_string(),
            event_id: "event_memory_status".to_string(),
            seq: 6,
            created_at: "2026-06-06T06:05:00.000Z".to_string(),
        }
    }

    #[test]
    fn rust_policy_plans_mcp_control_agent_state_update() {
        let record = McpControlAgentStateUpdateCore
            .plan(&mcp_control_agent_state_update_request())
            .expect("mcp control agent state update");

        assert_eq!(
            record.schema_version,
            MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.mcp_add");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T05:45:00.000Z");
        assert_eq!(record.control["control_kind"], "mcp_add");
        assert_eq!(record.control["event_id"], "event_mcp_add");
        assert_eq!(record.control["server_id"], "mcp.docs");
        assert_eq!(record.control["server_count"], 1);
        assert_eq!(record.control["enabled_server_count"], 1);
        assert_eq!(record.control["mutation_applied"], true);
        assert!(record.control["registry_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert!(record.control.get("serverId").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(record.agent["mcpRegistry"]["servers"][0]["id"], "mcp.docs");
        assert_eq!(
            record.agent["mcpRegistry"]["servers"][0]["allowed_tools"][0]["name"],
            "search"
        );
    }

    #[test]
    fn rust_policy_applies_mcp_control_agent_state_update_registry_mutations() {
        let mut request = mcp_control_agent_state_update_request();
        request.request = json!({
            "server": {
                "id": "mcp.git",
                "label": "Git",
                "enabled": true,
                "transport": "stdio",
                "command": "npx",
                "tools": [{ "name": "diff" }]
            }
        });
        let record = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect("mcp add registry update");
        assert_eq!(record.control["server_id"], "mcp.git");
        assert_eq!(record.control["server_count"], 2);
        assert_eq!(record.control["mutation_applied"], true);
        assert_eq!(record.agent["mcpRegistry"]["servers"][1]["id"], "mcp.git");
        assert_eq!(
            record.agent["mcpRegistry"]["servers"][1]["allowed_tools"][0]["name"],
            "diff"
        );
        assert!(record.agent["mcpRegistry"]["servers"][1]
            .get("serverId")
            .is_none());

        let mut disable = mcp_control_agent_state_update_request();
        disable.control_kind = "mcp_disable".to_string();
        disable.event_id = "event_mcp_disable".to_string();
        disable.request = json!({ "server_id": "mcp.docs" });
        let disabled = McpControlAgentStateUpdateCore
            .plan(&disable)
            .expect("mcp disable registry update");
        assert_eq!(disabled.control["server_id"], "mcp.docs");
        assert_eq!(disabled.control["enabled_server_count"], 0);
        assert_eq!(
            disabled.agent["mcpRegistry"]["servers"][0]["enabled"],
            false
        );
        assert_eq!(
            disabled.agent["mcpRegistry"]["servers"][0]["status"],
            "disabled"
        );

        let mut remove = mcp_control_agent_state_update_request();
        remove.control_kind = "mcp_remove".to_string();
        remove.event_id = "event_mcp_remove".to_string();
        remove.request = json!({ "server_id": "mcp.docs" });
        let removed = McpControlAgentStateUpdateCore
            .plan(&remove)
            .expect("mcp remove registry update");
        assert_eq!(removed.control["server_id"], "mcp.docs");
        assert_eq!(removed.control["server_count"], 0);
        assert_eq!(
            removed.agent["mcpRegistry"]["servers"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn rust_policy_plans_mcp_live_transport_admission_controls() {
        let mut request = mcp_control_agent_state_update_request();
        request.control_kind = "mcp_invoke".to_string();
        request.event_id = "event_mcp_invoke".to_string();
        request.request = json!({
            "server_id": "mcp.docs",
            "tool_id": "mcp.docs.search",
            "tool_name": "search",
            "live_transport": "stdio",
            "execution_mode": "live",
            "timeout_ms": 2500,
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"],
            "custody_ref": "ctee://workspace/public",
            "containment_ref": "containment://mcp/docs",
            "serverId": "retired",
            "toolId": "retired"
        });

        let record = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect("mcp invoke transport admission");

        assert_eq!(record.operation_kind, "thread.mcp_invoke");
        assert_eq!(record.control["server_id"], "mcp.docs");
        assert_eq!(record.control["tool_id"], "mcp.docs.search");
        assert_eq!(record.control["tool_name"], "search");
        assert_eq!(record.control["live_transport"], "stdio");
        assert_eq!(record.control["execution_mode"], "live");
        assert_eq!(record.control["timeout_ms"], 2500);
        assert_eq!(record.control["transport_admission_required"], true);
        assert_eq!(record.control["wallet_authority_required"], true);
        assert_eq!(
            record.control["wallet_authority_boundary"],
            "wallet.network.mcp_external_exit"
        );
        assert_eq!(record.control["ctee_custody_required"], true);
        assert_eq!(record.control["transport_containment_required"], true);
        assert_eq!(
            record.control["authority_grant_refs"][0],
            "wallet.network://grant/mcp/docs/search"
        );
        assert_eq!(
            record.control["authority_receipt_refs"][0],
            "receipt://wallet.network/mcp/docs/search"
        );
        assert_eq!(record.control["custody_ref"], "ctee://workspace/public");
        assert_eq!(record.control["containment_ref"], "containment://mcp/docs");
        assert!(record.control["authority_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(record.control["evidence_refs"]
            .as_array()
            .is_some_and(|refs| refs
                .iter()
                .any(|value| value == "wallet_network_mcp_external_exit_authority_required")));
        assert!(record.control["evidence_refs"]
            .as_array()
            .is_some_and(|refs| refs
                .iter()
                .any(|value| value == "ctee_mcp_external_exit_custody_required")));
        assert!(record.control["evidence_refs"]
            .as_array()
            .is_some_and(|refs| refs
                .iter()
                .any(|value| value == "mcp_transport_containment_required")));
        assert_eq!(
            record.control["content_receipt_id"],
            "receipt_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(
            record.control["result_receipt_id"],
            "receipt_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(
            record.control["result_record_id"],
            "result_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(record.control["runtime_mcp_live_receipt_required"], true);
        assert_eq!(record.control["runtime_mcp_live_result_required"], true);
        assert_eq!(
            record.control["runtime_mcp_live_result_status"],
            "admitted_pending_rust_transport"
        );
        assert!(record.control["runtime_mcp_agent_state_root_before"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(record.control["runtime_mcp_agent_state_root_after"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert_eq!(
            record.control["runtime_mcp_agentgres_operation_ref"],
            "agentgres://runtime-state/agents/agent_1/operations/mcp_invoke/event_mcp_invoke"
        );
        assert!(record.control["runtime_mcp_resulting_head"]
            .as_str()
            .is_some_and(|head| {
                head.starts_with("agentgres://runtime-state/agents/agent_1/head/sha256_")
            }));
        let receipt = record.receipt.as_ref().expect("Rust live-exit receipt");
        assert_eq!(
            receipt["schema_version"],
            "ioi.runtime.mcp-live-exit-receipt.v1"
        );
        assert_eq!(
            receipt["id"],
            "receipt_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(receipt["kind"], "runtime_mcp_live_exit");
        assert_eq!(
            receipt["details"]["rust_daemon_core_receipt_author"],
            "runtime.mcp_control"
        );
        assert_eq!(
            receipt["details"]["runtime_mcp_agentgres_operation_ref"],
            record.control["runtime_mcp_agentgres_operation_ref"]
        );
        assert_eq!(
            receipt["details"]["runtime_mcp_agent_state_root_after"],
            record.control["runtime_mcp_agent_state_root_after"]
        );
        assert_eq!(receipt["details"]["result_materialized"], false);
        assert_eq!(receipt["details"]["js_transport_invocation"], false);
        assert_eq!(receipt["details"]["command_transport_fallback"], false);
        assert!(receipt["evidence_refs"].as_array().is_some_and(|refs| refs
            .iter()
            .any(|value| value == "agentgres_runtime_mcp_live_receipt_truth_required")));
        let result = record.result.as_ref().expect("Rust live-result record");
        assert_eq!(result["schema_version"], "ioi.runtime.mcp-live-result.v1");
        assert_eq!(
            result["id"],
            "result_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(result["kind"], "runtime_mcp_live_result");
        assert_eq!(result["status"], "admitted_pending_rust_transport");
        assert_eq!(result["receipt_id"], receipt["id"]);
        assert_eq!(
            result["details"]["rust_daemon_core_result_author"],
            "runtime.mcp_control"
        );
        assert_eq!(
            result["details"]["runtime_mcp_agentgres_operation_ref"],
            record.control["runtime_mcp_agentgres_operation_ref"]
        );
        assert_eq!(
            result["details"]["runtime_mcp_agent_state_root_after"],
            record.control["runtime_mcp_agent_state_root_after"]
        );
        assert_eq!(
            result["details"]["backend_materialization_status"],
            "pending_rust_transport_backend"
        );
        assert_eq!(result["details"]["result_materialized"], false);
        assert_eq!(result["details"]["js_transport_invocation"], false);
        assert_eq!(result["details"]["command_transport_fallback"], false);
        assert!(result["evidence_refs"].as_array().is_some_and(|refs| refs
            .iter()
            .any(|value| value == "agentgres_runtime_mcp_live_result_truth_required")));
        assert_eq!(
            record.agent["receipt_refs"][0],
            "receipt_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(
            record.agent["result_refs"][0],
            "result_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"
        );
        assert_eq!(record.control["mutation_applied"], false);
        assert!(record.control.get("toolId").is_none());
        assert_eq!(
            record.agent["mcpRegistry"]["servers"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        let mut discovery = mcp_control_agent_state_update_request();
        discovery.control_kind = "mcp_live_discovery".to_string();
        discovery.event_id = "event_mcp_live_discovery".to_string();
        discovery.request = json!({
            "server_id": "mcp.docs",
            "live_transport": "stdio",
            "execution_mode": "discovery",
            "timeout_ms": 1500,
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/discovery"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/discovery"],
            "custody_ref": "ctee://workspace/public",
            "containment_ref": "containment://mcp/docs/discovery"
        });

        let discovery_record = McpControlAgentStateUpdateCore
            .plan(&discovery)
            .expect("mcp live discovery admission");

        assert_eq!(discovery_record.operation_kind, "thread.mcp_live_discovery");
        assert_eq!(
            discovery_record.control["transport_admission_required"],
            true
        );
        assert_eq!(discovery_record.control["server_id"], "mcp.docs");
        assert_eq!(discovery_record.control["live_transport"], "stdio");
        assert_eq!(discovery_record.control["timeout_ms"], 1500);
        assert_eq!(
            discovery_record.control["authority_grant_refs"][0],
            "wallet.network://grant/mcp/docs/discovery"
        );
        assert_eq!(
            discovery_record.control["content_receipt_id"],
            "receipt_runtime_mcp_live_exit_agent_1_mcp_live_discovery_event_mcp_live_discovery"
        );
        assert_eq!(
            discovery_record.control["result_record_id"],
            "result_runtime_mcp_live_exit_agent_1_mcp_live_discovery_event_mcp_live_discovery"
        );
        assert!(discovery_record.receipt.is_some());
        assert!(discovery_record.result.is_some());
        assert_eq!(discovery_record.control["mutation_applied"], false);
    }

    #[test]
    fn rust_policy_rejects_mcp_live_transport_without_wallet_authority() {
        let mut request = mcp_control_agent_state_update_request();
        request.control_kind = "mcp_invoke".to_string();
        request.event_id = "event_mcp_invoke".to_string();
        request.request = json!({
            "server_id": "mcp.docs",
            "tool_id": "mcp.docs.search",
            "tool_name": "search",
            "live_transport": "stdio",
            "execution_mode": "live",
        });

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("MCP live transport exits require wallet authority");

        assert!(matches!(
            error,
            McpControlAgentStateUpdateError::WalletAuthorityRequired(
                "request.authority_grant_refs"
            )
        ));
    }

    #[test]
    fn rust_policy_rejects_mcp_live_transport_without_custody_or_containment() {
        let mut request = mcp_control_agent_state_update_request();
        request.control_kind = "mcp_invoke".to_string();
        request.event_id = "event_mcp_invoke".to_string();
        request.request = json!({
            "server_id": "mcp.docs",
            "tool_id": "mcp.docs.search",
            "tool_name": "search",
            "live_transport": "stdio",
            "execution_mode": "live",
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"]
        });

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("MCP live transport exits require cTEE custody");

        assert!(matches!(
            error,
            McpControlAgentStateUpdateError::MissingField("request.custody_ref")
        ));

        request.request = json!({
            "server_id": "mcp.docs",
            "tool_id": "mcp.docs.search",
            "tool_name": "search",
            "live_transport": "stdio",
            "execution_mode": "live",
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"],
            "custody_ref": "ctee://workspace/public"
        });

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("MCP live transport exits require containment");

        assert!(matches!(
            error,
            McpControlAgentStateUpdateError::MissingField("request.containment_ref")
        ));
    }

    #[test]
    fn rust_policy_ignores_retired_mcp_control_request_aliases() {
        let mut request = mcp_control_agent_state_update_request();
        request.request = json!({
            "server": {
                "id": "mcp.canonical",
                "label": "Canonical",
                "enabled": true,
                "transport": "stdio",
                "tools": [{ "name": "search" }],
                "serverId": "mcp.retired"
            },
            "serverId": "mcp.retired.root",
            "mcpServer": { "id": "mcp.retired.object" }
        });
        let record = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect("mcp add ignores aliases");

        assert_eq!(record.control["server_id"], "mcp.canonical");
        assert!(record.control.get("serverId").is_none());
        assert_eq!(
            record.agent["mcpRegistry"]["servers"][1]["id"],
            "mcp.canonical"
        );
        assert!(record.agent["mcpRegistry"]["servers"][1]
            .get("serverId")
            .is_none());
        assert!(record.agent["mcpRegistry"].get("mcpServers").is_none());
    }

    #[test]
    fn rust_policy_rejects_mcp_control_agent_candidate_transport() {
        let mut request = mcp_control_agent_state_update_request();
        request.agent = json!({ "id": "agent_1", "mcpRegistry": { "servers": [] } });

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("JS agent candidate transport must be rejected");

        assert_eq!(
            error,
            McpControlAgentStateUpdateError::AgentCandidateTransportRetired
        );
    }

    #[test]
    fn rust_policy_requires_mcp_control_agentgres_replay_state_dir() {
        let mut request = mcp_control_agent_state_update_request();
        request.state_dir = None;

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("state_dir is required for Agentgres agent replay");

        assert_eq!(error, McpControlAgentStateUpdateError::StateDirRequired);
    }

    #[test]
    fn rust_policy_replays_runtime_mcp_live_results_from_agentgres_state() {
        let mut control_request = mcp_control_agent_state_update_request();
        control_request.control_kind = "mcp_invoke".to_string();
        control_request.event_id = "event_mcp_invoke".to_string();
        control_request.request = json!({
            "server_id": "mcp.docs",
            "tool_id": "mcp.docs.search",
            "tool_name": "search",
            "live_transport": "stdio",
            "execution_mode": "live",
            "timeout_ms": 2500,
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"],
            "custody_ref": "ctee://workspace/public",
            "containment_ref": "containment://mcp/docs/search"
        });
        let record = McpControlAgentStateUpdateCore
            .plan(&control_request)
            .expect("mcp live result record");
        let result = record.result.as_ref().expect("live result");
        let receipt = record.receipt.as_ref().expect("live receipt");
        let state_dir = PathBuf::from(control_request.state_dir.as_ref().expect("state dir"));
        seed_mcp_live_result_state(&state_dir, result);

        let replay = McpLiveResultReplayCore
            .project(&McpLiveResultReplayRequest {
                schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION.to_string(),
                state_dir: control_request.state_dir.clone(),
                result_id: optional_json_string(result, "id"),
                receipt_id: optional_json_string(receipt, "id"),
                thread_id: Some("thread_1".to_string()),
                agent_id: Some("agent_1".to_string()),
                control_kind: Some("mcp_invoke".to_string()),
            })
            .expect("Rust MCP live-result replay projection");

        assert_eq!(
            replay.schema_version,
            MCP_LIVE_RESULT_REPLAY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(replay.object, "ioi.runtime_mcp_live_result_replay");
        assert_eq!(replay.status, "projected");
        assert_eq!(replay.result_count, 1);
        assert_eq!(
            replay.result_ids,
            vec!["result_runtime_mcp_live_exit_agent_1_mcp_invoke_event_mcp_invoke"]
        );
        assert_eq!(replay.latest_result.as_ref(), Some(result));
        assert!(replay.replay_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_policy_rejects_mcp_live_result_replay_without_state_dir() {
        let error = McpLiveResultReplayCore
            .project(&McpLiveResultReplayRequest {
                schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION.to_string(),
                state_dir: None,
                result_id: Some("result_runtime_mcp_live_exit".to_string()),
                receipt_id: None,
                thread_id: None,
                agent_id: None,
                control_kind: None,
            })
            .expect_err("state dir is required for MCP live-result replay");

        assert_eq!(error, McpLiveResultReplayError::StateDirRequired);
    }

    #[test]
    fn rust_policy_filters_js_authored_mcp_live_result_candidates() {
        let state_dir = temp_mcp_state_dir("live-result-replay-filter");
        seed_mcp_live_result_state(
            &state_dir,
            &json!({
                "schema_version": "ioi.runtime.mcp-live-result.v1",
                "object": "ioi.runtime_mcp_live_result",
                "id": "result_runtime_mcp_live_exit",
                "kind": "runtime_mcp_live_result",
                "status": "admitted_pending_rust_transport",
                "created_at": "2026-06-06T05:45:00.000Z",
                "receipt_id": "receipt_runtime_mcp_live_exit",
                "receipt_refs": ["receipt_runtime_mcp_live_exit"],
                "evidence_refs": [
                    "runtime_mcp_live_result_rust_projection",
                    "agentgres_runtime_mcp_live_result_truth_required"
                ],
                "details": {
                    "rust_daemon_core_result_author": "js_mcp_control",
                    "thread_id": "thread_1",
                    "agent_id": "agent_1",
                    "control_kind": "mcp_invoke",
                    "js_transport_invocation": true,
                    "command_transport_fallback": true
                }
            }),
        );

        let error = McpLiveResultReplayCore
            .project(&McpLiveResultReplayRequest {
                schema_version: MCP_LIVE_RESULT_REPLAY_REQUEST_SCHEMA_VERSION.to_string(),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                result_id: Some("result_runtime_mcp_live_exit".to_string()),
                receipt_id: Some("receipt_runtime_mcp_live_exit".to_string()),
                thread_id: Some("thread_1".to_string()),
                agent_id: Some("agent_1".to_string()),
                control_kind: Some("mcp_invoke".to_string()),
            })
            .expect_err("JS-authored candidate must not replay");

        assert_eq!(
            error,
            McpLiveResultReplayError::ResultReplayRequired(
                "result_runtime_mcp_live_exit".to_string()
            )
        );
    }

    fn mcp_tool_search_projection_request() -> McpToolSearchProjectionRequest {
        McpToolSearchProjectionRequest {
            schema_version: MCP_TOOL_SEARCH_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            state_dir: None,
            thread_id: None,
            agent_id: None,
            server_id: None,
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "allowed_tools": [
                        { "name": "search", "description": "Search docs" },
                        { "name": "read", "description": "Read docs" }
                    ],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                }),
                json!({
                    "id": "mcp.git",
                    "label": "Git",
                    "enabled": false,
                    "allowed_tools": [{ "name": "diff" }]
                }),
            ],
            query: Some("search".to_string()),
            tool_id: None,
            exact: Some(false),
            limit: Some(25),
            preview_limit: Some(2),
            live_discovery: Some(true),
        }
    }

    #[test]
    fn rust_policy_projects_mcp_tool_search_without_js_filtering() {
        let projection = McpToolSearchProjectionCore
            .project(&mcp_tool_search_projection_request())
            .expect("MCP tool search projection");

        assert_eq!(
            projection.schema_version,
            MCP_TOOL_SEARCH_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(projection.object, "ioi.runtime_mcp_tool_search");
        assert_eq!(projection.status, "completed");
        assert_eq!(projection.query, "search");
        assert_eq!(projection.server_count, 2);
        assert_eq!(projection.tool_count, 1);
        assert_eq!(projection.returned_count, 1);
        assert_eq!(projection.tools[0]["tool_name"], "search");
        assert_eq!(projection.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert!(projection.rust_mcp_live_discovery_deferred);
        assert!(projection
            .catalog_summaries
            .iter()
            .any(|summary| summary["execution_mode"] == "rust_mcp_live_discovery_deferred"));
        assert!(projection
            .evidence_refs
            .contains(&"runtime_mcp_catalog_js_search_filter_retired".to_string()));
        assert_eq!(projection.routes["get_tool"], "/v1/mcp/tools/{tool_id}");
    }

    #[test]
    fn rust_policy_projects_mcp_tool_fetch_and_not_found_status() {
        let mut request = McpToolFetchProjectionRequest {
            schema_version: MCP_TOOL_FETCH_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            state_dir: None,
            thread_id: None,
            agent_id: None,
            server_id: Some("mcp.docs".to_string()),
            servers: mcp_tool_search_projection_request().servers,
            tool_id: Some("mcp.docs.search".to_string()),
            limit: Some(25),
            preview_limit: Some(2),
            live_discovery: Some(false),
        };

        let projection = McpToolFetchProjectionCore
            .project(&request)
            .expect("MCP tool fetch projection");

        assert_eq!(
            projection.schema_version,
            MCP_TOOL_FETCH_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(projection.object, "ioi.runtime_mcp_tool_fetch");
        assert_eq!(projection.status, "completed");
        assert_eq!(projection.tool_id.as_deref(), Some("mcp.docs.search"));
        assert_eq!(projection.server_id.as_deref(), Some("mcp.docs"));
        assert_eq!(projection.tool_name.as_deref(), Some("search"));
        assert_eq!(projection.returned_count, 1);
        assert!(projection
            .evidence_refs
            .contains(&"runtime_mcp_catalog_fetch_js_shape_retired".to_string()));

        request.tool_id = Some("mcp.docs.missing".to_string());
        let missing = McpToolFetchProjectionCore
            .project(&request)
            .expect("MCP missing tool fetch projection");
        assert_eq!(missing.status, "not_found");
        assert_eq!(missing.returned_count, 0);
        assert!(missing.tool.is_none());
    }

    #[test]
    fn rust_policy_validates_mcp_servers() {
        let record = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation");
        assert_eq!(record.status, "pass");
        assert!(record.ok);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert!(record.issues.is_empty());
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn rust_policy_projects_mcp_server_validation_input() {
        let record = McpServerValidationInputCore
            .project(&mcp_server_validation_input_request())
            .expect("mcp server validation input");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation_input");
        assert_eq!(record.status, "projected");
        assert_eq!(record.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(record.server_count, 1);
        assert_eq!(record.servers[0]["id"], "mcp.docs");
        assert_eq!(record.servers[0]["label"], "docs");
        assert_eq!(record.servers[0]["workspace_root"], "/workspace");
        assert_eq!(record.servers[0]["source_scope"], "validation");
        assert_eq!(record.servers[0]["tool_count"], 1);
        assert_eq!(record.servers[0]["allowed_tools"][0], "search");
        assert!(record.servers[0].get("sourcePath").is_none());
        assert!(record.servers[0].get("sourceScope").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_config_source_metadata() {
        let record = McpServerValidationInputCore
            .project(&McpServerValidationInputRequest {
                schema_version: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION.to_string(),
                workspace_root: Some("/workspace".to_string()),
                input: json!({
                    "mcp_json": {
                        "mcp_servers": {
                            "docs": {
                                "transport": "stdio",
                                "command": "npx",
                                "allowed_tools": ["search"],
                                "sourcePath": "/retired/mcp.json",
                                "sourceScope": "retired",
                                "configCompatibility": "retired"
                            }
                        }
                    },
                    "source": ".cursor/mcp.json",
                    "source_path": "/workspace/.cursor/mcp.json",
                    "source_scope": "workspace",
                    "config_compatibility": "cursor",
                    "status": "configured"
                }),
            })
            .expect("mcp config source metadata projection");

        assert_eq!(record.server_count, 1);
        assert_eq!(record.servers[0]["source"], ".cursor/mcp.json");
        assert_eq!(
            record.servers[0]["source_path"],
            "/workspace/.cursor/mcp.json"
        );
        assert_eq!(record.servers[0]["source_scope"], "workspace");
        assert_eq!(record.servers[0]["config_compatibility"], "cursor");
        assert!(record.servers[0].get("sourcePath").is_none());
        assert!(record.servers[0].get("sourceScope").is_none());
        assert!(record.servers[0].get("configCompatibility").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_status() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let request = McpManagerStatusProjectionRequest {
            schema_version: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some("ioi.runtime.mcp-manager-status.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "enabled": true,
                }),
                json!({
                    "id": "mcp.disabled",
                    "enabled": false,
                }),
            ],
            tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            resources: vec![json!({ "uri": "mcp.docs://root" })],
            prompts: vec![json!({ "name": "ask" })],
            enabled_tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            routes: json!({
                "search_tools": "/v1/mcp/tools/search",
            }),
        };

        let record = McpManagerStatusProjectionCore
            .project(&request)
            .expect("mcp manager status projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.enabled_server_count, 1);
        assert_eq!(record.enabled_tool_count, Some(1));
        assert_eq!(record.validation["server_count"], 2);
        assert_eq!(
            record.validation["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(record.routes["search_tools"], "/v1/mcp/tools/search");
        assert!(record.validation.get("serverCount").is_none());
        assert!(record.routes.get("searchTools").is_none());
    }

    #[test]
    fn rust_policy_projects_memory_manager_validation() {
        let request = MemoryManagerValidationProjectionRequest {
            schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "readOnly": true
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "recordsPath": "/retired/memory"
                },
                "filters": {
                    "scope": "thread"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memory_key": "project",
                    "redaction": "redacted"
                }]
            }),
        };

        let record = MemoryManagerValidationProjectionCore
            .project(&request)
            .expect("memory manager validation projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.warning_count, 3);
        assert!(record
            .warnings
            .iter()
            .any(|warning| warning["code"] == "memory_record_redacted_hash_missing"));
        assert!(record.policy.get("readOnly").is_some());
        assert_eq!(record.policy["read_only"], false);
        assert_eq!(record.paths["records_path"], "/state/memory");
    }

    #[test]
    fn rust_policy_shapes_memory_manager_validation_command_response() {
        let response = plan_memory_manager_validation_projection_response(
            MemoryManagerValidationProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: MemoryManagerValidationProjectionRequest {
                    schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    validation_schema_version: Some(
                        MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    projection: json!({
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread"
                        },
                        "paths": {},
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread"
                        }]
                    }),
                },
            },
        )
        .expect("memory manager validation command response");

        assert_eq!(
            response["source"],
            "rust_memory_manager_validation_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["ok"], false);
        assert_eq!(response["issue_count"], 2);
        assert_eq!(response["issues"][0]["code"], "memory_records_path_missing");
        assert_eq!(
            response["issues"][1]["code"],
            "memory_policies_path_missing"
        );
        assert!(response.get("issueCount").is_none());
        assert!(response.get("recordCount").is_none());
    }

    #[test]
    fn rust_policy_projects_memory_manager_status() {
        let request = MemoryManagerStatusProjectionRequest {
            schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some(
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "writeRequiresApproval": false
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "effective_policy_id": "policy.thread",
                    "effectivePolicyId": "policy.retired"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memoryKey": "retired.project",
                    "memory_key": "project"
                }]
            }),
        };

        let record = MemoryManagerStatusProjectionCore
            .project(&request)
            .expect("memory manager status projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.scope_count, 1);
        assert_eq!(record.memory_key_count, 1);
        assert_eq!(record.memory_keys, vec!["project".to_string()]);
        assert_eq!(record.write_requires_approval, true);
        assert_eq!(
            record.write_blocked_reason.as_deref(),
            Some("memory_write_requires_approval")
        );
        assert_eq!(
            record.validation["object"],
            "ioi.runtime_memory_manager_validation"
        );
        assert_eq!(
            record.routes["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(record.evidence_refs.contains(&"policy.thread".to_string()));
        assert!(!record.evidence_refs.contains(&"policy.retired".to_string()));
        assert!(record.evidence_refs.contains(&"memory.one".to_string()));
    }

    #[test]
    fn rust_policy_shapes_memory_manager_status_command_response() {
        let response = plan_memory_manager_status_projection_response(
            MemoryManagerStatusProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: MemoryManagerStatusProjectionRequest {
                    schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: Some(
                        MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    validation_schema_version: Some(
                        MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
                    ),
                    projection: json!({
                        "policy": {
                            "id": "policy.thread",
                            "scope": "thread",
                            "injection_enabled": true,
                            "read_only": false,
                            "write_requires_approval": true,
                            "writeRequiresApproval": false
                        },
                        "paths": {
                            "records_path": "/state/memory",
                            "policies_path": "/state/policies"
                        },
                        "records": [{
                            "id": "memory.one",
                            "fact": "Remember the runtime boundary.",
                            "scope": "thread",
                            "memoryKey": "retired.project",
                            "memory_key": "project"
                        }]
                    }),
                },
            },
        )
        .expect("memory manager status command response");

        assert_eq!(
            response["source"],
            "rust_memory_manager_status_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "ready");
        assert_eq!(response["record_count"], 1);
        assert_eq!(response["memory_key_count"], 1);
        assert_eq!(response["memory_keys"][0], "project");
        assert_eq!(response["write_requires_approval"], true);
        assert_eq!(
            response["write_blocked_reason"],
            "memory_write_requires_approval"
        );
        assert_eq!(
            response["routes"]["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(response.get("memoryKeys").is_none());
        assert!(response.get("writeRequiresApproval").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_rows() {
        let request = McpManagerCatalogProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            state_dir: None,
            thread_id: None,
            agent_id: None,
            agent: Value::Null,
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "transport": "stdio",
                    "allowed_tools": [
                        {
                            "name": "search",
                            "description": "Search docs",
                            "input_schema": { "type": "object" }
                        }
                    ],
                    "resources": [
                        {
                            "uri": "docs://index",
                            "name": "index",
                            "mime_type": "text/plain"
                        }
                    ],
                    "prompts": [
                        {
                            "name": "summarize",
                            "arguments": [{ "name": "topic" }]
                        }
                    ]
                }),
                json!({
                    "id": "mcp.disabled",
                    "label": "Disabled",
                    "enabled": false,
                    "allowed_tools": ["noop"]
                }),
            ],
        };

        let record = McpManagerCatalogProjectionCore
            .project(&request)
            .expect("mcp manager catalog projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_catalog_projection");
        assert_eq!(record.status, "projected");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 2);
        assert_eq!(record.enabled_tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(record.tools[1]["status"], "disabled");
        assert_eq!(
            record.resources[0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            record.prompts[0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(record.tools[0].get("stableToolId").is_none());
        assert!(record.resources[0].get("stableResourceId").is_none());
        assert!(record.prompts[0].get("stablePromptId").is_none());
    }

    #[test]
    fn rust_policy_replays_mcp_manager_catalog_from_agentgres_state() {
        let state_dir = temp_mcp_state_dir("catalog-replay");
        seed_mcp_agent_state(
            &state_dir,
            &json!({
                "id": "agent_1",
                "thread_id": "thread_1",
                "mcpRegistry": {
                    "servers": [{
                        "id": "mcp.agent.docs",
                        "label": "Agent Docs",
                        "source_scope": "thread",
                        "enabled": true,
                        "allowed_tools": [{ "name": "diff" }],
                        "resources": [{ "uri": "agent://docs" }],
                        "prompts": [{ "name": "agent_prompt" }]
                    }]
                }
            }),
        );
        seed_mcp_agent_state(
            &state_dir,
            &json!({
                "id": "agent_2",
                "thread_id": "thread_2",
                "mcpRegistry": {
                    "servers": [{
                        "id": "mcp.other",
                        "label": "Other",
                        "enabled": true,
                        "allowed_tools": [{ "name": "other" }]
                    }]
                }
            }),
        );

        let record = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                thread_id: Some("thread_1".to_string()),
                agent_id: None,
                agent: Value::Null,
                servers: vec![json!({
                    "id": "mcp.workspace",
                    "label": "Workspace",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search" }]
                })],
            })
            .expect("mcp manager catalog Agentgres replay");

        assert_eq!(record.server_count, 2);
        assert_eq!(record.servers[0]["id"], "mcp.workspace");
        assert_eq!(record.servers[1]["id"], "mcp.agent.docs");
        assert_eq!(record.tool_count, 2);
        assert_eq!(record.tools[1]["server_id"], "mcp.agent.docs");
        assert_eq!(record.tools[1]["tool_name"], "diff");
        assert_eq!(record.resources[0]["server_id"], "mcp.agent.docs");
        assert_eq!(record.prompts[0]["server_id"], "mcp.agent.docs");
        assert!(record
            .servers
            .iter()
            .all(|server| server["id"] != "mcp.other"));

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn rust_policy_rejects_mcp_manager_catalog_agent_candidate_transport() {
        let request = McpManagerCatalogProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            state_dir: Some("/runtime-state".to_string()),
            thread_id: Some("thread_1".to_string()),
            agent_id: None,
            agent: json!({ "id": "agent_1", "mcpRegistry": { "servers": [] } }),
            servers: vec![],
        };

        let error = McpManagerCatalogProjectionCore
            .project(&request)
            .expect_err("JS agent candidate transport must be rejected");

        assert_eq!(
            error,
            McpManagerCatalogProjectionError::AgentCandidateTransportRetired
        );
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_summary() {
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                state_dir: None,
                thread_id: None,
                agent_id: None,
                agent: Value::Null,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "transport": "stdio",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search.index" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerCatalogSummaryProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION
                .to_string(),
            status_schema_version: None,
            server: catalog.servers[0].clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
            live_mode: Some("declared_catalog".to_string()),
            status: None,
            error_code: None,
            preview_limit: Some(25),
            deferred: Some(false),
        };

        let record = McpManagerCatalogSummaryProjectionCore
            .project(&request)
            .expect("mcp catalog summary projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_catalog_summary");
        assert_eq!(record.status, "completed");
        assert_eq!(record.server_id.as_deref(), Some("mcp.docs"));
        assert_eq!(record.server_label.as_deref(), Some("Docs"));
        assert_eq!(record.execution_mode.as_deref(), Some("declared_catalog"));
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.namespace_count, 1);
        assert_eq!(record.namespaces[0], "search");
        assert_eq!(record.preview_tool_names[0], "search.index");
        assert_eq!(record.search_route, "/v1/mcp/tools/search");
        assert_eq!(record.fetch_route, "/v1/mcp/tools/{tool_id}");
        assert!(!record.catalog_hash.is_empty());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_validation_envelope() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                state_dir: None,
                thread_id: None,
                agent_id: None,
                agent: Value::Null,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerValidationProjectionRequest {
            schema_version: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some("ioi.runtime.mcp-manager-validation.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: catalog.servers.clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
        };

        let record = McpManagerValidationProjectionCore
            .project(&request)
            .expect("mcp validation projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.server_count, 1);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert!(record.tools[0].get("stableToolId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_records() {
        let mut request = mcp_server_validation_request();
        request.servers = vec![
            json!({
                "id": "mcp.bad-stdio",
                "transport": "stdio",
                "allowed_tools": []
            }),
            json!({
                "id": "mcp.remote",
                "transport": "http",
                "server_url": "file:///tmp/socket",
                "allowed_tools": ["fetch"],
                "containment": {
                    "allow_network_egress": false
                }
            }),
            json!({
                "id": "mcp.secret",
                "transport": "stdio",
                "command": "npx",
                "allowed_tools": ["secret"],
                "secret_refs": {
                    "Authorization": { "invalidVaultRef": true }
                },
                "secretRefs": {
                    "Authorization": { "invalidVaultRef": false }
                }
            }),
        ];

        let record = McpServerValidationCore
            .validate(&request)
            .expect("mcp server validation");

        assert_eq!(record.status, "blocked");
        assert!(!record.ok);
        assert_eq!(record.issue_count, 4);
        assert_eq!(record.warning_count, 1);
        let codes = record
            .issues
            .iter()
            .filter_map(|issue| issue["code"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "mcp_server_transport_missing",
                "mcp_remote_url_invalid",
                "mcp_remote_network_blocked",
                "mcp_secret_not_vault_ref",
            ]
        );
        assert_eq!(record.issues[3]["server_id"], "mcp.secret");
        assert_eq!(record.issues[3]["key"], "Authorization");
        assert!(record.issues[3].get("serverId").is_none());
        assert_eq!(record.warnings[0]["code"], "mcp_allowed_tools_empty");
        assert!(record.warnings[0].get("serverId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_validation_schema() {
        let mut request = mcp_server_validation_request();
        request.schema_version = "legacy.mcp-validation".to_string();

        let error = McpServerValidationCore
            .validate(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-validation".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_plans_thread_memory_agent_state_update() {
        let record = ThreadMemoryAgentStateUpdateCore
            .plan(&thread_memory_agent_state_update_request())
            .expect("thread memory agent state update");

        assert_eq!(
            record.schema_version,
            THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.memory_status");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:05:00.000Z");
        assert_eq!(record.control["control_kind"], "memory_status");
        assert_eq!(record.control["event_id"], "event_memory_status");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn rust_policy_shapes_thread_memory_agent_state_update_command_response() {
        let response = plan_thread_memory_agent_state_update_response(
            ThreadMemoryAgentStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: thread_memory_agent_state_update_request(),
            },
        )
        .expect("thread memory agent state update command response");

        assert_eq!(
            response["source"],
            "rust_thread_memory_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.memory_status");
        assert_eq!(response["control"]["control_kind"], "memory_status");
        assert_eq!(response["control"]["event_id"], "event_memory_status");
        assert!(response["control"].get("controlKind").is_none());
        assert!(response["control"].get("eventId").is_none());
        assert!(response["control"].get("createdAt").is_none());
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_control_agent_state_update_schema() {
        let mut request = mcp_control_agent_state_update_request();
        request.schema_version = "legacy.mcp-control-state-update".to_string();

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-control-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_memory_agent_state_update_schema() {
        let mut request = thread_memory_agent_state_update_request();
        request.schema_version = "legacy.thread-memory-state-update".to_string();

        let error = ThreadMemoryAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.thread-memory-state-update".to_string(),
            }
        );
    }
}
