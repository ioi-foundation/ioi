use super::RuntimeAgentService;
use ioi_types::app::WorkloadSpec;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

pub const RUNTIME_MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-live-backend-execution-request.v1";
pub const RUNTIME_MCP_LIVE_BACKEND_EXECUTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-live-backend-execution.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMcpLiveBackendExecutionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub control_kind: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_ref: Option<String>,
    #[serde(default)]
    pub live_transport: Option<String>,
    #[serde(default)]
    pub execution_mode: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub arguments: Value,
    #[serde(default)]
    pub workload_spec: Option<WorkloadSpec>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub custody_ref: Option<String>,
    #[serde(default)]
    pub containment_ref: Option<String>,
    #[serde(default)]
    pub backend_execution: Value,
    #[serde(default)]
    pub receipt: Value,
    #[serde(default)]
    pub control: Value,
    #[serde(default)]
    pub planned_result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMcpLiveBackendExecutionRecord {
    pub source: String,
    pub backend: String,
    pub schema_version: String,
    pub object: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_ref: Option<String>,
    pub backend_execution: Value,
    pub driver_result: Value,
    pub driver_result_hash: String,
    pub result: Value,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMcpLiveBackendExecutionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    BackendContractInvalid(&'static str),
    UnsupportedMethod(String),
    McpManagerRequired,
    WorkloadSpecRequired,
    DriverExecutionFailed(String),
}

impl fmt::Display for RuntimeMcpLiveBackendExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaVersion { expected, actual } => write!(
                formatter,
                "runtime MCP live backend execution expected schema_version {expected}, got {actual}"
            ),
            Self::MissingField(field) => {
                write!(formatter, "runtime MCP live backend execution missing {field}")
            }
            Self::BackendContractInvalid(field) => {
                write!(
                    formatter,
                    "runtime MCP live backend execution backend contract invalid: {field}"
                )
            }
            Self::UnsupportedMethod(method) => write!(
                formatter,
                "runtime MCP live backend execution unsupported method {method}"
            ),
            Self::McpManagerRequired => write!(
                formatter,
                "runtime MCP live backend execution requires RuntimeAgentService.mcp"
            ),
            Self::WorkloadSpecRequired => write!(
                formatter,
                "runtime MCP live backend execution tools/call requires workload_spec"
            ),
            Self::DriverExecutionFailed(message) => {
                write!(formatter, "runtime MCP live backend driver failed: {message}")
            }
        }
    }
}

impl Error for RuntimeMcpLiveBackendExecutionError {}

impl RuntimeAgentService {
    pub async fn execute_runtime_mcp_live_backend(
        &self,
        request: &RuntimeMcpLiveBackendExecutionRequest,
    ) -> Result<RuntimeMcpLiveBackendExecutionRecord, RuntimeMcpLiveBackendExecutionError> {
        request.validate()?;
        let mcp = self
            .mcp
            .as_ref()
            .ok_or(RuntimeMcpLiveBackendExecutionError::McpManagerRequired)?;
        let method = request.backend_method()?;
        let driver_result = match method.as_str() {
            "tools/call" => {
                let tool_ref = request.resolved_tool_ref()?;
                let workload_spec = request
                    .workload_spec
                    .as_ref()
                    .ok_or(RuntimeMcpLiveBackendExecutionError::WorkloadSpecRequired)?;
                let execution = mcp
                    .execute_tool_with_result(
                        &tool_ref,
                        request.arguments.clone(),
                        Some(workload_spec),
                    )
                    .await
                    .map_err(|error| {
                        RuntimeMcpLiveBackendExecutionError::DriverExecutionFailed(
                            error.to_string(),
                        )
                    })?;
                json!({
                    "schema_version": "ioi.runtime.mcp-live-driver-result.v1",
                    "object": "ioi.runtime_mcp_live_driver_result",
                    "status": "rust_driver_executed",
                    "method": "tools/call",
                    "server_id": request.server_id.as_deref(),
                    "server_name": execution.server_name,
                    "tool_ref": tool_ref,
                    "result": execution.result,
                    "driver_owner": "ioi_drivers::mcp::McpManager",
                    "transport_owner": "ioi_drivers::mcp::transport::McpTransport",
                    "js_backend_execution": false,
                    "command_transport_fallback": false,
                    "binary_bridge_fallback": false,
                    "compatibility_fallback": false
                })
            }
            "tools/list" => {
                let server_id = request.server_id.as_deref().and_then(trimmed).ok_or(
                    RuntimeMcpLiveBackendExecutionError::MissingField("server_id"),
                )?;
                let tools = mcp
                    .list_admitted_tools_for_server(&server_id)
                    .await
                    .map_err(|error| {
                        RuntimeMcpLiveBackendExecutionError::DriverExecutionFailed(
                            error.to_string(),
                        )
                    })?;
                json!({
                    "schema_version": "ioi.runtime.mcp-live-driver-result.v1",
                    "object": "ioi.runtime_mcp_live_driver_result",
                    "status": "rust_driver_executed",
                    "method": "tools/list",
                    "server_id": server_id,
                    "tool_count": tools.len(),
                    "tools": tools,
                    "driver_owner": "ioi_drivers::mcp::McpManager",
                    "transport_owner": "ioi_drivers::mcp::transport::McpTransport",
                    "js_backend_execution": false,
                    "command_transport_fallback": false,
                    "binary_bridge_fallback": false,
                    "compatibility_fallback": false
                })
            }
            other => {
                return Err(RuntimeMcpLiveBackendExecutionError::UnsupportedMethod(
                    other.to_string(),
                ))
            }
        };
        Ok(build_execution_record(request, method, driver_result))
    }
}

impl RuntimeMcpLiveBackendExecutionRequest {
    fn validate(&self) -> Result<(), RuntimeMcpLiveBackendExecutionError> {
        if self.schema_version != RUNTIME_MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeMcpLiveBackendExecutionError::InvalidSchemaVersion {
                expected: RUNTIME_MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_option(self.thread_id.as_deref(), "thread_id")?;
        require_option(self.agent_id.as_deref(), "agent_id")?;
        require_option(self.control_kind.as_deref(), "control_kind")?;
        require_option(self.event_id.as_deref(), "event_id")?;
        require_option(self.custody_ref.as_deref(), "custody_ref")?;
        require_option(self.containment_ref.as_deref(), "containment_ref")?;
        if self.authority_grant_refs.is_empty() {
            return Err(RuntimeMcpLiveBackendExecutionError::MissingField(
                "authority_grant_refs",
            ));
        }
        if self.authority_receipt_refs.is_empty() {
            return Err(RuntimeMcpLiveBackendExecutionError::MissingField(
                "authority_receipt_refs",
            ));
        }
        if !self.planned_result.is_object() {
            return Err(RuntimeMcpLiveBackendExecutionError::MissingField(
                "planned_result",
            ));
        }
        self.validate_backend_contract()
    }

    fn validate_backend_contract(&self) -> Result<(), RuntimeMcpLiveBackendExecutionError> {
        if !self.backend_execution.is_object() {
            return Err(RuntimeMcpLiveBackendExecutionError::MissingField(
                "backend_execution",
            ));
        }
        for (key, expected) in [
            ("schema_version", "ioi.runtime.mcp-backend-execution.v1"),
            ("status", "rust_driver_contract_bound"),
            ("owner", "ioi_drivers::mcp::McpManager"),
            (
                "transport_owner",
                "ioi_drivers::mcp::transport::McpTransport",
            ),
        ] {
            if json_string(&self.backend_execution, key).as_deref() != Some(expected) {
                return Err(RuntimeMcpLiveBackendExecutionError::BackendContractInvalid(
                    key,
                ));
            }
        }
        for key in [
            "js_backend_execution",
            "command_transport_fallback",
            "binary_bridge_fallback",
            "compatibility_fallback",
        ] {
            if json_bool(&self.backend_execution, key) != Some(false) {
                return Err(RuntimeMcpLiveBackendExecutionError::BackendContractInvalid(
                    key,
                ));
            }
        }
        self.backend_method().map(|_| ())
    }

    fn backend_method(&self) -> Result<String, RuntimeMcpLiveBackendExecutionError> {
        json_string(&self.backend_execution, "method")
            .and_then(|value| trimmed(&value))
            .ok_or(RuntimeMcpLiveBackendExecutionError::BackendContractInvalid(
                "method",
            ))
    }

    fn resolved_tool_ref(&self) -> Result<String, RuntimeMcpLiveBackendExecutionError> {
        for candidate in [
            self.tool_ref.as_deref(),
            self.tool_name.as_deref(),
            self.tool_id.as_deref(),
        ] {
            if let Some(value) = candidate.and_then(trimmed) {
                if value.contains("__") {
                    return Ok(value);
                }
            }
        }
        let server_id = self.server_id.as_deref().and_then(trimmed).ok_or(
            RuntimeMcpLiveBackendExecutionError::MissingField("server_id"),
        )?;
        let tool = self
            .tool_name
            .as_deref()
            .or(self.tool_id.as_deref())
            .and_then(trimmed)
            .ok_or(RuntimeMcpLiveBackendExecutionError::MissingField(
                "tool_ref",
            ))?;
        let raw_tool = tool
            .strip_prefix(&format!("{server_id}."))
            .or_else(|| tool.strip_prefix(&format!("{server_id}/")))
            .unwrap_or(&tool);
        Ok(format!("{server_id}__{raw_tool}"))
    }
}

fn build_execution_record(
    request: &RuntimeMcpLiveBackendExecutionRequest,
    method: String,
    driver_result: Value,
) -> RuntimeMcpLiveBackendExecutionRecord {
    let driver_result_hash = hash_json(&driver_result);
    let mut backend_execution = request.backend_execution.clone();
    if let Some(object) = backend_execution.as_object_mut() {
        object.insert(
            "status".to_string(),
            Value::String("rust_driver_executed".to_string()),
        );
        object.insert(
            "driver_result_hash".to_string(),
            Value::String(driver_result_hash.clone()),
        );
    }
    RuntimeMcpLiveBackendExecutionRecord {
        source: "rust_mcp_live_backend_execution_api".to_string(),
        backend: "rust_mcp_live_backend".to_string(),
        schema_version: RUNTIME_MCP_LIVE_BACKEND_EXECUTION_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.runtime_mcp_live_backend_execution".to_string(),
        status: "rust_driver_executed".to_string(),
        control_kind: request.control_kind.clone(),
        event_id: request.event_id.clone(),
        thread_id: request.thread_id.clone(),
        agent_id: request.agent_id.clone(),
        server_id: request.server_id.clone(),
        tool_ref: if method == "tools/call" {
            request.resolved_tool_ref().ok()
        } else {
            request.tool_ref.clone()
        },
        backend_execution,
        driver_result: driver_result.clone(),
        driver_result_hash: driver_result_hash.clone(),
        result: bind_planned_result_to_driver_execution(
            &request.planned_result,
            &driver_result_hash,
            &driver_result,
        ),
        evidence_refs: vec![
            "runtime_mcp_live_backend_rust_driver_executed".to_string(),
            "runtime_mcp_live_backend_actual_mcp_manager_io".to_string(),
            "runtime_mcp_live_backend_no_js_transport".to_string(),
        ],
    }
}

fn bind_planned_result_to_driver_execution(
    planned_result: &Value,
    driver_result_hash: &str,
    driver_result: &Value,
) -> Value {
    let mut result = planned_result.clone();
    let Some(object) = result.as_object_mut() else {
        return planned_result.clone();
    };
    ensure_string_array_entry(
        object,
        "evidence_refs",
        "runtime_mcp_live_backend_rust_driver_executed",
    );
    ensure_string_array_entry(
        object,
        "evidence_refs",
        "runtime_mcp_live_backend_actual_mcp_manager_io",
    );
    let details = ensure_object(object, "details");
    details.insert(
        "runtime_mcp_live_backend_execution_status".to_string(),
        Value::String("rust_driver_executed".to_string()),
    );
    details.insert(
        "runtime_mcp_live_backend_execution_required".to_string(),
        Value::Bool(true),
    );
    details.insert(
        "runtime_mcp_live_backend_execution_source".to_string(),
        Value::String("rust_mcp_live_backend_execution_api".to_string()),
    );
    details.insert(
        "runtime_mcp_live_backend_result_observed".to_string(),
        Value::Bool(true),
    );
    details.insert(
        "runtime_mcp_live_backend_driver_result_hash".to_string(),
        Value::String(driver_result_hash.to_string()),
    );
    details.insert(
        "runtime_mcp_live_backend_driver_method".to_string(),
        driver_result
            .get("method")
            .cloned()
            .unwrap_or(Value::String("unknown".to_string())),
    );
    result
}

fn ensure_object<'a>(object: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    if !object.get(key).is_some_and(Value::is_object) {
        object.insert(key.to_string(), Value::Object(Map::new()));
    }
    object
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("object inserted")
}

fn ensure_string_array_entry(object: &mut Map<String, Value>, key: &str, entry: &str) {
    let mut values = object
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    values.push(entry.to_string());
    values.sort();
    values.dedup();
    object.insert(
        key.to_string(),
        Value::Array(values.into_iter().map(Value::String).collect()),
    );
}

fn hash_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| value.to_string().into_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn require_option(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), RuntimeMcpLiveBackendExecutionError> {
    value
        .and_then(trimmed)
        .map(|_| ())
        .ok_or(RuntimeMcpLiveBackendExecutionError::MissingField(field))
}

fn trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).and_then(trimmed)
}

fn json_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result as AnyhowResult;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::mcp::{McpManager, McpServerConfig};
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::{
        ActionRequest, CapabilityLease, CapabilityLeaseMode, ContextSlice, NetMode, RuntimeTarget,
    };
    use ioi_types::config::{
        McpContainmentConfig, McpContainmentMode, McpIntegrityConfig, McpMode, McpServerSource,
        McpServerTier,
    };
    use ioi_types::error::VmError;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> std::result::Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> std::result::Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> std::result::Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(
            &self,
            _intent: &ActionRequest,
        ) -> std::result::Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> std::result::Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(
            &self,
            _id: u32,
        ) -> std::result::Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }
    }

    fn test_service(mcp: Option<Arc<McpManager>>) -> RuntimeAgentService {
        let inference = Arc::new(MockInferenceRuntime);
        let service = RuntimeAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        );
        if let Some(mcp) = mcp {
            service.with_mcp_manager(mcp)
        } else {
            service
        }
    }

    fn backend_contract(method: &str) -> Value {
        json!({
            "schema_version": "ioi.runtime.mcp-backend-execution.v1",
            "object": "ioi.runtime_mcp_backend_execution",
            "status": "rust_driver_contract_bound",
            "owner": "ioi_drivers::mcp::McpManager",
            "transport_owner": "ioi_drivers::mcp::transport::McpTransport",
            "method": method,
            "js_backend_execution": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false
        })
    }

    fn planned_result(method: &str) -> Value {
        json!({
            "schema_version": "ioi.runtime.mcp-live-result.v1",
            "object": "ioi.runtime_mcp_live_result",
            "id": "result_runtime_mcp_live_exit_fixture",
            "kind": "runtime_mcp_live_result",
            "status": "rust_materialized",
            "receipt_id": "receipt_runtime_mcp_live_exit_fixture",
            "receipt_refs": ["receipt_runtime_mcp_live_exit_fixture"],
            "evidence_refs": [
                "runtime_mcp_live_result_rust_projection",
                "agentgres_runtime_mcp_live_result_truth_required",
                "runtime_mcp_live_result_payload_rust_materialized",
                "runtime_mcp_no_js_transport_result",
                "runtime_mcp_backend_execution_rust_driver_bound",
                "receipt_state_root_binding_required"
            ],
            "payload": {
                "schema_version": "ioi.runtime.mcp-live-result-payload.v1",
                "object": "ioi.runtime_mcp_live_result_payload",
                "payload_hash": "sha256:planned",
                "result_payload_hash": "sha256:planned",
                "backend_execution": backend_contract(method),
                "protocol_result": {
                    "content": [{ "type": "text", "text": "planned" }],
                    "structuredContent": { "backend_method": method },
                    "isError": false
                }
            },
            "details": {
                "rust_daemon_core_result_author": "runtime.mcp_control",
                "result_materialized": true,
                "backend_materialization_status": "rust_driver_contract_bound",
                "runtime_mcp_backend_execution_status": "rust_driver_contract_bound",
                "runtime_mcp_backend_owner": "ioi_drivers::mcp::McpManager",
                "runtime_mcp_backend_transport_owner": "ioi_drivers::mcp::transport::McpTransport",
                "runtime_mcp_backend_method": method,
                "runtime_mcp_backend_contract_required": true,
                "payload_hash": "sha256:planned",
                "result_payload_hash": "sha256:planned",
                "js_backend_execution": false,
                "js_transport_invocation": false,
                "command_transport_fallback": false,
                "binary_bridge_fallback": false,
                "compatibility_fallback": false
            }
        })
    }

    fn workload_spec() -> WorkloadSpec {
        WorkloadSpec {
            runtime_target: RuntimeTarget::McpAdapter,
            net_mode: NetMode::Disabled,
            capability_lease: Some(CapabilityLease {
                lease_id: [7u8; 32],
                issued_at_ms: 0,
                expires_at_ms: u64::MAX,
                mode: CapabilityLeaseMode::OneShot,
                capability_allowlist: vec!["fixture__query".to_string()],
                domain_allowlist: vec![],
            }),
            ui_surface: None,
        }
    }

    fn request(method: &str) -> RuntimeMcpLiveBackendExecutionRequest {
        RuntimeMcpLiveBackendExecutionRequest {
            schema_version: RUNTIME_MCP_LIVE_BACKEND_EXECUTION_REQUEST_SCHEMA_VERSION.to_string(),
            state_dir: Some("/runtime-state".to_string()),
            thread_id: Some("thread_fixture".to_string()),
            agent_id: Some("agent_fixture".to_string()),
            control_kind: Some(if method == "tools/list" {
                "mcp_live_discovery".to_string()
            } else {
                "mcp_invoke".to_string()
            }),
            event_id: Some("event_fixture".to_string()),
            server_id: Some("fixture".to_string()),
            tool_id: Some("query".to_string()),
            tool_name: Some("query".to_string()),
            tool_ref: Some("fixture__query".to_string()),
            live_transport: Some("stdio".to_string()),
            execution_mode: Some("development".to_string()),
            timeout_ms: Some(5_000),
            arguments: json!({ "q": "hello" }),
            workload_spec: (method == "tools/call").then(workload_spec),
            authority_grant_refs: vec!["wallet.network://grant/mcp/fixture".to_string()],
            authority_receipt_refs: vec!["receipt://wallet.network/mcp/fixture".to_string()],
            custody_ref: Some("ctee://workspace/fixture".to_string()),
            containment_ref: Some("containment://mcp/fixture".to_string()),
            backend_execution: backend_contract(method),
            receipt: json!({ "id": "receipt_runtime_mcp_live_exit_fixture" }),
            control: json!({ "result_record_id": "result_runtime_mcp_live_exit_fixture" }),
            planned_result: planned_result(method),
        }
    }

    async fn fixture_mcp_manager() -> AnyhowResult<Arc<McpManager>> {
        let manager = Arc::new(McpManager::new());
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fixtures/mcp-stdio-echo-server.mjs");
        let fixture = std::fs::canonicalize(fixture)?;
        manager
            .start_server(
                "fixture",
                McpMode::Development,
                McpServerConfig {
                    command: "node".to_string(),
                    args: vec![fixture.to_string_lossy().to_string()],
                    env: HashMap::new(),
                    tier: McpServerTier::Unverified,
                    source: McpServerSource::LocalBin,
                    integrity: McpIntegrityConfig::default(),
                    containment: McpContainmentConfig {
                        mode: McpContainmentMode::DeveloperUnconfined,
                        ..McpContainmentConfig::default()
                    },
                    allowed_tools: vec!["query".to_string()],
                },
            )
            .await?;
        Ok(manager)
    }

    #[tokio::test]
    async fn runtime_mcp_live_backend_requires_mounted_mcp_manager() {
        let error = test_service(None)
            .execute_runtime_mcp_live_backend(&request("tools/call"))
            .await
            .expect_err("missing MCP manager must fail closed");

        assert_eq!(
            error,
            RuntimeMcpLiveBackendExecutionError::McpManagerRequired
        );
    }

    #[tokio::test]
    async fn runtime_mcp_live_backend_executes_tool_call_through_mcp_manager() -> AnyhowResult<()> {
        let service = test_service(Some(fixture_mcp_manager().await?));
        let record = service
            .execute_runtime_mcp_live_backend(&request("tools/call"))
            .await?;

        assert_eq!(record.source, "rust_mcp_live_backend_execution_api");
        assert_eq!(record.status, "rust_driver_executed");
        assert_eq!(record.backend_execution["status"], "rust_driver_executed");
        assert_eq!(record.backend_execution["method"], "tools/call");
        assert_eq!(record.driver_result["method"], "tools/call");
        assert_eq!(
            record.driver_result["result"]["content"][0]["text"],
            "query:hello"
        );
        assert!(record.driver_result_hash.starts_with("sha256:"));
        assert!(record
            .evidence_refs
            .contains(&"runtime_mcp_live_backend_actual_mcp_manager_io".to_string()));
        assert_eq!(
            record.result["details"]["runtime_mcp_live_backend_execution_status"],
            "rust_driver_executed"
        );
        assert_eq!(
            record.result["details"]["runtime_mcp_live_backend_driver_result_hash"],
            record.driver_result_hash
        );
        assert_eq!(
            record.result["details"]["command_transport_fallback"],
            false
        );
        Ok(())
    }

    #[tokio::test]
    async fn runtime_mcp_live_backend_executes_live_discovery_through_mcp_manager(
    ) -> AnyhowResult<()> {
        let service = test_service(Some(fixture_mcp_manager().await?));
        let record = service
            .execute_runtime_mcp_live_backend(&request("tools/list"))
            .await?;

        assert_eq!(record.backend_execution["status"], "rust_driver_executed");
        assert_eq!(record.backend_execution["method"], "tools/list");
        assert_eq!(record.driver_result["method"], "tools/list");
        assert_eq!(record.driver_result["tool_count"], 1);
        assert_eq!(record.driver_result["tools"][0]["name"], "fixture__query");
        assert_eq!(
            record.result["details"]["runtime_mcp_live_backend_driver_method"],
            "tools/list"
        );
        Ok(())
    }
}
