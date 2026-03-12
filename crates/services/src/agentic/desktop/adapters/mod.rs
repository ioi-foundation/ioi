use crate::agentic::desktop::connectors::{google_workspace, mail_connector};
use crate::agentic::desktop::execution::workload;
use crate::agentic::desktop::service::handler::try_execute_wallet_mail_dynamic_tool;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::tools::services as service_tools;
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::{service_namespace_prefix, NamespacedStateAccess, StateAccess};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition, ResolvedIntentState};
use ioi_types::app::{
    AdapterArtifactPointer, AdapterCallRequest, AdapterCallResponse, AdapterDefinition,
    AdapterFailure, AdapterKind, AdapterReceipt, AdapterRedactionSummary,
    AdapterReplayClassification, WorkloadActivityKind, WorkloadReceipt, WorkloadSpec,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};

const ADAPTER_REDACTION_VERSION: &str = "adapter_receipt.redaction.v1";
const GENERIC_CONNECTOR_RESPONSE_SCHEMA: &str = r#"{"type":"object","required":["connector_id","action_id","tool_name","provider","summary","data","executed_at_utc"],"properties":{"connector_id":{"type":"string"},"action_id":{"type":"string"},"tool_name":{"type":"string"},"provider":{"type":"string"},"summary":{"type":"string"},"data":{},"executed_at_utc":{"type":"string"}}}"#;
const GENERIC_MCP_RESPONSE_SCHEMA: &str = r#"{"type":"object","required":["tool_name","result"],"properties":{"tool_name":{"type":"string"},"result":{}}}"#;
const GENERIC_SERVICE_REQUEST_SCHEMA: &str =
    r#"{"type":"object","additionalProperties":true,"description":"JSON object parameters for the service method"}"#;
const GENERIC_SERVICE_RESPONSE_SCHEMA: &str = r#"{"type":"object","required":["service_id","method","status"],"properties":{"service_id":{"type":"string"},"method":{"type":"string"},"status":{"type":"string"}}}"#;

#[derive(Debug, Clone)]
pub struct AdapterExecutionOutcome {
    pub success: bool,
    pub history_entry: Option<String>,
    pub error: Option<String>,
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, TransactionError> {
    serde_jcs::to_vec(value)
        .or_else(|_| serde_json::to_vec(value))
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "failed to canonicalize adapter JSON payload: {}",
                error
            ))
        })
}

fn sha256_hex(bytes: &[u8]) -> Result<String, TransactionError> {
    sha256(bytes)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .map_err(|error| {
            TransactionError::Invalid(format!("failed to hash adapter payload: {}", error))
        })
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn sensitive_key_label(raw: &str) -> bool {
    let key = raw.trim().to_ascii_lowercase();
    key.contains("password")
        || key.contains("passwd")
        || key.contains("passphrase")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("auth")
        || key.contains("bearer")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.contains("private_key")
        || key.contains("privatekey")
}

fn string_looks_redacted(raw: &str) -> bool {
    let normalized = raw.trim().to_ascii_lowercase();
    normalized.contains("<redacted:")
        || normalized.contains("[redacted_pii]")
        || normalized == "redacted"
        || normalized == "redacted_email"
        || normalized == "redacted:email"
}

fn collect_redacted_fields(value: &Value, path: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                if sensitive_key_label(key) {
                    out.insert(next_path.clone());
                }
                collect_redacted_fields(child, &next_path, out);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_redacted_fields(child, &format!("{}[{}]", path, index), out);
            }
        }
        Value::String(raw) => {
            if !path.is_empty() && string_looks_redacted(raw) {
                out.insert(path.to_string());
            }
        }
        _ => {}
    }
}

fn summarize_redactions(values: &[&Value]) -> Option<AdapterRedactionSummary> {
    let mut fields = BTreeSet::new();
    for value in values {
        collect_redacted_fields(value, "", &mut fields);
    }
    if fields.is_empty() {
        None
    } else {
        let redaction_count = fields.len() as u32;
        Some(AdapterRedactionSummary {
            redacted_fields: fields.into_iter().collect(),
            redaction_count,
            redaction_version: ADAPTER_REDACTION_VERSION.to_string(),
        })
    }
}

fn extract_artifact_pointers(value: &Value) -> Vec<AdapterArtifactPointer> {
    fn collect(value: &Value, out: &mut Vec<AdapterArtifactPointer>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if let Some(raw) = child.as_str() {
                        let lower = key.trim().to_ascii_lowercase();
                        if matches!(
                            lower.as_str(),
                            "artifact"
                                | "artifact_path"
                                | "artifact_uri"
                                | "citation"
                                | "download_url"
                                | "path"
                                | "uri"
                                | "url"
                                | "webviewlink"
                        ) {
                            if !raw.trim().is_empty() {
                                out.push(AdapterArtifactPointer {
                                    uri: raw.trim().to_string(),
                                    media_type: None,
                                    sha256: None,
                                    label: Some(key.clone()),
                                });
                            }
                        }
                    }
                    collect(child, out);
                }
            }
            Value::Array(values) => {
                for child in values {
                    collect(child, out);
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    collect(value, &mut out);
    let mut seen = HashSet::new();
    out.retain(|pointer| seen.insert(pointer.uri.clone()));
    out
}

fn failure_from_message(message: String) -> AdapterFailure {
    AdapterFailure {
        error_class: workload::extract_error_class(Some(&message))
            .unwrap_or_else(|| "AdapterExecutionFailed".to_string()),
        message: Some(message),
        retryable: true,
    }
}

fn project_llm_tool(definition: AdapterDefinition) -> LlmToolDefinition {
    LlmToolDefinition {
        name: definition.tool_name,
        description: definition.description,
        parameters: definition.request_schema,
    }
}

fn mail_tool_aliases() -> HashSet<String> {
    mail_connector::mail_connector_tool_route_bindings()
        .into_iter()
        .map(|binding| binding.tool_name.to_string())
        .collect()
}

fn google_provider_route(tool_name: &str) -> (Option<String>, Option<String>) {
    (
        google_workspace::google_tool_provider_family(tool_name).map(str::to_string),
        google_workspace::google_tool_route_label(tool_name).map(str::to_string),
    )
}

fn google_capabilities(tool_name: &str) -> Vec<String> {
    google_workspace::google_connector_tool_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == tool_name)
        .map(|binding| {
            binding
                .capabilities
                .into_iter()
                .map(|capability| capability.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn adapter_definition_from_llm_tool(tool: LlmToolDefinition) -> AdapterDefinition {
    let normalized = tool.name.trim().to_ascii_lowercase();
    if google_workspace::is_google_connector_tool_name(&normalized) {
        let (provider_family, route_label) = google_provider_route(&normalized);
        return AdapterDefinition {
            adapter_id: google_workspace::GOOGLE_CONNECTOR_ID.to_string(),
            tool_name: tool.name,
            kind: AdapterKind::Connector,
            description: tool.description,
            request_schema: tool.parameters,
            response_schema: Some(GENERIC_CONNECTOR_RESPONSE_SCHEMA.to_string()),
            action_target: AgentTool::Dynamic(json!({
                "name": normalized,
                "arguments": {}
            }))
            .target(),
            capabilities: google_capabilities(&normalized),
            provider_family,
            route_label,
        };
    }

    if mail_tool_aliases().contains(&normalized) {
        return AdapterDefinition {
            adapter_id: mail_connector::MAIL_CONNECTOR_ID.to_string(),
            tool_name: tool.name,
            kind: AdapterKind::Connector,
            description: tool.description,
            request_schema: tool.parameters,
            response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
            action_target: AgentTool::Dynamic(json!({
                "name": normalized,
                "arguments": {}
            }))
            .target(),
            capabilities: vec![
                "mail.read.latest".to_string(),
                "mail.list.recent".to_string(),
                "mail.delete.spam".to_string(),
                "mail.reply".to_string(),
            ],
            provider_family: Some("mail.wallet_network".to_string()),
            route_label: Some("mail_connector".to_string()),
        };
    }

    if let Some((service_id, _)) = normalized.split_once("__") {
        return AdapterDefinition {
            adapter_id: format!("service::{}", service_id),
            tool_name: tool.name,
            kind: AdapterKind::Service,
            description: tool.description,
            request_schema: GENERIC_SERVICE_REQUEST_SCHEMA.to_string(),
            response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
            action_target: AgentTool::Dynamic(json!({
                "name": normalized,
                "arguments": {}
            }))
            .target(),
            capabilities: Vec::new(),
            provider_family: None,
            route_label: None,
        };
    }

    AdapterDefinition {
        adapter_id: format!("adapter::{}", normalized),
        tool_name: tool.name,
        kind: AdapterKind::Custom("dynamic".to_string()),
        description: tool.description,
        request_schema: tool.parameters,
        response_schema: None,
        action_target: AgentTool::Dynamic(json!({
            "name": normalized,
            "arguments": {}
        }))
        .target(),
        capabilities: Vec::new(),
        provider_family: None,
        route_label: None,
    }
}

fn mcp_response_schema() -> Option<String> {
    Some(GENERIC_MCP_RESPONSE_SCHEMA.to_string())
}

fn mcp_definition(tool: LlmToolDefinition, manager: &McpManager) -> AdapterDefinition {
    let _ = manager;
    let normalized = tool.name.trim().to_ascii_lowercase();
    AdapterDefinition {
        adapter_id: format!("mcp::{}", normalized),
        tool_name: tool.name,
        kind: AdapterKind::Mcp,
        description: tool.description,
        request_schema: tool.parameters,
        response_schema: mcp_response_schema(),
        action_target: AgentTool::Dynamic(json!({
            "name": normalized,
            "arguments": {}
        }))
        .target(),
        capabilities: Vec::new(),
        provider_family: None,
        route_label: None,
    }
}

pub async fn discover_adapter_definitions(
    state: &dyn StateAccess,
    mcp: Option<&McpManager>,
    active_window_title: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Vec<AdapterDefinition> {
    let mut llm_tools = Vec::new();
    service_tools::push_service_tools(state, active_window_title, &mut llm_tools);
    service_tools::inject_mail_connector_fallback_tools_if_needed(resolved_intent, &mut llm_tools);
    service_tools::inject_google_connector_tools_if_needed(&mut llm_tools);

    let mut definitions = llm_tools
        .into_iter()
        .map(adapter_definition_from_llm_tool)
        .collect::<Vec<_>>();

    if let Some(mcp) = mcp {
        definitions.extend(
            mcp.get_all_tools()
                .await
                .into_iter()
                .map(|tool| mcp_definition(tool, mcp)),
        );
    }

    let mut seen = HashSet::new();
    definitions.retain(|definition| seen.insert(definition.tool_name.clone()));
    definitions
}

pub async fn discover_adapter_tools(
    state: &dyn StateAccess,
    mcp: Option<&McpManager>,
    active_window_title: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> (Vec<LlmToolDefinition>, HashSet<String>) {
    let definitions =
        discover_adapter_definitions(state, mcp, active_window_title, resolved_intent).await;
    let mut names = HashSet::new();
    let tools = definitions
        .into_iter()
        .map(|definition| {
            names.insert(definition.tool_name.clone());
            project_llm_tool(definition)
        })
        .collect();
    (tools, names)
}

fn parse_response_payload(history_entry: Option<&str>) -> Value {
    history_entry
        .and_then(|entry| serde_json::from_str::<Value>(entry).ok())
        .unwrap_or_else(|| {
            json!({
                "status": "ok",
                "history_entry": history_entry.unwrap_or_default(),
            })
        })
}

fn build_connector_history(summary: &str, data: &Value) -> String {
    let payload = serde_json::to_string_pretty(data).unwrap_or_default();
    if payload.is_empty() || payload == "null" {
        summary.to_string()
    } else {
        format!("{}\n\n{}", summary, payload)
    }
}

fn build_request(
    adapter_id: String,
    tool_name: &str,
    arguments: &Value,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<AdapterCallRequest, TransactionError> {
    let request_payload = canonical_json_bytes(arguments)?;
    let request_hash = sha256_hex(&request_payload)?;
    let invocation_id = workload::compute_workload_id(
        session_id,
        step_index,
        tool_name,
        request_hash.as_str(),
    );
    let idempotency_key = sha256_hex(
        format!(
            "{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            tool_name,
            request_hash
        )
        .as_bytes(),
    )?;
    Ok(AdapterCallRequest {
        adapter_id,
        tool_name: tool_name.to_string(),
        invocation_id,
        idempotency_key,
        action_target: AgentTool::Dynamic(json!({
            "name": tool_name,
            "arguments": arguments,
        }))
        .target()
        .canonical_label(),
        request_payload,
    })
}

fn build_receipt(
    request: &AdapterCallRequest,
    response: &AdapterCallResponse,
) -> Result<AdapterReceipt, TransactionError> {
    Ok(AdapterReceipt {
        adapter_id: response.adapter_id.clone(),
        tool_name: response.tool_name.clone(),
        kind: response.kind.clone(),
        invocation_id: request.invocation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        action_target: request.action_target.clone(),
        request_hash: sha256_hex(&request.request_payload)?,
        response_hash: Some(sha256_hex(&response.response_payload)?),
        success: response.failure.is_none(),
        error_class: response.failure.as_ref().map(|failure| failure.error_class.clone()),
        artifact_pointers: response.artifact_pointers.clone(),
        redaction: response.redaction.clone(),
        replay_classification: response.replay_classification,
    })
}

fn emit_adapter_activity(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: &str,
    phase: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    workload::emit_workload_activity(
        tx,
        session_id,
        step_index,
        workload_id.to_string(),
        WorkloadActivityKind::Lifecycle {
            phase: phase.to_string(),
            exit_code: None,
        },
    );
}

fn emit_adapter_receipt(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: &str,
    receipt: AdapterReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    workload::emit_workload_receipt(
        tx,
        session_id,
        step_index,
        workload_id.to_string(),
        WorkloadReceipt::Adapter(receipt),
    );
}

async fn execute_wallet_mail_adapter(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    dynamic_tool: &Value,
    latest_user_message: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<Option<AdapterCallResponse>, TransactionError> {
    let result: Option<(bool, Option<String>, Option<String>)> = try_execute_wallet_mail_dynamic_tool(
        service,
        state,
        call_context,
        dynamic_tool,
        latest_user_message,
        session_id,
        step_index,
    )
    .await?;
    let Some((success, history_entry, error)) = result else {
        return Ok(None);
    };

    let tool_name = dynamic_tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("wallet_network__unknown");
    if success {
        let payload = parse_response_payload(history_entry.as_deref());
        let history_entry = history_entry.or_else(|| Some(pretty_json(&payload)));
        Ok(Some(AdapterCallResponse {
            adapter_id: mail_connector::MAIL_CONNECTOR_ID.to_string(),
            tool_name: tool_name.to_string(),
            kind: AdapterKind::Connector,
            response_payload: canonical_json_bytes(&payload)?,
            summary: format!("wallet mail adapter '{}' executed", tool_name),
            history_entry,
            artifact_pointers: extract_artifact_pointers(&payload),
            redaction: summarize_redactions(&[dynamic_tool, &payload]),
            failure: None,
            replay_classification: Some(AdapterReplayClassification::ReplaySafe),
            response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
        }))
    } else {
        let failure = failure_from_message(error.unwrap_or_else(|| {
            "ERROR_CLASS=AdapterExecutionFailed wallet mail adapter failed".to_string()
        }));
        let payload = json!({
            "tool_name": tool_name,
            "error_class": failure.error_class,
            "message": failure.message,
        });
        Ok(Some(AdapterCallResponse {
            adapter_id: mail_connector::MAIL_CONNECTOR_ID.to_string(),
            tool_name: tool_name.to_string(),
            kind: AdapterKind::Connector,
            response_payload: canonical_json_bytes(&payload)?,
            summary: format!("wallet mail adapter '{}' failed", tool_name),
            history_entry: None,
            artifact_pointers: Vec::new(),
            redaction: summarize_redactions(&[dynamic_tool, &payload]),
            failure: Some(failure),
            replay_classification: Some(AdapterReplayClassification::RetryRequired),
            response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
        }))
    }
}

async fn execute_google_adapter(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    dynamic_tool: &Value,
) -> Result<Option<AdapterCallResponse>, TransactionError> {
    let result = google_workspace::execute_dynamic_tool_as_result(
        service,
        agent_state,
        session_id,
        dynamic_tool,
    )
    .await?;
    let Some(result) = result else {
        return Ok(None);
    };

    let data = json!({
        "connector_id": result.connector_id,
        "action_id": result.action_id,
        "tool_name": result.tool_name,
        "provider": result.provider,
        "summary": result.summary,
        "data": result.data,
        "executed_at_utc": result.executed_at_utc,
    });
    let history_entry = Some(build_connector_history(
        data.get("summary").and_then(Value::as_str).unwrap_or_default(),
        data.get("data").unwrap_or(&Value::Null),
    ));
    let tool_name = data
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(Some(AdapterCallResponse {
        adapter_id: google_workspace::GOOGLE_CONNECTOR_ID.to_string(),
        tool_name,
        kind: AdapterKind::Connector,
        response_payload: canonical_json_bytes(&data)?,
        summary: data
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        history_entry,
        artifact_pointers: extract_artifact_pointers(&data),
        redaction: summarize_redactions(&[dynamic_tool, &data]),
        failure: None,
        replay_classification: Some(AdapterReplayClassification::ReplaySafe),
        response_schema: Some(GENERIC_CONNECTOR_RESPONSE_SCHEMA.to_string()),
    }))
}

fn load_active_service_meta(
    state: &dyn StateAccess,
    service_id: &str,
) -> Result<Option<ActiveServiceMeta>, TransactionError> {
    let key = active_service_key(service_id);
    let maybe_bytes = state.get(&key).map_err(TransactionError::State)?;
    let Some(bytes) = maybe_bytes else {
        return Ok(None);
    };
    Ok(Some(codec::from_bytes_canonical::<ActiveServiceMeta>(&bytes)?))
}

fn find_versioned_service_method(meta: &ActiveServiceMeta, simple_name: &str) -> Option<String> {
    let mut candidates = meta
        .methods
        .iter()
        .filter_map(|(method, permission)| {
            if *permission != MethodPermission::User {
                return None;
            }
            let current_simple = method.split('@').next().unwrap_or(method.as_str());
            if current_simple.eq_ignore_ascii_case(simple_name) {
                Some(method.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

fn extract_service_params_bytes(arguments: &Value) -> Result<Vec<u8>, TransactionError> {
    if let Some(raw) = arguments.get("params").and_then(Value::as_str) {
        return Ok(raw.as_bytes().to_vec());
    }
    if arguments.is_null() {
        return Ok(b"{}".to_vec());
    }
    serde_json::to_vec(arguments).map_err(|error| {
        TransactionError::Invalid(format!(
            "failed to serialize service adapter params: {}",
            error
        ))
    })
}

async fn execute_service_adapter(
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    dynamic_tool: &Value,
) -> Result<Option<AdapterCallResponse>, TransactionError> {
    let tool_name = dynamic_tool.get("name").and_then(Value::as_str).unwrap_or_default();
    let Some((service_id, simple_name)) = tool_name.split_once("__") else {
        return Ok(None);
    };
    if service_id.eq_ignore_ascii_case("desktop_agent") {
        let message = format!(
            "ERROR_CLASS=PolicyBlocked Recursive desktop_agent adapter calls are unsupported for '{}'",
            tool_name
        );
        let failure = failure_from_message(message.clone());
        let payload = json!({
            "service_id": service_id,
            "method": simple_name,
            "error_class": failure.error_class,
            "message": message,
        });
        return Ok(Some(AdapterCallResponse {
            adapter_id: format!("service::{}", service_id),
            tool_name: tool_name.to_string(),
            kind: AdapterKind::Service,
            response_payload: canonical_json_bytes(&payload)?,
            summary: format!("service adapter '{}' failed", tool_name),
            history_entry: None,
            artifact_pointers: Vec::new(),
            redaction: summarize_redactions(&[dynamic_tool, &payload]),
            failure: Some(failure),
            replay_classification: Some(AdapterReplayClassification::RetryRequired),
            response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
        }));
    }

    let Some(meta) = load_active_service_meta(state, service_id)? else {
        return Ok(None);
    };
    let Some(versioned_method) = find_versioned_service_method(&meta, simple_name) else {
        return Ok(None);
    };
    let service = call_context
        .services
        .services()
        .find(|service| service.id().eq_ignore_ascii_case(service_id))
        .cloned()
        .ok_or_else(|| {
            TransactionError::Invalid(format!(
                "service '{}' is not active in the ServiceDirectory",
                service_id
            ))
        })?;

    let prefix = service_namespace_prefix(service_id);
    let mut namespaced_state = NamespacedStateAccess::new(state, prefix, &meta);
    let params_bytes = extract_service_params_bytes(
        dynamic_tool
            .get("arguments")
            .unwrap_or(&Value::Null),
    )?;
    let mut tx_context = ioi_api::transaction::context::TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };
    service
        .handle_service_call(
            &mut namespaced_state,
            versioned_method.as_str(),
            &params_bytes,
            &mut tx_context,
        )
        .await?;

    let payload = json!({
        "service_id": service_id,
        "method": versioned_method,
        "status": "ok",
    });
    Ok(Some(AdapterCallResponse {
        adapter_id: format!("service::{}", service_id),
        tool_name: tool_name.to_string(),
        kind: AdapterKind::Service,
        response_payload: canonical_json_bytes(&payload)?,
        summary: format!("service adapter '{}' executed", tool_name),
        history_entry: Some(pretty_json(&payload)),
        artifact_pointers: Vec::new(),
        redaction: summarize_redactions(&[dynamic_tool, &payload]),
        failure: None,
        replay_classification: Some(AdapterReplayClassification::ReplaySafe),
        response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
    }))
}

async fn execute_mcp_adapter(
    mcp: &McpManager,
    dynamic_tool: &Value,
    request: &AdapterCallRequest,
    workload_spec: &WorkloadSpec,
) -> Result<Option<AdapterCallResponse>, TransactionError> {
    let tool_name = dynamic_tool.get("name").and_then(Value::as_str).unwrap_or_default();
    let arguments = dynamic_tool.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let execution = mcp
        .execute_tool_with_result(tool_name, arguments.clone(), Some(workload_spec))
        .await
        .map_err(|error| TransactionError::Invalid(error.to_string()))?;
    let adapter_id = format!("mcp::{}", execution.server_name);
    let payload = json!({
        "tool_name": tool_name,
        "server_name": execution.server_name,
        "result": execution.result,
    });
    Ok(Some(AdapterCallResponse {
        adapter_id,
        tool_name: request.tool_name.clone(),
        kind: AdapterKind::Mcp,
        response_payload: canonical_json_bytes(&payload)?,
        summary: format!("mcp adapter '{}' executed", tool_name),
        history_entry: Some(pretty_json(&payload.get("result").cloned().unwrap_or(Value::Null))),
        artifact_pointers: extract_artifact_pointers(&payload),
        redaction: summarize_redactions(&[dynamic_tool, &payload]),
        failure: None,
        replay_classification: Some(AdapterReplayClassification::ReplaySafe),
        response_schema: Some(GENERIC_MCP_RESPONSE_SCHEMA.to_string()),
    }))
}

pub async fn execute_dynamic_tool(
    service: &DesktopAgentService,
    dynamic_tool: &Value,
    session_id: [u8; 32],
    step_index: u32,
    workload_spec: &WorkloadSpec,
    agent_state: &AgentState,
    mut state: Option<&mut dyn StateAccess>,
    call_context: Option<ServiceCallContext<'_>>,
    latest_user_message: Option<&str>,
) -> Result<Option<AdapterExecutionOutcome>, TransactionError> {
    let Some(tool_name) = dynamic_tool.get("name").and_then(Value::as_str) else {
        return Ok(Some(AdapterExecutionOutcome {
            success: false,
            history_entry: None,
            error: Some("ERROR_CLASS=UnsupportedTool Missing tool name in dynamic adapter call".to_string()),
        }));
    };
    let arguments = dynamic_tool.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let request = build_request(
        if google_workspace::is_google_connector_tool_name(tool_name) {
            google_workspace::GOOGLE_CONNECTOR_ID.to_string()
        } else if mail_tool_aliases().contains(&tool_name.trim().to_ascii_lowercase()) {
            mail_connector::MAIL_CONNECTOR_ID.to_string()
        } else if let Some((service_id, _)) = tool_name.split_once("__") {
            format!("service::{}", service_id)
        } else {
            format!("adapter::{}", tool_name.trim().to_ascii_lowercase())
        },
        tool_name,
        &arguments,
        session_id,
        step_index,
    )?;

    emit_adapter_activity(
        service,
        session_id,
        step_index,
        &request.invocation_id,
        "started",
    );

    let response = if mail_tool_aliases().contains(&tool_name.trim().to_ascii_lowercase()) {
        match (state.as_deref_mut(), call_context) {
            (Some(state), Some(call_context)) => {
                execute_wallet_mail_adapter(
                    service,
                    state,
                    call_context,
                    dynamic_tool,
                    latest_user_message,
                    session_id,
                    step_index,
                )
                .await?
            }
            _ => Some(AdapterCallResponse {
                adapter_id: mail_connector::MAIL_CONNECTOR_ID.to_string(),
                tool_name: tool_name.to_string(),
                kind: AdapterKind::Connector,
                response_payload: canonical_json_bytes(&json!({
                    "tool_name": tool_name,
                    "error_class": "PolicyBlocked",
                    "message": "wallet mail adapter requires mutable state and call context",
                }))?,
                summary: format!("wallet mail adapter '{}' failed", tool_name),
                history_entry: None,
                artifact_pointers: Vec::new(),
                redaction: summarize_redactions(&[dynamic_tool]),
                failure: Some(AdapterFailure {
                    error_class: "PolicyBlocked".to_string(),
                    message: Some(
                        "wallet mail adapter requires mutable state and call context".to_string(),
                    ),
                    retryable: true,
                }),
                replay_classification: Some(AdapterReplayClassification::RetryRequired),
                response_schema: Some(GENERIC_SERVICE_RESPONSE_SCHEMA.to_string()),
            }),
        }
    } else if google_workspace::is_google_connector_tool_name(tool_name) {
        execute_google_adapter(service, agent_state, session_id, dynamic_tool).await?
    } else if let (Some(state), Some(call_context)) = (state.as_deref_mut(), call_context) {
        if let Some(response) = execute_service_adapter(state, call_context, dynamic_tool).await? {
            Some(response)
        } else if let Some(mcp) = service.mcp.as_ref() {
            execute_mcp_adapter(mcp, dynamic_tool, &request, workload_spec).await?
        } else {
            None
        }
    } else if let Some(mcp) = service.mcp.as_ref() {
        execute_mcp_adapter(mcp, dynamic_tool, &request, workload_spec).await?
    } else {
        None
    };

    let Some(response) = response else {
        emit_adapter_activity(
            service,
            session_id,
            step_index,
            &request.invocation_id,
            "failed",
        );
        return Ok(Some(AdapterExecutionOutcome {
            success: false,
            history_entry: None,
            error: Some(format!(
                "ERROR_CLASS=UnsupportedTool No adapter admitted tool '{}'",
                tool_name
            )),
        }));
    };

    let success = response.failure.is_none();
    let history_entry = response.history_entry.clone();
    let error = response
        .failure
        .as_ref()
        .and_then(|failure| failure.message.clone())
        .or_else(|| {
            response
                .failure
                .as_ref()
                .map(|failure| failure.error_class.clone())
        });
    let receipt = build_receipt(&request, &response)?;
    emit_adapter_receipt(
        service,
        session_id,
        step_index,
        &request.invocation_id,
        receipt,
    );
    emit_adapter_activity(
        service,
        session_id,
        step_index,
        &request.invocation_id,
        if success { "completed" } else { "failed" },
    );

    Ok(Some(AdapterExecutionOutcome {
        success,
        history_entry,
        error,
    }))
}

#[cfg(test)]
mod tests {
    use super::{discover_adapter_tools, execute_dynamic_tool};
    use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use async_trait::async_trait;
    use image::{ImageBuffer, ImageFormat, Rgba};
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::services::BlockchainService;
    use ioi_api::state::{service_namespace_prefix, StateAccess};
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::ResolvedIntentState;
    use ioi_types::app::{
        AccountId, ChainId, ContextSlice, KernelEvent, RuntimeTarget, WorkloadReceipt,
        WorkloadSpec,
    };
    use ioi_types::codec;
    use ioi_types::error::{TransactionError, VmError};
    use ioi_types::keys::active_service_key;
    use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Arc;

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
                .map_err(|e| VmError::HostError(format!("mock PNG encode failed: {}", e)))?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _som_map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct MockService;

    #[async_trait]
    impl BlockchainService for MockService {
        fn id(&self) -> &str {
            "mock_service"
        }

        fn abi_version(&self) -> u32 {
            1
        }

        fn state_schema(&self) -> &str {
            "mock.v1"
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::empty()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn handle_service_call(
            &self,
            state: &mut dyn StateAccess,
            method: &str,
            params: &[u8],
            _ctx: &mut ioi_api::transaction::context::TxContext<'_>,
        ) -> Result<(), TransactionError> {
            state
                .insert(
                    b"last_call",
                    format!("{}:{}", method, String::from_utf8_lossy(params)).as_bytes(),
                )
                .map_err(TransactionError::State)?;
            Ok(())
        }
    }

    fn mock_service_meta() -> ActiveServiceMeta {
        let mut methods = BTreeMap::new();
        methods.insert("ping@v1".to_string(), MethodPermission::User);
        ActiveServiceMeta {
            id: "mock_service".to_string(),
            abi_version: 1,
            state_schema: "mock.v1".to_string(),
            caps: Capabilities::empty(),
            artifact_hash: [0u8; 32],
            activated_at: 0,
            methods,
            allowed_system_prefixes: vec![],
            generation_id: 0,
            parent_hash: None,
            author: None,
            context_filter: None,
        }
    }

    fn agent_state() -> AgentState {
        AgentState {
            session_id: [0x11; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 4,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None::<ResolvedIntentState>,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            active_lens: None,
            pending_search_completion: None,
            planner_state: None,
            command_history: Default::default(),
        }
    }

    #[tokio::test]
    async fn discover_adapter_tools_includes_google_and_service_tools() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        state
            .insert(
                &active_service_key("mock_service"),
                &codec::to_bytes_canonical(&mock_service_meta()).expect("encode service meta"),
            )
            .expect("insert service meta");

        let (tools, names) = discover_adapter_tools(&state, None, "Autopilot Studio", None).await;
        assert!(names.contains("connector__google__gmail_read_emails"));
        assert!(names.contains("mock_service__ping"));
        assert!(
            tools.iter().any(|tool| tool.name == "connector__google__gmail_read_emails"),
            "google connector tools should flow through adapter discovery"
        );
    }

    #[tokio::test]
    async fn generic_service_adapter_executes_and_emits_adapter_receipt() {
        let runtime = Arc::new(MockInferenceRuntime);
        let (sender, mut receiver) = tokio::sync::broadcast::channel::<KernelEvent>(16);
        let service = DesktopAgentService::new_hybrid(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime.clone(),
            runtime,
        )
        .with_event_sender(sender);

        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        state
            .insert(
                &active_service_key("mock_service"),
                &codec::to_bytes_canonical(&mock_service_meta()).expect("encode service meta"),
            )
            .expect("insert service meta");

        let services = ServiceDirectory::new(vec![Arc::new(MockService)]);
        let call_context = ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(1),
            signer_account_id: AccountId::default(),
            services: &services,
            simulation: false,
            is_internal: false,
        };
        let outcome = execute_dynamic_tool(
            &service,
            &json!({
                "name": "mock_service__ping",
                "arguments": { "params": "{\"ping\":true}" }
            }),
            [0x44; 32],
            7,
            &WorkloadSpec {
                runtime_target: RuntimeTarget::Adapter,
                net_mode: ioi_types::app::NetMode::Disabled,
                capability_lease: None,
                ui_surface: None,
            },
            &agent_state(),
            Some(&mut state),
            Some(call_context),
            None,
        )
        .await
        .expect("adapter execution should succeed")
        .expect("adapter outcome should be present");

        assert!(outcome.success);
        let mut last_call_key = service_namespace_prefix("mock_service");
        last_call_key.extend_from_slice(b"last_call");
        let service_value = state
            .get(&last_call_key)
            .expect("state get should succeed")
            .expect("service side effect should be stored");
        assert_eq!(
            String::from_utf8(service_value).expect("utf8 state"),
            "ping@v1:{\"ping\":true}"
        );

        let mut saw_adapter_receipt = false;
        while let Ok(event) = receiver.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::Adapter(receipt) = receipt_event.receipt {
                    saw_adapter_receipt = true;
                    assert_eq!(receipt.adapter_id, "service::mock_service");
                    assert_eq!(receipt.tool_name, "mock_service__ping");
                    assert!(receipt.success);
                }
            }
        }
        assert!(saw_adapter_receipt, "adapter receipt should be emitted");
    }
}
