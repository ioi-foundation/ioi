use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, ModelMountError,
    MODEL_MOUNT_MCP_WORKFLOW_PLAN_SCHEMA_VERSION, MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountMcpWorkflowRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountMcpWorkflowPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub workflow_hash: String,
    pub authority_hash: String,
}

pub(super) fn plan_mcp_workflow(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    request.validate()?;
    match request.operation_kind.as_str() {
        "model_mount.mcp_server.import" => plan_mcp_import(request),
        "model_mount.mcp_server.ephemeral_register" => plan_ephemeral_register(request),
        "model_mount.mcp_tool.invoke" => plan_mcp_tool_invoke(request),
        "model_mount.workflow_node.execute" => plan_workflow_node_execute(request),
        _ => Err(ModelMountError::UnsupportedMcpWorkflowOperation),
    }
}

impl ModelMountMcpWorkflowRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !mcp_workflow_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedMcpWorkflowOperation);
        }
        let body = object_or_empty(&self.body);
        match self.operation_kind.as_str() {
            "model_mount.mcp_server.import" => {
                if mcp_server_configs_from_body(body).is_empty() {
                    return Err(ModelMountError::MissingField("mcp_servers"));
                }
            }
            "model_mount.mcp_server.ephemeral_register" => {
                if json_array_field(body, "integrations").is_empty() {
                    return Err(ModelMountError::MissingField("integrations"));
                }
            }
            "model_mount.mcp_tool.invoke" => {
                required_body_string(body, "server_id")?;
                required_body_string(body, "tool")?;
                require_mcp_external_exit_authority(self)?;
            }
            "model_mount.workflow_node.execute" => {
                if string_field(body, "node").is_none() && string_field(body, "node_type").is_none()
                {
                    return Err(ModelMountError::MissingField("node"));
                }
                require_mcp_external_exit_authority(self)?;
            }
            _ => return Err(ModelMountError::UnsupportedMcpWorkflowOperation),
        }
        Ok(())
    }
}

fn plan_mcp_import(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let servers = mcp_server_configs_from_body(body)
        .into_iter()
        .map(|(label, config)| mcp_server_record(&label, config, request.generated_at.as_deref()))
        .collect::<Result<Vec<_>, _>>()?;
    let server_ids = servers
        .iter()
        .filter_map(|server| {
            server
                .get("id")
                .and_then(Value::as_str)
                .and_then(non_empty_string)
        })
        .collect::<Vec<_>>();
    let record_id = string_field(body, "import_id").unwrap_or_else(|| {
        format!(
            "mcp_import.{}",
            hash_prefix(&json!({ "servers": server_ids }))
        )
    });
    mcp_workflow_plan(
        request,
        "mcp-servers",
        &record_id,
        "committed",
        json!({
            "servers": servers.clone(),
            "server_ids": server_ids.clone(),
            "import_count": server_ids.len(),
            "plaintext_secret_material_returned": false,
            "js_registry_mutation": false,
        }),
        json!({
            "status": "committed",
            "operation_kind": request.operation_kind,
            "server_ids": server_ids.clone(),
            "import_count": server_ids.len(),
            "servers": servers,
        }),
    )
}

fn plan_ephemeral_register(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let integrations = json_array_field(body, "integrations");
    let servers = integrations
        .iter()
        .filter_map(|integration| integration.as_object())
        .filter(|integration| string_field(integration, "type").as_deref() == Some("ephemeral_mcp"))
        .map(|integration| {
            let label = required_body_string(integration, "server_label")
                .unwrap_or_else(|_| "ephemeral_mcp".to_string());
            let server_url = required_body_string(integration, "server_url")?;
            let config = json!({
                "url": server_url,
                "allowed_tools": json_array_field(integration, "allowed_tools"),
                "source": "ephemeral_mcp",
            });
            mcp_server_record(
                &label,
                object_or_empty(&config),
                request.generated_at.as_deref(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if servers.is_empty() {
        return Err(ModelMountError::MissingField("integrations"));
    }
    let server_ids = servers
        .iter()
        .filter_map(|server| {
            server
                .get("id")
                .and_then(Value::as_str)
                .and_then(non_empty_string)
        })
        .collect::<Vec<_>>();
    let record_id = format!(
        "mcp_ephemeral.{}",
        hash_prefix(&json!({ "server_ids": server_ids }))
    );
    mcp_workflow_plan(
        request,
        "mcp-servers",
        &record_id,
        "committed",
        json!({
            "servers": servers.clone(),
            "server_ids": server_ids.clone(),
            "tool_receipt_ids": Vec::<String>::new(),
            "ephemeral": true,
            "input_hash": string_field(body, "input").map(|input| hash_text(&input)).transpose()?,
            "plaintext_secret_material_returned": false,
            "js_registry_mutation": false,
        }),
        json!({
            "status": "committed",
            "operation_kind": request.operation_kind,
            "server_ids": server_ids.clone(),
            "tool_receipt_ids": Vec::<String>::new(),
            "evidence_refs": mcp_workflow_evidence_refs(),
        }),
    )
}

fn plan_mcp_tool_invoke(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let authority = mcp_external_exit_authority(request)?;
    let server_id = required_body_string(body, "server_id")?;
    let tool = required_body_string(body, "tool")?;
    let input_hash = body
        .get("input")
        .map(hash_json)
        .transpose()?
        .unwrap_or_else(|| {
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        });
    let record_id = format!(
        "mcp_tool.{}.{}.{}",
        safe_segment(&server_id),
        safe_segment(&tool),
        hash_prefix(&json!({ "server_id": server_id, "tool": tool, "input_hash": input_hash }))
    );
    let receipt_id = receipt_id_for("mcp_tool_invocation", &record_id);
    let result_payload = mcp_tool_result_payload(&server_id, &tool, &input_hash, &receipt_id);
    let result_payload_hash = hash_json(&result_payload)?;
    mcp_workflow_plan(
        request,
        "mcp-workflow-controls",
        &record_id,
        "admitted",
        json!({
            "server_id": server_id,
            "tool": tool,
            "input_hash": input_hash,
            "tool_receipt_id": receipt_id,
            "tool_receipt_ids": [receipt_id],
            "content_receipt_id": receipt_id,
            "result_receipt_id": receipt_id,
            "content_receipt_required": true,
            "result_payload": result_payload.clone(),
            "result_payload_hash": result_payload_hash.clone(),
            "model_mount_mcp_result_materialized": true,
            "model_mount_mcp_result_materialization_status": "rust_materialized",
            "result_materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "result_payload_replay_owner": "rust_daemon_core.model_mount.read_projection.mcp_workflow_result",
            "transport_execution_status": "rust_admitted",
            "rust_transport_execution_admitted": true,
            "transport_execution_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "step_module_dispatch_owner": "rust_daemon_core.step_module_router",
            "agentgres_admission_required": true,
            "receipt_state_root_binding_required": true,
            "js_transport_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false,
            "legacy_js_result_fallback": false,
            "wallet_authority_required": true,
            "wallet_authority_boundary": "wallet.network.mcp_external_exit",
            "ctee_custody_required": true,
            "transport_containment_required": true,
            "authority_grant_refs": authority.authority_grant_refs,
            "authority_receipt_refs": authority.authority_receipt_refs,
            "custody_ref": authority.custody_ref,
            "containment_ref": authority.containment_ref,
        }),
        json!({
            "status": "admitted",
            "operation_kind": request.operation_kind,
            "server_id": server_id,
            "tool": tool,
            "tool_receipt_id": receipt_id,
            "tool_receipt_ids": [receipt_id],
            "content_receipt_id": receipt_id,
            "result_receipt_id": receipt_id,
            "content_receipt_required": true,
            "result_payload": result_payload,
            "result_payload_hash": result_payload_hash,
            "model_mount_mcp_result_materialized": true,
            "model_mount_mcp_result_materialization_status": "rust_materialized",
            "result_materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "result_payload_replay_owner": "rust_daemon_core.model_mount.read_projection.mcp_workflow_result",
            "transport_execution_status": "rust_admitted",
            "rust_transport_execution_admitted": true,
            "transport_execution_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "step_module_dispatch_owner": "rust_daemon_core.step_module_router",
            "agentgres_admission_required": true,
            "receipt_state_root_binding_required": true,
            "js_transport_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false,
            "legacy_js_result_fallback": false,
            "wallet_authority_required": true,
            "wallet_authority_boundary": "wallet.network.mcp_external_exit",
            "ctee_custody_required": true,
            "transport_containment_required": true,
            "custody_ref": authority.custody_ref,
            "containment_ref": authority.containment_ref,
        }),
    )
}

fn plan_workflow_node_execute(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let authority = mcp_external_exit_authority(request)?;
    let node = string_field(body, "node")
        .or_else(|| string_field(body, "node_type"))
        .ok_or(ModelMountError::MissingField("node"))?;
    let workflow_node_id = string_field(body, "workflow_node_id")
        .unwrap_or_else(|| format!("workflow.node.{}", safe_segment(&node)));
    let workflow_graph_id = string_field(body, "workflow_graph_id");
    let input_hash = body.get("input").map(hash_json).transpose()?;
    let record_id = format!(
        "workflow_node.{}.{}",
        safe_segment(&workflow_node_id),
        hash_prefix(&json!({
            "node": node,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
        }))
    );
    let receipt_id = receipt_id_for("workflow_node_execution", &record_id);
    let result_payload = workflow_node_result_payload(
        &node,
        workflow_graph_id.as_deref(),
        &workflow_node_id,
        input_hash.as_deref(),
        &receipt_id,
    );
    let result_payload_hash = hash_json(&result_payload)?;
    mcp_workflow_plan(
        request,
        "mcp-workflow-controls",
        &record_id,
        "admitted",
        json!({
            "node": node,
            "model_id": string_field(body, "model_id").or_else(|| string_field(body, "model")),
            "route_id": string_field(body, "route_id"),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "workflow_node_type": string_field(body, "workflow_node_type"),
            "input_hash": input_hash,
            "max_tokens": integer_field(body, "max_tokens"),
            "workflow_receipt_id": receipt_id,
            "workflow_receipt_ids": [receipt_id],
            "content_receipt_id": receipt_id,
            "result_receipt_id": receipt_id,
            "content_receipt_required": true,
            "result_payload": result_payload.clone(),
            "result_payload_hash": result_payload_hash.clone(),
            "model_mount_mcp_result_materialized": true,
            "model_mount_mcp_result_materialization_status": "rust_materialized",
            "result_materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "result_payload_replay_owner": "rust_daemon_core.model_mount.read_projection.mcp_workflow_result",
            "execution_status": "rust_admitted",
            "rust_step_module_dispatch_admitted": true,
            "step_module_dispatch_owner": "rust_daemon_core.step_module_router",
            "workflow_execution_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "agentgres_admission_required": true,
            "receipt_state_root_binding_required": true,
            "js_route_test": false,
            "js_model_invocation": false,
            "js_mcp_tool_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false,
            "legacy_js_result_fallback": false,
            "wallet_authority_required": true,
            "wallet_authority_boundary": "wallet.network.mcp_external_exit",
            "ctee_custody_required": true,
            "transport_containment_required": true,
            "authority_grant_refs": authority.authority_grant_refs,
            "authority_receipt_refs": authority.authority_receipt_refs,
            "custody_ref": authority.custody_ref,
            "containment_ref": authority.containment_ref,
        }),
        json!({
            "status": "admitted",
            "operation_kind": request.operation_kind,
            "node": node,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "workflow_receipt_id": receipt_id,
            "workflow_receipt_ids": [receipt_id],
            "content_receipt_id": receipt_id,
            "result_receipt_id": receipt_id,
            "content_receipt_required": true,
            "result_payload": result_payload,
            "result_payload_hash": result_payload_hash,
            "model_mount_mcp_result_materialized": true,
            "model_mount_mcp_result_materialization_status": "rust_materialized",
            "result_materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "result_payload_replay_owner": "rust_daemon_core.model_mount.read_projection.mcp_workflow_result",
            "execution_status": "rust_admitted",
            "rust_step_module_dispatch_admitted": true,
            "step_module_dispatch_owner": "rust_daemon_core.step_module_router",
            "workflow_execution_owner": "rust_daemon_core.model_mount.mcp_workflow",
            "agentgres_admission_required": true,
            "receipt_state_root_binding_required": true,
            "js_route_test": false,
            "js_model_invocation": false,
            "js_mcp_tool_invocation": false,
            "command_transport_fallback": false,
            "binary_bridge_fallback": false,
            "compatibility_fallback": false,
            "legacy_js_result_fallback": false,
            "wallet_authority_required": true,
            "wallet_authority_boundary": "wallet.network.mcp_external_exit",
            "ctee_custody_required": true,
            "transport_containment_required": true,
            "custody_ref": authority.custody_ref,
            "containment_ref": authority.containment_ref,
        }),
    )
}

fn mcp_tool_result_payload(
    server_id: &str,
    tool: &str,
    input_hash: &str,
    receipt_id: &str,
) -> Value {
    json!({
        "schema_version": "ioi.model_mount.mcp_result.v1",
        "payload_kind": "mcp_tool_result",
        "materialization_status": "rust_materialized",
        "materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
        "server_id": server_id,
        "tool": tool,
        "input_hash": input_hash,
        "content_receipt_id": receipt_id,
        "result_receipt_id": receipt_id,
        "content": [{
            "type": "text",
            "text": format!(
                "rust_materialized_mcp_tool_result:{}:{}",
                safe_segment(server_id),
                safe_segment(tool)
            )
        }],
        "is_error": false,
        "js_result_synthesis": false,
        "command_transport_fallback": false,
        "binary_bridge_fallback": false,
        "compatibility_fallback": false,
    })
}

fn workflow_node_result_payload(
    node: &str,
    workflow_graph_id: Option<&str>,
    workflow_node_id: &str,
    input_hash: Option<&str>,
    receipt_id: &str,
) -> Value {
    json!({
        "schema_version": "ioi.model_mount.mcp_result.v1",
        "payload_kind": "workflow_node_result",
        "materialization_status": "rust_materialized",
        "materialization_owner": "rust_daemon_core.model_mount.mcp_workflow",
        "node": node,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "input_hash": input_hash,
        "content_receipt_id": receipt_id,
        "result_receipt_id": receipt_id,
        "outputs": {
            "status": "admitted",
            "node": node,
            "workflow_node_id": workflow_node_id,
        },
        "is_error": false,
        "js_result_synthesis": false,
        "command_transport_fallback": false,
        "binary_bridge_fallback": false,
        "compatibility_fallback": false,
    })
}

fn mcp_workflow_plan(
    request: &ModelMountMcpWorkflowRequest,
    record_dir: &str,
    record_id: &str,
    status: &str,
    details: Value,
    public_response: Value,
) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
    let authority_grant_refs = unique_refs(
        request
            .authority_grant_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.body, "authority_grant_refs"))
            .collect(),
    );
    let authority_receipt_refs = unique_refs(
        request
            .authority_receipt_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.body, "authority_receipt_refs"))
            .collect(),
    );
    let external_authority = if matches!(
        request.operation_kind.as_str(),
        "model_mount.mcp_tool.invoke" | "model_mount.workflow_node.execute"
    ) {
        Some(mcp_external_exit_authority(request)?)
    } else {
        None
    };
    let custody_ref = external_authority
        .as_ref()
        .map(|authority| authority.custody_ref.clone())
        .or_else(|| request.custody_ref.clone());
    let containment_ref = external_authority
        .as_ref()
        .map(|authority| authority.containment_ref.clone())
        .or_else(|| request.containment_ref.clone());
    let workflow_hash = hash_json(&json!({
        "operation_kind": request.operation_kind,
        "record_id": record_id,
        "details": details,
    }))?;
    let authority_hash = hash_json(&json!({
        "operation_kind": request.operation_kind,
        "required_scope": request.required_scope,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": custody_ref,
        "containment_ref": containment_ref,
    }))?;
    let mut receipt_refs = Vec::new();
    if let Some(execution_receipt_id) = execution_receipt_id(&details) {
        push_unique_ref(&mut receipt_refs, &execution_receipt_id);
    }
    for receipt_ref in request
        .receipt_refs
        .iter()
        .cloned()
        .chain(string_array_field(&request.body, "receipt_refs"))
    {
        push_unique_ref(&mut receipt_refs, &receipt_ref);
    }
    if let Some(receipt_id) = string_field(object_or_empty(&request.body), "receipt_id") {
        push_unique_ref(&mut receipt_refs, &receipt_id);
    }
    if receipt_refs.is_empty() {
        push_unique_ref(
            &mut receipt_refs,
            &receipt_id_for(&request.operation_kind.replace('.', "_"), record_id),
        );
    }
    let evidence_refs = mcp_workflow_evidence_refs();
    let receipt = mcp_execution_receipt(
        request,
        record_id,
        &details,
        &receipt_refs,
        &authority_grant_refs,
        &authority_receipt_refs,
        custody_ref.as_deref(),
        containment_ref.as_deref(),
        &workflow_hash,
        &authority_hash,
        &evidence_refs,
    )?;
    let record = json!({
        "schema_version": MODEL_MOUNT_MCP_WORKFLOW_PLAN_SCHEMA_VERSION,
        "object": "ioi.model_mount_mcp_workflow",
        "id": record_id,
        "record_dir": record_dir,
        "status": status,
        "operation_kind": request.operation_kind,
        "source": request.source.as_deref().unwrap_or("rust_daemon_core.model_mount.mcp_workflow"),
        "generated_at": request.generated_at,
        "rust_core_boundary": "model_mount.mcp_workflow",
        "details": details,
        "receipt_id": receipt_refs.first().cloned(),
        "receipt_refs": receipt_refs,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": custody_ref,
        "containment_ref": containment_ref,
        "required_scope": request.required_scope,
        "workflow_hash": workflow_hash,
        "authority_hash": authority_hash,
        "evidence_refs": evidence_refs,
    });
    Ok(ModelMountMcpWorkflowPlan {
        schema_version: MODEL_MOUNT_MCP_WORKFLOW_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_mcp_workflow_plan".to_string(),
        status: status.to_string(),
        rust_core_boundary: "model_mount.mcp_workflow".to_string(),
        operation_kind: request.operation_kind.clone(),
        source: request
            .source
            .clone()
            .unwrap_or_else(|| "rust_daemon_core.model_mount.mcp_workflow".to_string()),
        record_dir: record_dir.to_string(),
        record_id: record_id.to_string(),
        record,
        public_response,
        receipt,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        workflow_hash,
        authority_hash,
    })
}

fn execution_receipt_id(details: &Value) -> Option<String> {
    let details = details.as_object()?;
    string_field(details, "tool_receipt_id")
        .or_else(|| string_field(details, "workflow_receipt_id"))
}

fn mcp_execution_receipt(
    request: &ModelMountMcpWorkflowRequest,
    record_id: &str,
    details: &Value,
    receipt_refs: &[String],
    authority_grant_refs: &[String],
    authority_receipt_refs: &[String],
    custody_ref: Option<&str>,
    containment_ref: Option<&str>,
    workflow_hash: &str,
    authority_hash: &str,
    evidence_refs: &[String],
) -> Result<Option<Value>, ModelMountError> {
    if !matches!(
        request.operation_kind.as_str(),
        "model_mount.mcp_tool.invoke" | "model_mount.workflow_node.execute"
    ) {
        return Ok(None);
    }
    let Some(receipt_id) = execution_receipt_id(details) else {
        return Err(ModelMountError::MissingField("receipt_id"));
    };
    let content_hash = hash_json(&json!({
        "operation_kind": request.operation_kind,
        "record_id": record_id,
        "details": details,
        "workflow_hash": workflow_hash,
        "authority_hash": authority_hash,
    }))?;
    let operation_ref = format!(
        "agentgres://model-mounting/mcp-workflow/{}",
        hash_prefix(&json!({
            "record_id": record_id,
            "receipt_id": receipt_id,
            "content_hash": content_hash,
        }))
    );
    let state_root_before = hash_json(&json!({
        "record_id": record_id,
        "operation_kind": request.operation_kind,
        "state": "before_mcp_execution_receipt",
    }))?;
    let state_root_after = hash_json(&json!({
        "operation_ref": operation_ref,
        "content_hash": content_hash,
        "workflow_hash": workflow_hash,
        "authority_hash": authority_hash,
        "state": "after_mcp_execution_receipt",
    }))?;
    let resulting_head = format!(
        "agentgres://model-mounting/mcp-workflow/head/{}",
        state_root_after
            .trim_start_matches("sha256:")
            .chars()
            .take(16)
            .collect::<String>()
    );
    let receipt_kind = if request.operation_kind == "model_mount.mcp_tool.invoke" {
        "mcp_tool_invocation"
    } else {
        "workflow_node_execution"
    };
    let result_payload = details
        .get("result_payload")
        .cloned()
        .unwrap_or(Value::Null);
    let result_payload_hash = details
        .get("result_payload_hash")
        .cloned()
        .unwrap_or(Value::Null);
    let result_materialized = details
        .get("model_mount_mcp_result_materialized")
        .cloned()
        .unwrap_or(json!(false));
    let result_materialization_status = details
        .get("model_mount_mcp_result_materialization_status")
        .cloned()
        .unwrap_or(json!("rust_materialization_missing"));
    let result_materialization_owner = details
        .get("result_materialization_owner")
        .cloned()
        .unwrap_or(Value::Null);
    let result_payload_replay_owner = details
        .get("result_payload_replay_owner")
        .cloned()
        .unwrap_or(Value::Null);
    let mut receipt_evidence_refs = unique_refs(
        evidence_refs
            .iter()
            .cloned()
            .chain([
                "rust_model_mount_core".to_string(),
                "model_mount_mcp_execution_content_receipt_rust_owned".to_string(),
                "model_mount_mcp_result_payload_rust_materialized".to_string(),
                "agentgres_mcp_content_receipt_truth_required".to_string(),
                "receipt_state_root_binding_required".to_string(),
            ])
            .collect(),
    );
    push_unique_ref(&mut receipt_evidence_refs, &operation_ref);
    let step_module_invocation = json!({
        "router": "rust_daemon_core.step_module_router",
        "input": {
            "state_root_before": state_root_before,
            "workflow_hash": workflow_hash,
            "authority_hash": authority_hash,
            "custody_ref": custody_ref,
            "containment_ref": containment_ref,
        }
    });
    let step_module_result = json!({
        "status": "admitted",
        "agentgres_operation_refs": [operation_ref],
        "state_root_after": state_root_after,
        "resulting_head": resulting_head,
        "content_hash": content_hash,
        "result_payload_hash": result_payload_hash,
        "result_materialized": result_materialized,
        "result_materialization_status": result_materialization_status,
        "result_materialization_owner": result_materialization_owner,
    });
    let receipt_details = json!({
        "rust_daemon_core_receipt_author": "model_mount.mcp_workflow",
        "operation_kind": request.operation_kind,
        "model_mount_mcp_workflow_ref": format!("model_mount://mcp_workflow/{}", record_id),
        "model_mount_mcp_record_id": record_id,
        "model_mount_mcp_content_receipt_id": receipt_id,
        "model_mount_mcp_content_hash": content_hash,
        "model_mount_mcp_result_materialized": result_materialized.clone(),
        "model_mount_mcp_result_materialization_status": result_materialization_status.clone(),
        "result_materialization_owner": result_materialization_owner.clone(),
        "result_payload": result_payload,
        "result_payload_hash": result_payload_hash.clone(),
        "result_payload_replay_owner": result_payload_replay_owner,
        "workflow_hash": workflow_hash,
        "authority_hash": authority_hash,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": custody_ref,
        "containment_ref": containment_ref,
        "receipt_refs": receipt_refs,
        "model_mount_agentgres_operation_ref": operation_ref,
        "model_mount_agentgres_state_root_before": state_root_before,
        "model_mount_agentgres_state_root_after": state_root_after,
        "model_mount_agentgres_resulting_head": resulting_head,
        "model_mount_step_module_invocation": step_module_invocation,
        "model_mount_step_module_result": step_module_result,
    });
    Ok(Some(json!({
        "schemaVersion": "ioi.model_mount.mcp_workflow_receipt.v1",
        "id": receipt_id,
        "kind": receipt_kind,
        "redaction": "redacted",
        "summary": if request.operation_kind == "model_mount.mcp_tool.invoke" {
            "Rust model_mount MCP tool execution admitted"
        } else {
            "Rust model_mount workflow node execution admitted"
        },
        "createdAt": request
            .generated_at
            .as_deref()
            .and_then(non_empty_string)
                .unwrap_or_else(|| "rust_model_mount_core".to_string()),
        "evidenceRefs": receipt_evidence_refs,
        "details": receipt_details,
    })))
}

fn mcp_server_record(
    label: &str,
    config: &Map<String, Value>,
    generated_at: Option<&str>,
) -> Result<Value, ModelMountError> {
    let id = string_field(config, "id").unwrap_or_else(|| format!("mcp.{}", safe_segment(label)));
    let server_url = string_field(config, "url").or_else(|| string_field(config, "server_url"));
    let transport = if server_url.is_some() {
        "remote"
    } else {
        "stdio"
    };
    let headers = object_field(config, "headers");
    let env = object_field(config, "env");
    validate_vault_refs(headers.as_ref())?;
    validate_vault_refs(env.as_ref())?;
    let secret_refs = secret_refs_for(&id, headers.as_ref().or(env.as_ref()));
    let redacted_headers = redacted_map(headers.as_ref());
    let allowed_tools = if let Some(values) = config
        .get("allowed_tools")
        .and_then(string_array_field_value)
    {
        values
    } else {
        object_field(config, "tools")
            .map(|tools| tools.keys().cloned().collect())
            .unwrap_or_default()
    };
    let server_hash = hash_json(&json!({
        "id": id,
        "label": label,
        "transport": transport,
        "server_url": server_url,
        "command": string_field(config, "command"),
        "args": json_array_field(config, "args"),
        "allowed_tools": allowed_tools,
        "secret_ref_keys": secret_refs.keys().cloned().collect::<Vec<_>>(),
    }))?;
    Ok(json!({
        "id": id,
        "label": label,
        "transport": transport,
        "command": string_field(config, "command"),
        "args": json_array_field(config, "args"),
        "server_url": server_url,
        "allowed_tools": allowed_tools,
        "secret_refs": secret_refs,
        "redacted_headers": redacted_headers,
        "status": "registered",
        "source": string_field(config, "source").unwrap_or_else(|| "mcp.json".to_string()),
        "imported_at": generated_at,
        "server_hash": server_hash,
        "plaintext_secret_material_returned": false,
        "js_registry_mutation": false,
    }))
}

fn mcp_server_configs_from_body(body: &Map<String, Value>) -> Vec<(String, &Map<String, Value>)> {
    let mut configs = Vec::new();
    collect_server_configs(body.get("mcp_servers"), &mut configs);
    collect_server_configs(body.get("servers"), &mut configs);
    if let Some(mcp_json) = body.get("mcp_json").and_then(Value::as_object) {
        collect_server_configs(mcp_json.get("mcp_servers"), &mut configs);
        collect_server_configs(mcp_json.get("servers"), &mut configs);
    }
    configs
}

fn collect_server_configs<'a>(
    value: Option<&'a Value>,
    configs: &mut Vec<(String, &'a Map<String, Value>)>,
) {
    if let Some(servers) = value.and_then(Value::as_object) {
        for (label, config) in servers {
            if let Some(config) = config.as_object() {
                configs.push((label.clone(), config));
            }
        }
    }
}

fn validate_vault_refs(value: Option<&Map<String, Value>>) -> Result<(), ModelMountError> {
    if let Some(value) = value {
        for secret in value.values() {
            let Some(secret) = secret.as_str() else {
                return Err(ModelMountError::MissingField("vault_ref"));
            };
            if !secret.trim().starts_with("vault://") {
                return Err(ModelMountError::MissingField("vault_ref"));
            }
        }
    }
    Ok(())
}

struct McpExternalExitAuthority {
    authority_grant_refs: Vec<String>,
    authority_receipt_refs: Vec<String>,
    custody_ref: String,
    containment_ref: String,
}

fn require_mcp_external_exit_authority(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<(), ModelMountError> {
    mcp_external_exit_authority(request).map(|_| ())
}

fn mcp_external_exit_authority(
    request: &ModelMountMcpWorkflowRequest,
) -> Result<McpExternalExitAuthority, ModelMountError> {
    let authority_grant_refs = unique_refs(
        request
            .authority_grant_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.body, "authority_grant_refs"))
            .collect(),
    );
    if authority_grant_refs.is_empty() {
        return Err(ModelMountError::MissingField("authority_grant_refs"));
    }
    let authority_receipt_refs = unique_refs(
        request
            .authority_receipt_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.body, "authority_receipt_refs"))
            .collect(),
    );
    if authority_receipt_refs.is_empty() {
        return Err(ModelMountError::MissingField("authority_receipt_refs"));
    }
    let body = object_or_empty(&request.body);
    let custody_ref = request
        .custody_ref
        .as_deref()
        .and_then(non_empty_string)
        .or_else(|| string_field(body, "custody_ref"))
        .ok_or(ModelMountError::MissingField("custody_ref"))?;
    let containment_ref = request
        .containment_ref
        .as_deref()
        .and_then(non_empty_string)
        .or_else(|| string_field(body, "containment_ref"))
        .ok_or(ModelMountError::MissingField("containment_ref"))?;
    Ok(McpExternalExitAuthority {
        authority_grant_refs,
        authority_receipt_refs,
        custody_ref,
        containment_ref,
    })
}

fn mcp_workflow_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.mcp_server.import"
            | "model_mount.mcp_server.ephemeral_register"
            | "model_mount.mcp_tool.invoke"
            | "model_mount.workflow_node.execute"
    )
}

fn mcp_workflow_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_model_mount_mcp_workflow".to_string(),
        "agentgres_mcp_workflow_truth_required".to_string(),
        "model_mount_mcp_workflow_js_facade_retired".to_string(),
        "model_mount_mcp_import_js_facade_retired".to_string(),
        "model_mount_ephemeral_mcp_registration_js_facade_retired".to_string(),
        "model_mount_mcp_tool_invocation_js_facade_retired".to_string(),
        "model_mount_workflow_node_execution_js_facade_retired".to_string(),
        "wallet_network_mcp_external_exit_authority_required".to_string(),
        "ctee_mcp_external_exit_custody_required".to_string(),
        "mcp_transport_containment_required".to_string(),
        "model_mount_mcp_workflow_receipt_synthesis_js_retired".to_string(),
        "model_mount_mcp_workflow_record_state_js_retired".to_string(),
        "model_mount_mcp_result_payload_rust_materialized".to_string(),
    ]
}

fn object_or_empty(value: &Value) -> &Map<String, Value> {
    value.as_object().unwrap_or_else(|| empty_map())
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn required_body_string(
    body: &Map<String, Value>,
    key: &'static str,
) -> Result<String, ModelMountError> {
    string_field(body, key).ok_or(ModelMountError::MissingField(key))
}

fn string_field(body: &Map<String, Value>, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn object_field(body: &Map<String, Value>, key: &str) -> Option<Map<String, Value>> {
    body.get(key).and_then(Value::as_object).cloned()
}

fn json_array_field(body: &Map<String, Value>, key: &str) -> Vec<Value> {
    body.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn integer_field(body: &Map<String, Value>, key: &str) -> Option<i64> {
    body.get(key).and_then(Value::as_i64)
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(string_array_field_value)
        .unwrap_or_default()
}

fn string_array_field_value(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .filter_map(non_empty_string)
            .collect()
    })
}

fn unique_refs(values: Vec<String>) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        push_unique_ref(&mut refs, &value);
    }
    refs
}

fn secret_refs_for(id: &str, secrets: Option<&Map<String, Value>>) -> Map<String, Value> {
    let mut refs = Map::new();
    if let Some(secrets) = secrets {
        for key in secrets.keys() {
            refs.insert(
                key.clone(),
                json!(format!("vault://{}/{}", id, safe_segment(key))),
            );
        }
    }
    refs
}

fn redacted_map(headers: Option<&Map<String, Value>>) -> Map<String, Value> {
    let mut redacted = Map::new();
    if let Some(headers) = headers {
        for key in headers.keys() {
            redacted.insert(key.clone(), json!("[REDACTED]"));
        }
    }
    redacted
}

fn receipt_id_for(kind: &str, seed: &str) -> String {
    format!("receipt.{}.{}", safe_segment(kind), safe_segment(seed))
}

fn hash_prefix(value: &Value) -> String {
    hash_json(value)
        .ok()
        .and_then(|hash| {
            hash.strip_prefix("sha256:")
                .map(|value| value[..12].to_string())
        })
        .unwrap_or_else(|| "hash_failed".to_string())
}

fn hash_text(value: &str) -> Result<String, ModelMountError> {
    Ok(format!("sha256:{}", sha256_hex(value.as_bytes())?))
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)?))
}

fn safe_segment(value: &str) -> String {
    let mut output = String::new();
    let mut last_dot = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
            last_dot = false;
        } else if !last_dot {
            output.push('.');
            last_dot = true;
        }
    }
    let trimmed = output.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn import_request() -> ModelMountMcpWorkflowRequest {
        ModelMountMcpWorkflowRequest {
            schema_version: MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.mcp_server.import".to_string(),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body: json!({
                "mcp_servers": {
                    "Docs MCP": {
                        "url": "https://example.test/mcp",
                        "headers": { "Authorization": "vault://mcp/docs/token" },
                        "allowed_tools": ["search", "read"]
                    }
                }
            }),
            receipt_refs: vec![],
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
            custody_ref: None,
            containment_ref: None,
            required_scope: Some("model.mcp.import".to_string()),
        }
    }

    #[test]
    fn rust_plans_model_mount_mcp_import_records() {
        let plan = plan_mcp_workflow(&import_request()).expect("mcp import plan");

        assert_eq!(plan.record_dir, "mcp-servers");
        assert_eq!(plan.operation_kind, "model_mount.mcp_server.import");
        assert_eq!(plan.rust_core_boundary, "model_mount.mcp_workflow");
        assert_eq!(plan.record["details"]["server_ids"][0], "mcp.docs.mcp");
        assert_eq!(
            plan.record["details"]["servers"][0]["redacted_headers"]["Authorization"],
            "[REDACTED]"
        );
        assert_eq!(
            plan.record["details"]["servers"][0]["secret_refs"]["Authorization"],
            "vault://mcp.docs.mcp/authorization"
        );
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_model_mount_mcp_workflow".to_string()));
        assert!(!plan.receipt_refs.is_empty());
    }

    #[test]
    fn rust_core_plans_model_mount_mcp_workflow_direct_api() {
        let mut request = import_request();
        request.source = None;
        let plan = plan_mcp_workflow(&request).expect("mcp workflow direct api plan");

        assert_eq!(plan.source, "rust_daemon_core.model_mount.mcp_workflow");
        assert_eq!(plan.record_dir, "mcp-servers");
        assert_eq!(plan.rust_core_boundary, "model_mount.mcp_workflow");
        assert!(plan.workflow_hash.starts_with("sha256:"));
        assert!(plan.authority_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_admits_model_mount_mcp_tool_invocation_without_js_or_command_fallback() {
        let mut request = import_request();
        request.operation_kind = "model_mount.mcp_tool.invoke".to_string();
        request.body = json!({
            "server_id": "mcp.docs",
            "tool": "search",
            "input": { "query": "rust" },
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"],
            "custody_ref": "ctee://workspace/docs",
            "containment_ref": "containment://mcp/docs"
        });

        let plan = plan_mcp_workflow(&request).expect("mcp tool plan");

        assert_eq!(plan.record_dir, "mcp-workflow-controls");
        assert_eq!(plan.status, "admitted");
        assert_eq!(plan.record["status"], "admitted");
        assert_eq!(plan.record["details"]["server_id"], "mcp.docs");
        assert_eq!(plan.record["details"]["tool"], "search");
        assert_eq!(plan.record["details"]["js_transport_invocation"], false);
        assert_eq!(
            plan.public_response["transport_execution_status"],
            "rust_admitted"
        );
        assert_eq!(
            plan.public_response["rust_transport_execution_admitted"],
            true
        );
        assert_eq!(
            plan.public_response["transport_execution_owner"],
            "rust_daemon_core.model_mount.mcp_workflow"
        );
        assert_eq!(
            plan.public_response["step_module_dispatch_owner"],
            "rust_daemon_core.step_module_router"
        );
        assert_eq!(plan.public_response["content_receipt_required"], true);
        assert_eq!(
            plan.public_response["result_receipt_id"],
            plan.public_response["content_receipt_id"]
        );
        assert_eq!(
            plan.public_response["model_mount_mcp_result_materialized"],
            true
        );
        assert_eq!(
            plan.public_response["model_mount_mcp_result_materialization_status"],
            "rust_materialized"
        );
        assert_eq!(
            plan.public_response["result_materialization_owner"],
            "rust_daemon_core.model_mount.mcp_workflow"
        );
        assert_eq!(
            plan.public_response["result_payload"]["payload_kind"],
            "mcp_tool_result"
        );
        assert!(plan.public_response["result_payload_hash"]
            .as_str()
            .expect("result payload hash")
            .starts_with("sha256:"));
        let receipt = plan.receipt.as_ref().expect("mcp execution receipt");
        assert_eq!(receipt["kind"], "mcp_tool_invocation");
        assert_eq!(receipt["id"], plan.public_response["content_receipt_id"]);
        assert_eq!(
            receipt["details"]["rust_daemon_core_receipt_author"],
            "model_mount.mcp_workflow"
        );
        assert_eq!(
            receipt["details"]["model_mount_mcp_result_materialized"],
            true
        );
        assert_eq!(
            receipt["details"]["model_mount_mcp_result_materialization_status"],
            "rust_materialized"
        );
        assert_eq!(
            receipt["details"]["result_payload_hash"],
            plan.public_response["result_payload_hash"]
        );
        assert_eq!(
            receipt["details"]["model_mount_step_module_result"]["result_materialized"],
            true
        );
        assert_eq!(
            receipt["details"]["model_mount_step_module_result"]["result_payload_hash"],
            plan.public_response["result_payload_hash"]
        );
        assert_eq!(
            receipt["details"]["model_mount_step_module_result"]["state_root_after"],
            receipt["details"]["model_mount_agentgres_state_root_after"]
        );
        assert!(receipt["evidenceRefs"]
            .as_array()
            .expect("receipt evidence")
            .iter()
            .any(|value| value == "model_mount_mcp_execution_content_receipt_rust_owned"));
        assert!(receipt["evidenceRefs"]
            .as_array()
            .expect("receipt evidence")
            .iter()
            .any(|value| value == "model_mount_mcp_result_payload_rust_materialized"));
        assert_eq!(plan.public_response["command_transport_fallback"], false);
        assert_eq!(plan.public_response["binary_bridge_fallback"], false);
        assert_eq!(plan.public_response["compatibility_fallback"], false);
        assert_eq!(plan.public_response["legacy_js_result_fallback"], false);
        assert_eq!(plan.public_response["wallet_authority_required"], true);
        assert_eq!(
            plan.authority_grant_refs[0],
            "wallet.network://grant/mcp/docs/search"
        );
        assert_eq!(
            plan.record["details"]["wallet_authority_boundary"],
            "wallet.network.mcp_external_exit"
        );
        assert_eq!(plan.record["details"]["ctee_custody_required"], true);
        assert_eq!(
            plan.record["details"]["transport_containment_required"],
            true
        );
        assert_eq!(
            plan.record["details"]["custody_ref"],
            "ctee://workspace/docs"
        );
        assert_eq!(
            plan.record["details"]["containment_ref"],
            "containment://mcp/docs"
        );
        assert_eq!(plan.record["containment_ref"], "containment://mcp/docs");
        let mut different_containment = request.clone();
        different_containment.body["containment_ref"] = json!("containment://mcp/docs/other");
        let different_plan =
            plan_mcp_workflow(&different_containment).expect("different containment plan");
        assert_ne!(plan.authority_hash, different_plan.authority_hash);
    }

    #[test]
    fn rust_admits_model_mount_workflow_node_dispatch_without_js_fallback() {
        let mut request = import_request();
        request.operation_kind = "model_mount.workflow_node.execute".to_string();
        request.body = json!({
            "node": "Embed",
            "workflow_graph_id": "graph.docs",
            "workflow_node_id": "node.embed",
            "workflow_node_type": "Embedding",
            "input": { "text": "rust" },
            "authority_grant_refs": ["wallet.network://grant/workflow/node/embed"],
            "authority_receipt_refs": ["receipt://wallet.network/workflow/node/embed"],
            "custody_ref": "ctee://workspace/workflow",
            "containment_ref": "containment://workflow/node/embed"
        });

        let plan = plan_mcp_workflow(&request).expect("workflow node plan");

        assert_eq!(plan.record_dir, "mcp-workflow-controls");
        assert_eq!(plan.status, "admitted");
        assert_eq!(plan.public_response["execution_status"], "rust_admitted");
        assert_eq!(
            plan.public_response["rust_step_module_dispatch_admitted"],
            true
        );
        assert_eq!(
            plan.public_response["workflow_execution_owner"],
            "rust_daemon_core.model_mount.mcp_workflow"
        );
        assert_eq!(
            plan.public_response["step_module_dispatch_owner"],
            "rust_daemon_core.step_module_router"
        );
        assert_eq!(plan.public_response["content_receipt_required"], true);
        assert_eq!(
            plan.public_response["result_receipt_id"],
            plan.public_response["content_receipt_id"]
        );
        assert_eq!(
            plan.public_response["model_mount_mcp_result_materialized"],
            true
        );
        assert_eq!(
            plan.public_response["model_mount_mcp_result_materialization_status"],
            "rust_materialized"
        );
        assert_eq!(
            plan.public_response["result_payload"]["payload_kind"],
            "workflow_node_result"
        );
        let receipt = plan.receipt.as_ref().expect("workflow execution receipt");
        assert_eq!(receipt["kind"], "workflow_node_execution");
        assert_eq!(receipt["id"], plan.public_response["content_receipt_id"]);
        assert_eq!(
            receipt["details"]["rust_daemon_core_receipt_author"],
            "model_mount.mcp_workflow"
        );
        assert_eq!(
            receipt["details"]["model_mount_mcp_result_materialization_status"],
            "rust_materialized"
        );
        assert_eq!(
            receipt["details"]["model_mount_mcp_result_materialized"],
            true
        );
        assert_eq!(
            receipt["details"]["result_payload"]["payload_kind"],
            "workflow_node_result"
        );
        assert_eq!(
            receipt["details"]["model_mount_step_module_result"]["result_materialized"],
            true
        );
        assert!(receipt["details"]["model_mount_agentgres_operation_ref"]
            .as_str()
            .unwrap()
            .starts_with("agentgres://model-mounting/mcp-workflow/"));
        assert_eq!(plan.public_response["js_route_test"], false);
        assert_eq!(plan.public_response["js_model_invocation"], false);
        assert_eq!(plan.public_response["js_mcp_tool_invocation"], false);
        assert_eq!(plan.public_response["command_transport_fallback"], false);
        assert_eq!(plan.public_response["binary_bridge_fallback"], false);
        assert_eq!(plan.public_response["compatibility_fallback"], false);
        assert_eq!(plan.public_response["legacy_js_result_fallback"], false);
        assert_eq!(
            plan.record["details"]["containment_ref"],
            "containment://workflow/node/embed"
        );
    }

    #[test]
    fn rust_rejects_model_mount_mcp_tool_invocation_without_wallet_authority() {
        let mut request = import_request();
        request.operation_kind = "model_mount.mcp_tool.invoke".to_string();
        request.body = json!({
            "server_id": "mcp.docs",
            "tool": "search",
            "input": { "query": "rust" }
        });

        assert_eq!(
            plan_mcp_workflow(&request).expect_err("wallet authority required"),
            ModelMountError::MissingField("authority_grant_refs")
        );
    }

    #[test]
    fn rust_rejects_model_mount_mcp_tool_invocation_without_custody_or_containment() {
        let mut request = import_request();
        request.operation_kind = "model_mount.mcp_tool.invoke".to_string();
        request.body = json!({
            "server_id": "mcp.docs",
            "tool": "search",
            "input": { "query": "rust" },
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"]
        });

        assert_eq!(
            plan_mcp_workflow(&request).expect_err("custody ref required"),
            ModelMountError::MissingField("custody_ref")
        );

        request.body = json!({
            "server_id": "mcp.docs",
            "tool": "search",
            "input": { "query": "rust" },
            "authority_grant_refs": ["wallet.network://grant/mcp/docs/search"],
            "authority_receipt_refs": ["receipt://wallet.network/mcp/docs/search"],
            "custody_ref": "ctee://workspace/docs"
        });

        assert_eq!(
            plan_mcp_workflow(&request).expect_err("containment ref required"),
            ModelMountError::MissingField("containment_ref")
        );
    }

    #[test]
    fn rust_rejects_model_mount_mcp_plaintext_secrets() {
        let mut request = import_request();
        request.body = json!({
            "mcp_servers": {
                "Bad": {
                    "url": "https://example.test/mcp",
                    "headers": { "Authorization": "plaintext" }
                }
            }
        });

        assert!(matches!(
            plan_mcp_workflow(&request),
            Err(ModelMountError::MissingField("vault_ref"))
        ));
    }
}
