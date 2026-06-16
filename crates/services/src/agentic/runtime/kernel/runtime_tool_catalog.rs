use serde::Deserialize;
use serde_json::{json, Value};

pub const RUNTIME_TOOL_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.tool-catalog-projection-request.v1";
pub const RUNTIME_TOOL_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.tool-catalog-projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeToolCatalogProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub operator_email: Option<String>,
    #[serde(default)]
    pub hosted_endpoint_configured: bool,
    #[serde(default)]
    pub self_hosted_endpoint_configured: bool,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeToolCatalogProjectionError {
    code: &'static str,
    message: String,
}

impl RuntimeToolCatalogProjectionError {
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
pub struct RuntimeToolCatalogProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeToolCatalogProjectionRecord {
    pub object: String,
    pub status: String,
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub pack: Option<String>,
    pub workspace_root: Option<String>,
    pub account: Option<Value>,
    pub runtime_nodes: Vec<Value>,
    pub tools: Vec<Value>,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

impl RuntimeToolCatalogProjectionCore {
    pub fn project(
        &self,
        request: RuntimeToolCatalogProjectionRequest,
    ) -> Result<RuntimeToolCatalogProjectionRecord, RuntimeToolCatalogProjectionError> {
        let projection_kind = normalized_projection_kind(&request)?;
        let operation_kind =
            request
                .operation_kind
                .clone()
                .unwrap_or_else(|| match projection_kind.as_str() {
                    "account" => "runtime.tool_catalog.projection.account".to_string(),
                    "runtime_nodes" => "runtime.tool_catalog.projection.runtime_nodes".to_string(),
                    "tools" => "runtime.tool_catalog.projection.tools".to_string(),
                    _ => "runtime.tool_catalog.projection.unknown".to_string(),
                });
        let pack = optional_trimmed_lower(request.pack.as_deref());
        let mut record = RuntimeToolCatalogProjectionRecord {
            object: "ioi.runtime_tool_catalog_projection".to_string(),
            status: "projected".to_string(),
            operation: request
                .operation
                .clone()
                .unwrap_or_else(|| "runtime_tool_catalog".to_string()),
            operation_kind,
            projection_kind: projection_kind.clone(),
            pack: pack.clone(),
            workspace_root: optional_trimmed(request.workspace_root.as_deref()),
            account: None,
            runtime_nodes: vec![],
            tools: vec![],
            record_count: 0,
            evidence_refs: vec![
                "rust_daemon_core_runtime_tool_catalog_projection".to_string(),
                "agentgres_runtime_tool_catalog_truth_required".to_string(),
            ],
            receipt_refs: vec![format!(
                "receipt_runtime_tool_catalog_projection_{}",
                projection_kind
            )],
        };

        match projection_kind.as_str() {
            "account" => {
                record.account = Some(runtime_account(request.operator_email.as_deref()));
                record.record_count = 1;
            }
            "runtime_nodes" => {
                record.runtime_nodes = runtime_nodes(
                    request.hosted_endpoint_configured,
                    request.self_hosted_endpoint_configured,
                );
                record.record_count = record.runtime_nodes.len();
            }
            "tools" => {
                record.tools = runtime_tools(pack.as_deref());
                record.record_count = record.tools.len();
            }
            _ => {
                return Err(RuntimeToolCatalogProjectionError::new(
                    "runtime_tool_catalog_projection_kind_invalid",
                    format!("unsupported runtime tool catalog projection kind {projection_kind}"),
                ));
            }
        }
        Ok(record)
    }
}

impl RuntimeToolCatalogProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_TOOL_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": self.object,
            "status": self.status,
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "pack": self.pack,
            "workspace_root": self.workspace_root,
            "account": self.account,
            "runtime_nodes": self.runtime_nodes,
            "tools": self.tools,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn normalized_projection_kind(
    request: &RuntimeToolCatalogProjectionRequest,
) -> Result<String, RuntimeToolCatalogProjectionError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if operation_kind.ends_with(".account") {
        return Ok("account".to_string());
    }
    if operation_kind.ends_with(".runtime_nodes") {
        return Ok("runtime_nodes".to_string());
    }
    if operation_kind.ends_with(".tools") {
        return Ok("tools".to_string());
    }
    Err(RuntimeToolCatalogProjectionError::new(
        "runtime_tool_catalog_projection_kind_required",
        "runtime tool catalog projection kind is required",
    ))
}

fn runtime_account(operator_email: Option<&str>) -> Value {
    json!({
        "id": "local-operator",
        "email": optional_trimmed(operator_email),
        "authorityLevel": "local",
        "privacyClass": "local_private",
        "source": "rust-daemon-core-agentgres",
    })
}

fn runtime_nodes(
    hosted_endpoint_configured: bool,
    self_hosted_endpoint_configured: bool,
) -> Vec<Value> {
    vec![
        json!({
            "id": "local-daemon-agentgres",
            "kind": "local",
            "status": "available",
            "endpoint": "local",
            "privacyClass": "local_private",
            "evidence_refs": [
                "agentgres_canonical_state_projection",
                "rust_daemon_core_runtime_tool_catalog_projection",
            ],
        }),
        json!({
            "id": "hosted-provider",
            "kind": "hosted",
            "status": if hosted_endpoint_configured { "available" } else { "blocked" },
            "endpoint": null,
            "privacyClass": "hosted",
            "evidence_refs": ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
        }),
        json!({
            "id": "self-hosted-provider",
            "kind": "self_hosted",
            "status": if self_hosted_endpoint_configured { "available" } else { "blocked" },
            "endpoint": null,
            "privacyClass": "workspace",
            "evidence_refs": ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
        }),
    ]
}

fn runtime_tools(pack: Option<&str>) -> Vec<Value> {
    let tools = vec![
        tool_contract(
            "fs.read",
            "Read file",
            "runtime",
            &["prim:fs.read"],
            &[],
            "local_read",
            "filesystem",
            &["file_read_receipt"],
            None,
            &[],
        ),
        tool_contract(
            "sys.exec",
            "Shell command",
            "runtime",
            &["prim:sys.exec"],
            &["scope:host.controlled_execution"],
            "local_command",
            "host",
            &["shell_receipt", "sandbox_profile"],
            None,
            &[],
        ),
        tool_contract(
            "mcp.invoke",
            "MCP tool invocation",
            "runtime",
            &["prim:connector.invoke"],
            &["scope:mcp.invoke"],
            "connector_call",
            "connector",
            &["mcp_containment_receipt"],
            None,
            &[],
        ),
        tool_contract(
            "workspace.status",
            "Workspace status",
            "coding",
            &["prim:workspace.status", "prim:git.status"],
            &[],
            "local_read",
            "filesystem",
            &["workspace_status_receipt"],
            Some("CodingToolNode"),
            &[],
        ),
        tool_contract(
            "git.diff",
            "Git diff",
            "coding",
            &["prim:git.diff"],
            &[],
            "local_read",
            "git",
            &["git_diff_receipt"],
            Some("GitToolNode"),
            &["path"],
        ),
        tool_contract(
            "file.inspect",
            "Inspect file",
            "coding",
            &["prim:fs.inspect"],
            &[],
            "local_read",
            "filesystem",
            &["file_inspection_receipt"],
            Some("FilesystemToolNode"),
            &["path"],
        ),
        tool_contract(
            "file.apply_patch",
            "Apply patch",
            "coding",
            &["prim:fs.apply_patch", "prim:fs.write"],
            &["scope:workspace.write"],
            "local_command",
            "filesystem",
            &["file_patch_receipt", "workspace_snapshot_receipt"],
            Some("FilesystemPatchNode"),
            &["path", "edits"],
        ),
        tool_contract(
            "test.run",
            "Run tests",
            "coding",
            &["prim:test.run", "prim:process.exec_file"],
            &["scope:workspace.test"],
            "local_command",
            "host",
            &["test_run_receipt", "sandbox_profile"],
            Some("TestRunNode"),
            &["command_id", "path"],
        ),
        tool_contract(
            "lsp.diagnostics",
            "LSP diagnostics",
            "coding",
            &["prim:lsp.diagnostics", "prim:process.exec_file"],
            &[],
            "local_read",
            "diagnostics",
            &["diagnostics_receipt"],
            Some("LspDiagnosticsNode"),
            &["command_id", "path"],
        ),
        tool_contract(
            "artifact.read",
            "Read artifact",
            "coding",
            &["prim:artifact.read"],
            &[],
            "local_read",
            "artifact",
            &["artifact_read_receipt"],
            Some("ArtifactReadNode"),
            &["artifact_id"],
        ),
        tool_contract(
            "tool.retrieve_result",
            "Retrieve tool result",
            "coding",
            &["prim:tool.retrieve_result", "prim:artifact.read"],
            &[],
            "local_read",
            "tool_result",
            &["tool_result_receipt"],
            Some("ToolResultRetrievalNode"),
            &["tool_call_id"],
        ),
        tool_contract(
            "computer_use.request_lease",
            "Request computer-use lease",
            "coding",
            &[
                "prim:computer_use.lease.request",
                "prim:computer_use.manifest",
            ],
            &["computer_use.lease.request"],
            "external_control",
            "computer_use",
            &["computer_use_lease_receipt"],
            Some("ComputerUseLeaseRequestNode"),
            &["provider_id"],
        ),
    ];
    match pack {
        Some(pack) => tools
            .into_iter()
            .filter(|tool| tool.get("pack").and_then(Value::as_str) == Some(pack))
            .collect(),
        None => tools,
    }
}

fn tool_contract(
    stable_tool_id: &str,
    display_name: &str,
    pack: &str,
    primitive_capabilities: &[&str],
    authority_scope_requirements: &[&str],
    effect_class: &str,
    risk_domain: &str,
    evidence_requirements: &[&str],
    workflow_node_type: Option<&str>,
    workflow_config_fields: &[&str],
) -> Value {
    let approval_required =
        !authority_scope_requirements.is_empty() || !runtime_tool_effect_is_read_only(effect_class);
    json!({
        "schema_version": "ioi.runtime.coding-tool-pack.v1",
        "stable_tool_id": stable_tool_id,
        "display_name": display_name,
        "pack": pack,
        "primitive_capabilities": primitive_capabilities,
        "authority_scope_requirements": authority_scope_requirements,
        "effect_class": effect_class,
        "risk_domain": risk_domain,
        "input_schema": { "type": "object" },
        "output_schema": { "type": "object" },
        "evidence_requirements": evidence_requirements,
        "credential_ready": !runtime_tool_likely_requires_credential(stable_tool_id, risk_domain, effect_class),
        "credential_readiness": {
            "status": if runtime_tool_likely_requires_credential(stable_tool_id, risk_domain, effect_class) { "unknown" } else { "not_required" },
            "checked_at": null,
            "evidence_refs": [],
            "reason": null,
        },
        "approval_required": approval_required,
        "rate_limit_profile": {
            "policy": if runtime_tool_effect_is_read_only(effect_class) { "unlimited_local_read" } else { "runtime_governed" },
            "scope": stable_tool_id,
            "max_calls": null,
            "window_ms": null,
            "burst": null,
            "evidence_refs": [],
        },
        "idempotency_behavior": {
            "required": !runtime_tool_effect_is_read_only(effect_class),
            "strategy": if runtime_tool_effect_is_read_only(effect_class) { "read_only" } else { "runtime_key" },
            "key_scope": if runtime_tool_effect_is_read_only(effect_class) { Value::Null } else { json!(stable_tool_id) },
            "evidence_refs": [],
        },
        "receipt_behavior": {
            "emits_receipt": !evidence_requirements.is_empty(),
            "receipt_required": !evidence_requirements.is_empty(),
            "required_receipt_types": evidence_requirements,
            "evidence_requirements": evidence_requirements,
        },
        "workflow_availability": {
            "available": workflow_node_type.is_some(),
            "reason": if workflow_node_type.is_some() { Value::Null } else { json!("No workflow node projection registered.") },
            "node_type": workflow_node_type,
            "config_fields": workflow_config_fields,
            "evidence_refs": [],
        },
        "agent_availability": {
            "available": true,
            "reason": null,
            "node_type": null,
            "config_fields": [],
            "evidence_refs": [],
        },
        "marketplace_exposure": {
            "eligible": !approval_required && !runtime_tool_likely_requires_credential(stable_tool_id, risk_domain, effect_class) && runtime_tool_effect_is_read_only(effect_class),
            "reason": if !approval_required && !runtime_tool_likely_requires_credential(stable_tool_id, risk_domain, effect_class) && runtime_tool_effect_is_read_only(effect_class) {
                "Read-only tool is eligible for governed exposure."
            } else {
                "Requires authority review before exposure."
            },
            "trust_required": approval_required,
            "version_pinned": true,
            "evidence_refs": [],
        },
        "workflow_node_type": workflow_node_type,
        "workflow_config_fields": workflow_config_fields,
    })
}

fn runtime_tool_effect_is_read_only(effect_class: &str) -> bool {
    let normalized = effect_class.trim().to_lowercase();
    normalized == "read" || normalized == "local_read" || normalized.ends_with("_read")
}

fn runtime_tool_likely_requires_credential(
    stable_tool_id: &str,
    risk_domain: &str,
    effect_class: &str,
) -> bool {
    let haystack = format!("{stable_tool_id} {risk_domain} {effect_class}").to_lowercase();
    haystack.contains("connector")
        || haystack.contains("mcp")
        || haystack.contains("model")
        || haystack.contains("oauth")
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(projection_kind: &str) -> RuntimeToolCatalogProjectionRequest {
        RuntimeToolCatalogProjectionRequest {
            operation: Some("runtime_tool_catalog".to_string()),
            operation_kind: Some(format!("runtime.tool_catalog.projection.{projection_kind}")),
            projection_kind: Some(projection_kind.to_string()),
            workspace_root: Some("/workspace/project".to_string()),
            ..RuntimeToolCatalogProjectionRequest::default()
        }
    }

    #[test]
    fn rust_projects_runtime_tool_catalog_tools() {
        let mut request = base_request("tools");
        request.pack = Some("coding".to_string());
        let record = RuntimeToolCatalogProjectionCore::default()
            .project(request)
            .expect("runtime tool catalog projection");

        assert_eq!(record.status, "projected");
        assert_eq!(record.projection_kind, "tools");
        assert!(record
            .tools
            .iter()
            .any(|tool| tool["stable_tool_id"] == "file.apply_patch"));
        assert!(record.tools.iter().all(|tool| tool["pack"] == "coding"));
        assert!(record.tools[0].get("stableToolId").is_none());
        assert!(record.receipt_refs[0].starts_with("receipt_runtime_tool_catalog_projection_"));
    }

    #[test]
    fn rust_projects_runtime_account() {
        let mut request = base_request("account");
        request.operator_email = Some("operator@example.test".to_string());
        let record = RuntimeToolCatalogProjectionCore::default()
            .project(request)
            .expect("runtime account projection");

        let account = record.account.as_ref().expect("account");
        assert_eq!(account["id"], "local-operator");
        assert_eq!(account["email"], "operator@example.test");
        assert_eq!(record.record_count, 1);
    }

    #[test]
    fn rust_projects_runtime_nodes_without_endpoint_values() {
        let mut request = base_request("runtime_nodes");
        request.hosted_endpoint_configured = true;
        let record = RuntimeToolCatalogProjectionCore::default()
            .project(request)
            .expect("runtime nodes projection");

        assert_eq!(record.runtime_nodes.len(), 3);
        assert_eq!(record.runtime_nodes[1]["status"], "available");
        assert!(record.runtime_nodes[1]["endpoint"].is_null());
    }

    #[test]
    fn rust_shapes_runtime_tool_catalog_direct_record() {
        let record = RuntimeToolCatalogProjectionCore::default()
            .project(RuntimeToolCatalogProjectionRequest {
                projection_kind: Some("tools".to_string()),
                pack: Some("runtime".to_string()),
                ..RuntimeToolCatalogProjectionRequest::default()
            })
            .expect("runtime tool catalog direct record");
        let record = record.to_value();

        assert_eq!(record["projection_kind"], "tools");
        assert!(record["record_count"].as_u64().unwrap() >= 3);
    }
}
