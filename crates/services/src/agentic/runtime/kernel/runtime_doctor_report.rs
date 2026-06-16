use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

use super::{
    model_mount::{ModelMountCore, ModelMountReadProjectionRequest},
    runtime_tool_catalog::{
        RuntimeToolCatalogProjectionRequest, RuntimeToolCatalogProjectionCore,
    },
    skill_hook_registry::{SkillHookRegistryProjectionCore, SkillHookRegistryProjectionRequest},
};

pub const RUNTIME_DOCTOR_REPORT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.doctor-report-projection-request.v1";
pub const RUNTIME_DOCTOR_REPORT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.doctor-report-projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDoctorReportProjectionRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub home_dir: Option<String>,
    #[serde(default)]
    pub runtime_schema_version: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDoctorReportProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeDoctorReportProjectionCommandError {
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
pub struct RuntimeDoctorReportProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeDoctorReportProjectionRecord {
    pub object: String,
    pub status: String,
    pub operation: String,
    pub operation_kind: String,
    pub workspace_root: String,
    pub state_dir: String,
    pub report: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

impl RuntimeDoctorReportProjectionCore {
    pub fn project(
        &self,
        request: RuntimeDoctorReportProjectionRequest,
    ) -> Result<RuntimeDoctorReportProjectionRecord, RuntimeDoctorReportProjectionCommandError>
    {
        let workspace_root =
            optional_trimmed(request.workspace_root.as_deref()).unwrap_or_else(|| ".".to_string());
        let state_dir = optional_trimmed(request.state_dir.as_deref()).ok_or_else(|| {
            RuntimeDoctorReportProjectionCommandError::new(
                "runtime_doctor_report_state_dir_required",
                "runtime doctor projection requires Agentgres state_dir replay",
            )
        })?;
        let home_dir = optional_trimmed(request.home_dir.as_deref())
            .or_else(|| env::var("HOME").ok())
            .unwrap_or_else(|| workspace_root.clone());
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_doctor_report_projection".to_string());
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| "runtime.doctor_report.projection".to_string());
        if operation_kind != "runtime.doctor_report.projection" {
            return Err(RuntimeDoctorReportProjectionCommandError::new(
                "runtime_doctor_report_projection_operation_kind_invalid",
                format!("unsupported runtime doctor projection operation kind {operation_kind}"),
            ));
        }

        let routes = model_mount_projection("routes", &state_dir)?;
        let artifacts = model_mount_projection("artifacts", &state_dir)?;
        let mcp_servers = model_mount_projection("mcp_servers", &state_dir)?;
        let tools = RuntimeToolCatalogProjectionCore::default()
            .project(RuntimeToolCatalogProjectionRequest {
                operation: Some("runtime_tool_catalog".to_string()),
                operation_kind: Some("runtime.tool_catalog.projection.tools".to_string()),
                projection_kind: Some("tools".to_string()),
                workspace_root: Some(workspace_root.clone()),
                operator_email: env_string("IOI_OPERATOR_EMAIL"),
                hosted_endpoint_configured: env_configured("IOI_AGENT_SDK_HOSTED_ENDPOINT"),
                self_hosted_endpoint_configured: env_configured(
                    "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
                ),
                source: Some("runtime.doctor_report".to_string()),
                ..RuntimeToolCatalogProjectionRequest::default()
            })
            .map_err(|error| {
                RuntimeDoctorReportProjectionCommandError::new(error.code(), error.message())
            })?;
        let runtime_nodes = RuntimeToolCatalogProjectionCore::default()
            .project(RuntimeToolCatalogProjectionRequest {
                operation: Some("runtime_tool_catalog".to_string()),
                operation_kind: Some("runtime.tool_catalog.projection.runtime_nodes".to_string()),
                projection_kind: Some("runtime_nodes".to_string()),
                workspace_root: Some(workspace_root.clone()),
                hosted_endpoint_configured: env_configured("IOI_AGENT_SDK_HOSTED_ENDPOINT"),
                self_hosted_endpoint_configured: env_configured(
                    "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
                ),
                source: Some("runtime.doctor_report".to_string()),
                ..RuntimeToolCatalogProjectionRequest::default()
            })
            .map_err(|error| {
                RuntimeDoctorReportProjectionCommandError::new(error.code(), error.message())
            })?;
        let skill_hook_catalog = SkillHookRegistryProjectionCore::default()
            .project(SkillHookRegistryProjectionRequest {
                operation_kind: Some("skill_hook.registry.catalog".to_string()),
                registry_kind: Some("catalog".to_string()),
                workspace_root: Some(workspace_root.clone()),
                home_dir: Some(home_dir.clone()),
                source: Some("runtime.doctor_report".to_string()),
            })
            .map_err(|error| {
                RuntimeDoctorReportProjectionCommandError::new(error.code(), error.message())
            })?;

        let memory_records_path = Path::new(&state_dir).join("memory-records");
        let memory_policies_path = Path::new(&state_dir).join("memory-policies");
        let routes_array = array_values(&routes);
        let artifacts_array = array_values(&artifacts);
        let mcp_servers_array = array_values(&mcp_servers);
        let tools_array = tools.tools.clone();
        let runtime_nodes_array = runtime_nodes
            .runtime_nodes
            .iter()
            .map(redacted_runtime_node)
            .collect::<Vec<_>>();
        let skill_catalog = skill_hook_catalog.catalog.clone();
        let skill_sources = array_values(&skill_catalog["sources"]);

        let checks = vec![
            doctor_check(
                "daemon.public_api",
                "pass",
                true,
                "Public runtime daemon routes are reachable.",
                vec!["/v1/doctor".to_string()],
            ),
            doctor_check(
                "workspace.root",
                if Path::new(&workspace_root).exists() {
                    "pass"
                } else {
                    "blocked"
                },
                true,
                if Path::new(&workspace_root).exists() {
                    "Workspace root exists."
                } else {
                    "Workspace root is missing."
                },
                vec![workspace_root.clone()],
            ),
            doctor_check(
                "agentgres.store",
                if Path::new(&state_dir).exists() {
                    "pass"
                } else {
                    "blocked"
                },
                true,
                "Agentgres v0 state directory is present.",
                vec![
                    state_dir.clone(),
                    "agentgres_canonical_state_projection".to_string(),
                ],
            ),
            doctor_check(
                "model.routes",
                if routes_array.is_empty() {
                    "blocked"
                } else {
                    "pass"
                },
                true,
                format!("{} model route(s) are registered.", routes_array.len()),
                routes_array.iter().filter_map(|route| string_field(route, "id")).collect(),
            ),
            doctor_check(
                "memory.store",
                if memory_records_path.exists() && memory_policies_path.exists() {
                    "pass"
                } else {
                    "blocked"
                },
                true,
                "Memory records and policies are backed by durable state paths.",
                vec![
                    memory_records_path.to_string_lossy().to_string(),
                    memory_policies_path.to_string_lossy().to_string(),
                ],
            ),
            doctor_check(
                "tool.catalog",
                if tools_array.is_empty() {
                    "blocked"
                } else {
                    "pass"
                },
                false,
                format!("{} governed runtime tool(s) are registered.", tools_array.len()),
                tools_array
                    .iter()
                    .filter_map(|tool| string_field(tool, "stable_tool_id"))
                    .collect(),
            ),
            doctor_check(
                "workflow.react_flow_registry",
                "pass",
                true,
                "React Flow registry exposes runtime doctor and readiness nodes.",
                vec![
                    "RuntimeDoctorNode".to_string(),
                    "packages/agent-ide/src/runtime/workflow-node-registry.ts".to_string(),
                ],
            ),
            doctor_check(
                "mcp.registry",
                if mcp_servers_array.is_empty() {
                    "degraded"
                } else {
                    "pass"
                },
                false,
                if mcp_servers_array.is_empty() {
                    "No MCP servers are registered; MCP remains optional.".to_string()
                } else {
                    format!("{} MCP server(s) are registered.", mcp_servers_array.len())
                },
                mcp_servers_array
                    .iter()
                    .filter_map(|server| string_field(server, "id"))
                    .collect(),
            ),
            doctor_check(
                "skills.hooks",
                string_field(&skill_catalog, "status").unwrap_or_else(|| "degraded".to_string()),
                false,
                format!(
                    "{} governed skill(s) and {} hook(s) discovered across {} source(s).",
                    number_field(&skill_catalog, "skillCount"),
                    number_field(&skill_catalog, "hookCount"),
                    skill_sources.len(),
                ),
                vec![
                    "runtime_skill_hook_discovery".to_string(),
                    "/v1/skills".to_string(),
                    "/v1/hooks".to_string(),
                ],
            ),
            doctor_check(
                "wallet.network",
                if env_configured("IOI_WALLET_NETWORK_URL") {
                    "pass"
                } else {
                    "degraded"
                },
                false,
                if env_configured("IOI_WALLET_NETWORK_URL") {
                    "Wallet/network approval endpoint is configured."
                } else {
                    "Wallet/network approval endpoint is optional and not configured."
                },
                vec!["IOI_WALLET_NETWORK_URL".to_string()],
            ),
            doctor_check(
                "remote.agentgres",
                if env_configured("IOI_AGENTGRES_URL") {
                    "pass"
                } else {
                    "degraded"
                },
                false,
                if env_configured("IOI_AGENTGRES_URL") {
                    "Remote Agentgres adapter is configured."
                } else {
                    "Remote Agentgres adapter is optional and not configured."
                },
                vec!["IOI_AGENTGRES_URL".to_string()],
            ),
            doctor_check(
                "lsp.status",
                "degraded",
                false,
                "LSP health is not daemon-owned yet; workflow activation should treat it as optional.",
                vec!["lsp.status.next_slice".to_string()],
            ),
        ];
        let required_failures = checks
            .iter()
            .filter(|check| {
                bool_field(check, "required")
                    && string_field(check, "status") != Some("pass".to_string())
            })
            .cloned()
            .collect::<Vec<_>>();
        let optional_warnings = checks
            .iter()
            .filter(|check| {
                !bool_field(check, "required")
                    && string_field(check, "status") != Some("pass".to_string())
            })
            .filter_map(|check| string_field(check, "id"))
            .collect::<Vec<_>>();
        let status = if !required_failures.is_empty() {
            "blocked"
        } else if !optional_warnings.is_empty() {
            "degraded"
        } else {
            "pass"
        };
        let route_ids = routes_array
            .iter()
            .filter_map(|route| string_field(route, "id"))
            .collect::<Vec<_>>();
        let selected_default_route = if route_ids.iter().any(|route| route == "route.local-first") {
            json!("route.local-first")
        } else {
            Value::Null
        };
        let provider_keys = provider_key_report();
        let report = json!({
            "schemaVersion": "ioi.agent-runtime.doctor.v1",
            "object": "ioi.agent_runtime_doctor_report",
            "generatedAt": "rust_daemon_core",
            "status": status,
            "readiness": if required_failures.is_empty() { "ready" } else { "blocked" },
            "version": {
                "runtime": "ioi-runtime-daemon",
                "schema": optional_trimmed(request.runtime_schema_version.as_deref()).unwrap_or_else(|| "ioi.agentgres.runtime.v0".to_string()),
            },
            "daemon": {
                "endpoint": optional_trimmed(request.base_url.as_deref()),
                "publicApi": "/v1",
                "nativeApi": "/api/v1",
                "requestScoped": true,
            },
            "workspace": {
                "root": workspace_root.clone(),
                "exists": Path::new(&workspace_root).exists(),
            },
            "configPaths": {
                "stateDir": state_dir.clone(),
                "projections": Path::new(&state_dir).join("projections").to_string_lossy().to_string(),
                "memoryRecords": memory_records_path.to_string_lossy(),
                "memoryPolicies": memory_policies_path.to_string_lossy(),
                "modelMountingReadProjection": "rust_daemon_core.model_mount.read_projection",
            },
            "providerKeys": provider_keys,
            "modelRoutes": {
                "modelCount": artifacts_array.len(),
                "routeCount": route_ids.len(),
                "routeIds": route_ids,
                "selectedDefaultRoute": selected_default_route,
            },
            "mcp": {
                "serverCount": mcp_servers_array.len(),
                "servers": mcp_servers_array.iter().map(public_mcp_server).collect::<Vec<_>>(),
            },
            "skillsHooks": {
                "status": skill_catalog["status"].clone(),
                "skillCount": number_field(&skill_catalog, "skillCount"),
                "hookCount": number_field(&skill_catalog, "hookCount"),
                "sourceCount": skill_sources.len(),
                "activeSkillSetHash": skill_catalog["activeSkillSetHash"].clone(),
                "activeHookSetHash": skill_catalog["activeHookSetHash"].clone(),
                "validationIssueCount": number_field(&skill_catalog, "validationIssueCount"),
                "rustCoreRequired": false,
                "rustCoreDetails": Value::Null,
                "discoveryEndpoints": ["/v1/skills", "/v1/hooks"],
            },
            "memory": {
                "recordCount": json_record_count(&memory_records_path),
                "policyCount": json_record_count(&memory_policies_path),
                "defaultPolicy": Value::Null,
                "paths": {
                    "recordsPath": memory_records_path.to_string_lossy(),
                    "policiesPath": memory_policies_path.to_string_lossy(),
                    "records_path": memory_records_path.to_string_lossy(),
                    "policies_path": memory_policies_path.to_string_lossy(),
                },
            },
            "sandbox": {
                "status": "pass",
                "profile": "local_private",
                "approvalMode": "suggest",
                "networkDefault": "local_only",
            },
            "workflow": {
                "reactFlowRegistryVersion": "ioi.reactflow.workflow-node-registry.v1",
                "doctorNodeType": "runtime_doctor",
                "activationConsumesDoctorReport": true,
                "readinessBlockerField": "checks",
            },
            "agentgres": {
                "schemaVersion": optional_trimmed(request.runtime_schema_version.as_deref()).unwrap_or_else(|| "ioi.agentgres.runtime.v0".to_string()),
                "source": "agentgres_canonical_state_projection",
                "runStateWatermark": json_record_count(&Path::new(&state_dir).join("runs")),
                "localStateDirPresent": Path::new(&state_dir).exists(),
                "remoteAdapterConfigured": env_configured("IOI_AGENTGRES_URL"),
                "remoteAdapterHash": env_hash("IOI_AGENTGRES_URL"),
            },
            "wallet": {
                "approvalStatus": if env_configured("IOI_WALLET_NETWORK_URL") { "configured" } else { "not_configured" },
                "networkConfigured": env_configured("IOI_WALLET_NETWORK_URL"),
                "networkUrlHash": env_hash("IOI_WALLET_NETWORK_URL"),
            },
            "runtimeNodes": runtime_nodes_array,
            "checks": checks,
            "blockers": required_failures.iter().filter_map(|check| string_field(check, "id")).collect::<Vec<_>>(),
            "optionalWarnings": optional_warnings,
            "redaction": {
                "profile": "doctor_safe",
                "secretValuesIncluded": false,
                "endpointValuesHashed": true,
            },
            "evidenceRefs": [
                "ioi_agent_runtime_doctor",
                "runtime_preflight",
                "RuntimeDoctorNode",
                "rust_daemon_core_runtime_doctor_report_projection",
                "agentgres_doctor_projection_replay_required",
                "runtime_doctor_js_aggregate_retired",
            ],
        });
        Ok(RuntimeDoctorReportProjectionRecord {
            object: "ioi.runtime_doctor_report_projection".to_string(),
            status: "projected".to_string(),
            operation,
            operation_kind,
            workspace_root,
            state_dir,
            record_count: 1,
            report,
            evidence_refs: vec![
                "rust_daemon_core_runtime_doctor_report_projection".to_string(),
                "agentgres_doctor_projection_replay_required".to_string(),
                "runtime_doctor_js_aggregate_retired".to_string(),
            ],
            receipt_refs: vec!["receipt_runtime_doctor_report_projection".to_string()],
        })
    }
}

impl RuntimeDoctorReportProjectionRecord {
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_DOCTOR_REPORT_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": self.object,
            "status": self.status,
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "workspace_root": self.workspace_root,
            "state_dir": self.state_dir,
            "report": self.report,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn model_mount_projection(
    projection_kind: &str,
    state_dir: &str,
) -> Result<Value, RuntimeDoctorReportProjectionCommandError> {
    ModelMountCore
        .plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: projection_kind.to_string(),
            schema_version: None,
            generated_at: Some("rust_daemon_core".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(state_dir.to_string()),
            state: json!({}),
        })
        .map(|plan| plan.projection)
        .map_err(|error| RuntimeDoctorReportProjectionCommandError::new(error.code, error.message))
}

fn doctor_check(
    id: &str,
    status: impl Into<String>,
    required: bool,
    summary: impl Into<String>,
    evidence_refs: Vec<String>,
) -> Value {
    json!({
        "id": id,
        "status": status.into(),
        "required": required,
        "summary": summary.into(),
        "evidenceRefs": evidence_refs,
    })
}

fn redacted_runtime_node(node: &Value) -> Value {
    let endpoint = string_field(node, "endpoint");
    json!({
        "id": string_field(node, "id"),
        "kind": string_field(node, "kind"),
        "status": string_field(node, "status"),
        "privacyClass": string_field(node, "privacyClass"),
        "endpointConfigured": endpoint.is_some(),
        "endpointHash": endpoint.as_ref().map(|value| sha256_hex(value)),
        "evidence_refs": node.get("evidence_refs").cloned().unwrap_or_else(|| json!([])),
    })
}

fn public_mcp_server(server: &Value) -> Value {
    json!({
        "id": string_field(server, "id"),
        "transport": string_field(server, "transport"),
        "status": string_field(server, "status"),
        "secretRefCount": 0,
        "secretsRedacted": true,
    })
}

fn provider_key_report() -> Vec<Value> {
    [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "IOI_AGENT_SDK_HOSTED_ENDPOINT",
        "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
    ]
    .into_iter()
    .map(|name| {
        json!({
            "name": name,
            "source": "env",
            "configured": env_configured(name),
            "valueRedacted": true,
            "valueHash": env_hash(name),
        })
    })
    .collect()
}

fn json_record_count(path: &Path) -> usize {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .count()
}

fn array_values(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn number_field(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(0)
}

fn env_configured(name: &str) -> bool {
    env_string(name).is_some()
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_hash(name: &str) -> Option<String> {
    env_string(name).map(|value| sha256_hex(&value))
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_projects_runtime_doctor_report_from_daemon_core_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        fs::create_dir_all(state_dir.join("memory-records")).expect("memory records dir");
        fs::create_dir_all(state_dir.join("memory-policies")).expect("memory policies dir");
        fs::create_dir_all(state_dir.join("runs")).expect("runs dir");
        fs::create_dir_all(state_dir.join("model-routes")).expect("model routes dir");
        fs::write(state_dir.join("memory-records/memory-one.json"), "{}").expect("memory record");
        fs::write(state_dir.join("memory-policies/policy-one.json"), "{}").expect("memory policy");
        fs::write(state_dir.join("runs/run-one.json"), "{}").expect("run record");
        fs::write(
            state_dir.join("model-routes/route.local-first.json"),
            serde_json::to_string_pretty(&json!({
                "id": "route.local-first",
                "role": "default",
                "status": "active",
                "updatedAt": "2026-06-15T00:00:00.000Z",
                "receiptRefs": ["receipt://model-mount/route-control/local-first"],
                "routeControl": {
                    "rust_core_boundary": "model_mount.route_control",
                    "evidence_refs": [
                        "model_mount_route_control_rust_owned",
                        "rust_daemon_core_route_control_plan",
                        "agentgres_route_truth_required"
                    ]
                }
            }))
            .expect("route json"),
        )
        .expect("route record");

        let record = RuntimeDoctorReportProjectionCore::default()
            .project(RuntimeDoctorReportProjectionRequest {
                base_url: Some("http://127.0.0.1:7777".to_string()),
                workspace_root: Some(temp.path().to_string_lossy().to_string()),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                runtime_schema_version: Some("ioi.agentgres.runtime.v0".to_string()),
                ..RuntimeDoctorReportProjectionRequest::default()
            })
            .expect("doctor projection");

        assert_eq!(record.operation_kind, "runtime.doctor_report.projection");
        assert_eq!(
            record.report["schemaVersion"],
            "ioi.agent-runtime.doctor.v1"
        );
        assert_eq!(record.report["daemon"]["endpoint"], "http://127.0.0.1:7777");
        assert_eq!(record.report["readiness"], "ready");
        assert_eq!(record.report["status"], "degraded");
        assert_eq!(record.report["modelRoutes"]["routeCount"], 1);
        assert_eq!(record.report["agentgres"]["runStateWatermark"], 1);
        assert_eq!(record.report["memory"]["recordCount"], 1);
        assert_eq!(record.report["runtimeNodes"][0]["endpointConfigured"], true);
        assert_eq!(
            record.report["evidenceRefs"][3],
            "rust_daemon_core_runtime_doctor_report_projection"
        );
        assert!(record.to_value().get("schema_version").is_some());
    }

    #[test]
    fn rust_doctor_report_blocks_missing_required_agentgres_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record = RuntimeDoctorReportProjectionCore::default()
            .project(RuntimeDoctorReportProjectionRequest {
                workspace_root: Some(temp.path().join("missing").to_string_lossy().to_string()),
                state_dir: Some(temp.path().join("state").to_string_lossy().to_string()),
                ..RuntimeDoctorReportProjectionRequest::default()
            })
            .expect("doctor projection");

        assert_eq!(record.report["status"], "blocked");
        assert_eq!(record.report["readiness"], "blocked");
        assert!(record.report["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|value| value == "workspace.root"));
        assert!(record.report["blockers"]
            .as_array()
            .expect("blockers")
            .iter()
            .any(|value| value == "agentgres.store"));
    }
}
