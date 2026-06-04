#![forbid(unsafe_code)]

use ioi_services::agentic::runtime::kernel::receipt_binder::ReceiptBinder;
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleInvocation, StepModuleNext, StepModuleProjectionStatus, StepModuleResult,
    StepModuleStatus, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

const COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";

#[derive(Debug, Deserialize)]
struct StepModuleBridgeRequest {
    #[serde(rename = "schema_version", alias = "schemaVersion")]
    schema_version: String,
    operation: String,
    backend: String,
    invocation: StepModuleInvocation,
    #[serde(default)]
    input: Value,
}

fn main() {
    let response = match run_bridge() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }),
    };
    println!("{}", response);
}

fn run_bridge() -> Result<Value, BridgeError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| BridgeError::new("stdin_read_failed", error.to_string()))?;
    let request: StepModuleBridgeRequest = serde_json::from_str(&input)
        .map_err(|error| BridgeError::new("request_json_invalid", error.to_string()))?;
    if request.schema_version != COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "run_coding_tool_step_module" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    request
        .invocation
        .validate()
        .map_err(|errors| BridgeError::new("invocation_invalid", format!("{errors:?}")))?;

    match request.invocation.module_ref.id.as_str() {
        "workspace.status" => Ok(workspace_status_shadow_response(request)),
        other => Err(BridgeError::new(
            "tool_unsupported",
            format!("unsupported StepModule tool {}", other),
        )),
    }
}

fn workspace_status_shadow_response(request: StepModuleBridgeRequest) -> Value {
    let invocation_id = request.invocation.invocation_id.clone();
    let suffix = short_suffix(&invocation_id);
    let receipt_ref = format!("receipt://rust-workload-shadow/workspace.status/{suffix}");
    let input_hash = request.invocation.input.input_hash.clone();
    let authority_scopes = request.invocation.authority.authority_scopes.clone();
    let primitive_capabilities = request.invocation.authority.primitive_capabilities.clone();
    let result = StepModuleResult {
        schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
        invocation_id,
        status: StepModuleStatus::Success,
        execution_result_ref: format!("result://rust-workload-shadow/workspace.status/{suffix}"),
        normalized_observation_ref: format!(
            "observation://rust-workload-shadow/workspace.status/{suffix}"
        ),
        receipt_refs: vec![receipt_ref.clone()],
        artifact_refs: vec![],
        payload_refs: vec![],
        agentgres_operation_refs: vec![],
        state_root_after: None,
        resulting_head: None,
        workflow_projection: StepModuleWorkflowProjection {
            workflow_graph_id: request
                .invocation
                .workflow_graph_id
                .clone()
                .unwrap_or_else(|| "workflow:projection".to_string()),
            workflow_node_id: request
                .invocation
                .workflow_node_id
                .clone()
                .unwrap_or_else(|| "node:coding-tool:workspace.status".to_string()),
            component_kind: "CodingToolNode".to_string(),
            status: StepModuleProjectionStatus::Shadow,
            attempt_id: format!("attempt://rust-workload-shadow/workspace.status/{suffix}"),
            evidence_refs: vec!["evidence://rust-workload-shadow/workspace.status".to_string()],
            receipt_refs: vec![receipt_ref],
        },
        next: StepModuleNext {
            model_reentry_required: false,
            verifier_required: false,
        },
    };
    if let Err(errors) = result.validate() {
        return json!({
            "source": "rust_workload_command",
            "error": {
                "code": "result_invalid",
                "message": format!("{errors:?}"),
            }
        });
    }
    let receipt_binding =
        match ReceiptBinder.bind_step_module_result(&request.invocation, &result, vec![]) {
            Ok(binding) => binding,
            Err(error) => {
                return json!({
                    "source": "rust_workload_command",
                    "error": {
                        "code": "receipt_binding_invalid",
                        "message": format!("{error:?}"),
                    }
                });
            }
        };
    json!({
        "source": "rust_workload_command",
        "backend": request.backend,
        "invocation": request.invocation,
        "result": result,
        "receipt_binding": receipt_binding,
        "shadow_observation": {
            "tool": "workspace.status",
            "input_hash": input_hash,
            "include_ignored": request.input.get("includeIgnored").and_then(Value::as_bool).unwrap_or(false),
            "authority_scopes": authority_scopes,
            "primitive_capabilities": primitive_capabilities,
        }
    })
}

fn short_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(24)
        .collect::<String>()
}

#[derive(Debug)]
struct BridgeError {
    code: &'static str,
    message: String,
}

impl BridgeError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}
