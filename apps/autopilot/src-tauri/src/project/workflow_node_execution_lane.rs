// apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs

use super::repository_pr_lane::{
    workflow_branch_policy_output, workflow_github_context_output,
    workflow_github_pr_create_output, workflow_issue_context_output, workflow_pr_attempt_output,
    workflow_repository_context_output, workflow_review_gate_output,
};
use super::workflow_authority_tooling_lane::{
    workflow_live_authority_approval_gate, workflow_live_authority_destructive_denial,
    workflow_live_authority_policy_gate, workflow_live_connector_catalog_describe,
    workflow_live_mcp_provider_catalog, workflow_live_mcp_tool_catalog,
    workflow_live_native_tool_catalog, workflow_live_wallet_capability_dry_run,
    workflow_side_effect_requires_live_runtime,
};
use super::workflow_binding_lane::{
    workflow_connector_binding, workflow_function_binding, workflow_function_dependency_precheck,
    workflow_function_input_schema, workflow_function_output_schema,
    workflow_function_sandbox_precheck, workflow_model_binding, workflow_parser_binding,
    workflow_sandbox_policy, workflow_tool_binding,
};
use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_memory_lane::{
    workflow_memory_mutation_output, workflow_memory_query_output, workflow_memory_send_options,
};
use super::workflow_node_metadata_lane::{
    workflow_node_id, workflow_node_logic, workflow_node_type,
};
use super::workflow_output_lane::{
    workflow_output_bundle, workflow_output_satisfies_schema, workflow_truncate_output,
};
use super::workflow_package_lane::{
    execute_workflow_package_export_node, execute_workflow_package_import_node,
};
use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn execute_workflow_tool_binding(
    parent_workflow_path: &Path,
    node_id: &str,
    binding: &WorkflowToolBinding,
    input: Value,
) -> Result<Value, String> {
    let Some(tool) = binding.workflow_tool.as_ref() else {
        return Err("Workflow tool binding is missing a child workflow reference.".to_string());
    };
    let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
    if let Some(schema) = tool.argument_schema.as_ref() {
        workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
            format!(
                "Workflow tool arguments failed schema validation: {}",
                error
            )
        })?;
    }
    let child_path = resolve_workflow_reference_path(parent_workflow_path, &tool.workflow_path)?;
    if child_path == parent_workflow_path {
        return Err("Workflow tools cannot invoke their own workflow.".to_string());
    }
    let child_bundle = load_workflow_bundle_from_path(&child_path)?;
    let child_input = json!({
        "arguments": arguments,
        "input": input
    });
    let max_attempts = tool.max_attempts.unwrap_or(1).clamp(1, 5);
    let mut last_error = None;
    let mut last_child_summary: Option<WorkflowRunSummary> = None;
    for attempt in 1..=max_attempts {
        let child_thread = new_workflow_thread(&child_path, Some(child_input.clone()));
        let child_state = initial_workflow_state(&child_thread, "workflow-tool-start");
        let child_result = execute_workflow_project(
            &child_path,
            child_bundle.clone(),
            child_thread,
            child_state,
            None,
            &WorkflowSkillResolver::default(),
        )?;
        last_child_summary = Some(child_result.summary.clone());
        if child_result.summary.status != "passed" {
            last_error = Some(format!(
                "Workflow tool child run '{}' finished with status {}.",
                child_result.summary.id, child_result.summary.status
            ));
            continue;
        }
        let result = child_result.final_state.values.clone();
        if let Some(schema) = tool.result_schema.as_ref() {
            workflow_json_satisfies_schema(schema, &json!(result)).map_err(|error| {
                format!("Workflow tool result failed schema validation: {}", error)
            })?;
        }
        return Ok(json!({
            "nodeId": node_id,
            "kind": "tool",
            "toolKind": "workflow_tool",
            "toolName": binding.tool_ref,
            "attempt": attempt,
            "maxAttempts": max_attempts,
            "timeoutMs": tool.timeout_ms.unwrap_or(30_000),
            "argumentSchema": tool.argument_schema,
            "resultSchema": tool.result_schema,
            "childWorkflowPath": child_path.display().to_string(),
            "childRunId": child_result.summary.id,
            "childRunStatus": child_result.summary.status,
            "childThreadId": child_result.thread.id,
            "result": result,
            "outputNodeIds": child_result.final_state
                .node_outputs
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        }));
    }
    Err(last_error.unwrap_or_else(|| {
        format!(
            "Workflow tool child workflow failed after {} attempt(s){}.",
            max_attempts,
            last_child_summary
                .map(|summary| format!("; last run was {}", summary.status))
                .unwrap_or_default()
        )
    }))
}

pub(super) fn workflow_model_ref_from_input(input: &Value) -> Option<String> {
    input
        .get("modelRef")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            input.as_object().and_then(|object| {
                object.values().find_map(|value| {
                    value
                        .get("modelRef")
                        .and_then(Value::as_str)
                        .filter(|model_ref| !model_ref.trim().is_empty())
                        .map(str::to_string)
                })
            })
        })
}

fn workflow_collect_inputs_by_kind(value: &Value, kind: &str, collected: &mut Vec<Value>) {
    if value.get("kind").and_then(Value::as_str) == Some(kind) {
        collected.push(value.clone());
    }
    match value {
        Value::Array(items) => {
            for item in items {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        Value::Object(object) => {
            for item in object.values() {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        _ => {}
    }
}

fn workflow_inputs_by_kind(input: &Value, kind: &str) -> Vec<Value> {
    let mut collected = Vec::new();
    workflow_collect_inputs_by_kind(input, kind, &mut collected);
    collected
}

pub(super) fn execute_workflow_function_node(node: &Value, input: Value) -> Result<Value, String> {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let binding = workflow_function_binding(node)?;
    workflow_function_dependency_precheck(&binding)?;
    if let Some(schema) = workflow_function_input_schema(&binding) {
        workflow_json_satisfies_schema(schema, &input)
            .map_err(|error| format!("Function input failed schema validation: {}", error))?;
    }
    let mut code_hash = None;
    let function_source = if let Some(function_ref) = binding.function_ref.as_ref() {
        let source_path = PathBuf::from(&function_ref.source_path);
        if source_path.exists() {
            code_hash = workflow_file_sha256(&source_path).ok();
            fs::read_to_string(&source_path).map_err(|error| {
                format!(
                    "Failed to read workflow function source '{}': {}",
                    source_path.display(),
                    error
                )
            })?
        } else {
            binding.code.clone()
        }
    } else {
        binding.code.clone()
    };
    let language = binding.language.trim().to_lowercase();
    if language != "javascript" && language != "typescript" {
        return Err(format!(
            "Function language '{}' is not supported in the local sandbox.",
            binding.language
        ));
    }
    let policy = workflow_sandbox_policy(&binding, node);
    workflow_function_sandbox_precheck(&function_source, &policy)?;
    let timeout_ms = policy.timeout_ms.unwrap_or(1000).clamp(50, 30_000);
    let memory_mb = policy.memory_mb.unwrap_or(64).clamp(16, 256);
    let output_limit = policy
        .output_limit_bytes
        .unwrap_or(32768)
        .clamp(1024, 262_144);
    let script_path =
        std::env::temp_dir().join(format!("{}-function.js", unique_runtime_id("workflow")));
    let script = format!(
        r#"
const vm = require("vm");
const source = {code};
const input = {input};
const stdoutLogs = [];
const stderrLogs = [];
const sandbox = {{
  input,
  context: {{ input }},
  console: {{
    log: (...args) => stdoutLogs.push(args.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join(" ")),
    error: (...args) => stderrLogs.push(args.map(String).join(" "))
  }},
  JSON,
  Math,
  Date,
}};
const wrapped = `(function(){{ "use strict"; const require = undefined; const process = undefined; const fetch = undefined; const Buffer = undefined; ${{source}}\n}})()`;
try {{
  const result = vm.runInNewContext(wrapped, sandbox, {{ timeout: {timeout_ms} }});
  process.stdout.write(JSON.stringify({{ ok: true, result, stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
}} catch (error) {{
  process.stdout.write(JSON.stringify({{ ok: false, error: String(error && error.message ? error.message : error), stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
  process.exitCode = 1;
}}
"#,
        code = serde_json::to_string(&function_source).map_err(|error| error.to_string())?,
        input = serde_json::to_string(&input).map_err(|error| error.to_string())?,
        timeout_ms = timeout_ms,
    );
    fs::write(&script_path, script)
        .map_err(|error| format!("Failed to prepare function sandbox: {}", error))?;
    let mut child = Command::new("node")
        .arg(format!("--max-old-space-size={}", memory_mb))
        .arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed to start JavaScript sandbox: {}", error))?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms + 250);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("Failed to poll JavaScript sandbox: {}", error))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = fs::remove_file(&script_path);
            return Err(format!("Function timed out after {}ms.", timeout_ms));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Failed to collect JavaScript sandbox output: {}", error))?;
    let _ = fs::remove_file(&script_path);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let process_stderr = workflow_truncate_output(&output.stderr, output_limit);
    let payload: Value = serde_json::from_str(&stdout).map_err(|error| {
        format!(
            "Function sandbox returned invalid JSON: {} | stderr={}",
            error, process_stderr
        )
    })?;
    if !payload.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Function execution failed.")
            .to_string());
    }
    let result = payload.get("result").cloned().unwrap_or(Value::Null);
    let function_stdout = payload
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let function_stderr = payload
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let output_bytes = serde_json::to_vec(&result)
        .map_err(|error| format!("Failed to measure function output: {}", error))?
        .len()
        + function_stdout.as_bytes().len()
        + function_stderr.as_bytes().len();
    if output_bytes > output_limit {
        return Err(format!(
            "Function output exceeded sandbox output limit of {} bytes.",
            output_limit
        ));
    }
    if let Some(schema) = workflow_function_output_schema(&binding) {
        let wrapper = json!({ "schema": schema });
        workflow_output_satisfies_schema(&wrapper, &result)?;
    }
    Ok(json!({
        "nodeId": node_id,
        "kind": "function",
        "language": binding.language,
        "result": result,
        "stdout": function_stdout,
        "stderr": if function_stderr.is_empty() { process_stderr } else { function_stderr },
        "codeHash": code_hash.or_else(|| binding.function_ref.as_ref().and_then(|function_ref| function_ref.code_hash.clone())),
        "dependencyManifest": binding.function_ref.as_ref().and_then(|function_ref| function_ref.dependency_manifest.clone()),
        "sandbox": {
            "timeoutMs": timeout_ms,
            "memoryMb": memory_mb,
            "outputLimitBytes": output_limit,
            "permissions": policy.permissions
        }
    }))
}

fn workflow_runtime_control_clean_string(value: String) -> Option<String> {
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn workflow_runtime_control_logic_string(logic: &Value, key: &str) -> Option<String> {
    workflow_value_string(logic, key).and_then(workflow_runtime_control_clean_string)
}

fn workflow_runtime_control_value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.trim().is_empty()) {
        if segment == "[]" {
            current = current.as_array()?.first()?;
            continue;
        }
        current = current.get(segment)?;
    }
    Some(current)
}

fn workflow_runtime_control_input_string(input: &Value, path: &str) -> Option<String> {
    workflow_runtime_control_value_at_path(input, path)
        .and_then(Value::as_str)
        .map(str::to_string)
        .and_then(workflow_runtime_control_clean_string)
}

fn workflow_runtime_control_input_bool(input: &Value, path: &str) -> Option<bool> {
    workflow_runtime_control_value_at_path(input, path).and_then(Value::as_bool)
}

fn workflow_runtime_control_input_number(input: &Value, path: &str) -> Option<f64> {
    workflow_runtime_control_value_at_path(input, path).and_then(Value::as_f64)
}

fn workflow_runtime_control_input_string_array(input: &Value, path: &str) -> Vec<String> {
    workflow_runtime_control_string_array(workflow_runtime_control_value_at_path(input, path))
}

fn workflow_runtime_control_logic_string_array(logic: &Value, key: &str) -> Vec<String> {
    workflow_runtime_control_string_array(logic.get(key))
}

fn workflow_runtime_control_string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

struct WorkflowRuntimeControlEnvelopeConfig<'a> {
    thread_id_logic_key: &'a str,
    thread_id_field_key: &'a str,
    turn_id_logic_key: Option<&'a str>,
    turn_id_field_key: Option<&'a str>,
    workflow_node_id_logic_key: &'a str,
    actor_logic_key: &'a str,
    endpoint_logic_key: &'a str,
    default_workflow_node_id: &'a str,
    default_endpoint: &'a str,
    missing_turn_id: Option<&'a str>,
}

struct WorkflowRuntimeControlEnvelope {
    workflow_graph_id: Value,
    workflow_node_id: String,
    actor: String,
    thread_id: String,
    turn_id: Option<String>,
    endpoint: String,
}

struct WorkflowRuntimeControlOutputConfig<'a> {
    schema_version: &'a str,
    source: &'a str,
    component_kind: &'a str,
    event_kind: &'a str,
    payload_schema_version: &'a str,
    nested_key: &'a str,
}

fn workflow_runtime_control_input_field_or_logic(
    logic: &Value,
    input: &Value,
    field_key: &str,
    default_field: &str,
    logic_key: &str,
    default_value: &str,
) -> String {
    let field = workflow_runtime_control_logic_string(logic, field_key)
        .unwrap_or_else(|| default_field.to_string());
    workflow_runtime_control_input_string(input, &field)
        .or_else(|| workflow_runtime_control_logic_string(logic, logic_key))
        .unwrap_or_else(|| default_value.to_string())
}

fn workflow_runtime_control_bool_field_or_logic(
    logic: &Value,
    input: &Value,
    field_key: &str,
    default_field: &str,
    logic_key: &str,
    default_value: bool,
) -> bool {
    let field = workflow_runtime_control_logic_string(logic, field_key)
        .unwrap_or_else(|| default_field.to_string());
    workflow_runtime_control_input_bool(input, &field)
        .or_else(|| logic.get(logic_key).and_then(Value::as_bool))
        .unwrap_or(default_value)
}

fn workflow_runtime_restore_gate_mode(value: String) -> String {
    if value == "apply" {
        "apply".to_string()
    } else {
        "preview".to_string()
    }
}

fn workflow_runtime_restore_conflict_policy(value: String) -> String {
    if value == "allow_override" {
        "allow_override".to_string()
    } else {
        "block".to_string()
    }
}

fn workflow_runtime_diagnostics_repair_action(value: String) -> String {
    match value.replace(['-', '.'], "_").as_str() {
        "restore_preview" | "preview" | "preview_restore" => "restore_preview".to_string(),
        "restore_apply" | "apply" | "apply_restore" => "restore_apply".to_string(),
        "operator_override" | "override" => "operator_override".to_string(),
        _ => "repair_retry".to_string(),
    }
}

fn workflow_runtime_coding_tool_budget_recovery_action(value: String) -> String {
    match value.to_lowercase().replace(['-', '.'], "_").as_str() {
        "approve" | "approved" | "approve_override" | "allow" | "allowed" => {
            "approve_override".to_string()
        }
        "reject" | "rejected" | "reject_override" | "deny" | "denied" => {
            "reject_override".to_string()
        }
        "retry" | "retry_approved" | "approved_retry" => "retry_approved".to_string(),
        _ => "request_approval".to_string(),
    }
}

fn workflow_runtime_thread_mode_mode(value: String) -> String {
    match value.to_lowercase().replace(['-', '.'], "_").as_str() {
        "plan" | "planning" | "read_only" | "readonly" => "plan".to_string(),
        "review" | "review_mode" | "human_review" | "approval_review" => "review".to_string(),
        "yolo" | "auto" | "auto_local" | "never_prompt" => "yolo".to_string(),
        "custom" | "dry_run" | "handoff" | "learn" => "custom".to_string(),
        _ => "agent".to_string(),
    }
}

fn workflow_runtime_thread_mode_default_approval(mode: &str) -> &'static str {
    match mode {
        "plan" | "review" => "human_required",
        "yolo" => "never_prompt",
        _ => "suggest",
    }
}

fn workflow_runtime_thread_mode_approval_mode(value: String, mode: &str) -> String {
    match value.to_lowercase().replace(['-', '.'], "_").as_str() {
        "suggest" | "auto_local" | "never_prompt" | "human_required" | "policy_required" => {
            value.to_lowercase().replace(['-', '.'], "_")
        }
        _ => workflow_runtime_thread_mode_default_approval(mode).to_string(),
    }
}

fn workflow_runtime_control_envelope(
    workflow: Option<&WorkflowProject>,
    logic: &Value,
    input: &Value,
    config: &WorkflowRuntimeControlEnvelopeConfig,
) -> WorkflowRuntimeControlEnvelope {
    let thread_id_field = workflow_runtime_control_logic_string(logic, config.thread_id_field_key)
        .unwrap_or_else(|| "threadId".to_string());
    let thread_id = workflow_runtime_control_logic_string(logic, config.thread_id_logic_key)
        .or_else(|| workflow_runtime_control_input_string(input, &thread_id_field))
        .or_else(|| workflow_runtime_control_input_string(input, "thread_id"))
        .unwrap_or_else(|| "{{runtime.thread_id}}".to_string());
    let turn_id = config.turn_id_logic_key.and_then(|turn_id_logic_key| {
        let turn_id_field = config
            .turn_id_field_key
            .and_then(|key| workflow_runtime_control_logic_string(logic, key))
            .unwrap_or_else(|| "turnId".to_string());
        workflow_runtime_control_logic_string(logic, turn_id_logic_key)
            .or_else(|| workflow_runtime_control_input_string(input, &turn_id_field))
            .or_else(|| workflow_runtime_control_input_string(input, "turn_id"))
            .or_else(|| config.missing_turn_id.map(str::to_string))
    });
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let workflow_node_id =
        workflow_runtime_control_logic_string(logic, config.workflow_node_id_logic_key)
            .unwrap_or_else(|| config.default_workflow_node_id.to_string());
    let actor = workflow_runtime_control_logic_string(logic, config.actor_logic_key)
        .unwrap_or_else(|| "operator".to_string());
    let endpoint_template = workflow_runtime_control_logic_string(logic, config.endpoint_logic_key)
        .unwrap_or_else(|| config.default_endpoint.to_string());
    let endpoint = workflow_runtime_control_endpoint(
        &endpoint_template,
        &thread_id,
        turn_id.as_deref(),
        config.turn_id_logic_key.is_some(),
    );
    WorkflowRuntimeControlEnvelope {
        workflow_graph_id,
        workflow_node_id,
        actor,
        thread_id,
        turn_id,
        endpoint,
    }
}

fn workflow_runtime_control_endpoint(
    template: &str,
    thread_id: &str,
    turn_id: Option<&str>,
    replace_turn_id: bool,
) -> String {
    let endpoint = template.replace("{threadId}", thread_id);
    if replace_turn_id {
        endpoint.replace("{turnId}", turn_id.unwrap_or(""))
    } else {
        endpoint
    }
}

fn workflow_runtime_control_request(
    config: &WorkflowRuntimeControlOutputConfig,
    envelope: &WorkflowRuntimeControlEnvelope,
    extra_fields: Vec<(&str, Value)>,
) -> Value {
    let mut request = json!({
        "source": config.source,
        "actor": envelope.actor.clone(),
        "workflowGraphId": envelope.workflow_graph_id.clone(),
        "workflowNodeId": envelope.workflow_node_id.clone(),
        "eventKind": config.event_kind,
        "componentKind": config.component_kind,
        "payloadSchemaVersion": config.payload_schema_version
    });
    if let Value::Object(object) = &mut request {
        for (key, value) in extra_fields {
            object.insert(key.to_string(), value);
        }
    }
    request
}

fn workflow_runtime_control_output(
    node_id: &str,
    evidence_kind: &str,
    input: &Value,
    config: &WorkflowRuntimeControlOutputConfig,
    envelope: WorkflowRuntimeControlEnvelope,
    turn_id_value: Option<Value>,
    request: Value,
) -> Value {
    let mut runtime_control = json!({
        "schemaVersion": config.schema_version,
        "status": "ready",
        "source": config.source,
        "componentKind": config.component_kind,
        "workflowGraphId": envelope.workflow_graph_id,
        "workflowNodeId": envelope.workflow_node_id,
        "threadId": envelope.thread_id,
        "endpoint": envelope.endpoint,
        "request": request,
        "mutationExecuted": false
    });
    if let Some(turn_id_value) = turn_id_value.clone() {
        runtime_control["turnId"] = turn_id_value;
    }

    let mut output = json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": config.schema_version,
        "status": "ready",
        "source": config.source,
        "componentKind": config.component_kind,
        "workflowGraphId": runtime_control.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": runtime_control.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_control.get("threadId").cloned().unwrap_or(Value::Null),
        "endpoint": runtime_control.get("endpoint").cloned().unwrap_or(Value::Null),
        "request": runtime_control.get("request").cloned().unwrap_or(Value::Null),
        "mutationExecuted": false,
        "input": input
    });
    if let Some(turn_id_value) = turn_id_value {
        output["turnId"] = turn_id_value;
    }
    if let Value::Object(object) = &mut output {
        object.insert(config.nested_key.to_string(), runtime_control);
    }
    output
}

fn workflow_runtime_thread_fork_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeThreadForkThreadId",
            thread_id_field_key: "runtimeThreadForkThreadIdField",
            turn_id_logic_key: None,
            turn_id_field_key: None,
            workflow_node_id_logic_key: "runtimeThreadForkWorkflowNodeId",
            actor_logic_key: "runtimeThreadForkActor",
            endpoint_logic_key: "runtimeThreadForkEndpoint",
            default_workflow_node_id: "runtime.thread-fork",
            default_endpoint: "/v1/threads/{threadId}/fork",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-thread-fork-control.v1",
        source: "react_flow",
        component_kind: "thread_fork",
        event_kind: "OperatorControl.Fork",
        payload_schema_version: "ioi.runtime.thread-fork.v1",
        nested_key: "runtimeThreadFork",
    };
    let reason = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeThreadForkReasonField",
        "reason",
        "runtimeThreadForkReason",
        "Fork thread from React Flow workflow control.",
    );
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![("reason", json!(reason))],
    );
    workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        None,
        request,
    )
}

fn workflow_runtime_operator_interrupt_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeOperatorInterruptThreadId",
            thread_id_field_key: "runtimeOperatorInterruptThreadIdField",
            turn_id_logic_key: Some("runtimeOperatorInterruptTurnId"),
            turn_id_field_key: Some("runtimeOperatorInterruptTurnIdField"),
            workflow_node_id_logic_key: "runtimeOperatorInterruptWorkflowNodeId",
            actor_logic_key: "runtimeOperatorInterruptActor",
            endpoint_logic_key: "runtimeOperatorInterruptEndpoint",
            default_workflow_node_id: "runtime.operator-interrupt",
            default_endpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
            missing_turn_id: Some("{{runtime.turn_id}}"),
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-operator-interrupt-control.v1",
        source: "react_flow",
        component_kind: "operator_control",
        event_kind: "OperatorControl.Interrupt",
        payload_schema_version: "ioi.runtime.operator-control.v1",
        nested_key: "runtimeOperatorInterrupt",
    };
    let reason = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeOperatorInterruptReasonField",
        "reason",
        "runtimeOperatorInterruptReason",
        "Interrupt turn from React Flow workflow control.",
    );
    let turn_id_value = envelope.turn_id.clone().map(Value::String);
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![("reason", json!(reason))],
    );
    workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        turn_id_value,
        request,
    )
}

fn workflow_runtime_operator_steer_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeOperatorSteerThreadId",
            thread_id_field_key: "runtimeOperatorSteerThreadIdField",
            turn_id_logic_key: Some("runtimeOperatorSteerTurnId"),
            turn_id_field_key: Some("runtimeOperatorSteerTurnIdField"),
            workflow_node_id_logic_key: "runtimeOperatorSteerWorkflowNodeId",
            actor_logic_key: "runtimeOperatorSteerActor",
            endpoint_logic_key: "runtimeOperatorSteerEndpoint",
            default_workflow_node_id: "runtime.operator-steer",
            default_endpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
            missing_turn_id: Some("{{runtime.turn_id}}"),
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-operator-steer-control.v1",
        source: "react_flow",
        component_kind: "operator_control",
        event_kind: "OperatorControl.Steer",
        payload_schema_version: "ioi.runtime.operator-control.v1",
        nested_key: "runtimeOperatorSteer",
    };
    let guidance = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeOperatorSteerGuidanceField",
        "guidance",
        "runtimeOperatorSteerGuidance",
        "Steer turn from React Flow workflow control.",
    );
    let turn_id_value = envelope.turn_id.clone().map(Value::String);
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![("guidance", json!(guidance))],
    );
    workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        turn_id_value,
        request,
    )
}

fn workflow_runtime_context_compact_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeContextCompactThreadId",
            thread_id_field_key: "runtimeContextCompactThreadIdField",
            turn_id_logic_key: Some("runtimeContextCompactTurnId"),
            turn_id_field_key: Some("runtimeContextCompactTurnIdField"),
            workflow_node_id_logic_key: "runtimeContextCompactWorkflowNodeId",
            actor_logic_key: "runtimeContextCompactActor",
            endpoint_logic_key: "runtimeContextCompactEndpoint",
            default_workflow_node_id: "runtime.context-compact",
            default_endpoint: "/v1/threads/{threadId}/compact",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-context-compact-control.v1",
        source: "react_flow",
        component_kind: "context_compaction",
        event_kind: "OperatorControl.Compact",
        payload_schema_version: "ioi.runtime.context-compaction.v1",
        nested_key: "runtimeContextCompact",
    };
    let reason = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeContextCompactReasonField",
        "reason",
        "runtimeContextCompactReason",
        "Compact thread context from React Flow workflow control.",
    );
    let scope = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeContextCompactScopeField",
        "scope",
        "runtimeContextCompactScope",
        "thread",
    );
    let turn_id_value = envelope
        .turn_id
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![
            ("reason", json!(reason)),
            ("scope", json!(scope)),
            ("turnId", turn_id_value.clone()),
        ],
    );
    workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        Some(turn_id_value),
        request,
    )
}

fn workflow_runtime_thread_mode_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeThreadModeThreadId",
            thread_id_field_key: "runtimeThreadModeThreadIdField",
            turn_id_logic_key: None,
            turn_id_field_key: None,
            workflow_node_id_logic_key: "runtimeThreadModeWorkflowNodeId",
            actor_logic_key: "runtimeThreadModeActor",
            endpoint_logic_key: "runtimeThreadModeEndpoint",
            default_workflow_node_id: "runtime.thread-mode",
            default_endpoint: "/v1/threads/{threadId}/mode",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-thread-mode-control.v1",
        source: "react_flow",
        component_kind: "runtime_mode",
        event_kind: "OperatorControl.Mode",
        payload_schema_version: "ioi.runtime.thread-mode-control.v1",
        nested_key: "runtimeThreadMode",
    };
    let mode = workflow_runtime_thread_mode_mode(workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeThreadModeModeField",
        "mode",
        "runtimeThreadModeMode",
        "agent",
    ));
    let approval_mode = workflow_runtime_thread_mode_approval_mode(
        workflow_runtime_control_input_field_or_logic(
            logic,
            input,
            "runtimeThreadModeApprovalModeField",
            "approvalMode",
            "runtimeThreadModeApprovalMode",
            workflow_runtime_thread_mode_default_approval(&mode),
        ),
        &mode,
    );
    let trust_profile = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeThreadModeTrustProfileField",
        "trustProfile",
        "runtimeThreadModeTrustProfile",
        "local_private",
    );
    let workspace_trust_workflow_node_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeThreadModeWorkspaceTrustWorkflowNodeIdField",
        "workspaceTrustWorkflowNodeId",
        "runtimeThreadModeWorkspaceTrustWorkflowNodeId",
        &format!("{}.workspace-trust", envelope.workflow_node_id),
    );
    let request_warning_acknowledgement = workflow_runtime_control_bool_field_or_logic(
        logic,
        input,
        "runtimeThreadModeRequestWarningAcknowledgementField",
        "requestWarningAcknowledgement",
        "runtimeThreadModeRequestWarningAcknowledgement",
        true,
    );
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![
            ("mode", json!(mode.clone())),
            ("interactionMode", json!(mode.clone())),
            ("interaction_mode", json!(mode.clone())),
            ("approvalMode", json!(approval_mode.clone())),
            ("approval_mode", json!(approval_mode.clone())),
            ("trustProfile", json!(trust_profile.clone())),
            ("trust_profile", json!(trust_profile)),
            (
                "workspaceTrustWorkflowNodeId",
                json!(workspace_trust_workflow_node_id.clone()),
            ),
            (
                "workspace_trust_workflow_node_id",
                json!(workspace_trust_workflow_node_id),
            ),
            (
                "requestWarningAcknowledgement",
                json!(request_warning_acknowledgement),
            ),
            (
                "request_warning_acknowledgement",
                json!(request_warning_acknowledgement),
            ),
        ],
    );
    let mut output = workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        None,
        request,
    );
    output["mode"] = json!(mode);
    output["approvalMode"] = json!(approval_mode);
    output
}

fn workflow_runtime_workspace_trust_gate_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let workflow_node_id =
        workflow_runtime_control_logic_string(logic, "runtimeWorkspaceTrustGateWorkflowNodeId")
            .unwrap_or_else(|| "runtime.workspace-trust-gate".to_string());
    let warning_workflow_node_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeWorkspaceTrustGateWarningWorkflowNodeIdField",
        "warningWorkflowNodeId",
        "runtimeWorkspaceTrustGateWarningWorkflowNodeId",
        "runtime.thread-mode.workspace-trust",
    );
    let warning_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeWorkspaceTrustGateWarningIdField",
        "warningId",
        "runtimeWorkspaceTrustGateWarningId",
        "",
    );
    let acknowledgement_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeWorkspaceTrustGateAcknowledgementEventField",
        "acknowledgementEventId",
        "runtimeWorkspaceTrustGateAcknowledgementEventId",
        "",
    );
    let require_acknowledgement = workflow_runtime_control_bool_field_or_logic(
        logic,
        input,
        "runtimeWorkspaceTrustGateRequireAcknowledgementField",
        "requireAcknowledgement",
        "runtimeWorkspaceTrustGateRequireAcknowledgement",
        true,
    );
    let acknowledged = !require_acknowledgement || !acknowledgement_event_id.trim().is_empty();
    let status = if acknowledged { "passed" } else { "blocked" };
    let warning_id_value = if warning_id.trim().is_empty() {
        Value::Null
    } else {
        json!(warning_id)
    };
    let acknowledgement_event_value = if acknowledgement_event_id.trim().is_empty() {
        Value::Null
    } else {
        json!(acknowledgement_event_id)
    };
    let gate = json!({
        "schemaVersion": "ioi.workflow.runtime-workspace-trust-gate.v1",
        "status": status,
        "componentKind": "workspace_trust_gate",
        "workflowGraphId": workflow_graph_id.clone(),
        "workflowNodeId": workflow_node_id.clone(),
        "warningId": warning_id_value.clone(),
        "warningWorkflowNodeId": warning_workflow_node_id,
        "acknowledgementEventId": acknowledgement_event_value.clone(),
        "receiptRefs": [],
        "policyDecisionRefs": [],
        "daemonEventHistoryRequired": true,
        "canvasLocalTrustAccepted": false
    });
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": "ioi.workflow.runtime-workspace-trust-gate.v1",
        "status": status,
        "componentKind": "workspace_trust_gate",
        "workflowGraphId": workflow_graph_id,
        "workflowNodeId": workflow_node_id,
        "warningId": gate.get("warningId").cloned().unwrap_or(Value::Null),
        "warningWorkflowNodeId": gate.get("warningWorkflowNodeId").cloned().unwrap_or(Value::Null),
        "acknowledgementEventId": acknowledgement_event_value,
        "receiptRefs": [],
        "policyDecisionRefs": [],
        "daemonEventHistoryRequired": true,
        "canvasLocalTrustAccepted": false,
        "runtimeWorkspaceTrustGate": gate,
        "input": input
    })
}

fn workflow_runtime_approval_request_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeApprovalRequestThreadId",
            thread_id_field_key: "runtimeApprovalRequestThreadIdField",
            turn_id_logic_key: Some("runtimeApprovalRequestTurnId"),
            turn_id_field_key: Some("runtimeApprovalRequestTurnIdField"),
            workflow_node_id_logic_key: "runtimeApprovalRequestWorkflowNodeId",
            actor_logic_key: "runtimeApprovalRequestActor",
            endpoint_logic_key: "runtimeApprovalRequestEndpoint",
            default_workflow_node_id: "runtime.approval.context-pressure",
            default_endpoint: "/v1/threads/{threadId}/approvals",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-approval-request-control.v1",
        source: "react_flow",
        component_kind: "approval_gate",
        event_kind: "OperatorApproval.Request",
        payload_schema_version: "ioi.runtime.approval-request.v1",
        nested_key: "runtimeApprovalRequest",
    };
    let approval_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestApprovalIdField",
        "approvalId",
        "runtimeApprovalRequestApprovalId",
        &format!(
            "approval-{}-{}",
            envelope.thread_id,
            envelope.turn_id.as_deref().unwrap_or("thread")
        ),
    );
    let reason = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestReasonField",
        "reason",
        "runtimeApprovalRequestReason",
        "Request operator approval from React Flow workflow control.",
    );
    let scope = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestScopeField",
        "scope",
        "runtimeApprovalRequestScope",
        "thread",
    );
    let pressure_field =
        workflow_runtime_control_logic_string(logic, "runtimeApprovalRequestPressureField")
            .unwrap_or_else(|| "pressure".to_string());
    let pressure = workflow_runtime_control_input_number(input, &pressure_field)
        .map(Value::from)
        .unwrap_or(Value::Null);
    let pressure_status = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestPressureStatusField",
        "pressureStatus",
        "runtimeApprovalRequestPressureStatus",
        "",
    );
    let alert_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestAlertIdField",
        "alertId",
        "runtimeApprovalRequestAlertId",
        "",
    );
    let source_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeApprovalRequestSourceEventIdField",
        "sourceEventId",
        "runtimeApprovalRequestSourceEventId",
        "",
    );
    let turn_id_value = envelope
        .turn_id
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![
            ("approvalId", json!(approval_id.clone())),
            ("approval_id", json!(approval_id.clone())),
            ("reason", json!(reason)),
            ("scope", json!(scope)),
            ("turnId", turn_id_value.clone()),
            ("turn_id", turn_id_value.clone()),
            ("pressure", pressure),
            ("pressureStatus", json!(pressure_status.clone())),
            ("pressure_status", json!(pressure_status)),
            ("alertId", json!(alert_id.clone())),
            ("alert_id", json!(alert_id)),
            ("sourceEventId", json!(source_event_id.clone())),
            ("source_event_id", json!(source_event_id)),
        ],
    );
    let mut output = workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        Some(turn_id_value),
        request,
    );
    output["approvalId"] = json!(approval_id);
    output
}

fn workflow_runtime_rollback_snapshot_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeRollbackSnapshotThreadId",
            thread_id_field_key: "runtimeRollbackSnapshotThreadIdField",
            turn_id_logic_key: None,
            turn_id_field_key: None,
            workflow_node_id_logic_key: "runtimeRollbackSnapshotWorkflowNodeId",
            actor_logic_key: "runtimeRollbackSnapshotActor",
            endpoint_logic_key: "runtimeRollbackSnapshotEndpoint",
            default_workflow_node_id: "runtime.rollback-snapshot",
            default_endpoint: "/v1/threads/{threadId}/snapshots",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-rollback-snapshot-control.v1",
        source: "react_flow",
        component_kind: "workspace_snapshot",
        event_kind: "WorkspaceSnapshot.List",
        payload_schema_version: "ioi.runtime.workspace-snapshot.v1",
        nested_key: "runtimeRollbackSnapshot",
    };
    let request = workflow_runtime_control_request(&output_config, &envelope, vec![]);
    workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        None,
        request,
    )
}

fn workflow_runtime_restore_gate_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let mut envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeRestoreGateThreadId",
            thread_id_field_key: "runtimeRestoreGateThreadIdField",
            turn_id_logic_key: None,
            turn_id_field_key: None,
            workflow_node_id_logic_key: "runtimeRestoreGateWorkflowNodeId",
            actor_logic_key: "runtimeRestoreGateActor",
            endpoint_logic_key: "runtimeRestoreGateEndpoint",
            default_workflow_node_id: "runtime.restore-gate",
            default_endpoint: "/v1/threads/{threadId}/snapshots/{snapshotId}/restore-{mode}",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-restore-gate-control.v1",
        source: "react_flow",
        component_kind: "restore_gate",
        event_kind: "WorkspaceRestore.Gate",
        payload_schema_version: "ioi.runtime.workspace-restore-gate.v1",
        nested_key: "runtimeRestoreGate",
    };
    let snapshot_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeRestoreGateSnapshotIdField",
        "snapshotId",
        "runtimeRestoreGateSnapshotId",
        "{{runtime.snapshot_id}}",
    );
    let mode = workflow_runtime_restore_gate_mode(workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeRestoreGateModeField",
        "mode",
        "runtimeRestoreGateMode",
        "preview",
    ));
    let conflict_policy =
        workflow_runtime_restore_conflict_policy(workflow_runtime_control_input_field_or_logic(
            logic,
            input,
            "runtimeRestoreGateConflictPolicyField",
            "conflictPolicy",
            "runtimeRestoreGateConflictPolicy",
            "block",
        ));
    let approval_granted = workflow_runtime_control_bool_field_or_logic(
        logic,
        input,
        "runtimeRestoreGateApprovalGrantedField",
        "approvalGranted",
        "runtimeRestoreGateApprovalGranted",
        false,
    );
    let allow_conflicts = conflict_policy == "allow_override";
    envelope.endpoint = envelope
        .endpoint
        .replace("{snapshotId}", &snapshot_id)
        .replace("{mode}", &mode);
    let mutation_executed = mode == "apply" && approval_granted;
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![
            ("snapshotId", json!(snapshot_id.clone())),
            ("snapshot_id", json!(snapshot_id.clone())),
            ("mode", json!(mode.clone())),
            ("conflictPolicy", json!(conflict_policy.clone())),
            ("conflict_policy", json!(conflict_policy.clone())),
            ("approvalGranted", json!(approval_granted)),
            ("approval_granted", json!(approval_granted)),
            ("allowConflicts", json!(allow_conflicts)),
            ("allow_conflicts", json!(allow_conflicts)),
        ],
    );
    let mut output = workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        None,
        request,
    );
    output["snapshotId"] = json!(snapshot_id.clone());
    output["mode"] = json!(mode.clone());
    output["conflictPolicy"] = json!(conflict_policy.clone());
    output["approvalGranted"] = json!(approval_granted);
    output["mutationExecuted"] = json!(mutation_executed);
    output["runtimeRestoreGate"]["snapshotId"] = json!(snapshot_id);
    output["runtimeRestoreGate"]["mode"] = json!(mode);
    output["runtimeRestoreGate"]["conflictPolicy"] = json!(conflict_policy);
    output["runtimeRestoreGate"]["approvalGranted"] = json!(approval_granted);
    output["runtimeRestoreGate"]["mutationExecuted"] = json!(mutation_executed);
    output
}

fn workflow_runtime_diagnostics_repair_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let mut envelope = workflow_runtime_control_envelope(
        workflow,
        logic,
        input,
        &WorkflowRuntimeControlEnvelopeConfig {
            thread_id_logic_key: "runtimeDiagnosticsRepairThreadId",
            thread_id_field_key: "runtimeDiagnosticsRepairThreadIdField",
            turn_id_logic_key: None,
            turn_id_field_key: None,
            workflow_node_id_logic_key: "runtimeDiagnosticsRepairWorkflowNodeId",
            actor_logic_key: "runtimeDiagnosticsRepairActor",
            endpoint_logic_key: "runtimeDiagnosticsRepairEndpoint",
            default_workflow_node_id: "runtime.diagnostics-repair",
            default_endpoint:
                "/v1/threads/{threadId}/diagnostics/repair-decisions/{decisionId}/execute",
            missing_turn_id: None,
        },
    );
    let output_config = WorkflowRuntimeControlOutputConfig {
        schema_version: "ioi.workflow.runtime-diagnostics-repair-control.v1",
        source: "react_flow",
        component_kind: "lsp_diagnostics_repair",
        event_kind: "LspDiagnostics.RepairDecisionExecuted",
        payload_schema_version: "ioi.runtime.diagnostics-repair-decision-execution.v1",
        nested_key: "runtimeDiagnosticsRepair",
    };
    let action =
        workflow_runtime_diagnostics_repair_action(workflow_runtime_control_input_field_or_logic(
            logic,
            input,
            "runtimeDiagnosticsRepairActionField",
            "action",
            "runtimeDiagnosticsRepairAction",
            "repair_retry",
        ));
    let decision_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeDiagnosticsRepairDecisionIdField",
        "decisionId",
        "runtimeDiagnosticsRepairDecisionId",
        &action,
    );
    let message = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeDiagnosticsRepairMessageField",
        "message",
        "runtimeDiagnosticsRepairMessage",
        "",
    );
    let approval_granted = workflow_runtime_control_bool_field_or_logic(
        logic,
        input,
        "runtimeDiagnosticsRepairApprovalGrantedField",
        "approvalGranted",
        "runtimeDiagnosticsRepairApprovalGranted",
        false,
    );
    let allow_conflicts = workflow_runtime_control_bool_field_or_logic(
        logic,
        input,
        "runtimeDiagnosticsRepairAllowConflictsField",
        "allowConflicts",
        "runtimeDiagnosticsRepairAllowConflicts",
        false,
    );
    envelope.endpoint = envelope.endpoint.replace("{decisionId}", &decision_id);
    let mutation_executed =
        action == "repair_retry" || action == "restore_apply" || action == "operator_override";
    let request = workflow_runtime_control_request(
        &output_config,
        &envelope,
        vec![
            ("decisionId", json!(decision_id.clone())),
            ("decision_id", json!(decision_id.clone())),
            ("action", json!(action.clone())),
            ("message", json!(message.clone())),
            ("approvalGranted", json!(approval_granted)),
            ("approval_granted", json!(approval_granted)),
            ("approved", json!(approval_granted)),
            ("confirm", json!(approval_granted)),
            ("operatorOverrideApproved", json!(approval_granted)),
            ("operator_override_approved", json!(approval_granted)),
            ("allowConflicts", json!(allow_conflicts)),
            ("allow_conflicts", json!(allow_conflicts)),
            ("overrideConflicts", json!(allow_conflicts)),
            ("override_conflicts", json!(allow_conflicts)),
        ],
    );
    let mut output = workflow_runtime_control_output(
        node_id,
        evidence_kind,
        input,
        &output_config,
        envelope,
        None,
        request,
    );
    output["decisionId"] = json!(decision_id.clone());
    output["action"] = json!(action.clone());
    output["message"] = json!(message.clone());
    output["approvalGranted"] = json!(approval_granted);
    output["allowConflicts"] = json!(allow_conflicts);
    output["mutationExecuted"] = json!(mutation_executed);
    output["runtimeDiagnosticsRepair"]["decisionId"] = json!(decision_id);
    output["runtimeDiagnosticsRepair"]["action"] = json!(action);
    output["runtimeDiagnosticsRepair"]["message"] = json!(message);
    output["runtimeDiagnosticsRepair"]["approvalGranted"] = json!(approval_granted);
    output["runtimeDiagnosticsRepair"]["allowConflicts"] = json!(allow_conflicts);
    output["runtimeDiagnosticsRepair"]["mutationExecuted"] = json!(mutation_executed);
    output
}

fn workflow_runtime_coding_tool_budget_recovery_policy(
    logic: &Value,
    input: &Value,
    target_node_ids: &[String],
) -> Value {
    let policy_field = workflow_runtime_control_logic_string(
        logic,
        "runtimeCodingToolBudgetRecoveryPolicyInputField",
    )
    .unwrap_or_else(|| "recoveryPolicy".to_string());
    let mut policy = workflow_runtime_control_value_at_path(input, &policy_field)
        .or_else(|| workflow_runtime_control_value_at_path(input, "recovery_policy"))
        .or_else(|| logic.get("runtimeCodingToolBudgetRecoveryPolicy"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !policy.is_object() {
        policy = json!({});
    }
    if let Value::Object(object) = &mut policy {
        object
            .entry("schemaVersion")
            .or_insert_with(|| json!("ioi.workflow.coding-tool-budget-recovery-policy.v1"));
        object
            .entry("schema_version")
            .or_insert_with(|| json!("ioi.workflow.coding-tool-budget-recovery-policy.v1"));
        object
            .entry("source")
            .or_insert_with(|| json!("react_flow"));
        object
            .entry("approvalScope")
            .or_insert_with(|| json!("target_nodes"));
        object
            .entry("approval_scope")
            .or_insert_with(|| json!("target_nodes"));
        object
            .entry("operatorRole")
            .or_insert_with(|| json!("budget_operator"));
        object
            .entry("operator_role")
            .or_insert_with(|| json!("budget_operator"));
        object.entry("retryLimit").or_insert_with(|| json!(1));
        object.entry("retry_limit").or_insert_with(|| json!(1));
        object.entry("ttlMs").or_insert_with(|| json!(900000));
        object.entry("ttl_ms").or_insert_with(|| json!(900000));
        object
            .entry("requiresApproval")
            .or_insert_with(|| json!(true));
        object
            .entry("requires_approval")
            .or_insert_with(|| json!(true));
        object.entry("allowOverride").or_insert_with(|| json!(true));
        object
            .entry("allow_override")
            .or_insert_with(|| json!(true));
        if !object.contains_key("targetNodeIds") && !object.contains_key("target_node_ids") {
            object.insert("targetNodeIds".to_string(), json!(target_node_ids));
            object.insert("target_node_ids".to_string(), json!(target_node_ids));
        }
        object.entry("sourceNodeIds").or_insert_with(|| json!([]));
        object.entry("source_node_ids").or_insert_with(|| json!([]));
    }
    policy
}

fn workflow_runtime_coding_tool_budget_recovery_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let run_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeCodingToolBudgetRecoveryRunIdField")
            .unwrap_or_else(|| "runId".to_string());
    let run_id =
        workflow_runtime_control_logic_string(logic, "runtimeCodingToolBudgetRecoveryRunId")
            .or_else(|| workflow_runtime_control_input_string(input, &run_id_field))
            .or_else(|| workflow_runtime_control_input_string(input, "run_id"))
            .unwrap_or_else(|| "{{runtime.run_id}}".to_string());
    let thread_id_field = workflow_runtime_control_logic_string(
        logic,
        "runtimeCodingToolBudgetRecoveryThreadIdField",
    )
    .unwrap_or_else(|| "threadId".to_string());
    let thread_id =
        workflow_runtime_control_logic_string(logic, "runtimeCodingToolBudgetRecoveryThreadId")
            .or_else(|| workflow_runtime_control_input_string(input, &thread_id_field))
            .or_else(|| workflow_runtime_control_input_string(input, "thread_id"))
            .unwrap_or_else(|| "{{runtime.thread_id}}".to_string());
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let workflow_node_id = workflow_runtime_control_logic_string(
        logic,
        "runtimeCodingToolBudgetRecoveryWorkflowNodeId",
    )
    .unwrap_or_else(|| "runtime.coding-tool-budget-recovery".to_string());
    let actor =
        workflow_runtime_control_logic_string(logic, "runtimeCodingToolBudgetRecoveryActor")
            .unwrap_or_else(|| "operator".to_string());
    let endpoint_template =
        workflow_runtime_control_logic_string(logic, "runtimeCodingToolBudgetRecoveryEndpoint")
            .unwrap_or_else(|| "/v1/runs/{runId}/coding-tool-budget-recovery".to_string());
    let action = workflow_runtime_coding_tool_budget_recovery_action(
        workflow_runtime_control_input_field_or_logic(
            logic,
            input,
            "runtimeCodingToolBudgetRecoveryActionField",
            "action",
            "runtimeCodingToolBudgetRecoveryAction",
            "request_approval",
        ),
    );
    let approval_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoveryApprovalIdField",
        "approvalId",
        "runtimeCodingToolBudgetRecoveryApprovalId",
        &format!("approval_workflow_run_coding_tool_budget_{}", run_id),
    );
    let source_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoverySourceEventIdField",
        "sourceEventId",
        "runtimeCodingToolBudgetRecoverySourceEventId",
        "",
    );
    let blocked_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoveryBlockedEventIdField",
        "blockedEventId",
        "runtimeCodingToolBudgetRecoveryBlockedEventId",
        "",
    );
    let approval_request_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoveryApprovalRequestEventIdField",
        "approvalRequestEventId",
        "runtimeCodingToolBudgetRecoveryApprovalRequestEventId",
        "",
    );
    let approval_decision_event_id = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoveryApprovalDecisionEventIdField",
        "approvalDecisionEventId",
        "runtimeCodingToolBudgetRecoveryApprovalDecisionEventId",
        "",
    );
    let target_node_ids_field = workflow_runtime_control_logic_string(
        logic,
        "runtimeCodingToolBudgetRecoveryTargetNodeIdsField",
    )
    .unwrap_or_else(|| "targetNodeIds".to_string());
    let mut target_node_ids =
        workflow_runtime_control_input_string_array(input, &target_node_ids_field);
    if target_node_ids.is_empty() {
        target_node_ids = workflow_runtime_control_input_string_array(input, "target_node_ids");
    }
    if target_node_ids.is_empty() {
        target_node_ids = workflow_runtime_control_logic_string_array(
            logic,
            "runtimeCodingToolBudgetRecoveryTargetNodeIds",
        );
    }
    let recovery_policy =
        workflow_runtime_coding_tool_budget_recovery_policy(logic, input, &target_node_ids);
    let reason = workflow_runtime_control_input_field_or_logic(
        logic,
        input,
        "runtimeCodingToolBudgetRecoveryReasonField",
        "reason",
        "runtimeCodingToolBudgetRecoveryReason",
        "coding_tool_budget_preflight_blocked",
    );
    let source_event_id_value = if source_event_id.trim().is_empty() {
        Value::Null
    } else {
        json!(source_event_id)
    };
    let blocked_event_id_value = if blocked_event_id.trim().is_empty() {
        Value::Null
    } else {
        json!(blocked_event_id)
    };
    let approval_request_event_id_value = if approval_request_event_id.trim().is_empty() {
        Value::Null
    } else {
        json!(approval_request_event_id)
    };
    let approval_decision_event_id_value = if approval_decision_event_id.trim().is_empty() {
        Value::Null
    } else {
        json!(approval_decision_event_id)
    };
    let endpoint = endpoint_template
        .replace("{runId}", &run_id)
        .replace("{threadId}", &thread_id)
        .replace("{approvalId}", &approval_id)
        .replace(
            "{sourceEventId}",
            source_event_id_value.as_str().unwrap_or(""),
        );
    let request = json!({
        "source": "react_flow",
        "actor": actor,
        "eventKind": "WorkflowRunCodingToolBudgetRecoveryControl",
        "event_kind": "WorkflowRunCodingToolBudgetRecoveryControl",
        "componentKind": "coding_tool_budget_recovery",
        "component_kind": "coding_tool_budget_recovery",
        "payloadSchemaVersion": "ioi.workflow.coding-tool-budget-recovery.v1",
        "payload_schema_version": "ioi.workflow.coding-tool-budget-recovery.v1",
        "action": action,
        "recoveryAction": action,
        "recovery_action": action,
        "reason": reason,
        "runId": run_id,
        "run_id": run_id,
        "threadId": thread_id,
        "thread_id": thread_id,
        "approvalId": approval_id,
        "approval_id": approval_id,
        "sourceEventId": source_event_id_value,
        "source_event_id": source_event_id_value,
        "blockedEventId": blocked_event_id_value,
        "blocked_event_id": blocked_event_id_value,
        "approvalRequestEventId": approval_request_event_id_value,
        "approval_request_event_id": approval_request_event_id_value,
        "approvalDecisionEventId": approval_decision_event_id_value,
        "approval_decision_event_id": approval_decision_event_id_value,
        "targetNodeIds": target_node_ids,
        "target_node_ids": target_node_ids,
        "workflowGraphId": workflow_graph_id,
        "workflow_graph_id": workflow_graph_id,
        "workflowNodeId": workflow_node_id,
        "workflow_node_id": workflow_node_id,
        "recoveryPolicy": recovery_policy,
        "recovery_policy": recovery_policy,
        "receiptRefs": [],
        "receipt_refs": [],
        "policyDecisionRefs": [],
        "policy_decision_refs": []
    });
    let runtime_control = json!({
        "schemaVersion": "ioi.workflow.runtime-coding-tool-budget-recovery-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "coding_tool_budget_recovery",
        "workflowGraphId": request.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": request.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "runId": request.get("runId").cloned().unwrap_or(Value::Null),
        "threadId": request.get("threadId").cloned().unwrap_or(Value::Null),
        "action": request.get("action").cloned().unwrap_or(Value::Null),
        "approvalId": request.get("approvalId").cloned().unwrap_or(Value::Null),
        "sourceEventId": request.get("sourceEventId").cloned().unwrap_or(Value::Null),
        "targetNodeIds": request.get("targetNodeIds").cloned().unwrap_or(Value::Null),
        "recoveryPolicy": request.get("recoveryPolicy").cloned().unwrap_or(Value::Null),
        "endpoint": endpoint,
        "request": request,
        "mutationExecuted": true
    });
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": "ioi.workflow.runtime-coding-tool-budget-recovery-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "coding_tool_budget_recovery",
        "workflowGraphId": runtime_control.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": runtime_control.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "runId": runtime_control.get("runId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_control.get("threadId").cloned().unwrap_or(Value::Null),
        "action": runtime_control.get("action").cloned().unwrap_or(Value::Null),
        "approvalId": runtime_control.get("approvalId").cloned().unwrap_or(Value::Null),
        "sourceEventId": runtime_control.get("sourceEventId").cloned().unwrap_or(Value::Null),
        "targetNodeIds": runtime_control.get("targetNodeIds").cloned().unwrap_or(Value::Null),
        "recoveryPolicy": runtime_control.get("recoveryPolicy").cloned().unwrap_or(Value::Null),
        "endpoint": runtime_control.get("endpoint").cloned().unwrap_or(Value::Null),
        "request": runtime_control.get("request").cloned().unwrap_or(Value::Null),
        "mutationExecuted": true,
        "runtimeCodingToolBudgetRecovery": runtime_control,
        "input": input
    })
}

pub(super) fn execute_workflow_node(
    workflow_path: &Path,
    workflow: Option<&WorkflowProject>,
    node: &Value,
    input: Value,
    attempt: usize,
    resume_outcome: Option<&Value>,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<Value, String> {
    let frame = workflow_action_frame(node);
    let node_id = frame.id.clone();
    let node_name = frame.label.clone();
    let node_type = frame.kind.node_type().to_string();
    let action_kind = frame.kind.clone();
    let logic = workflow_node_logic(node);

    if logic
        .get("failUntilAttempt")
        .and_then(Value::as_u64)
        .map(|limit| attempt as u64 <= limit)
        .unwrap_or(false)
    {
        return Err(format!(
            "Node '{}' failed on attempt {}.",
            node_name, attempt
        ));
    }
    if logic.get("fail").and_then(Value::as_bool).unwrap_or(false) {
        return Err(format!(
            "Node '{}' requested a deterministic failure.",
            node_name
        ));
    }

    let evidence_kind = action_kind.evidence_kind();
    let output = match action_kind {
        ActionKind::SourceInput => {
            let payload = logic
                .get("payload")
                .or_else(|| logic.get("variables"))
                .cloned()
                .unwrap_or_else(|| json!({"source": node_name}));
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "payload": payload
            })
        }
        ActionKind::Trigger => {
            let trigger_kind = logic
                .get("triggerKind")
                .and_then(Value::as_str)
                .unwrap_or("manual");
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "triggerKind": trigger_kind,
                "schedule": logic.get("cronSchedule").cloned().unwrap_or(Value::Null),
                "eventSourceRef": logic.get("eventSourceRef").cloned().unwrap_or(Value::Null),
                "dedupeKey": logic.get("dedupeKey").cloned().unwrap_or(Value::Null),
                "payload": input
            })
        }
        ActionKind::TaskState => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "currentObjective": logic.get("objective").cloned().unwrap_or_else(|| input.clone()),
                "knownFacts": logic.get("knownFacts").cloned().unwrap_or_else(|| json!([])),
                "uncertainFacts": logic.get("uncertainFacts").cloned().unwrap_or_else(|| json!([])),
                "constraints": logic.get("constraints").cloned().unwrap_or_else(|| json!([])),
                "evidenceRefs": logic.get("evidenceRefs").cloned().unwrap_or_else(|| json!([])),
                "input": input
            })
        }
        ActionKind::UncertaintyGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "ambiguityLevel": logic.get("ambiguityLevel").and_then(Value::as_str).unwrap_or("medium"),
                "selectedAction": logic.get("selectedAction").and_then(Value::as_str).unwrap_or("probe"),
                "valueOfProbe": logic.get("valueOfProbe").and_then(Value::as_str).unwrap_or("medium"),
                "input": input
            })
        }
        ActionKind::Probe => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "hypothesis": logic.get("hypothesis").cloned().unwrap_or_else(|| json!("Probe workflow assumption")),
                "cheapestValidationAction": logic.get("cheapestValidationAction").cloned().unwrap_or_else(|| json!("Inspect current workflow evidence")),
                "result": logic.get("result").cloned().unwrap_or_else(|| json!("confirmed")),
                "input": input
            })
        }
        ActionKind::BudgetGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "budget": logic.get("budget").cloned().unwrap_or_else(|| json!({"maxToolCalls": 1, "maxRetries": 0})),
                "decision": logic.get("decision").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::CapabilitySequence => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sequence": logic.get("sequence").cloned().unwrap_or_else(|| json!(["discover", "select", "execute", "verify"])),
                "input": input
            })
        }
        ActionKind::RepositoryContext => {
            workflow_repository_context_output(workflow_path, &node_id, &logic, evidence_kind)
        }
        ActionKind::BranchPolicy => {
            workflow_branch_policy_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::GithubContext => {
            workflow_github_context_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::IssueContext => {
            workflow_issue_context_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::PrAttempt => {
            workflow_pr_attempt_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::ReviewGate => {
            workflow_review_gate_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::GithubPrCreate => {
            workflow_github_pr_create_output(&node_id, &logic, &input, evidence_kind)?
        }
        ActionKind::WorkflowPackageExport => execute_workflow_package_export_node(
            workflow_path,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        )?,
        ActionKind::WorkflowPackageImport => execute_workflow_package_import_node(
            workflow_path,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        )?,
        ActionKind::RuntimeThreadFork => {
            workflow_runtime_thread_fork_output(workflow, &node_id, &logic, &input, evidence_kind)
        }
        ActionKind::RuntimeOperatorInterrupt => workflow_runtime_operator_interrupt_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeOperatorSteer => workflow_runtime_operator_steer_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeThreadMode => {
            workflow_runtime_thread_mode_output(workflow, &node_id, &logic, &input, evidence_kind)
        }
        ActionKind::RuntimeWorkspaceTrustGate => workflow_runtime_workspace_trust_gate_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeContextCompact => workflow_runtime_context_compact_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeApprovalRequest => workflow_runtime_approval_request_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeRollbackSnapshot => workflow_runtime_rollback_snapshot_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeRestoreGate => {
            workflow_runtime_restore_gate_output(workflow, &node_id, &logic, &input, evidence_kind)
        }
        ActionKind::RuntimeDiagnosticsRepair => workflow_runtime_diagnostics_repair_output(
            workflow,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        ),
        ActionKind::RuntimeCodingToolBudgetRecovery => {
            workflow_runtime_coding_tool_budget_recovery_output(
                workflow,
                &node_id,
                &logic,
                &input,
                evidence_kind,
            )
        }
        ActionKind::DryRun => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sideEffectPreview": true,
                "mutationExecuted": false,
                "input": input
            })
        }
        ActionKind::Function => execute_workflow_function_node(node, input.clone())?,
        ActionKind::ModelBinding => {
            let binding = workflow_model_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": binding.model_ref,
                "capabilityScope": binding.capability_scope,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding,
                "credentialReady": binding.credential_ready.unwrap_or(false),
                "toolUseMode": binding.tool_use_mode.unwrap_or_else(|| "none".to_string())
            })
        }
        ActionKind::SkillContext => {
            skill_resolver.resolve_skill_context(workflow, &node_id, &logic, &input)?
        }
        ActionKind::ModelCall => {
            let model_ref = logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .or_else(|| workflow_model_ref_from_input(&input))
                .ok_or_else(|| "Model binding is missing.".to_string())?;
            let parser_attachment = workflow_inputs_by_kind(&input, "parser").into_iter().next();
            let skill_context_attachment = workflow_inputs_by_kind(&input, "skill_context")
                .into_iter()
                .next();
            let memory_attachment = workflow_inputs_by_kind(&input, "state").into_iter().next();
            let mut tool_attachments = workflow_inputs_by_kind(&input, "plugin_tool");
            tool_attachments.extend(workflow_inputs_by_kind(&input, "tool"));
            let tool_calls = tool_attachments
                .iter()
                .map(|tool| {
                    json!({
                        "toolName": tool
                            .get("toolName")
                            .or_else(|| tool.get("toolKind"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "mockBinding": tool.get("mockBinding").cloned().unwrap_or(Value::Null),
                        "sideEffectClass": tool.get("sideEffectClass").cloned().unwrap_or(Value::Null),
                        "result": tool
                            .get("result")
                            .or_else(|| tool.get("input"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    })
                })
                .collect::<Vec<_>>();
            let parsed_output_schema = parser_attachment
                .as_ref()
                .and_then(|parser| parser.get("resultSchema").cloned())
                .or_else(|| logic.get("outputSchema").cloned());
            let memory_send_options = workflow_memory_send_options(&logic, &node_id);
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": model_ref,
                "message": format!("{} completed with bound model {}.", node_name, model_ref),
                "input": input,
                "attachments": {
                    "skillContext": skill_context_attachment,
                    "parser": parser_attachment,
                    "memory": memory_attachment,
                    "memoryPolicy": memory_send_options.clone(),
                    "tools": tool_attachments
                },
                "runtimeSendOptions": {
                    "memory": memory_send_options
                },
                "toolCalls": tool_calls,
                "structuredOutputSchema": parsed_output_schema,
                "streaming": {
                    "eventKinds": ["node_started", "state_updated", "node_succeeded"]
                }
            })
        }
        ActionKind::Parser => {
            let binding = workflow_parser_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "parserRef": binding.parser_ref,
                "parserKind": binding.parser_kind,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding.unwrap_or(true)
            })
        }
        ActionKind::AdapterConnector => {
            let binding = workflow_connector_binding(node)?;
            if !binding.mock_binding
                && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
            {
                return Err(
                    "Live connector writes require a configured approval-backed connector runtime."
                        .to_string(),
                );
            }
            let provider_catalog = workflow_live_mcp_provider_catalog(&binding, &input);
            let connector_catalog = workflow_live_connector_catalog_describe(&binding, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "connector": binding.connector_ref,
                "mockBinding": binding.mock_binding,
                "credentialReady": binding.credential_ready.unwrap_or(false),
                "sideEffectClass": binding.side_effect_class,
                "operation": binding.operation,
                "providerCatalog": provider_catalog,
                "connectorCatalog": connector_catalog,
                "input": input
            })
        }
        ActionKind::PluginTool => {
            let binding = workflow_tool_binding(node)?;
            if binding.binding_kind.as_deref() == Some("workflow_tool") {
                execute_workflow_tool_binding(workflow_path, &node_id, &binding, input.clone())?
            } else {
                if !binding.mock_binding
                    && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
                {
                    return Err(
                    "Live plugin side effects require a configured approval-backed tool runtime."
                        .to_string(),
                );
                }
                let tool_ref = binding.tool_ref.clone();
                let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
                if let Some(schema) = binding.argument_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
                        format!("Tool arguments failed schema validation: {}", error)
                    })?;
                }
                let live_mcp_tool_catalog =
                    workflow_live_mcp_tool_catalog(&binding, &arguments, &input)?;
                let live_native_tool_catalog = if live_mcp_tool_catalog.is_none() {
                    workflow_live_native_tool_catalog(&binding, &arguments, &input)?
                } else {
                    None
                };
                let result = live_mcp_tool_catalog
                    .or(live_native_tool_catalog)
                    .unwrap_or_else(|| {
                        json!({
                            "toolRef": tool_ref,
                            "arguments": arguments.clone(),
                            "input": input
                        })
                    });
                if let Some(schema) = binding.result_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &result).map_err(|error| {
                        format!("Tool result failed schema validation: {}", error)
                    })?;
                }
                json!({
                    "nodeId": node_id,
                    "kind": evidence_kind,
                    "toolName": tool_ref,
                    "mockBinding": binding.mock_binding,
                    "credentialReady": binding.credential_ready.unwrap_or(false),
                    "sideEffectClass": binding.side_effect_class,
                    "arguments": arguments,
                    "argumentSchema": binding.argument_schema,
                    "resultSchema": binding.result_schema,
                    "mcpToolCatalog": if result.get("schemaVersion").and_then(Value::as_str) == Some("workflow.mcp-tool.catalog-read.v1") { Some(result.clone()) } else { None },
                    "nativeToolCatalog": if result.get("schemaVersion").and_then(Value::as_str) == Some("workflow.native-tool.catalog-read.v1") { Some(result.clone()) } else { None },
                    "result": result
                })
            }
        }
        ActionKind::Decision => {
            let branch = logic
                .get("defaultRoute")
                .and_then(Value::as_str)
                .or_else(|| {
                    logic
                        .get("routes")
                        .and_then(Value::as_array)
                        .and_then(|routes| routes.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or("left");
            let authority_policy_gate = workflow_live_authority_policy_gate(&logic, &input)?;
            let authority_destructive_denial =
                workflow_live_authority_destructive_denial(&logic, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": branch,
                "authorityPolicyGate": authority_policy_gate,
                "authorityDestructiveDenial": authority_destructive_denial,
                "input": input
            })
        }
        ActionKind::State => {
            let key = logic
                .get("stateKey")
                .and_then(Value::as_str)
                .unwrap_or("memory");
            let operation = logic
                .get("stateOperation")
                .and_then(Value::as_str)
                .unwrap_or("merge");
            if matches!(operation, "memory_search" | "memory_list") {
                workflow_memory_query_output(&logic, &input, &node_id, evidence_kind)
            } else if matches!(
                operation,
                "memory_remember" | "memory_edit" | "memory_delete"
            ) {
                workflow_memory_mutation_output(&logic, &input, &node_id, evidence_kind)
            } else {
                let reducer =
                    logic
                        .get("reducer")
                        .and_then(Value::as_str)
                        .unwrap_or(match operation {
                            "append" => "append",
                            "merge" => "merge",
                            _ => "replace",
                        });
                json!({
                    "nodeId": node_id,
                    "kind": evidence_kind,
                    "stateKey": key,
                    "operation": operation,
                    "reducer": reducer,
                    "value": input
                })
            }
        }
        ActionKind::Loop => {
            let max_iterations = logic
                .get("maxIterations")
                .and_then(Value::as_u64)
                .unwrap_or(3);
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": "output",
                "maxIterations": max_iterations,
                "input": input
            })
        }
        ActionKind::Barrier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "strategy": logic.get("barrierStrategy").and_then(Value::as_str).unwrap_or("all"),
                "inputs": input
            })
        }
        ActionKind::Subgraph => {
            let path = logic
                .get("subgraphRef")
                .and_then(|ref_value| ref_value.get("workflowPath"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "Subgraph workflow path is missing.".to_string())?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "childWorkflowPath": path,
                "childRunStatus": "blocked",
                "summary": "Subgraph invocation is bound but deferred to child workflow runtime.",
                "input": input
            })
        }
        ActionKind::HumanGate => {
            let Some(outcome) = resume_outcome else {
                return Err("Human gate requires an interrupt.".to_string());
            };
            let wallet_capability_dry_run =
                workflow_live_wallet_capability_dry_run(&logic, outcome, &input)?;
            let authority_approval_gate =
                workflow_live_authority_approval_gate(&logic, outcome, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "outcome": outcome,
                "authorityApprovalGate": authority_approval_gate,
                "walletCapabilityDryRun": wallet_capability_dry_run,
                "input": input
            })
        }
        ActionKind::SemanticImpact => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "changedSymbols": logic.get("changedSymbols").cloned().unwrap_or_else(|| json!([])),
                "changedApis": logic.get("changedApis").cloned().unwrap_or_else(|| json!([])),
                "affectedTests": logic.get("affectedTests").cloned().unwrap_or_else(|| json!([])),
                "riskClass": logic.get("riskClass").and_then(Value::as_str).unwrap_or("bounded"),
                "input": input
            })
        }
        ActionKind::PostconditionSynthesis => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "checks": logic.get("checks").cloned().unwrap_or_else(|| json!([])),
                "minimumEvidence": logic.get("minimumEvidence").cloned().unwrap_or_else(|| json!(["trace", "receipt", "stop_condition"])),
                "input": input
            })
        }
        ActionKind::Verifier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "independent": logic.get("independent").and_then(Value::as_bool).unwrap_or(true),
                "verdict": logic.get("verdict").and_then(Value::as_str).unwrap_or("passed"),
                "input": input
            })
        }
        ActionKind::DriftDetector => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "signals": logic.get("signals").cloned().unwrap_or_else(|| json!([])),
                "driftDetected": logic.get("driftDetected").and_then(Value::as_bool).unwrap_or(false),
                "input": input
            })
        }
        ActionKind::QualityLedger => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "scorecard": logic.get("scorecard").cloned().unwrap_or_else(|| json!({})),
                "taskPassRate": logic.get("taskPassRate").and_then(Value::as_f64).unwrap_or(1.0),
                "input": input
            })
        }
        ActionKind::Handoff => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "objectivePreserved": true,
                "evidencePreserved": true,
                "nextAction": logic.get("nextAction").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::GuiHarnessValidation => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "markdownStatus": logic.get("markdownStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "mermaidStatus": logic.get("mermaidStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "sourceChipStatus": logic.get("sourceChipStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "input": input
            })
        }
        ActionKind::Output => workflow_output_bundle(&node_id, &node_name, &logic, input),
        ActionKind::TestAssertion => {
            let assertion = logic
                .get("assertion")
                .cloned()
                .and_then(|value| serde_json::from_value::<WorkflowTestAssertion>(value).ok())
                .unwrap_or_else(|| WorkflowTestAssertion {
                    kind: logic
                        .get("assertionKind")
                        .and_then(Value::as_str)
                        .unwrap_or("node_exists")
                        .to_string(),
                    expected: logic.get("expected").cloned(),
                    expression: logic
                        .get("expression")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            let (passed, message) = workflow_evaluate_value_assertion(&assertion, &input, None)?;
            if !passed {
                return Err(format!("Test assertion failed: {}", message));
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "assertionKind": assertion.kind,
                "passed": passed,
                "message": message,
                "input": input
            })
        }
        ActionKind::Proposal => {
            let proposal_action = logic.get("proposalAction").cloned().unwrap_or_else(|| {
                json!({
                    "actionKind": "create",
                    "boundedTargets": [],
                    "requiresApproval": true
                })
            });
            let bounded_count = proposal_action
                .get("boundedTargets")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if bounded_count == 0 {
                return Err("Proposal node requires bounded targets.".to_string());
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "proposal": proposal_action,
                "input": input
            })
        }
        ActionKind::Unknown => {
            return Err(format!("Unsupported workflow node type '{}'.", node_type))
        }
    };
    workflow_output_satisfies_schema(node, &output)?;
    Ok(output)
}

pub(crate) fn execute_workflow_harness_canary_node(
    node: &Value,
    input: Value,
    attempt: usize,
) -> Result<Value, String> {
    let canary_human_gate_outcome = (workflow_node_type(node) == "human_gate").then(|| {
        json!({
            "approved": true,
            "decision": "approved",
            "reason": "Synthetic approval outcome for non-mutating harness canary execution.",
            "authorityTransferred": false
        })
    });
    execute_workflow_node(
        Path::new(".agents/workflows/default-agent-harness.workflow.json"),
        None,
        node,
        input,
        attempt,
        canary_human_gate_outcome.as_ref(),
        &WorkflowSkillResolver::default(),
    )
}

pub(crate) fn execute_workflow_harness_live_default_node(
    node: &Value,
    input: Value,
    attempt: usize,
) -> Result<Value, String> {
    let default_human_gate_outcome = (workflow_node_type(node) == "human_gate").then(|| {
        json!({
            "approved": true,
            "decision": "approved",
            "reason": "Synthetic approval outcome for read-only blessed default harness dispatch.",
            "authorityTransferred": false
        })
    });
    execute_workflow_node(
        Path::new(".agents/workflows/default-agent-harness.workflow.json"),
        None,
        node,
        input,
        attempt,
        default_human_gate_outcome.as_ref(),
        &WorkflowSkillResolver::default(),
    )
}
