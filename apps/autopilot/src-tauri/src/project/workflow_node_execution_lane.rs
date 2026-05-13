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
use super::workflow_memory_lane::{workflow_memory_query_output, workflow_memory_send_options};
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

fn workflow_runtime_thread_fork_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let thread_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeThreadForkThreadIdField")
            .unwrap_or_else(|| "threadId".to_string());
    let reason_field = workflow_runtime_control_logic_string(logic, "runtimeThreadForkReasonField")
        .unwrap_or_else(|| "reason".to_string());
    let thread_id = workflow_runtime_control_logic_string(logic, "runtimeThreadForkThreadId")
        .or_else(|| workflow_runtime_control_input_string(input, &thread_id_field))
        .or_else(|| workflow_runtime_control_input_string(input, "thread_id"))
        .unwrap_or_else(|| "{{runtime.thread_id}}".to_string());
    let reason = workflow_runtime_control_input_string(input, &reason_field)
        .or_else(|| workflow_runtime_control_logic_string(logic, "runtimeThreadForkReason"))
        .unwrap_or_else(|| "Fork thread from React Flow workflow control.".to_string());
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty());
    let workflow_graph_id_value = workflow_graph_id.map(Value::String).unwrap_or(Value::Null);
    let workflow_node_id =
        workflow_runtime_control_logic_string(logic, "runtimeThreadForkWorkflowNodeId")
            .unwrap_or_else(|| "runtime.thread-fork".to_string());
    let actor = workflow_runtime_control_logic_string(logic, "runtimeThreadForkActor")
        .unwrap_or_else(|| "operator".to_string());
    let endpoint_template =
        workflow_runtime_control_logic_string(logic, "runtimeThreadForkEndpoint")
            .unwrap_or_else(|| "/v1/threads/{threadId}/fork".to_string());
    let endpoint = endpoint_template.replace("{threadId}", &thread_id);
    let request = json!({
        "reason": reason,
        "source": "react_flow",
        "actor": actor,
        "workflowGraphId": workflow_graph_id_value.clone(),
        "workflowNodeId": workflow_node_id.clone(),
        "eventKind": "OperatorControl.Fork",
        "componentKind": "thread_fork",
        "payloadSchemaVersion": "ioi.runtime.thread-fork.v1"
    });
    let runtime_thread_fork = json!({
        "schemaVersion": "ioi.workflow.runtime-thread-fork-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "thread_fork",
        "workflowGraphId": workflow_graph_id_value,
        "workflowNodeId": workflow_node_id,
        "threadId": thread_id,
        "endpoint": endpoint,
        "request": request,
        "mutationExecuted": false
    });
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": "ioi.workflow.runtime-thread-fork-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "thread_fork",
        "workflowGraphId": runtime_thread_fork.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": runtime_thread_fork.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_thread_fork.get("threadId").cloned().unwrap_or(Value::Null),
        "endpoint": runtime_thread_fork.get("endpoint").cloned().unwrap_or(Value::Null),
        "request": runtime_thread_fork.get("request").cloned().unwrap_or(Value::Null),
        "runtimeThreadFork": runtime_thread_fork,
        "mutationExecuted": false,
        "input": input
    })
}

fn workflow_runtime_operator_interrupt_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let thread_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptThreadIdField")
            .unwrap_or_else(|| "threadId".to_string());
    let turn_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptTurnIdField")
            .unwrap_or_else(|| "turnId".to_string());
    let reason_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptReasonField")
            .unwrap_or_else(|| "reason".to_string());
    let thread_id =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptThreadId")
            .or_else(|| workflow_runtime_control_input_string(input, &thread_id_field))
            .or_else(|| workflow_runtime_control_input_string(input, "thread_id"))
            .unwrap_or_else(|| "{{runtime.thread_id}}".to_string());
    let turn_id = workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptTurnId")
        .or_else(|| workflow_runtime_control_input_string(input, &turn_id_field))
        .or_else(|| workflow_runtime_control_input_string(input, "turn_id"))
        .unwrap_or_else(|| "{{runtime.turn_id}}".to_string());
    let reason = workflow_runtime_control_input_string(input, &reason_field)
        .or_else(|| workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptReason"))
        .unwrap_or_else(|| "Interrupt turn from React Flow workflow control.".to_string());
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty());
    let workflow_graph_id_value = workflow_graph_id.map(Value::String).unwrap_or(Value::Null);
    let workflow_node_id =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptWorkflowNodeId")
            .unwrap_or_else(|| "runtime.operator-interrupt".to_string());
    let actor = workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptActor")
        .unwrap_or_else(|| "operator".to_string());
    let endpoint_template =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorInterruptEndpoint")
            .unwrap_or_else(|| "/v1/threads/{threadId}/turns/{turnId}/interrupt".to_string());
    let endpoint = endpoint_template
        .replace("{threadId}", &thread_id)
        .replace("{turnId}", &turn_id);
    let request = json!({
        "reason": reason,
        "source": "react_flow",
        "actor": actor,
        "workflowGraphId": workflow_graph_id_value.clone(),
        "workflowNodeId": workflow_node_id.clone(),
        "eventKind": "OperatorControl.Interrupt",
        "componentKind": "operator_control",
        "payloadSchemaVersion": "ioi.runtime.operator-control.v1"
    });
    let runtime_operator_interrupt = json!({
        "schemaVersion": "ioi.workflow.runtime-operator-interrupt-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "operator_control",
        "workflowGraphId": workflow_graph_id_value,
        "workflowNodeId": workflow_node_id,
        "threadId": thread_id,
        "turnId": turn_id,
        "endpoint": endpoint,
        "request": request,
        "mutationExecuted": false
    });
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": "ioi.workflow.runtime-operator-interrupt-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "operator_control",
        "workflowGraphId": runtime_operator_interrupt.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": runtime_operator_interrupt.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_operator_interrupt.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_operator_interrupt.get("turnId").cloned().unwrap_or(Value::Null),
        "endpoint": runtime_operator_interrupt.get("endpoint").cloned().unwrap_or(Value::Null),
        "request": runtime_operator_interrupt.get("request").cloned().unwrap_or(Value::Null),
        "runtimeOperatorInterrupt": runtime_operator_interrupt,
        "mutationExecuted": false,
        "input": input
    })
}

fn workflow_runtime_operator_steer_output(
    workflow: Option<&WorkflowProject>,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let thread_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerThreadIdField")
            .unwrap_or_else(|| "threadId".to_string());
    let turn_id_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerTurnIdField")
            .unwrap_or_else(|| "turnId".to_string());
    let guidance_field =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerGuidanceField")
            .unwrap_or_else(|| "guidance".to_string());
    let thread_id = workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerThreadId")
        .or_else(|| workflow_runtime_control_input_string(input, &thread_id_field))
        .or_else(|| workflow_runtime_control_input_string(input, "thread_id"))
        .unwrap_or_else(|| "{{runtime.thread_id}}".to_string());
    let turn_id = workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerTurnId")
        .or_else(|| workflow_runtime_control_input_string(input, &turn_id_field))
        .or_else(|| workflow_runtime_control_input_string(input, "turn_id"))
        .unwrap_or_else(|| "{{runtime.turn_id}}".to_string());
    let guidance = workflow_runtime_control_input_string(input, &guidance_field)
        .or_else(|| workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerGuidance"))
        .unwrap_or_else(|| "Steer turn from React Flow workflow control.".to_string());
    let workflow_graph_id = workflow
        .map(|project| project.metadata.id.clone())
        .filter(|value| !value.trim().is_empty());
    let workflow_graph_id_value = workflow_graph_id.map(Value::String).unwrap_or(Value::Null);
    let workflow_node_id =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerWorkflowNodeId")
            .unwrap_or_else(|| "runtime.operator-steer".to_string());
    let actor = workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerActor")
        .unwrap_or_else(|| "operator".to_string());
    let endpoint_template =
        workflow_runtime_control_logic_string(logic, "runtimeOperatorSteerEndpoint")
            .unwrap_or_else(|| "/v1/threads/{threadId}/turns/{turnId}/steer".to_string());
    let endpoint = endpoint_template
        .replace("{threadId}", &thread_id)
        .replace("{turnId}", &turn_id);
    let request = json!({
        "guidance": guidance,
        "source": "react_flow",
        "actor": actor,
        "workflowGraphId": workflow_graph_id_value.clone(),
        "workflowNodeId": workflow_node_id.clone(),
        "eventKind": "OperatorControl.Steer",
        "componentKind": "operator_control",
        "payloadSchemaVersion": "ioi.runtime.operator-control.v1"
    });
    let runtime_operator_steer = json!({
        "schemaVersion": "ioi.workflow.runtime-operator-steer-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "operator_control",
        "workflowGraphId": workflow_graph_id_value,
        "workflowNodeId": workflow_node_id,
        "threadId": thread_id,
        "turnId": turn_id,
        "endpoint": endpoint,
        "request": request,
        "mutationExecuted": false
    });
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "schemaVersion": "ioi.workflow.runtime-operator-steer-control.v1",
        "status": "ready",
        "source": "react_flow",
        "componentKind": "operator_control",
        "workflowGraphId": runtime_operator_steer.get("workflowGraphId").cloned().unwrap_or(Value::Null),
        "workflowNodeId": runtime_operator_steer.get("workflowNodeId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_operator_steer.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_operator_steer.get("turnId").cloned().unwrap_or(Value::Null),
        "endpoint": runtime_operator_steer.get("endpoint").cloned().unwrap_or(Value::Null),
        "request": runtime_operator_steer.get("request").cloned().unwrap_or(Value::Null),
        "runtimeOperatorSteer": runtime_operator_steer,
        "mutationExecuted": false,
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
