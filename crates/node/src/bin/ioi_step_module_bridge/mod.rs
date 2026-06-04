use ioi_services::agentic::runtime::kernel::projection::RustProjectionCore;
use ioi_services::agentic::runtime::kernel::receipt_binder::ReceiptBinder;
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleInvocation, StepModuleNext, StepModuleProjectionStatus, StepModuleResult,
    StepModuleStatus, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_router::StepModuleRouterCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";
const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const DEFAULT_PREVIEW_BYTES: u64 = 16 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_DIFF_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_DEFAULT_TIMEOUT_MS: u64 = 30 * 1000;
const DIAGNOSTIC_MAX_TIMEOUT_MS: u64 = 2 * 60 * 1000;
const DIAGNOSTIC_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_DEFAULT_TIMEOUT_MS: u64 = 60 * 1000;
const TEST_MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const TEST_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 500;
const DIAGNOSTIC_COMMAND_IDS: [&str; 3] = ["auto", "node.check", "typescript.check"];
const TEST_COMMAND_IDS: [&str; 4] = ["node.test", "npm.test", "cargo.test", "cargo.check"];

#[derive(Debug, Deserialize)]
struct StepModuleBridgeRequest {
    #[serde(rename = "schema_version", alias = "schemaVersion")]
    schema_version: String,
    operation: String,
    backend: String,
    invocation: StepModuleInvocation,
    #[serde(default)]
    workspace_root: Option<String>,
    #[serde(default)]
    input: Value,
}

pub fn run_bridge_response_from_stdin() -> Value {
    match run_bridge() {
        Ok(response) => json!({ "ok": true, "result": response }),
        Err(error) => json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }),
    }
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
        "workspace.status" => workspace_status_response(request),
        "git.diff" => git_diff_response(request),
        "file.inspect" => file_inspect_response(request),
        "test.run" => test_run_response(request),
        "lsp.diagnostics" => lsp_diagnostics_response(request),
        other => Err(BridgeError::new(
            "tool_unsupported",
            format!("unsupported StepModule tool {}", other),
        )),
    }
}

fn workspace_status_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let status_result = inspect_workspace_status(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "workspace.status", "CodingToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "workspace.status",
            "result": status_result,
        }),
    ))
}

fn git_diff_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let diff_result = inspect_git_diff(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "git.diff", "GitToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "git.diff",
            "result": diff_result,
        }),
    ))
}

fn file_inspect_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let selected_path = request
        .input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::new(
                "file_inspect_path_required",
                "file.inspect requires path".to_string(),
            )
        })?;
    let inspected = inspect_workspace_path(&workspace_root, selected_path, &request.input)?;
    let result = successful_step_module_result(&request, "file.inspect", "FilesystemToolNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "file.inspect",
            "result": inspected,
        }),
    ))
}

fn test_run_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let test_result = inspect_test_run(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "test.run", "TestRunNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "test.run",
            "result": test_result,
        }),
    ))
}

fn lsp_diagnostics_response(request: StepModuleBridgeRequest) -> Result<Value, BridgeError> {
    let workspace_root = request.workspace_root.clone().ok_or_else(|| {
        BridgeError::new(
            "workspace_root_required",
            "workspace_root is required".to_string(),
        )
    })?;
    let diagnostics_result = inspect_lsp_diagnostics(&workspace_root, &request.input)?;
    let result = successful_step_module_result(&request, "lsp.diagnostics", "LspDiagnosticsNode");
    Ok(step_module_response(
        request,
        result,
        json!({
            "tool": "lsp.diagnostics",
            "result": diagnostics_result,
        }),
    ))
}

fn successful_step_module_result(
    request: &StepModuleBridgeRequest,
    tool_id: &str,
    component_kind: &str,
) -> StepModuleResult {
    let invocation_id = request.invocation.invocation_id.clone();
    let suffix = short_suffix(&invocation_id);
    let receipt_ref = format!("receipt://rust-workload/{tool_id}/{suffix}");
    StepModuleResult {
        schema_version: STEP_MODULE_RESULT_SCHEMA_VERSION.to_string(),
        invocation_id,
        status: StepModuleStatus::Success,
        execution_result_ref: format!("result://rust-workload/{tool_id}/{suffix}"),
        normalized_observation_ref: format!("observation://rust-workload/{tool_id}/{suffix}"),
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
                .unwrap_or_else(|| format!("node:coding-tool:{tool_id}")),
            component_kind: component_kind.to_string(),
            status: projection_status_for_backend(&request.backend),
            attempt_id: format!("attempt://rust-workload/{tool_id}/{suffix}"),
            evidence_refs: vec![format!("evidence://rust-workload/{tool_id}")],
            receipt_refs: vec![receipt_ref],
        },
        next: StepModuleNext {
            model_reentry_required: false,
            verifier_required: false,
        },
    }
}

fn step_module_response(
    request: StepModuleBridgeRequest,
    result: StepModuleResult,
    shadow_observation: Value,
) -> Value {
    if let Err(errors) = result.validate() {
        return json!({
            "source": "rust_workload_command",
            "error": {
                "code": "result_invalid",
                "message": format!("{errors:?}"),
            }
        });
    }
    let router_admission = match StepModuleRouterCore.admit_execution(&request.invocation, &result)
    {
        Ok(record) => record,
        Err(error) => {
            return json!({
                "source": "rust_workload_command",
                "error": {
                    "code": "router_admission_invalid",
                    "message": format!("{error:?}"),
                }
            });
        }
    };
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
    let projection_record = match RustProjectionCore.project_step_module_result(
        &request.invocation,
        &result,
        &receipt_binding,
    ) {
        Ok(record) => record,
        Err(error) => {
            return json!({
                "source": "rust_workload_command",
                "error": {
                    "code": "projection_record_invalid",
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
        "router_admission": router_admission,
        "receipt_binding": receipt_binding,
        "projection_record": projection_record,
        "shadow_observation": shadow_observation,
    })
}

fn inspect_test_run(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("node.test");
    if !TEST_COMMAND_IDS.contains(&command_id) {
        return Err(BridgeError::new(
            "test_run_command_not_allowed",
            format!("test.run commandId is not allowlisted: {command_id}"),
        ));
    }
    if command_id != "node.test" {
        return Err(BridgeError::new(
            "test_run_backend_unsupported",
            format!("{command_id} is not live in the Rust bridge yet"),
        ));
    }
    let cwd = input
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(".");
    let run_cwd = workspace_directory(&root, cwd, "test_run_cwd_missing")?;
    let paths = workspace_tool_paths(&root, input)?;
    let timeout_ms = bounded_u64(
        input
            .get("timeoutMs")
            .or_else(|| input.get("timeout_ms"))
            .and_then(Value::as_u64),
        TEST_DEFAULT_TIMEOUT_MS,
        1,
        TEST_MAX_TIMEOUT_MS,
    );
    let max_output_bytes = bounded_u64(
        input
            .get("maxOutputBytes")
            .or_else(|| input.get("max_output_bytes"))
            .and_then(Value::as_u64),
        TEST_DEFAULT_OUTPUT_BYTES,
        1,
        TEST_MAX_OUTPUT_BYTES,
    ) as usize;
    let mut args = vec!["--test".to_string()];
    args.extend(
        paths
            .iter()
            .map(|path| relative_path_between(&run_cwd.absolute_path, &path.absolute_path)),
    );
    args.extend(sanitize_string_array(input.get("args")));
    let env_overrides = sanitize_test_env(input.get("env"));
    let started = Instant::now();
    let run = run_command_with_timeout(
        "node",
        &args,
        &run_cwd.absolute_path,
        timeout_ms,
        &env_overrides,
    )?;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = ioi_crypto::algorithms::hash::sha256(output_text.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("test_run_hash_failed", error.to_string()))?;
    let truncated = stdout_truncated || stderr_truncated;
    let test_status = if run.timed_out {
        "timed_out"
    } else if run.exit_code == 0 {
        "passed"
    } else {
        "failed"
    };
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "commandId": command_id,
        "command": "node --test",
        "executable": "node",
        "args": args,
        "cwd": run_cwd.relative_path,
        "exitCode": run.exit_code,
        "signal": null,
        "testStatus": test_status,
        "timedOut": run.timed_out,
        "durationMs": duration_ms,
        "timeoutMs": timeout_ms,
        "stdout": stdout,
        "stderr": stderr,
        "stdoutBytes": run.stdout.len(),
        "stderrBytes": run.stderr.len(),
        "outputBytes": run.stdout.len() + run.stderr.len(),
        "outputHash": output_hash,
        "truncated": truncated,
        "spilloverRecommended": truncated,
        "artifactDrafts": [],
        "allowedCommandIds": TEST_COMMAND_IDS,
        "shellFallbackUsed": false,
    }))
}

fn inspect_lsp_diagnostics(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto");
    if !DIAGNOSTIC_COMMAND_IDS.contains(&command_id) {
        return Err(BridgeError::new(
            "lsp_diagnostics_command_not_allowed",
            format!("lsp.diagnostics commandId is not allowlisted: {command_id}"),
        ));
    }
    if command_id != "node.check" {
        return Err(BridgeError::new(
            "lsp_diagnostics_backend_unsupported",
            format!("{command_id} is not live in the Rust bridge yet"),
        ));
    }
    let cwd = input
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(".");
    let run_cwd = workspace_directory(&root, cwd, "lsp_diagnostics_cwd_missing")?;
    let paths = workspace_tool_paths(&root, input)?;
    if paths.is_empty() {
        return Err(BridgeError::new(
            "lsp_diagnostics_path_required",
            "lsp.diagnostics requires path or paths".to_string(),
        ));
    }
    let timeout_ms = bounded_u64(
        input
            .get("timeoutMs")
            .or_else(|| input.get("timeout_ms"))
            .and_then(Value::as_u64),
        DIAGNOSTIC_DEFAULT_TIMEOUT_MS,
        1,
        DIAGNOSTIC_MAX_TIMEOUT_MS,
    );
    let max_output_bytes = bounded_u64(
        input
            .get("maxOutputBytes")
            .or_else(|| input.get("max_output_bytes"))
            .and_then(Value::as_u64),
        DIAGNOSTIC_DEFAULT_OUTPUT_BYTES,
        1,
        DIAGNOSTIC_MAX_OUTPUT_BYTES,
    ) as usize;
    let started = Instant::now();
    let run = run_node_check(&run_cwd.absolute_path, &paths, timeout_ms)?;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = ioi_crypto::algorithms::hash::sha256(output_text.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("lsp_diagnostics_hash_failed", error.to_string()))?;
    let truncated = stdout_truncated || stderr_truncated;
    let diagnostics = run.diagnostics;
    let diagnostic_status = if run.backend_status == "degraded" {
        "degraded"
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.get("severity").and_then(Value::as_str) == Some("error"))
    {
        "findings"
    } else {
        "clean"
    };
    let diagnostic_count = diagnostics.len();
    let path_refs = paths
        .iter()
        .map(|path| path.relative_path.clone())
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "commandId": command_id,
        "requestedCommandId": command_id,
        "resolvedCommandId": "node.check",
        "command": "node --check",
        "cwd": run_cwd.relative_path.clone(),
        "backend": "node.check",
        "backendStatus": run.backend_status,
        "backendReason": run.backend_reason,
        "fallbackUsed": false,
        "fallbackFrom": null,
        "projectContext": {
            "schemaVersion": "ioi.runtime.diagnostics-project-context.v1",
            "workspaceRoot": workspace_root,
            "cwd": run_cwd.relative_path,
            "paths": path_refs.clone(),
        },
        "diagnosticStatus": diagnostic_status,
        "diagnostics": diagnostics,
        "diagnosticCount": diagnostic_count,
        "paths": path_refs,
        "exitCode": run.exit_code,
        "timedOut": run.timed_out,
        "durationMs": duration_ms,
        "timeoutMs": timeout_ms,
        "stdout": stdout,
        "stderr": stderr,
        "outputBytes": run.stdout.len() + run.stderr.len(),
        "outputHash": output_hash,
        "truncated": truncated,
        "spilloverRecommended": truncated,
        "artifactDrafts": [],
        "allowedCommandIds": DIAGNOSTIC_COMMAND_IDS,
        "shellFallbackUsed": false,
    }))
}

fn inspect_workspace_status(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let include_ignored = input
        .get("includeIgnored")
        .or_else(|| input.get("include_ignored"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut args = vec![
        "status".to_string(),
        "--short".to_string(),
        "--branch".to_string(),
        "--untracked-files=all".to_string(),
    ];
    if include_ignored {
        args.push("--ignored".to_string());
    }
    let status = run_git_read_only(&root, &args)?;
    if !status.ok {
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "git": {
                "available": false,
                "status": "not_git_repository",
                "error": nonempty_command_error(&status, "git status failed"),
            },
            "changedFiles": [],
            "counts": {
                "changed": 0,
                "untracked": 0,
                "ignored": 0,
            },
            "shellFallbackUsed": false,
        }));
    }

    let lines = status
        .stdout
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let branch = lines
        .iter()
        .find_map(|line| line.strip_prefix("##").map(str::trim))
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned);
    let mut changed_files = Vec::new();
    let mut changed = 0u64;
    let mut untracked = 0u64;
    let mut ignored = 0u64;
    for line in lines.iter().filter(|line| !line.starts_with("##")) {
        let path = line.get(3..).unwrap_or("").trim();
        if path.is_empty() {
            continue;
        }
        let status_code = line.get(0..2).unwrap_or("").trim();
        let status_code = if status_code.is_empty() {
            "modified"
        } else {
            status_code
        };
        changed += 1;
        if status_code.contains('?') {
            untracked += 1;
        }
        if status_code.contains('!') {
            ignored += 1;
        }
        changed_files.push(json!({
            "status": status_code,
            "path": path,
        }));
    }
    let porcelain_hash = ioi_crypto::algorithms::hash::sha256(status.stdout.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("workspace_status_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "git": {
            "available": true,
            "branch": branch,
            "porcelainHash": porcelain_hash,
        },
        "changedFiles": changed_files,
        "counts": {
            "changed": changed,
            "untracked": untracked,
            "ignored": ignored,
        },
        "shellFallbackUsed": false,
    }))
}

fn inspect_git_diff(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let paths = workspace_diff_paths(&root, input)?;
    let max_bytes = bounded_u64(
        input
            .get("maxBytes")
            .or_else(|| input.get("max_bytes"))
            .and_then(Value::as_u64),
        MAX_DIFF_BYTES,
        1,
        MAX_DIFF_BYTES,
    ) as usize;
    let mut diff_args = vec!["diff".to_string(), "--".to_string()];
    diff_args.extend(paths.iter().cloned());
    let diff_output = run_git_read_only(&root, &diff_args)?;
    if !diff_output.ok {
        return Err(BridgeError::new(
            "git_diff_failed",
            nonempty_command_error(&diff_output, "git diff failed"),
        ));
    }
    let mut stat_args = vec!["diff".to_string(), "--stat".to_string(), "--".to_string()];
    stat_args.extend(paths.iter().cloned());
    let stat_output = run_git_read_only(&root, &stat_args)?;
    let (diff_preview, truncated) = utf8_preview(&diff_output.stdout, max_bytes);
    let diff_hash = ioi_crypto::algorithms::hash::sha256(diff_output.stdout.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("git_diff_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "paths": paths,
        "git": { "available": true },
        "diff": diff_preview,
        "diffBytes": diff_output.stdout.len(),
        "diffHash": diff_hash,
        "truncated": truncated,
        "stat": if stat_output.ok { stat_output.stdout } else { String::new() },
        "shellFallbackUsed": false,
    }))
}

fn inspect_workspace_path(
    workspace_root: &str,
    selected_path: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    let root = fs::canonicalize(workspace_root)
        .map_err(|error| BridgeError::new("workspace_root_invalid", error.to_string()))?;
    let target = workspace_target(&root, selected_path)?;
    let metadata =
        fs::metadata(&target).map_err(|error| BridgeError::new("not_found", error.to_string()))?;
    let relative_path = target
        .strip_prefix(&root)
        .unwrap_or(target.as_path())
        .to_string_lossy()
        .replace('\\', "/");
    if metadata.is_dir() {
        let mut entries = fs::read_dir(&target)
            .map_err(|error| BridgeError::new("file_inspect_read_dir_failed", error.to_string()))?
            .take(100)
            .map(|entry| {
                entry
                    .map_err(|error| BridgeError::new("file_inspect_read_dir_failed", error.to_string()))
                    .and_then(|entry| {
                        let kind = entry
                            .file_type()
                            .map_err(|error| BridgeError::new("file_inspect_file_type_failed", error.to_string()))?;
                        Ok(json!({
                            "name": entry.file_name().to_string_lossy(),
                            "kind": if kind.is_dir() { "directory" } else if kind.is_file() { "file" } else { "other" },
                        }))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "path": relative_path,
            "kind": "directory",
            "exists": true,
            "sizeBytes": metadata.len(),
            "entries": entries,
            "entryCount": entries.len(),
            "shellFallbackUsed": false,
        }));
    }
    if !metadata.is_file() {
        return Ok(json!({
            "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "workspaceRoot": workspace_root,
            "path": relative_path,
            "kind": "other",
            "exists": true,
            "sizeBytes": metadata.len(),
            "shellFallbackUsed": false,
        }));
    }
    let max_bytes = bounded_u64(
        input
            .get("maxBytes")
            .or_else(|| input.get("max_bytes"))
            .and_then(Value::as_u64),
        DEFAULT_PREVIEW_BYTES,
        1,
        MAX_PREVIEW_BYTES,
    );
    let preview_lines = bounded_usize(
        input
            .get("previewLines")
            .or_else(|| input.get("preview_lines"))
            .and_then(Value::as_u64),
        DEFAULT_PREVIEW_LINES,
        1,
        MAX_PREVIEW_LINES,
    );
    let bytes_to_read = metadata.len().min(max_bytes) as usize;
    let mut file = fs::File::open(&target)
        .map_err(|error| BridgeError::new("file_inspect_open_failed", error.to_string()))?;
    let mut buffer = vec![0u8; bytes_to_read];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|error| BridgeError::new("file_inspect_read_failed", error.to_string()))?;
    buffer.truncate(bytes_read);
    let preview = String::from_utf8_lossy(&buffer);
    let lines = preview.split('\n').collect::<Vec<_>>();
    let line_preview = lines
        .iter()
        .take(preview_lines)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let preview_hash = ioi_crypto::algorithms::hash::sha256(line_preview.as_bytes())
        .map(|hash| format!("sha256:{}", hex::encode(hash)))
        .map_err(|error| BridgeError::new("file_inspect_hash_failed", error.to_string()))?;
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "path": relative_path,
        "kind": "file",
        "exists": true,
        "sizeBytes": metadata.len(),
        "preview": line_preview,
        "previewBytes": line_preview.len(),
        "previewHash": preview_hash,
        "truncated": bytes_read < metadata.len() as usize || lines.len() > preview_lines,
        "previewLineCount": lines.len().min(preview_lines),
        "shellFallbackUsed": false,
    }))
}

fn workspace_diff_paths(root: &Path, input: &Value) -> Result<Vec<String>, BridgeError> {
    let selected_paths = selected_workspace_paths(input);
    selected_paths
        .iter()
        .map(|selected_path| workspace_relative_path_allow_missing(root, selected_path))
        .collect()
}

fn workspace_tool_paths(root: &Path, input: &Value) -> Result<Vec<WorkspacePath>, BridgeError> {
    selected_workspace_paths(input)
        .iter()
        .map(|selected_path| workspace_path_allow_missing(root, selected_path))
        .collect()
}

fn selected_workspace_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(values) = input.get("paths").and_then(Value::as_array) {
        paths.extend(
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    if let Some(path) = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        paths.push(path.to_string());
    }
    paths
}

fn workspace_relative_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<String, BridgeError> {
    Ok(workspace_path_allow_missing(root, selected_path)?.relative_path)
}

fn workspace_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<WorkspacePath, BridgeError> {
    let candidate = path_candidate(root, selected_path);
    let normalized_root = normalize_path_lexically(root);
    let normalized_candidate = normalize_path_lexically(&candidate);
    if !normalized_candidate.starts_with(&normalized_root) {
        return Err(BridgeError::new(
            "path_outside_workspace",
            "git.diff path must stay inside workspace".to_string(),
        ));
    }
    if let Some(boundary) = nearest_existing_path(&normalized_candidate) {
        let real_boundary = fs::canonicalize(&boundary)
            .map_err(|error| BridgeError::new("path_boundary_invalid", error.to_string()))?;
        if !real_boundary.starts_with(root) {
            return Err(BridgeError::new(
                "path_outside_workspace",
                "git.diff path must stay inside workspace".to_string(),
            ));
        }
    }
    let relative = normalized_candidate
        .strip_prefix(&normalized_root)
        .map_err(|_| {
            BridgeError::new(
                "path_outside_workspace",
                "git.diff path must stay inside workspace".to_string(),
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(if relative.is_empty() {
        WorkspacePath {
            absolute_path: normalized_candidate,
            relative_path: ".".to_string(),
        }
    } else {
        WorkspacePath {
            absolute_path: normalized_candidate,
            relative_path: relative,
        }
    })
}

fn workspace_directory(
    root: &Path,
    selected_path: &str,
    error_code: &'static str,
) -> Result<WorkspacePath, BridgeError> {
    let path = workspace_path_allow_missing(root, selected_path)?;
    if !path.absolute_path.is_dir() {
        return Err(BridgeError::new(
            error_code,
            "workspace directory must exist".to_string(),
        ));
    }
    Ok(path)
}

fn workspace_target(root: &Path, selected_path: &str) -> Result<PathBuf, BridgeError> {
    let candidate = path_candidate(root, selected_path);
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| BridgeError::new("not_found", error.to_string()))?;
    if !canonical.starts_with(root) {
        return Err(BridgeError::new(
            "path_outside_workspace",
            "file.inspect path must stay inside workspace".to_string(),
        ));
    }
    Ok(canonical)
}

fn path_candidate(root: &Path, selected_path: &str) -> PathBuf {
    if Path::new(selected_path).is_absolute() {
        PathBuf::from(selected_path)
    } else {
        root.join(selected_path)
    }
}

fn relative_path_between(base: &Path, target: &Path) -> String {
    let normalized_base = normalize_path_lexically(base);
    let normalized_target = normalize_path_lexically(target);
    let base_parts = normal_path_parts(&normalized_base);
    let target_parts = normal_path_parts(&normalized_target);
    let common_len = base_parts
        .iter()
        .zip(target_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts = Vec::new();
    parts.extend(std::iter::repeat("..".to_string()).take(base_parts.len() - common_len));
    parts.extend(target_parts[common_len..].iter().cloned());
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn normal_path_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    while !current.exists() {
        if !current.pop() {
            return None;
        }
    }
    Some(current)
}

fn normalize_path_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

struct CommandOutput {
    ok: bool,
    stdout: String,
    stderr: String,
}

struct WorkspacePath {
    absolute_path: PathBuf,
    relative_path: String,
}

struct DiagnosticRun {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
    backend_status: &'static str,
    backend_reason: Option<&'static str>,
    diagnostics: Vec<Value>,
}

struct CapturedCommand {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
}

fn run_node_check(
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
) -> Result<DiagnosticRun, BridgeError> {
    let mut stdout_parts = Vec::new();
    let mut stderr_parts = Vec::new();
    let mut diagnostics = Vec::new();
    let mut exit_code = 0;
    let mut timed_out = false;
    let mut unsupported_count = 0usize;
    for target in paths {
        if !node_check_path_supported(&target.relative_path) {
            unsupported_count += 1;
            diagnostics.push(json!({
                "path": target.relative_path,
                "severity": "warning",
                "source": "node.check",
                "code": "unsupported_path",
                "message": "node.check only supports .js, .mjs, and .cjs files.",
                "line": null,
                "column": null,
            }));
            continue;
        }
        let run = run_command_with_timeout(
            "node",
            &[
                "--check".to_string(),
                target.absolute_path.to_string_lossy().to_string(),
            ],
            cwd,
            timeout_ms,
            &[],
        )?;
        if !run.stdout.is_empty() {
            stdout_parts.push(run.stdout.clone());
        }
        let stderr_entry = ["# ".to_string() + &target.relative_path, run.stderr.clone()]
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if !stderr_entry.is_empty() {
            stderr_parts.push(stderr_entry);
        }
        exit_code = exit_code.max(run.exit_code);
        timed_out = timed_out || run.timed_out;
        if run.exit_code != 0 || run.timed_out {
            diagnostics.extend(node_check_output_diagnostics(target, &run));
        }
    }
    let backend_status = if unsupported_count == paths.len() {
        "degraded"
    } else if timed_out {
        "timed_out"
    } else {
        "available"
    };
    Ok(DiagnosticRun {
        stdout: stdout_parts.join("\n"),
        stderr: stderr_parts.join("\n"),
        exit_code: if timed_out { 124 } else { exit_code },
        timed_out,
        backend_status,
        backend_reason: if backend_status == "degraded" {
            Some("unsupported_path")
        } else {
            None
        },
        diagnostics,
    })
}

fn node_check_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")
}

fn run_command_with_timeout(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    env_overrides: &[(String, String)],
) -> Result<CapturedCommand, BridgeError> {
    let command_env = safe_subprocess_env(env_overrides);
    let mut child = Command::new(command)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(command_env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| BridgeError::new("diagnostic_command_spawn_failed", error.to_string()))?;
    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    loop {
        match child.try_wait().map_err(|error| {
            BridgeError::new("diagnostic_command_wait_failed", error.to_string())
        })? {
            Some(_) => break,
            None if started.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| BridgeError::new("diagnostic_command_output_failed", error.to_string()))?;
    Ok(CapturedCommand {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: if timed_out {
            124
        } else {
            output.status.code().unwrap_or(1)
        },
        timed_out,
    })
}

fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .take(100)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn sanitize_test_env(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .filter_map(|(key, value)| {
                    let value = value.as_str()?;
                    if env_key_allowed(key) {
                        Some((key.clone(), value.to_string()))
                    } else {
                        None
                    }
                })
                .take(40)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn safe_subprocess_env(overrides: &[(String, String)]) -> Vec<(String, String)> {
    let mut env_values = env::vars()
        .filter(|(key, _)| env_key_allowed(key) && !key.starts_with("NODE_TEST"))
        .collect::<Vec<_>>();
    for (key, value) in overrides {
        if env_key_allowed(key) && !key.starts_with("NODE_TEST") {
            env_values.retain(|(existing_key, _)| existing_key != key);
            env_values.push((key.clone(), value.clone()));
        }
    }
    env_values
}

fn env_key_allowed(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    if !chars.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        return false;
    }
    !is_sensitive_env_key(key)
}

fn is_sensitive_env_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
        "cookie",
        "session",
        "vault",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("privatekey")
        || lower.contains("private_key")
        || lower.contains("private-key")
}

fn node_check_output_diagnostics(target: &WorkspacePath, run: &CapturedCommand) -> Vec<Value> {
    if run.timed_out {
        return vec![json!({
            "path": target.relative_path,
            "severity": "error",
            "source": "node.check",
            "code": "timeout",
            "message": "node.check timed out.",
            "line": null,
            "column": null,
        })];
    }
    let message = run
        .stderr
        .lines()
        .find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("SyntaxError")
                || trimmed.starts_with("TypeError")
                || trimmed.starts_with("ReferenceError")
                || trimmed.starts_with("Error:")
        })
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            run.stderr
                .lines()
                .rev()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "node.check reported a diagnostic.".to_string());
    vec![json!({
        "path": target.relative_path,
        "severity": "error",
        "source": "node.check",
        "code": diagnostic_code(&message),
        "message": message,
        "line": null,
        "column": null,
    })]
}

fn diagnostic_code(message: &str) -> String {
    let head = message.split(':').next().unwrap_or("diagnostic");
    let code = head
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if code.is_empty() {
        "diagnostic".to_string()
    } else {
        code
    }
}

fn run_git_read_only(root: &Path, args: &[String]) -> Result<CommandOutput, BridgeError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| BridgeError::new("git_spawn_failed", error.to_string()))?;
    Ok(CommandOutput {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn nonempty_command_error(output: &CommandOutput, fallback: &str) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    fallback.to_string()
}

fn utf8_preview(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

fn bounded_u64(value: Option<u64>, default: u64, min: u64, max: u64) -> u64 {
    value.unwrap_or(default).clamp(min, max)
}

fn bounded_usize(value: Option<u64>, default: usize, min: usize, max: usize) -> usize {
    value
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn projection_status_for_backend(backend: &str) -> StepModuleProjectionStatus {
    match backend {
        "rust_workload_live" => StepModuleProjectionStatus::Live,
        "rust_workload_gated" => StepModuleProjectionStatus::Gated,
        _ => StepModuleProjectionStatus::Shadow,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workspace_status_reads_git_porcelain_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "after\n").expect("updated file");
        fs::write(workspace.join("new.txt"), "new\n").expect("new file");

        let result = inspect_workspace_status(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "includeIgnored": true
            }),
        )
        .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], true);
        assert!(
            result["git"]["branch"]
                .as_str()
                .expect("branch")
                .contains("main")
                || result["git"]["branch"]
                    .as_str()
                    .expect("branch")
                    .contains("master")
        );
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "README.md"));
        assert!(result["changedFiles"]
            .as_array()
            .expect("changed files")
            .iter()
            .any(|entry| entry["path"] == "new.txt" && entry["status"] == "??"));
        assert_eq!(result["counts"]["changed"], 2);
        assert_eq!(result["counts"]["untracked"], 1);
        assert_eq!(
            result["git"]["porcelainHash"].as_str().expect("hash").len(),
            64
        );
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn workspace_status_reports_not_git_repository_without_failing_step() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let result = inspect_workspace_status(workspace.to_str().expect("utf8 path"), &json!({}))
            .expect("status result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["git"]["available"], false);
        assert_eq!(result["git"]["status"], "not_git_repository");
        assert_eq!(result["changedFiles"], json!([]));
        assert_eq!(result["counts"]["changed"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn test_run_node_test_reports_passed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("passing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('passes', () => assert.equal(1, 1));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "passing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["command"], "node --test");
        assert_eq!(result["args"], json!(["--test", "passing.test.mjs"]));
        assert_eq!(result["testStatus"], "passed");
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
        assert_eq!(result["shellFallbackUsed"], false);
        assert_eq!(result["outputHash"].as_str().expect("hash").len(), 64);
    }

    #[test]
    fn test_run_node_test_reports_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(
            workspace.join("failing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('fails', () => assert.equal(1, 2));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.test",
                "path": "failing.test.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("test result");

        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["testStatus"], "failed");
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["timedOut"], false);
    }

    #[test]
    fn test_run_non_node_backend_fails_closed_until_live() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_test_run(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "cargo.check"
            }),
        )
        .expect_err("cargo.check should fail closed until migrated");

        assert_eq!(error.code, "test_run_backend_unsupported");
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_clean_javascript() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["diagnosticCount"], 0);
        assert_eq!(result["paths"], json!(["ok.mjs"]));
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn lsp_diagnostics_node_check_reports_syntax_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("broken.mjs"), "const = ;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "node.check",
                "path": "broken.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics result");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["diagnostics"][0]["path"], "broken.mjs");
        assert_eq!(result["diagnostics"][0]["severity"], "error");
    }

    #[test]
    fn lsp_diagnostics_auto_fails_closed_until_backend_is_live() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let error = inspect_lsp_diagnostics(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "commandId": "auto",
                "path": "ok.mjs"
            }),
        )
        .expect_err("auto should fail closed until migrated");

        assert_eq!(error.code, "lsp_diagnostics_backend_unsupported");
    }

    #[test]
    fn git_diff_reads_bounded_workspace_diff() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        run_test_git(&workspace, &["init"]);
        run_test_git(&workspace, &["config", "user.email", "test@example.com"]);
        run_test_git(&workspace, &["config", "user.name", "IOI Test"]);
        fs::write(workspace.join("README.md"), "before\n").expect("fixture file");
        run_test_git(&workspace, &["add", "README.md"]);
        run_test_git(&workspace, &["commit", "-m", "initial"]);
        fs::write(workspace.join("README.md"), "before\nafter\n").expect("updated file");

        let result = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "README.md",
                "maxBytes": 4096
            }),
        )
        .expect("diff result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["paths"], json!(["README.md"]));
        assert_eq!(result["git"]["available"], true);
        assert!(result["diff"].as_str().expect("diff").contains("+after"));
        assert!(result["stat"].as_str().expect("stat").contains("README.md"));
        assert_eq!(result["diffHash"].as_str().expect("hash").len(), 64);
        assert_eq!(result["truncated"], false);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn git_diff_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");

        let error = inspect_git_diff(
            workspace.to_str().expect("utf8 path"),
            &json!({
                "path": "../outside.txt"
            }),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    #[test]
    fn file_inspect_reads_workspace_file_preview() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(workspace.join("README.md"), "# IOI\nsecond line\n").expect("fixture file");

        let result = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "README.md",
            &json!({
                "maxBytes": 128,
                "previewLines": 1
            }),
        )
        .expect("inspect result");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["path"], "README.md");
        assert_eq!(result["kind"], "file");
        assert_eq!(result["preview"], "# IOI");
        assert_eq!(result["previewLineCount"], 1);
        assert_eq!(result["shellFallbackUsed"], false);
    }

    #[test]
    fn file_inspect_rejects_paths_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace dir");
        fs::write(temp.path().join("outside.txt"), "outside").expect("outside fixture");

        let error = inspect_workspace_path(
            workspace.to_str().expect("utf8 path"),
            "../outside.txt",
            &json!({}),
        )
        .expect_err("outside path should fail");

        assert_eq!(error.code, "path_outside_workspace");
    }

    fn run_test_git(workspace: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
