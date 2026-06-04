use ioi_services::agentic::runtime::kernel::projection::RustProjectionCore;
use ioi_services::agentic::runtime::kernel::receipt_binder::ReceiptBinder;
use ioi_services::agentic::runtime::kernel::step_module::{
    StepModuleInvocation, StepModuleNext, StepModuleProjectionStatus, StepModuleResult,
    StepModuleStatus, StepModuleWorkflowProjection, STEP_MODULE_RESULT_SCHEMA_VERSION,
};
use ioi_services::agentic::runtime::kernel::step_router::StepModuleRouterCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const COMMAND_SCHEMA_VERSION: &str = "ioi.step_module.command_bridge.v1";
const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const DEFAULT_PREVIEW_BYTES: u64 = 16 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_DIFF_BYTES: u64 = 64 * 1024;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 500;

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
        "workspace.status" => Ok(workspace_status_shadow_response(request)),
        "git.diff" => git_diff_response(request),
        "file.inspect" => file_inspect_response(request),
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
            status: projection_status_for_backend(&request.backend),
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
        "shadow_observation": {
            "tool": "workspace.status",
            "input_hash": input_hash,
            "include_ignored": request.input.get("includeIgnored").and_then(Value::as_bool).unwrap_or(false),
            "authority_scopes": authority_scopes,
            "primitive_capabilities": primitive_capabilities,
        }
    })
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
    let candidate = if Path::new(selected_path).is_absolute() {
        PathBuf::from(selected_path)
    } else {
        root.join(selected_path)
    };
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
        ".".to_string()
    } else {
        relative
    })
}

fn workspace_target(root: &Path, selected_path: &str) -> Result<PathBuf, BridgeError> {
    let candidate = root.join(selected_path);
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
