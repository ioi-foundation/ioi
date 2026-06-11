use ioi_services::agentic::runtime::kernel::coding_tool_execution::{
    env_key_allowed, run_command_with_timeout as run_core_command_with_timeout,
    run_git_read_only as run_core_git_read_only, CapturedCommand, CommandOutput,
};
use ioi_services::agentic::runtime::kernel::coding_tool_workspace::{
    apply_workspace_patch as apply_core_workspace_patch,
    inspect_workspace_path as inspect_core_workspace_path, WorkspacePatchOutcome,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use super::{
    BridgeError, CODING_TOOL_RESULT_SCHEMA_VERSION, DIAGNOSTIC_COMMAND_IDS,
    DIAGNOSTIC_DEFAULT_OUTPUT_BYTES, DIAGNOSTIC_DEFAULT_TIMEOUT_MS, DIAGNOSTIC_MAX_OUTPUT_BYTES,
    DIAGNOSTIC_MAX_TIMEOUT_MS, MAX_DIFF_BYTES, TEST_COMMAND_IDS, TEST_DEFAULT_OUTPUT_BYTES,
    TEST_DEFAULT_TIMEOUT_MS, TEST_MAX_OUTPUT_BYTES, TEST_MAX_TIMEOUT_MS,
};

pub(super) fn inspect_test_run(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
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
    let command = test_command_for_input(command_id, &run_cwd.absolute_path, &paths);
    let mut args = command.args;
    args.extend(sanitize_string_array(input.get("args")));
    let env_overrides = sanitize_test_env(input.get("env"));
    let started = Instant::now();
    let run = run_command_with_timeout(
        command.executable,
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
        "command": command.display_command,
        "executable": command.executable,
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

pub(super) fn inspect_lsp_diagnostics(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
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
    let project_context = diagnostics_project_context(&root, &run_cwd.absolute_path, &paths);
    let has_typescript_path = paths
        .iter()
        .any(|path| typescript_path_supported(&path.relative_path));
    let run_typescript =
        command_id == "typescript.check" || (command_id == "auto" && has_typescript_path);
    let started = Instant::now();
    let run = if run_typescript {
        run_typescript_check(
            &root,
            &run_cwd.absolute_path,
            &paths,
            timeout_ms,
            input,
            project_context,
        )?
    } else {
        run_node_check(&run_cwd.absolute_path, &paths, timeout_ms, project_context)?
    };
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = ioi_crypto::algorithms::hash::sha256(output_text.as_bytes())
        .map(|hash| hex::encode(hash))
        .map_err(|error| BridgeError::new("lsp_diagnostics_hash_failed", error.to_string()))?;
    let truncated = stdout_truncated || stderr_truncated;
    let diagnostics = run.diagnostics;
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
        "resolvedCommandId": run.resolved_command_id,
        "command": run.display_command,
        "cwd": run_cwd.relative_path.clone(),
        "backend": run.backend,
        "backendStatus": run.backend_status,
        "backendReason": run.backend_reason,
        "fallbackUsed": run.fallback_used,
        "fallbackFrom": run.fallback_from,
        "projectContext": run.project_context,
        "diagnosticStatus": run.diagnostic_status,
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

pub(super) fn inspect_workspace_status(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
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

pub(super) fn inspect_git_diff(workspace_root: &str, input: &Value) -> Result<Value, BridgeError> {
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

pub(super) fn inspect_workspace_path(
    workspace_root: &str,
    selected_path: &str,
    input: &Value,
) -> Result<Value, BridgeError> {
    inspect_core_workspace_path(workspace_root, selected_path, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn apply_workspace_patch(
    workspace_root: &str,
    input: &Value,
) -> Result<WorkspacePatchOutcome, BridgeError> {
    apply_core_workspace_patch(workspace_root, input)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn workspace_diff_paths(root: &Path, input: &Value) -> Result<Vec<String>, BridgeError> {
    let selected_paths = selected_workspace_paths(input);
    selected_paths
        .iter()
        .map(|selected_path| workspace_relative_path_allow_missing(root, selected_path))
        .collect()
}

pub(super) fn workspace_tool_paths(
    root: &Path,
    input: &Value,
) -> Result<Vec<WorkspacePath>, BridgeError> {
    selected_workspace_paths(input)
        .iter()
        .map(|selected_path| workspace_path_allow_missing(root, selected_path))
        .collect()
}

pub(super) fn selected_workspace_paths(input: &Value) -> Vec<String> {
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

pub(super) fn workspace_relative_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<String, BridgeError> {
    Ok(workspace_path_allow_missing(root, selected_path)?.relative_path)
}

pub(super) fn workspace_path_allow_missing(
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

pub(super) fn workspace_directory(
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

pub(super) fn path_candidate(root: &Path, selected_path: &str) -> PathBuf {
    if Path::new(selected_path).is_absolute() {
        PathBuf::from(selected_path)
    } else {
        root.join(selected_path)
    }
}

pub(super) fn relative_path_between(base: &Path, target: &Path) -> String {
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

pub(super) fn normal_path_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

pub(super) fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    while !current.exists() {
        if !current.pop() {
            return None;
        }
    }
    Some(current)
}

pub(super) fn normalize_path_lexically(path: &Path) -> PathBuf {
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

pub(super) struct WorkspacePath {
    pub(super) absolute_path: PathBuf,
    pub(super) relative_path: String,
}

pub(super) struct DiagnosticRun {
    backend: &'static str,
    resolved_command_id: &'static str,
    display_command: &'static str,
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
    backend_status: &'static str,
    backend_reason: Option<&'static str>,
    fallback_used: bool,
    fallback_from: Option<&'static str>,
    project_context: Value,
    diagnostic_status: &'static str,
    diagnostics: Vec<Value>,
}

pub(super) struct DiagnosticsProjectContext {
    workspace_root: PathBuf,
    project_root_absolute_path: PathBuf,
    tsconfig_absolute_path: Option<PathBuf>,
    tsconfig_paths: Vec<PathBuf>,
    package_root_absolute_path: Option<PathBuf>,
    path_count: usize,
}

pub(super) struct TestCommand {
    executable: &'static str,
    display_command: &'static str,
    args: Vec<String>,
}

pub(super) fn test_command_for_input(
    command_id: &str,
    cwd: &Path,
    paths: &[WorkspacePath],
) -> TestCommand {
    match command_id {
        "node.test" => {
            let mut args = vec!["--test".to_string()];
            args.extend(
                paths
                    .iter()
                    .map(|path| relative_path_between(cwd, &path.absolute_path)),
            );
            TestCommand {
                executable: "node",
                display_command: "node --test",
                args,
            }
        }
        "npm.test" => TestCommand {
            executable: "npm",
            display_command: "npm test",
            args: vec!["test".to_string()],
        },
        "cargo.test" => TestCommand {
            executable: "cargo",
            display_command: "cargo test",
            args: vec!["test".to_string()],
        },
        "cargo.check" => TestCommand {
            executable: "cargo",
            display_command: "cargo check",
            args: vec!["check".to_string()],
        },
        _ => unreachable!("test command id is validated before command mapping"),
    }
}

pub(super) fn diagnostics_project_context(
    root: &Path,
    run_cwd: &Path,
    paths: &[WorkspacePath],
) -> DiagnosticsProjectContext {
    let mut tsconfig_paths = Vec::new();
    for path in paths {
        let start = path
            .absolute_path
            .parent()
            .unwrap_or(path.absolute_path.as_path());
        if let Some(tsconfig_path) = find_nearest_file(start, "tsconfig.json", root) {
            if !tsconfig_paths.contains(&tsconfig_path) {
                tsconfig_paths.push(tsconfig_path);
            }
        }
    }
    let tsconfig_absolute_path = tsconfig_paths
        .first()
        .cloned()
        .or_else(|| find_nearest_file(run_cwd, "tsconfig.json", root));
    let project_root_absolute_path = tsconfig_absolute_path
        .as_ref()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| run_cwd.to_path_buf());
    let package_root_absolute_path =
        find_nearest_file(&project_root_absolute_path, "package.json", root)
            .and_then(|path| path.parent().map(Path::to_path_buf));
    DiagnosticsProjectContext {
        workspace_root: root.to_path_buf(),
        project_root_absolute_path,
        tsconfig_absolute_path,
        tsconfig_paths,
        package_root_absolute_path,
        path_count: paths.len(),
    }
}

impl DiagnosticsProjectContext {
    fn to_json(&self, tsc_available: bool) -> Value {
        json!({
            "schemaVersion": "ioi.runtime.diagnostics-project-context.v1",
            "projectRoot": workspace_relative_from_absolute(&self.workspace_root, &self.project_root_absolute_path),
            "tsconfigPath": self.tsconfig_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path)),
            "tsconfigPaths": self.tsconfig_paths
                .iter()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path))
                .collect::<Vec<_>>(),
            "packageRoot": self.package_root_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(&self.workspace_root, path)),
            "packageManager": self.package_root_absolute_path
                .as_ref()
                .and_then(|path| package_manager_for_directory(path)),
            "pathCount": self.path_count,
            "tscAvailable": tsc_available,
        })
    }
}

pub(super) fn run_typescript_check(
    root: &Path,
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    input: &Value,
    project_context: DiagnosticsProjectContext,
) -> Result<DiagnosticRun, BridgeError> {
    let backend = if project_context.tsconfig_absolute_path.is_some() {
        "typescript.project.check"
    } else {
        "typescript.file.check"
    };
    let display_command = if project_context.tsconfig_absolute_path.is_some() {
        "tsc --noEmit --pretty false -p tsconfig.json"
    } else {
        "tsc --noEmit --pretty false"
    };
    let executable = local_tsc_executable(root, &project_context.project_root_absolute_path);
    let project_context_json = project_context.to_json(executable.is_some());
    let Some(executable) = executable else {
        return Ok(DiagnosticRun {
            backend,
            resolved_command_id: "typescript.check",
            display_command,
            stdout: String::new(),
            stderr: "typescript.check degraded: local node_modules/.bin/tsc was not found."
                .to_string(),
            exit_code: 0,
            timed_out: false,
            backend_status: "degraded",
            backend_reason: Some("typescript_executable_missing"),
            fallback_used: false,
            fallback_from: None,
            project_context: project_context_json,
            diagnostic_status: "degraded",
            diagnostics: vec![],
        });
    };
    let mut args = vec![
        "--noEmit".to_string(),
        "--pretty".to_string(),
        "false".to_string(),
    ];
    if let Some(tsconfig_path) = project_context.tsconfig_absolute_path.as_ref() {
        args.push("-p".to_string());
        args.push(relative_path_between(cwd, tsconfig_path));
    } else {
        args.extend(
            paths
                .iter()
                .map(|path| relative_path_between(cwd, &path.absolute_path)),
        );
    }
    args.extend(sanitize_string_array(input.get("args")));
    let executable_text = executable.to_string_lossy().to_string();
    let run = run_command_with_timeout(&executable_text, &args, cwd, timeout_ms, &[])?;
    let mut diagnostics = if run.exit_code == 0 && !run.timed_out {
        vec![]
    } else {
        typescript_output_diagnostics(root, cwd, &format!("{}\n{}", run.stdout, run.stderr))
    };
    if run.timed_out && diagnostics.is_empty() {
        diagnostics.push(json!({
            "path": project_context.tsconfig_absolute_path
                .as_ref()
                .map(|path| workspace_relative_from_absolute(root, path))
                .or_else(|| paths.first().map(|path| path.relative_path.clone())),
            "severity": "error",
            "source": "typescript.check",
            "code": "timeout",
            "message": "typescript.check timed out.",
            "line": null,
            "column": null,
        }));
    }
    let diagnostic_status = if run.timed_out || !diagnostics.is_empty() {
        "findings"
    } else {
        "clean"
    };
    Ok(DiagnosticRun {
        backend,
        resolved_command_id: "typescript.check",
        display_command,
        stdout: run.stdout,
        stderr: run.stderr,
        exit_code: run.exit_code,
        timed_out: run.timed_out,
        backend_status: if run.timed_out {
            "timed_out"
        } else {
            "available"
        },
        backend_reason: None,
        fallback_used: false,
        fallback_from: None,
        project_context: project_context_json,
        diagnostic_status,
        diagnostics,
    })
}

pub(super) fn typescript_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
}

pub(super) fn typescript_output_diagnostics(root: &Path, cwd: &Path, output: &str) -> Vec<Value> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| typescript_output_diagnostic(root, cwd, line))
        .collect()
}

pub(super) fn typescript_output_diagnostic(root: &Path, cwd: &Path, line: &str) -> Option<Value> {
    let marker = "): error ";
    let marker_index = line.find(marker)?;
    let prefix = &line[..marker_index + 1];
    let rest = &line[marker_index + marker.len()..];
    let open_index = prefix.rfind('(')?;
    let close_index = prefix.rfind(')')?;
    let path_text = prefix[..open_index].trim();
    let location = &prefix[open_index + 1..close_index];
    let mut location_parts = location.split(',');
    let line_number = location_parts.next()?.trim().parse::<u64>().ok()?;
    let column_number = location_parts.next()?.trim().parse::<u64>().ok()?;
    let code_end = rest.find(':')?;
    let code = rest[..code_end].trim();
    let message = rest[code_end + 1..].trim();
    if code.is_empty() || message.is_empty() {
        return None;
    }
    Some(json!({
        "path": normalize_diagnostic_path(root, cwd, path_text),
        "severity": "error",
        "source": "typescript.check",
        "code": code,
        "message": message,
        "line": line_number,
        "column": column_number,
    }))
}

pub(super) fn normalize_diagnostic_path(root: &Path, cwd: &Path, diagnostic_path: &str) -> String {
    let normalized = diagnostic_path.replace('\\', "/");
    let candidate = if Path::new(&normalized).is_absolute() {
        PathBuf::from(&normalized)
    } else {
        cwd.join(&normalized)
    };
    let normalized_candidate = normalize_path_lexically(&candidate);
    if normalized_candidate.starts_with(root) {
        workspace_relative_from_absolute(root, &normalized_candidate)
    } else {
        normalized
    }
}

pub(super) fn local_tsc_executable(root: &Path, preferred_directory: &Path) -> Option<PathBuf> {
    let executable_name = if cfg!(windows) { "tsc.cmd" } else { "tsc" };
    let mut current = if preferred_directory.starts_with(root) {
        preferred_directory.to_path_buf()
    } else {
        root.to_path_buf()
    };
    loop {
        let candidate = current
            .join("node_modules")
            .join(".bin")
            .join(executable_name);
        if candidate.exists() {
            return Some(candidate);
        }
        if current == root || !current.pop() {
            break;
        }
    }
    None
}

pub(super) fn find_nearest_file(
    start_directory: &Path,
    file_name: &str,
    root: &Path,
) -> Option<PathBuf> {
    let mut current = normalize_path_lexically(start_directory);
    if !current.starts_with(root) {
        current = root.to_path_buf();
    }
    loop {
        let candidate = current.join(file_name);
        if candidate.exists() {
            return Some(candidate);
        }
        if current == root || !current.pop() {
            break;
        }
    }
    None
}

pub(super) fn package_manager_for_directory(directory: &Path) -> Option<&'static str> {
    if directory.join("pnpm-lock.yaml").exists() {
        Some("pnpm")
    } else if directory.join("yarn.lock").exists() {
        Some("yarn")
    } else if directory.join("bun.lockb").exists() {
        Some("bun")
    } else if directory.join("package-lock.json").exists()
        || directory.join("package.json").exists()
    {
        Some("npm")
    } else {
        None
    }
}

pub(super) fn workspace_relative_from_absolute(root: &Path, target: &Path) -> String {
    let normalized_root = normalize_path_lexically(root);
    let normalized_target = normalize_path_lexically(target);
    normalized_target
        .strip_prefix(&normalized_root)
        .ok()
        .map(|path| {
            let relative = path.to_string_lossy().replace('\\', "/");
            if relative.is_empty() {
                ".".to_string()
            } else {
                relative
            }
        })
        .unwrap_or_else(|| normalized_target.to_string_lossy().replace('\\', "/"))
}

pub(super) fn run_node_check(
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    project_context: DiagnosticsProjectContext,
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
    let diagnostic_status = if backend_status == "degraded" {
        "degraded"
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.get("severity").and_then(Value::as_str) == Some("error"))
    {
        "findings"
    } else {
        "clean"
    };
    Ok(DiagnosticRun {
        backend: "node.check",
        resolved_command_id: "node.check",
        display_command: "node --check",
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
        fallback_used: false,
        fallback_from: None,
        project_context: project_context.to_json(false),
        diagnostic_status,
        diagnostics,
    })
}

pub(super) fn node_check_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")
}

pub(super) fn run_command_with_timeout(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    env_overrides: &[(String, String)],
) -> Result<CapturedCommand, BridgeError> {
    run_core_command_with_timeout(command, args, cwd, timeout_ms, env_overrides)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn sanitize_string_array(value: Option<&Value>) -> Vec<String> {
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

pub(super) fn json_string_refs(value: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        let refs = sanitize_string_array(value.get(*key));
        if !refs.is_empty() {
            return refs;
        }
    }
    Vec::new()
}

pub(super) fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn unique_string_refs(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut unique, value| {
        if !unique.contains(&value) {
            unique.push(value);
        }
        unique
    })
}

pub(super) fn sanitize_test_env(value: Option<&Value>) -> Vec<(String, String)> {
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

pub(super) fn node_check_output_diagnostics(
    target: &WorkspacePath,
    run: &CapturedCommand,
) -> Vec<Value> {
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

pub(super) fn diagnostic_code(message: &str) -> String {
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

pub(super) fn run_git_read_only(
    root: &Path,
    args: &[String],
) -> Result<CommandOutput, BridgeError> {
    run_core_git_read_only(root, args)
        .map_err(|error| BridgeError::new(error.code(), error.message().to_string()))
}

pub(super) fn nonempty_command_error(output: &CommandOutput, fallback: &str) -> String {
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

pub(super) fn sha256_hex(bytes: &[u8]) -> Result<String, BridgeError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| BridgeError::new("sha256_failed", error.to_string()))
}

pub(super) fn safe_ref_path(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    if safe.is_empty() {
        "file".to_string()
    } else {
        safe
    }
}

pub(super) fn utf8_preview(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

pub(super) fn bounded_u64(value: Option<u64>, default: u64, min: u64, max: u64) -> u64 {
    value.unwrap_or(default).clamp(min, max)
}
