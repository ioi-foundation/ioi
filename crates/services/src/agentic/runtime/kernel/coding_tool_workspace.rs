use crate::agentic::runtime::kernel::coding_tool_execution::{
    env_key_allowed, run_command_with_timeout, run_git_read_only, CapturedCommand, CommandOutput,
};
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const APPLY_PATCH_MAX_FILE_BYTES: u64 = 1024 * 1024;
const APPLY_PATCH_MAX_DIFF_BYTES: usize = 32 * 1024;
const APPLY_PATCH_MAX_EDITS: usize = 20;
const DEFAULT_PREVIEW_BYTES: u64 = 8 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 1000;
const MAX_DIFF_BYTES: u64 = 64 * 1024;
const TEST_DEFAULT_TIMEOUT_MS: u64 = 60 * 1000;
const TEST_MAX_TIMEOUT_MS: u64 = 5 * 60 * 1000;
const TEST_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const TEST_COMMAND_IDS: [&str; 4] = ["node.test", "npm.test", "cargo.test", "cargo.check"];
const DIAGNOSTIC_DEFAULT_TIMEOUT_MS: u64 = 30 * 1000;
const DIAGNOSTIC_MAX_TIMEOUT_MS: u64 = 2 * 60 * 1000;
const DIAGNOSTIC_DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_COMMAND_IDS: [&str; 3] = ["auto", "node.check", "typescript.check"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolWorkspaceError {
    code: &'static str,
    message: String,
}

impl CodingToolWorkspaceError {
    pub fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePatchOutcome {
    pub observation: Value,
    pub transition: Option<WorkspacePatchTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePatchTransition {
    pub operation_ref: String,
    pub payload_ref: String,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspacePath {
    absolute_path: PathBuf,
    relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatchDiffPreview {
    text: String,
    bytes: usize,
    hash: String,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatchEditApplication {
    text: String,
    summary: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestCommand {
    executable: &'static str,
    display_command: &'static str,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticRun {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticsProjectContext {
    workspace_root: PathBuf,
    project_root_absolute_path: PathBuf,
    tsconfig_absolute_path: Option<PathBuf>,
    tsconfig_paths: Vec<PathBuf>,
    package_root_absolute_path: Option<PathBuf>,
    path_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatchEdit {
    Replace {
        old_text: String,
        new_text: String,
        occurrence: String,
    },
    Append {
        text: String,
    },
    Prepend {
        text: String,
    },
}

pub fn apply_workspace_patch(
    workspace_root: &str,
    input: &Value,
) -> Result<WorkspacePatchOutcome, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
    let selected_path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CodingToolWorkspaceError::new(
                "file_apply_patch_path_required",
                "file.apply_patch requires a workspace-relative path.".to_string(),
            )
        })?;
    let target = workspace_path_allow_missing(&root, selected_path)?;
    let dry_run = input
        .get("dryRun")
        .or_else(|| input.get("dry_run"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let create = input
        .get("create")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let exists = target.absolute_path.exists();
    let before_metadata = if exists {
        Some(fs::metadata(&target.absolute_path).map_err(|error| {
            CodingToolWorkspaceError::new("file_apply_patch_metadata_failed", error.to_string())
        })?)
    } else {
        None
    };
    if !exists && !create {
        return Err(CodingToolWorkspaceError::new(
            "not_found",
            format!("File not found: {}", target.relative_path),
        ));
    }
    if let Some(metadata) = before_metadata.as_ref() {
        if !metadata.is_file() {
            return Err(CodingToolWorkspaceError::new(
                "file_apply_patch_not_file",
                "file.apply_patch can only edit regular files.".to_string(),
            ));
        }
        if metadata.len() > APPLY_PATCH_MAX_FILE_BYTES {
            return Err(CodingToolWorkspaceError::new(
                "file_apply_patch_file_too_large",
                "file.apply_patch refused a file over the edit size limit.".to_string(),
            ));
        }
    } else if let Some(parent) = target.absolute_path.parent() {
        if !parent.exists() || !parent.is_dir() {
            return Err(CodingToolWorkspaceError::new(
                "file_apply_patch_parent_missing",
                "file.apply_patch create mode requires an existing parent directory.".to_string(),
            ));
        }
    }
    let before = if exists {
        fs::read_to_string(&target.absolute_path).map_err(|error| {
            CodingToolWorkspaceError::new("file_apply_patch_read_failed", error.to_string())
        })?
    } else {
        String::new()
    };
    let edits = normalize_patch_edits(input)?;
    if edits.is_empty() {
        return Err(CodingToolWorkspaceError::new(
            "file_apply_patch_empty",
            "file.apply_patch requires at least one edit.".to_string(),
        ));
    }
    let mut after = before.clone();
    let mut applied_edits = Vec::new();
    for edit in &edits {
        let applied = apply_patch_edit(&after, edit, &target.relative_path)?;
        after = applied.text;
        applied_edits.push(applied.summary);
    }
    let before_hash = sha256_hex(before.as_bytes())?;
    let after_hash = sha256_hex(after.as_bytes())?;
    let changed = before_hash != after_hash;
    let diff = text_diff_preview(&target.relative_path, &before, &after)?;
    if !dry_run && changed {
        fs::write(&target.absolute_path, after.as_bytes()).map_err(|error| {
            CodingToolWorkspaceError::new("file_apply_patch_write_failed", error.to_string())
        })?;
    }
    let after_metadata = if !dry_run && target.absolute_path.exists() {
        fs::metadata(&target.absolute_path).ok()
    } else {
        None
    };
    let before_bytes = before.len();
    let after_bytes = after.len();
    let changed_file = json!({
        "path": target.relative_path,
        "beforeHash": before_hash,
        "afterHash": after_hash,
        "beforeExists": exists,
        "afterExists": if !dry_run { true } else { exists },
        "beforeSizeBytes": if exists { before_bytes } else { 0 },
        "afterSizeBytes": after_bytes,
        "beforeMtimeMs": before_metadata.as_ref().and_then(metadata_mtime_ms),
        "afterMtimeMs": after_metadata.as_ref().and_then(metadata_mtime_ms),
        "created": !exists,
        "diagnosticsRecommended": !dry_run,
    });
    let transition = if changed && !dry_run {
        Some(patch_transition(
            &target.relative_path,
            &before_hash,
            &after_hash,
        ))
    } else {
        None
    };
    let transition_payload_ref = transition
        .as_ref()
        .map(|transition| transition.payload_ref.clone());
    let observation = json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "path": target.relative_path,
        "dryRun": dry_run,
        "applied": !dry_run && changed,
        "changed": changed,
        "created": !exists,
        "editCount": applied_edits.len(),
        "edits": applied_edits,
        "beforeHash": before_hash,
        "afterHash": after_hash,
        "diff": diff.text,
        "diffBytes": diff.bytes,
        "diffHash": diff.hash,
        "truncated": diff.truncated,
        "changedFiles": if changed { vec![changed_file] } else { vec![] },
        "workspaceSnapshotDrafts": if changed && !dry_run {
            vec![json!({
                "path": target.relative_path,
                "encoding": "utf8",
                "beforeExists": exists,
                "afterExists": true,
                "beforeContent": if exists { Some(before.clone()) } else { None },
                "afterContent": after,
            })]
        } else {
            vec![]
        },
        "diagnosticsRecommended": changed && !dry_run,
        "receiptRefs": [
            format!("receipt_file_apply_patch_{}_{}", safe_ref_path(&target.relative_path), after_hash.chars().take(12).collect::<String>())
        ],
        "payloadRefs": transition_payload_ref.into_iter().collect::<Vec<_>>(),
        "shellFallbackUsed": false,
    });
    Ok(WorkspacePatchOutcome {
        observation,
        transition,
    })
}

pub fn inspect_test_run(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("node.test");
    if !TEST_COMMAND_IDS.contains(&command_id) {
        return Err(CodingToolWorkspaceError::new(
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
    let run_cwd = workspace_directory(
        &root,
        cwd,
        "test_run_cwd_missing",
        "test.run path must stay inside workspace",
    )?;
    let paths = workspace_tool_paths(&root, input, "test.run path must stay inside workspace")?;
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
    )
    .map_err(workspace_execution_error)?;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let (stdout, stdout_truncated) = utf8_preview(&run.stdout, max_output_bytes);
    let (stderr, stderr_truncated) = utf8_preview(&run.stderr, max_output_bytes);
    let output_text = format!("{}\n{}", run.stdout, run.stderr);
    let output_hash = sha256_hex(output_text.as_bytes())?;
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

pub fn inspect_lsp_diagnostics(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
    let command_id = input
        .get("commandId")
        .or_else(|| input.get("command_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto");
    if !DIAGNOSTIC_COMMAND_IDS.contains(&command_id) {
        return Err(CodingToolWorkspaceError::new(
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
    let run_cwd = workspace_directory(
        &root,
        cwd,
        "lsp_diagnostics_cwd_missing",
        "lsp.diagnostics path must stay inside workspace",
    )?;
    let paths = workspace_tool_paths(
        &root,
        input,
        "lsp.diagnostics path must stay inside workspace",
    )?;
    if paths.is_empty() {
        return Err(CodingToolWorkspaceError::new(
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
    let output_hash = sha256_hex(output_text.as_bytes())?;
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

pub fn inspect_workspace_status(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
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
    let status = run_git_read_only(&root, &args).map_err(workspace_execution_error)?;
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
    let porcelain_hash = sha256_hex(status.stdout.as_bytes())?;
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

pub fn inspect_git_diff(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
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
    let diff_output = run_git_read_only(&root, &diff_args).map_err(workspace_execution_error)?;
    if !diff_output.ok {
        return Err(CodingToolWorkspaceError::new(
            "git_diff_failed",
            nonempty_command_error(&diff_output, "git diff failed"),
        ));
    }
    let mut stat_args = vec!["diff".to_string(), "--stat".to_string(), "--".to_string()];
    stat_args.extend(paths.iter().cloned());
    let stat_output = run_git_read_only(&root, &stat_args).map_err(workspace_execution_error)?;
    let (diff_preview, truncated) = utf8_preview(&diff_output.stdout, max_bytes);
    let diff_hash = sha256_hex(diff_output.stdout.as_bytes())?;
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

pub fn inspect_workspace_path(
    workspace_root: &str,
    selected_path: &str,
    input: &Value,
) -> Result<Value, CodingToolWorkspaceError> {
    let root = fs::canonicalize(workspace_root).map_err(|error| {
        CodingToolWorkspaceError::new("workspace_root_invalid", error.to_string())
    })?;
    let target = workspace_existing_path(&root, selected_path)?;
    let metadata = fs::metadata(&target.absolute_path)
        .map_err(|error| CodingToolWorkspaceError::new("not_found", error.to_string()))?;
    if metadata.is_dir() {
        let mut entries = fs::read_dir(&target.absolute_path)
            .map_err(|error| {
                CodingToolWorkspaceError::new("file_inspect_read_dir_failed", error.to_string())
            })?
            .take(100)
            .map(|entry| {
                entry
                    .map_err(|error| {
                        CodingToolWorkspaceError::new(
                            "file_inspect_read_dir_failed",
                            error.to_string(),
                        )
                    })
                    .and_then(|entry| {
                        let kind = entry.file_type().map_err(|error| {
                            CodingToolWorkspaceError::new(
                                "file_inspect_file_type_failed",
                                error.to_string(),
                            )
                        })?;
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
            "path": target.relative_path,
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
            "path": target.relative_path,
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
    let mut file = fs::File::open(&target.absolute_path).map_err(|error| {
        CodingToolWorkspaceError::new("file_inspect_open_failed", error.to_string())
    })?;
    let mut buffer = vec![0u8; bytes_to_read];
    let bytes_read = file.read(&mut buffer).map_err(|error| {
        CodingToolWorkspaceError::new("file_inspect_read_failed", error.to_string())
    })?;
    buffer.truncate(bytes_read);
    let preview = String::from_utf8_lossy(&buffer);
    let lines = preview.split('\n').collect::<Vec<_>>();
    let line_preview = lines
        .iter()
        .take(preview_lines)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    let preview_hash = format!("sha256:{}", sha256_hex(line_preview.as_bytes())?);
    Ok(json!({
        "schemaVersion": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "workspaceRoot": workspace_root,
        "path": target.relative_path,
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

fn workspace_tool_paths(
    root: &Path,
    input: &Value,
    outside_message: &'static str,
) -> Result<Vec<WorkspacePath>, CodingToolWorkspaceError> {
    selected_workspace_paths(input)
        .iter()
        .map(|selected_path| {
            workspace_path_allow_missing_with_message(root, selected_path, outside_message)
        })
        .collect()
}

fn workspace_directory(
    root: &Path,
    selected_path: &str,
    error_code: &'static str,
    outside_message: &'static str,
) -> Result<WorkspacePath, CodingToolWorkspaceError> {
    let path = workspace_path_allow_missing_with_message(root, selected_path, outside_message)?;
    if !path.absolute_path.is_dir() {
        return Err(CodingToolWorkspaceError::new(
            error_code,
            "workspace directory must exist".to_string(),
        ));
    }
    Ok(path)
}

fn test_command_for_input(command_id: &str, cwd: &Path, paths: &[WorkspacePath]) -> TestCommand {
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

fn diagnostics_project_context(
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

fn run_typescript_check(
    root: &Path,
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    input: &Value,
    project_context: DiagnosticsProjectContext,
) -> Result<DiagnosticRun, CodingToolWorkspaceError> {
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
    let run = run_command_with_timeout(&executable_text, &args, cwd, timeout_ms, &[])
        .map_err(workspace_execution_error)?;
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

fn typescript_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".mts")
        || lower.ends_with(".cts")
}

fn typescript_output_diagnostics(root: &Path, cwd: &Path, output: &str) -> Vec<Value> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| typescript_output_diagnostic(root, cwd, line))
        .collect()
}

fn typescript_output_diagnostic(root: &Path, cwd: &Path, line: &str) -> Option<Value> {
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

fn normalize_diagnostic_path(root: &Path, cwd: &Path, diagnostic_path: &str) -> String {
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

fn local_tsc_executable(root: &Path, preferred_directory: &Path) -> Option<PathBuf> {
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

fn find_nearest_file(start_directory: &Path, file_name: &str, root: &Path) -> Option<PathBuf> {
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

fn package_manager_for_directory(directory: &Path) -> Option<&'static str> {
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

fn workspace_relative_from_absolute(root: &Path, target: &Path) -> String {
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

fn run_node_check(
    cwd: &Path,
    paths: &[WorkspacePath],
    timeout_ms: u64,
    project_context: DiagnosticsProjectContext,
) -> Result<DiagnosticRun, CodingToolWorkspaceError> {
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
        )
        .map_err(workspace_execution_error)?;
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

fn node_check_path_supported(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs")
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

fn workspace_diff_paths(
    root: &Path,
    input: &Value,
) -> Result<Vec<String>, CodingToolWorkspaceError> {
    let selected_paths = selected_workspace_paths(input);
    selected_paths
        .iter()
        .map(|selected_path| {
            workspace_relative_path_allow_missing(
                root,
                selected_path,
                "git.diff path must stay inside workspace",
            )
        })
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
    outside_message: &'static str,
) -> Result<String, CodingToolWorkspaceError> {
    Ok(
        workspace_path_allow_missing_with_message(root, selected_path, outside_message)?
            .relative_path,
    )
}

fn workspace_path_allow_missing(
    root: &Path,
    selected_path: &str,
) -> Result<WorkspacePath, CodingToolWorkspaceError> {
    workspace_path_allow_missing_with_message(
        root,
        selected_path,
        "file.apply_patch path must stay inside workspace",
    )
}

fn workspace_path_allow_missing_with_message(
    root: &Path,
    selected_path: &str,
    outside_message: &'static str,
) -> Result<WorkspacePath, CodingToolWorkspaceError> {
    let candidate = path_candidate(root, selected_path);
    let normalized_root = normalize_path_lexically(root);
    let normalized_candidate = normalize_path_lexically(&candidate);
    if !normalized_candidate.starts_with(&normalized_root) {
        return Err(CodingToolWorkspaceError::new(
            "path_outside_workspace",
            outside_message.to_string(),
        ));
    }
    if let Some(boundary) = nearest_existing_path(&normalized_candidate) {
        let real_boundary = fs::canonicalize(&boundary).map_err(|error| {
            CodingToolWorkspaceError::new("path_boundary_invalid", error.to_string())
        })?;
        if !real_boundary.starts_with(root) {
            return Err(CodingToolWorkspaceError::new(
                "path_outside_workspace",
                outside_message.to_string(),
            ));
        }
    }
    let relative = normalized_candidate
        .strip_prefix(&normalized_root)
        .map_err(|_| {
            CodingToolWorkspaceError::new("path_outside_workspace", outside_message.to_string())
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

fn workspace_existing_path(
    root: &Path,
    selected_path: &str,
) -> Result<WorkspacePath, CodingToolWorkspaceError> {
    let candidate = path_candidate(root, selected_path);
    let canonical = fs::canonicalize(&candidate)
        .map_err(|error| CodingToolWorkspaceError::new("not_found", error.to_string()))?;
    if !canonical.starts_with(root) {
        return Err(CodingToolWorkspaceError::new(
            "path_outside_workspace",
            "file.inspect path must stay inside workspace".to_string(),
        ));
    }
    let relative = canonical
        .strip_prefix(root)
        .unwrap_or(canonical.as_path())
        .to_string_lossy()
        .replace('\\', "/");
    Ok(WorkspacePath {
        absolute_path: canonical,
        relative_path: if relative.is_empty() {
            ".".to_string()
        } else {
            relative
        },
    })
}

fn path_candidate(root: &Path, selected_path: &str) -> PathBuf {
    if Path::new(selected_path).is_absolute() {
        PathBuf::from(selected_path)
    } else {
        root.join(selected_path)
    }
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

fn normalize_patch_edits(input: &Value) -> Result<Vec<PatchEdit>, CodingToolWorkspaceError> {
    let mut edits = Vec::new();
    if let Some(values) = input.get("edits").and_then(Value::as_array) {
        for value in values.iter().take(APPLY_PATCH_MAX_EDITS) {
            edits.push(patch_edit_from_value(value)?);
        }
    }
    if input.get("oldText").is_some() || input.get("old_text").is_some() {
        edits.push(PatchEdit::Replace {
            old_text: string_field(input, &["oldText", "old_text"]).unwrap_or_default(),
            new_text: string_field(input, &["newText", "new_text"]).unwrap_or_default(),
            occurrence: string_field(input, &["occurrence"]).unwrap_or_else(|| "only".to_string()),
        });
    }
    if input.get("appendText").is_some() || input.get("append_text").is_some() {
        edits.push(PatchEdit::Append {
            text: string_field(input, &["appendText", "append_text"]).unwrap_or_default(),
        });
    }
    if input.get("prependText").is_some() || input.get("prepend_text").is_some() {
        edits.push(PatchEdit::Prepend {
            text: string_field(input, &["prependText", "prepend_text"]).unwrap_or_default(),
        });
    }
    edits.truncate(APPLY_PATCH_MAX_EDITS);
    Ok(edits)
}

fn patch_edit_from_value(value: &Value) -> Result<PatchEdit, CodingToolWorkspaceError> {
    let object = value.as_object().ok_or_else(|| {
        CodingToolWorkspaceError::new(
            "file_apply_patch_unknown_edit",
            "Patch edit entries must be objects.".to_string(),
        )
    })?;
    let edit_value = Value::Object(object.clone());
    let edit_type = string_field(&edit_value, &["type"]).unwrap_or_default();
    match edit_type.as_str() {
        "append" => Ok(PatchEdit::Append {
            text: string_field(&edit_value, &["text"]).unwrap_or_default(),
        }),
        "prepend" => Ok(PatchEdit::Prepend {
            text: string_field(&edit_value, &["text"]).unwrap_or_default(),
        }),
        "replace" => Ok(PatchEdit::Replace {
            old_text: string_field(&edit_value, &["oldText", "old_text"]).unwrap_or_default(),
            new_text: string_field(&edit_value, &["newText", "new_text"]).unwrap_or_default(),
            occurrence: string_field(&edit_value, &["occurrence"])
                .unwrap_or_else(|| "only".to_string()),
        }),
        _ => Err(CodingToolWorkspaceError::new(
            "file_apply_patch_unknown_edit",
            "Unsupported file.apply_patch edit type.".to_string(),
        )),
    }
}

fn apply_patch_edit(
    text: &str,
    edit: &PatchEdit,
    relative_path: &str,
) -> Result<PatchEditApplication, CodingToolWorkspaceError> {
    match edit {
        PatchEdit::Append { text: addition } => Ok(PatchEditApplication {
            text: format!("{text}{addition}"),
            summary: json!({
                "type": "append",
                "bytesAdded": addition.len(),
            }),
        }),
        PatchEdit::Prepend { text: addition } => Ok(PatchEditApplication {
            text: format!("{addition}{text}"),
            summary: json!({
                "type": "prepend",
                "bytesAdded": addition.len(),
            }),
        }),
        PatchEdit::Replace {
            old_text,
            new_text,
            occurrence,
        } => {
            if old_text.is_empty() {
                return Err(CodingToolWorkspaceError::new(
                    "file_apply_patch_empty_old_text",
                    "Replace edits require non-empty oldText.".to_string(),
                ));
            }
            let count = count_occurrences(text, old_text);
            if count == 0 {
                return Err(CodingToolWorkspaceError::new(
                    "file_apply_patch_old_text_missing",
                    format!("file.apply_patch could not find oldText in {relative_path}."),
                ));
            }
            if occurrence == "only" && count != 1 {
                return Err(CodingToolWorkspaceError::new(
                    "file_apply_patch_old_text_ambiguous",
                    format!("file.apply_patch oldText matched more than once in {relative_path}."),
                ));
            }
            let next_text = if occurrence == "all" {
                text.replace(old_text, new_text)
            } else {
                text.replacen(old_text, new_text, 1)
            };
            Ok(PatchEditApplication {
                text: next_text,
                summary: json!({
                    "type": "replace",
                    "occurrence": occurrence,
                    "matches": if occurrence == "all" { count } else { 1 },
                    "oldHash": sha256_hex(old_text.as_bytes())?,
                    "newHash": sha256_hex(new_text.as_bytes())?,
                }),
            })
        }
    }
}

fn count_occurrences(text: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut offset = 0;
    while let Some(found) = text[offset..].find(needle) {
        count += 1;
        offset += found + needle.len();
        if offset > text.len() {
            break;
        }
    }
    count
}

fn text_diff_preview(
    relative_path: &str,
    before: &str,
    after: &str,
) -> Result<PatchDiffPreview, CodingToolWorkspaceError> {
    if before == after {
        return Ok(PatchDiffPreview {
            text: String::new(),
            bytes: 0,
            hash: sha256_hex(b"")?,
            truncated: false,
        });
    }
    let raw = format!("--- a/{relative_path}\n+++ b/{relative_path}\n@@\n-{before}\n+{after}\n");
    let bytes = raw.len();
    let (text, truncated) = utf8_preview(&raw, APPLY_PATCH_MAX_DIFF_BYTES);
    let hash = sha256_hex(raw.as_bytes())?;
    Ok(PatchDiffPreview {
        text,
        bytes,
        hash,
        truncated,
    })
}

fn patch_transition(
    relative_path: &str,
    before_hash: &str,
    after_hash: &str,
) -> WorkspacePatchTransition {
    let path_ref = safe_ref_path(relative_path);
    WorkspacePatchTransition {
        operation_ref: format!(
            "agentgres://operation/file.apply_patch/{}/{}",
            path_ref,
            &after_hash[..12]
        ),
        payload_ref: format!(
            "payload://workspace/file.apply_patch/{path_ref}/{}",
            &after_hash[..12]
        ),
        expected_heads: vec![format!(
            "head://workspace/{path_ref}/{}",
            &before_hash[..12]
        )],
        state_root_before: format!("state://workspace/{path_ref}/{}", &before_hash[..12]),
        state_root_after: format!("state://workspace/{path_ref}/{}", &after_hash[..12]),
        resulting_head: format!("head://workspace/{path_ref}/{}", &after_hash[..12]),
    }
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn sha256_hex(bytes: &[u8]) -> Result<String, CodingToolWorkspaceError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| CodingToolWorkspaceError::new("sha256_failed", error.to_string()))
}

fn workspace_execution_error(
    error: crate::agentic::runtime::kernel::coding_tool_execution::CodingToolExecutionError,
) -> CodingToolWorkspaceError {
    CodingToolWorkspaceError::new(error.code(), error.message().to_string())
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

fn safe_ref_path(value: &str) -> String {
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

fn bounded_u64(value: Option<u64>, default_value: u64, minimum: u64, maximum: u64) -> u64 {
    value.unwrap_or(default_value).clamp(minimum, maximum)
}

fn bounded_usize(
    value: Option<u64>,
    default_value: usize,
    minimum: usize,
    maximum: usize,
) -> usize {
    value
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default_value)
        .clamp(minimum, maximum)
}

fn metadata_mtime_ms(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_workspace_patch_and_derives_transition_in_rust_core() {
        let workspace = temp_workspace("apply");
        let target = workspace.join("README.md");
        fs::write(&target, "before\n").expect("fixture file");

        let outcome = apply_workspace_patch(
            workspace.to_str().expect("workspace path"),
            &json!({
                "path": "README.md",
                "oldText": "before",
                "newText": "after"
            }),
        )
        .expect("patch applies");

        assert_eq!(
            fs::read_to_string(&target).expect("updated file"),
            "after\n"
        );
        assert_eq!(outcome.observation["applied"], true);
        let transition = outcome.transition.expect("transition");
        assert!(transition
            .operation_ref
            .starts_with("agentgres://operation/file.apply_patch/README.md/"));
        assert!(transition
            .payload_ref
            .starts_with("payload://workspace/file.apply_patch/README.md/"));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rejects_workspace_patch_path_escape_in_rust_core() {
        let workspace = temp_workspace("escape");
        let outside = workspace.parent().expect("parent").join("outside-file.txt");
        fs::write(&outside, "outside").expect("outside file");

        let error = apply_workspace_patch(
            workspace.to_str().expect("workspace path"),
            &json!({
                "path": "../outside-file.txt",
                "oldText": "outside",
                "newText": "changed"
            }),
        )
        .expect_err("path escape rejected");

        assert_eq!(error.code(), "path_outside_workspace");
        assert_eq!(fs::read_to_string(&outside).expect("outside"), "outside");
        let _ = fs::remove_file(outside);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_file_preview_in_rust_core() {
        let workspace = temp_workspace("inspect-file");
        let target = workspace.join("README.md");
        fs::write(&target, "# IOI\nsecond line\nthird line\n").expect("fixture file");

        let result = inspect_workspace_path(
            workspace.to_str().expect("workspace path"),
            "README.md",
            &json!({
                "previewLines": 2,
                "maxBytes": 100,
            }),
        )
        .expect("file inspected");

        assert_eq!(result["kind"], "file");
        assert_eq!(result["path"], "README.md");
        assert_eq!(result["preview"], "# IOI\nsecond line");
        assert_eq!(result["previewLineCount"], 2);
        assert!(result["previewHash"]
            .as_str()
            .expect("preview hash")
            .starts_with("sha256:"));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rejects_workspace_inspect_path_escape_in_rust_core() {
        let workspace = temp_workspace("inspect-escape");
        let outside = workspace
            .parent()
            .expect("parent")
            .join("outside-inspect.txt");
        fs::write(&outside, "outside").expect("outside file");

        let error = inspect_workspace_path(
            workspace.to_str().expect("workspace path"),
            "../outside-inspect.txt",
            &json!({}),
        )
        .expect_err("path escape rejected");

        assert_eq!(error.code(), "path_outside_workspace");
        let _ = fs::remove_file(outside);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_workspace_status_in_rust_core() {
        let workspace = temp_workspace("status");
        init_git_workspace(&workspace);
        fs::write(workspace.join("README.md"), "hello\n").expect("fixture file");

        let result =
            inspect_workspace_status(workspace.to_str().expect("workspace path"), &json!({}))
                .expect("status inspected");

        assert_eq!(result["git"]["available"], true);
        assert_eq!(result["counts"]["changed"], 1);
        assert_eq!(result["counts"]["untracked"], 1);
        assert_eq!(result["changedFiles"][0]["path"], "README.md");
        assert!(
            result["git"]["porcelainHash"]
                .as_str()
                .expect("porcelain hash")
                .len()
                >= 32
        );
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_git_diff_in_rust_core() {
        let workspace = temp_workspace("git-diff");
        init_git_workspace(&workspace);
        let target = workspace.join("README.md");
        fs::write(&target, "before\n").expect("fixture file");
        run_git(&workspace, &["add", "README.md"]);
        fs::write(&target, "before\nafter\n").expect("updated file");

        let result = inspect_git_diff(
            workspace.to_str().expect("workspace path"),
            &json!({
                "path": "README.md",
                "maxBytes": 4096,
            }),
        )
        .expect("diff inspected");

        assert_eq!(result["paths"][0], "README.md");
        assert!(result["diff"].as_str().expect("diff").contains("+after"));
        assert_eq!(result["truncated"], false);
        assert!(result["diffHash"].as_str().expect("diff hash").len() >= 32);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_test_run_in_rust_core() {
        let workspace = temp_workspace("test-run");
        fs::write(
            workspace.join("passing.test.mjs"),
            "import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('passes', () => assert.equal(1, 1));\n",
        )
        .expect("fixture file");

        let result = inspect_test_run(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "node.test",
                "path": "passing.test.mjs",
                "timeoutMs": 5000,
            }),
        )
        .expect("test inspected");

        assert_eq!(result["commandId"], "node.test");
        assert_eq!(result["command"], "node --test");
        assert_eq!(result["args"], json!(["--test", "passing.test.mjs"]));
        assert_eq!(result["testStatus"], "passed");
        assert_eq!(result["exitCode"], 0);
        assert!(result["outputHash"].as_str().expect("hash").len() >= 32);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rejects_disallowed_test_run_command_in_rust_core() {
        let workspace = temp_workspace("test-run-disallowed");

        let error = inspect_test_run(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "python.test",
            }),
        )
        .expect_err("command rejected");

        assert_eq!(error.code(), "test_run_command_not_allowed");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_lsp_diagnostics_node_check_in_rust_core() {
        let workspace = temp_workspace("lsp-node-clean");
        fs::write(workspace.join("ok.mjs"), "const value = 1;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "node.check",
                "path": "ok.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics inspected");

        assert_eq!(result["schemaVersion"], CODING_TOOL_RESULT_SCHEMA_VERSION);
        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["resolvedCommandId"], "node.check");
        assert_eq!(result["diagnosticStatus"], "clean");
        assert_eq!(result["diagnosticCount"], 0);
        assert_eq!(result["paths"], json!(["ok.mjs"]));
        assert_eq!(result["exitCode"], 0);
        assert_eq!(result["shellFallbackUsed"], false);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_lsp_diagnostics_node_check_findings_in_rust_core() {
        let workspace = temp_workspace("lsp-node-findings");
        fs::write(workspace.join("broken.mjs"), "const = ;\n").expect("fixture file");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "node.check",
                "path": "broken.mjs",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics inspected");

        assert_eq!(result["backend"], "node.check");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_ne!(result["exitCode"], 0);
        assert_eq!(result["diagnostics"][0]["path"], "broken.mjs");
        assert_eq!(result["diagnostics"][0]["severity"], "error");
        let _ = fs::remove_dir_all(workspace);
    }

    #[cfg(unix)]
    #[test]
    fn inspects_lsp_diagnostics_typescript_findings_in_rust_core() {
        let workspace = temp_workspace("lsp-typescript-findings");
        let source_dir = workspace.join("src");
        let bin = workspace.join("node_modules").join(".bin");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::create_dir_all(&bin).expect("bin dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");
        write_fake_executable(
            &bin.join("tsc"),
            "#!/bin/sh\necho \"src/broken.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.\"\nexit 2\n",
        );

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "typescript.check",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics inspected");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(
            result["command"],
            "tsc --noEmit --pretty false -p tsconfig.json"
        );
        assert_eq!(result["backendStatus"], "available");
        assert_eq!(result["diagnosticStatus"], "findings");
        assert_eq!(result["diagnosticCount"], 1);
        assert_eq!(result["diagnostics"][0]["path"], "src/broken.ts");
        assert_eq!(result["diagnostics"][0]["code"], "TS2322");
        assert_eq!(result["diagnostics"][0]["line"], 1);
        assert_eq!(result["diagnostics"][0]["column"], 7);
        assert_eq!(result["projectContext"]["tsconfigPath"], "tsconfig.json");
        assert_eq!(result["projectContext"]["tscAvailable"], true);
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn inspects_lsp_diagnostics_typescript_degraded_in_rust_core() {
        let workspace = temp_workspace("lsp-typescript-degraded");
        let source_dir = workspace.join("src");
        fs::create_dir_all(&source_dir).expect("source dir");
        fs::write(
            workspace.join("tsconfig.json"),
            r#"{"compilerOptions":{"strict":true},"include":["src/**/*.ts"]}"#,
        )
        .expect("tsconfig");
        fs::write(
            source_dir.join("broken.ts"),
            "const value: number = 'oops';\n",
        )
        .expect("ts fixture");

        let result = inspect_lsp_diagnostics(
            workspace.to_str().expect("workspace path"),
            &json!({
                "commandId": "auto",
                "path": "src/broken.ts",
                "timeoutMs": 5000
            }),
        )
        .expect("diagnostics inspected");

        assert_eq!(result["backend"], "typescript.project.check");
        assert_eq!(result["resolvedCommandId"], "typescript.check");
        assert_eq!(result["backendStatus"], "degraded");
        assert_eq!(result["backendReason"], "typescript_executable_missing");
        assert_eq!(result["diagnosticStatus"], "degraded");
        assert_eq!(result["projectContext"]["tscAvailable"], false);
        assert_eq!(result["fallbackUsed"], false);
        let _ = fs::remove_dir_all(workspace);
    }

    fn init_git_workspace(workspace: &Path) {
        run_git(workspace, &["init"]);
    }

    fn run_git(workspace: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn temp_workspace(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ioi-coding-tool-workspace-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("workspace dir");
        fs::canonicalize(path).expect("canonical workspace")
    }

    #[cfg(unix)]
    fn write_fake_executable(path: &Path, content: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, content).expect("fake executable");
        let mut permissions = fs::metadata(path)
            .expect("fake executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake executable permissions");
    }
}
