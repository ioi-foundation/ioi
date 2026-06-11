use crate::agentic::runtime::kernel::coding_tool_execution::{run_git_read_only, CommandOutput};
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const APPLY_PATCH_MAX_FILE_BYTES: u64 = 1024 * 1024;
const APPLY_PATCH_MAX_DIFF_BYTES: usize = 32 * 1024;
const APPLY_PATCH_MAX_EDITS: usize = 20;
const DEFAULT_PREVIEW_BYTES: u64 = 8 * 1024;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const DEFAULT_PREVIEW_LINES: usize = 200;
const MAX_PREVIEW_LINES: usize = 1000;
const MAX_DIFF_BYTES: u64 = 64 * 1024;

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
}
