use super::types::WorkflowPortablePackageFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) fn workflow_base_dir(root: &Path) -> PathBuf {
    root.join(".agents").join("workflows")
}

pub(super) fn workflow_tests_path(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".tests.json"))
    } else {
        workflow_path.with_extension("tests.json")
    }
}

pub(super) fn workflow_proposals_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".proposals"))
    } else {
        workflow_path.with_extension("proposals")
    }
}

pub(super) fn workflow_fixtures_path(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".fixtures.json"))
    } else {
        workflow_path.with_extension("fixtures.json")
    }
}

pub(super) fn workflow_runs_path(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".runs"))
    } else {
        workflow_path.with_extension("runs")
    }
}

pub(super) fn workflow_run_result_path(workflow_path: &Path, run_id: &str) -> PathBuf {
    workflow_runs_path(workflow_path).join(format!("{}.json", run_id))
}

pub(super) fn workflow_checkpoints_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".checkpoints"))
    } else {
        workflow_path.with_extension("checkpoints")
    }
}

pub(super) fn workflow_thread_checkpoints_dir(workflow_path: &Path, thread_id: &str) -> PathBuf {
    workflow_checkpoints_dir(workflow_path).join(thread_id)
}

pub(super) fn workflow_interrupts_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".interrupts"))
    } else {
        workflow_path.with_extension("interrupts")
    }
}

pub(super) fn workflow_interrupt_path(workflow_path: &Path, run_id: &str) -> PathBuf {
    workflow_interrupts_dir(workflow_path).join(format!("{}.json", run_id))
}

pub(super) fn workflow_threads_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".threads"))
    } else {
        workflow_path.with_extension("threads")
    }
}

pub(super) fn workflow_thread_path(workflow_path: &Path, thread_id: &str) -> PathBuf {
    workflow_threads_dir(workflow_path).join(format!("{}.json", thread_id))
}

pub(super) fn workflow_evidence_path(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".evidence.json"))
    } else {
        workflow_path.with_extension("evidence.json")
    }
}

pub(super) fn workflow_binding_manifest_path(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".bindings.json"))
    } else {
        workflow_path.with_extension("bindings.json")
    }
}

pub(super) fn workflow_functions_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".functions"))
    } else {
        workflow_path.with_extension("functions")
    }
}

pub(super) fn workflow_package_default_dir(workflow_path: &Path) -> PathBuf {
    let path_text = workflow_path.display().to_string();
    if path_text.ends_with(".workflow.json") {
        PathBuf::from(path_text.replace(".workflow.json", ".portable"))
    } else {
        workflow_path.with_extension("portable")
    }
}

pub(super) fn workflow_file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("Failed to read '{}': {}", path.display(), error))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn workflow_package_file_record(
    package_dir: &Path,
    role: &str,
    relative_path: &str,
) -> Result<WorkflowPortablePackageFile, String> {
    let file_path = package_dir.join(relative_path);
    let metadata = fs::metadata(&file_path)
        .map_err(|error| format!("Failed to inspect '{}': {}", file_path.display(), error))?;
    Ok(WorkflowPortablePackageFile {
        role: role.to_string(),
        relative_path: relative_path.to_string(),
        bytes: metadata.len(),
        sha256: workflow_file_sha256(&file_path)?,
    })
}

pub(super) fn resolve_workflow_file_path(path: &str) -> Result<PathBuf, String> {
    let requested = PathBuf::from(path);
    let candidate = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|error| format!("Failed to resolve current directory: {}", error))?
            .join(requested)
    };
    if candidate.exists() {
        return candidate.canonicalize().map_err(|error| {
            format!(
                "Failed to canonicalize '{}': {}",
                candidate.display(),
                error
            )
        });
    }
    if let Some(parent) = candidate.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create workflow directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }
    Ok(candidate)
}

pub(super) fn resolve_workflow_reference_path(
    parent_workflow_path: &Path,
    reference: &str,
) -> Result<PathBuf, String> {
    let requested = PathBuf::from(reference);
    if requested.is_absolute() {
        return resolve_workflow_file_path(reference);
    }

    let mut candidates = Vec::new();
    if let Some(parent_dir) = parent_workflow_path.parent() {
        candidates.push(parent_dir.join(&requested));
        if parent_dir.file_name().and_then(|name| name.to_str()) == Some("workflows") {
            if let Some(agents_dir) = parent_dir.parent() {
                if agents_dir.file_name().and_then(|name| name.to_str()) == Some(".agents") {
                    if let Some(project_root) = agents_dir.parent() {
                        candidates.push(project_root.join(&requested));
                    }
                }
            }
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join(&requested));
    }

    for candidate in &candidates {
        if candidate.exists() {
            return candidate.canonicalize().map_err(|error| {
                format!(
                    "Failed to canonicalize workflow reference '{}': {}",
                    candidate.display(),
                    error
                )
            });
        }
    }

    let attempted = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "Workflow reference '{}' was not found relative to parent workflow '{}'. Tried: {}",
        reference,
        parent_workflow_path.display(),
        attempted
    ))
}

pub(super) fn resolve_scoped_existing_path(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, String> {
    let safe_relative = safe_relative_input(relative_path)?;
    let candidate = root.join(&safe_relative);
    let canonical = candidate.canonicalize().map_err(|error| {
        format!(
            "Failed to resolve project path '{}': {}",
            candidate.display(),
            error
        )
    })?;

    if !canonical.starts_with(root) {
        return Err("Resolved path falls outside the project boundary.".to_string());
    }

    Ok(canonical)
}

pub(super) fn safe_relative_input(relative_path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(relative_path);
    if path.as_os_str().is_empty() || relative_path == "." {
        return Ok(PathBuf::new());
    }
    if path.is_absolute() {
        return Err("Absolute paths are not allowed in the project shell.".to_string());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("Path traversal is not allowed in the project shell.".to_string());
    }
    Ok(path)
}

pub(super) fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }
    let json = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, json.as_bytes())
        .map_err(|error| format!("Failed to write '{}': {}", path.display(), error))
}

pub(super) fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read '{}': {}", path.display(), error))?;
    serde_json::from_str(&content)
        .map_err(|error| format!("Failed to parse '{}': {}", path.display(), error))
}
