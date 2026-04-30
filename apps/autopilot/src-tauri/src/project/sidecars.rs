use super::explorer::sort_paths;
use super::paths::*;
use super::types::{
    WorkflowBindingManifest, WorkflowCheckpoint, WorkflowEvidenceSummary, WorkflowNodeFixture,
    WorkflowProposal, WorkflowRunResult, WorkflowRunSummary, WorkflowStateSnapshot,
    WorkflowTestCase, WorkflowThread,
};
use std::fs;
use std::path::Path;

pub(super) fn load_workflow_tests(path: &Path) -> Result<Vec<WorkflowTestCase>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_json_file(path)
}

pub(super) fn load_workflow_node_fixtures_from_path(
    path: &Path,
) -> Result<Vec<WorkflowNodeFixture>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_json_file(path)
}

pub(super) fn load_workflow_proposals(path: &Path) -> Result<Vec<WorkflowProposal>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut proposals = Vec::new();
    let mut entries = fs::read_dir(path)
        .map_err(|error| format!("Failed to read proposals '{}': {}", path.display(), error))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|entry| {
            entry
                .extension()
                .and_then(|value| value.to_str())
                .map(|extension| extension == "json")
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by(sort_paths);
    for proposal_path in entries {
        proposals.push(read_json_file(&proposal_path)?);
    }
    Ok(proposals)
}

pub(super) fn load_workflow_runs(path: &Path) -> Result<Vec<WorkflowRunSummary>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if !path.is_dir() {
        return Err(format!(
            "Workflow run sidecar path '{}' is not a directory.",
            path.display()
        ));
    }
    let mut run_paths = fs::read_dir(path)
        .map_err(|error| {
            format!(
                "Failed to read workflow runs '{}': {}",
                path.display(),
                error
            )
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|entry| {
            entry
                .extension()
                .and_then(|value| value.to_str())
                .map(|extension| extension == "json")
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    run_paths.sort_by(sort_paths);
    let mut runs = Vec::new();
    for run_path in run_paths {
        let result: WorkflowRunResult = read_json_file(&run_path)?;
        runs.push(result.summary);
    }
    runs.sort_by(|left, right| right.started_at_ms.cmp(&left.started_at_ms));
    Ok(runs)
}

pub(super) fn ensure_workflow_runtime_dirs(workflow_path: &Path) -> Result<(), String> {
    for path in [
        workflow_runs_path(workflow_path),
        workflow_checkpoints_dir(workflow_path),
        workflow_interrupts_dir(workflow_path),
        workflow_threads_dir(workflow_path),
    ] {
        fs::create_dir_all(&path)
            .map_err(|error| format!("Failed to create '{}': {}", path.display(), error))?;
    }
    Ok(())
}

pub(super) fn save_workflow_run_result(
    workflow_path: &Path,
    result: &WorkflowRunResult,
) -> Result<(), String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    write_json_pretty(
        &workflow_run_result_path(workflow_path, &result.summary.id),
        result,
    )
}

pub(super) fn load_workflow_run_result(
    workflow_path: &Path,
    run_id: &str,
) -> Result<WorkflowRunResult, String> {
    read_json_file(&workflow_run_result_path(workflow_path, run_id))
}

pub(super) fn save_workflow_thread(
    workflow_path: &Path,
    thread: &WorkflowThread,
) -> Result<(), String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    write_json_pretty(&workflow_thread_path(workflow_path, &thread.id), thread)
}

pub(super) fn load_workflow_thread(
    workflow_path: &Path,
    thread_id: &str,
) -> Result<WorkflowThread, String> {
    read_json_file(&workflow_thread_path(workflow_path, thread_id))
}

pub(super) fn save_workflow_checkpoint(
    workflow_path: &Path,
    checkpoint: &WorkflowCheckpoint,
    state: &WorkflowStateSnapshot,
) -> Result<(), String> {
    let dir = workflow_thread_checkpoints_dir(workflow_path, &checkpoint.thread_id);
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Failed to create '{}': {}", dir.display(), error))?;
    write_json_pretty(
        &dir.join(format!("{}.json", checkpoint.id)),
        &(checkpoint, state),
    )
}

pub(super) fn load_workflow_checkpoint_record(
    workflow_path: &Path,
    checkpoint_id: &str,
) -> Result<(WorkflowCheckpoint, WorkflowStateSnapshot), String> {
    let base_dir = workflow_checkpoints_dir(workflow_path);
    if !base_dir.exists() {
        return Err(format!("Unknown workflow checkpoint '{}'.", checkpoint_id));
    }
    for thread_entry in fs::read_dir(&base_dir).map_err(|error| {
        format!(
            "Failed to read checkpoints '{}': {}",
            base_dir.display(),
            error
        )
    })? {
        let thread_dir = thread_entry
            .map_err(|error| format!("Failed to read checkpoint entry: {}", error))?
            .path();
        if !thread_dir.is_dir() {
            continue;
        }
        let path = thread_dir.join(format!("{}.json", checkpoint_id));
        if path.exists() {
            return read_json_file(&path);
        }
    }
    Err(format!("Unknown workflow checkpoint '{}'.", checkpoint_id))
}

pub(super) fn load_workflow_checkpoints_for_thread(
    workflow_path: &Path,
    thread_id: &str,
) -> Result<Vec<WorkflowCheckpoint>, String> {
    let dir = workflow_thread_checkpoints_dir(workflow_path, thread_id);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(&dir)
        .map_err(|error| format!("Failed to read checkpoints '{}': {}", dir.display(), error))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|entry| {
            entry
                .extension()
                .and_then(|value| value.to_str())
                .map(|extension| extension == "json")
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    paths.sort_by(sort_paths);
    let mut checkpoints = Vec::new();
    for path in paths {
        let (checkpoint, _state): (WorkflowCheckpoint, WorkflowStateSnapshot) =
            read_json_file(&path)?;
        checkpoints.push(checkpoint);
    }
    checkpoints.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    Ok(checkpoints)
}

pub(super) fn load_workflow_evidence(path: &Path) -> Result<Vec<WorkflowEvidenceSummary>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_json_file(path)
}

pub(super) fn load_workflow_binding_manifest_sidecar(
    path: &Path,
) -> Result<Option<WorkflowBindingManifest>, String> {
    if !path.exists() {
        return Ok(None);
    }
    read_json_file(path).map(Some)
}

pub(super) fn save_workflow_binding_manifest(
    workflow_path: &Path,
    manifest: &WorkflowBindingManifest,
) -> Result<(), String> {
    write_json_pretty(&workflow_binding_manifest_path(workflow_path), manifest)
}

pub(super) fn append_workflow_evidence(
    workflow_path: &Path,
    evidence: WorkflowEvidenceSummary,
) -> Result<(), String> {
    let evidence_path = workflow_evidence_path(workflow_path);
    let mut entries = load_workflow_evidence(&evidence_path)?;
    entries.insert(0, evidence);
    write_json_pretty(&evidence_path, &entries)
}
