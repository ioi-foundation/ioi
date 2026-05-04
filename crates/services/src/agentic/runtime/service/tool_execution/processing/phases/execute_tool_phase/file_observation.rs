use crate::agentic::runtime::execution::filesystem::resolve_tool_path;
use crate::agentic::runtime::service::tool_execution::{
    execution_evidence_value, record_execution_evidence_with_value,
};
use crate::agentic::runtime::types::ToolCallStatus;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkspaceFileObservation {
    pub step_index: u32,
    pub tool_name: String,
    pub requested_path: String,
    pub canonical_path: String,
    pub content_hash: String,
    pub mtime_ms: u128,
    pub size: u64,
}

pub(crate) fn record_file_read_observation(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    working_directory: &str,
    tool: &AgentTool,
    step_index: u32,
) -> Option<WorkspaceFileObservation> {
    let (tool_name, requested_path) = read_tool_path(tool)?;
    let observation =
        observe_file(tool_name, requested_path, working_directory, step_index).ok()?;
    let key = observation_key(&observation.canonical_path);
    let value = serde_json::to_string(&observation).ok()?;
    record_execution_evidence_with_value(tool_execution_log, &key, value);
    Some(observation)
}

pub(crate) fn enforce_file_write_observation(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    working_directory: &str,
    tool: &AgentTool,
    step_index: u32,
) -> Result<Option<String>, String> {
    let Some((tool_name, requested_path)) = mutation_tool_path(tool) else {
        return Ok(None);
    };
    let resolved = resolve_tool_path(requested_path, Some(working_directory))?;
    if fs::symlink_metadata(&resolved)
        .map(|metadata| !metadata.file_type().is_file() || metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Ok(None);
    }
    if !resolved.exists() {
        return Ok(Some(format!(
            "step={step_index};tool={tool_name};path={requested_path};new_file_intent=true"
        )));
    }

    let current = observe_file(tool_name, requested_path, working_directory, step_index)?;
    let key = observation_key(&current.canonical_path);
    let Some(raw_observation) = execution_evidence_value(tool_execution_log, &key) else {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to mutate {}: existing file has no matching read observation. Use `file__read` or `file__view` first so the runtime can bind the edit to observed content.",
            current.canonical_path
        ));
    };
    let prior: WorkspaceFileObservation =
        serde_json::from_str(raw_observation).map_err(|error| {
            format!(
                "ERROR_CLASS=DeterminismBoundary Refusing to mutate {}: prior read observation is malformed: {}",
                current.canonical_path, error
            )
        })?;

    if prior.content_hash != current.content_hash {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing stale write to {}: content hash changed since read (observed {}, current {}). Reread the file before editing.",
            current.canonical_path, prior.content_hash, current.content_hash
        ));
    }

    Ok(Some(format!(
        "step={step_index};tool={tool_name};path={};observed_step={};content_hash={};mtime_changed={}",
        current.canonical_path,
        prior.step_index,
        current.content_hash,
        prior.mtime_ms != current.mtime_ms
    )))
}

fn read_tool_path(tool: &AgentTool) -> Option<(&'static str, &str)> {
    match tool {
        AgentTool::FsRead { path } => Some(("file__read", path.as_str())),
        AgentTool::FsView { path, .. } => Some(("file__view", path.as_str())),
        _ => None,
    }
}

fn mutation_tool_path(tool: &AgentTool) -> Option<(&'static str, &str)> {
    match tool {
        AgentTool::FsWrite { path, .. } => {
            let tool_name = "file__write";
            Some((tool_name, path.as_str()))
        }
        AgentTool::FsPatch { path, .. } => Some(("file__edit", path.as_str())),
        AgentTool::FsMultiPatch { path, .. } => Some(("file__multi_edit", path.as_str())),
        _ => None,
    }
}

fn observe_file(
    tool_name: &str,
    requested_path: &str,
    working_directory: &str,
    step_index: u32,
) -> Result<WorkspaceFileObservation, String> {
    let resolved = resolve_tool_path(requested_path, Some(working_directory))?;
    let canonical = fs::canonicalize(&resolved)
        .map_err(|error| format!("Failed to canonicalize {}: {}", resolved.display(), error))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("Failed to inspect {}: {}", canonical.display(), error))?;
    let bytes = fs::read(&canonical)
        .map_err(|error| format!("Failed to hash {}: {}", canonical.display(), error))?;
    let content_hash = sha256(&bytes)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .map_err(|error| format!("Failed to hash {}: {}", canonical.display(), error))?;
    let mtime_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    Ok(WorkspaceFileObservation {
        step_index,
        tool_name: tool_name.to_string(),
        requested_path: requested_path.to_string(),
        canonical_path: canonical.to_string_lossy().to_string(),
        content_hash,
        mtime_ms,
        size: metadata.len(),
    })
}

fn observation_key(canonical_path: &str) -> String {
    let digest = sha256(canonical_path.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "unavailable".to_string());
    format!("workspace_read_observed:{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ioi-file-observation-{label}-{nonce}"));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    fn write_tool(path: &str) -> AgentTool {
        AgentTool::FsWrite {
            path: path.to_string(),
            content: "updated".to_string(),
            line_number: None,
        }
    }

    #[test]
    fn existing_file_write_requires_prior_read_observation() {
        let dir = make_temp_dir("requires-read");
        fs::write(dir.join("a.txt"), "before").expect("fixture write");
        let log = BTreeMap::new();

        let error = enforce_file_write_observation(
            &log,
            dir.to_string_lossy().as_ref(),
            &write_tool("a.txt"),
            2,
        )
        .expect_err("existing write without read must be blocked");

        assert!(error.contains("no matching read observation"));
    }

    #[test]
    fn new_file_write_is_explicit_create_intent_without_prior_read() {
        let dir = make_temp_dir("new-file");
        let log = BTreeMap::new();

        let evidence = enforce_file_write_observation(
            &log,
            dir.to_string_lossy().as_ref(),
            &write_tool("new.txt"),
            2,
        )
        .expect("new file should not need read observation")
        .expect("new file evidence should be returned");

        assert!(evidence.contains("new_file_intent=true"));
    }

    #[test]
    fn write_after_read_allows_same_content_hash() {
        let dir = make_temp_dir("same-hash");
        fs::write(dir.join("a.txt"), "before").expect("fixture write");
        let mut log = BTreeMap::new();
        record_file_read_observation(
            &mut log,
            dir.to_string_lossy().as_ref(),
            &AgentTool::FsRead {
                path: "a.txt".to_string(),
            },
            1,
        )
        .expect("read observation should record");
        fs::write(dir.join("a.txt"), "before").expect("same content rewrite");

        let evidence = enforce_file_write_observation(
            &log,
            dir.to_string_lossy().as_ref(),
            &write_tool("a.txt"),
            2,
        )
        .expect("same content should pass")
        .expect("guard evidence should be returned");

        assert!(evidence.contains("content_hash=sha256:"));
    }

    #[test]
    fn write_after_read_blocks_changed_content_hash() {
        let dir = make_temp_dir("stale-hash");
        fs::write(dir.join("a.txt"), "before").expect("fixture write");
        let mut log = BTreeMap::new();
        record_file_read_observation(
            &mut log,
            dir.to_string_lossy().as_ref(),
            &AgentTool::FsRead {
                path: "a.txt".to_string(),
            },
            1,
        )
        .expect("read observation should record");
        fs::write(dir.join("a.txt"), "external change").expect("external change");

        let error = enforce_file_write_observation(
            &log,
            dir.to_string_lossy().as_ref(),
            &write_tool("a.txt"),
            2,
        )
        .expect_err("stale write must be blocked");

        assert!(error.contains("stale write"));
    }
}
