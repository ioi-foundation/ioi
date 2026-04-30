use super::explorer::sort_paths;
use super::ids::now_ms;
use super::paths::workflow_package_file_record;
use super::types::{WorkflowPortablePackageFile, WorkflowPortablePackageManifest, WorkflowProject};
use super::{workflow_node_id, workflow_node_logic, workflow_node_name, workflow_node_type};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn workflow_package_copy_file(
    source_path: &Path,
    package_dir: &Path,
    relative_path: &str,
    role: &str,
    files: &mut Vec<WorkflowPortablePackageFile>,
) -> Result<(), String> {
    if !source_path.exists() {
        return Ok(());
    }
    let target_path = package_dir.join(relative_path);
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create package directory '{}': {}",
                parent.display(),
                error
            )
        })?;
    }
    fs::copy(source_path, &target_path).map_err(|error| {
        format!(
            "Failed to copy '{}' to '{}': {}",
            source_path.display(),
            target_path.display(),
            error
        )
    })?;
    files.push(workflow_package_file_record(
        package_dir,
        role,
        relative_path,
    )?);
    Ok(())
}

pub(super) fn workflow_package_copy_dir(
    source_dir: &Path,
    package_dir: &Path,
    package_relative_dir: &str,
    role: &str,
    files: &mut Vec<WorkflowPortablePackageFile>,
) -> Result<(), String> {
    if !source_dir.exists() {
        return Ok(());
    }
    let mut stack = vec![source_dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let mut entries = fs::read_dir(&current)
            .map_err(|error| format!("Failed to read '{}': {}", current.display(), error))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect::<Vec<_>>();
        entries.sort_by(sort_paths);
        for entry in entries {
            if entry.is_dir() {
                stack.push(entry);
                continue;
            }
            let rel = entry
                .strip_prefix(source_dir)
                .map_err(|error| format!("Failed to relativize package file: {}", error))?;
            let package_rel = Path::new(package_relative_dir).join(rel);
            let package_rel_text = package_rel.to_string_lossy().replace('\\', "/");
            workflow_package_copy_file(&entry, package_dir, &package_rel_text, role, files)?;
        }
    }
    Ok(())
}

pub(super) fn workflow_policy_manifest(workflow: &WorkflowProject) -> Value {
    let policies = workflow
        .nodes
        .iter()
        .filter_map(|node| {
            let node_id = workflow_node_id(node)?;
            let node_type = workflow_node_type(node);
            let logic = workflow_node_logic(node);
            let binding = logic
                .get("toolBinding")
                .or_else(|| logic.get("connectorBinding"))
                .or_else(|| logic.get("deliveryTarget"));
            let side_effect_class = binding
                .and_then(|value| value.get("sideEffectClass"))
                .and_then(Value::as_str)
                .unwrap_or("none");
            let requires_approval = binding
                .and_then(|value| value.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let sandbox = logic
                .get("functionBinding")
                .and_then(|binding| binding.get("sandboxPolicy"))
                .cloned()
                .unwrap_or(Value::Null);
            (side_effect_class != "none" || requires_approval || !sandbox.is_null()).then(|| {
                json!({
                    "nodeId": node_id,
                    "nodeType": node_type,
                    "sideEffectClass": side_effect_class,
                    "requiresApproval": requires_approval,
                    "sandboxPolicy": sandbox
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": "workflow.policy-manifest.v1",
        "generatedAtMs": now_ms(),
        "policies": policies
    })
}

pub(super) fn workflow_output_manifest(workflow: &WorkflowProject) -> Value {
    let outputs = workflow
        .nodes
        .iter()
        .filter(|node| workflow_node_type(node) == "output")
        .map(|node| {
            let logic = workflow_node_logic(node);
            json!({
                "nodeId": workflow_node_id(node).unwrap_or_else(|| "unknown-output".to_string()),
                "name": workflow_node_name(node),
                "format": logic.get("format").cloned().unwrap_or_else(|| json!("summary")),
                "rendererRef": logic.get("rendererRef").cloned().unwrap_or(Value::Null),
                "deliveryTarget": logic.get("deliveryTarget").cloned().unwrap_or(Value::Null),
                "materialization": logic.get("materialization").cloned().unwrap_or(Value::Null)
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": "workflow.output-manifest.v1",
        "generatedAtMs": now_ms(),
        "outputs": outputs
    })
}

pub(super) fn workflow_package_manifest_file<'a>(
    manifest: &'a WorkflowPortablePackageManifest,
    role: &str,
) -> Option<&'a WorkflowPortablePackageFile> {
    manifest.files.iter().find(|file| file.role == role)
}

pub(super) fn workflow_package_dir_from_request(path: &str) -> Result<PathBuf, String> {
    let requested = PathBuf::from(path);
    let package_path = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|error| format!("Failed to resolve current directory: {}", error))?
            .join(requested)
    };
    let dir = if package_path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value == "manifest.json")
        .unwrap_or(false)
    {
        package_path
            .parent()
            .ok_or_else(|| "Package manifest must have a parent directory.".to_string())?
            .to_path_buf()
    } else {
        package_path
    };
    if !dir.exists() {
        return Err(format!(
            "Workflow package '{}' does not exist.",
            dir.display()
        ));
    }
    Ok(dir.canonicalize().unwrap_or(dir))
}

pub(super) fn rewrite_workflow_function_refs(
    workflow: &mut WorkflowProject,
    target_functions_dir: &Path,
) {
    for node in &mut workflow.nodes {
        if workflow_node_type(node) != "function" {
            continue;
        }
        let Some(logic) = node
            .get_mut("config")
            .and_then(|config| config.get_mut("logic"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let Some(binding) = logic
            .get_mut("functionBinding")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let Some(function_ref) = binding
            .get_mut("functionRef")
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let Some(source_path) = function_ref
            .get("sourcePath")
            .and_then(Value::as_str)
            .and_then(|value| Path::new(value).file_name())
            .and_then(|value| value.to_str())
        else {
            continue;
        };
        function_ref.insert(
            "sourcePath".to_string(),
            Value::String(target_functions_dir.join(source_path).display().to_string()),
        );
    }
}
