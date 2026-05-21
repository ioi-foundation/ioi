// apps/autopilot/src-tauri/src/project/workflow_package_lane.rs

use super::workflow_value_helpers::{
    workflow_logic_string, workflow_project_root_for_path, workflow_value_at_path,
};
use super::*;

fn workflow_deep_string_field(value: &Value, key: &str) -> Option<String> {
    if let Some(text) = value
        .get(key)
        .and_then(Value::as_str)
        .filter(|item| !item.trim().is_empty())
    {
        return Some(text.to_string());
    }
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| workflow_deep_string_field(item, key)),
        Value::Object(object) => object
            .values()
            .find_map(|item| workflow_deep_string_field(item, key)),
        _ => None,
    }
}

fn workflow_resolved_path_string(
    logic: &Value,
    input: &Value,
    key: &str,
    workflow_path: &Path,
) -> Option<String> {
    let configured = workflow_logic_string(logic, key);
    match configured.as_deref() {
        Some("{{workflow.path}}") => Some(workflow_path.display().to_string()),
        Some("{{project.root}}") => Some(workflow_project_root_for_path(workflow_path)),
        Some("{{workflowPackageExport.packagePath}}") => {
            workflow_value_at_path(input, "workflowPackageExport.packagePath")
                .and_then(|value| value.as_str().map(str::to_string))
                .or_else(|| workflow_deep_string_field(input, "packagePath"))
        }
        Some(value) if value.starts_with("{{") && value.ends_with("}}") => None,
        Some(value) => Some(value.to_string()),
        None => None,
    }
}

pub(super) fn execute_workflow_package_export_node(
    workflow_path: &Path,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Result<Value, String> {
    let path = workflow_resolved_path_string(logic, input, "workflowPackagePath", workflow_path)
        .unwrap_or_else(|| workflow_path.display().to_string());
    let output_dir =
        workflow_resolved_path_string(logic, input, "workflowPackageOutputDir", workflow_path);
    if logic
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({
            "schemaVersion": "workflow.package-export.output.v1",
            "status": "dry_run",
            "toolName": "workflow.package.export",
            "nodeId": node_id,
            "kind": evidence_kind,
            "workflowPath": path,
            "packagePath": output_dir,
            "portable": false,
            "readinessStatus": "dry_run",
            "workflowChromeLocale": Value::Null,
            "packageEvidenceReady": false,
            "mutationExecuted": false,
            "input": input
        }));
    }
    let package = export_workflow_package(path.clone(), output_dir)?;
    let package_evidence_ready = package.manifest.harness_package_manifest.is_some();
    let package_path = package.package_path.clone();
    let manifest_path = package.manifest_path.clone();
    let manifest = package.manifest.clone();
    Ok(json!({
        "schemaVersion": "workflow.package-export.output.v1",
        "status": if manifest.portable { "ok" } else { "blocked" },
        "toolName": "workflow.package.export",
        "nodeId": node_id,
        "kind": evidence_kind,
        "workflowPath": path,
        "packagePath": package_path,
        "manifestPath": manifest_path,
        "manifest": manifest.clone(),
        "portable": manifest.portable,
        "readinessStatus": manifest.readiness_status,
        "workflowChromeLocale": manifest.workflow_chrome_locale,
        "packageEvidenceReady": package_evidence_ready,
        "mutationExecuted": true,
        "workflowPackageExport": package,
        "input": input
    }))
}

pub(super) fn execute_workflow_package_import_node(
    workflow_path: &Path,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Result<Value, String> {
    let package_path =
        workflow_resolved_path_string(logic, input, "workflowPackagePath", workflow_path)
            .or_else(|| workflow_deep_string_field(input, "packagePath"))
            .ok_or_else(|| "Workflow package import requires a package path.".to_string())?;
    let project_root =
        workflow_resolved_path_string(logic, input, "workflowPackageProjectRoot", workflow_path)
            .unwrap_or_else(|| workflow_project_root_for_path(workflow_path));
    let import_name = workflow_logic_string(logic, "workflowPackageImportName");
    if logic
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({
            "schemaVersion": "workflow.package-import.output.v1",
            "status": "dry_run",
            "toolName": "workflow.package.import",
            "nodeId": node_id,
            "kind": evidence_kind,
            "packagePath": package_path,
            "projectRoot": project_root,
            "importedWorkflowPath": Value::Null,
            "packageEvidenceReady": false,
            "workflowChromeLocalePreserved": false,
            "mutationExecuted": false,
            "input": input
        }));
    }
    let imported = import_workflow_package(ImportWorkflowPackageRequest {
        package_path: package_path.clone(),
        project_root: project_root.clone(),
        name: import_name,
    })?;
    let imported_package = imported.imported_package.clone();
    let imported_workflow_path = imported.workflow_path.clone();
    let manifest = imported_package
        .as_ref()
        .map(|package| package.manifest.clone());
    let source_workflow_chrome_locale = manifest
        .as_ref()
        .and_then(|item| item.workflow_chrome_locale.clone());
    let imported_workflow_chrome_locale = imported
        .workflow
        .global_config
        .get("workflowChromeLocale")
        .and_then(Value::as_str)
        .map(str::to_string);
    let workflow_chrome_locale_preserved =
        source_workflow_chrome_locale == imported_workflow_chrome_locale;
    let package_evidence_ready = manifest
        .as_ref()
        .and_then(|item| item.harness_package_manifest.as_ref())
        .is_some();
    let review = json!({
        "schemaVersion": "workflow.package-import-review.v1",
        "source": {
            "packagePath": package_path.clone(),
            "workflowChromeLocale": source_workflow_chrome_locale.clone(),
            "readinessStatus": manifest
                .as_ref()
                .map(|item| item.readiness_status.clone())
                .unwrap_or_else(|| "unknown".to_string())
        },
        "imported": {
            "workflowPath": imported_workflow_path.clone(),
            "workflowChromeLocale": imported_workflow_chrome_locale.clone()
        },
        "evidence": {
            "packageEvidenceReady": package_evidence_ready,
            "workflowChromeLocalePreserved": workflow_chrome_locale_preserved
        }
    });
    Ok(json!({
        "schemaVersion": "workflow.package-import.output.v1",
        "status": "ok",
        "toolName": "workflow.package.import",
        "nodeId": node_id,
        "kind": evidence_kind,
        "packagePath": package_path,
        "projectRoot": project_root,
        "importedWorkflowPath": imported_workflow_path,
        "review": review.clone(),
        "packageEvidenceReady": package_evidence_ready,
        "workflowChromeLocalePreserved": workflow_chrome_locale_preserved,
        "sourceWorkflowChromeLocale": source_workflow_chrome_locale,
        "importedWorkflowChromeLocale": imported_workflow_chrome_locale,
        "mutationExecuted": true,
        "workflowPackageImport": {
            "workflowPath": imported.workflow_path,
            "importedPackage": imported_package
        },
        "workflowPackageImportReview": review,
        "input": input
    }))
}
