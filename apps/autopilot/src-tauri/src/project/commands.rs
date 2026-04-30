// apps/autopilot/src-tauri/src/project/commands.rs

use super::*;

#[tauri::command]
pub fn save_project(path: String, project: ProjectFile) -> Result<(), String> {
    // 1. Enforce versioning
    let mut final_project = project;
    final_project.version = "1.0.0".to_string();

    // 2. Update metadata
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Some(ref mut meta) = final_project.metadata {
        meta.last_modified = now;
    } else {
        final_project.metadata = Some(ProjectMetadata {
            name: std::path::Path::new(&path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Untitled")
                .to_string(),
            created_at: now,
            last_modified: now,
            author: None,
        });
    }

    let json = serde_json::to_string_pretty(&final_project).map_err(|e| e.to_string())?;

    // 3. Ensure directory exists
    let path_buf = PathBuf::from(&path);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // 4. Atomic Write (Write to .tmp then rename)
    let temp_path = format!("{}.tmp", path);
    let mut file = fs::File::create(&temp_path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;

    // Sync to disk to ensure data is flushed
    file.sync_all().map_err(|e| e.to_string())?;

    // Rename to overwrite target
    fs::rename(temp_path, path).map_err(|e| e.to_string())?;

    println!("[Project] Saved successfully to {}", path_buf.display());
    Ok(())
}

#[tauri::command]
pub fn load_project(path: String) -> Result<ProjectFile, String> {
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let project: ProjectFile = serde_json::from_str(&content).map_err(|e| e.to_string())?;

    // Basic validation
    if project.nodes.is_empty() && project.global_config.is_none() {
        println!("[Project] Warning: Loaded empty project from {}", path);
    } else {
        println!(
            "[Project] Loaded {} nodes from {}",
            project.nodes.len(),
            path
        );
    }

    Ok(project)
}

#[tauri::command]
pub fn list_workflow_projects(project_root: String) -> Result<Vec<WorkflowProjectSummary>, String> {
    let root_path = resolve_root_path(&project_root, true)?;
    let workflows_dir = workflow_base_dir(&root_path);
    if !workflows_dir.exists() {
        return Ok(Vec::new());
    }

    let git = inspect_git(&root_path);
    let mut entries = fs::read_dir(&workflows_dir)
        .map_err(|error| {
            format!(
                "Failed to read workflow directory '{}': {}",
                workflows_dir.display(),
                error
            )
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(|name| name.ends_with(".workflow.json"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    entries.sort_by(sort_paths);

    entries
        .into_iter()
        .map(|path| {
            let mut workflow: WorkflowProject = read_json_file(&path)?;
            normalize_legacy_workflow_output_nodes(&mut workflow);
            let tests_path = workflow_tests_path(&path);
            let proposals_dir = workflow_proposals_dir(&path);
            Ok(WorkflowProjectSummary {
                id: workflow.metadata.id,
                name: workflow.metadata.name,
                slug: workflow.metadata.slug,
                workflow_kind: workflow.metadata.workflow_kind,
                execution_mode: workflow.metadata.execution_mode,
                workflow_path: path.display().to_string(),
                tests_path: tests_path.display().to_string(),
                proposals_dir: proposals_dir.display().to_string(),
                node_count: workflow.nodes.len(),
                updated_at_ms: workflow.metadata.updated_at_ms,
                branch: git.branch.clone(),
                dirty: Some(git.dirty),
            })
        })
        .collect()
}

#[tauri::command]
pub fn create_workflow_project(
    request: CreateWorkflowProjectRequest,
) -> Result<WorkflowWorkbenchBundle, String> {
    let root_path = resolve_root_path(&request.project_root, true)?;
    let workflows_dir = workflow_base_dir(&root_path);
    fs::create_dir_all(&workflows_dir).map_err(|error| {
        format!(
            "Failed to create workflow directory '{}': {}",
            workflows_dir.display(),
            error
        )
    })?;

    let slug = slugify_workflow_name(&request.name);
    let workflow_path = workflows_dir.join(format!("{}.workflow.json", slug));
    let tests_path = workflow_tests_path(&workflow_path);
    let proposals_dir = workflow_proposals_dir(&workflow_path);
    fs::create_dir_all(&proposals_dir).map_err(|error| {
        format!(
            "Failed to create proposals directory '{}': {}",
            proposals_dir.display(),
            error
        )
    })?;

    let (workflow, tests) = if let Some(template_id) = request.template_id.as_deref() {
        workflow_project_from_template(template_id, Some(&request.name), &workflow_path)?
    } else {
        (
            default_workflow_project(
                &request.name,
                &request.workflow_kind,
                &request.execution_mode,
                &workflow_path,
            ),
            default_workflow_tests(),
        )
    };
    write_json_pretty(&workflow_path, &workflow)?;
    write_json_pretty(&tests_path, &tests)?;
    ensure_workflow_runtime_dirs(&workflow_path)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("bundle-{}", now_ms()),
            kind: "bundle".to_string(),
            created_at_ms: now_ms(),
            summary: "Workflow bundle created through typed runtime API.".to_string(),
            path: Some(workflow_path.display().to_string()),
        },
    )?;

    Ok(WorkflowWorkbenchBundle {
        workflow_path: workflow_path.display().to_string(),
        tests_path: tests_path.display().to_string(),
        proposals_dir: proposals_dir.display().to_string(),
        workflow,
        tests,
        proposals: Vec::new(),
        runs: Vec::new(),
    })
}

#[tauri::command]
pub fn create_workflow_from_template(
    request: CreateWorkflowFromTemplateRequest,
) -> Result<WorkflowWorkbenchBundle, String> {
    let root_path = resolve_root_path(&request.project_root, true)?;
    let workflows_dir = workflow_base_dir(&root_path);
    fs::create_dir_all(&workflows_dir).map_err(|error| {
        format!(
            "Failed to create workflow directory '{}': {}",
            workflows_dir.display(),
            error
        )
    })?;
    let default_name = template_workflow_seed(&request.template_id)
        .map(|(name, _, _, _, _, _)| name)
        .ok_or_else(|| format!("Unknown workflow template '{}'.", request.template_id))?;
    let name = request.name.as_deref().unwrap_or(default_name);
    let slug = slugify_workflow_name(name);
    let workflow_path = workflows_dir.join(format!("{}.workflow.json", slug));
    let tests_path = workflow_tests_path(&workflow_path);
    let proposals_dir = workflow_proposals_dir(&workflow_path);
    fs::create_dir_all(&proposals_dir).map_err(|error| {
        format!(
            "Failed to create proposals directory '{}': {}",
            proposals_dir.display(),
            error
        )
    })?;

    let (workflow, tests) =
        workflow_project_from_template(&request.template_id, Some(name), &workflow_path)?;
    write_json_pretty(&workflow_path, &workflow)?;
    write_json_pretty(&tests_path, &tests)?;
    ensure_workflow_runtime_dirs(&workflow_path)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("template-{}", now_ms()),
            kind: "bundle".to_string(),
            created_at_ms: now_ms(),
            summary: format!("Workflow template '{}' instantiated.", request.template_id),
            path: Some(workflow_path.display().to_string()),
        },
    )?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn load_workflow_bundle(path: String) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn save_workflow_project(path: String, mut workflow: WorkflowProject) -> Result<(), String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    normalize_legacy_workflow_output_nodes(&mut workflow);
    workflow.version = "workflow.v1".to_string();
    workflow.metadata.updated_at_ms = Some(now_ms());
    workflow.metadata.dirty = Some(false);
    write_json_pretty(&workflow_path, &workflow)
}

#[tauri::command]
pub fn save_workflow_tests(path: String, tests: Vec<WorkflowTestCase>) -> Result<(), String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let tests_path = workflow_tests_path(&workflow_path);
    write_json_pretty(&tests_path, &tests)
}

#[derive(Debug, Clone)]
struct WorkflowBindingInspection {
    row_id: String,
    node_id: String,
    node_name: String,
    node_type: String,
    binding_kind: String,
    reference: String,
    mode: String,
    ready: bool,
    mock_binding: bool,
    credential_ready: bool,
    side_effect_class: String,
    requires_approval: bool,
    capability_scope: Vec<String>,
}

fn workflow_binding_bool(binding: &Value, key: &str, default_value: bool) -> bool {
    binding
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(default_value)
}

fn workflow_binding_text(binding: &Value, key: &str) -> Option<String> {
    binding
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn workflow_binding_string_array(binding: &Value, key: &str, fallback: &[&str]) -> Vec<String> {
    let values = binding
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty());
    values.unwrap_or_else(|| fallback.iter().map(|value| value.to_string()).collect())
}

fn workflow_binding_side_effect(binding: &Value, default_value: &str) -> String {
    workflow_binding_text(binding, "sideEffectClass").unwrap_or_else(|| default_value.to_string())
}

fn workflow_binding_inspections(
    workflow: &WorkflowProject,
    node: &Value,
) -> Vec<WorkflowBindingInspection> {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown-node".to_string());
    let node_type = workflow_node_type(node);
    let node_name = workflow_node_name(node);
    let logic = workflow_node_logic(node);
    let mut rows = Vec::new();

    if node_type == "model_call" {
        if let Some(binding) = logic.get("modelBinding") {
            let mock_binding = workflow_binding_bool(binding, "mockBinding", false);
            let credential_ready = workflow_binding_bool(binding, "credentialReady", false);
            let model_ref =
                workflow_binding_text(binding, "modelRef").unwrap_or_else(|| "model".to_string());
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-model", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: "Model".to_string(),
                reference: model_ref,
                mode: if mock_binding { "mock" } else { "live" }.to_string(),
                ready: mock_binding || credential_ready,
                mock_binding,
                credential_ready,
                side_effect_class: workflow_binding_side_effect(binding, "none"),
                requires_approval: workflow_binding_bool(binding, "requiresApproval", false),
                capability_scope: workflow_binding_string_array(
                    binding,
                    "capabilityScope",
                    &["reasoning"],
                ),
            });
        } else {
            let model_ref = logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("reasoning");
            let global_binding = workflow
                .global_config
                .get("modelBindings")
                .and_then(|bindings| bindings.get(model_ref));
            let model_id = global_binding
                .and_then(|binding| binding.get("modelId"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty());
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-global-model", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: "Model".to_string(),
                reference: model_id.unwrap_or(model_ref).to_string(),
                mode: if model_id.is_some() { "live" } else { "local" }.to_string(),
                ready: model_id.is_some()
                    || workflow_has_incoming_connection_class(workflow, &node_id, "model"),
                mock_binding: false,
                credential_ready: model_id.is_some(),
                side_effect_class: "none".to_string(),
                requires_approval: false,
                capability_scope: vec![model_ref.to_string()],
            });
        }
    }

    if node_type == "model_binding" {
        if let Some(binding) = logic.get("modelBinding") {
            let mock_binding = workflow_binding_bool(binding, "mockBinding", false);
            let credential_ready = workflow_binding_bool(binding, "credentialReady", false);
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-model-binding", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: "Model".to_string(),
                reference: workflow_binding_text(binding, "modelRef")
                    .unwrap_or_else(|| "model".to_string()),
                mode: if mock_binding { "mock" } else { "live" }.to_string(),
                ready: mock_binding || credential_ready,
                mock_binding,
                credential_ready,
                side_effect_class: workflow_binding_side_effect(binding, "none"),
                requires_approval: workflow_binding_bool(binding, "requiresApproval", false),
                capability_scope: workflow_binding_string_array(
                    binding,
                    "capabilityScope",
                    &["reasoning"],
                ),
            });
        }
    }

    if node_type == "adapter" {
        if let Some(binding) = logic.get("connectorBinding") {
            let mock_binding = workflow_binding_bool(binding, "mockBinding", false);
            let credential_ready = workflow_binding_bool(binding, "credentialReady", false);
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-connector", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: "Connector".to_string(),
                reference: workflow_binding_text(binding, "connectorRef")
                    .unwrap_or_else(|| "connector".to_string()),
                mode: if mock_binding { "mock" } else { "live" }.to_string(),
                ready: mock_binding || credential_ready,
                mock_binding,
                credential_ready,
                side_effect_class: workflow_binding_side_effect(binding, "read"),
                requires_approval: workflow_binding_bool(binding, "requiresApproval", false),
                capability_scope: workflow_binding_string_array(
                    binding,
                    "capabilityScope",
                    &["read"],
                ),
            });
        }
    }

    if node_type == "plugin_tool" {
        if let Some(binding) = logic.get("toolBinding") {
            let binding_kind = binding
                .get("bindingKind")
                .and_then(Value::as_str)
                .unwrap_or("plugin_tool");
            let workflow_tool_path = binding
                .get("workflowTool")
                .and_then(|tool| tool.get("workflowPath"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty());
            let mock_binding = workflow_binding_bool(binding, "mockBinding", false);
            let credential_ready = workflow_binding_bool(binding, "credentialReady", false);
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-tool", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: if binding_kind == "workflow_tool" {
                    "Workflow tool".to_string()
                } else {
                    "Tool".to_string()
                },
                reference: workflow_tool_path
                    .map(str::to_string)
                    .or_else(|| workflow_binding_text(binding, "toolRef"))
                    .unwrap_or_else(|| "tool".to_string()),
                mode: if binding_kind == "workflow_tool" {
                    "local"
                } else if mock_binding {
                    "mock"
                } else {
                    "live"
                }
                .to_string(),
                ready: if binding_kind == "workflow_tool" {
                    workflow_tool_path.is_some()
                } else {
                    mock_binding || credential_ready
                },
                mock_binding,
                credential_ready,
                side_effect_class: workflow_binding_side_effect(binding, "none"),
                requires_approval: workflow_binding_bool(binding, "requiresApproval", false),
                capability_scope: workflow_binding_string_array(
                    binding,
                    "capabilityScope",
                    &["tool"],
                ),
            });
        }
    }

    if node_type == "parser" {
        if let Some(binding) = logic.get("parserBinding") {
            let mock_binding = workflow_binding_bool(binding, "mockBinding", false);
            rows.push(WorkflowBindingInspection {
                row_id: format!("{}-parser", node_id),
                node_id: node_id.clone(),
                node_name: node_name.clone(),
                node_type: node_type.clone(),
                binding_kind: "Parser".to_string(),
                reference: workflow_binding_text(binding, "parserRef")
                    .unwrap_or_else(|| "parser".to_string()),
                mode: if mock_binding { "mock" } else { "local" }.to_string(),
                ready: true,
                mock_binding,
                credential_ready: true,
                side_effect_class: "none".to_string(),
                requires_approval: false,
                capability_scope: workflow_binding_string_array(
                    binding,
                    "capabilityScope",
                    &["structured_output"],
                ),
            });
        }
    }

    rows
}

fn workflow_binding_check_result(
    inspection: WorkflowBindingInspection,
    workflow: &WorkflowProject,
) -> WorkflowBindingCheckResult {
    let created_at_ms = now_ms();
    let environment = workflow
        .global_config
        .get("environmentProfile")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let environment_target = environment
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("local");
    let mock_binding_policy = environment
        .get("mockBindingPolicy")
        .and_then(Value::as_str)
        .unwrap_or("block");

    let (status, summary, detail) = if inspection.mode == "mock" {
        let strict_environment =
            environment_target == "production" || mock_binding_policy == "block";
        if strict_environment {
            (
                "blocked",
                "Mock binding blocked for activation",
                "This binding is explicitly mocked. Switch to live credentials or relax the environment mock policy before activation.",
            )
        } else {
            (
                "warning",
                "Mock binding available for sandbox use",
                "This check validates the explicit mock contract locally. It does not call a live external service.",
            )
        }
    } else if inspection.mode == "live" {
        if inspection.ready {
            (
                "passed",
                "Live binding contract is ready",
                "Credentials are marked ready in workflow config. No hidden vendor connectivity probe was run.",
            )
        } else {
            (
                "blocked",
                "Live credentials are not ready",
                "Mark credentials ready from the node configuration after the connector or tool is configured.",
            )
        }
    } else if inspection.binding_kind == "Workflow tool" {
        if inspection.ready {
            (
                "passed",
                "Workflow tool reference is configured",
                "The child workflow path is present. Execution will validate the child workflow and record lineage at run time.",
            )
        } else {
            (
                "blocked",
                "Workflow tool needs a child workflow",
                "Select a child workflow path before this binding can run as a tool.",
            )
        }
    } else if inspection.ready {
        (
            "passed",
            "Local binding contract is ready",
            "This local binding can be validated without external credentials.",
        )
    } else {
        (
            "blocked",
            "Binding is incomplete",
            "Open the node configuration and complete the binding fields.",
        )
    };

    WorkflowBindingCheckResult {
        id: format!("binding-check-{}-{}", inspection.row_id, created_at_ms),
        row_id: inspection.row_id,
        node_id: inspection.node_id,
        binding_kind: inspection.binding_kind,
        reference: inspection.reference,
        mode: inspection.mode,
        status: status.to_string(),
        summary: summary.to_string(),
        detail: detail.to_string(),
        created_at_ms,
    }
}

fn workflow_binding_manifest_for_workflow(workflow: &WorkflowProject) -> WorkflowBindingManifest {
    let generated_at_ms = now_ms();
    let environment_profile = workflow
        .global_config
        .get("environmentProfile")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "target": "local",
                "credentialScope": "local",
                "mockBindingPolicy": "block"
            })
        });
    let mut entries = Vec::new();
    for node in &workflow.nodes {
        for inspection in workflow_binding_inspections(workflow, node) {
            let check = workflow_binding_check_result(inspection.clone(), workflow);
            entries.push(WorkflowBindingManifestEntry {
                id: inspection.row_id,
                node_id: inspection.node_id,
                node_name: inspection.node_name,
                node_type: inspection.node_type,
                binding_kind: inspection.binding_kind,
                reference: inspection.reference,
                mode: inspection.mode,
                credential_ready: inspection.credential_ready,
                mock_binding: inspection.mock_binding,
                side_effect_class: inspection.side_effect_class,
                requires_approval: inspection.requires_approval,
                capability_scope: inspection.capability_scope,
                status: check.status,
                status_reason: check.summary,
            });
        }
    }
    let summary = WorkflowBindingManifestSummary {
        total: entries.len(),
        live: entries.iter().filter(|entry| entry.mode == "live").count(),
        mock_bindings: entries.iter().filter(|entry| entry.mode == "mock").count(),
        local: entries.iter().filter(|entry| entry.mode == "local").count(),
        ready: entries
            .iter()
            .filter(|entry| entry.status == "passed" || entry.status == "warning")
            .count(),
        blocked: entries
            .iter()
            .filter(|entry| entry.status == "blocked")
            .count(),
        approval_required: entries
            .iter()
            .filter(|entry| entry.requires_approval)
            .count(),
    };
    WorkflowBindingManifest {
        schema_version: "workflow.bindings.v1".to_string(),
        workflow_id: workflow.metadata.id.clone(),
        workflow_slug: workflow.metadata.slug.clone(),
        generated_at_ms,
        environment_profile,
        bindings: entries,
        summary,
    }
}

#[tauri::command]
pub fn check_workflow_binding(
    path: String,
    node_id: String,
    binding_id: Option<String>,
) -> Result<WorkflowBindingCheckResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let node = workflow_node_by_id(&bundle.workflow, &node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    let rows = workflow_binding_inspections(&bundle.workflow, node);
    let inspection = if let Some(binding_id) = binding_id.as_deref() {
        rows.into_iter()
            .find(|row| row.row_id == binding_id)
            .ok_or_else(|| format!("Workflow binding '{}' was not found.", binding_id))?
    } else {
        rows.into_iter()
            .next()
            .unwrap_or_else(|| WorkflowBindingInspection {
                row_id: format!("{}-binding", node_id),
                node_id: node_id.clone(),
                node_name: workflow_node_name(node),
                node_type: workflow_node_type(node),
                binding_kind: "Binding".to_string(),
                reference: String::new(),
                mode: "local".to_string(),
                ready: false,
                mock_binding: false,
                credential_ready: false,
                side_effect_class: "none".to_string(),
                requires_approval: false,
                capability_scope: Vec::new(),
            })
    };
    let result = workflow_binding_check_result(inspection, &bundle.workflow);
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: result.id.clone(),
            kind: "binding_check".to_string(),
            created_at_ms: result.created_at_ms,
            summary: format!(
                "Binding check for '{}' {}: {}.",
                workflow_node_name(node),
                result.status,
                result.summary
            ),
            path: None,
        },
    )?;
    Ok(result)
}

#[tauri::command]
pub fn generate_workflow_binding_manifest(path: String) -> Result<WorkflowBindingManifest, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let manifest = workflow_binding_manifest_for_workflow(&bundle.workflow);
    save_workflow_binding_manifest(&workflow_path, &manifest)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("binding-manifest-{}", manifest.generated_at_ms),
            kind: "binding_manifest".to_string(),
            created_at_ms: manifest.generated_at_ms,
            summary: format!(
                "Binding manifest generated with {} ready and {} blocked bindings.",
                manifest.summary.ready, manifest.summary.blocked
            ),
            path: None,
        },
    )?;
    Ok(manifest)
}

#[tauri::command]
pub fn load_workflow_binding_manifest(
    path: String,
) -> Result<Option<WorkflowBindingManifest>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_binding_manifest_sidecar(&workflow_binding_manifest_path(&workflow_path))
}

#[tauri::command]
pub fn run_workflow_tests(
    path: String,
    test_ids: Option<Vec<String>>,
) -> Result<WorkflowTestRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let node_ids = bundle
        .workflow
        .nodes
        .iter()
        .filter_map(|node| {
            node.get("id")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .collect::<std::collections::HashSet<_>>();
    let selected_tests = bundle
        .tests
        .iter()
        .filter(|test| {
            test_ids
                .as_ref()
                .map(|ids| ids.iter().any(|id| id == &test.id))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let started_at_ms = now_ms();
    let skipped = if selected_tests.is_empty() {
        bundle.tests.len()
    } else {
        0
    };
    let executable_assertions = selected_tests
        .iter()
        .any(|test| workflow_test_needs_run(test));
    let run_result = if executable_assertions {
        Some(run_workflow_project(
            workflow_path.display().to_string(),
            None,
        )?)
    } else {
        None
    };

    let results = selected_tests
        .iter()
        .map(|test| {
            workflow_evaluate_test_case(test, &bundle.workflow, &node_ids, run_result.as_ref())
        })
        .collect::<Vec<_>>();
    let passed = results
        .iter()
        .filter(|result| result.status == "passed")
        .count();
    let failed = results
        .iter()
        .filter(|result| result.status == "failed")
        .count();
    let blocked = results
        .iter()
        .filter(|result| result.status == "blocked")
        .count();

    if let Some(run) = run_result {
        append_workflow_evidence(
            &workflow_path,
            WorkflowEvidenceSummary {
                id: format!("test-run-{}", started_at_ms),
                kind: "test_run".to_string(),
                created_at_ms: started_at_ms,
                summary: format!("Workflow tests evaluated against run '{}'.", run.summary.id),
                path: Some(
                    workflow_run_result_path(&workflow_path, &run.summary.id)
                        .display()
                        .to_string(),
                ),
            },
        )?;
    }

    let status = if failed > 0 {
        "failed"
    } else if blocked > 0 {
        "blocked"
    } else {
        "passed"
    };

    Ok(WorkflowTestRunResult {
        run_id: format!("workflow-test-{}", started_at_ms),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: now_ms(),
        passed,
        failed,
        blocked,
        skipped,
        results,
    })
}

#[tauri::command]
pub fn validate_workflow_bundle(path: String) -> Result<WorkflowValidationResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let result = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("validation-{}", now_ms()),
            kind: "validation".to_string(),
            created_at_ms: now_ms(),
            summary: format!("Workflow validation {}.", result.status),
            path: Some(workflow_evidence_path(&workflow_path).display().to_string()),
        },
    )?;
    Ok(result)
}

#[tauri::command]
pub fn create_workflow_thread(
    path: String,
    input: Option<Value>,
) -> Result<WorkflowThread, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    ensure_workflow_runtime_dirs(&workflow_path)?;
    let thread = new_workflow_thread(&workflow_path, input);
    save_workflow_thread(&workflow_path, &thread)?;
    Ok(thread)
}

#[tauri::command]
pub fn run_workflow_project(
    path: String,
    options: Option<Value>,
) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let input = options.and_then(|value| value.get("input").cloned());
    let thread = new_workflow_thread(&workflow_path, input);
    save_workflow_thread(&workflow_path, &thread)?;
    let state = initial_workflow_state(&thread, "pending");
    let result = execute_workflow_project(&workflow_path, bundle, thread, state, None)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: "run".to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(&workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}

#[tauri::command]
pub fn run_workflow_node(
    path: String,
    node_id: String,
    input: Option<Value>,
    _options: Option<Value>,
) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    workflow_single_node_result(&workflow_path, &bundle.workflow, &node_id, input, false)
}

#[tauri::command]
pub fn dry_run_workflow_function(
    path: String,
    node_id: String,
    input: Option<Value>,
) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let node = workflow_node_by_id(&bundle.workflow, &node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    if ActionKind::from_node_type(&workflow_node_type(node)) != ActionKind::Function {
        return Err("Only function nodes support dry run.".to_string());
    }
    let binding = workflow_function_binding(node)?;
    let dry_input = input.or(binding.test_input);
    workflow_single_node_result(&workflow_path, &bundle.workflow, &node_id, dry_input, true)
}

#[tauri::command]
pub fn list_workflow_scaffolds(_project_root: String) -> Result<Vec<Value>, String> {
    Ok(workflow_scaffold_definitions())
}

#[tauri::command]
pub fn create_workflow_node_from_scaffold(
    path: String,
    request: CreateWorkflowNodeFromScaffoldRequest,
) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let mut bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let scaffold = workflow_scaffold_definitions().into_iter().find(|item| {
        item.get("scaffoldId").and_then(Value::as_str) == Some(request.scaffold_id.as_str())
    });
    let Some(scaffold) = scaffold else {
        return Err(format!(
            "Unknown workflow scaffold '{}'.",
            request.scaffold_id
        ));
    };
    let node_type = scaffold
        .get("nodeType")
        .and_then(Value::as_str)
        .unwrap_or("source");
    let index = bundle.workflow.nodes.len() as i64;
    let node_id = request
        .node_id
        .unwrap_or_else(|| format!("{}-{}", node_type.replace('_', "-"), now_ms()));
    let label = scaffold
        .get("defaultName")
        .and_then(Value::as_str)
        .or_else(|| scaffold.get("label").and_then(Value::as_str))
        .unwrap_or("Workflow node");
    let metric_label = scaffold
        .get("metricLabel")
        .and_then(Value::as_str)
        .unwrap_or("Status");
    let metric_value = scaffold
        .get("metricValue")
        .and_then(Value::as_str)
        .unwrap_or("idle");
    let mut node = workflow_node(
        &node_id,
        node_type,
        request.name.as_deref().unwrap_or(label),
        request.x.unwrap_or(120 + (index % 5) * 260),
        request.y.unwrap_or(160 + (index / 5) * 150),
        metric_label,
        metric_value,
    );
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        if let Some(preset) = scaffold.get("presetLogic").and_then(Value::as_object) {
            for (key, value) in preset {
                logic.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some(law) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("law"))
        .and_then(Value::as_object_mut)
    {
        if let Some(preset) = scaffold.get("presetLaw").and_then(Value::as_object) {
            for (key, value) in preset {
                law.insert(key.clone(), value.clone());
            }
        }
    }
    bundle.workflow.nodes.push(node);
    bundle.workflow.metadata.dirty = Some(true);
    bundle.workflow.metadata.updated_at_ms = Some(now_ms());
    save_workflow_project(workflow_path.display().to_string(), bundle.workflow.clone())?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn validate_workflow_node_config(
    path: String,
    node_id: String,
) -> Result<WorkflowValidationResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    if workflow_node_by_id(&bundle.workflow, &node_id).is_none() {
        return Err(format!("Workflow node '{}' was not found.", node_id));
    }
    let mut result = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let node_id_ref = node_id.as_str();
    result
        .errors
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result
        .warnings
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result
        .missing_config
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result
        .connector_binding_issues
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result
        .execution_readiness_issues
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result
        .verification_issues
        .retain(|issue| issue.node_id.as_deref() == Some(node_id_ref));
    result.blocked_nodes.retain(|id| id == &node_id);
    result.policy_required_nodes.retain(|id| id == &node_id);
    result.unsupported_runtime_nodes.retain(|id| id == &node_id);
    result.status = if !result.errors.is_empty() {
        "failed".to_string()
    } else if !result.blocked_nodes.is_empty() || !result.warnings.is_empty() {
        "blocked".to_string()
    } else {
        "passed".to_string()
    };
    Ok(result)
}

#[tauri::command]
pub fn dry_run_workflow_node(
    path: String,
    node_id: String,
    input: Option<Value>,
) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    workflow_single_node_result(&workflow_path, &bundle.workflow, &node_id, input, true)
}

#[tauri::command]
pub fn materialize_workflow_function(
    path: String,
    node_id: String,
    _options: Option<Value>,
) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let mut bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let functions_dir = workflow_path
        .display()
        .to_string()
        .replace(".workflow.json", ".functions");
    fs::create_dir_all(&functions_dir).map_err(|error| {
        format!(
            "Failed to create workflow functions directory '{}': {}",
            functions_dir, error
        )
    })?;
    let Some(node) = bundle
        .workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some(node_id.as_str()))
    else {
        return Err(format!("Workflow node '{}' was not found.", node_id));
    };
    if workflow_node_type(node) != "function" {
        return Err(
            "Only function nodes can be materialized as file-backed functions.".to_string(),
        );
    }
    let logic = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Function node is missing logic.".to_string())?;
    let code = logic
        .get("functionBinding")
        .and_then(|binding| binding.get("code"))
        .or_else(|| logic.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("return { result: input };");
    let source_path = PathBuf::from(&functions_dir).join(format!("{}.js", node_id));
    fs::write(&source_path, code).map_err(|error| {
        format!(
            "Failed to write workflow function '{}': {}",
            source_path.display(),
            error
        )
    })?;
    let code_hash = workflow_file_sha256(&source_path)?;
    let function_ref = json!({
        "runtime": "javascript",
        "entrypoint": "default",
        "sourcePath": source_path.display().to_string(),
        "codeHash": code_hash,
        "dependencyManifest": {
            "runtime": "node",
            "dependencies": {}
        },
        "inputSchema": logic.get("inputSchema").cloned().unwrap_or_else(|| json!({"type":"object"})),
        "outputSchema": logic.get("outputSchema").cloned().unwrap_or_else(|| json!({"type":"object"})),
        "fixtureSet": [],
        "sandboxPolicy": logic
            .get("functionBinding")
            .and_then(|binding| binding.get("sandboxPolicy"))
            .cloned()
            .unwrap_or_else(|| json!({"timeoutMs":1000,"memoryMb":64,"outputLimitBytes":32768,"permissions":[]}))
    });
    let mut binding = logic
        .get("functionBinding")
        .cloned()
        .unwrap_or_else(|| json!({"language":"javascript","code": code}));
    if let Some(object) = binding.as_object_mut() {
        object.insert("functionRef".to_string(), function_ref);
    }
    logic.insert("functionBinding".to_string(), binding);
    save_workflow_project(workflow_path.display().to_string(), bundle.workflow.clone())?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn list_workflow_model_bindings(_project_root: String) -> Result<Vec<Value>, String> {
    Ok(vec![
        json!({
            "modelRef": "reasoning",
            "mockBinding": true,
            "capabilityScope": ["reasoning"],
            "sideEffectClass": "none",
            "requiresApproval": false,
            "credentialReady": false,
            "toolUseMode": "explicit"
        }),
        json!({
            "modelRef": "vision",
            "mockBinding": true,
            "capabilityScope": ["vision"],
            "sideEffectClass": "none",
            "requiresApproval": false,
            "credentialReady": false,
            "toolUseMode": "none"
        }),
    ])
}

#[tauri::command]
pub fn list_workflow_delivery_targets(_project_root: String) -> Result<Vec<Value>, String> {
    Ok(vec![
        json!({"targetKind": "none", "requiresApproval": false}),
        json!({"targetKind": "chat_inline", "requiresApproval": false}),
        json!({"targetKind": "local_file", "requiresApproval": true}),
        json!({"targetKind": "repo_patch", "requiresApproval": true}),
        json!({"targetKind": "ticket_draft", "requiresApproval": false}),
        json!({"targetKind": "message_draft", "requiresApproval": false}),
        json!({"targetKind": "connector_write", "requiresApproval": true}),
        json!({"targetKind": "deploy", "requiresApproval": true}),
    ])
}

#[tauri::command]
pub fn list_workflow_tool_catalog(
    _project_root: String,
) -> Result<Vec<WorkflowToolBinding>, String> {
    Ok(vec![
        WorkflowToolBinding {
            tool_ref: "web_search_mcp".to_string(),
            binding_kind: Some("mcp_tool".to_string()),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            arguments: Some(json!({ "query": "{{input}}" })),
            argument_schema: Some(json!({"type": "object", "required": ["query"]})),
            result_schema: Some(json!({"type": "object"})),
            workflow_tool: None,
        },
        WorkflowToolBinding {
            tool_ref: "codex_plugin".to_string(),
            binding_kind: Some("plugin_tool".to_string()),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string(), "analyze".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            arguments: Some(json!({})),
            argument_schema: Some(json!({"type": "object"})),
            result_schema: Some(json!({"type": "object"})),
            workflow_tool: None,
        },
        WorkflowToolBinding {
            tool_ref: "workflow_tool".to_string(),
            binding_kind: Some("workflow_tool".to_string()),
            mock_binding: false,
            credential_ready: Some(true),
            capability_scope: vec!["invoke".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            arguments: Some(json!({})),
            argument_schema: Some(json!({"type": "object"})),
            result_schema: Some(json!({"type": "object"})),
            workflow_tool: Some(WorkflowToolSubgraphBinding {
                workflow_path: ".agents/workflows/scratch-gui-node-composition.workflow.json"
                    .to_string(),
                argument_schema: Some(json!({"type": "object"})),
                result_schema: Some(json!({"type": "object"})),
                timeout_ms: Some(30000),
                max_attempts: Some(1),
            }),
        },
    ])
}

#[tauri::command]
pub fn list_workflow_connector_catalog(
    _project_root: String,
) -> Result<Vec<WorkflowConnectorBinding>, String> {
    Ok(vec![
        WorkflowConnectorBinding {
            connector_ref: "slack".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            operation: Some("read".to_string()),
        },
        WorkflowConnectorBinding {
            connector_ref: "support".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            operation: Some("read".to_string()),
        },
        WorkflowConnectorBinding {
            connector_ref: "it_ticketing".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string(), "write".to_string()],
            side_effect_class: "external_write".to_string(),
            requires_approval: true,
            operation: Some("draft_or_create".to_string()),
        },
        WorkflowConnectorBinding {
            connector_ref: "analytics".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            operation: Some("read".to_string()),
        },
        WorkflowConnectorBinding {
            connector_ref: "accounting_system".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            operation: Some("read".to_string()),
        },
        WorkflowConnectorBinding {
            connector_ref: "docs".to_string(),
            mock_binding: true,
            credential_ready: Some(false),
            capability_scope: vec!["read".to_string()],
            side_effect_class: "read".to_string(),
            requires_approval: false,
            operation: Some("lookup".to_string()),
        },
    ])
}

#[tauri::command]
pub fn validate_workflow_execution_readiness(
    path: String,
) -> Result<WorkflowValidationResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let base = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let fixtures = load_workflow_node_fixtures_from_path(&workflow_fixtures_path(&workflow_path))?;
    let result =
        apply_workflow_activation_readiness(&bundle.workflow, &bundle.tests, base, &fixtures);
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("readiness-{}", now_ms()),
            kind: "readiness".to_string(),
            created_at_ms: now_ms(),
            summary: format!("Workflow readiness {}.", result.status),
            path: Some(workflow_evidence_path(&workflow_path).display().to_string()),
        },
    )?;
    Ok(result)
}

#[tauri::command]
pub fn export_workflow_package(
    path: String,
    output_dir: Option<String>,
) -> Result<WorkflowPortablePackage, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let base = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let fixtures = load_workflow_node_fixtures_from_path(&workflow_fixtures_path(&workflow_path))?;
    let readiness =
        apply_workflow_activation_readiness(&bundle.workflow, &bundle.tests, base, &fixtures);
    let blockers = workflow_validation_blockers(&readiness);
    let package_dir = output_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| workflow_package_default_dir(&workflow_path));
    if package_dir.exists() {
        fs::remove_dir_all(&package_dir).map_err(|error| {
            format!(
                "Failed to reset workflow package '{}': {}",
                package_dir.display(),
                error
            )
        })?;
    }
    fs::create_dir_all(&package_dir).map_err(|error| {
        format!(
            "Failed to create workflow package '{}': {}",
            package_dir.display(),
            error
        )
    })?;

    let mut files = Vec::new();
    workflow_package_copy_file(
        &workflow_path,
        &package_dir,
        "workflow.workflow.json",
        "workflow",
        &mut files,
    )?;
    workflow_package_copy_file(
        &workflow_tests_path(&workflow_path),
        &package_dir,
        "workflow.tests.json",
        "tests",
        &mut files,
    )?;
    workflow_package_copy_file(
        &workflow_fixtures_path(&workflow_path),
        &package_dir,
        "workflow.fixtures.json",
        "fixtures",
        &mut files,
    )?;
    workflow_package_copy_file(
        &workflow_evidence_path(&workflow_path),
        &package_dir,
        "workflow.evidence.json",
        "evidence",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_proposals_dir(&workflow_path),
        &package_dir,
        "proposals",
        "proposal",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_functions_dir(&workflow_path),
        &package_dir,
        "functions",
        "function",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_runs_path(&workflow_path),
        &package_dir,
        "runs",
        "run_summary",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_checkpoints_dir(&workflow_path),
        &package_dir,
        "checkpoints",
        "checkpoint",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_interrupts_dir(&workflow_path),
        &package_dir,
        "interrupts",
        "interrupt",
        &mut files,
    )?;
    workflow_package_copy_dir(
        &workflow_threads_dir(&workflow_path),
        &package_dir,
        "threads",
        "thread",
        &mut files,
    )?;

    let binding_manifest = workflow_binding_manifest_for_workflow(&bundle.workflow);
    save_workflow_binding_manifest(&workflow_path, &binding_manifest)?;
    workflow_package_copy_file(
        &workflow_binding_manifest_path(&workflow_path),
        &package_dir,
        "workflow.bindings.json",
        "binding_manifest_sidecar",
        &mut files,
    )?;
    write_json_pretty(
        &package_dir.join("binding-manifest.json"),
        &binding_manifest,
    )?;
    files.push(workflow_package_file_record(
        &package_dir,
        "binding_manifest",
        "binding-manifest.json",
    )?);
    write_json_pretty(
        &package_dir.join("policy-manifest.json"),
        &workflow_policy_manifest(&bundle.workflow),
    )?;
    files.push(workflow_package_file_record(
        &package_dir,
        "policy_manifest",
        "policy-manifest.json",
    )?);
    write_json_pretty(
        &package_dir.join("output-manifest.json"),
        &workflow_output_manifest(&bundle.workflow),
    )?;
    files.push(workflow_package_file_record(
        &package_dir,
        "output_manifest",
        "output-manifest.json",
    )?);
    write_json_pretty(
        &package_dir.join("hidden-evidence-schema.json"),
        &json!({
            "schemaVersion": "workflow.hidden-evidence-schema.v1",
            "generatedAtMs": now_ms(),
            "records": [
                { "kind": "run", "storedIn": "runs/*.json" },
                { "kind": "checkpoint", "storedIn": "checkpoints/*/*.json" },
                { "kind": "interrupt", "storedIn": "interrupts/*.json" },
                { "kind": "evidence", "storedIn": "workflow.evidence.json" }
            ],
            "uiVisibility": "hidden"
        }),
    )?;
    files.push(workflow_package_file_record(
        &package_dir,
        "hidden_evidence_schema",
        "hidden-evidence-schema.json",
    )?);

    let manifest = WorkflowPortablePackageManifest {
        schema_version: "workflow.portable-package.v1".to_string(),
        exported_at_ms: now_ms(),
        workflow_name: bundle.workflow.metadata.name.clone(),
        workflow_slug: bundle.workflow.metadata.slug.clone(),
        source_workflow_path: workflow_path.display().to_string(),
        readiness_status: readiness.status.clone(),
        portable: readiness.status != "blocked",
        blockers,
        files,
    };
    let manifest_path = package_dir.join("manifest.json");
    write_json_pretty(&manifest_path, &manifest)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("package-{}", manifest.exported_at_ms),
            kind: "package".to_string(),
            created_at_ms: manifest.exported_at_ms,
            summary: format!(
                "Workflow portable package exported with readiness {}.",
                manifest.readiness_status
            ),
            path: Some(package_dir.display().to_string()),
        },
    )?;

    Ok(WorkflowPortablePackage {
        package_path: package_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        manifest,
        imported_workflow_path: None,
    })
}

#[tauri::command]
pub fn import_workflow_package(
    request: ImportWorkflowPackageRequest,
) -> Result<WorkflowWorkbenchBundle, String> {
    let package_dir = workflow_package_dir_from_request(&request.package_path)?;
    let manifest_path = package_dir.join("manifest.json");
    let manifest: WorkflowPortablePackageManifest = read_json_file(&manifest_path)?;
    let root_path = resolve_root_path(&request.project_root, true)?;
    let workflows_dir = workflow_base_dir(&root_path);
    fs::create_dir_all(&workflows_dir).map_err(|error| {
        format!(
            "Failed to create workflow directory '{}': {}",
            workflows_dir.display(),
            error
        )
    })?;

    let workflow_file = workflow_package_manifest_file(&manifest, "workflow")
        .ok_or_else(|| "Workflow package is missing workflow.workflow.json.".to_string())?;
    let mut workflow: WorkflowProject =
        read_json_file(&package_dir.join(&workflow_file.relative_path))?;
    normalize_legacy_workflow_output_nodes(&mut workflow);
    let imported_name = request
        .name
        .clone()
        .unwrap_or_else(|| workflow.metadata.name.clone());
    let slug = slugify_workflow_name(&imported_name);
    let workflow_path = workflows_dir.join(format!("{}.workflow.json", slug));
    let tests_path = workflow_tests_path(&workflow_path);
    let fixtures_path = workflow_fixtures_path(&workflow_path);
    let evidence_path = workflow_evidence_path(&workflow_path);
    let proposals_dir = workflow_proposals_dir(&workflow_path);
    let functions_dir = workflow_functions_dir(&workflow_path);

    workflow.metadata.name = imported_name;
    workflow.metadata.slug = slug;
    workflow.metadata.git_location = Some(workflow_path.display().to_string());
    workflow.metadata.updated_at_ms = Some(now_ms());
    workflow.metadata.dirty = Some(false);

    if package_dir.join("functions").exists() {
        if functions_dir.exists() {
            fs::remove_dir_all(&functions_dir).map_err(|error| {
                format!(
                    "Failed to reset workflow functions '{}': {}",
                    functions_dir.display(),
                    error
                )
            })?;
        }
        workflow_package_copy_dir(
            &package_dir.join("functions"),
            functions_dir
                .parent()
                .unwrap_or_else(|| workflows_dir.as_path()),
            functions_dir
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("imported.functions"),
            "function",
            &mut Vec::new(),
        )?;
    }
    rewrite_workflow_function_refs(&mut workflow, &functions_dir);
    write_json_pretty(&workflow_path, &workflow)?;

    if let Some(tests_file) = workflow_package_manifest_file(&manifest, "tests") {
        fs::copy(package_dir.join(&tests_file.relative_path), &tests_path).map_err(|error| {
            format!(
                "Failed to import workflow tests '{}': {}",
                tests_path.display(),
                error
            )
        })?;
    } else {
        write_json_pretty(&tests_path, &Vec::<WorkflowTestCase>::new())?;
    }
    if let Some(fixtures_file) = workflow_package_manifest_file(&manifest, "fixtures") {
        fs::copy(
            package_dir.join(&fixtures_file.relative_path),
            &fixtures_path,
        )
        .map_err(|error| {
            format!(
                "Failed to import workflow fixtures '{}': {}",
                fixtures_path.display(),
                error
            )
        })?;
    }
    if let Some(evidence_file) = workflow_package_manifest_file(&manifest, "evidence") {
        fs::copy(
            package_dir.join(&evidence_file.relative_path),
            &evidence_path,
        )
        .map_err(|error| {
            format!(
                "Failed to import workflow evidence '{}': {}",
                evidence_path.display(),
                error
            )
        })?;
    }
    if package_dir.join("proposals").exists() {
        if proposals_dir.exists() {
            fs::remove_dir_all(&proposals_dir).map_err(|error| {
                format!(
                    "Failed to reset workflow proposals '{}': {}",
                    proposals_dir.display(),
                    error
                )
            })?;
        }
        workflow_package_copy_dir(
            &package_dir.join("proposals"),
            proposals_dir
                .parent()
                .unwrap_or_else(|| workflows_dir.as_path()),
            proposals_dir
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("imported.proposals"),
            "proposal",
            &mut Vec::new(),
        )?;
    } else {
        fs::create_dir_all(&proposals_dir).map_err(|error| {
            format!(
                "Failed to create proposals directory '{}': {}",
                proposals_dir.display(),
                error
            )
        })?;
    }
    let binding_manifest = workflow_binding_manifest_for_workflow(&workflow);
    save_workflow_binding_manifest(&workflow_path, &binding_manifest)?;
    ensure_workflow_runtime_dirs(&workflow_path)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!(
                "binding-manifest-import-{}",
                binding_manifest.generated_at_ms
            ),
            kind: "binding_manifest".to_string(),
            created_at_ms: binding_manifest.generated_at_ms,
            summary: format!(
                "Binding manifest generated for imported workflow with {} bindings.",
                binding_manifest.summary.total
            ),
            path: None,
        },
    )?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: format!("package-import-{}", now_ms()),
            kind: "package".to_string(),
            created_at_ms: now_ms(),
            summary: "Workflow portable package imported.".to_string(),
            path: Some(package_dir.display().to_string()),
        },
    )?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn load_workflow_run(path: String, run_id: String) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_run_result(&workflow_path, &run_id)
}

#[tauri::command]
pub fn resume_workflow_run(
    path: String,
    request: WorkflowResumeRequest,
) -> Result<WorkflowRunResult, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let mut thread = load_workflow_thread(&workflow_path, &request.thread_id)?;
    let checkpoint_id = request
        .checkpoint_id
        .clone()
        .or_else(|| thread.latest_checkpoint_id.clone())
        .ok_or_else(|| "A checkpoint is required to resume this workflow run.".to_string())?;
    let (checkpoint, mut state) = load_workflow_checkpoint_record(&workflow_path, &checkpoint_id)?;
    let interrupt_path = request
        .run_id
        .as_deref()
        .map(|run_id| workflow_interrupt_path(&workflow_path, run_id));
    let mut interrupt = if let Some(path) = interrupt_path.as_ref().filter(|path| path.exists()) {
        Some(read_json_file::<WorkflowInterrupt>(path)?)
    } else {
        None
    };
    if request.outcome == "reject" {
        state
            .blocked_node_ids
            .extend(state.interrupted_node_ids.clone());
    }
    if let Some(edited_state) = request.edited_state.clone() {
        if let Some(object) = edited_state.as_object() {
            for (key, value) in object {
                state.values.insert(key.clone(), value.clone());
            }
        }
    }
    let interrupted_node_id = request
        .interrupt_id
        .as_ref()
        .and_then(|interrupt_id| {
            interrupt
                .as_ref()
                .and_then(|item| (&item.id == interrupt_id).then(|| item.node_id.clone()))
        })
        .or_else(|| state.interrupted_node_ids.first().cloned());
    let resume_gate = if let Some(gate_node_id) = interrupted_node_id {
        if let Some(item) = interrupt.as_mut() {
            item.status = match request.outcome.as_str() {
                "approve" => "approved",
                "edit" => "edited",
                _ => "rejected",
            }
            .to_string();
            item.resolved_at_ms = Some(now_ms());
            item.response = Some(json!({
                "outcome": request.outcome,
                "editedState": request.edited_state
            }));
            if let Some(run_id) = request.run_id.as_deref() {
                write_json_pretty(&workflow_interrupt_path(&workflow_path, run_id), item)?;
            }
        }
        Some((
            gate_node_id,
            json!({
                "outcome": request.outcome,
                "editedState": request.edited_state
            }),
        ))
    } else {
        let failed_node_id = request
            .node_id
            .clone()
            .or_else(|| checkpoint.node_id.clone())
            .or_else(|| state.blocked_node_ids.first().cloned())
            .ok_or_else(|| "No interrupted or failed node is available to resume.".to_string())?;
        if checkpoint.status != "failed" && checkpoint.status != "blocked" {
            return Err(format!(
                "Checkpoint '{}' is '{}' and cannot be resumed as a failed node.",
                checkpoint.id, checkpoint.status
            ));
        }
        state.blocked_node_ids.retain(|id| id != &failed_node_id);
        state
            .interrupted_node_ids
            .retain(|id| id != &failed_node_id);
        state
            .active_node_ids
            .retain(|node_id| node_id != &failed_node_id);
        state.active_node_ids.insert(0, failed_node_id);
        None
    };
    thread.status = "running".to_string();
    save_workflow_thread(&workflow_path, &thread)?;
    let result = execute_workflow_project(&workflow_path, bundle, thread, state, resume_gate)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: "run".to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(&workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}

#[tauri::command]
pub fn list_workflow_checkpoints(
    path: String,
    thread_id: String,
) -> Result<Vec<WorkflowCheckpoint>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_checkpoints_for_thread(&workflow_path, &thread_id)
}

#[tauri::command]
pub fn load_workflow_checkpoint(
    path: String,
    checkpoint_id: String,
) -> Result<WorkflowStateSnapshot, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let (_checkpoint, state) = load_workflow_checkpoint_record(&workflow_path, &checkpoint_id)?;
    Ok(state)
}

#[tauri::command]
pub fn fork_workflow_checkpoint(
    path: String,
    request: WorkflowCheckpointForkRequest,
) -> Result<WorkflowThread, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let (_checkpoint, mut state) =
        load_workflow_checkpoint_record(&workflow_path, &request.checkpoint_id)?;
    let thread = new_workflow_thread(&workflow_path, request.input);
    state.thread_id = thread.id.clone();
    save_workflow_thread(&workflow_path, &thread)?;
    let mut checkpoints = Vec::new();
    let mut fork_state = state;
    workflow_checkpoint_state(
        &workflow_path,
        &mut fork_state,
        "fork",
        &thread.id,
        None,
        "queued",
        request
            .name
            .unwrap_or_else(|| "Forked workflow checkpoint.".to_string()),
        &mut checkpoints,
    )?;
    Ok(thread)
}

fn workflow_value_fingerprint(value: &Option<Value>) -> Option<String> {
    value
        .as_ref()
        .and_then(|item| serde_json::to_string(item).ok())
}

fn workflow_run_node_map(
    run: &WorkflowRunResult,
) -> std::collections::BTreeMap<String, WorkflowNodeRun> {
    run.node_runs
        .iter()
        .map(|node_run| (node_run.node_id.clone(), node_run.clone()))
        .collect()
}

#[tauri::command]
pub fn compare_workflow_runs(
    path: String,
    baseline_run_id: String,
    target_run_id: String,
) -> Result<WorkflowRunComparison, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let baseline = load_workflow_run_result(&workflow_path, &baseline_run_id)?;
    let target = load_workflow_run_result(&workflow_path, &target_run_id)?;
    let baseline_nodes = workflow_run_node_map(&baseline);
    let target_nodes = workflow_run_node_map(&target);
    let node_ids = baseline_nodes
        .keys()
        .chain(target_nodes.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let node_changes = node_ids
        .into_iter()
        .filter_map(|node_id| {
            let baseline_node = baseline_nodes.get(&node_id);
            let target_node = target_nodes.get(&node_id);
            let input_changed = workflow_value_fingerprint(
                &baseline_node.and_then(|node_run| node_run.input.clone()),
            ) != workflow_value_fingerprint(
                &target_node.and_then(|node_run| node_run.input.clone()),
            );
            let output_changed = workflow_value_fingerprint(
                &baseline_node.and_then(|node_run| node_run.output.clone()),
            ) != workflow_value_fingerprint(
                &target_node.and_then(|node_run| node_run.output.clone()),
            );
            let error_changed = baseline_node.and_then(|node_run| node_run.error.clone())
                != target_node.and_then(|node_run| node_run.error.clone());
            let status_changed = baseline_node.map(|node_run| node_run.status.clone())
                != target_node.map(|node_run| node_run.status.clone());
            (status_changed || input_changed || output_changed || error_changed).then(|| {
                WorkflowRunNodeComparison {
                    node_id,
                    baseline_status: baseline_node.map(|node_run| node_run.status.clone()),
                    target_status: target_node.map(|node_run| node_run.status.clone()),
                    input_changed,
                    output_changed,
                    error_changed,
                }
            })
        })
        .collect::<Vec<_>>();
    let state_keys = baseline
        .final_state
        .values
        .keys()
        .chain(target.final_state.values.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let state_changes = state_keys
        .into_iter()
        .filter_map(|key| {
            let baseline_value = baseline.final_state.values.get(&key).cloned();
            let target_value = target.final_state.values.get(&key).cloned();
            if baseline_value == target_value {
                return None;
            }
            let change = match (baseline_value.is_some(), target_value.is_some()) {
                (false, true) => "added",
                (true, false) => "removed",
                _ => "changed",
            }
            .to_string();
            Some(WorkflowRunStateComparison {
                key,
                change,
                baseline_value,
                target_value,
            })
        })
        .collect::<Vec<_>>();
    Ok(WorkflowRunComparison {
        baseline_run_id,
        target_run_id,
        status_changed: baseline.summary.status != target.summary.status,
        checkpoint_delta: target.checkpoints.len() as i64 - baseline.checkpoints.len() as i64,
        node_changes,
        state_changes,
    })
}

#[tauri::command]
pub fn list_workflow_runs(path: String) -> Result<Vec<WorkflowRunSummary>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_runs(&workflow_runs_path(&workflow_path))
}

#[tauri::command]
pub fn list_workflow_evidence(path: String) -> Result<Vec<WorkflowEvidenceSummary>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    load_workflow_evidence(&workflow_evidence_path(&workflow_path))
}

#[tauri::command]
pub fn list_workflow_node_fixtures(
    path: String,
    node_id: Option<String>,
) -> Result<Vec<WorkflowNodeFixture>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let fixtures = load_workflow_node_fixtures_from_path(&workflow_fixtures_path(&workflow_path))?;
    Ok(match node_id {
        Some(id) => fixtures
            .into_iter()
            .filter(|fixture| fixture.node_id == id)
            .collect(),
        None => fixtures,
    })
}

#[tauri::command]
pub fn save_workflow_node_fixture(
    path: String,
    mut fixture: WorkflowNodeFixture,
) -> Result<Vec<WorkflowNodeFixture>, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let node = workflow_node_by_id(&bundle.workflow, &fixture.node_id).ok_or_else(|| {
        format!(
            "Workflow node '{}' was not found for fixture '{}'.",
            fixture.node_id, fixture.id
        )
    })?;
    let schema_declared = workflow_node_schema(node, "outputSchema").is_some();
    match fixture.output.as_ref() {
        Some(output) if schema_declared => match workflow_output_satisfies_schema(node, output) {
            Ok(()) => {
                fixture.validation_status = Some("passed".to_string());
                fixture.validation_message =
                    Some("Fixture output matches the current output schema.".to_string());
            }
            Err(error) => {
                fixture.validation_status = Some("failed".to_string());
                fixture.validation_message = Some(error);
            }
        },
        Some(_) => {
            fixture.validation_status = Some("not_declared".to_string());
            fixture.validation_message =
                Some("No output schema is declared for this node.".to_string());
        }
        None => {
            fixture.validation_status = Some("failed".to_string());
            fixture.validation_message =
                Some("Fixture does not include captured output.".to_string());
        }
    }
    let fixtures_path = workflow_fixtures_path(&workflow_path);
    let mut fixtures = load_workflow_node_fixtures_from_path(&fixtures_path)?;
    if fixture.pinned.unwrap_or(false) {
        for existing in fixtures.iter_mut() {
            if existing.node_id == fixture.node_id {
                existing.pinned = Some(false);
            }
        }
    }
    fixtures.retain(|item| item.id != fixture.id);
    fixtures.insert(0, fixture.clone());
    write_json_pretty(&fixtures_path, &fixtures)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: fixture.id,
            kind: "fixture".to_string(),
            created_at_ms: now_ms(),
            summary: format!("Fixture captured for workflow node '{}'.", fixture.node_id),
            path: Some(fixtures_path.display().to_string()),
        },
    )?;
    Ok(fixtures)
}

fn workflow_proposal_node_map(
    workflow: &WorkflowProject,
) -> std::collections::BTreeMap<String, Value> {
    workflow
        .nodes
        .iter()
        .filter_map(|node| workflow_node_id(node).map(|node_id| (node_id, node.clone())))
        .collect()
}

fn workflow_changed_object_keys(current: &Value, proposed: &Value) -> Vec<String> {
    let Some(current_object) = current.as_object() else {
        return if current == proposed {
            Vec::new()
        } else {
            vec!["value".to_string()]
        };
    };
    let Some(proposed_object) = proposed.as_object() else {
        return if current == proposed {
            Vec::new()
        } else {
            vec!["value".to_string()]
        };
    };
    let mut keys = current_object
        .keys()
        .chain(proposed_object.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    keys.retain(|key| current_object.get(key) != proposed_object.get(key));
    keys.into_iter().collect()
}

fn workflow_proposal_graph_diff(
    current: &WorkflowProject,
    proposed: &WorkflowProject,
) -> WorkflowProposalGraphDiff {
    let current_nodes = workflow_proposal_node_map(current);
    let proposed_nodes = workflow_proposal_node_map(proposed);
    let current_ids = current_nodes
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let proposed_ids = proposed_nodes
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let added_node_ids = proposed_ids
        .difference(&current_ids)
        .cloned()
        .collect::<Vec<_>>();
    let removed_node_ids = current_ids
        .difference(&proposed_ids)
        .cloned()
        .collect::<Vec<_>>();
    let changed_node_ids = current_ids
        .intersection(&proposed_ids)
        .filter(|node_id| current_nodes.get(*node_id) != proposed_nodes.get(*node_id))
        .cloned()
        .collect::<Vec<_>>();
    WorkflowProposalGraphDiff {
        added_node_ids: if added_node_ids.is_empty() {
            None
        } else {
            Some(added_node_ids)
        },
        removed_node_ids: if removed_node_ids.is_empty() {
            None
        } else {
            Some(removed_node_ids)
        },
        changed_node_ids: if changed_node_ids.is_empty() {
            None
        } else {
            Some(changed_node_ids)
        },
    }
}

fn workflow_proposal_config_diff(
    current: &WorkflowProject,
    proposed: &WorkflowProject,
) -> WorkflowProposalConfigDiff {
    let graph_diff = workflow_proposal_graph_diff(current, proposed);
    let changed_node_ids = graph_diff
        .added_node_ids
        .unwrap_or_default()
        .into_iter()
        .chain(graph_diff.removed_node_ids.unwrap_or_default())
        .chain(graph_diff.changed_node_ids.unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>();
    WorkflowProposalConfigDiff {
        changed_node_ids: changed_node_ids.into_iter().collect(),
        changed_global_keys: workflow_changed_object_keys(
            &current.global_config,
            &proposed.global_config,
        ),
        changed_metadata_keys: workflow_changed_object_keys(
            &serde_json::to_value(&current.metadata).unwrap_or(Value::Null),
            &serde_json::to_value(&proposed.metadata).unwrap_or(Value::Null),
        ),
    }
}

fn workflow_proposal_sidecar_diff(
    request: &CreateWorkflowProposalRequest,
) -> WorkflowProposalSidecarDiff {
    let mut changed_roles = vec!["proposal".to_string()];
    if request.workflow_patch.is_some() {
        changed_roles.push("workflow".to_string());
    }
    if request.code_diff.is_some() {
        changed_roles.push("code".to_string());
    }
    WorkflowProposalSidecarDiff {
        tests_changed: false,
        fixtures_changed: false,
        functions_changed: request.code_diff.is_some(),
        bindings_changed: false,
        proposals_changed: true,
        changed_roles,
    }
}

fn workflow_proposal_graph_changed_ids(diff: &WorkflowProposalGraphDiff) -> Vec<String> {
    diff.added_node_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .chain(diff.removed_node_ids.clone().unwrap_or_default())
        .chain(diff.changed_node_ids.clone().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn workflow_proposal_bounds_allow_all(bounded_targets: &[String], aliases: &[&str]) -> bool {
    bounded_targets
        .iter()
        .any(|target| aliases.iter().any(|alias| target.as_str() == *alias))
}

fn validate_workflow_proposal_patch_bounds(
    current: &WorkflowProject,
    proposed: &WorkflowProject,
    proposal: &WorkflowProposal,
) -> Result<(), String> {
    let graph_diff = workflow_proposal_graph_diff(current, proposed);
    let changed_node_ids = workflow_proposal_graph_changed_ids(&graph_diff);
    let bounded_targets = proposal
        .bounded_targets
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let graph_wide_bound =
        workflow_proposal_bounds_allow_all(&proposal.bounded_targets, &["workflow", "graph"]);
    let unauthorized_nodes = if graph_wide_bound {
        Vec::new()
    } else {
        changed_node_ids
            .iter()
            .filter(|node_id| !bounded_targets.contains(*node_id))
            .cloned()
            .collect::<Vec<_>>()
    };
    let config_diff = workflow_proposal_config_diff(current, proposed);
    let global_config_allowed = workflow_proposal_bounds_allow_all(
        &proposal.bounded_targets,
        &["workflow", "workflow-config", "global-config"],
    );
    let metadata_allowed = workflow_proposal_bounds_allow_all(
        &proposal.bounded_targets,
        &["workflow", "workflow-metadata", "metadata"],
    );
    let mut blockers = Vec::new();
    if !unauthorized_nodes.is_empty() {
        blockers.push(format!(
            "node changes outside bounded targets: {}",
            unauthorized_nodes.join(", ")
        ));
    }
    if !config_diff.changed_global_keys.is_empty() && !global_config_allowed {
        blockers.push(format!(
            "workflow config changes require workflow-config bound: {}",
            config_diff.changed_global_keys.join(", ")
        ));
    }
    if !config_diff.changed_metadata_keys.is_empty() && !metadata_allowed {
        blockers.push(format!(
            "workflow metadata changes require workflow-metadata bound: {}",
            config_diff.changed_metadata_keys.join(", ")
        ));
    }
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Workflow proposal '{}' cannot be applied because its patch exceeds declared bounds: {}.",
            proposal.id,
            blockers.join("; ")
        ))
    }
}

#[tauri::command]
pub fn create_workflow_proposal(
    path: String,
    request: CreateWorkflowProposalRequest,
) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let current_bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let proposals_dir = workflow_proposals_dir(&workflow_path);
    fs::create_dir_all(&proposals_dir).map_err(|error| {
        format!(
            "Failed to create proposals directory '{}': {}",
            proposals_dir.display(),
            error
        )
    })?;
    let created_at_ms = now_ms();
    let graph_diff = request
        .workflow_patch
        .as_ref()
        .map(|workflow_patch| {
            workflow_proposal_graph_diff(&current_bundle.workflow, workflow_patch)
        })
        .unwrap_or(WorkflowProposalGraphDiff {
            added_node_ids: None,
            removed_node_ids: None,
            changed_node_ids: Some(request.bounded_targets.clone()),
        });
    let config_diff = request.workflow_patch.as_ref().map(|workflow_patch| {
        workflow_proposal_config_diff(&current_bundle.workflow, workflow_patch)
    });
    let sidecar_diff = workflow_proposal_sidecar_diff(&request);
    let proposal = WorkflowProposal {
        id: format!("proposal-{}", created_at_ms),
        title: request.title,
        summary: request.summary,
        status: "open".to_string(),
        created_at_ms,
        bounded_targets: request.bounded_targets.clone(),
        graph_diff: Some(graph_diff),
        config_diff,
        sidecar_diff: Some(sidecar_diff),
        code_diff: request.code_diff,
        workflow_patch: request.workflow_patch,
    };
    let proposal_path = proposals_dir.join(format!("{}.proposal.json", proposal.id));
    write_json_pretty(&proposal_path, &proposal)?;
    append_workflow_evidence(
        &workflow_path,
        WorkflowEvidenceSummary {
            id: proposal.id.clone(),
            kind: "proposal".to_string(),
            created_at_ms,
            summary: proposal.summary.clone(),
            path: Some(proposal_path.display().to_string()),
        },
    )?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn create_workflow_repair_proposal(
    path: String,
    validation_issue_ids: Vec<String>,
) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let validation = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let bounded_targets = validation
        .warnings
        .iter()
        .chain(validation.errors.iter())
        .filter(|issue| {
            validation_issue_ids.is_empty()
                || validation_issue_ids.iter().any(|id| id == &issue.code)
        })
        .filter_map(|issue| issue.node_id.clone())
        .collect::<Vec<_>>();
    create_workflow_proposal(
        workflow_path.display().to_string(),
        CreateWorkflowProposalRequest {
            title: "Repair workflow blockers".to_string(),
            summary: "Bounded repair proposal for the selected validation blockers.".to_string(),
            bounded_targets,
            workflow_patch: Some(bundle.workflow),
            code_diff: Some(
                "Workflow graph/config repair only; apply requires explicit confirmation."
                    .to_string(),
            ),
        },
    )
}

#[tauri::command]
pub fn run_workflow_dogfood_suite(
    project_root: String,
    suite_id: String,
    _options: Option<Value>,
) -> Result<WorkflowDogfoodRun, String> {
    let started_at_ms = now_ms();
    let output_dir = std::env::temp_dir()
        .join("autopilot-heavy-workflows")
        .join(format!("{}-{}", suite_id, started_at_ms));
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("Failed to create dogfood output directory: {}", error))?;
    let template_ids = [
        "heavy-repo-test-engineer",
        "heavy-mcp-research-operator",
        "heavy-connector-triage",
        "heavy-financial-close",
        "heavy-media-transform",
        "heavy-scheduled-reporter",
        "heavy-self-improving-proposal",
    ];
    let mut workflow_paths = Vec::new();
    let mut ledger_entries = Vec::<WorkflowGapLedgerEntry>::new();
    for template_id in template_ids {
        let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
            project_root: project_root.clone(),
            template_id: template_id.to_string(),
            name: None,
        })?;
        workflow_paths.push(bundle.workflow_path.clone());
        let validation = validate_workflow_bundle(bundle.workflow_path.clone())?;
        if validation.status != "passed" {
            ledger_entries.push(WorkflowGapLedgerEntry {
                id: unique_runtime_id("gap"),
                workflow_id: template_id.to_string(),
                severity: "blocking".to_string(),
                area: "validation".to_string(),
                summary: format!("Validation {} before run.", validation.status),
                status: "open".to_string(),
            });
            continue;
        }
        let tests = run_workflow_tests(bundle.workflow_path.clone(), None)?;
        if tests.status != "passed" {
            ledger_entries.push(WorkflowGapLedgerEntry {
                id: unique_runtime_id("gap"),
                workflow_id: template_id.to_string(),
                severity: "blocking".to_string(),
                area: "validation".to_string(),
                summary: format!("Unit tests {}.", tests.status),
                status: "open".to_string(),
            });
        }
        let mut run = run_workflow_project(bundle.workflow_path.clone(), None)?;
        for _approval in 0..8 {
            if run.summary.status != "interrupted" {
                break;
            }
            let Some(interrupt) = run.interrupt.clone() else {
                break;
            };
            run = resume_workflow_run(
                bundle.workflow_path.clone(),
                WorkflowResumeRequest {
                    run_id: Some(run.summary.id.clone()),
                    thread_id: run.thread.id.clone(),
                    node_id: None,
                    interrupt_id: Some(interrupt.id),
                    checkpoint_id: run.thread.latest_checkpoint_id.clone(),
                    outcome: "approve".to_string(),
                    edited_state: None,
                },
            )?;
        }
        let final_status = run.summary.status.clone();
        if final_status != "passed" {
            ledger_entries.push(WorkflowGapLedgerEntry {
                id: unique_runtime_id("gap"),
                workflow_id: template_id.to_string(),
                severity: "blocking".to_string(),
                area: "runtime".to_string(),
                summary: format!("Run ended with status {}.", final_status),
                status: "open".to_string(),
            });
        }
    }
    if ledger_entries.is_empty() {
        ledger_entries.push(WorkflowGapLedgerEntry {
            id: unique_runtime_id("gap"),
            workflow_id: "suite".to_string(),
            severity: "info".to_string(),
            area: "runtime".to_string(),
            summary:
                "All heavy workflow targets created, tested, and run through typed workflow APIs."
                    .to_string(),
            status: "closed".to_string(),
        });
    }
    let gap_ledger_path = output_dir.join("gap-ledger.json");
    write_json_pretty(&gap_ledger_path, &ledger_entries)?;
    Ok(WorkflowDogfoodRun {
        id: unique_runtime_id("workflow-dogfood"),
        suite_id,
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        status: if ledger_entries.iter().any(|entry| entry.status == "open") {
            "blocked".to_string()
        } else {
            "passed".to_string()
        },
        output_dir: output_dir.display().to_string(),
        workflow_paths,
        gap_ledger_path: gap_ledger_path.display().to_string(),
    })
}

#[tauri::command]
pub fn apply_workflow_proposal(
    path: String,
    proposal_id: String,
) -> Result<WorkflowWorkbenchBundle, String> {
    let workflow_path = resolve_workflow_file_path(&path)?;
    let proposals_dir = workflow_proposals_dir(&workflow_path);
    let proposal_path = proposals_dir.join(format!("{}.proposal.json", proposal_id));
    if !proposal_path.exists() {
        return Err(format!("Unknown workflow proposal '{}'.", proposal_id));
    }
    let mut proposal: WorkflowProposal = read_json_file(&proposal_path)?;
    let Some(workflow_patch) = proposal.workflow_patch.clone() else {
        return Err(format!(
            "Workflow proposal '{}' does not include an applicable workflow patch.",
            proposal_id
        ));
    };
    let current_bundle = load_workflow_bundle_from_path(&workflow_path)?;
    let mut workflow_patch = workflow_patch;
    normalize_legacy_workflow_output_nodes(&mut workflow_patch);
    validate_workflow_proposal_patch_bounds(&current_bundle.workflow, &workflow_patch, &proposal)?;
    proposal.graph_diff = Some(workflow_proposal_graph_diff(
        &current_bundle.workflow,
        &workflow_patch,
    ));
    proposal.config_diff = Some(workflow_proposal_config_diff(
        &current_bundle.workflow,
        &workflow_patch,
    ));
    write_json_pretty(&workflow_path, &workflow_patch)?;
    proposal.status = "applied".to_string();
    write_json_pretty(&proposal_path, &proposal)?;
    load_workflow_bundle_from_path(&workflow_path)
}

#[tauri::command]
pub fn project_shell_inspect(root: String) -> Result<ProjectShellSnapshot, String> {
    let root_path = resolve_root_path(&root, false)?;
    Ok(inspect_project_root(&root_path))
}

#[tauri::command]
pub fn project_initialize_repository(root: String) -> Result<ProjectShellSnapshot, String> {
    let root_path = resolve_root_path(&root, true)?;

    if !inspect_git(&root_path).is_repo {
        run_git(&root_path, &["init"])?;
    }

    let gitignore_path = root_path.join(".gitignore");
    if !gitignore_path.exists() {
        fs::write(&gitignore_path, default_gitignore()).map_err(|error| {
            format!(
                "Failed to write default .gitignore at '{}': {}",
                gitignore_path.display(),
                error
            )
        })?;
    }

    Ok(inspect_project_root(&root_path))
}

#[tauri::command]
pub fn project_shell_list_directory(
    root: String,
    directory: String,
) -> Result<Vec<ProjectExplorerNode>, String> {
    let root_path = resolve_root_path(&root, false)?;
    let directory_path = if directory.is_empty() || directory == "." {
        root_path.clone()
    } else {
        resolve_scoped_existing_path(&root_path, &directory)?
    };

    if !directory_path.is_dir() {
        return Err(format!(
            "'{}' is not a directory inside the project boundary.",
            directory_path.display()
        ));
    }

    Ok(build_directory_listing(&root_path, &directory_path))
}

#[tauri::command]
pub fn project_read_file(
    root: String,
    relative_path: String,
) -> Result<ProjectFileDocument, String> {
    let root_path = resolve_root_path(&root, false)?;
    read_project_file_document(&root_path, &relative_path)
}

#[tauri::command]
pub fn project_write_file(
    root: String,
    relative_path: String,
    content: String,
) -> Result<ProjectFileDocument, String> {
    let root_path = resolve_root_path(&root, false)?;
    let file_path = resolve_scoped_existing_path(&root_path, &relative_path)?;

    if file_path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an editable file.",
            file_path.display()
        ));
    }

    fs::write(&file_path, content.as_bytes())
        .map_err(|error| format!("Failed to save '{}': {}", file_path.display(), error))?;

    read_project_file_document(&root_path, &relative_path)
}
