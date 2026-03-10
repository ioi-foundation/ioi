use super::*;

#[tauri::command]
pub async fn automation_create_monitor(
    manager: State<'_, WorkflowManager>,
    request: CreateMonitorRequest,
) -> Result<InstalledWorkflowSummary, String> {
    let artifact = compile_monitor_request(request)?;
    manager
        .install_workflow(artifact, Some("automation.create_monitor"))
        .await
}

#[tauri::command]
pub async fn workflow_install(
    manager: State<'_, WorkflowManager>,
    artifact: WorkflowArtifact,
) -> Result<InstalledWorkflowSummary, String> {
    manager.install_workflow(artifact, None).await
}

#[tauri::command]
pub async fn workflow_list(
    manager: State<'_, WorkflowManager>,
) -> Result<Vec<InstalledWorkflowSummary>, String> {
    manager.list_workflows().await
}

#[tauri::command]
pub async fn workflow_get(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<InstalledWorkflowDetail, String> {
    manager
        .get_workflow(&workflow_id)
        .await?
        .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))
}

#[tauri::command]
pub async fn workflow_pause(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<InstalledWorkflowSummary, String> {
    manager.pause_workflow(&workflow_id).await
}

#[tauri::command]
pub async fn workflow_resume(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<InstalledWorkflowSummary, String> {
    manager.resume_workflow(&workflow_id).await
}

#[tauri::command]
pub async fn workflow_delete(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<InstalledWorkflowSummary, String> {
    manager.delete_workflow(&workflow_id).await
}

#[tauri::command]
pub async fn workflow_run_now(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<WorkflowRunReceipt, String> {
    manager.run_workflow_now(&workflow_id).await
}

#[tauri::command]
pub async fn workflow_export_project(
    manager: State<'_, WorkflowManager>,
    workflow_id: String,
) -> Result<WorkflowProjectFile, String> {
    manager.export_project(&workflow_id).await
}
