fn app_memory_runtime(
    state: &State<'_, Mutex<AppState>>,
) -> Option<std::sync::Arc<ioi_memory::MemoryRuntime>> {
    state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
}

#[tauri::command]
pub async fn get_available_tools(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    collect_available_tools(&state).await
}

async fn collect_available_tools(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    let mut tools = execution::get_active_mcp_tools().await;
    let mut existing = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<std::collections::HashSet<_>>();
    tools.extend(
        ioi_services::agentic::runtime::connectors::google_workspace::google_connector_tool_definitions()
            .into_iter()
            .filter(|tool| !existing.contains(&tool.name)),
    );
    existing.extend(tools.iter().map(|tool| tool.name.clone()));

    if let Ok(mut client) = get_rpc_client(&state).await {
        if let Ok(skill_catalog) = load_skill_catalog_entries(&mut client).await {
            for entry in skill_catalog {
                if entry.stale || entry.lifecycle_state == "Deprecated" {
                    continue;
                }
                if existing.insert(entry.definition.name.clone()) {
                    tools.push(entry.definition);
                }
            }
        }
    }

    Ok(tools)
}
