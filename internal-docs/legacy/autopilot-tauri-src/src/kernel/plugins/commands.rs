use super::*;

#[tauri::command]
pub async fn get_session_plugin_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let current_task = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .current_task
        .clone();

    let session_id = normalized_optional_text(session_id).or_else(|| {
        current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())))
    });
    let workspace_root = normalized_optional_text(workspace_root)
        .or_else(|| current_task.as_ref().and_then(workspace_root_from_task));

    let snapshot = plugin_capability_snapshot(state, policy_manager).await?;
    Ok(build_session_plugin_snapshot(
        snapshot,
        plugin_runtime.snapshot(),
        session_id,
        workspace_root,
    ))
}

pub(crate) fn find_manifest<'a>(
    snapshot: &'a CapabilityRegistrySnapshot,
    plugin_id: &str,
) -> Result<&'a ExtensionManifestRecord, String> {
    snapshot
        .extension_manifests
        .iter()
        .find(|manifest| manifest.extension_id == plugin_id)
        .ok_or_else(|| {
            format!(
                "Plugin '{}' is not present in the manifest inventory.",
                plugin_id
            )
        })
}

pub(crate) fn normalize_plugin_id(value: String) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Plugin id is required.".to_string());
    }
    Ok(trimmed.to_string())
}

pub(crate) async fn plugin_snapshot_for_context(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    get_session_plugin_snapshot(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn trust_session_plugin(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    enable_after_trust: Option<bool>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.trust_plugin(&manifest, enable_after_trust.unwrap_or(true))?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn set_session_plugin_enabled(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    enabled: bool,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.set_plugin_enabled(&manifest, enabled)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn reload_session_plugin(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.reload_plugin(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn refresh_session_plugin_catalog(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    let refresh_target = plugin_marketplace_fixture_path()
        .ok_or_else(|| {
            "Signed plugin catalog refresh requires IOI_PLUGIN_MARKETPLACE_FIXTURE_PATH."
                .to_string()
        })
        .and_then(|fixture_path| {
            load_plugin_marketplace_catalog_refresh_target_from_path(&fixture_path, &plugin_id)
        });
    plugin_runtime.refresh_plugin_catalog(&manifest, refresh_target)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn revoke_session_plugin_trust(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.revoke_plugin_trust(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn install_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.install_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn update_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.update_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn remove_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.remove_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}
