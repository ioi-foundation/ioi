use super::*;

pub(crate) fn plugin_display_label(manifest: &ExtensionManifestRecord) -> String {
    manifest
        .display_name
        .clone()
        .unwrap_or_else(|| manifest.name.clone())
}

pub(crate) fn safe_plugin_fs_segment(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_dash = false;
    for ch in value.chars() {
        let allowed = ch.is_ascii_alphanumeric();
        if allowed {
            output.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}

pub(crate) fn managed_plugin_root_for(state_path: &Path, plugin_id: &str) -> PathBuf {
    let safe_id = safe_plugin_fs_segment(plugin_id);
    let slug = if safe_id.is_empty() {
        "plugin".to_string()
    } else {
        safe_id
    };
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(MANAGED_PLUGIN_PACKAGES_DIR)
        .join(slug)
}

pub(crate) fn copy_directory_contents(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {}", destination.display(), error))?;
    let entries = fs::read_dir(source)
        .map_err(|error| format!("Failed to read {}: {}", source.display(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_name = entry.file_name();
        let destination_path = destination.join(&file_name);
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if IGNORED_PACKAGE_COPY_DIRS
                .iter()
                .any(|ignored| ignored == &name)
            {
                continue;
            }
            copy_directory_contents(&path, &destination_path)?;
            continue;
        }
        if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("Failed to create {}: {}", parent.display(), error))?;
            }
            fs::copy(&path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy {} to {}: {}",
                    path.display(),
                    destination_path.display(),
                    error
                )
            })?;
        }
    }
    Ok(())
}

pub(crate) fn write_manifest_version(
    manifest_path: &Path,
    version: Option<&str>,
) -> Result<(), String> {
    let Some(version) = version.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let raw = fs::read_to_string(manifest_path)
        .map_err(|error| format!("Failed to read {}: {}", manifest_path.display(), error))?;
    let mut parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", manifest_path.display(), error))?;
    let object = parsed
        .as_object_mut()
        .ok_or_else(|| format!("Manifest {} is not a JSON object.", manifest_path.display()))?;
    object.insert(
        "version".to_string(),
        serde_json::Value::String(version.to_string()),
    );
    let next = serde_json::to_vec_pretty(&parsed)
        .map_err(|error| format!("Failed to encode {}: {}", manifest_path.display(), error))?;
    fs::write(manifest_path, next)
        .map_err(|error| format!("Failed to write {}: {}", manifest_path.display(), error))?;
    Ok(())
}

pub(crate) fn install_managed_plugin_package(
    source_root: &Path,
    managed_root: &Path,
    managed_manifest_path: &Path,
    version_override: Option<&str>,
) -> Result<(), String> {
    if !source_root.exists() {
        return Err(format!(
            "Tracked source '{}' is unavailable, so the managed package copy could not be prepared.",
            source_root.display()
        ));
    }
    if managed_root.exists() {
        fs::remove_dir_all(managed_root)
            .map_err(|error| format!("Failed to clear {}: {}", managed_root.display(), error))?;
    }
    copy_directory_contents(source_root, managed_root)?;
    write_manifest_version(managed_manifest_path, version_override)?;
    Ok(())
}

pub(crate) fn install_managed_plugin_package_from_archive(
    archive_location: &str,
    managed_root: &Path,
    managed_manifest_path: &Path,
    version_override: Option<&str>,
) -> Result<(), String> {
    with_extracted_plugin_archive(
        archive_location,
        "plugin marketplace package archive",
        |plugin_root| {
            install_managed_plugin_package(
                plugin_root,
                managed_root,
                managed_manifest_path,
                version_override,
            )
        },
    )
}

pub(crate) fn remove_managed_plugin_package(managed_root: PathBuf) -> Result<(), String> {
    if !managed_root.exists() {
        return Ok(());
    }
    fs::remove_dir_all(&managed_root)
        .map_err(|error| format!("Failed to remove {}: {}", managed_root.display(), error))
}

pub(crate) fn package_install_source(manifest: &ExtensionManifestRecord) -> (String, String) {
    if let Some(display_name) = manifest
        .marketplace_display_name
        .clone()
        .or_else(|| manifest.marketplace_name.clone())
    {
        if manifest.marketplace_package_url.is_some() {
            return ("marketplace_remote".to_string(), display_name);
        }
        return ("marketplace".to_string(), display_name);
    }
    if manifest.source_kind.contains("home") {
        return ("home_plugins".to_string(), "Home plugins".to_string());
    }
    if manifest.source_kind.contains("workspace") {
        return ("workspace".to_string(), "Workspace source".to_string());
    }
    ("tracked_source".to_string(), manifest.source_label.clone())
}

pub(crate) fn normalize_path_like(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    let normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(crate) fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

pub(crate) fn scope_matches_workspace(
    workspace_root: Option<&str>,
    manifest: &ExtensionManifestRecord,
) -> bool {
    let Some(workspace_root) = workspace_root.and_then(normalize_path_like) else {
        return false;
    };
    let manifest_roots = [
        manifest.root_path.as_str(),
        manifest.source_uri.as_str(),
        manifest.manifest_path.as_str(),
    ];

    manifest_roots.iter().any(|candidate| {
        let Some(candidate) = normalize_path_like(candidate) else {
            return false;
        };
        workspace_root.starts_with(&candidate) || candidate.starts_with(&workspace_root)
    })
}

pub(crate) fn reloadable(manifest: &ExtensionManifestRecord) -> bool {
    Path::new(&manifest.root_path).exists() || Path::new(&manifest.manifest_path).exists()
}

pub(crate) fn session_scope_label(
    workspace_root: Option<&str>,
    manifest: &ExtensionManifestRecord,
) -> String {
    if scope_matches_workspace(workspace_root, manifest) {
        "Matches current workspace".to_string()
    } else if manifest.source_kind.contains("home") {
        "Home plugin source".to_string()
    } else if manifest.source_kind.contains("workspace") {
        "Workspace plugin source".to_string()
    } else {
        "Shared runtime inventory".to_string()
    }
}

pub(crate) fn reloadability_label(manifest: &ExtensionManifestRecord, can_reload: bool) -> String {
    if can_reload && manifest.enabled {
        "Reloadable from tracked source".to_string()
    } else if can_reload {
        "Source present for enable or reload".to_string()
    } else {
        "Static manifest inventory".to_string()
    }
}

pub fn plugin_runtime_state_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join(PLUGIN_RUNTIME_STATE_FILE)
}

pub(crate) fn load_plugin_runtime_state(path: &Path) -> Result<PluginRuntimeState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read plugin runtime state: {}", error))?;
    let parsed: PluginRuntimeState = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse plugin runtime state: {}", error))?;
    Ok(normalize_plugin_runtime_state(parsed))
}

pub(crate) fn persist_plugin_runtime_state(
    path: &Path,
    state: &PluginRuntimeState,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create plugin runtime directory: {}", error))?;
    }
    let raw = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to serialize plugin runtime state: {}", error))?;
    fs::write(path, raw)
        .map_err(|error| format!("Failed to persist plugin runtime state: {}", error))?;
    Ok(())
}

pub(crate) fn normalize_plugin_runtime_state(input: PluginRuntimeState) -> PluginRuntimeState {
    let mut plugins = BTreeMap::new();
    for record in input.plugins {
        plugins.insert(record.plugin_id.clone(), record);
    }
    let mut recent_receipts = input.recent_receipts;
    recent_receipts.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    if recent_receipts.len() > MAX_PLUGIN_RUNTIME_RECEIPTS {
        recent_receipts.truncate(MAX_PLUGIN_RUNTIME_RECEIPTS);
    }
    PluginRuntimeState {
        plugins: plugins.into_values().collect(),
        recent_receipts,
    }
}

pub(crate) fn push_plugin_receipt(
    state: &mut PluginRuntimeState,
    receipt: SessionPluginLifecycleReceipt,
) {
    state.recent_receipts.insert(0, receipt);
    if state.recent_receipts.len() > MAX_PLUGIN_RUNTIME_RECEIPTS {
        state.recent_receipts.truncate(MAX_PLUGIN_RUNTIME_RECEIPTS);
    }
}

pub(crate) fn runtime_record_lookup(
    state: &PluginRuntimeState,
) -> HashMap<String, PluginRuntimeRecord> {
    state
        .plugins
        .iter()
        .map(|record| (record.plugin_id.clone(), record.clone()))
        .collect()
}

pub(crate) fn plugin_runtime_trust_label(trust_state: &str) -> String {
    match trust_state {
        "trusted" => "Remembered trust granted".to_string(),
        "revoked" => "Trust revoked".to_string(),
        _ => "Trust required".to_string(),
    }
}

pub(crate) fn plugin_runtime_load_state(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
    can_reload: bool,
) -> (bool, String, String, String, Option<String>) {
    let record = runtime_record
        .cloned()
        .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));
    let trust_state = record.trust_state.as_str();
    let trusted = trust_state == "trusted";

    if trust_state == "revoked" {
        return (
            false,
            "blocked".to_string(),
            "Blocked by revoked trust".to_string(),
            "Runtime trust was revoked, so this plugin will not load until an operator trusts it again.".to_string(),
            record.load_error.or_else(|| {
                Some("Trust revoked. Grant trust again before enabling or reloading this plugin.".to_string())
            }),
        );
    }

    if !trusted {
        return (
            false,
            "blocked".to_string(),
            "Trust required before load".to_string(),
            "Manifest inventory is present, but runtime load is gated until an operator grants remembered trust.".to_string(),
            record
                .load_error
                .or_else(|| Some("Trust this plugin before enabling or reloading it in runtime.".to_string())),
        );
    }

    if !record.enabled {
        return (
            false,
            "disabled".to_string(),
            "Trusted but disabled".to_string(),
            "Remembered trust exists, but runtime load is currently disabled for this plugin."
                .to_string(),
            record.load_error,
        );
    }

    if !manifest.enabled {
        return (
            false,
            "blocked".to_string(),
            "Tracked source disabled".to_string(),
            "The tracked source is disabled, so runtime load is paused even though remembered trust exists.".to_string(),
            record.load_error.or_else(|| {
                Some("The tracked source is disabled, so runtime load cannot start yet.".to_string())
            }),
        );
    }

    if can_reload {
        return (
            true,
            "ready".to_string(),
            "Loaded from remembered trust".to_string(),
            "Runtime load is active and the tracked source is available for safe reloads."
                .to_string(),
            record.load_error,
        );
    }

    (
        true,
        "degraded".to_string(),
        "Loaded without a reloadable source".to_string(),
        "Runtime load is active, but the tracked source is not currently available for reload."
            .to_string(),
        record.load_error.or_else(|| {
            Some(
                "Tracked source is unavailable, so runtime reload could not be completed."
                    .to_string(),
            )
        }),
    )
}

pub(crate) fn marketplace_available_version(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
) -> Option<String> {
    runtime_record
        .and_then(|record| record.available_version.clone())
        .or_else(|| manifest.marketplace_available_version.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn package_update_available(
    runtime_record: Option<&PluginRuntimeRecord>,
    manifest: &ExtensionManifestRecord,
) -> bool {
    let Some(available_version) = marketplace_available_version(manifest, runtime_record) else {
        return false;
    };
    let installed_version = runtime_record
        .and_then(|record| record.installed_version.clone())
        .or_else(|| manifest.version.clone())
        .unwrap_or_default();
    available_version != installed_version.trim()
}

#[allow(clippy::type_complexity)]
pub(crate) fn plugin_package_state(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
) -> (
    bool,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    let update_available = package_update_available(runtime_record, manifest);
    let record = runtime_record.cloned();
    let package_managed = record
        .as_ref()
        .map(|item| item.package_managed)
        .unwrap_or(false);
    let installed_version = record
        .as_ref()
        .and_then(|item| item.installed_version.clone());
    let available_version = marketplace_available_version(manifest, runtime_record);
    let package_install_source_value = record
        .as_ref()
        .and_then(|item| item.package_install_source.clone());
    let package_install_source_label = record
        .as_ref()
        .and_then(|item| item.package_install_source_label.clone());
    let package_root_path = record
        .as_ref()
        .and_then(|item| item.package_root_path.clone());
    let package_manifest_path = record
        .as_ref()
        .and_then(|item| item.package_manifest_path.clone());
    let package_error = record.as_ref().and_then(|item| item.package_error.clone());
    let last_installed_at_ms = record.as_ref().and_then(|item| item.last_installed_at_ms);
    let last_updated_at_ms = record.as_ref().and_then(|item| item.last_updated_at_ms);
    let last_removed_at_ms = record.as_ref().and_then(|item| item.last_removed_at_ms);

    if package_managed {
        let install_label = if update_available {
            "Package update available".to_string()
        } else {
            "Managed package installed".to_string()
        };
        let install_detail = if update_available {
            format!(
                "A profile-local managed package copy is installed at {} and update {} is ready to apply.",
                installed_version
                    .clone()
                    .or_else(|| manifest.version.clone())
                    .unwrap_or_else(|| "an unknown version".to_string()),
                available_version
                    .clone()
                    .unwrap_or_else(|| "a newer version".to_string())
            )
        } else {
            format!(
                "A profile-local managed package copy is installed so this plugin can move into packaged update flow without changing the tracked source manifest."
            )
        };
        return (
            true,
            if update_available {
                "update_available".to_string()
            } else {
                "installed".to_string()
            },
            install_label,
            install_detail,
            package_install_source_value,
            package_install_source_label,
            package_root_path,
            package_manifest_path,
            installed_version,
            available_version,
            update_available,
            package_error,
            last_installed_at_ms,
            last_updated_at_ms,
            last_removed_at_ms,
        );
    }

    if last_removed_at_ms.is_some() {
        return (
            false,
            "removed".to_string(),
            "Managed package removed".to_string(),
            "The profile-local managed package copy was removed. The tracked source manifest still exists and can be installed again later.".to_string(),
            package_install_source_value,
            package_install_source_label,
            None,
            None,
            None,
            available_version,
            false,
            package_error,
            last_installed_at_ms,
            last_updated_at_ms,
            last_removed_at_ms,
        );
    }

    let (install_source, install_source_label) = package_install_source(manifest);
    let install_label = if manifest.marketplace_installation_policy.is_some() {
        "Ready for managed install".to_string()
    } else {
        "Tracked source only".to_string()
    };
    let install_detail = if let Some(policy) = manifest.marketplace_installation_policy.as_ref() {
        format!(
            "{} advertises {} installation policy. Install a profile-local managed package copy to track updates and trust posture without mutating the tracked source manifest.",
            plugin_display_label(manifest),
            policy.replace('_', " ")
        )
    } else {
        "This plugin is currently visible from its tracked source only. Install a profile-local managed package copy to track packaged updates and removal separately from runtime trust."
            .to_string()
    };
    (
        false,
        "installable".to_string(),
        install_label,
        install_detail,
        Some(install_source),
        Some(install_source_label),
        None,
        None,
        None,
        available_version,
        false,
        package_error,
        last_installed_at_ms,
        last_updated_at_ms,
        last_removed_at_ms,
    )
}

pub(crate) fn entry_lookup(
    entries: &[CapabilityRegistryEntry],
) -> HashMap<String, CapabilityRegistryEntry> {
    entries
        .iter()
        .filter(|entry| entry.kind == "extension")
        .map(|entry| (entry.entry_id.clone(), entry.clone()))
        .collect()
}

pub(crate) fn merge_catalog_channel_record(
    existing: &mut SessionPluginCatalogChannelRecord,
    incoming: SessionPluginCatalogChannelRecord,
) {
    if catalog_channel_status_severity(&incoming.status)
        > catalog_channel_status_severity(&existing.status)
    {
        existing.status = incoming.status;
        existing.status_label = incoming.status_label;
        existing.status_detail = incoming.status_detail;
    }
    existing.plugin_count = existing.plugin_count.max(incoming.plugin_count);
    existing.valid_plugin_count = existing.valid_plugin_count.max(incoming.valid_plugin_count);
    existing.invalid_plugin_count = existing
        .invalid_plugin_count
        .max(incoming.invalid_plugin_count);
    existing.refresh_bundle_count = existing
        .refresh_bundle_count
        .max(incoming.refresh_bundle_count);
    if existing.refresh_error.is_none() {
        existing.refresh_error = incoming.refresh_error;
    }
    if existing.refresh_source.is_none() {
        existing.refresh_source = incoming.refresh_source;
    }
    if existing.issued_at_ms.is_none() {
        existing.issued_at_ms = incoming.issued_at_ms;
    }
    if existing.expires_at_ms.is_none() {
        existing.expires_at_ms = incoming.expires_at_ms;
    }
    existing.refreshed_at_ms = existing.refreshed_at_ms.max(incoming.refreshed_at_ms);
    if incoming.conformance_status != "conformant" {
        existing.conformance_status = incoming.conformance_status;
        existing.conformance_label = incoming.conformance_label;
        if existing.conformance_error.is_none() {
            existing.conformance_error = incoming.conformance_error;
        }
        if catalog_channel_status_severity("nonconformant")
            > catalog_channel_status_severity(&existing.status)
        {
            existing.status = "nonconformant".to_string();
            existing.status_label = "Nonconformant channel".to_string();
            existing.status_detail = existing.conformance_error.clone().unwrap_or_else(|| {
                format!(
                    "Marketplace catalog '{}' is not conformant yet.",
                    existing.label
                )
            });
        }
    }
}

pub(crate) fn catalog_channel_records_from_manifests(
    extension_manifests: &[ExtensionManifestRecord],
    runtime_lookup: &HashMap<String, PluginRuntimeRecord>,
    now_ms: u64,
) -> Vec<SessionPluginCatalogChannelRecord> {
    let mut grouped = BTreeMap::<String, SessionPluginCatalogChannelRecord>::new();
    for manifest in extension_manifests {
        let Some(catalog_id) = manifest.marketplace_name.clone() else {
            continue;
        };
        let source_uri = manifest.source_uri.clone();
        let channel = manifest.marketplace_catalog_channel.clone();
        let key = catalog_channel_key(&catalog_id, &source_uri, channel.as_deref());
        let signal =
            plugin_catalog_signal(manifest, runtime_lookup.get(&manifest.extension_id), now_ms);
        let record = SessionPluginCatalogChannelRecord {
            catalog_id,
            label: manifest
                .marketplace_display_name
                .clone()
                .unwrap_or_else(|| manifest.source_label.clone()),
            source_uri,
            refresh_source: signal.refresh_source.clone(),
            channel,
            status: signal.status,
            status_label: signal.label,
            status_detail: signal.detail,
            issued_at_ms: signal.issued_at_ms,
            expires_at_ms: signal.expires_at_ms,
            refreshed_at_ms: signal.refreshed_at_ms,
            plugin_count: 1,
            valid_plugin_count: 1,
            invalid_plugin_count: 0,
            refresh_bundle_count: usize::from(
                manifest.marketplace_catalog_refresh_bundle_id.is_some(),
            ),
            refresh_error: runtime_lookup
                .get(&manifest.extension_id)
                .and_then(|record| record.catalog_refresh_error.clone()),
            conformance_status: "conformant".to_string(),
            conformance_label: "Conformant channel".to_string(),
            conformance_error: None,
        };
        if let Some(existing) = grouped.get_mut(&key) {
            existing.plugin_count += 1;
            existing.valid_plugin_count += 1;
            existing.refresh_bundle_count += record.refresh_bundle_count;
            merge_catalog_channel_record(existing, record);
        } else {
            grouped.insert(key, record);
        }
    }
    grouped.into_values().collect()
}

pub(crate) fn marketplace_catalog_channel_records_for_fixture_path(
    fixture_path: Option<&Path>,
) -> Vec<SessionPluginCatalogChannelRecord> {
    fixture_path
        .and_then(|path| load_plugin_marketplace_feed_catalog_channels_from_path(path).ok())
        .unwrap_or_default()
}

pub(crate) fn merge_catalog_channels(
    mut derived: Vec<SessionPluginCatalogChannelRecord>,
    overlays: Vec<SessionPluginCatalogChannelRecord>,
) -> Vec<SessionPluginCatalogChannelRecord> {
    let mut grouped = BTreeMap::<String, SessionPluginCatalogChannelRecord>::new();
    for record in derived.drain(..) {
        let key = catalog_channel_key(
            &record.catalog_id,
            &record.source_uri,
            record.channel.as_deref(),
        );
        grouped.insert(key, record);
    }
    for overlay in overlays {
        let key = catalog_channel_key(
            &overlay.catalog_id,
            &overlay.source_uri,
            overlay.channel.as_deref(),
        );
        if let Some(existing) = grouped.get_mut(&key) {
            merge_catalog_channel_record(existing, overlay);
        } else {
            grouped.insert(key, overlay);
        }
    }
    let mut records = grouped.into_values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        catalog_channel_status_severity(&right.status)
            .cmp(&catalog_channel_status_severity(&left.status))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.channel.cmp(&right.channel))
    });
    records
}
