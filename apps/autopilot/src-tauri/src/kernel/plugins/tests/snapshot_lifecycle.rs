use super::*;

#[test]
fn session_plugin_snapshot_collects_manifest_inventory() {
    let temp_root =
        std::env::temp_dir().join(format!("autopilot-plugin-snapshot-{}", std::process::id()));
    let plugin_root = temp_root.join("plugin-alpha");
    std::fs::create_dir_all(plugin_root.join(".codex-plugin")).expect("create plugin root");
    let manifest_path = plugin_root.join(".codex-plugin/plugin.json");
    std::fs::write(&manifest_path, "{}").expect("write manifest");

    let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);

    let plugin_snapshot = build_session_plugin_snapshot(
        snapshot,
        PluginRuntimeState::default(),
        Some("session-123".to_string()),
        Some(temp_root.to_string_lossy().to_string()),
    );

    assert_eq!(plugin_snapshot.plugin_count, 1);
    assert_eq!(plugin_snapshot.enabled_plugin_count, 0);
    assert_eq!(plugin_snapshot.trusted_plugin_count, 0);
    assert_eq!(plugin_snapshot.blocked_plugin_count, 1);
    assert_eq!(plugin_snapshot.reloadable_plugin_count, 1);
    assert_eq!(plugin_snapshot.hook_contribution_count, 1);
    assert_eq!(plugin_snapshot.filesystem_skill_count, 1);
    assert_eq!(
        plugin_snapshot.plugins[0].authority_tier_label,
        "Governed extension"
    );
    assert_eq!(
        plugin_snapshot.plugins[0].session_scope_label,
        "Matches current workspace"
    );
    assert_eq!(
        plugin_snapshot.plugins[0].runtime_trust_state,
        "trust_required"
    );
    assert_eq!(
        plugin_snapshot.plugins[0].requested_capabilities,
        vec!["hooks".to_string(), "runtime".to_string()]
    );

    let _ = std::fs::remove_file(manifest_path);
    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn plugin_runtime_lifecycle_tracks_trust_reload_and_revocation() {
    let temp_root =
        std::env::temp_dir().join(format!("autopilot-plugin-runtime-{}", std::process::id()));
    let plugin_root = temp_root.join("plugin-alpha");
    std::fs::create_dir_all(plugin_root.join(".codex-plugin")).expect("create plugin root");
    let manifest_path = plugin_root.join(".codex-plugin/plugin.json");
    std::fs::write(&manifest_path, "{}").expect("write manifest");
    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);
    let manifest = snapshot.extension_manifests[0].clone();

    manager
        .trust_plugin(&manifest, true)
        .expect("trust plugin should persist");
    manager
        .reload_plugin(&manifest)
        .expect("trusted reload should succeed");
    manager
        .revoke_plugin_trust(&manifest)
        .expect("revoking trust should persist");
    manager
        .reload_plugin(&manifest)
        .expect("blocked reload should still persist receipts");

    let plugin_snapshot = build_session_plugin_snapshot(
        snapshot,
        manager.snapshot(),
        Some("session-123".to_string()),
        Some(temp_root.to_string_lossy().to_string()),
    );

    assert_eq!(plugin_snapshot.enabled_plugin_count, 0);
    assert_eq!(plugin_snapshot.trusted_plugin_count, 0);
    assert_eq!(plugin_snapshot.plugins[0].runtime_trust_state, "revoked");
    assert_eq!(plugin_snapshot.plugins[0].runtime_load_state, "blocked");
    assert!(plugin_snapshot.plugins[0].load_error.is_some());
    assert_eq!(plugin_snapshot.recent_receipts[0].action, "reload");
    assert_eq!(plugin_snapshot.recent_receipts[0].status, "blocked");
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "reload" && receipt.status == "matched"));
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "trust" && receipt.status == "recorded"));
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "revoke" && receipt.status == "revoked"));

    let _ = std::fs::remove_file(manifest_path);
    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn plugin_package_lifecycle_tracks_install_update_and_remove() {
    let temp_root =
        std::env::temp_dir().join(format!("autopilot-plugin-package-{}", std::process::id()));
    let plugin_root = temp_root.join("plugin-alpha");
    let manifest_dir = plugin_root.join(".codex-plugin");
    std::fs::create_dir_all(&manifest_dir).expect("create plugin root");
    let manifest_path = manifest_dir.join("plugin.json");
    std::fs::write(
        &manifest_path,
        r#"{
  "name": "alpha-plugin",
  "version": "1.0.0",
  "interface": {
"displayName": "Alpha Plugin",
"category": "Automation"
  }
}"#,
    )
    .expect("write manifest");
    std::fs::write(plugin_root.join("README.md"), "# Alpha").expect("write source file");

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);
    let manifest = snapshot.extension_manifests[0].clone();

    manager
        .install_plugin_package(&manifest)
        .expect("package install should persist");
    manager
        .stage_plugin_update(&manifest, "1.1.0")
        .expect("staged update should persist");
    manager
        .update_plugin_package(&manifest)
        .expect("apply update should persist");

    let managed_root = managed_plugin_root_for(manager.path(), &manifest.extension_id);
    let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
    assert!(managed_manifest.exists(), "managed manifest should exist");
    let managed_manifest_raw =
        std::fs::read_to_string(&managed_manifest).expect("read managed manifest");
    assert!(
        managed_manifest_raw.contains("\"version\": \"1.1.0\""),
        "managed package manifest should carry the updated version"
    );

    manager
        .remove_plugin_package(&manifest)
        .expect("remove package should persist");

    let plugin_snapshot = build_session_plugin_snapshot(
        snapshot,
        manager.snapshot(),
        Some("session-123".to_string()),
        Some(temp_root.to_string_lossy().to_string()),
    );

    assert_eq!(plugin_snapshot.managed_package_count, 0);
    assert_eq!(plugin_snapshot.update_available_count, 0);
    assert_eq!(plugin_snapshot.plugins[0].package_install_state, "removed");
    assert!(!plugin_snapshot.plugins[0].package_managed);
    assert_eq!(
        plugin_snapshot.recent_receipts[0].action, "remove",
        "latest receipt should describe package removal"
    );
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "install" && receipt.status == "applied"));
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "update_detected" && receipt.status == "available"));
    assert!(plugin_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "update" && receipt.status == "applied"));
    assert!(
        !managed_root.exists(),
        "managed package copy should be removed from disk"
    );

    let _ = std::fs::remove_file(manifest_path);
    let _ = std::fs::remove_dir_all(temp_root);
}
