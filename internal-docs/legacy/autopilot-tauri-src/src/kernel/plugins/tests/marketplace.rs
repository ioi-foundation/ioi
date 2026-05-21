use super::*;

#[test]
fn marketplace_feed_manifest_supports_catalog_install_and_update_signal() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-feed-{}",
        std::process::id()
    ));
    let plugin_root = temp_root.join("plugin-marketplace-alpha");
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
"category": "Automation",
"capabilities": ["filesystem", "hooks"]
  }
}"#,
    )
    .expect("write manifest");
    std::fs::write(plugin_root.join("README.md"), "# Alpha").expect("write source file");

    let fixture_path = temp_root.join("plugin-marketplace-feed.json");
    std::fs::write(
        &fixture_path,
        format!(
            r#"{{
  "catalogs": [
{{
  "id": "local-dev-marketplace",
  "label": "Local Dev Marketplace",
  "plugins": [
    {{
      "manifestPath": "{}",
      "installationPolicy": "managed_copy",
      "authenticationPolicy": "operator_trust",
      "products": ["plugin", "validation"],
      "availableVersion": "9.9.9"
    }}
  ]
}}
  ]
}}"#,
            slash_path(&manifest_path)
        ),
    )
    .expect("write marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load marketplace manifests");
    assert_eq!(manifests.len(), 1);
    assert_eq!(
        manifests[0].marketplace_display_name.as_deref(),
        Some("Local Dev Marketplace")
    );
    assert_eq!(
        manifests[0].marketplace_available_version.as_deref(),
        Some("9.9.9")
    );

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    let initial_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    assert_eq!(initial_snapshot.plugin_count, 1);
    assert_eq!(initial_snapshot.installable_package_count, 1);
    assert_eq!(
        initial_snapshot.plugins[0].available_version.as_deref(),
        Some("9.9.9")
    );
    assert_eq!(
        initial_snapshot.plugins[0].package_install_state,
        "installable"
    );

    manager
        .install_plugin_package(&manifests[0])
        .expect("catalog install should reuse managed package path");

    let installed_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    assert!(installed_snapshot.plugins[0].package_managed);
    assert_eq!(
        installed_snapshot.plugins[0].installed_version.as_deref(),
        Some("1.0.0")
    );
    assert_eq!(
        installed_snapshot.plugins[0].available_version.as_deref(),
        Some("9.9.9")
    );
    assert!(installed_snapshot.plugins[0].update_available);
    assert_eq!(
        installed_snapshot.recent_receipts[0].action, "install",
        "catalog install should emit the existing managed-package install receipt"
    );

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_channel_precedence_prefers_health_before_channel_priority() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-channel-precedence-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let manifest_path = write_test_plugin_manifest(
        &temp_root.join("shared-plugin"),
        "shared-plugin",
        "Shared Channel Plugin",
    );
    let now_ms = state::now();
    let fixture_path = temp_root.join("plugin-marketplace-channel-precedence.json");
    let fixture = serde_json::json!({
        "catalogs": [
            {
                "id": "stable-release",
                "label": "Stable Release Catalog",
                "channel": "stable",
                "issuedAtMs": now_ms.saturating_sub(172_800_000),
                "refreshedAtMs": now_ms.saturating_sub(172_800_000),
                "expiresAtMs": now_ms.saturating_sub(60_000),
                "plugins": [
                    {
                        "manifestPath": slash_path(&manifest_path),
                        "displayName": "Shared Channel Plugin",
                        "availableVersion": "9.9.9"
                    }
                ]
            },
            {
                "id": "community-release",
                "label": "Community Release Catalog",
                "channel": "community",
                "issuedAtMs": now_ms.saturating_sub(60_000),
                "refreshedAtMs": now_ms.saturating_sub(30_000),
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "plugins": [
                    {
                        "manifestPath": slash_path(&manifest_path),
                        "displayName": "Shared Channel Plugin",
                        "availableVersion": "1.1.0"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("encode channel precedence fixture"),
    )
    .expect("write channel precedence fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load channel precedence manifests");
    assert_eq!(
        manifests.len(),
        1,
        "duplicate plugin ids should collapse to one manifest"
    );
    assert_eq!(
        manifests[0].marketplace_catalog_channel.as_deref(),
        Some("community"),
        "a healthy lower-priority channel should win over an expired higher-priority channel"
    );
    assert_eq!(
        manifests[0].marketplace_display_name.as_deref(),
        Some("Community Release Catalog")
    );

    let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
        Some(&fixture_path),
    );
    let plugin = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Shared Channel Plugin")
        .expect("shared plugin present");
    assert_eq!(plugin.catalog_channel.as_deref(), Some("community"));
    assert_eq!(plugin.catalog_status, "active");
    assert_eq!(snapshot.catalog_channel_count, 2);
    assert!(snapshot
        .catalog_channels
        .iter()
        .any(|channel| channel.catalog_id == "stable-release" && channel.status == "expired"));
    assert!(snapshot.catalog_channels.iter().any(|channel| {
        channel.catalog_id == "community-release" && channel.status == "active"
    }));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_nonconformant_channel_surfaces_without_breaking_valid_channels() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-nonconformant-channel-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let valid_manifest = write_test_plugin_manifest(
        &temp_root.join("valid-plugin"),
        "valid-plugin",
        "Valid Channel Plugin",
    );
    let fixture_path = temp_root.join("plugin-marketplace-nonconformant-channel.json");
    let fixture = serde_json::json!({
        "catalogs": [
            {
                "id": "stable-release",
                "label": "Stable Release Catalog",
                "channel": "stable",
                "plugins": [
                    {
                        "manifestPath": slash_path(&valid_manifest),
                        "displayName": "Valid Channel Plugin",
                        "availableVersion": "1.0.0"
                    }
                ]
            },
            {
                "id": "security-release",
                "label": "Security Release Catalog",
                "channel": "security",
                "plugins": [
                    {
                        "manifestPath": "",
                        "displayName": "Broken Channel Plugin",
                        "availableVersion": "9.9.9"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("encode nonconformant channel fixture"),
    )
    .expect("write nonconformant channel fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load nonconformant channel manifests");
    assert_eq!(
        manifests.len(),
        1,
        "valid catalog entries should still load"
    );

    let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
        Some(&fixture_path),
    );
    assert_eq!(snapshot.plugin_count, 1);
    assert_eq!(snapshot.catalog_channel_count, 2);
    assert_eq!(snapshot.nonconformant_channel_count, 1);
    let nonconformant = snapshot
        .catalog_channels
        .iter()
        .find(|channel| channel.catalog_id == "security-release")
        .expect("nonconformant security channel present");
    assert_eq!(nonconformant.status, "nonconformant");
    assert_eq!(nonconformant.conformance_status, "nonconformant");
    assert_eq!(nonconformant.invalid_plugin_count, 1);
    assert!(nonconformant
        .conformance_error
        .as_deref()
        .is_some_and(|error| error.contains("manifestPath")));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_distribution_prefers_healthy_source_and_surfaces_source_health() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-distribution-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let shared_manifest = write_test_plugin_manifest(
        &temp_root.join("shared-plugin"),
        "shared-plugin",
        "Shared Channel Plugin",
    );
    let now_ms = state::now();

    let stable_feed = temp_root.join("stable-feed.json");
    let community_feed = temp_root.join("community-feed.json");
    let security_feed = temp_root.join("security-feed.json");
    let distribution_path = temp_root.join("plugin-marketplace-distribution.json");

    std::fs::write(
        &stable_feed,
        serde_json::to_vec_pretty(&serde_json::json!({
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "channel": "stable",
                    "issuedAtMs": now_ms.saturating_sub(172_800_000),
                    "refreshedAtMs": now_ms.saturating_sub(172_800_000),
                    "expiresAtMs": now_ms.saturating_sub(60_000),
                    "plugins": [
                        {
                            "manifestPath": slash_path(&shared_manifest),
                            "displayName": "Shared Channel Plugin",
                            "availableVersion": "9.9.9"
                        }
                    ]
                }
            ]
        }))
        .expect("encode stable feed"),
    )
    .expect("write stable feed");
    std::fs::write(
        &community_feed,
        serde_json::to_vec_pretty(&serde_json::json!({
            "catalogs": [
                {
                    "id": "community-release",
                    "label": "Community Release Catalog",
                    "channel": "community",
                    "issuedAtMs": now_ms.saturating_sub(60_000),
                    "refreshedAtMs": now_ms.saturating_sub(30_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "plugins": [
                        {
                            "manifestPath": slash_path(&shared_manifest),
                            "displayName": "Shared Channel Plugin",
                            "availableVersion": "1.1.0"
                        }
                    ]
                }
            ]
        }))
        .expect("encode community feed"),
    )
    .expect("write community feed");
    std::fs::write(
        &security_feed,
        serde_json::to_vec_pretty(&serde_json::json!({
            "catalogs": [
                {
                    "id": "security-release",
                    "label": "Security Release Catalog",
                    "channel": "security",
                    "issuedAtMs": now_ms.saturating_sub(60_000),
                    "refreshedAtMs": now_ms.saturating_sub(30_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "plugins": [
                        {
                            "manifestPath": "",
                            "displayName": "Broken Channel Plugin",
                            "availableVersion": "9.9.9"
                        }
                    ]
                }
            ]
        }))
        .expect("encode security feed"),
    )
    .expect("write security feed");
    std::fs::write(
        &distribution_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "sources": [
                {
                    "id": "stable-source",
                    "label": "Stable Channel Source",
                    "sourceUri": "fixture://stable-channel",
                    "fixturePath": "stable-feed.json",
                    "channel": "stable",
                    "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(172_800_000)
                },
                {
                    "id": "community-source",
                    "label": "Community Channel Source",
                    "sourceUri": "fixture://community-channel",
                    "fixturePath": "community-feed.json",
                    "channel": "community",
                    "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                },
                {
                    "id": "security-source",
                    "label": "Security Channel Source",
                    "sourceUri": "fixture://security-channel",
                    "fixturePath": "security-feed.json",
                    "channel": "security",
                    "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                }
            ]
        }))
        .expect("encode distribution"),
    )
    .expect("write distribution");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
        .expect("load distribution manifests");
    assert_eq!(manifests.len(), 1);
    assert_eq!(
        manifests[0].marketplace_catalog_channel.as_deref(),
        Some("community")
    );
    assert_eq!(
        manifests[0].marketplace_catalog_source_id.as_deref(),
        Some("community-source")
    );
    assert_eq!(
        manifests[0].marketplace_catalog_source_label.as_deref(),
        Some("Community Channel Source")
    );
    assert_eq!(
        manifests[0].marketplace_catalog_source_uri.as_deref(),
        Some("fixture://community-channel")
    );

    let source_records = load_plugin_marketplace_feed_catalog_sources_from_path(&distribution_path)
        .expect("load distribution sources");
    assert_eq!(source_records.len(), 3);
    assert!(source_records
        .iter()
        .any(|source| { source.source_id == "stable-source" && source.status == "expired" }));
    assert!(source_records
        .iter()
        .any(|source| { source.source_id == "community-source" && source.status == "active" }));
    assert!(source_records.iter().any(|source| {
        source.source_id == "security-source"
            && source.status == "nonconformant"
            && source.conformance_status == "nonconformant"
    }));

    let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
        Some(&distribution_path),
    );
    assert_eq!(snapshot.plugin_count, 1);
    assert_eq!(snapshot.catalog_channel_count, 3);
    assert_eq!(snapshot.catalog_source_count, 3);
    assert_eq!(snapshot.failed_catalog_source_count, 0);
    assert_eq!(snapshot.nonconformant_source_count, 1);
    let plugin = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Shared Channel Plugin")
        .expect("shared plugin present");
    assert_eq!(plugin.catalog_channel.as_deref(), Some("community"));
    assert_eq!(
        plugin.catalog_source_label.as_deref(),
        Some("Community Channel Source")
    );
    assert_eq!(
        plugin.catalog_source_uri.as_deref(),
        Some("fixture://community-channel")
    );

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_distribution_source_failures_surface_without_hiding_valid_sources() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-distribution-failure-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let valid_manifest = write_test_plugin_manifest(
        &temp_root.join("valid-plugin"),
        "valid-plugin",
        "Valid Source Plugin",
    );
    let stable_feed = temp_root.join("stable-feed.json");
    let distribution_path = temp_root.join("plugin-marketplace-distribution-failure.json");

    std::fs::write(
        &stable_feed,
        serde_json::to_vec_pretty(&serde_json::json!({
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "channel": "stable",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&valid_manifest),
                            "displayName": "Valid Source Plugin",
                            "availableVersion": "1.0.0"
                        }
                    ]
                }
            ]
        }))
        .expect("encode valid stable feed"),
    )
    .expect("write valid stable feed");
    std::fs::write(
        &distribution_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "sources": [
                {
                    "id": "stable-source",
                    "label": "Stable Channel Source",
                    "sourceUri": "fixture://stable-channel",
                    "fixturePath": "stable-feed.json",
                    "channel": "stable"
                },
                {
                    "id": "missing-source",
                    "label": "Missing Security Source",
                    "sourceUri": "fixture://missing-security",
                    "fixturePath": "missing-security-feed.json",
                    "channel": "security"
                }
            ]
        }))
        .expect("encode distribution failure fixture"),
    )
    .expect("write distribution failure fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
        .expect("load distribution manifests with one valid source");
    assert_eq!(manifests.len(), 1);

    let source_records = load_plugin_marketplace_feed_catalog_sources_from_path(&distribution_path)
        .expect("load distribution source records");
    assert_eq!(source_records.len(), 2);
    let missing = source_records
        .iter()
        .find(|source| source.source_id == "missing-source")
        .expect("missing source record present");
    assert_eq!(missing.status, "refresh_failed");
    assert!(missing
        .refresh_error
        .as_deref()
        .is_some_and(|error| error.contains("does not exist")));

    let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
        Some(&distribution_path),
    );
    assert_eq!(snapshot.plugin_count, 1);
    assert_eq!(snapshot.catalog_source_count, 2);
    assert_eq!(snapshot.failed_catalog_source_count, 1);

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_remote_distribution_supports_http_sources_and_remote_package_lifecycle() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-remote-distribution-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let plugin_root = temp_root.join("remote-plugin-source");
    let manifest_path =
        write_test_plugin_manifest(&plugin_root, "remote-plugin", "Remote Package Plugin");
    let (digest_sha256, signature_public_key, package_signature) =
        sign_plugin_package(&plugin_root);
    let server_root = temp_root.join("server-root");
    let remote_plugin_root = server_root.join("remote-plugin");
    copy_directory_contents(&plugin_root, &remote_plugin_root).expect("copy remote plugin fixture");
    let archive_path = server_root.join("packages/remote-plugin.zip");
    write_test_plugin_archive(&plugin_root, &archive_path);

    let server = spawn_static_http_server(server_root.clone());
    let remote_manifest_url = server.url("remote-plugin/.codex-plugin/plugin.json");
    let remote_archive_url = server.url("packages/remote-plugin.zip");
    let remote_feed_url = server.url("feeds/remote-release.json");
    let now_ms = state::now();

    std::fs::create_dir_all(server_root.join("feeds")).expect("create feeds directory");
    std::fs::write(
        server_root.join("feeds/remote-release.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "catalogs": [
                {
                    "id": "remote-release",
                    "label": "Remote Release Catalog",
                    "sourceUri": remote_feed_url,
                    "channel": "stable",
                    "issuedAtMs": now_ms.saturating_sub(60_000),
                    "refreshedAtMs": now_ms.saturating_sub(30_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "plugins": [
                        {
                            "manifestPath": remote_manifest_url,
                            "packageUrl": remote_archive_url,
                            "displayName": "Remote Package Plugin",
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.2.0",
                            "packageDigestSha256": digest_sha256,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": signature_public_key,
                            "packageSignature": package_signature,
                            "publisherLabel": "Remote Publisher",
                            "signerIdentity": "remote-release-signing"
                        }
                    ]
                }
            ]
        }))
        .expect("encode remote feed"),
    )
    .expect("write remote feed");

    let distribution_path = temp_root.join("plugin-marketplace-remote-distribution.json");
    std::fs::write(
        &distribution_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "sources": [
                {
                    "id": "remote-source",
                    "label": "Remote Release Source",
                    "sourceUri": remote_feed_url,
                    "fixturePath": remote_feed_url,
                    "channel": "stable",
                    "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                }
            ]
        }))
        .expect("encode remote distribution"),
    )
    .expect("write remote distribution");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
        .expect("load remote distribution manifests");
    assert_eq!(manifests.len(), 1);
    let manifest = manifests[0].clone();
    assert_eq!(manifest.manifest_path, remote_manifest_url);
    assert_eq!(
        manifest.marketplace_package_url.as_deref(),
        Some(remote_archive_url.as_str())
    );
    assert_eq!(
        manifest.marketplace_catalog_source_id.as_deref(),
        Some("remote-source")
    );

    let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
        Some(&distribution_path),
    );
    assert_eq!(snapshot.catalog_source_count, 1);
    assert_eq!(snapshot.local_catalog_source_count, 0);
    assert_eq!(snapshot.remote_catalog_source_count, 1);
    let source = snapshot
        .catalog_sources
        .iter()
        .find(|source| source.source_id == "remote-source")
        .expect("remote source present");
    assert_eq!(source.transport_kind, "remote_url");
    let plugin = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Remote Package Plugin")
        .expect("remote plugin present");
    assert_eq!(plugin.authenticity_state, "verified");
    assert_eq!(
        plugin.marketplace_package_url.as_deref(),
        Some(remote_archive_url.as_str())
    );

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    manager
        .install_plugin_package(&manifest)
        .expect("install remote package archive");
    manager
        .stage_plugin_update(&manifest, "1.2.0")
        .expect("stage remote update");
    manager
        .update_plugin_package(&manifest)
        .expect("apply remote archive update");

    let managed_root = managed_plugin_root_for(manager.path(), &manifest.extension_id);
    let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
    assert!(managed_manifest.exists(), "managed manifest should exist");
    let managed_manifest_raw =
        std::fs::read_to_string(&managed_manifest).expect("read managed manifest");
    assert!(
        managed_manifest_raw.contains("\"version\": \"1.2.0\""),
        "remote archive update should rewrite the installed version"
    );
    assert!(
        managed_root.join("README.md").exists(),
        "remote archive payload should be unpacked into the managed package root"
    );

    let installed_snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
        &manifests,
        manager.snapshot(),
        None,
        None,
        Some(&distribution_path),
    );
    let installed_plugin = installed_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Remote Package Plugin")
        .expect("installed remote plugin present");
    assert!(installed_plugin.package_managed);
    assert_eq!(
        installed_plugin.package_install_source.as_deref(),
        Some("marketplace_remote")
    );
    assert_eq!(installed_plugin.installed_version.as_deref(), Some("1.2.0"));

    drop(server);
    let _ = std::fs::remove_file(manifest_path);
    let _ = std::fs::remove_dir_all(temp_root);
}
