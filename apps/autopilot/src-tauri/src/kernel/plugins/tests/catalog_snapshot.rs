use super::*;

#[test]
fn marketplace_trust_scoring_and_catalog_refresh_states_flow_into_snapshot() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-scoring-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let recommended_manifest = write_test_plugin_manifest(
        &temp_root.join("recommended-plugin"),
        "recommended-plugin",
        "Recommended Plugin",
    );
    let unknown_manifest = write_test_plugin_manifest(
        &temp_root.join("unknown-plugin"),
        "unknown-plugin",
        "Unknown Root Plugin",
    );
    let stale_manifest = write_test_plugin_manifest(
        &temp_root.join("stale-plugin"),
        "stale-plugin",
        "Stale Feed Plugin",
    );
    let expired_manifest = write_test_plugin_manifest(
        &temp_root.join("expired-plugin"),
        "expired-plugin",
        "Expired Catalog Plugin",
    );

    let recommended_root = manifest_parent_root(&recommended_manifest).expect("recommended root");
    let unknown_root = manifest_parent_root(&unknown_manifest).expect("unknown root");
    let stale_root = manifest_parent_root(&stale_manifest).expect("stale root");
    let expired_root = manifest_parent_root(&expired_manifest).expect("expired root");

    let (recommended_digest, recommended_public_key, recommended_signature) =
        sign_plugin_package(&recommended_root);
    let (unknown_digest, unknown_public_key, unknown_signature) =
        sign_plugin_package(&unknown_root);
    let (stale_digest, stale_public_key, stale_signature) = sign_plugin_package(&stale_root);
    let (expired_digest, expired_public_key, expired_signature) =
        sign_plugin_package(&expired_root);

    let (recommended_marketplace_root, recommended_publisher) = rooted_publisher_fixture(
        "recommended-marketplace-root",
        "Recommended Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "recommended-publisher",
        "IOI Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "recommended-ed25519",
        &recommended_public_key,
        Some("active"),
        None,
        1775440000000,
    );
    let (_missing_marketplace_root, unknown_publisher) = rooted_publisher_fixture(
        "community-marketplace-root",
        "Community Marketplace Root",
        Some("active"),
        "community marketplace root store",
        None,
        "unknown-publisher",
        "Community Labs",
        Some("trusted"),
        "community marketplace chain",
        None,
        "unknown-ed25519",
        &unknown_public_key,
        Some("active"),
        None,
        1775440600000,
    );
    let (stale_marketplace_root, stale_publisher) = rooted_publisher_fixture(
        "stale-marketplace-root",
        "Stale Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "stale-publisher",
        "Stale Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "stale-ed25519",
        &stale_public_key,
        Some("active"),
        None,
        1775441200000,
    );
    let (expired_marketplace_root, expired_publisher) = rooted_publisher_fixture(
        "expired-marketplace-root",
        "Expired Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "expired-publisher",
        "Expiry Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "expired-ed25519",
        &expired_public_key,
        Some("active"),
        None,
        1775441800000,
    );

    let now_ms = state::now();
    let stale_refreshed_at_ms = now_ms.saturating_sub(MARKETPLACE_CATALOG_STALE_AFTER_MS + 60_000);
    let stale_issued_at_ms = stale_refreshed_at_ms.saturating_sub(3_600_000);

    let fixture_path = temp_root.join("plugin-marketplace-scoring.json");
    let (recommended_refresh_root, recommended_refresh_bundle) = catalog_refresh_bundle_fixture(
        "stable-refresh-root",
        "Stable Refresh Root",
        "stable-release-refresh-1",
        "Stable Release Refresh",
        "stable-release",
        "signed catalog refresh",
        "stable",
        vec![catalog_refresh_entry(
            &recommended_manifest,
            "Recommended Plugin",
            "Healthy rooted plugin with a signed catalog refresh ready to apply.",
            "1.1.0",
            &recommended_digest,
            &recommended_public_key,
            &recommended_signature,
            "recommended-publisher",
            "recommended-ed25519",
            "IOI Labs",
            "ioi-release-signing",
        )],
        now_ms.saturating_sub(30_000),
        now_ms.saturating_sub(10_000),
        Some(now_ms.saturating_add(86_400_000)),
        false,
    );
    let (stale_refresh_root, stale_refresh_bundle) = catalog_refresh_bundle_fixture(
        "stale-refresh-root",
        "Stale Refresh Root",
        "canary-release-refresh-1",
        "Canary Release Refresh",
        "canary-release",
        "signed catalog refresh",
        "canary",
        vec![catalog_refresh_entry(
            &stale_manifest,
            "Stale Feed Plugin",
            "Tampered refresh bundle to prove refresh failures surface in the snapshot.",
            "1.2.0",
            &stale_digest,
            &stale_public_key,
            &stale_signature,
            "stale-publisher",
            "stale-ed25519",
            "Stale Labs",
            "stale-release-signing",
        )],
        now_ms.saturating_sub(45_000),
        now_ms.saturating_sub(15_000),
        Some(now_ms.saturating_add(86_400_000)),
        true,
    );

    let fixture = serde_json::json!({
        "roots": [
            recommended_marketplace_root,
            stale_marketplace_root,
            expired_marketplace_root,
            recommended_refresh_root,
            stale_refresh_root
        ],
        "publishers": [
            recommended_publisher,
            unknown_publisher,
            stale_publisher,
            expired_publisher
        ],
        "catalogRefreshBundles": [
            recommended_refresh_bundle,
            stale_refresh_bundle
        ],
        "catalogs": [
            {
                "id": "stable-release",
                "label": "Stable Release Catalog",
                "issuedAtMs": now_ms.saturating_sub(3_600_000),
                "refreshedAtMs": now_ms.saturating_sub(60_000),
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "refreshSource": "signed fixture refresh",
                "channel": "stable",
                "plugins": [
                    {
                        "manifestPath": slash_path(&recommended_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "1.0.0",
                        "packageDigestSha256": recommended_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": recommended_public_key,
                        "packageSignature": recommended_signature,
                        "publisherId": "recommended-publisher",
                        "signingKeyId": "recommended-ed25519",
                        "publisherLabel": "IOI Labs",
                        "signerIdentity": "ioi-release-signing"
                    }
                ]
            },
            {
                "id": "community-release",
                "label": "Community Release Catalog",
                "issuedAtMs": now_ms.saturating_sub(3_600_000),
                "refreshedAtMs": now_ms.saturating_sub(60_000),
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "refreshSource": "community mirror",
                "channel": "community",
                "plugins": [
                    {
                        "manifestPath": slash_path(&unknown_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "1.0.0",
                        "packageDigestSha256": unknown_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": unknown_public_key,
                        "packageSignature": unknown_signature,
                        "publisherId": "unknown-publisher",
                        "signingKeyId": "unknown-ed25519",
                        "publisherLabel": "Community Labs",
                        "signerIdentity": "community-release-signing"
                    }
                ]
            },
            {
                "id": "canary-release",
                "label": "Canary Release Catalog",
                "issuedAtMs": stale_issued_at_ms,
                "refreshedAtMs": stale_refreshed_at_ms,
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "refreshSource": "background refresh",
                "channel": "canary",
                "plugins": [
                    {
                        "manifestPath": slash_path(&stale_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "1.1.0",
                        "packageDigestSha256": stale_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": stale_public_key,
                        "packageSignature": stale_signature,
                        "publisherId": "stale-publisher",
                        "signingKeyId": "stale-ed25519",
                        "publisherLabel": "Stale Labs",
                        "signerIdentity": "stale-release-signing"
                    }
                ]
            },
            {
                "id": "security-release",
                "label": "Security Release Catalog",
                "issuedAtMs": now_ms.saturating_sub(172_800_000),
                "refreshedAtMs": now_ms.saturating_sub(86_400_000),
                "expiresAtMs": now_ms.saturating_sub(1_000),
                "refreshSource": "security mirror",
                "channel": "security",
                "plugins": [
                    {
                        "manifestPath": slash_path(&expired_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "2.0.0",
                        "packageDigestSha256": expired_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": expired_public_key,
                        "packageSignature": expired_signature,
                        "publisherId": "expired-publisher",
                        "signingKeyId": "expired-ed25519",
                        "publisherLabel": "Expiry Labs",
                        "signerIdentity": "expiry-release-signing"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("encode scoring marketplace fixture"),
    )
    .expect("write scoring marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load scoring marketplace manifests");
    let snapshot = build_session_plugin_snapshot_for_manifests(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
    );

    assert_eq!(snapshot.plugin_count, 4);
    assert_eq!(snapshot.recommended_plugin_count, 1);
    assert_eq!(snapshot.review_required_plugin_count, 2);
    assert_eq!(
        snapshot
            .plugins
            .iter()
            .filter(|plugin| plugin.operator_review_state == "blocked")
            .count(),
        1
    );
    assert_eq!(snapshot.stale_catalog_count, 1);
    assert_eq!(snapshot.expired_catalog_count, 1);
    assert_eq!(snapshot.critical_update_count, 2);
    assert_eq!(snapshot.refresh_available_count, 1);
    assert_eq!(snapshot.refresh_failed_count, 0);

    let recommended = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Recommended Plugin")
        .expect("recommended plugin present");
    assert_eq!(recommended.operator_review_state, "recommended");
    assert_eq!(recommended.operator_review_label, "Recommended");
    assert_eq!(recommended.catalog_status, "refresh_available");
    assert_eq!(recommended.catalog_status_label, "Refresh available");
    assert_eq!(recommended.catalog_channel.as_deref(), Some("stable"));
    assert_eq!(
        recommended.catalog_refresh_source.as_deref(),
        Some("signed fixture refresh")
    );
    assert_eq!(
        recommended.catalog_refresh_bundle_id.as_deref(),
        Some("stable-release-refresh-1")
    );
    assert_eq!(
        recommended.catalog_refresh_available_version.as_deref(),
        Some("1.1.0")
    );
    assert_eq!(recommended.update_severity, None);
    assert_eq!(recommended.publisher_trust_state.as_deref(), Some("rooted"));

    let unknown = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Unknown Root Plugin")
        .expect("unknown plugin present");
    assert_eq!(unknown.operator_review_state, "review_required");
    assert_eq!(unknown.operator_review_label, "Review required");
    assert_eq!(unknown.catalog_status, "active");
    assert_eq!(
        unknown.publisher_trust_state.as_deref(),
        Some("unknown_root")
    );
    assert_eq!(unknown.update_severity, None);
    assert!(!unknown.operator_review_reason.trim().is_empty());

    let stale = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Stale Feed Plugin")
        .expect("stale plugin present");
    assert_eq!(stale.catalog_status, "stale");
    assert_eq!(stale.catalog_status_label, "Catalog refresh stale");
    assert_eq!(stale.update_severity.as_deref(), Some("review_stale_feed"));
    assert_eq!(
        stale.update_severity_label.as_deref(),
        Some("Review stale feed")
    );
    assert_eq!(stale.operator_review_state, "review_required");
    assert!(stale
        .operator_review_reason
        .contains("catalog freshness window is stale"));

    let expired = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Expired Catalog Plugin")
        .expect("expired plugin present");
    assert_eq!(expired.catalog_status, "expired");
    assert_eq!(expired.catalog_status_label, "Catalog expired");
    assert_eq!(expired.update_severity.as_deref(), Some("blocked"));
    assert_eq!(
        expired.update_severity_label.as_deref(),
        Some("Blocked update channel")
    );
    assert_eq!(expired.operator_review_state, "blocked");
    assert!(expired
        .operator_review_reason
        .contains("catalog has expired"));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn signed_catalog_refresh_runtime_flow_updates_snapshot_and_failures_surface() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-refresh-runtime-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_root);
    let recommended_manifest = write_test_plugin_manifest(
        &temp_root.join("recommended-plugin"),
        "recommended-plugin",
        "Recommended Plugin",
    );
    let stale_manifest = write_test_plugin_manifest(
        &temp_root.join("stale-plugin"),
        "stale-plugin",
        "Stale Feed Plugin",
    );

    let recommended_root = manifest_parent_root(&recommended_manifest).expect("recommended root");
    let stale_root = manifest_parent_root(&stale_manifest).expect("stale root");

    let (recommended_digest, recommended_public_key, recommended_signature) =
        sign_plugin_package(&recommended_root);
    let (stale_digest, stale_public_key, stale_signature) = sign_plugin_package(&stale_root);

    let (recommended_marketplace_root, recommended_publisher) = rooted_publisher_fixture(
        "recommended-marketplace-root",
        "Recommended Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "recommended-publisher",
        "IOI Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "recommended-ed25519",
        &recommended_public_key,
        Some("active"),
        None,
        1775440000000,
    );
    let (stale_marketplace_root, stale_publisher) = rooted_publisher_fixture(
        "stale-marketplace-root",
        "Stale Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "stale-publisher",
        "Stale Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "stale-ed25519",
        &stale_public_key,
        Some("active"),
        None,
        1775441200000,
    );

    let now_ms = state::now();
    let stale_refreshed_at_ms = now_ms.saturating_sub(MARKETPLACE_CATALOG_STALE_AFTER_MS + 60_000);
    let stale_issued_at_ms = stale_refreshed_at_ms.saturating_sub(3_600_000);
    let (recommended_refresh_root, recommended_refresh_bundle) = catalog_refresh_bundle_fixture(
        "stable-refresh-root",
        "Stable Refresh Root",
        "stable-release-refresh-1",
        "Stable Release Refresh",
        "stable-release",
        "signed catalog refresh",
        "stable",
        vec![catalog_refresh_entry(
            &recommended_manifest,
            "Recommended Plugin",
            "Healthy rooted plugin with a signed refresh.",
            "1.1.0",
            &recommended_digest,
            &recommended_public_key,
            &recommended_signature,
            "recommended-publisher",
            "recommended-ed25519",
            "IOI Labs",
            "ioi-release-signing",
        )],
        now_ms.saturating_sub(30_000),
        now_ms.saturating_sub(10_000),
        Some(now_ms.saturating_add(86_400_000)),
        false,
    );
    let (stale_refresh_root, stale_refresh_bundle) = catalog_refresh_bundle_fixture(
        "stale-refresh-root",
        "Stale Refresh Root",
        "canary-release-refresh-1",
        "Canary Release Refresh",
        "canary-release",
        "signed catalog refresh",
        "canary",
        vec![catalog_refresh_entry(
            &stale_manifest,
            "Stale Feed Plugin",
            "Tampered refresh bundle.",
            "1.2.0",
            &stale_digest,
            &stale_public_key,
            &stale_signature,
            "stale-publisher",
            "stale-ed25519",
            "Stale Labs",
            "stale-release-signing",
        )],
        now_ms.saturating_sub(45_000),
        now_ms.saturating_sub(15_000),
        Some(now_ms.saturating_add(86_400_000)),
        true,
    );

    let fixture_path = temp_root.join("plugin-marketplace-refresh.json");
    let fixture = serde_json::json!({
        "roots": [
            recommended_marketplace_root,
            stale_marketplace_root,
            recommended_refresh_root,
            stale_refresh_root
        ],
        "publishers": [
            recommended_publisher,
            stale_publisher
        ],
        "catalogRefreshBundles": [
            recommended_refresh_bundle,
            stale_refresh_bundle
        ],
        "catalogs": [
            {
                "id": "stable-release",
                "label": "Stable Release Catalog",
                "issuedAtMs": now_ms.saturating_sub(3_600_000),
                "refreshedAtMs": now_ms.saturating_sub(60_000),
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "refreshSource": "signed fixture refresh",
                "channel": "stable",
                "plugins": [
                    {
                        "manifestPath": slash_path(&recommended_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "1.0.0",
                        "packageDigestSha256": recommended_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": recommended_public_key,
                        "packageSignature": recommended_signature,
                        "publisherId": "recommended-publisher",
                        "signingKeyId": "recommended-ed25519",
                        "publisherLabel": "IOI Labs",
                        "signerIdentity": "ioi-release-signing"
                    }
                ]
            },
            {
                "id": "canary-release",
                "label": "Canary Release Catalog",
                "issuedAtMs": stale_issued_at_ms,
                "refreshedAtMs": stale_refreshed_at_ms,
                "expiresAtMs": now_ms.saturating_add(86_400_000),
                "refreshSource": "background refresh",
                "channel": "canary",
                "plugins": [
                    {
                        "manifestPath": slash_path(&stale_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "1.1.0",
                        "packageDigestSha256": stale_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": stale_public_key,
                        "packageSignature": stale_signature,
                        "publisherId": "stale-publisher",
                        "signingKeyId": "stale-ed25519",
                        "publisherLabel": "Stale Labs",
                        "signerIdentity": "stale-release-signing"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("encode refresh marketplace fixture"),
    )
    .expect("write refresh marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load refresh marketplace manifests");
    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);

    let initial_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    assert_eq!(initial_snapshot.refresh_available_count, 1);
    assert_eq!(initial_snapshot.refresh_failed_count, 0);
    let initial_recommended = initial_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Recommended Plugin")
        .expect("recommended plugin present");
    assert_eq!(initial_recommended.catalog_status, "refresh_available");
    assert_eq!(
        initial_recommended
            .catalog_refresh_available_version
            .as_deref(),
        Some("1.1.0")
    );
    assert!(!initial_recommended.update_available);

    let recommended_manifest = manifests
        .iter()
        .find(|manifest| manifest.display_name.as_deref() == Some("Recommended Plugin"))
        .expect("recommended manifest present");
    let stale_manifest = manifests
        .iter()
        .find(|manifest| manifest.display_name.as_deref() == Some("Stale Feed Plugin"))
        .expect("stale manifest present");

    let recommended_target = load_plugin_marketplace_catalog_refresh_target_from_path(
        &fixture_path,
        &recommended_manifest.extension_id,
    );
    manager
        .refresh_plugin_catalog(recommended_manifest, recommended_target)
        .expect("apply recommended refresh");

    let refreshed_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let refreshed_recommended = refreshed_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Recommended Plugin")
        .expect("recommended plugin present after refresh");
    assert_eq!(refreshed_recommended.catalog_status, "active");
    assert_eq!(refreshed_recommended.catalog_status_label, "Catalog fresh");
    assert_eq!(
        refreshed_recommended.available_version.as_deref(),
        Some("1.1.0")
    );
    assert!(!refreshed_recommended.update_available);
    assert_eq!(
        refreshed_recommended.update_severity.as_deref(),
        Some("recommended")
    );
    assert_eq!(refreshed_snapshot.refresh_available_count, 0);
    assert!(refreshed_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "catalog_refresh" && receipt.status == "applied"));

    let stale_target = load_plugin_marketplace_catalog_refresh_target_from_path(
        &fixture_path,
        &stale_manifest.extension_id,
    );
    manager
        .refresh_plugin_catalog(stale_manifest, stale_target)
        .expect("stale refresh failure should still persist a snapshot");

    let failed_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let failed_stale = failed_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Stale Feed Plugin")
        .expect("stale plugin present after failed refresh");
    assert_eq!(failed_stale.catalog_status, "refresh_failed");
    assert_eq!(failed_stale.catalog_status_label, "Refresh failed");
    assert_eq!(
        failed_stale.update_severity.as_deref(),
        Some("review_refresh_failure")
    );
    assert_eq!(failed_stale.operator_review_state, "review_required");
    assert!(failed_stale.catalog_refresh_error.is_some());
    assert_eq!(failed_snapshot.refresh_failed_count, 1);
    assert!(failed_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "catalog_refresh" && receipt.status == "failed"));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn marketplace_feed_signature_verification_flows_into_snapshot() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-verification-{}",
        std::process::id()
    ));
    let verified_manifest = write_test_plugin_manifest(
        &temp_root.join("verified-plugin"),
        "verified-plugin",
        "Verified Plugin",
    );
    let unverified_manifest = write_test_plugin_manifest(
        &temp_root.join("unverified-plugin"),
        "unverified-plugin",
        "Unverified Plugin",
    );
    let mismatch_manifest = write_test_plugin_manifest(
        &temp_root.join("mismatch-plugin"),
        "mismatch-plugin",
        "Mismatch Plugin",
    );
    let verified_root = manifest_parent_root(&verified_manifest).expect("verified root");
    let unsigned_root = manifest_parent_root(&unverified_manifest).expect("unsigned root");
    let mismatch_root = manifest_parent_root(&mismatch_manifest).expect("mismatch root");
    let (verified_digest, verified_public_key, verified_signature) =
        sign_plugin_package(&verified_root);
    let (mismatch_digest, mismatch_public_key, mismatch_signature) =
        sign_plugin_package(&mismatch_root);
    std::fs::write(
        mismatch_root.join("README.md"),
        "Mismatch Plugin tampered payload\n",
    )
    .expect("tamper mismatch plugin payload");
    let unsigned_digest =
        compute_plugin_package_digest_sha256(&unsigned_root).expect("compute unsigned digest");

    let fixture_path = temp_root.join("plugin-marketplace-verification.json");
    std::fs::write(
        &fixture_path,
        format!(
            r#"{{
  "publishers": [
{{
  "id": "ioi-labs",
  "label": "IOI Labs",
  "trustStatus": "trusted",
  "trustSource": "local test registry",
  "signingKeys": [
    {{
      "id": "ioi-release-key",
      "algorithm": "ed25519",
      "publicKey": "{verified_public_key}",
      "status": "active"
    }}
  ]
}}
  ],
  "catalogs": [
{{
  "id": "local-verification-marketplace",
  "label": "Local Verification Marketplace",
  "plugins": [
    {{
      "manifestPath": "{}",
      "installationPolicy": "managed_copy",
      "authenticationPolicy": "operator_trust",
      "products": ["Autopilot"],
      "availableVersion": "2.0.0",
      "packageDigestSha256": "{verified_digest}",
      "signatureAlgorithm": "ed25519",
      "signaturePublicKey": "{verified_public_key}",
      "packageSignature": "{verified_signature}",
      "publisherId": "ioi-labs",
      "signingKeyId": "ioi-release-key",
      "publisherLabel": "IOI Labs",
      "signerIdentity": "ioi-release-signing",
      "verifiedAtMs": 1775419000000
    }},
    {{
      "manifestPath": "{}",
      "installationPolicy": "managed_copy",
      "authenticationPolicy": "operator_trust",
      "products": ["Autopilot"],
      "availableVersion": "2.0.0",
      "packageDigestSha256": "{unsigned_digest}",
      "publisherLabel": "Community Labs"
    }},
    {{
      "manifestPath": "{}",
      "installationPolicy": "managed_copy",
      "authenticationPolicy": "operator_trust",
      "products": ["Autopilot"],
      "availableVersion": "2.0.0",
      "packageDigestSha256": "{mismatch_digest}",
      "signatureAlgorithm": "ed25519",
      "signaturePublicKey": "{mismatch_public_key}",
      "packageSignature": "{mismatch_signature}",
      "publisherLabel": "Unknown Publisher",
      "signerIdentity": "tampered-signer"
    }}
  ]
}}
  ]
}}"#,
            slash_path(&verified_manifest),
            slash_path(&unverified_manifest),
            slash_path(&mismatch_manifest)
        ),
    )
    .expect("write verification marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load verification marketplace manifests");
    let snapshot = build_session_plugin_snapshot_for_manifests(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
    );

    assert_eq!(snapshot.plugin_count, 3);
    assert_eq!(snapshot.verified_plugin_count, 1);
    assert_eq!(snapshot.unverified_plugin_count, 1);
    assert_eq!(snapshot.signature_mismatch_plugin_count, 1);

    let verified = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Verified Plugin")
        .expect("verified plugin present");
    assert_eq!(verified.authenticity_state, "verified");
    assert_eq!(verified.authenticity_label, "Signature verified");
    assert_eq!(verified.verification_algorithm.as_deref(), Some("ed25519"));
    assert_eq!(verified.publisher_label.as_deref(), Some("IOI Labs"));
    assert_eq!(
        verified.signer_identity.as_deref(),
        Some("ioi-release-signing")
    );
    assert_eq!(verified.verification_timestamp_ms, Some(1775419000000));
    assert_eq!(
        verified.verification_source.as_deref(),
        Some("runtime signature verification")
    );
    assert_eq!(verified.publisher_id.as_deref(), Some("ioi-labs"));
    assert_eq!(verified.signing_key_id.as_deref(), Some("ioi-release-key"));
    assert_eq!(verified.publisher_trust_state.as_deref(), Some("trusted"));
    assert_eq!(
        verified.publisher_trust_label.as_deref(),
        Some("Trusted publisher")
    );
    assert_eq!(
        verified.verified_digest_sha256.as_deref(),
        Some(verified_digest.as_str())
    );
    assert_eq!(
        verified.trust_score_label.as_deref(),
        Some("High confidence")
    );

    let unverified = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Unverified Plugin")
        .expect("unverified plugin present");
    assert_eq!(unverified.authenticity_state, "unsigned");
    assert_eq!(unverified.authenticity_label, "Unsigned package");
    assert_eq!(
        unverified.verification_source.as_deref(),
        Some("runtime package digest")
    );
    assert_eq!(
        unverified.verified_digest_sha256.as_deref(),
        Some(unsigned_digest.as_str())
    );
    assert_eq!(
        unverified.trust_recommendation.as_deref(),
        Some("Review the publisher, signer, and requested capabilities before granting trust.")
    );

    let mismatch = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Mismatch Plugin")
        .expect("mismatch plugin present");
    let tampered_mismatch_digest = compute_plugin_package_digest_sha256(&mismatch_root)
        .expect("compute tampered mismatch digest");
    let expected_mismatch_error = format!(
        "Computed package digest sha256:{} did not match the published digest sha256:{}.",
        tampered_mismatch_digest, mismatch_digest
    );
    assert_eq!(mismatch.authenticity_state, "signature_mismatch");
    assert_eq!(mismatch.verification_algorithm.as_deref(), Some("ed25519"));
    assert_eq!(
        mismatch.verification_error.as_deref(),
        Some(expected_mismatch_error.as_str())
    );
    assert_eq!(mismatch.trust_score_label.as_deref(), Some("Blocked"));

    let _ = std::fs::remove_dir_all(temp_root);
}
