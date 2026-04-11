use super::*;

#[test]
fn distributed_authority_bundle_states_flow_into_snapshot() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-authority-trust-bundle-{}",
        std::process::id()
    ));
    let rooted_manifest = write_test_plugin_manifest(
        &temp_root.join("rooted-distributed-plugin"),
        "rooted-distributed-plugin",
        "Rooted Distributed Plugin",
    );
    let unknown_manifest = write_test_plugin_manifest(
        &temp_root.join("unknown-distributed-plugin"),
        "unknown-distributed-plugin",
        "Unknown Distributed Plugin",
    );
    let expired_manifest = write_test_plugin_manifest(
        &temp_root.join("expired-distributed-plugin"),
        "expired-distributed-plugin",
        "Expired Distributed Plugin",
    );
    let rooted_root = manifest_parent_root(&rooted_manifest).expect("rooted distributed root");
    let unknown_root = manifest_parent_root(&unknown_manifest).expect("unknown distributed root");
    let expired_root = manifest_parent_root(&expired_manifest).expect("expired distributed root");
    let (rooted_digest, rooted_public_key, rooted_signature) = sign_plugin_package(&rooted_root);
    let (unknown_digest, unknown_public_key, unknown_signature) =
        sign_plugin_package(&unknown_root);
    let (expired_digest, expired_public_key, expired_signature) =
        sign_plugin_package(&expired_root);
    let (rooted_marketplace_root, rooted_publisher) = rooted_publisher_fixture(
        "distributed-ioi-marketplace-root",
        "Distributed IOI Marketplace Root",
        Some("active"),
        "distributed marketplace root store",
        None,
        "rooted-distributed-publisher",
        "IOI Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "rooted-distributed-ed25519",
        &rooted_public_key,
        Some("active"),
        None,
        1775431800000,
    );
    let (missing_marketplace_root, unknown_publisher) = rooted_publisher_fixture(
        "distributed-community-marketplace-root",
        "Distributed Community Root",
        Some("active"),
        "distributed community root store",
        None,
        "unknown-distributed-publisher",
        "Community Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "unknown-distributed-ed25519",
        &unknown_public_key,
        Some("active"),
        None,
        1775432400000,
    );
    let (expired_marketplace_root, expired_publisher) = rooted_publisher_fixture(
        "distributed-expired-marketplace-root",
        "Distributed Expired Root",
        Some("active"),
        "distributed expired root store",
        None,
        "expired-distributed-publisher",
        "Expired Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "expired-distributed-ed25519",
        &expired_public_key,
        Some("active"),
        None,
        1775433000000,
    );
    let (rooted_authority, rooted_bundle) = authority_bundle_fixture(
        "distributed-ioi-marketplace-authority",
        "Distributed IOI Marketplace Authority",
        Some("active"),
        "distributed marketplace authority bundle",
        "distributed-ioi-marketplace-authority-bundle",
        "Distributed IOI Marketplace Authority Bundle",
        vec![rooted_marketplace_root.clone()],
        Vec::new(),
        1775433600000,
    );
    let (unknown_authority, _unknown_bundle_not_used) = authority_bundle_fixture(
        "distributed-community-marketplace-authority",
        "Distributed Community Marketplace Authority",
        Some("active"),
        "distributed marketplace authority bundle",
        "distributed-community-marketplace-authority-bundle",
        "Distributed Community Marketplace Authority Bundle",
        vec![missing_marketplace_root.clone()],
        Vec::new(),
        1775434200000,
    );
    let (expired_authority, expired_bundle) = authority_bundle_fixture(
        "distributed-expired-marketplace-authority",
        "Distributed Expired Marketplace Authority",
        Some("active"),
        "distributed marketplace authority bundle",
        "distributed-expired-marketplace-authority-bundle",
        "Distributed Expired Marketplace Authority Bundle",
        vec![expired_marketplace_root.clone()],
        Vec::new(),
        1775434800000,
    );
    let now_ms = state::now();
    let (authority_trust_root, authority_trust_bundle) = authority_trust_bundle_fixture(
        "distributed-authority-root",
        "Distributed Authority Root",
        Some("active"),
        "distributed authority root store",
        None,
        "distributed-authority-trust-bundle",
        "Distributed Authority Trust Bundle",
        "distributed authority bundle verification",
        vec![rooted_authority.clone()],
        Vec::new(),
        now_ms.saturating_sub(60_000),
        Some(now_ms.saturating_add(86_400_000)),
    );
    let (expired_authority_trust_root, expired_authority_trust_bundle) =
        authority_trust_bundle_fixture(
            "distributed-expired-authority-root",
            "Distributed Expired Authority Root",
            Some("active"),
            "distributed authority root store",
            None,
            "distributed-expired-authority-trust-bundle",
            "Distributed Expired Authority Trust Bundle",
            "distributed authority bundle verification",
            vec![expired_authority.clone()],
            Vec::new(),
            now_ms.saturating_sub(172_800_000),
            Some(now_ms.saturating_sub(60_000)),
        );

    let fixture_path = temp_root.join("plugin-marketplace-authority-trust-bundle.json");
    let fixture = serde_json::json!({
        "authorityTrustRoots": [authority_trust_root, expired_authority_trust_root],
        "authorityTrustBundles": [authority_trust_bundle, expired_authority_trust_bundle],
        "authorityBundles": [rooted_bundle, expired_bundle],
        "publishers": [rooted_publisher, unknown_publisher, expired_publisher],
        "catalogs": [
            {
                "id": "distributed-authority-marketplace",
                "label": "Distributed Authority Marketplace",
                "plugins": [
                    {
                        "manifestPath": slash_path(&rooted_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "2.0.0",
                        "packageDigestSha256": rooted_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": rooted_public_key,
                        "packageSignature": rooted_signature,
                        "publisherId": "rooted-distributed-publisher",
                        "signingKeyId": "rooted-distributed-ed25519",
                        "publisherLabel": "IOI Labs",
                        "signerIdentity": "ioi-release-signing"
                    },
                    {
                        "manifestPath": slash_path(&unknown_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "2.0.0",
                        "packageDigestSha256": unknown_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": unknown_public_key,
                        "packageSignature": unknown_signature,
                        "publisherId": "unknown-distributed-publisher",
                        "signingKeyId": "unknown-distributed-ed25519",
                        "publisherLabel": "Community Labs",
                        "signerIdentity": "community-release-signing"
                    },
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
                        "publisherId": "expired-distributed-publisher",
                        "signingKeyId": "expired-distributed-ed25519",
                        "publisherLabel": "Expired Labs",
                        "signerIdentity": "expired-release-signing"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture)
            .expect("encode authority trust bundle marketplace fixture"),
    )
    .expect("write authority trust bundle marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load authority trust bundle manifests");
    let snapshot = build_session_plugin_snapshot_for_manifests(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
    );

    let rooted = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Rooted Distributed Plugin")
        .expect("rooted distributed plugin present");
    assert_eq!(rooted.authenticity_state, "verified");
    assert_eq!(
        rooted.publisher_trust_state.as_deref(),
        Some("rooted_bundle")
    );
    assert_eq!(
        rooted.authority_trust_bundle_label.as_deref(),
        Some("Distributed Authority Trust Bundle")
    );
    assert_eq!(
        rooted.authority_trust_bundle_status.as_deref(),
        Some("active")
    );

    let unknown = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Unknown Distributed Plugin")
        .expect("unknown distributed plugin present");
    assert_eq!(unknown.authenticity_state, "verified");
    assert_eq!(
        unknown.publisher_trust_state.as_deref(),
        Some("unknown_authority_bundle")
    );
    assert_eq!(
        unknown.publisher_trust_label.as_deref(),
        Some("Publisher unknown authority bundle")
    );
    assert_eq!(
        unknown.trust_score_label.as_deref(),
        Some("Authority bundle review required")
    );

    let expired = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Expired Distributed Plugin")
        .expect("expired distributed plugin present");
    assert_eq!(expired.authenticity_state, "verified");
    assert_eq!(
        expired.publisher_trust_state.as_deref(),
        Some("expired_authority_bundle")
    );
    assert_eq!(
        expired.publisher_trust_label.as_deref(),
        Some("Authority bundle expired")
    );
    assert_eq!(
        expired.authority_trust_bundle_status.as_deref(),
        Some("expired")
    );
    assert_eq!(expired.trust_score_label.as_deref(), Some("Blocked"));

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    let expired_manifest_record = manifests
        .iter()
        .find(|manifest| manifest.display_name.as_deref() == Some("Expired Distributed Plugin"))
        .expect("expired distributed manifest present")
        .clone();
    manager
        .trust_plugin(&expired_manifest_record, true)
        .expect("expired authority trust should still record a receipt");
    let blocked_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let blocked = blocked_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Expired Distributed Plugin")
        .expect("blocked expired distributed plugin present");
    assert_eq!(blocked.runtime_trust_state, "trust_required");
    assert_eq!(blocked.runtime_load_state, "blocked");
    assert!(blocked_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| { receipt.action == "trust" && receipt.status == "blocked" }));

    let _ = unknown_authority;
    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn signature_mismatch_blocks_trust_and_install() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-lifecycle-{}",
        std::process::id()
    ));
    let mismatch_manifest = write_test_plugin_manifest(
        &temp_root.join("mismatch-plugin"),
        "mismatch-plugin",
        "Mismatch Plugin",
    );
    let mismatch_root = manifest_parent_root(&mismatch_manifest).expect("mismatch root");
    let (mismatch_digest, mismatch_public_key, mismatch_signature) =
        sign_plugin_package(&mismatch_root);
    std::fs::write(
        mismatch_root.join("README.md"),
        "Mismatch Plugin tampered payload\n",
    )
    .expect("tamper mismatch plugin payload");

    let fixture_path = temp_root.join("plugin-marketplace-lifecycle.json");
    std::fs::write(
        &fixture_path,
        format!(
            r#"{{
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
      "packageDigestSha256": "{mismatch_digest}",
      "signatureAlgorithm": "ed25519",
      "signaturePublicKey": "{mismatch_public_key}",
      "packageSignature": "{mismatch_signature}",
      "publisherLabel": "Unknown Publisher"
    }}
  ]
}}
  ]
}}"#,
            slash_path(&mismatch_manifest),
        ),
    )
    .expect("write lifecycle marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load lifecycle manifests");
    let manifest = manifests[0].clone();
    assert_eq!(
        manifest.marketplace_verification_status.as_deref(),
        Some("signature_mismatch")
    );

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    manager
        .trust_plugin(&manifest, true)
        .expect("blocked trust should still record a receipt");
    manager
        .install_plugin_package(&manifest)
        .expect("blocked install should still record a receipt");

    let snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let plugin = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Mismatch Plugin")
        .expect("mismatch plugin present");
    assert_eq!(plugin.runtime_trust_state, "trust_required");
    assert_eq!(plugin.runtime_load_state, "blocked");
    assert!(!plugin.package_managed);
    assert!(plugin.package_error.is_some());
    assert!(snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "trust" && receipt.status == "blocked"));
    assert!(snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "install" && receipt.status == "blocked"));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn revoked_publisher_blocks_trust_and_install() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-revoked-publisher-{}",
        std::process::id()
    ));
    let revoked_manifest = write_test_plugin_manifest(
        &temp_root.join("revoked-plugin"),
        "revoked-plugin",
        "Revoked Publisher Plugin",
    );
    let revoked_root = manifest_parent_root(&revoked_manifest).expect("revoked root");
    let (revoked_digest, revoked_public_key, revoked_signature) =
        sign_plugin_package(&revoked_root);
    let (root, publisher) = rooted_publisher_fixture(
        "revoked-marketplace-root",
        "Revocation Marketplace Root",
        Some("active"),
        "revocation marketplace root store",
        None,
        "revoked-publisher",
        "Revoked Labs",
        Some("revoked"),
        "marketplace publisher chain",
        Some(1775421000000),
        "revoked-ed25519",
        &revoked_public_key,
        Some("active"),
        None,
        1775431400000,
    );

    let fixture_path = temp_root.join("plugin-marketplace-revoked-publisher.json");
    let fixture = serde_json::json!({
        "roots": [
            {
                "id": root.id,
                "label": root.label,
                "publicKey": root.public_key,
                "algorithm": root.algorithm,
                "status": root.status,
                "trustSource": root.trust_source,
                "revokedAtMs": root.revoked_at_ms
            }
        ],
        "publishers": [
            {
                "id": publisher.id,
                "label": publisher.label,
                "trustRootId": publisher.trust_root_id,
                "trustStatus": publisher.trust_status,
                "trustSource": publisher.trust_source,
                "revokedAtMs": publisher.revoked_at_ms,
                "statementSignature": publisher.statement_signature,
                "statementIssuedAtMs": publisher.statement_issued_at_ms,
                "signingKeys": publisher.signing_keys.iter().map(|key| serde_json::json!({
                    "id": key.id,
                    "algorithm": key.algorithm,
                    "publicKey": key.public_key,
                    "status": key.status,
                    "revokedAtMs": key.revoked_at_ms
                })).collect::<Vec<_>>()
            }
        ],
        "catalogs": [
            {
                "id": "rooted-publisher-marketplace",
                "label": "Rooted Publisher Marketplace",
                "plugins": [
                    {
                        "manifestPath": slash_path(&revoked_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "2.0.0",
                        "packageDigestSha256": revoked_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": revoked_public_key,
                        "packageSignature": revoked_signature,
                        "publisherId": "revoked-publisher",
                        "signingKeyId": "revoked-ed25519",
                        "publisherLabel": "Revoked Labs",
                        "signerIdentity": "revoked-release-signing"
                    }
                ]
            }
        ]
    });
    std::fs::write(
        &fixture_path,
        serde_json::to_vec_pretty(&fixture).expect("encode revoked publisher fixture"),
    )
    .expect("write revoked publisher fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load revoked publisher manifests");
    let manifest = manifests[0].clone();
    assert_eq!(
        manifest.marketplace_verification_status.as_deref(),
        Some("verified")
    );
    assert_eq!(
        manifest.marketplace_publisher_trust_status.as_deref(),
        Some("revoked_by_root")
    );

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    manager
        .trust_plugin(&manifest, true)
        .expect("revoked publisher trust should still record a receipt");
    manager
        .install_plugin_package(&manifest)
        .expect("revoked publisher install should still record a receipt");

    let snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let plugin = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Revoked Publisher Plugin")
        .expect("revoked publisher plugin present");
    assert_eq!(plugin.authenticity_state, "verified");
    assert_eq!(
        plugin.publisher_trust_state.as_deref(),
        Some("revoked_by_root")
    );
    assert_eq!(plugin.runtime_trust_state, "trust_required");
    assert_eq!(plugin.runtime_load_state, "blocked");
    assert!(!plugin.package_managed);
    assert!(plugin.package_error.is_some());
    assert!(snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "trust" && receipt.status == "blocked"));
    assert!(snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "install" && receipt.status == "blocked"));

    let _ = std::fs::remove_dir_all(temp_root);
}
