use super::*;

#[test]
fn publisher_chain_states_flow_into_snapshot() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-publisher-chain-{}",
        std::process::id()
    ));
    let trusted_manifest = write_test_plugin_manifest(
        &temp_root.join("trusted-plugin"),
        "trusted-plugin",
        "Trusted Publisher Plugin",
    );
    let unknown_manifest = write_test_plugin_manifest(
        &temp_root.join("unknown-plugin"),
        "unknown-plugin",
        "Unknown Publisher Plugin",
    );
    let revoked_manifest = write_test_plugin_manifest(
        &temp_root.join("revoked-plugin"),
        "revoked-plugin",
        "Revoked Publisher Plugin",
    );
    let trusted_root = manifest_parent_root(&trusted_manifest).expect("trusted root");
    let unknown_root = manifest_parent_root(&unknown_manifest).expect("unknown root");
    let revoked_root = manifest_parent_root(&revoked_manifest).expect("revoked root");
    let (trusted_digest, trusted_public_key, trusted_signature) =
        sign_plugin_package(&trusted_root);
    let (unknown_digest, unknown_public_key, unknown_signature) =
        sign_plugin_package(&unknown_root);
    let (revoked_digest, revoked_public_key, revoked_signature) =
        sign_plugin_package(&revoked_root);
    let (trusted_marketplace_root, trusted_publisher) = rooted_publisher_fixture(
        "ioi-marketplace-root",
        "IOI Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "trusted-publisher",
        "IOI Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "trusted-ed25519",
        &trusted_public_key,
        Some("active"),
        None,
        1775431200000,
    );
    let (missing_root, unknown_publisher) = rooted_publisher_fixture(
        "community-marketplace-root",
        "Community Marketplace Root",
        Some("active"),
        "community marketplace root store",
        None,
        "community-labs",
        "Community Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "community-ed25519",
        &unknown_public_key,
        Some("active"),
        None,
        1775431300000,
    );
    let (rooted_revocation_root, revoked_publisher) = rooted_publisher_fixture(
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

    let fixture_path = temp_root.join("plugin-marketplace-publisher-chain.json");
    let fixture = serde_json::json!({
        "roots": [
            {
                "id": trusted_marketplace_root.id,
                "label": trusted_marketplace_root.label,
                "publicKey": trusted_marketplace_root.public_key,
                "algorithm": trusted_marketplace_root.algorithm,
                "status": trusted_marketplace_root.status,
                "trustSource": trusted_marketplace_root.trust_source,
                "revokedAtMs": trusted_marketplace_root.revoked_at_ms
            },
            {
                "id": rooted_revocation_root.id,
                "label": rooted_revocation_root.label,
                "publicKey": rooted_revocation_root.public_key,
                "algorithm": rooted_revocation_root.algorithm,
                "status": rooted_revocation_root.status,
                "trustSource": rooted_revocation_root.trust_source,
                "revokedAtMs": rooted_revocation_root.revoked_at_ms
            }
        ],
        "publishers": [
            {
                "id": trusted_publisher.id,
                "label": trusted_publisher.label,
                "trustRootId": trusted_publisher.trust_root_id,
                "trustStatus": trusted_publisher.trust_status,
                "trustSource": trusted_publisher.trust_source,
                "revokedAtMs": trusted_publisher.revoked_at_ms,
                "statementSignature": trusted_publisher.statement_signature,
                "statementIssuedAtMs": trusted_publisher.statement_issued_at_ms,
                "signingKeys": trusted_publisher.signing_keys.iter().map(|key| serde_json::json!({
                    "id": key.id,
                    "algorithm": key.algorithm,
                    "publicKey": key.public_key,
                    "status": key.status,
                    "revokedAtMs": key.revoked_at_ms
                })).collect::<Vec<_>>()
            },
            {
                "id": unknown_publisher.id,
                "label": unknown_publisher.label,
                "trustRootId": unknown_publisher.trust_root_id,
                "trustStatus": unknown_publisher.trust_status,
                "trustSource": unknown_publisher.trust_source,
                "revokedAtMs": unknown_publisher.revoked_at_ms,
                "statementSignature": unknown_publisher.statement_signature,
                "statementIssuedAtMs": unknown_publisher.statement_issued_at_ms,
                "signingKeys": unknown_publisher.signing_keys.iter().map(|key| serde_json::json!({
                    "id": key.id,
                    "algorithm": key.algorithm,
                    "publicKey": key.public_key,
                    "status": key.status,
                    "revokedAtMs": key.revoked_at_ms
                })).collect::<Vec<_>>()
            },
            {
                "id": revoked_publisher.id,
                "label": revoked_publisher.label,
                "trustRootId": revoked_publisher.trust_root_id,
                "trustStatus": revoked_publisher.trust_status,
                "trustSource": revoked_publisher.trust_source,
                "revokedAtMs": revoked_publisher.revoked_at_ms,
                "statementSignature": revoked_publisher.statement_signature,
                "statementIssuedAtMs": revoked_publisher.statement_issued_at_ms,
                "signingKeys": revoked_publisher.signing_keys.iter().map(|key| serde_json::json!({
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
                        "manifestPath": slash_path(&trusted_manifest),
                        "installationPolicy": "managed_copy",
                        "authenticationPolicy": "operator_trust",
                        "products": ["Autopilot"],
                        "availableVersion": "2.0.0",
                        "packageDigestSha256": trusted_digest,
                        "signatureAlgorithm": "ed25519",
                        "signaturePublicKey": trusted_public_key,
                        "packageSignature": trusted_signature,
                        "publisherId": "trusted-publisher",
                        "signingKeyId": "trusted-ed25519",
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
                        "publisherId": "community-labs",
                        "signingKeyId": "community-ed25519",
                        "publisherLabel": "Community Labs",
                        "signerIdentity": "community-release-signing"
                    },
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
        serde_json::to_vec_pretty(&fixture).expect("encode publisher chain marketplace fixture"),
    )
    .expect("write publisher chain marketplace fixture");
    std::mem::drop(missing_root);

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load publisher chain manifests");
    let snapshot = build_session_plugin_snapshot_for_manifests(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
    );

    assert_eq!(snapshot.plugin_count, 3);
    assert_eq!(snapshot.verified_plugin_count, 3);
    assert_eq!(snapshot.signature_mismatch_plugin_count, 0);

    let trusted = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Trusted Publisher Plugin")
        .expect("trusted publisher plugin present");
    assert_eq!(trusted.authenticity_state, "verified");
    assert_eq!(trusted.publisher_trust_state.as_deref(), Some("rooted"));
    assert_eq!(
        trusted.publisher_trust_label.as_deref(),
        Some("Publisher rooted")
    );
    assert_eq!(
        trusted.publisher_root_label.as_deref(),
        Some("IOI Marketplace Root")
    );
    assert_eq!(
        trusted.publisher_statement_issued_at_ms,
        Some(1775431200000)
    );
    assert_eq!(
        trusted.trust_score_label.as_deref(),
        Some("High confidence")
    );

    let unknown = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Unknown Publisher Plugin")
        .expect("unknown publisher plugin present");
    assert_eq!(unknown.authenticity_state, "verified");
    assert_eq!(
        unknown.publisher_trust_state.as_deref(),
        Some("unknown_root")
    );
    assert_eq!(
        unknown.publisher_trust_label.as_deref(),
        Some("Publisher unknown root")
    );
    assert_eq!(
        unknown.trust_score_label.as_deref(),
        Some("Root review required")
    );
    assert_eq!(
        unknown.publisher_root_id.as_deref(),
        Some("community-marketplace-root")
    );

    let revoked = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Revoked Publisher Plugin")
        .expect("revoked publisher plugin present");
    assert_eq!(revoked.authenticity_state, "verified");
    assert_eq!(
        revoked.publisher_trust_state.as_deref(),
        Some("revoked_by_root")
    );
    assert_eq!(
        revoked.publisher_trust_label.as_deref(),
        Some("Publisher revoked by root")
    );
    assert_eq!(revoked.publisher_revoked_at_ms, Some(1775421000000));
    assert_eq!(revoked.trust_score_label.as_deref(), Some("Blocked"));

    let _ = std::fs::remove_dir_all(temp_root);
}

#[test]
fn authority_bundle_states_flow_into_snapshot() {
    let temp_root = std::env::temp_dir().join(format!(
        "autopilot-plugin-marketplace-authority-bundle-{}",
        std::process::id()
    ));
    let rooted_manifest = write_test_plugin_manifest(
        &temp_root.join("rooted-bundle-plugin"),
        "rooted-bundle-plugin",
        "Rooted Bundle Plugin",
    );
    let unknown_manifest = write_test_plugin_manifest(
        &temp_root.join("unknown-bundle-plugin"),
        "unknown-bundle-plugin",
        "Unknown Bundle Plugin",
    );
    let revoked_manifest = write_test_plugin_manifest(
        &temp_root.join("revoked-bundle-plugin"),
        "revoked-bundle-plugin",
        "Revoked Bundle Plugin",
    );
    let rooted_root = manifest_parent_root(&rooted_manifest).expect("rooted bundle root");
    let unknown_root = manifest_parent_root(&unknown_manifest).expect("unknown bundle root");
    let revoked_root = manifest_parent_root(&revoked_manifest).expect("revoked bundle root");
    let (rooted_digest, rooted_public_key, rooted_signature) = sign_plugin_package(&rooted_root);
    let (unknown_digest, unknown_public_key, unknown_signature) =
        sign_plugin_package(&unknown_root);
    let (revoked_digest, revoked_public_key, revoked_signature) =
        sign_plugin_package(&revoked_root);
    let (rooted_marketplace_root, rooted_publisher) = rooted_publisher_fixture(
        "ioi-marketplace-root",
        "IOI Marketplace Root",
        Some("active"),
        "trusted marketplace root store",
        None,
        "rooted-bundle-publisher",
        "IOI Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "rooted-ed25519",
        &rooted_public_key,
        Some("active"),
        None,
        1775431800000,
    );
    let (missing_bundle_root, unknown_publisher) = rooted_publisher_fixture(
        "community-marketplace-root",
        "Community Marketplace Root",
        Some("active"),
        "community marketplace root store",
        None,
        "unknown-bundle-publisher",
        "Community Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "unknown-ed25519",
        &unknown_public_key,
        Some("active"),
        None,
        1775432400000,
    );
    let (revoked_marketplace_root, revoked_publisher) = rooted_publisher_fixture(
        "revoked-marketplace-root",
        "Revocation Marketplace Root",
        Some("active"),
        "revocation marketplace root store",
        None,
        "revoked-bundle-publisher",
        "Revoked Labs",
        Some("trusted"),
        "marketplace publisher chain",
        None,
        "revoked-ed25519",
        &revoked_public_key,
        Some("active"),
        None,
        1775433000000,
    );
    let (rooted_authority, rooted_bundle) = authority_bundle_fixture(
        "ioi-marketplace-authority",
        "IOI Marketplace Authority",
        Some("active"),
        "trusted marketplace authority bundle",
        "ioi-marketplace-authority-bundle",
        "IOI Marketplace Authority Bundle",
        vec![rooted_marketplace_root.clone()],
        Vec::new(),
        1775433600000,
    );
    let (_missing_authority, unknown_bundle) = authority_bundle_fixture(
        "community-marketplace-authority",
        "Community Marketplace Authority",
        Some("active"),
        "community marketplace authority bundle",
        "community-marketplace-authority-bundle",
        "Community Marketplace Authority Bundle",
        vec![missing_bundle_root.clone()],
        Vec::new(),
        1775434200000,
    );
    let (revoked_authority, revoked_bundle) = authority_bundle_fixture(
        "revocation-marketplace-authority",
        "Revocation Marketplace Authority",
        Some("active"),
        "revocation marketplace authority bundle",
        "revocation-marketplace-authority-bundle",
        "Revocation Marketplace Authority Bundle",
        vec![revoked_marketplace_root.clone()],
        vec![PluginMarketplacePublisherRevocation {
            publisher_id: "revoked-bundle-publisher".to_string(),
            label: Some("Revoked Labs".to_string()),
            revoked_at_ms: Some(1775434800000),
            reason: Some("Publisher certificate revoked by authority".to_string()),
        }],
        1775434800000,
    );

    let fixture_path = temp_root.join("plugin-marketplace-authority-bundle.json");
    let fixture = serde_json::json!({
        "bundleAuthorities": [
            {
                "id": rooted_authority.id,
                "label": rooted_authority.label,
                "publicKey": rooted_authority.public_key,
                "algorithm": rooted_authority.algorithm,
                "status": rooted_authority.status,
                "trustSource": rooted_authority.trust_source,
            },
            {
                "id": revoked_authority.id,
                "label": revoked_authority.label,
                "publicKey": revoked_authority.public_key,
                "algorithm": revoked_authority.algorithm,
                "status": revoked_authority.status,
                "trustSource": revoked_authority.trust_source,
            }
        ],
        "authorityBundles": [
            {
                "id": rooted_bundle.id,
                "label": rooted_bundle.label,
                "authorityId": rooted_bundle.authority_id,
                "issuedAtMs": rooted_bundle.issued_at_ms,
                "signature": rooted_bundle.signature,
                "signatureAlgorithm": rooted_bundle.signature_algorithm,
                "trustSource": rooted_bundle.trust_source,
                "roots": rooted_bundle.roots,
                "publisherRevocations": rooted_bundle.publisher_revocations,
            },
            {
                "id": unknown_bundle.id,
                "label": unknown_bundle.label,
                "authorityId": unknown_bundle.authority_id,
                "issuedAtMs": unknown_bundle.issued_at_ms,
                "signature": unknown_bundle.signature,
                "signatureAlgorithm": unknown_bundle.signature_algorithm,
                "trustSource": unknown_bundle.trust_source,
                "roots": unknown_bundle.roots,
                "publisherRevocations": unknown_bundle.publisher_revocations,
            },
            {
                "id": revoked_bundle.id,
                "label": revoked_bundle.label,
                "authorityId": revoked_bundle.authority_id,
                "issuedAtMs": revoked_bundle.issued_at_ms,
                "signature": revoked_bundle.signature,
                "signatureAlgorithm": revoked_bundle.signature_algorithm,
                "trustSource": revoked_bundle.trust_source,
                "roots": revoked_bundle.roots,
                "publisherRevocations": revoked_bundle.publisher_revocations,
            }
        ],
        "publishers": [rooted_publisher, unknown_publisher, revoked_publisher],
        "catalogs": [
            {
                "id": "authority-bundle-marketplace",
                "label": "Authority Bundle Marketplace",
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
                        "publisherId": "rooted-bundle-publisher",
                        "signingKeyId": "rooted-ed25519",
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
                        "publisherId": "unknown-bundle-publisher",
                        "signingKeyId": "unknown-ed25519",
                        "publisherLabel": "Community Labs",
                        "signerIdentity": "community-release-signing"
                    },
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
                        "publisherId": "revoked-bundle-publisher",
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
        serde_json::to_vec_pretty(&fixture).expect("encode authority bundle marketplace fixture"),
    )
    .expect("write authority bundle marketplace fixture");

    let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
        .expect("load authority bundle manifests");
    let snapshot = build_session_plugin_snapshot_for_manifests(
        &manifests,
        PluginRuntimeState::default(),
        None,
        None,
    );

    let rooted = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Rooted Bundle Plugin")
        .expect("rooted bundle plugin present");
    assert_eq!(rooted.authenticity_state, "verified");
    assert_eq!(
        rooted.publisher_trust_state.as_deref(),
        Some("rooted_bundle")
    );
    assert_eq!(
        rooted.publisher_trust_label.as_deref(),
        Some("Publisher rooted by authority bundle")
    );
    assert_eq!(
        rooted.authority_bundle_label.as_deref(),
        Some("IOI Marketplace Authority Bundle")
    );
    assert_eq!(
        rooted.authority_label.as_deref(),
        Some("IOI Marketplace Authority")
    );

    let unknown = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Unknown Bundle Plugin")
        .expect("unknown bundle plugin present");
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

    let revoked = snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Revoked Bundle Plugin")
        .expect("revoked bundle plugin present");
    assert_eq!(revoked.authenticity_state, "verified");
    assert_eq!(
        revoked.publisher_trust_state.as_deref(),
        Some("revoked_by_authority_bundle")
    );
    assert_eq!(
        revoked.publisher_trust_label.as_deref(),
        Some("Publisher revoked by authority bundle")
    );
    assert_eq!(revoked.publisher_revoked_at_ms, Some(1775434800000));
    assert_eq!(revoked.trust_score_label.as_deref(), Some("Blocked"));

    let runtime_path = temp_root.join("plugin_runtime_state.json");
    let manager = PluginRuntimeManager::new(runtime_path);
    let revoked_manifest_record = manifests
        .iter()
        .find(|manifest| manifest.display_name.as_deref() == Some("Revoked Bundle Plugin"))
        .expect("revoked bundle manifest present")
        .clone();
    manager
        .trust_plugin(&revoked_manifest_record, true)
        .expect("blocked authority trust should still record a receipt");
    let blocked_snapshot =
        build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
    let blocked = blocked_snapshot
        .plugins
        .iter()
        .find(|plugin| plugin.label == "Revoked Bundle Plugin")
        .expect("blocked revoked bundle plugin present");
    assert_eq!(blocked.runtime_trust_state, "trust_required");
    assert_eq!(blocked.runtime_load_state, "blocked");
    assert!(blocked_snapshot
        .recent_receipts
        .iter()
        .any(|receipt| receipt.action == "trust" && receipt.status == "blocked"));

    let _ = std::fs::remove_dir_all(temp_root);
}
