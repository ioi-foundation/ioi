use super::*;

pub(crate) fn verify_plugin_marketplace_catalog_refresh_bundles(
    roots: &[PluginMarketplaceTrustRoot],
    bundles: &[PluginMarketplaceCatalogRefreshBundle],
    now_ms: u64,
) -> Vec<PluginVerifiedCatalogRefreshBundle> {
    let mut verified = Vec::new();
    for bundle in bundles {
        let issuer_id = bundle.issuer_id.trim();
        let catalog_id = bundle.catalog_id.trim();
        if issuer_id.is_empty() || catalog_id.is_empty() || bundle.plugins.is_empty() {
            continue;
        }
        let Some(root) = roots
            .iter()
            .find(|candidate| candidate.id.trim() == issuer_id)
        else {
            continue;
        };
        if matches!(root.status.as_deref(), Some("revoked")) || root.revoked_at_ms.is_some() {
            continue;
        }

        let root_algorithm = root
            .algorithm
            .clone()
            .unwrap_or_else(|| "ed25519".to_string());
        let bundle_algorithm = bundle
            .signature_algorithm
            .clone()
            .unwrap_or_else(|| "ed25519".to_string());
        if !root_algorithm.eq_ignore_ascii_case("ed25519")
            || !bundle_algorithm.eq_ignore_ascii_case("ed25519")
        {
            continue;
        }

        let Some(signature_raw) = bundle
            .signature
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let root_public_key_bytes = match decode_signature_material(
            &root.public_key,
            "marketplace catalog refresh root public key",
        ) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let root_public_key =
            match <Ed25519PublicKey as SerializableKey>::from_bytes(&root_public_key_bytes) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
        let signature_bytes =
            match decode_signature_material(signature_raw, "marketplaceCatalogRefreshSignature") {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
        let signature = match <Ed25519Signature as SerializableKey>::from_bytes(&signature_bytes) {
            Ok(signature) => signature,
            Err(_) => continue,
        };
        let message = plugin_marketplace_catalog_refresh_bundle_message(bundle);
        if root_public_key.verify(&message, &signature).is_err() {
            continue;
        }

        let bundle_status = if bundle
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            "expired".to_string()
        } else {
            "active".to_string()
        };

        verified.push(PluginVerifiedCatalogRefreshBundle {
            bundle_id: bundle.id.clone(),
            bundle_label: bundle.label.clone(),
            catalog_id: bundle.catalog_id.clone(),
            issued_at_ms: bundle.issued_at_ms,
            expires_at_ms: bundle.expires_at_ms,
            refreshed_at_ms: bundle.refreshed_at_ms,
            refresh_source: bundle.refresh_source.clone(),
            channel: bundle.channel.clone(),
            issuer_id: root.id.clone(),
            issuer_label: root.label.clone(),
            bundle_status,
            plugins: bundle.plugins.clone(),
        });
    }
    verified
}

pub(crate) fn compute_plugin_marketplace_verification(
    entry: &PluginMarketplaceCatalogEntry,
    package_target: &PluginPackageVerificationTarget,
) -> Result<Option<PluginComputedVerification>, String> {
    let has_runtime_inputs = entry.package_digest_sha256.is_some()
        || entry.signature_algorithm.is_some()
        || entry.signature_public_key.is_some()
        || entry.package_signature.is_some();
    if !has_runtime_inputs {
        return Ok(None);
    }

    let digest_sha256 = match package_target {
        PluginPackageVerificationTarget::LocalRoot(root) => {
            compute_plugin_package_digest_sha256(root)?
        }
        PluginPackageVerificationTarget::ArchiveUri(location) => {
            compute_plugin_package_digest_sha256_from_archive(location)?
        }
    };
    if let Some(expected_digest) = entry.package_digest_sha256.as_deref() {
        let expected_digest = match normalize_sha256_hex(expected_digest, "packageDigestSha256") {
            Ok(value) => value,
            Err(error) => {
                return Ok(Some(PluginComputedVerification {
                    status: Some("signature_mismatch".to_string()),
                    error: Some(error),
                    algorithm: entry.signature_algorithm.clone(),
                    source: Some("runtime signature verification".to_string()),
                    digest_sha256: Some(digest_sha256),
                }))
            }
        };
        if digest_sha256 != expected_digest {
            return Ok(Some(PluginComputedVerification {
                status: Some("signature_mismatch".to_string()),
                error: Some(format!(
                    "Computed package digest sha256:{} did not match the published digest sha256:{}.",
                    digest_sha256, expected_digest
                )),
                algorithm: entry.signature_algorithm.clone(),
                source: Some("runtime signature verification".to_string()),
                digest_sha256: Some(digest_sha256),
            }));
        }
    }

    let signature_public_key = entry
        .signature_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let package_signature = entry
        .package_signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if signature_public_key.is_none() && package_signature.is_none() {
        return Ok(Some(PluginComputedVerification {
            status: Some("unsigned".to_string()),
            error: None,
            algorithm: entry.signature_algorithm.clone(),
            source: Some("runtime package digest".to_string()),
            digest_sha256: Some(digest_sha256),
        }));
    }
    if signature_public_key.is_none() || package_signature.is_none() {
        return Ok(Some(PluginComputedVerification {
            status: Some("signature_mismatch".to_string()),
            error: Some(
                "Marketplace signature metadata is incomplete for this package.".to_string(),
            ),
            algorithm: entry.signature_algorithm.clone(),
            source: Some("runtime signature verification".to_string()),
            digest_sha256: Some(digest_sha256),
        }));
    }

    let algorithm = entry
        .signature_algorithm
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    if !algorithm.eq_ignore_ascii_case("ed25519") {
        return Ok(Some(PluginComputedVerification {
            status: Some("signature_mismatch".to_string()),
            error: Some(format!(
                "Unsupported plugin signature algorithm '{}'.",
                algorithm
            )),
            algorithm: Some(algorithm),
            source: Some("runtime signature verification".to_string()),
            digest_sha256: Some(digest_sha256),
        }));
    }

    let public_key_bytes = match decode_signature_material(
        signature_public_key.unwrap_or_default(),
        "signaturePublicKey",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(Some(PluginComputedVerification {
                status: Some("signature_mismatch".to_string()),
                error: Some(error),
                algorithm: Some(algorithm),
                source: Some("runtime signature verification".to_string()),
                digest_sha256: Some(digest_sha256),
            }))
        }
    };
    let signature_bytes = match decode_signature_material(
        package_signature.unwrap_or_default(),
        "packageSignature",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(Some(PluginComputedVerification {
                status: Some("signature_mismatch".to_string()),
                error: Some(error),
                algorithm: Some(algorithm),
                source: Some("runtime signature verification".to_string()),
                digest_sha256: Some(digest_sha256),
            }))
        }
    };
    let public_key = match <Ed25519PublicKey as SerializableKey>::from_bytes(&public_key_bytes) {
        Ok(public_key) => public_key,
        Err(error) => {
            return Ok(Some(PluginComputedVerification {
                status: Some("signature_mismatch".to_string()),
                error: Some(format!("Invalid plugin signature public key: {}", error)),
                algorithm: Some(algorithm),
                source: Some("runtime signature verification".to_string()),
                digest_sha256: Some(digest_sha256),
            }))
        }
    };
    let signature = match <Ed25519Signature as SerializableKey>::from_bytes(&signature_bytes) {
        Ok(signature) => signature,
        Err(error) => {
            return Ok(Some(PluginComputedVerification {
                status: Some("signature_mismatch".to_string()),
                error: Some(format!("Invalid plugin package signature: {}", error)),
                algorithm: Some(algorithm),
                source: Some("runtime signature verification".to_string()),
                digest_sha256: Some(digest_sha256),
            }))
        }
    };
    let verification_message = plugin_signature_message(&digest_sha256);
    let status = if public_key.verify(&verification_message, &signature).is_ok() {
        "verified"
    } else {
        "signature_mismatch"
    };
    let error = if status == "verified" {
        None
    } else {
        Some(format!(
            "Package signature did not validate against computed digest sha256:{}.",
            digest_sha256
        ))
    };

    Ok(Some(PluginComputedVerification {
        status: Some(status.to_string()),
        error,
        algorithm: Some(algorithm),
        source: Some("runtime signature verification".to_string()),
        digest_sha256: Some(digest_sha256),
    }))
}
