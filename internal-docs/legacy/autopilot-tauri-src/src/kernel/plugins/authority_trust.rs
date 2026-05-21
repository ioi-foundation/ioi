use super::*;

pub(crate) fn verify_plugin_marketplace_authority_bundles(
    legacy_authorities: &[PluginMarketplaceBundleAuthority],
    distributed_authorities: &[PluginDistributedAuthority],
    bundles: &[PluginMarketplaceAuthorityBundle],
) -> Vec<PluginVerifiedAuthorityBundle> {
    let mut verified = Vec::new();
    for bundle in bundles {
        let authority_id = bundle.authority_id.trim();
        if authority_id.is_empty() {
            continue;
        }
        let distributed_authority = distributed_authorities
            .iter()
            .find(|candidate| candidate.authority.id.trim() == authority_id);
        let legacy_authority = legacy_authorities
            .iter()
            .find(|candidate| candidate.id.trim() == authority_id);
        let authority = if let Some(distributed_authority) = distributed_authority {
            &distributed_authority.authority
        } else if let Some(legacy_authority) = legacy_authority {
            legacy_authority
        } else {
            continue;
        };
        if distributed_authority.is_none()
            && (matches!(authority.status.as_deref(), Some("revoked"))
                || authority.revoked_at_ms.is_some())
        {
            continue;
        }

        let authority_algorithm = authority
            .algorithm
            .clone()
            .unwrap_or_else(|| "ed25519".to_string());
        let bundle_algorithm = bundle
            .signature_algorithm
            .clone()
            .unwrap_or_else(|| "ed25519".to_string());
        if !authority_algorithm.eq_ignore_ascii_case("ed25519")
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

        let authority_public_key_bytes = match decode_signature_material(
            &authority.public_key,
            "marketplace authority public key",
        ) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let authority_public_key =
            match <Ed25519PublicKey as SerializableKey>::from_bytes(&authority_public_key_bytes) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
        let signature_bytes =
            match decode_signature_material(signature_raw, "marketplaceAuthorityBundleSignature") {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
        let signature = match <Ed25519Signature as SerializableKey>::from_bytes(&signature_bytes) {
            Ok(signature) => signature,
            Err(_) => continue,
        };
        let message = plugin_marketplace_authority_bundle_message(bundle);
        if authority_public_key.verify(&message, &signature).is_err() {
            continue;
        }

        verified.push(PluginVerifiedAuthorityBundle {
            bundle_id: bundle.id.clone(),
            bundle_label: bundle.label.clone(),
            bundle_issued_at_ms: bundle.issued_at_ms,
            authority_id: authority.id.clone(),
            authority_label: authority.label.clone(),
            trust_source: distributed_authority
                .and_then(|candidate| candidate.trust_source.clone())
                .or_else(|| bundle.trust_source.clone())
                .or_else(|| authority.trust_source.clone())
                .or(Some(
                    "marketplace authority bundle verification".to_string(),
                )),
            authority_trust_bundle_id: distributed_authority
                .map(|candidate| candidate.trust_bundle_id.clone()),
            authority_trust_bundle_label: distributed_authority
                .and_then(|candidate| candidate.trust_bundle_label.clone()),
            authority_trust_bundle_issued_at_ms: distributed_authority
                .and_then(|candidate| candidate.trust_bundle_issued_at_ms),
            authority_trust_bundle_expires_at_ms: distributed_authority
                .and_then(|candidate| candidate.trust_bundle_expires_at_ms),
            authority_trust_bundle_status: distributed_authority
                .map(|candidate| candidate.trust_bundle_status.clone()),
            authority_trust_issuer_id: distributed_authority
                .map(|candidate| candidate.trust_bundle_issuer_id.clone()),
            authority_trust_issuer_label: distributed_authority
                .and_then(|candidate| candidate.trust_bundle_issuer_label.clone()),
            roots: bundle.roots.clone(),
            publisher_revocations: bundle.publisher_revocations.clone(),
        });
    }
    verified
}

pub(crate) fn verify_plugin_marketplace_authority_trust_bundles(
    roots: &[PluginMarketplaceTrustRoot],
    bundles: &[PluginMarketplaceAuthorityTrustBundle],
    now_ms: u64,
) -> Vec<PluginVerifiedAuthorityTrustBundle> {
    let mut verified = Vec::new();
    for bundle in bundles {
        let issuer_id = bundle.issuer_id.trim();
        if issuer_id.is_empty() {
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
            "marketplace authority trust root public key",
        ) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let root_public_key =
            match <Ed25519PublicKey as SerializableKey>::from_bytes(&root_public_key_bytes) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
        let signature_bytes = match decode_signature_material(
            signature_raw,
            "marketplaceAuthorityTrustBundleSignature",
        ) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let signature = match <Ed25519Signature as SerializableKey>::from_bytes(&signature_bytes) {
            Ok(signature) => signature,
            Err(_) => continue,
        };
        let message = plugin_marketplace_authority_trust_bundle_message(bundle);
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

        verified.push(PluginVerifiedAuthorityTrustBundle {
            bundle_id: bundle.id.clone(),
            bundle_label: bundle.label.clone(),
            bundle_issued_at_ms: bundle.issued_at_ms,
            bundle_expires_at_ms: bundle.expires_at_ms,
            bundle_status,
            issuer_id: root.id.clone(),
            issuer_label: root.label.clone(),
            trust_source: bundle
                .trust_source
                .clone()
                .or_else(|| root.trust_source.clone())
                .or(Some(
                    "distributed marketplace authority bundle verification".to_string(),
                )),
            authorities: bundle.authorities.clone(),
            authority_revocations: bundle.authority_revocations.clone(),
        });
    }
    verified
}

pub(crate) fn distributed_authorities_from_trust_bundles(
    bundles: &[PluginVerifiedAuthorityTrustBundle],
) -> Vec<PluginDistributedAuthority> {
    let mut distributed = Vec::new();
    for bundle in bundles {
        for authority in &bundle.authorities {
            let revoked = bundle
                .authority_revocations
                .iter()
                .any(|revocation| revocation.authority_id.trim() == authority.id.trim());
            let trust_bundle_status = if revoked {
                "revoked".to_string()
            } else {
                bundle.bundle_status.clone()
            };
            distributed.push(PluginDistributedAuthority {
                authority: authority.clone(),
                trust_bundle_id: bundle.bundle_id.clone(),
                trust_bundle_label: bundle.bundle_label.clone(),
                trust_bundle_issued_at_ms: bundle.bundle_issued_at_ms,
                trust_bundle_expires_at_ms: bundle.bundle_expires_at_ms,
                trust_bundle_status,
                trust_bundle_issuer_id: bundle.issuer_id.clone(),
                trust_bundle_issuer_label: bundle.issuer_label.clone(),
                trust_source: bundle.trust_source.clone(),
            });
        }
    }
    distributed
}

pub(crate) fn verified_authority_bundle_roots(
    bundles: &[PluginVerifiedAuthorityBundle],
) -> Vec<PluginMarketplaceTrustRoot> {
    let mut roots = Vec::new();
    for bundle in bundles {
        for root in &bundle.roots {
            if roots
                .iter()
                .any(|existing: &PluginMarketplaceTrustRoot| existing.id == root.id)
            {
                continue;
            }
            roots.push(root.clone());
        }
    }
    roots
}

pub(crate) fn find_verified_authority_bundle_for_root<'a>(
    root_id: &str,
    bundles: &'a [PluginVerifiedAuthorityBundle],
) -> Option<&'a PluginVerifiedAuthorityBundle> {
    bundles
        .iter()
        .find(|bundle| bundle.roots.iter().any(|root| root.id.trim() == root_id))
}

pub(crate) fn compute_plugin_authority_bundle_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    bundles: &[PluginVerifiedAuthorityBundle],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if verification.status.as_deref() != Some("verified") {
        return None;
    }

    let authority_roots = verified_authority_bundle_roots(bundles);
    let mut trust =
        compute_plugin_rooted_publisher_trust(entry, publishers, &authority_roots, verification)?;

    let publisher_label = entry
        .publisher_label
        .clone()
        .unwrap_or_else(|| "this publisher".to_string());
    let publisher = normalize_registry_id(entry.publisher_id.clone()).and_then(|publisher_id| {
        publishers
            .iter()
            .find(|candidate| candidate.id.trim() == publisher_id)
            .cloned()
    });
    let expected_root_id = publisher
        .as_ref()
        .and_then(|publisher| normalize_registry_id(publisher.trust_root_id.clone()));
    let bundle = expected_root_id
        .as_deref()
        .and_then(|root_id| find_verified_authority_bundle_for_root(root_id, bundles));

    if let Some(bundle) = bundle {
        trust.authority_bundle_id = Some(bundle.bundle_id.clone());
        trust.authority_bundle_label = bundle
            .bundle_label
            .clone()
            .or_else(|| Some(bundle.bundle_id.clone()));
        trust.authority_bundle_issued_at_ms = bundle.bundle_issued_at_ms;
        trust.authority_trust_bundle_id = bundle.authority_trust_bundle_id.clone();
        trust.authority_trust_bundle_label = bundle
            .authority_trust_bundle_label
            .clone()
            .or_else(|| bundle.authority_trust_bundle_id.clone());
        trust.authority_trust_bundle_issued_at_ms = bundle.authority_trust_bundle_issued_at_ms;
        trust.authority_trust_bundle_expires_at_ms = bundle.authority_trust_bundle_expires_at_ms;
        trust.authority_trust_bundle_status = bundle.authority_trust_bundle_status.clone();
        trust.authority_trust_issuer_id = bundle.authority_trust_issuer_id.clone();
        trust.authority_trust_issuer_label = bundle.authority_trust_issuer_label.clone();
        trust.authority_id = Some(bundle.authority_id.clone());
        trust.authority_label = bundle
            .authority_label
            .clone()
            .or_else(|| Some(bundle.authority_id.clone()));
        trust.source = bundle.trust_source.clone();

        let bundle_label = trust
            .authority_bundle_label
            .clone()
            .unwrap_or_else(|| bundle.bundle_id.clone());
        let trust_bundle_label = trust
            .authority_trust_bundle_label
            .clone()
            .or_else(|| trust.authority_trust_bundle_id.clone())
            .unwrap_or_else(|| "authority trust bundle".to_string());

        match trust.authority_trust_bundle_status.as_deref() {
            Some("expired") => {
                trust.state = Some("expired_authority_bundle".to_string());
                trust.detail = Some(format!(
                    "Package signature is valid, but publisher '{}' chains through marketplace authority bundle '{}' whose authority trust bundle '{}' has expired.",
                    publisher
                        .as_ref()
                        .and_then(|value| value.label.clone())
                        .unwrap_or_else(|| publisher_label.clone()),
                    bundle_label,
                    trust_bundle_label
                ));
                return Some(trust);
            }
            Some("revoked") => {
                trust.state = Some("revoked_by_authority_bundle".to_string());
                trust.detail = Some(format!(
                    "Package signature is valid, but publisher '{}' can no longer be trusted because marketplace authority bundle '{}' depends on revoked authority '{}' from trust bundle '{}'.",
                    publisher
                        .as_ref()
                        .and_then(|value| value.label.clone())
                        .unwrap_or_else(|| publisher_label.clone()),
                    bundle_label,
                    trust
                        .authority_label
                        .clone()
                        .unwrap_or_else(|| bundle.authority_id.clone()),
                    trust_bundle_label
                ));
                return Some(trust);
            }
            _ => {}
        }

        if let Some(publisher_id) = trust.publisher_id.as_deref() {
            if let Some(revocation) = bundle
                .publisher_revocations
                .iter()
                .find(|candidate| candidate.publisher_id.trim() == publisher_id)
            {
                let bundle_label = trust
                    .authority_bundle_label
                    .clone()
                    .unwrap_or_else(|| bundle.bundle_id.clone());
                trust.state = Some("revoked_by_authority_bundle".to_string());
                trust.detail = Some(format!(
                    "Package signature is valid, but publisher '{}' has been revoked by authority bundle '{}'.{}",
                    publisher
                        .as_ref()
                        .and_then(|value| value.label.clone())
                        .unwrap_or_else(|| publisher_label.clone()),
                    bundle_label,
                    revocation
                        .reason
                        .as_deref()
                        .map(|reason| format!(" Reason: {reason}"))
                        .unwrap_or_default()
                ));
                trust.revoked_at_ms = revocation.revoked_at_ms.or(trust.revoked_at_ms);
                return Some(trust);
            }
        }

        let root_label = trust
            .root_label
            .clone()
            .or_else(|| expected_root_id.clone())
            .unwrap_or_else(|| "this marketplace root".to_string());
        trust.state = Some(match trust.state.as_deref() {
            Some("rooted") => "rooted_bundle".to_string(),
            Some("revoked_by_root") => "revoked_by_authority_bundle".to_string(),
            _ => "unknown_authority_bundle".to_string(),
        });
        trust.detail = Some(match trust.state.as_deref() {
            Some("rooted_bundle") => format!(
                "Package signature is valid and publisher '{}' is rooted in marketplace authority bundle '{}' via root '{}' and trust bundle '{}'.",
                publisher
                    .as_ref()
                    .and_then(|value| value.label.clone())
                    .unwrap_or_else(|| publisher_label.clone()),
                bundle_label,
                root_label,
                trust_bundle_label
            ),
            Some("revoked_by_authority_bundle") => format!(
                "Package signature is valid, but publisher '{}' can no longer be trusted because authority bundle '{}' revoked the active trust path through root '{}'.",
                publisher
                    .as_ref()
                    .and_then(|value| value.label.clone())
                    .unwrap_or_else(|| publisher_label.clone()),
                bundle_label,
                root_label
            ),
            _ => trust.detail.clone().unwrap_or_else(|| {
                format!(
                    "Package signature is valid, but publisher '{}' still needs review against marketplace authority bundle '{}'.",
                    publisher
                        .as_ref()
                        .and_then(|value| value.label.clone())
                        .unwrap_or_else(|| publisher_label.clone()),
                    bundle_label
                )
            }),
        });
        return Some(trust);
    }

    let root_reference = expected_root_id
        .clone()
        .or_else(|| trust.root_id.clone())
        .unwrap_or_else(|| "unknown-root".to_string());
    trust.state = Some("unknown_authority_bundle".to_string());
    trust.source = Some("marketplace authority bundle verification".to_string());
    trust.detail = Some(format!(
        "Package signature is valid, but publisher '{}' chains to root '{}' without a trusted marketplace authority bundle.",
        publisher
            .as_ref()
            .and_then(|value| value.label.clone())
            .unwrap_or_else(|| publisher_label),
        root_reference
    ));
    Some(trust)
}

pub(crate) fn compute_plugin_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    roots: &[PluginMarketplaceTrustRoot],
    authority_bundle_configured: bool,
    authority_bundles: &[PluginVerifiedAuthorityBundle],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if authority_bundle_configured {
        return compute_plugin_authority_bundle_publisher_trust(
            entry,
            publishers,
            authority_bundles,
            verification,
        );
    }
    let should_use_root_chain = !roots.is_empty()
        || publishers.iter().any(|publisher| {
            publisher
                .trust_root_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
                || publisher
                    .statement_signature
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some()
        });
    if should_use_root_chain {
        compute_plugin_rooted_publisher_trust(entry, publishers, roots, verification)
    } else {
        compute_plugin_local_registry_publisher_trust(entry, publishers, verification)
    }
}
