use super::*;

pub(crate) fn merge_plugin_marketplace_manifests(
    mut snapshot: CapabilityRegistrySnapshot,
    overlays: Vec<ExtensionManifestRecord>,
) -> CapabilityRegistrySnapshot {
    let mut manifests = snapshot.extension_manifests;
    for overlay in overlays {
        if let Some(existing) = manifests
            .iter_mut()
            .find(|manifest| manifest.extension_id == overlay.extension_id)
        {
            enrich_manifest_with_marketplace(existing, &overlay);
            continue;
        }
        manifests.push(overlay);
    }
    manifests.sort_by(|left, right| {
        left.display_name
            .as_deref()
            .unwrap_or(&left.name)
            .cmp(right.display_name.as_deref().unwrap_or(&right.name))
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
    });
    snapshot.extension_manifests = manifests;
    snapshot.summary.extension_count = snapshot.extension_manifests.len();
    snapshot
}

pub(crate) struct PluginAuthenticitySignal {
    pub(crate) state: String,
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) verification_error: Option<String>,
    pub(crate) verification_algorithm: Option<String>,
    pub(crate) publisher_label: Option<String>,
    pub(crate) publisher_id: Option<String>,
    pub(crate) signer_identity: Option<String>,
    pub(crate) signing_key_id: Option<String>,
    pub(crate) verification_timestamp_ms: Option<u64>,
    pub(crate) verification_source: Option<String>,
    pub(crate) verified_digest_sha256: Option<String>,
    pub(crate) publisher_trust_state: Option<String>,
    pub(crate) publisher_trust_label: Option<String>,
    pub(crate) publisher_trust_detail: Option<String>,
    pub(crate) publisher_trust_source: Option<String>,
    pub(crate) publisher_root_id: Option<String>,
    pub(crate) publisher_root_label: Option<String>,
    pub(crate) authority_bundle_id: Option<String>,
    pub(crate) authority_bundle_label: Option<String>,
    pub(crate) authority_bundle_issued_at_ms: Option<u64>,
    pub(crate) authority_trust_bundle_id: Option<String>,
    pub(crate) authority_trust_bundle_label: Option<String>,
    pub(crate) authority_trust_bundle_issued_at_ms: Option<u64>,
    pub(crate) authority_trust_bundle_expires_at_ms: Option<u64>,
    pub(crate) authority_trust_bundle_status: Option<String>,
    pub(crate) authority_trust_issuer_id: Option<String>,
    pub(crate) authority_trust_issuer_label: Option<String>,
    pub(crate) authority_id: Option<String>,
    pub(crate) authority_label: Option<String>,
    pub(crate) publisher_statement_issued_at_ms: Option<u64>,
    pub(crate) publisher_revoked_at_ms: Option<u64>,
    pub(crate) trust_score_label: Option<String>,
    pub(crate) trust_score_source: Option<String>,
    pub(crate) trust_recommendation: Option<String>,
}

pub(crate) fn publisher_trust_label(state: Option<&str>) -> Option<String> {
    match state {
        Some("rooted_bundle") => Some("Publisher rooted by authority bundle".to_string()),
        Some("unknown_authority_bundle") => Some("Publisher unknown authority bundle".to_string()),
        Some("expired_authority_bundle") => Some("Authority bundle expired".to_string()),
        Some("revoked_by_authority_bundle") => {
            Some("Publisher revoked by authority bundle".to_string())
        }
        Some("rooted") => Some("Publisher rooted".to_string()),
        Some("unknown_root") => Some("Publisher unknown root".to_string()),
        Some("revoked_by_root") => Some("Publisher revoked by root".to_string()),
        Some("trusted") => Some("Trusted publisher".to_string()),
        Some("revoked") => Some("Publisher revoked".to_string()),
        Some("unknown") => Some("Publisher unknown".to_string()),
        _ => None,
    }
}

pub(crate) fn plugin_authenticity_signal(
    manifest: &ExtensionManifestRecord,
) -> PluginAuthenticitySignal {
    let state = manifest
        .marketplace_verification_status
        .clone()
        .unwrap_or_else(|| {
            if manifest.marketplace_display_name.is_some() {
                "catalog_metadata_only".to_string()
            } else {
                "local_only".to_string()
            }
        });
    let verification_algorithm = manifest.marketplace_signature_algorithm.clone();
    let publisher_label = manifest.marketplace_publisher_label.clone();
    let publisher_id = manifest.marketplace_publisher_id.clone();
    let signer_identity = manifest.marketplace_signer_identity.clone();
    let signing_key_id = manifest.marketplace_signing_key_id.clone();
    let verification_timestamp_ms = manifest.marketplace_verified_at_ms;
    let verification_source = manifest.marketplace_verification_source.clone();
    let verified_digest_sha256 = manifest.marketplace_verified_digest_sha256.clone();
    let verification_error = manifest.marketplace_verification_error.clone();
    let publisher_trust_state = manifest.marketplace_publisher_trust_status.clone();
    let publisher_trust_source = manifest.marketplace_publisher_trust_source.clone();
    let publisher_root_id = manifest.marketplace_publisher_root_id.clone();
    let publisher_root_label = manifest.marketplace_publisher_root_label.clone();
    let authority_bundle_id = manifest.marketplace_authority_bundle_id.clone();
    let authority_bundle_label = manifest.marketplace_authority_bundle_label.clone();
    let authority_bundle_issued_at_ms = manifest.marketplace_authority_bundle_issued_at_ms;
    let authority_trust_bundle_id = manifest.marketplace_authority_trust_bundle_id.clone();
    let authority_trust_bundle_label = manifest.marketplace_authority_trust_bundle_label.clone();
    let authority_trust_bundle_issued_at_ms =
        manifest.marketplace_authority_trust_bundle_issued_at_ms;
    let authority_trust_bundle_expires_at_ms =
        manifest.marketplace_authority_trust_bundle_expires_at_ms;
    let authority_trust_bundle_status = manifest.marketplace_authority_trust_bundle_status.clone();
    let authority_trust_issuer_id = manifest.marketplace_authority_trust_issuer_id.clone();
    let authority_trust_issuer_label = manifest.marketplace_authority_trust_issuer_label.clone();
    let authority_id = manifest.marketplace_authority_id.clone();
    let authority_label = manifest.marketplace_authority_label.clone();
    let publisher_statement_issued_at_ms = manifest.marketplace_publisher_statement_issued_at_ms;
    let publisher_trust_detail = manifest.marketplace_publisher_trust_detail.clone();
    let publisher_revoked_at_ms = manifest.marketplace_publisher_revoked_at_ms;

    let (label, detail, derived_score_label, derived_score_source, derived_recommendation) =
        match state.as_str() {
            "verified" => match publisher_trust_state.as_deref() {
                Some("rooted_bundle") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        let bundle_label = authority_bundle_label
                            .as_deref()
                            .or(authority_bundle_id.as_deref())
                            .unwrap_or("trusted marketplace authority bundle");
                        if let Some(root_label) = publisher_root_label.as_deref() {
                            format!(
                                "Package signature is valid and publisher '{}' is rooted by authority bundle '{}' via root '{}'.",
                                publisher_label
                                    .as_deref()
                                    .unwrap_or("this publisher"),
                                bundle_label,
                                root_label
                            )
                        } else {
                            format!(
                                "Package signature is valid and publisher '{}' is rooted by authority bundle '{}'.",
                                publisher_label
                                    .as_deref()
                                    .unwrap_or("this publisher"),
                                bundle_label
                            )
                        }
                    }),
                    Some("High confidence".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace authority bundle verification".to_string())),
                    Some(
                        "Package integrity is proven and the publisher chain resolves through a trusted marketplace authority bundle. Operator trust is still required before runtime load."
                            .to_string(),
                    ),
                ),
                Some("revoked_by_authority_bundle") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher has been revoked by marketplace authority bundle."
                            .to_string()
                    }),
                    Some("Blocked".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace authority bundle verification".to_string())),
                    Some(
                        "Do not trust or enable this package until the marketplace authority bundle revocation is cleared."
                            .to_string(),
                    ),
                ),
                Some("unknown_authority_bundle") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher chain does not resolve through a trusted marketplace authority bundle."
                            .to_string()
                    }),
                    Some("Authority bundle review required".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace authority bundle verification".to_string())),
                    Some(
                        "Package integrity is proven, but the publisher authority bundle still needs operator review."
                            .to_string(),
                    ),
                ),
                Some("expired_authority_bundle") => (
                    "Authority bundle expired".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        let trust_bundle_label = authority_trust_bundle_label
                            .as_deref()
                            .or(authority_trust_bundle_id.as_deref())
                            .unwrap_or("authority trust bundle");
                        format!(
                            "Package integrity is valid, but authority trust bundle '{}' has expired and the publisher chain must be refreshed before trust can be granted.",
                            trust_bundle_label
                        )
                    }),
                    Some("Blocked".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("distributed authority bundle verification".to_string())),
                    Some(
                        "Do not trust or enable this package until the authority trust bundle is refreshed."
                            .to_string(),
                    ),
                ),
                Some("rooted") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        if let Some(root_label) = publisher_root_label.as_deref() {
                            format!(
                                "Package signature is valid and publisher '{}' is rooted in trusted marketplace authority '{}'.",
                                publisher_label
                                    .as_deref()
                                    .unwrap_or("this publisher"),
                                root_label
                            )
                        } else {
                            "Package signature is valid and the publisher chain is rooted in trusted marketplace authority."
                                .to_string()
                        }
                    }),
                    Some("High confidence".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace root verification".to_string())),
                    Some(
                        "Package integrity is proven and the publisher chain is rooted in trusted marketplace authority. Operator trust is still required before runtime load."
                            .to_string(),
                    ),
                ),
                Some("revoked_by_root") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher has been revoked by marketplace authority."
                            .to_string()
                    }),
                    Some("Blocked".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace root verification".to_string())),
                    Some(
                        "Do not trust or enable this package until the marketplace root revocation is cleared."
                            .to_string(),
                    ),
                ),
                Some("unknown_root") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher chain does not resolve to a trusted marketplace root."
                            .to_string()
                    }),
                    Some("Root review required".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("marketplace root verification".to_string())),
                    Some(
                        "Package integrity is proven, but the publisher chain is not yet rooted in trusted marketplace authority."
                            .to_string(),
                    ),
                ),
                Some("trusted") => (
                    "Signature verified".to_string(),
                    if let Some(detail) = publisher_trust_detail.clone() {
                        detail
                    } else if let Some(publisher) = publisher_label.as_deref() {
                        format!(
                            "{publisher} published a verified package{} and the publisher chain is trusted.",
                            signer_identity
                                .as_deref()
                                .map(|signer| format!(" signed by {signer}"))
                                .unwrap_or_default()
                        )
                    } else {
                        "Runtime signature verification confirmed this package and the publisher chain is trusted."
                            .to_string()
                    },
                    Some("High confidence".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(verification_source.clone())
                        .or(Some("publisher chain verification".to_string())),
                    Some(
                        "Package integrity and publisher trust are both proven. Operator trust is still required before runtime load."
                            .to_string(),
                    ),
                ),
                Some("revoked") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher trust chain has been revoked."
                            .to_string()
                    }),
                    Some("Blocked".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(Some("publisher chain verification".to_string())),
                    Some(
                        "Do not trust or enable this package until the publisher trust chain is reinstated."
                            .to_string(),
                    ),
                ),
                Some("unknown") => (
                    "Signature verified".to_string(),
                    publisher_trust_detail.clone().unwrap_or_else(|| {
                        "Package integrity is valid, but the publisher identity is not recognized in the trusted registry."
                            .to_string()
                    }),
                    Some("Publisher review required".to_string()),
                    publisher_trust_source
                        .clone()
                        .or(verification_source.clone())
                        .or(Some("publisher chain verification".to_string())),
                    Some(
                        "Package integrity is proven, but the publisher chain still needs operator review."
                            .to_string(),
                    ),
                ),
                _ => (
                    "Signature verified".to_string(),
                    if let Some(publisher) = publisher_label.as_deref() {
                        format!(
                            "{publisher} published a verified package{}.",
                            signer_identity
                                .as_deref()
                                .map(|signer| format!(" signed by {signer}"))
                                .unwrap_or_default()
                        )
                    } else {
                        "Runtime signature verification confirmed this plugin package."
                            .to_string()
                    },
                    Some("High confidence".to_string()),
                    verification_source
                        .clone()
                        .or(Some("runtime signature verification".to_string())),
                    Some(
                        "Authenticity is proven. Operator trust is still required before runtime load."
                            .to_string(),
                    ),
                ),
            },
            "signature_mismatch" => (
                "Signature mismatch".to_string(),
                verification_error.clone().unwrap_or_else(|| {
                    "Runtime signature verification did not match the package payload."
                        .to_string()
                }),
                Some("Blocked".to_string()),
                verification_source
                    .clone()
                    .or(Some("runtime signature verification".to_string())),
                Some(
                    "Do not trust or enable this package until it is republished with a valid signature."
                        .to_string(),
                ),
            ),
            "unsigned" => (
                "Unsigned package".to_string(),
                if verified_digest_sha256.is_some() {
                    "A package digest was computed locally, but no signature proof is attached yet."
                        .to_string()
                } else {
                    "No signature proof is attached to this package yet.".to_string()
                },
                Some("Needs review".to_string()),
                verification_source
                    .clone()
                    .or(Some("runtime package digest".to_string())),
                Some(
                    "Review the publisher, signer, and requested capabilities before granting trust."
                        .to_string(),
                ),
            ),
            "unverified" => (
                "Unverified package".to_string(),
                "Marketplace metadata exposes this package, but no signature proof is attached yet."
                    .to_string(),
                Some("Needs review".to_string()),
                Some("marketplace metadata".to_string()),
                Some(
                    "Review the publisher, signer, and requested capabilities before granting trust."
                        .to_string(),
                ),
            ),
            "catalog_metadata_only" => (
                "Catalog metadata only".to_string(),
                "This package is visible from a marketplace feed, but verification status has not been supplied yet."
                    .to_string(),
                Some("Metadata only".to_string()),
                Some("marketplace feed".to_string()),
                Some(
                    "Treat this package like an unverified catalog entry until verification metadata arrives."
                        .to_string(),
                ),
            ),
            _ => (
                "Local tracked source".to_string(),
                "This plugin is visible from a local tracked source and does not carry marketplace verification metadata."
                    .to_string(),
                Some("Local development".to_string()),
                Some("tracked source".to_string()),
                Some(
                    "Trust should be based on local source review and repository controls."
                        .to_string(),
                ),
            ),
        };

    PluginAuthenticitySignal {
        state,
        label,
        detail,
        verification_error,
        verification_algorithm,
        publisher_label,
        publisher_id,
        signer_identity,
        signing_key_id,
        verification_timestamp_ms,
        verification_source,
        verified_digest_sha256,
        publisher_trust_state: publisher_trust_state.clone(),
        publisher_trust_label: publisher_trust_label(publisher_trust_state.as_deref()),
        publisher_trust_detail,
        publisher_trust_source,
        publisher_root_id,
        publisher_root_label,
        authority_bundle_id,
        authority_bundle_label,
        authority_bundle_issued_at_ms,
        authority_trust_bundle_id,
        authority_trust_bundle_label,
        authority_trust_bundle_issued_at_ms,
        authority_trust_bundle_expires_at_ms,
        authority_trust_bundle_status,
        authority_trust_issuer_id,
        authority_trust_issuer_label,
        authority_id,
        authority_label,
        publisher_statement_issued_at_ms,
        publisher_revoked_at_ms,
        trust_score_label: manifest
            .marketplace_trust_score_label
            .clone()
            .or(derived_score_label),
        trust_score_source: manifest
            .marketplace_trust_score_source
            .clone()
            .or(derived_score_source),
        trust_recommendation: manifest
            .marketplace_trust_recommendation
            .clone()
            .or(derived_recommendation),
    }
}

pub(crate) fn plugin_authenticity_block_reason(
    manifest: &ExtensionManifestRecord,
    action: &str,
) -> Option<String> {
    match (
        manifest.marketplace_verification_status.as_deref(),
        manifest.marketplace_publisher_trust_status.as_deref(),
    ) {
        (Some("signature_mismatch"), _) => {
            let action_label = action.replace('_', " ");
            Some(
                manifest
                    .marketplace_verification_error
                    .clone()
                    .unwrap_or_else(|| {
                        format!(
                            "Blocked {} because runtime signature verification failed for this package.",
                            action_label
                        )
                    }),
            )
        }
        (_, Some("revoked" | "revoked_by_root")) => Some(
            manifest
                .marketplace_publisher_trust_detail
                .clone()
                .unwrap_or_else(|| {
                    format!(
                        "Blocked {} because the publisher trust chain for this package has been revoked.",
                        action.replace('_', " ")
                    )
                }),
        ),
        (_, Some("revoked_by_authority_bundle")) => Some(
            manifest
                .marketplace_publisher_trust_detail
                .clone()
                .unwrap_or_else(|| {
                    format!(
                        "Blocked {} because the publisher trust chain for this package has been revoked.",
                        action.replace('_', " ")
                    )
                }),
        ),
        (_, Some("expired_authority_bundle")) => Some(
            manifest
                .marketplace_publisher_trust_detail
                .clone()
                .unwrap_or_else(|| {
                    format!(
                        "Blocked {} because the authority trust bundle for this package has expired.",
                        action.replace('_', " ")
                    )
                }),
        ),
        _ => None,
    }
}
pub(crate) struct PluginCatalogSignal {
    pub(crate) status: String,
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) issued_at_ms: Option<u64>,
    pub(crate) expires_at_ms: Option<u64>,
    pub(crate) refreshed_at_ms: Option<u64>,
    pub(crate) refresh_source: Option<String>,
    pub(crate) channel: Option<String>,
}

pub(crate) fn plugin_catalog_signal(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
    now_ms: u64,
) -> PluginCatalogSignal {
    let display_name = manifest
        .marketplace_display_name
        .as_deref()
        .unwrap_or("marketplace feed");
    let issued_at_ms = runtime_record
        .and_then(|record| record.catalog_issued_at_ms)
        .or(manifest.marketplace_catalog_issued_at_ms);
    let expires_at_ms = runtime_record
        .and_then(|record| record.catalog_expires_at_ms)
        .or(manifest.marketplace_catalog_expires_at_ms);
    let refreshed_at_ms = runtime_record
        .and_then(|record| record.catalog_refreshed_at_ms)
        .or(manifest.marketplace_catalog_refreshed_at_ms);
    let refresh_source = runtime_record
        .and_then(|record| record.catalog_refresh_source.clone())
        .or_else(|| manifest.marketplace_catalog_refresh_source.clone());
    let channel = runtime_record
        .and_then(|record| record.catalog_channel.clone())
        .or_else(|| manifest.marketplace_catalog_channel.clone());
    let pending_refresh_bundle_id = manifest.marketplace_catalog_refresh_bundle_id.clone();
    let applied_refresh_bundle_id =
        runtime_record.and_then(|record| record.catalog_refresh_bundle_id.clone());
    let refresh_available = pending_refresh_bundle_id.is_some()
        && pending_refresh_bundle_id != applied_refresh_bundle_id;
    let freshness_anchor_ms = refreshed_at_ms.or(issued_at_ms);
    let channel_label = channel
        .as_deref()
        .map(|value| format!(" on the {} channel", value))
        .unwrap_or_default();

    let (status, label, detail) = if let Some(refresh_error) =
        runtime_record.and_then(|record| record.catalog_refresh_error.clone())
    {
        (
            "refresh_failed".to_string(),
            "Refresh failed".to_string(),
            refresh_error,
        )
    } else if refresh_available {
        let bundle_label = manifest
            .marketplace_catalog_refresh_bundle_label
            .clone()
            .or_else(|| manifest.marketplace_catalog_refresh_bundle_id.clone())
            .unwrap_or_else(|| "signed catalog refresh".to_string());
        let next_version = manifest
            .marketplace_catalog_refresh_available_version
            .clone()
            .map(|version| format!(" It advertises update {}.", version))
            .unwrap_or_default();
        (
            "refresh_available".to_string(),
            "Refresh available".to_string(),
            format!(
                "{}{} has a newer signed catalog refresh bundle '{}' ready to apply.{}",
                display_name, channel_label, bundle_label, next_version
            ),
        )
    } else if expires_at_ms.is_some_and(|expires_at| expires_at <= now_ms) {
        (
            "expired".to_string(),
            "Catalog expired".to_string(),
            format!(
                "{}{} is past its declared freshness window. Refresh the signed catalog before trusting updates from this feed.",
                display_name, channel_label
            ),
        )
    } else if freshness_anchor_ms
        .map(|timestamp_ms| {
            now_ms.saturating_sub(timestamp_ms) > MARKETPLACE_CATALOG_STALE_AFTER_MS
        })
        .unwrap_or(false)
    {
        (
            "stale".to_string(),
            "Catalog refresh stale".to_string(),
            format!(
                "{}{} has not been refreshed recently enough to recommend automatic trust or update decisions.",
                display_name, channel_label
            ),
        )
    } else if issued_at_ms.is_some() || refreshed_at_ms.is_some() || expires_at_ms.is_some() {
        (
            "active".to_string(),
            "Catalog fresh".to_string(),
            format!(
                "{}{} is within its declared freshness window.",
                display_name, channel_label
            ),
        )
    } else {
        (
            "timing_unavailable".to_string(),
            "Catalog timing unavailable".to_string(),
            format!(
                "{}{} does not expose issued-at or refresh timing yet, so freshness must be reviewed manually.",
                display_name, channel_label
            ),
        )
    };

    PluginCatalogSignal {
        status,
        label,
        detail,
        issued_at_ms,
        expires_at_ms,
        refreshed_at_ms,
        refresh_source,
        channel,
    }
}

pub(crate) fn parse_plugin_semver_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let trimmed = version.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .split(|char: char| !char.is_ascii_digit())
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split(|char: char| !char.is_ascii_digit())
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .ok()?;
    Some((major, minor, patch))
}

pub(crate) fn plugin_update_signal(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
    authenticity: &PluginAuthenticitySignal,
    catalog: &PluginCatalogSignal,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(available_version) = marketplace_available_version(manifest, runtime_record) else {
        return (None, None, None);
    };
    let installed_version = runtime_record
        .and_then(|record| record.installed_version.clone())
        .or_else(|| manifest.version.clone())
        .unwrap_or_default();
    if available_version == installed_version.trim() {
        return (None, None, None);
    }

    if matches!(
        authenticity.publisher_trust_state.as_deref(),
        Some(
            "revoked"
                | "revoked_by_root"
                | "revoked_by_authority_bundle"
                | "expired_authority_bundle"
        )
    ) || authenticity.state == "signature_mismatch"
    {
        return (
            Some("blocked".to_string()),
            Some("Blocked update channel".to_string()),
            Some(
                "An update is advertised, but the package trust chain is currently blocked. Resolve verification or revocation problems before applying this update."
                    .to_string(),
            ),
        );
    }

    if catalog.status == "expired" {
        return (
            Some("blocked".to_string()),
            Some("Blocked update channel".to_string()),
            Some(
                "An update is advertised, but the marketplace catalog has expired. Refresh the signed catalog before applying it."
                    .to_string(),
            ),
        );
    }

    if catalog.status == "stale" {
        return (
            Some("review_stale_feed".to_string()),
            Some("Review stale feed".to_string()),
            Some(format!(
                "Update {} is visible, but the catalog freshness window is stale. Refresh the feed before relying on this update.",
                available_version
            )),
        );
    }

    if catalog.status == "refresh_failed" {
        return (
            Some("review_refresh_failure".to_string()),
            Some("Review refresh failure".to_string()),
            Some(
                "A signed catalog refresh failed, so update metadata should be reviewed manually before applying it."
                    .to_string(),
            ),
        );
    }

    if let (Some(current), Some(next)) = (
        parse_plugin_semver_triplet(&installed_version),
        parse_plugin_semver_triplet(&available_version),
    ) {
        if next.0 > current.0 {
            return (
                Some("critical_review".to_string()),
                Some("Critical review".to_string()),
                Some(format!(
                    "Update {} changes the major version from {}. Review compatibility and requested capabilities before applying it.",
                    available_version, installed_version
                )),
            );
        }
        if next.1 > current.1 {
            return (
                Some("recommended".to_string()),
                Some("Recommended update".to_string()),
                Some(format!(
                    "Update {} advances the minor version from {} and is ready to review and apply.",
                    available_version, installed_version
                )),
            );
        }
    }

    (
        Some("routine".to_string()),
        Some("Routine update".to_string()),
        Some(format!(
            "Update {} is available over {} with no major compatibility jump detected.",
            available_version, installed_version
        )),
    )
}

pub(crate) fn plugin_capability_review_flags(capabilities: &[String]) -> Vec<String> {
    let mut flags = Vec::new();
    for capability in capabilities {
        let lowered = capability.trim().to_ascii_lowercase();
        let flag = if lowered.contains("hook") {
            Some("hooks".to_string())
        } else if lowered.contains("shell") || lowered.contains("exec") {
            Some("shell execution".to_string())
        } else if lowered.contains("network") || lowered.contains("http") {
            Some("network access".to_string())
        } else if lowered.contains("browser") {
            Some("browser control".to_string())
        } else if lowered.contains("connector") {
            Some("connector access".to_string())
        } else if lowered.contains("write") {
            Some("write access".to_string())
        } else {
            None
        };
        if let Some(flag) = flag {
            if !flags.iter().any(|existing| existing == &flag) {
                flags.push(flag);
            }
        }
    }
    flags
}

pub(crate) fn plugin_operator_review_signal(
    authenticity: &PluginAuthenticitySignal,
    capabilities: &[String],
    catalog: &PluginCatalogSignal,
    update_severity: Option<&str>,
    update_detail: Option<&str>,
) -> (String, String, String) {
    let capability_flags = plugin_capability_review_flags(capabilities);
    let trust_state = authenticity.publisher_trust_state.as_deref();

    if matches!(
        trust_state,
        Some(
            "revoked"
                | "revoked_by_root"
                | "revoked_by_authority_bundle"
                | "expired_authority_bundle"
        )
    ) || authenticity.state == "signature_mismatch"
        || catalog.status == "expired"
        || matches!(update_severity, Some("blocked"))
    {
        return (
            "blocked".to_string(),
            "Blocked".to_string(),
            if matches!(update_severity, Some("blocked")) {
                update_detail.map(str::to_string)
            } else {
                None
            }
            .or_else(|| {
                if catalog.status == "expired" {
                    Some(catalog.detail.clone())
                } else {
                    authenticity.publisher_trust_detail.clone()
                }
            })
            .unwrap_or_else(|| {
                "The plugin trust chain is blocked and should not be enabled until the marketplace state is repaired."
                    .to_string()
            }),
        );
    }

    let rooted = matches!(trust_state, Some("rooted_bundle" | "rooted" | "trusted"));
    let review_required = matches!(
        trust_state,
        Some("unknown" | "unknown_root" | "unknown_authority_bundle")
    ) || matches!(
        authenticity.state.as_str(),
        "unsigned" | "unverified" | "catalog_metadata_only"
    ) || matches!(
        catalog.status.as_str(),
        "stale" | "timing_unavailable" | "refresh_failed"
    ) || matches!(
        update_severity,
        Some("critical_review" | "review_stale_feed" | "review_refresh_failure")
    ) || capability_flags.len() >= 2
        || (!capability_flags.is_empty() && !rooted);

    if review_required {
        let capability_reason = if capability_flags.is_empty() {
            None
        } else {
            Some(format!(
                "Requested capabilities need review: {}.",
                capability_flags.join(", ")
            ))
        };
        return (
            "review_required".to_string(),
            "Review required".to_string(),
            if matches!(
                update_severity,
                Some("critical_review" | "review_stale_feed" | "review_refresh_failure")
            ) {
                update_detail.map(str::to_string)
            } else {
                None
            }
            .or_else(|| {
                if matches!(
                    catalog.status.as_str(),
                    "stale" | "timing_unavailable" | "refresh_failed"
                ) {
                    Some(catalog.detail.clone())
                } else {
                    authenticity.trust_recommendation.clone()
                }
            })
                .or(capability_reason)
                .unwrap_or_else(|| {
                    "Review the package trust chain, feed freshness, and requested capabilities before trusting runtime load."
                        .to_string()
                }),
        );
    }

    (
        "recommended".to_string(),
        "Recommended".to_string(),
        if let Some(update_detail) = authenticity.trust_recommendation.clone() {
            update_detail
        } else {
            "Package integrity, publisher trust, and catalog freshness all look healthy enough for operator trust review."
                .to_string()
        },
    )
}
