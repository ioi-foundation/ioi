use super::*;

pub(crate) fn load_plugin_marketplace_feed_from_fixture(
    parsed: PluginMarketplaceFixture,
    fixture_source: &str,
    source: Option<&PluginMarketplaceCatalogSourceContext>,
) -> Result<PluginMarketplaceFeedLoad, String> {
    let now_ms = state::now();
    let authority_bundle_configured = !parsed.bundle_authorities.is_empty()
        || !parsed.authority_bundles.is_empty()
        || !parsed.authority_trust_roots.is_empty()
        || !parsed.authority_trust_bundles.is_empty();
    let verified_authority_trust_bundles = verify_plugin_marketplace_authority_trust_bundles(
        &parsed.authority_trust_roots,
        &parsed.authority_trust_bundles,
        now_ms,
    );
    let distributed_authorities =
        distributed_authorities_from_trust_bundles(&verified_authority_trust_bundles);
    let verified_authority_bundles = verify_plugin_marketplace_authority_bundles(
        &parsed.bundle_authorities,
        &distributed_authorities,
        &parsed.authority_bundles,
    );
    let PluginMarketplaceFixture {
        catalogs,
        catalog_refresh_bundles,
        roots,
        publishers,
        ..
    } = parsed;
    let refresh_evaluation =
        plugin_catalog_refresh_targets_from_fixture(&roots, &catalog_refresh_bundles, now_ms);
    let mut manifest_candidates: HashMap<String, PluginMarketplaceManifestCandidate> =
        HashMap::new();
    let mut catalog_channels = Vec::new();

    for catalog in catalogs {
        let catalog_id = catalog_identity(&catalog, fixture_source);
        let catalog_label = catalog_label(&catalog, fixture_source);
        let source_uri = source
            .map(|source| source.source_uri.clone())
            .or_else(|| normalized_optional_text(catalog.source_uri.clone()))
            .unwrap_or_else(|| fixture_source.to_string());
        let channel = normalized_optional_text(catalog.channel.clone())
            .or_else(|| source.and_then(|source| source.channel.clone()));
        let refresh_error = refresh_evaluation.catalog_errors.get(&catalog_id).cloned();
        let refresh_bundle_count = refresh_evaluation
            .active_bundle_counts
            .get(&catalog_id)
            .copied()
            .unwrap_or(0);
        let catalog_conformance_error = catalog_base_conformance_error(&catalog);
        let mut invalid_plugin_count = 0usize;
        let mut valid_plugin_count = 0usize;
        let mut first_conformance_error = catalog_conformance_error.clone();
        let mut channel_status = if catalog_conformance_error.is_some() {
            "nonconformant".to_string()
        } else {
            let (status, _, _) = catalog_channel_status_from_metadata(
                &catalog_label,
                channel.as_deref(),
                catalog.issued_at_ms,
                catalog.expires_at_ms,
                catalog.refreshed_at_ms,
                refresh_error.as_deref(),
                refresh_bundle_count > 0,
                now_ms,
            );
            status
        };

        for entry in &catalog.plugins {
            if let Some(error) = catalog_entry_conformance_error(entry) {
                invalid_plugin_count += 1;
                channel_status = "nonconformant".to_string();
                if first_conformance_error.is_none() {
                    first_conformance_error = Some(error);
                }
                continue;
            }
            match plugin_manifest_from_catalog_entry(
                fixture_source,
                &roots,
                &publishers,
                authority_bundle_configured,
                &verified_authority_bundles,
                &catalog,
                entry,
                source,
            ) {
                Ok(manifest) => {
                    valid_plugin_count += 1;
                    let candidate = PluginMarketplaceManifestCandidate {
                        status: channel_status.clone(),
                        channel_priority: catalog_channel_priority(channel.as_deref()),
                        recency_ms: catalog_recency_ms(&catalog),
                        conformance_penalty: catalog_conformance_error.is_some(),
                        manifest,
                    };
                    let plugin_id = candidate.manifest.extension_id.clone();
                    let should_replace = manifest_candidates
                        .get(&plugin_id)
                        .map(|existing| catalog_candidate_should_replace(existing, &candidate))
                        .unwrap_or(true);
                    if should_replace {
                        manifest_candidates.insert(plugin_id, candidate);
                    }
                }
                Err(error) => {
                    invalid_plugin_count += 1;
                    channel_status = "nonconformant".to_string();
                    if first_conformance_error.is_none() {
                        first_conformance_error = Some(error);
                    }
                }
            }
        }

        let conformance_status = if first_conformance_error.is_some() || invalid_plugin_count > 0 {
            "nonconformant".to_string()
        } else {
            "conformant".to_string()
        };
        let conformance_label = if conformance_status == "nonconformant" {
            "Nonconformant channel".to_string()
        } else {
            "Conformant channel".to_string()
        };
        let (status, status_label, status_detail) = if conformance_status == "nonconformant" {
            (
                    "nonconformant".to_string(),
                    "Nonconformant channel".to_string(),
                    first_conformance_error.clone().unwrap_or_else(|| {
                        format!(
                            "Marketplace catalog '{}' has entries that do not conform to the accepted channel format.",
                            catalog_label
                        )
                    }),
                )
        } else {
            catalog_channel_status_from_metadata(
                &catalog_label,
                channel.as_deref(),
                catalog.issued_at_ms,
                catalog.expires_at_ms,
                catalog.refreshed_at_ms,
                refresh_error.as_deref(),
                refresh_bundle_count > 0,
                now_ms,
            )
        };
        catalog_channels.push(SessionPluginCatalogChannelRecord {
            catalog_id,
            label: catalog_label,
            source_uri,
            refresh_source: normalized_optional_text(catalog.refresh_source.clone()),
            channel,
            status,
            status_label,
            status_detail,
            issued_at_ms: catalog.issued_at_ms,
            expires_at_ms: catalog.expires_at_ms,
            refreshed_at_ms: catalog.refreshed_at_ms,
            plugin_count: catalog.plugins.len(),
            valid_plugin_count,
            invalid_plugin_count,
            refresh_bundle_count,
            refresh_error,
            conformance_status,
            conformance_label,
            conformance_error: first_conformance_error,
        });
    }

    let mut manifests = manifest_candidates
        .into_values()
        .map(|candidate| candidate.manifest)
        .collect::<Vec<_>>();
    for manifest in &mut manifests {
        if let Some(target) = refresh_evaluation.targets.get(&manifest.extension_id) {
            apply_catalog_refresh_target(manifest, target);
        }
    }

    manifests.sort_by(|left, right| {
        left.display_name
            .as_deref()
            .unwrap_or(&left.name)
            .cmp(right.display_name.as_deref().unwrap_or(&right.name))
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
    });
    catalog_channels.sort_by(|left, right| {
        catalog_channel_status_severity(&right.status)
            .cmp(&catalog_channel_status_severity(&left.status))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.channel.cmp(&right.channel))
    });

    Ok(PluginMarketplaceFeedLoad {
        manifests,
        catalog_channels,
        catalog_sources: Vec::new(),
    })
}

pub(crate) fn load_plugin_marketplace_distribution_from_fixture(
    distribution: PluginMarketplaceCatalogDistributionFixture,
    distribution_path: &Path,
) -> Result<PluginMarketplaceFeedLoad, String> {
    let now_ms = state::now();
    let mut manifest_candidates: HashMap<String, PluginMarketplaceManifestCandidate> =
        HashMap::new();
    let mut catalog_channels = Vec::new();
    let mut catalog_sources = Vec::new();

    for source in distribution.sources {
        let context = build_catalog_source_context(&source, distribution_path)?;
        match read_plugin_marketplace_value_from_target(&context.load_target).and_then(|value| {
            if plugin_marketplace_distribution_fixture_from_value(&value)?.is_some() {
                return Err(format!(
                    "Nested plugin marketplace source distributions are not supported yet ('{}').",
                    load_target_display(&context.load_target)
                ));
            }
            let parsed: PluginMarketplaceFixture =
                serde_json::from_value(value).map_err(|error| {
                    format!(
                        "Failed to parse {}: {}",
                        load_target_display(&context.load_target),
                        error
                    )
                })?;
            load_plugin_marketplace_feed_from_fixture(
                parsed,
                &load_target_source_uri(&context.load_target),
                Some(&context),
            )
        }) {
            Ok(mut source_load) => {
                for channel in &mut source_load.catalog_channels {
                    apply_catalog_source_to_channel(channel, &context);
                }
                catalog_sources.push(build_catalog_source_record(
                    &context,
                    &source_load.catalog_channels,
                    None,
                    now_ms,
                ));
                catalog_channels.extend(source_load.catalog_channels.into_iter());
                for mut manifest in source_load.manifests.drain(..) {
                    apply_catalog_source_to_manifest(&mut manifest, &context);
                    let candidate = manifest_candidate_from_record(manifest, now_ms);
                    let plugin_id = candidate.manifest.extension_id.clone();
                    let should_replace = manifest_candidates
                        .get(&plugin_id)
                        .map(|existing| catalog_candidate_should_replace(existing, &candidate))
                        .unwrap_or(true);
                    if should_replace {
                        manifest_candidates.insert(plugin_id, candidate);
                    }
                }
            }
            Err(error) => {
                catalog_sources.push(build_catalog_source_record(
                    &context,
                    &[],
                    Some(error),
                    now_ms,
                ));
            }
        }
    }

    let mut manifests = manifest_candidates
        .into_values()
        .map(|candidate| candidate.manifest)
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| {
        left.display_name
            .as_deref()
            .unwrap_or(&left.name)
            .cmp(right.display_name.as_deref().unwrap_or(&right.name))
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
    });
    catalog_channels.sort_by(|left, right| {
        catalog_channel_status_severity(&right.status)
            .cmp(&catalog_channel_status_severity(&left.status))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.channel.cmp(&right.channel))
    });
    catalog_sources.sort_by(|left, right| {
        catalog_channel_status_severity(&right.status)
            .cmp(&catalog_channel_status_severity(&left.status))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.channel.cmp(&right.channel))
    });

    Ok(PluginMarketplaceFeedLoad {
        manifests,
        catalog_channels,
        catalog_sources,
    })
}

pub(crate) fn load_plugin_marketplace_feed_from_target(
    target: &PluginMarketplaceLoadTarget,
) -> Result<PluginMarketplaceFeedLoad, String> {
    let value = read_plugin_marketplace_value_from_target(target)?;
    if let Some(distribution) = plugin_marketplace_distribution_fixture_from_value(&value)? {
        let distribution_path = match target {
            PluginMarketplaceLoadTarget::LocalPath(path) => path.as_path(),
            PluginMarketplaceLoadTarget::RemoteUri(uri) => {
                return Err(format!(
                    "Top-level remote marketplace distributions are not supported yet ('{}').",
                    uri
                ));
            }
        };
        return load_plugin_marketplace_distribution_from_fixture(distribution, distribution_path);
    }
    let parsed: PluginMarketplaceFixture = serde_json::from_value(value)
        .map_err(|error| format!("Failed to parse {}: {}", load_target_display(target), error))?;
    load_plugin_marketplace_feed_from_fixture(parsed, &load_target_source_uri(target), None)
}

pub(crate) fn load_plugin_marketplace_feed_from_path(
    fixture_path: &Path,
) -> Result<PluginMarketplaceFeedLoad, String> {
    load_plugin_marketplace_feed_from_target(&PluginMarketplaceLoadTarget::LocalPath(
        fixture_path.to_path_buf(),
    ))
}

pub(crate) fn load_plugin_marketplace_feed_catalog_channels_from_path(
    fixture_path: &Path,
) -> Result<Vec<SessionPluginCatalogChannelRecord>, String> {
    Ok(load_plugin_marketplace_feed_from_path(fixture_path)?.catalog_channels)
}

pub(crate) fn load_plugin_marketplace_feed_catalog_sources_from_path(
    fixture_path: &Path,
) -> Result<Vec<SessionPluginCatalogSourceRecord>, String> {
    Ok(load_plugin_marketplace_feed_from_path(fixture_path)?.catalog_sources)
}

pub(crate) fn load_plugin_marketplace_feed_manifests_from_path(
    fixture_path: &Path,
) -> Result<Vec<ExtensionManifestRecord>, String> {
    Ok(load_plugin_marketplace_feed_from_path(fixture_path)?.manifests)
}

pub(crate) fn load_plugin_marketplace_catalog_refresh_target_from_path(
    fixture_path: &Path,
    plugin_id: &str,
) -> Result<PluginCatalogRefreshTarget, String> {
    load_plugin_marketplace_catalog_refresh_target_from_target(
        &PluginMarketplaceLoadTarget::LocalPath(fixture_path.to_path_buf()),
        plugin_id,
    )
}

pub(crate) fn load_plugin_marketplace_catalog_refresh_target_from_target(
    target: &PluginMarketplaceLoadTarget,
    plugin_id: &str,
) -> Result<PluginCatalogRefreshTarget, String> {
    let value = read_plugin_marketplace_value_from_target(target)?;
    if let Some(distribution) = plugin_marketplace_distribution_fixture_from_value(&value)? {
        let distribution_path = match target {
            PluginMarketplaceLoadTarget::LocalPath(path) => path.as_path(),
            PluginMarketplaceLoadTarget::RemoteUri(uri) => {
                return Err(format!(
                    "Top-level remote marketplace distributions are not supported yet ('{}').",
                    uri
                ));
            }
        };
        let manifests = load_plugin_marketplace_feed_from_target(target)?.manifests;
        let selected_manifest = manifests
            .into_iter()
            .find(|manifest| manifest.extension_id == plugin_id)
            .ok_or_else(|| {
                format!(
                    "Plugin '{plugin_id}' is not present in the plugin marketplace distribution."
                )
            })?;
        let selected_source_id = selected_manifest.marketplace_catalog_source_id.clone();
        let selected_source_uri = selected_manifest.marketplace_catalog_source_uri.clone();
        let mut fallback_error = None;
        for source in distribution.sources {
            let context = build_catalog_source_context(&source, distribution_path)?;
            if selected_source_id.as_deref() != Some(context.source_id.as_str())
                && selected_source_uri.as_deref() != Some(context.source_uri.as_str())
            {
                continue;
            }
            match load_plugin_marketplace_catalog_refresh_target_from_target(
                &context.load_target,
                plugin_id,
            ) {
                Ok(target) => return Ok(target),
                Err(error) => fallback_error = Some(error),
            }
        }
        if let Some(error) = fallback_error {
            return Err(error);
        }
        return Err(format!(
            "No signed catalog refresh bundle is currently available for plugin '{}' in the selected marketplace source.",
            plugin_id
        ));
    }
    let parsed: PluginMarketplaceFixture = serde_json::from_value(value)
        .map_err(|error| format!("Failed to parse {}: {}", load_target_display(target), error))?;
    let now_ms = state::now();
    let refresh_evaluation = plugin_catalog_refresh_targets_from_fixture(
        &parsed.roots,
        &parsed.catalog_refresh_bundles,
        now_ms,
    );
    if let Some(target) = refresh_evaluation.targets.get(plugin_id) {
        return Ok(target.clone());
    }
    if let Some(error) = refresh_evaluation.plugin_errors.get(plugin_id) {
        return Err(error.clone());
    }
    Err(format!(
        "No signed catalog refresh bundle is currently available for plugin '{}'.",
        plugin_id
    ))
}

pub(crate) fn load_plugin_marketplace_feed_manifests(
) -> Result<Vec<ExtensionManifestRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
}

pub(crate) fn load_plugin_marketplace_feed_catalog_channels(
) -> Result<Vec<SessionPluginCatalogChannelRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_catalog_channels_from_path(&fixture_path)
}

pub(crate) fn load_plugin_marketplace_feed_catalog_sources(
) -> Result<Vec<SessionPluginCatalogSourceRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_catalog_sources_from_path(&fixture_path)
}

pub(crate) fn enrich_manifest_with_marketplace(
    existing: &mut ExtensionManifestRecord,
    overlay: &ExtensionManifestRecord,
) {
    if existing.marketplace_name.is_none() {
        existing.marketplace_name = overlay.marketplace_name.clone();
    }
    if existing.marketplace_display_name.is_none() {
        existing.marketplace_display_name = overlay.marketplace_display_name.clone();
    }
    if existing.marketplace_category.is_none() {
        existing.marketplace_category = overlay.marketplace_category.clone();
    }
    if existing.marketplace_installation_policy.is_none() {
        existing.marketplace_installation_policy = overlay.marketplace_installation_policy.clone();
    }
    if existing.marketplace_authentication_policy.is_none() {
        existing.marketplace_authentication_policy =
            overlay.marketplace_authentication_policy.clone();
    }
    if existing.marketplace_products.is_empty() {
        existing.marketplace_products = overlay.marketplace_products.clone();
    }
    if existing.marketplace_available_version.is_none() {
        existing.marketplace_available_version = overlay.marketplace_available_version.clone();
    }
    if existing.marketplace_catalog_issued_at_ms.is_none() {
        existing.marketplace_catalog_issued_at_ms = overlay.marketplace_catalog_issued_at_ms;
    }
    if existing.marketplace_catalog_expires_at_ms.is_none() {
        existing.marketplace_catalog_expires_at_ms = overlay.marketplace_catalog_expires_at_ms;
    }
    if existing.marketplace_catalog_refreshed_at_ms.is_none() {
        existing.marketplace_catalog_refreshed_at_ms = overlay.marketplace_catalog_refreshed_at_ms;
    }
    if existing.marketplace_catalog_refresh_source.is_none() {
        existing.marketplace_catalog_refresh_source =
            overlay.marketplace_catalog_refresh_source.clone();
    }
    if existing.marketplace_catalog_channel.is_none() {
        existing.marketplace_catalog_channel = overlay.marketplace_catalog_channel.clone();
    }
    if existing.marketplace_catalog_refresh_bundle_id.is_none() {
        existing.marketplace_catalog_refresh_bundle_id =
            overlay.marketplace_catalog_refresh_bundle_id.clone();
    }
    if existing.marketplace_catalog_refresh_bundle_label.is_none() {
        existing.marketplace_catalog_refresh_bundle_label =
            overlay.marketplace_catalog_refresh_bundle_label.clone();
    }
    if existing
        .marketplace_catalog_refresh_bundle_issued_at_ms
        .is_none()
    {
        existing.marketplace_catalog_refresh_bundle_issued_at_ms =
            overlay.marketplace_catalog_refresh_bundle_issued_at_ms;
    }
    if existing
        .marketplace_catalog_refresh_bundle_expires_at_ms
        .is_none()
    {
        existing.marketplace_catalog_refresh_bundle_expires_at_ms =
            overlay.marketplace_catalog_refresh_bundle_expires_at_ms;
    }
    if existing
        .marketplace_catalog_refresh_available_version
        .is_none()
    {
        existing.marketplace_catalog_refresh_available_version = overlay
            .marketplace_catalog_refresh_available_version
            .clone();
    }
    if existing.marketplace_verification_status.is_none() {
        existing.marketplace_verification_status = overlay.marketplace_verification_status.clone();
    }
    if existing.marketplace_signature_algorithm.is_none() {
        existing.marketplace_signature_algorithm = overlay.marketplace_signature_algorithm.clone();
    }
    if existing.marketplace_signer_identity.is_none() {
        existing.marketplace_signer_identity = overlay.marketplace_signer_identity.clone();
    }
    if existing.marketplace_publisher_id.is_none() {
        existing.marketplace_publisher_id = overlay.marketplace_publisher_id.clone();
    }
    if existing.marketplace_signing_key_id.is_none() {
        existing.marketplace_signing_key_id = overlay.marketplace_signing_key_id.clone();
    }
    if existing.marketplace_publisher_label.is_none() {
        existing.marketplace_publisher_label = overlay.marketplace_publisher_label.clone();
    }
    if existing.marketplace_publisher_trust_status.is_none() {
        existing.marketplace_publisher_trust_status =
            overlay.marketplace_publisher_trust_status.clone();
    }
    if existing.marketplace_publisher_trust_source.is_none() {
        existing.marketplace_publisher_trust_source =
            overlay.marketplace_publisher_trust_source.clone();
    }
    if existing.marketplace_publisher_root_id.is_none() {
        existing.marketplace_publisher_root_id = overlay.marketplace_publisher_root_id.clone();
    }
    if existing.marketplace_publisher_root_label.is_none() {
        existing.marketplace_publisher_root_label =
            overlay.marketplace_publisher_root_label.clone();
    }
    if existing.marketplace_authority_bundle_id.is_none() {
        existing.marketplace_authority_bundle_id = overlay.marketplace_authority_bundle_id.clone();
    }
    if existing.marketplace_authority_bundle_label.is_none() {
        existing.marketplace_authority_bundle_label =
            overlay.marketplace_authority_bundle_label.clone();
    }
    if existing.marketplace_authority_bundle_issued_at_ms.is_none() {
        existing.marketplace_authority_bundle_issued_at_ms =
            overlay.marketplace_authority_bundle_issued_at_ms;
    }
    if existing.marketplace_authority_trust_bundle_id.is_none() {
        existing.marketplace_authority_trust_bundle_id =
            overlay.marketplace_authority_trust_bundle_id.clone();
    }
    if existing.marketplace_authority_trust_bundle_label.is_none() {
        existing.marketplace_authority_trust_bundle_label =
            overlay.marketplace_authority_trust_bundle_label.clone();
    }
    if existing
        .marketplace_authority_trust_bundle_issued_at_ms
        .is_none()
    {
        existing.marketplace_authority_trust_bundle_issued_at_ms =
            overlay.marketplace_authority_trust_bundle_issued_at_ms;
    }
    if existing
        .marketplace_authority_trust_bundle_expires_at_ms
        .is_none()
    {
        existing.marketplace_authority_trust_bundle_expires_at_ms =
            overlay.marketplace_authority_trust_bundle_expires_at_ms;
    }
    if existing.marketplace_authority_trust_bundle_status.is_none() {
        existing.marketplace_authority_trust_bundle_status =
            overlay.marketplace_authority_trust_bundle_status.clone();
    }
    if existing.marketplace_authority_trust_issuer_id.is_none() {
        existing.marketplace_authority_trust_issuer_id =
            overlay.marketplace_authority_trust_issuer_id.clone();
    }
    if existing.marketplace_authority_trust_issuer_label.is_none() {
        existing.marketplace_authority_trust_issuer_label =
            overlay.marketplace_authority_trust_issuer_label.clone();
    }
    if existing.marketplace_authority_id.is_none() {
        existing.marketplace_authority_id = overlay.marketplace_authority_id.clone();
    }
    if existing.marketplace_authority_label.is_none() {
        existing.marketplace_authority_label = overlay.marketplace_authority_label.clone();
    }
    if existing
        .marketplace_publisher_statement_issued_at_ms
        .is_none()
    {
        existing.marketplace_publisher_statement_issued_at_ms =
            overlay.marketplace_publisher_statement_issued_at_ms;
    }
    if existing.marketplace_publisher_trust_detail.is_none() {
        existing.marketplace_publisher_trust_detail =
            overlay.marketplace_publisher_trust_detail.clone();
    }
    if existing.marketplace_publisher_revoked_at_ms.is_none() {
        existing.marketplace_publisher_revoked_at_ms = overlay.marketplace_publisher_revoked_at_ms;
    }
    if existing.marketplace_verification_error.is_none() {
        existing.marketplace_verification_error = overlay.marketplace_verification_error.clone();
    }
    if existing.marketplace_verified_at_ms.is_none() {
        existing.marketplace_verified_at_ms = overlay.marketplace_verified_at_ms;
    }
    if existing.marketplace_verification_source.is_none() {
        existing.marketplace_verification_source = overlay.marketplace_verification_source.clone();
    }
    if existing.marketplace_verified_digest_sha256.is_none() {
        existing.marketplace_verified_digest_sha256 =
            overlay.marketplace_verified_digest_sha256.clone();
    }
    if existing.marketplace_trust_score_label.is_none() {
        existing.marketplace_trust_score_label = overlay.marketplace_trust_score_label.clone();
    }
    if existing.marketplace_trust_score_source.is_none() {
        existing.marketplace_trust_score_source = overlay.marketplace_trust_score_source.clone();
    }
    if existing.marketplace_trust_recommendation.is_none() {
        existing.marketplace_trust_recommendation =
            overlay.marketplace_trust_recommendation.clone();
    }
    if existing.description.is_none() {
        existing.description = overlay.description.clone();
    }
    if existing.category.is_none() {
        existing.category = overlay.category.clone();
    }
}
