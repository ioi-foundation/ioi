use super::*;

pub(crate) fn build_session_plugin_snapshot_from_parts(
    entries: &[CapabilityRegistryEntry],
    extension_manifests: &[ExtensionManifestRecord],
    runtime_state: PluginRuntimeState,
    session_id: Option<String>,
    workspace_root: Option<String>,
    catalog_channel_overlays: Vec<SessionPluginCatalogChannelRecord>,
    catalog_source_overlays: Vec<SessionPluginCatalogSourceRecord>,
) -> SessionPluginSnapshot {
    let extension_lookup = entry_lookup(entries);
    let runtime_lookup = runtime_record_lookup(&runtime_state);
    let workspace_root_ref = workspace_root.as_deref();
    let now_ms = state::now();

    let mut plugins = extension_manifests
        .iter()
        .map(|manifest| {
            let entry_id = format!("extension:{}", manifest.extension_id);
            let capability_entry = extension_lookup.get(&entry_id);
            let runtime_record = runtime_lookup.get(&manifest.extension_id);
            let can_reload = reloadable(manifest);
            let label = manifest
                .display_name
                .clone()
                .unwrap_or_else(|| manifest.name.clone());
            let contribution_count = manifest.contributions.len();
            let hook_contribution_count = manifest
                .contributions
                .iter()
                .filter(|contribution| contribution.kind == "hooks")
                .count();
            let filesystem_skill_count = manifest.filesystem_skills.len();
            let capability_count = manifest.capabilities.len();
            let (
                runtime_enabled,
                runtime_load_state,
                runtime_load_label,
                runtime_status_detail,
                load_error,
            ) =
                plugin_runtime_load_state(manifest, runtime_record, can_reload);
            let (
                package_managed,
                package_install_state,
                package_install_label,
                package_install_detail,
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
            ) = plugin_package_state(manifest, runtime_record);
            let authenticity = plugin_authenticity_signal(manifest);
            let catalog = plugin_catalog_signal(manifest, runtime_record, now_ms);
            let (update_severity, update_severity_label, update_detail) =
                plugin_update_signal(manifest, runtime_record, &authenticity, &catalog);
            let (operator_review_state, operator_review_label, operator_review_reason) =
                plugin_operator_review_signal(
                    &authenticity,
                    &manifest.capabilities,
                    &catalog,
                    update_severity.as_deref(),
                    update_detail.as_deref(),
                );
            let runtime_trust_state = runtime_record
                .map(|record| record.trust_state.clone())
                .unwrap_or_else(|| "trust_required".to_string());
            let runtime_trust_label = plugin_runtime_trust_label(&runtime_trust_state);
            let runtime_load_label_for_reason = runtime_load_label.clone();

            SessionPluginRecord {
                plugin_id: manifest.extension_id.clone(),
                entry_id: capability_entry.map(|entry| entry.entry_id.clone()),
                label: label.clone(),
                description: manifest.description.clone(),
                version: manifest.version.clone(),
                source_enabled: manifest.enabled,
                enabled: runtime_enabled,
                status_label: runtime_load_label.clone(),
                source_label: manifest.source_label.clone(),
                source_kind: manifest.source_kind.clone(),
                source_uri: Some(manifest.source_uri.clone()),
                category: manifest
                    .category
                    .clone()
                    .or_else(|| manifest.marketplace_category.clone()),
                marketplace_display_name: manifest.marketplace_display_name.clone(),
                marketplace_installation_policy: manifest.marketplace_installation_policy.clone(),
                marketplace_authentication_policy: manifest
                    .marketplace_authentication_policy
                    .clone(),
                marketplace_products: manifest.marketplace_products.clone(),
                operator_review_state,
                operator_review_label,
                operator_review_reason,
                catalog_status: catalog.status,
                catalog_status_label: catalog.label,
                catalog_status_detail: catalog.detail,
                catalog_issued_at_ms: catalog.issued_at_ms,
                catalog_expires_at_ms: catalog.expires_at_ms,
                catalog_refreshed_at_ms: catalog.refreshed_at_ms,
                catalog_refresh_source: catalog.refresh_source,
                catalog_channel: catalog.channel,
                catalog_source_id: manifest.marketplace_catalog_source_id.clone(),
                catalog_source_label: manifest.marketplace_catalog_source_label.clone(),
                catalog_source_uri: manifest.marketplace_catalog_source_uri.clone(),
                marketplace_package_url: manifest.marketplace_package_url.clone(),
                catalog_refresh_bundle_id: runtime_record
                    .and_then(|record| record.catalog_refresh_bundle_id.clone())
                    .or_else(|| manifest.marketplace_catalog_refresh_bundle_id.clone()),
                catalog_refresh_bundle_label: runtime_record
                    .and_then(|record| record.catalog_refresh_bundle_label.clone())
                    .or_else(|| manifest.marketplace_catalog_refresh_bundle_label.clone()),
                catalog_refresh_bundle_issued_at_ms: runtime_record
                    .and_then(|record| record.catalog_refresh_bundle_issued_at_ms)
                    .or(manifest.marketplace_catalog_refresh_bundle_issued_at_ms),
                catalog_refresh_bundle_expires_at_ms: runtime_record
                    .and_then(|record| record.catalog_refresh_bundle_expires_at_ms)
                    .or(manifest.marketplace_catalog_refresh_bundle_expires_at_ms),
                catalog_refresh_available_version: runtime_record
                    .and_then(|record| record.available_version.clone())
                    .or_else(|| manifest.marketplace_catalog_refresh_available_version.clone()),
                catalog_refresh_error: runtime_record
                    .and_then(|record| record.catalog_refresh_error.clone()),
                last_catalog_refresh_at_ms: runtime_record
                    .and_then(|record| record.last_catalog_refresh_at_ms),
                authenticity_state: authenticity.state,
                authenticity_label: authenticity.label,
                authenticity_detail: authenticity.detail,
                verification_error: authenticity.verification_error,
                verification_algorithm: authenticity.verification_algorithm,
                publisher_label: authenticity.publisher_label,
                publisher_id: authenticity.publisher_id,
                signer_identity: authenticity.signer_identity,
                signing_key_id: authenticity.signing_key_id,
                verification_timestamp_ms: authenticity.verification_timestamp_ms,
                verification_source: authenticity.verification_source,
                verified_digest_sha256: authenticity.verified_digest_sha256,
                publisher_trust_state: authenticity.publisher_trust_state,
                publisher_trust_label: authenticity.publisher_trust_label,
                publisher_trust_detail: authenticity.publisher_trust_detail,
                publisher_trust_source: authenticity.publisher_trust_source,
                publisher_root_id: authenticity.publisher_root_id,
                publisher_root_label: authenticity.publisher_root_label,
                authority_bundle_id: authenticity.authority_bundle_id,
                authority_bundle_label: authenticity.authority_bundle_label,
                authority_bundle_issued_at_ms: authenticity.authority_bundle_issued_at_ms,
                authority_trust_bundle_id: authenticity.authority_trust_bundle_id,
                authority_trust_bundle_label: authenticity.authority_trust_bundle_label,
                authority_trust_bundle_issued_at_ms:
                    authenticity.authority_trust_bundle_issued_at_ms,
                authority_trust_bundle_expires_at_ms:
                    authenticity.authority_trust_bundle_expires_at_ms,
                authority_trust_bundle_status: authenticity.authority_trust_bundle_status,
                authority_trust_issuer_id: authenticity.authority_trust_issuer_id,
                authority_trust_issuer_label: authenticity.authority_trust_issuer_label,
                authority_id: authenticity.authority_id,
                authority_label: authenticity.authority_label,
                publisher_statement_issued_at_ms: authenticity.publisher_statement_issued_at_ms,
                publisher_revoked_at_ms: authenticity.publisher_revoked_at_ms,
                trust_score_label: authenticity.trust_score_label,
                trust_score_source: authenticity.trust_score_source,
                trust_recommendation: authenticity.trust_recommendation,
                update_severity,
                update_severity_label,
                update_detail,
                requested_capabilities: manifest.capabilities.clone(),
                trust_posture: capability_entry
                    .map(|entry| entry.trust_posture.clone())
                    .unwrap_or_else(|| manifest.trust_posture.clone()),
                governed_profile: capability_entry
                    .and_then(|entry| entry.governed_profile.clone())
                    .unwrap_or_else(|| manifest.governed_profile.clone()),
                authority_tier_label: capability_entry
                    .map(|entry| entry.authority.tier_label.clone())
                    .unwrap_or_else(|| "Governed extension".to_string()),
                availability_label: runtime_load_label.clone(),
                session_scope_label: session_scope_label(workspace_root_ref, manifest),
                reloadable: can_reload,
                reloadability_label: reloadability_label(manifest, can_reload),
                contribution_count,
                hook_contribution_count,
                filesystem_skill_count,
                capability_count,
                runtime_trust_state,
                runtime_trust_label,
                runtime_load_state,
                runtime_load_label,
                runtime_status_detail,
                load_error,
                last_trusted_at_ms: runtime_record.and_then(|record| record.last_trusted_at_ms),
                last_reloaded_at_ms: runtime_record.and_then(|record| record.last_reloaded_at_ms),
                last_installed_at_ms,
                last_updated_at_ms,
                last_removed_at_ms,
                trust_remembered: runtime_record
                    .map(|record| record.remembered_trust)
                    .unwrap_or(false),
                package_managed,
                package_install_state,
                package_install_label,
                package_install_detail,
                package_install_source: package_install_source_value,
                package_install_source_label,
                package_root_path,
                package_manifest_path,
                installed_version,
                available_version,
                update_available,
                package_error,
                why_available: capability_entry
                    .map(|entry| entry.why_selectable.clone())
                    .unwrap_or_else(|| {
                        if runtime_enabled {
                            format!(
                                "{} is loaded in the manifest-backed runtime inventory with remembered trust.",
                                label
                            )
                        } else if runtime_load_label_for_reason == "Trust required before load" {
                            format!(
                                "{} is installed in the manifest-backed inventory, but runtime load is still waiting for trust.",
                                label
                            )
                        } else {
                            format!(
                                "{} is present in the manifest inventory but not active in runtime yet.",
                                label
                            )
                        }
                    }),
            }
        })
        .collect::<Vec<_>>();

    plugins.sort_by(|left, right| {
        right
            .enabled
            .cmp(&left.enabled)
            .then_with(|| left.label.cmp(&right.label))
    });
    let catalog_channels = merge_catalog_channels(
        catalog_channel_records_from_manifests(extension_manifests, &runtime_lookup, now_ms),
        catalog_channel_overlays,
    );

    let enabled_plugin_count = plugins.iter().filter(|plugin| plugin.enabled).count();
    let disabled_plugin_count = plugins.len().saturating_sub(enabled_plugin_count);
    let trusted_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.runtime_trust_state == "trusted")
        .count();
    let untrusted_plugin_count = plugins.len().saturating_sub(trusted_plugin_count);
    let blocked_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.runtime_load_state == "blocked")
        .count();
    let reloadable_plugin_count = plugins.iter().filter(|plugin| plugin.reloadable).count();
    let managed_package_count = plugins
        .iter()
        .filter(|plugin| plugin.package_managed)
        .count();
    let update_available_count = plugins
        .iter()
        .filter(|plugin| plugin.update_available)
        .count();
    let installable_package_count = plugins
        .iter()
        .filter(|plugin| {
            matches!(
                plugin.package_install_state.as_str(),
                "installable" | "removed"
            )
        })
        .count();
    let verified_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.authenticity_state == "verified")
        .count();
    let unverified_plugin_count = plugins
        .iter()
        .filter(|plugin| {
            matches!(
                plugin.authenticity_state.as_str(),
                "unsigned" | "unverified" | "catalog_metadata_only"
            )
        })
        .count();
    let signature_mismatch_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.authenticity_state == "signature_mismatch")
        .count();
    let recommended_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.operator_review_state == "recommended")
        .count();
    let review_required_plugin_count = plugins
        .iter()
        .filter(|plugin| plugin.operator_review_state == "review_required")
        .count();
    let stale_catalog_count = plugins
        .iter()
        .filter(|plugin| plugin.catalog_status == "stale")
        .count();
    let expired_catalog_count = plugins
        .iter()
        .filter(|plugin| plugin.catalog_status == "expired")
        .count();
    let refresh_available_count = plugins
        .iter()
        .filter(|plugin| plugin.catalog_status == "refresh_available")
        .count();
    let refresh_failed_count = plugins
        .iter()
        .filter(|plugin| plugin.catalog_status == "refresh_failed")
        .count();
    let catalog_channel_count = catalog_channels.len();
    let nonconformant_channel_count = catalog_channels
        .iter()
        .filter(|channel| channel.conformance_status == "nonconformant")
        .count();
    let catalog_source_count = catalog_source_overlays.len();
    let local_catalog_source_count = catalog_source_overlays
        .iter()
        .filter(|source| source.transport_kind == "local_path")
        .count();
    let remote_catalog_source_count = catalog_source_overlays
        .iter()
        .filter(|source| source.transport_kind == "remote_url")
        .count();
    let failed_catalog_source_count = catalog_source_overlays
        .iter()
        .filter(|source| source.status == "refresh_failed")
        .count();
    let nonconformant_source_count = catalog_source_overlays
        .iter()
        .filter(|source| source.conformance_status == "nonconformant")
        .count();
    let critical_update_count = plugins
        .iter()
        .filter(|plugin| {
            matches!(
                plugin.update_severity.as_deref(),
                Some(
                    "critical_review" | "blocked" | "review_stale_feed" | "review_refresh_failure"
                )
            )
        })
        .count();
    let hook_contribution_count = plugins
        .iter()
        .map(|plugin| plugin.hook_contribution_count)
        .sum();
    let filesystem_skill_count = plugins
        .iter()
        .map(|plugin| plugin.filesystem_skill_count)
        .sum();

    SessionPluginSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        plugin_count: plugins.len(),
        enabled_plugin_count,
        disabled_plugin_count,
        trusted_plugin_count,
        untrusted_plugin_count,
        blocked_plugin_count,
        reloadable_plugin_count,
        managed_package_count,
        update_available_count,
        installable_package_count,
        verified_plugin_count,
        unverified_plugin_count,
        signature_mismatch_plugin_count,
        recommended_plugin_count,
        review_required_plugin_count,
        stale_catalog_count,
        expired_catalog_count,
        critical_update_count,
        refresh_available_count,
        refresh_failed_count,
        catalog_channel_count,
        nonconformant_channel_count,
        catalog_source_count,
        local_catalog_source_count,
        remote_catalog_source_count,
        failed_catalog_source_count,
        nonconformant_source_count,
        hook_contribution_count,
        filesystem_skill_count,
        recent_receipt_count: runtime_state.recent_receipts.len(),
        recent_receipts: runtime_state.recent_receipts,
        catalog_sources: catalog_source_overlays,
        catalog_channels,
        plugins,
    }
}

pub(crate) fn build_session_plugin_snapshot(
    snapshot: CapabilityRegistrySnapshot,
    runtime_state: PluginRuntimeState,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionPluginSnapshot {
    build_session_plugin_snapshot_from_parts(
        &snapshot.entries,
        &snapshot.extension_manifests,
        runtime_state,
        session_id,
        workspace_root,
        load_plugin_marketplace_feed_catalog_channels().unwrap_or_default(),
        load_plugin_marketplace_feed_catalog_sources().unwrap_or_default(),
    )
}

pub(crate) fn build_session_plugin_snapshot_for_manifests_with_fixture_path(
    extension_manifests: &[ExtensionManifestRecord],
    runtime_state: PluginRuntimeState,
    session_id: Option<String>,
    workspace_root: Option<String>,
    fixture_path: Option<&Path>,
) -> SessionPluginSnapshot {
    build_session_plugin_snapshot_from_parts(
        &[],
        extension_manifests,
        runtime_state,
        session_id,
        workspace_root,
        marketplace_catalog_channel_records_for_fixture_path(fixture_path),
        fixture_path
            .and_then(|path| load_plugin_marketplace_feed_catalog_sources_from_path(path).ok())
            .unwrap_or_default(),
    )
}

#[cfg(test)]
pub(crate) fn build_session_plugin_snapshot_for_manifests(
    extension_manifests: &[ExtensionManifestRecord],
    runtime_state: PluginRuntimeState,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionPluginSnapshot {
    let fixture_path = plugin_marketplace_fixture_path();
    build_session_plugin_snapshot_for_manifests_with_fixture_path(
        extension_manifests,
        runtime_state,
        session_id,
        workspace_root,
        fixture_path.as_deref(),
    )
}

pub(crate) async fn plugin_capability_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
) -> Result<CapabilityRegistrySnapshot, String> {
    let snapshot = capabilities::get_capability_registry_snapshot(state, policy_manager).await?;
    let overlays = load_plugin_marketplace_feed_manifests()?;
    if overlays.is_empty() {
        Ok(snapshot)
    } else {
        Ok(merge_plugin_marketplace_manifests(snapshot, overlays))
    }
}
