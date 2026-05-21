use super::*;

pub(crate) fn plugin_marketplace_fixture_path() -> Option<PathBuf> {
    env_text(PLUGIN_MARKETPLACE_FIXTURE_ENV).map(PathBuf::from)
}

pub(crate) fn load_target_display(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(path) => path.display().to_string(),
        PluginMarketplaceLoadTarget::RemoteUri(uri) => uri.clone(),
    }
}

pub(crate) fn load_target_transport_kind(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(_) => "local_path".to_string(),
        PluginMarketplaceLoadTarget::RemoteUri(_) => "remote_url".to_string(),
    }
}

pub(crate) fn load_target_source_uri(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(path) => slash_path(path),
        PluginMarketplaceLoadTarget::RemoteUri(uri) => uri.clone(),
    }
}

pub(crate) fn read_plugin_marketplace_value_from_target(
    target: &PluginMarketplaceLoadTarget,
) -> Result<Value, String> {
    let raw = match target {
        PluginMarketplaceLoadTarget::LocalPath(path) => {
            if !path.exists() {
                return Err(format!(
                    "Plugin marketplace fixture '{}' does not exist.",
                    path.display()
                ));
            }
            fs::read_to_string(path)
                .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?
        }
        PluginMarketplaceLoadTarget::RemoteUri(uri) => {
            read_text_from_location(uri, "plugin marketplace fixture")?
        }
    };
    serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", load_target_display(target), error))
}

pub(crate) fn plugin_marketplace_distribution_fixture_from_value(
    value: &Value,
) -> Result<Option<PluginMarketplaceCatalogDistributionFixture>, String> {
    let Some(sources) = value.get("sources").and_then(Value::as_array) else {
        return Ok(None);
    };
    if sources.is_empty() {
        return Ok(None);
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| format!("Failed to parse plugin marketplace source distribution: {error}"))
}

pub(crate) fn normalized_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn resolve_distribution_load_target(
    distribution_path: &Path,
    fixture_path: &str,
) -> Result<PluginMarketplaceLoadTarget, String> {
    let normalized = fixture_path.trim();
    if normalized.is_empty() {
        return Err("Plugin marketplace source is missing fixturePath.".to_string());
    }
    if supported_remote_uri(normalized).is_some() {
        return Ok(PluginMarketplaceLoadTarget::RemoteUri(
            normalized.to_string(),
        ));
    }
    let path = PathBuf::from(normalized);
    if path.is_absolute() {
        return Ok(PluginMarketplaceLoadTarget::LocalPath(path));
    }
    Ok(PluginMarketplaceLoadTarget::LocalPath(
        distribution_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path),
    ))
}

pub(crate) fn catalog_source_identity(
    source: &PluginMarketplaceCatalogSourceFixture,
    source_fixture: &str,
) -> String {
    normalized_optional_text(source.id.clone())
        .or_else(|| normalized_optional_text(source.label.clone()))
        .or_else(|| normalized_optional_text(source.source_uri.clone()))
        .unwrap_or_else(|| format!("catalog-source:{}", source_fixture))
}

pub(crate) fn catalog_source_label(
    source: &PluginMarketplaceCatalogSourceFixture,
    source_fixture: &str,
) -> String {
    normalized_optional_text(source.label.clone())
        .or_else(|| normalized_optional_text(source.id.clone()))
        .or_else(|| normalized_optional_text(source.source_uri.clone()))
        .unwrap_or_else(|| format!("Catalog source ({})", source_fixture))
}

pub(crate) fn build_catalog_source_context(
    source: &PluginMarketplaceCatalogSourceFixture,
    distribution_path: &Path,
) -> Result<PluginMarketplaceCatalogSourceContext, String> {
    let load_target = resolve_distribution_load_target(distribution_path, &source.fixture_path)?;
    let fixture_display = load_target_display(&load_target);
    Ok(PluginMarketplaceCatalogSourceContext {
        source_id: catalog_source_identity(source, &fixture_display),
        label: catalog_source_label(source, &fixture_display),
        source_uri: normalized_optional_text(source.source_uri.clone())
            .unwrap_or_else(|| load_target_source_uri(&load_target)),
        transport_kind: load_target_transport_kind(&load_target),
        load_target,
        channel: normalized_optional_text(source.channel.clone()),
        authority_bundle_id: normalized_optional_text(source.authority_bundle_id.clone()),
        authority_bundle_label: normalized_optional_text(source.authority_bundle_label.clone()),
        last_successful_refresh_at_ms: source.last_successful_refresh_at_ms,
        last_failed_refresh_at_ms: source.last_failed_refresh_at_ms,
        refresh_error: normalized_optional_text(source.refresh_error.clone()),
    })
}

pub(crate) fn catalog_identity(catalog: &PluginMarketplaceCatalog, fixture_source: &str) -> String {
    normalized_optional_text(catalog.id.clone()).unwrap_or_else(|| {
        normalized_optional_text(catalog.label.clone())
            .unwrap_or_else(|| format!("catalog:{}", fixture_source))
    })
}

pub(crate) fn catalog_label(catalog: &PluginMarketplaceCatalog, fixture_source: &str) -> String {
    normalized_optional_text(catalog.label.clone())
        .or_else(|| normalized_optional_text(catalog.id.clone()))
        .unwrap_or_else(|| format!("Plugin marketplace feed ({})", fixture_source))
}

pub(crate) fn catalog_channel_priority(channel: Option<&str>) -> u8 {
    match channel
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("security") => 0,
        Some("stable") => 1,
        Some("beta") => 2,
        Some("community") => 3,
        Some("canary") => 4,
        Some(_) => 5,
        None => 6,
    }
}

pub(crate) fn catalog_channel_key(
    catalog_id: &str,
    source_uri: &str,
    channel: Option<&str>,
) -> String {
    format!(
        "{}::{}::{}",
        catalog_id.trim(),
        source_uri.trim(),
        channel.unwrap_or_default().trim()
    )
}

pub(crate) fn catalog_recency_ms(catalog: &PluginMarketplaceCatalog) -> u64 {
    catalog
        .refreshed_at_ms
        .or(catalog.issued_at_ms)
        .unwrap_or(0)
}

pub(crate) fn catalog_channel_status_severity(status: &str) -> u8 {
    match status {
        "nonconformant" => 6,
        "refresh_failed" => 5,
        "refresh_available" => 4,
        "expired" => 3,
        "stale" | "timing_unavailable" => 2,
        _ => 1,
    }
}

pub(crate) fn catalog_candidate_should_replace(
    existing: &PluginMarketplaceManifestCandidate,
    candidate: &PluginMarketplaceManifestCandidate,
) -> bool {
    let existing_severity = catalog_channel_status_severity(&existing.status);
    let candidate_severity = catalog_channel_status_severity(&candidate.status);
    if candidate_severity < existing_severity {
        return true;
    }
    if candidate_severity > existing_severity {
        return false;
    }
    if candidate.conformance_penalty != existing.conformance_penalty {
        return !candidate.conformance_penalty;
    }
    if candidate.channel_priority != existing.channel_priority {
        return candidate.channel_priority < existing.channel_priority;
    }
    if candidate.recency_ms != existing.recency_ms {
        return candidate.recency_ms > existing.recency_ms;
    }
    candidate.manifest.manifest_path < existing.manifest.manifest_path
}

pub(crate) fn catalog_base_conformance_error(catalog: &PluginMarketplaceCatalog) -> Option<String> {
    if normalized_optional_text(catalog.id.clone()).is_none() {
        return Some("Marketplace catalog is missing its id.".to_string());
    }
    if catalog.plugins.is_empty() {
        return Some(format!(
            "Marketplace catalog '{}' does not publish any plugin entries.",
            normalized_optional_text(catalog.label.clone())
                .or_else(|| normalized_optional_text(catalog.id.clone()))
                .unwrap_or_else(|| "unnamed catalog".to_string())
        ));
    }
    None
}

pub(crate) fn catalog_entry_conformance_error(
    entry: &PluginMarketplaceCatalogEntry,
) -> Option<String> {
    if entry.manifest_path.trim().is_empty() {
        return Some("Plugin catalog entry is missing manifestPath.".to_string());
    }
    if supported_remote_uri(entry.manifest_path.trim())
        .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
        && normalized_optional_text(entry.package_url.clone()).is_none()
    {
        return Some(
            "Remote plugin catalog entries must publish packageUrl for runtime verification and install.".to_string(),
        );
    }
    None
}

pub(crate) fn catalog_channel_status_from_metadata(
    label: &str,
    channel: Option<&str>,
    issued_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
    refreshed_at_ms: Option<u64>,
    refresh_error: Option<&str>,
    refresh_available: bool,
    now_ms: u64,
) -> (String, String, String) {
    let channel_label = channel
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!(" on the {} channel", value))
        .unwrap_or_default();
    let freshness_anchor_ms = refreshed_at_ms.or(issued_at_ms);

    if let Some(refresh_error) = refresh_error {
        return (
            "refresh_failed".to_string(),
            "Refresh failed".to_string(),
            refresh_error.to_string(),
        );
    }
    if refresh_available {
        return (
            "refresh_available".to_string(),
            "Refresh available".to_string(),
            format!(
                "{}{} has a newer signed catalog refresh bundle ready to apply.",
                label, channel_label
            ),
        );
    }
    if expires_at_ms.is_some_and(|expires_at_ms| expires_at_ms <= now_ms) {
        return (
            "expired".to_string(),
            "Catalog expired".to_string(),
            format!(
                "{}{} is past its declared freshness window. Refresh the signed catalog before trusting updates from this channel.",
                label, channel_label
            ),
        );
    }
    if freshness_anchor_ms
        .map(|timestamp_ms| {
            now_ms.saturating_sub(timestamp_ms) > MARKETPLACE_CATALOG_STALE_AFTER_MS
        })
        .unwrap_or(false)
    {
        return (
            "stale".to_string(),
            "Catalog refresh stale".to_string(),
            format!(
                "{}{} has not been refreshed recently enough to recommend automatic trust or update decisions.",
                label, channel_label
            ),
        );
    }
    if issued_at_ms.is_some() || refreshed_at_ms.is_some() || expires_at_ms.is_some() {
        return (
            "active".to_string(),
            "Catalog fresh".to_string(),
            format!(
                "{}{} is within its declared freshness window.",
                label, channel_label
            ),
        );
    }
    (
        "timing_unavailable".to_string(),
        "Catalog timing unavailable".to_string(),
        format!(
            "{}{} does not expose issued-at or refresh timing yet, so freshness must be reviewed manually.",
            label, channel_label
        ),
    )
}

pub(crate) fn source_record_status_from_channels(
    channels: &[SessionPluginCatalogChannelRecord],
    refresh_error: Option<&str>,
) -> (String, String, String, String, String, Option<String>) {
    if let Some(refresh_error) = refresh_error {
        return (
            "refresh_failed".to_string(),
            "Refresh failed".to_string(),
            refresh_error.to_string(),
            "nonconformant".to_string(),
            "Nonconformant source".to_string(),
            Some(refresh_error.to_string()),
        );
    }

    if channels
        .iter()
        .any(|channel| channel.conformance_status == "nonconformant")
    {
        let detail = channels
            .iter()
            .find_map(|channel| channel.conformance_error.clone())
            .unwrap_or_else(|| {
                "One or more channel catalogs are nonconformant and require review.".to_string()
            });
        return (
            "nonconformant".to_string(),
            "Nonconformant source".to_string(),
            detail.clone(),
            "nonconformant".to_string(),
            "Nonconformant source".to_string(),
            Some(detail),
        );
    }

    let mut chosen: Option<&SessionPluginCatalogChannelRecord> = None;
    for channel in channels {
        if let Some(existing) = chosen {
            if catalog_channel_status_severity(&channel.status)
                > catalog_channel_status_severity(&existing.status)
            {
                chosen = Some(channel);
            }
        } else {
            chosen = Some(channel);
        }
    }

    if let Some(channel) = chosen {
        return (
            channel.status.clone(),
            channel.status_label.clone(),
            channel.status_detail.clone(),
            "conformant".to_string(),
            "Conformant source".to_string(),
            None,
        );
    }

    (
        "timing_unavailable".to_string(),
        "Catalog timing unavailable".to_string(),
        "This catalog source has not published channel timing or refresh state yet.".to_string(),
        "conformant".to_string(),
        "Conformant source".to_string(),
        None,
    )
}

pub(crate) fn apply_catalog_source_to_manifest(
    manifest: &mut ExtensionManifestRecord,
    source: &PluginMarketplaceCatalogSourceContext,
) {
    manifest.source_uri = source.source_uri.clone();
    if manifest.marketplace_catalog_channel.is_none() {
        manifest.marketplace_catalog_channel = source.channel.clone();
    }
    manifest.marketplace_catalog_source_id = Some(source.source_id.clone());
    manifest.marketplace_catalog_source_label = Some(source.label.clone());
    manifest.marketplace_catalog_source_uri = Some(source.source_uri.clone());
}

pub(crate) fn apply_catalog_source_to_channel(
    record: &mut SessionPluginCatalogChannelRecord,
    source: &PluginMarketplaceCatalogSourceContext,
) {
    record.source_uri = source.source_uri.clone();
    if record.channel.is_none() {
        record.channel = source.channel.clone();
    }
}

pub(crate) fn plugin_manifest_from_catalog_entry(
    fixture_source: &str,
    roots: &[PluginMarketplaceTrustRoot],
    publishers: &[PluginMarketplacePublisher],
    authority_bundle_configured: bool,
    authority_bundles: &[PluginVerifiedAuthorityBundle],
    catalog: &PluginMarketplaceCatalog,
    entry: &PluginMarketplaceCatalogEntry,
    source: Option<&PluginMarketplaceCatalogSourceContext>,
) -> Result<ExtensionManifestRecord, String> {
    if entry.manifest_path.trim().is_empty() {
        return Err("Plugin catalog entry is missing manifestPath.".to_string());
    }
    let manifest_location = normalized_location_text(&entry.manifest_path);
    let package_url = normalized_optional_text(entry.package_url.clone());
    let (raw, root_path, verification_target) = if let Some(url) =
        supported_remote_uri(entry.manifest_path.trim())
    {
        if let Some(path) = local_path_from_supported_uri(&url, "plugin manifest")? {
            let raw = fs::read_to_string(&path)
                .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;
            let manifest_root = manifest_parent_root(&path)?;
            (
                raw,
                slash_path(&manifest_root),
                Some(PluginPackageVerificationTarget::LocalRoot(manifest_root)),
            )
        } else {
            (
                read_text_from_location(&manifest_location, "plugin manifest")?,
                manifest_location.clone(),
                package_url
                    .clone()
                    .map(PluginPackageVerificationTarget::ArchiveUri),
            )
        }
    } else {
        let manifest_path = PathBuf::from(entry.manifest_path.trim());
        let raw = fs::read_to_string(&manifest_path)
            .map_err(|error| format!("Failed to read {}: {}", manifest_path.display(), error))?;
        let manifest_root = manifest_parent_root(&manifest_path)?;
        (
            raw,
            slash_path(&manifest_root),
            Some(PluginPackageVerificationTarget::LocalRoot(manifest_root)),
        )
    };
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", manifest_location, error))?;
    let interface = parsed.get("interface").and_then(Value::as_object);
    let name = string_value(parsed.get("name")).unwrap_or_else(|| {
        Path::new(&root_path)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unnamed-plugin")
            .to_string()
    });
    let computed_verification = if let Some(target) = verification_target.as_ref() {
        compute_plugin_marketplace_verification(entry, target)?
    } else if entry.package_digest_sha256.is_some()
        || entry.signature_algorithm.is_some()
        || entry.signature_public_key.is_some()
        || entry.package_signature.is_some()
    {
        Some(PluginComputedVerification {
            status: Some("signature_mismatch".to_string()),
            error: Some(
                "Remote plugin catalog entry is missing packageUrl, so runtime verification cannot inspect its package contents."
                    .to_string(),
            ),
            algorithm: entry.signature_algorithm.clone(),
            source: Some("runtime signature verification".to_string()),
            digest_sha256: None,
        })
    } else {
        None
    };
    let computed_publisher_trust = computed_verification.as_ref().and_then(|verification| {
        compute_plugin_publisher_trust(
            entry,
            publishers,
            roots,
            authority_bundle_configured,
            authority_bundles,
            verification,
        )
    });
    let catalog_id = catalog_identity(catalog, fixture_source);
    let catalog_label = catalog_label(catalog, fixture_source);
    let display_name = entry
        .display_name
        .clone()
        .or_else(|| interface.and_then(|value| string_value(value.get("displayName"))));
    let description = entry
        .description
        .clone()
        .or_else(|| string_value(parsed.get("description")))
        .or_else(|| interface.and_then(|value| string_value(value.get("shortDescription"))))
        .or_else(|| interface.and_then(|value| string_value(value.get("longDescription"))));
    let category = entry
        .category
        .clone()
        .or_else(|| interface.and_then(|value| string_value(value.get("category"))));
    let governed_profile =
        if entry.installation_policy.is_some() || entry.authentication_policy.is_some() {
            "governed_marketplace".to_string()
        } else {
            "tracked_source".to_string()
        };
    let trust_posture =
        if entry.installation_policy.is_some() || entry.authentication_policy.is_some() {
            "policy_limited".to_string()
        } else {
            "local_only".to_string()
        };

    let source_uri = source
        .map(|source| source.source_uri.clone())
        .or_else(|| normalized_optional_text(catalog.source_uri.clone()))
        .unwrap_or_else(|| fixture_source.to_string());
    Ok(ExtensionManifestRecord {
        extension_id: format!("manifest:{}", manifest_location),
        manifest_kind: "codex_plugin".to_string(),
        manifest_path: manifest_location,
        root_path,
        source_label: catalog_label.clone(),
        source_uri,
        source_kind: "marketplace_catalog".to_string(),
        enabled: true,
        name,
        display_name,
        version: string_value(parsed.get("version")),
        description,
        developer_name: interface.and_then(|value| string_value(value.get("developerName"))),
        author_name: None,
        author_email: None,
        author_url: None,
        category,
        trust_posture,
        governed_profile,
        homepage: string_value(parsed.get("homepage")),
        repository: string_value(parsed.get("repository")),
        license: string_value(parsed.get("license")),
        keywords: string_array(parsed.get("keywords")),
        capabilities: interface
            .map(|value| string_array(value.get("capabilities")))
            .unwrap_or_default(),
        default_prompts: interface
            .map(|value| string_array(value.get("defaultPrompt")))
            .unwrap_or_default()
            .into_iter()
            .take(3)
            .collect(),
        contributions: Vec::new(),
        filesystem_skills: Vec::new(),
        marketplace_name: Some(catalog_id),
        marketplace_display_name: Some(catalog_label),
        marketplace_category: entry.category.clone(),
        marketplace_installation_policy: entry.installation_policy.clone(),
        marketplace_authentication_policy: entry.authentication_policy.clone(),
        marketplace_products: entry.products.clone(),
        marketplace_available_version: entry.available_version.clone(),
        marketplace_catalog_issued_at_ms: catalog.issued_at_ms,
        marketplace_catalog_expires_at_ms: catalog.expires_at_ms,
        marketplace_catalog_refreshed_at_ms: catalog.refreshed_at_ms,
        marketplace_catalog_refresh_source: catalog.refresh_source.clone(),
        marketplace_catalog_channel: catalog.channel.clone(),
        marketplace_catalog_source_id: source.map(|source| source.source_id.clone()),
        marketplace_catalog_source_label: source.map(|source| source.label.clone()),
        marketplace_catalog_source_uri: source.map(|source| source.source_uri.clone()),
        marketplace_package_url: package_url,
        marketplace_catalog_refresh_bundle_id: None,
        marketplace_catalog_refresh_bundle_label: None,
        marketplace_catalog_refresh_bundle_issued_at_ms: None,
        marketplace_catalog_refresh_bundle_expires_at_ms: None,
        marketplace_catalog_refresh_available_version: None,
        marketplace_verification_status: computed_verification
            .as_ref()
            .and_then(|verification| verification.status.clone())
            .or_else(|| entry.verification_status.clone()),
        marketplace_signature_algorithm: computed_verification
            .as_ref()
            .and_then(|verification| verification.algorithm.clone())
            .or_else(|| entry.signature_algorithm.clone()),
        marketplace_signer_identity: entry.signer_identity.clone(),
        marketplace_publisher_id: normalize_registry_id(entry.publisher_id.clone()),
        marketplace_signing_key_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.signing_key_id.clone())
            .or_else(|| normalize_registry_id(entry.signing_key_id.clone())),
        marketplace_publisher_label: entry.publisher_label.clone(),
        marketplace_publisher_trust_status: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.state.clone()),
        marketplace_publisher_trust_source: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.source.clone()),
        marketplace_publisher_root_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.root_id.clone()),
        marketplace_publisher_root_label: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.root_label.clone()),
        marketplace_authority_bundle_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_bundle_id.clone()),
        marketplace_authority_bundle_label: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_bundle_label.clone()),
        marketplace_authority_bundle_issued_at_ms: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_bundle_issued_at_ms),
        marketplace_authority_trust_bundle_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_bundle_id.clone()),
        marketplace_authority_trust_bundle_label: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_bundle_label.clone()),
        marketplace_authority_trust_bundle_issued_at_ms: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_bundle_issued_at_ms),
        marketplace_authority_trust_bundle_expires_at_ms: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_bundle_expires_at_ms),
        marketplace_authority_trust_bundle_status: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_bundle_status.clone()),
        marketplace_authority_trust_issuer_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_issuer_id.clone()),
        marketplace_authority_trust_issuer_label: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_trust_issuer_label.clone()),
        marketplace_authority_id: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_id.clone()),
        marketplace_authority_label: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.authority_label.clone()),
        marketplace_publisher_statement_issued_at_ms: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.statement_issued_at_ms),
        marketplace_publisher_trust_detail: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.detail.clone()),
        marketplace_publisher_revoked_at_ms: computed_publisher_trust
            .as_ref()
            .and_then(|trust| trust.revoked_at_ms),
        marketplace_verification_error: computed_verification
            .as_ref()
            .and_then(|verification| verification.error.clone())
            .or_else(|| entry.verification_error.clone()),
        marketplace_verified_at_ms: entry.verified_at_ms,
        marketplace_verification_source: computed_verification
            .as_ref()
            .and_then(|verification| verification.source.clone()),
        marketplace_verified_digest_sha256: computed_verification
            .as_ref()
            .and_then(|verification| verification.digest_sha256.clone()),
        marketplace_trust_score_label: entry.trust_score_label.clone(),
        marketplace_trust_score_source: entry.trust_score_source.clone(),
        marketplace_trust_recommendation: entry.trust_recommendation.clone(),
    })
}

pub(crate) fn plugin_id_for_manifest_path(manifest_path: &str) -> Option<String> {
    let trimmed = manifest_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!("manifest:{}", normalized_location_text(trimmed)))
}

pub(crate) fn catalog_refresh_target_priority(target: &PluginCatalogRefreshTarget) -> u64 {
    target
        .catalog_refreshed_at_ms
        .or(target.bundle_issued_at_ms)
        .or(target.catalog_issued_at_ms)
        .unwrap_or(0)
}

pub(crate) fn apply_catalog_refresh_target(
    manifest: &mut ExtensionManifestRecord,
    target: &PluginCatalogRefreshTarget,
) {
    manifest.marketplace_catalog_refresh_bundle_id = Some(target.bundle_id.clone());
    manifest.marketplace_catalog_refresh_bundle_label = target.bundle_label.clone();
    manifest.marketplace_catalog_refresh_bundle_issued_at_ms = target.bundle_issued_at_ms;
    manifest.marketplace_catalog_refresh_bundle_expires_at_ms = target.bundle_expires_at_ms;
    manifest.marketplace_catalog_refresh_available_version = target.available_version.clone();
}

pub(crate) fn plugin_catalog_refresh_targets_from_fixture(
    roots: &[PluginMarketplaceTrustRoot],
    bundles: &[PluginMarketplaceCatalogRefreshBundle],
    now_ms: u64,
) -> PluginCatalogRefreshFixtureEvaluation {
    let verified = verify_plugin_marketplace_catalog_refresh_bundles(roots, bundles, now_ms);
    let mut evaluation = PluginCatalogRefreshFixtureEvaluation::default();
    for bundle in &verified {
        if bundle.bundle_status != "active" {
            continue;
        }
        *evaluation
            .active_bundle_counts
            .entry(bundle.catalog_id.clone())
            .or_insert(0) += 1;
        for entry in &bundle.plugins {
            let Some(plugin_id) = plugin_id_for_manifest_path(&entry.manifest_path) else {
                continue;
            };
            let target = PluginCatalogRefreshTarget {
                bundle_id: bundle.bundle_id.clone(),
                bundle_label: bundle.bundle_label.clone(),
                bundle_issued_at_ms: bundle.issued_at_ms,
                bundle_expires_at_ms: bundle.expires_at_ms,
                catalog_issued_at_ms: bundle.issued_at_ms,
                catalog_expires_at_ms: bundle.expires_at_ms,
                catalog_refreshed_at_ms: bundle.refreshed_at_ms,
                catalog_refresh_source: bundle.refresh_source.clone(),
                catalog_channel: bundle.channel.clone(),
                available_version: entry.available_version.clone(),
            };
            let replace = evaluation
                .targets
                .get(&plugin_id)
                .map(|existing| {
                    catalog_refresh_target_priority(&target)
                        > catalog_refresh_target_priority(existing)
                })
                .unwrap_or(true);
            if replace {
                evaluation.targets.insert(plugin_id, target);
            }
        }
    }

    for bundle in bundles {
        let plugin_ids = bundle
            .plugins
            .iter()
            .filter_map(|entry| plugin_id_for_manifest_path(&entry.manifest_path))
            .collect::<Vec<_>>();
        if plugin_ids.is_empty() {
            continue;
        }
        let mut failure_reason = None;
        if bundle.id.trim().is_empty() {
            failure_reason = Some("Catalog refresh bundle is missing its id.".to_string());
        } else if bundle.issuer_id.trim().is_empty() {
            failure_reason = Some(format!(
                "Catalog refresh bundle '{}' is missing its issuer id.",
                bundle.id
            ));
        } else if bundle.catalog_id.trim().is_empty() {
            failure_reason = Some(format!(
                "Catalog refresh bundle '{}' is missing its target catalog id.",
                bundle.id
            ));
        } else if bundle
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms)
        {
            failure_reason = Some(format!(
                "Catalog refresh bundle '{}' has expired and can no longer be applied.",
                bundle.id
            ));
        } else if let Some(root) = roots
            .iter()
            .find(|candidate| candidate.id.trim() == bundle.issuer_id.trim())
        {
            if matches!(root.status.as_deref(), Some("revoked")) || root.revoked_at_ms.is_some() {
                failure_reason = Some(format!(
                    "Catalog refresh bundle '{}' is signed by revoked issuer '{}'.",
                    bundle.id,
                    root.label
                        .clone()
                        .unwrap_or_else(|| bundle.issuer_id.trim().to_string())
                ));
            } else {
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
                    failure_reason = Some(format!(
                        "Catalog refresh bundle '{}' uses unsupported signature metadata.",
                        bundle.id
                    ));
                } else if let Some(signature_raw) = bundle
                    .signature
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    match decode_signature_material(
                        &root.public_key,
                        "marketplace catalog refresh root public key",
                    ) {
                        Ok(root_public_key_bytes) => {
                            match <Ed25519PublicKey as SerializableKey>::from_bytes(
                                &root_public_key_bytes,
                            ) {
                                Ok(root_public_key) => {
                                    match decode_signature_material(
                                        signature_raw,
                                        "marketplaceCatalogRefreshSignature",
                                    ) {
                                        Ok(signature_bytes) => {
                                            match <Ed25519Signature as SerializableKey>::from_bytes(
                                                &signature_bytes,
                                            ) {
                                                Ok(signature) => {
                                                    let message =
                                                        plugin_marketplace_catalog_refresh_bundle_message(bundle);
                                                    if root_public_key
                                                        .verify(&message, &signature)
                                                        .is_err()
                                                    {
                                                        failure_reason = Some(format!(
                                                            "Catalog refresh bundle '{}' failed signature verification.",
                                                            bundle.id
                                                        ));
                                                    }
                                                }
                                                Err(error) => {
                                                    failure_reason = Some(format!(
                                                        "Invalid marketplace catalog refresh signature for bundle '{}': {}",
                                                        bundle.id, error
                                                    ));
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            failure_reason = Some(error);
                                        }
                                    }
                                }
                                Err(error) => {
                                    failure_reason = Some(format!(
                                        "Invalid marketplace catalog refresh issuer key for bundle '{}': {}",
                                        bundle.id, error
                                    ));
                                }
                            }
                        }
                        Err(error) => {
                            failure_reason = Some(error);
                        }
                    }
                } else {
                    failure_reason = Some(format!(
                        "Catalog refresh bundle '{}' is missing its signature.",
                        bundle.id
                    ));
                }
            }
        } else {
            failure_reason = Some(format!(
                "Catalog refresh bundle '{}' is signed by unknown issuer '{}'.",
                bundle.id,
                bundle.issuer_id.trim()
            ));
        }

        if let Some(reason) = failure_reason {
            for plugin_id in plugin_ids {
                evaluation
                    .plugin_errors
                    .entry(plugin_id)
                    .or_insert_with(|| reason.clone());
            }
            if !bundle.catalog_id.trim().is_empty() {
                evaluation
                    .catalog_errors
                    .entry(bundle.catalog_id.trim().to_string())
                    .or_insert(reason);
            }
        }
    }

    evaluation
}

pub(crate) fn build_catalog_source_record(
    source: &PluginMarketplaceCatalogSourceContext,
    channels: &[SessionPluginCatalogChannelRecord],
    refresh_error: Option<String>,
    now_ms: u64,
) -> SessionPluginCatalogSourceRecord {
    let (
        status,
        status_label,
        status_detail,
        conformance_status,
        conformance_label,
        conformance_error,
    ) = source_record_status_from_channels(
        channels,
        refresh_error.as_deref().or(source.refresh_error.as_deref()),
    );
    let invalid_catalog_count = channels
        .iter()
        .filter(|channel| channel.conformance_status == "nonconformant")
        .count();
    SessionPluginCatalogSourceRecord {
        source_id: source.source_id.clone(),
        label: source.label.clone(),
        source_uri: source.source_uri.clone(),
        transport_kind: source.transport_kind.clone(),
        channel: source.channel.clone(),
        authority_bundle_id: source.authority_bundle_id.clone(),
        authority_bundle_label: source.authority_bundle_label.clone(),
        status,
        status_label,
        status_detail,
        last_successful_refresh_at_ms: source.last_successful_refresh_at_ms.or_else(|| {
            channels
                .iter()
                .filter_map(|channel| channel.refreshed_at_ms)
                .max()
        }),
        last_failed_refresh_at_ms: source
            .last_failed_refresh_at_ms
            .or_else(|| refresh_error.as_ref().map(|_| now_ms)),
        refresh_error: refresh_error.or_else(|| source.refresh_error.clone()),
        conformance_status,
        conformance_label,
        conformance_error,
        catalog_count: channels.len(),
        valid_catalog_count: channels.len().saturating_sub(invalid_catalog_count),
        invalid_catalog_count,
    }
}

pub(crate) fn manifest_candidate_from_record(
    manifest: ExtensionManifestRecord,
    now_ms: u64,
) -> PluginMarketplaceManifestCandidate {
    let (status, _, _) = catalog_channel_status_from_metadata(
        manifest
            .marketplace_display_name
            .as_deref()
            .unwrap_or(&manifest.source_label),
        manifest.marketplace_catalog_channel.as_deref(),
        manifest.marketplace_catalog_issued_at_ms,
        manifest.marketplace_catalog_expires_at_ms,
        manifest.marketplace_catalog_refreshed_at_ms,
        None,
        manifest
            .marketplace_catalog_refresh_available_version
            .as_deref()
            .is_some(),
        now_ms,
    );
    PluginMarketplaceManifestCandidate {
        status,
        channel_priority: catalog_channel_priority(manifest.marketplace_catalog_channel.as_deref()),
        recency_ms: manifest
            .marketplace_catalog_refreshed_at_ms
            .or(manifest.marketplace_catalog_issued_at_ms)
            .unwrap_or(0),
        conformance_penalty: false,
        manifest,
    }
}
