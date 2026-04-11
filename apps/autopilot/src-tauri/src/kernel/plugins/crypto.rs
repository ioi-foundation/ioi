use super::*;

pub(crate) fn plugin_signature_message(digest_sha256: &str) -> Vec<u8> {
    format!("{PLUGIN_SIGNATURE_DOMAIN}{digest_sha256}").into_bytes()
}

pub(crate) fn publisher_statement_signing_key_entries(
    publisher: &PluginMarketplacePublisher,
) -> Vec<String> {
    let mut entries = publisher
        .signing_keys
        .iter()
        .map(|key| {
            format!(
                "{}|{}|{}|{}",
                key.id.trim(),
                key.public_key.trim(),
                key.status.as_deref().unwrap_or("active").trim(),
                key.revoked_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string())
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn plugin_publisher_statement_message(
    root_id: &str,
    publisher: &PluginMarketplacePublisher,
) -> Vec<u8> {
    format!(
        "{PLUGIN_PUBLISHER_STATEMENT_DOMAIN}{root_id}\npublisherId={}\nlabel={}\ntrustStatus={}\nrevokedAtMs={}\nsigningKeys={}\n",
        publisher.id.trim(),
        publisher.label.as_deref().unwrap_or("").trim(),
        publisher.trust_status.as_deref().unwrap_or("").trim(),
        publisher.revoked_at_ms.unwrap_or(0),
        publisher_statement_signing_key_entries(publisher).join(","),
    )
    .into_bytes()
}

pub(crate) fn authority_bundle_root_entries(roots: &[PluginMarketplaceTrustRoot]) -> Vec<String> {
    let mut entries = roots
        .iter()
        .map(|root| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                root.id.trim(),
                root.label.as_deref().unwrap_or("").trim(),
                root.public_key.trim(),
                root.algorithm.as_deref().unwrap_or("ed25519").trim(),
                root.status.as_deref().unwrap_or("active").trim(),
                root.revoked_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string())
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn authority_bundle_revocation_entries(
    revocations: &[PluginMarketplacePublisherRevocation],
) -> Vec<String> {
    let mut entries = revocations
        .iter()
        .map(|revocation| {
            format!(
                "{}|{}|{}|{}",
                revocation.publisher_id.trim(),
                revocation.label.as_deref().unwrap_or("").trim(),
                revocation
                    .revoked_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                revocation.reason.as_deref().unwrap_or("").trim()
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn authority_trust_bundle_authority_entries(
    authorities: &[PluginMarketplaceBundleAuthority],
) -> Vec<String> {
    let mut entries = authorities
        .iter()
        .map(|authority| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                authority.id.trim(),
                authority.label.as_deref().unwrap_or("").trim(),
                authority.public_key.trim(),
                authority.algorithm.as_deref().unwrap_or("ed25519").trim(),
                authority.status.as_deref().unwrap_or("active").trim(),
                authority
                    .revoked_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                authority.trust_source.as_deref().unwrap_or("").trim()
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn authority_trust_bundle_revocation_entries(
    revocations: &[PluginMarketplaceAuthorityRevocation],
) -> Vec<String> {
    let mut entries = revocations
        .iter()
        .map(|revocation| {
            format!(
                "{}|{}|{}|{}",
                revocation.authority_id.trim(),
                revocation.label.as_deref().unwrap_or("").trim(),
                revocation
                    .revoked_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "0".to_string()),
                revocation.reason.as_deref().unwrap_or("").trim()
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

pub(crate) fn plugin_marketplace_authority_bundle_message(
    bundle: &PluginMarketplaceAuthorityBundle,
) -> Vec<u8> {
    format!(
        "{PLUGIN_MARKETPLACE_AUTHORITY_BUNDLE_DOMAIN}{}\nbundleId={}\nlabel={}\nissuedAtMs={}\nroots={}\npublisherRevocations={}\n",
        bundle.authority_id.trim(),
        bundle.id.trim(),
        bundle.label.as_deref().unwrap_or("").trim(),
        bundle.issued_at_ms.unwrap_or(0),
        authority_bundle_root_entries(&bundle.roots).join(","),
        authority_bundle_revocation_entries(&bundle.publisher_revocations).join(","),
    )
    .into_bytes()
}

pub(crate) fn plugin_marketplace_authority_trust_bundle_message(
    bundle: &PluginMarketplaceAuthorityTrustBundle,
) -> Vec<u8> {
    format!(
        "{PLUGIN_MARKETPLACE_AUTHORITY_TRUST_BUNDLE_DOMAIN}{}\nbundleId={}\nlabel={}\nissuedAtMs={}\nexpiresAtMs={}\nauthorities={}\nauthorityRevocations={}\n",
        bundle.issuer_id.trim(),
        bundle.id.trim(),
        bundle.label.as_deref().unwrap_or("").trim(),
        bundle.issued_at_ms.unwrap_or(0),
        bundle.expires_at_ms.unwrap_or(0),
        authority_trust_bundle_authority_entries(&bundle.authorities).join(","),
        authority_trust_bundle_revocation_entries(&bundle.authority_revocations).join(","),
    )
    .into_bytes()
}

pub(crate) fn catalog_refresh_bundle_plugin_entries(
    entries: &[PluginMarketplaceCatalogEntry],
) -> Vec<String> {
    let mut values = entries
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                entry.manifest_path.trim(),
                entry.display_name.as_deref().unwrap_or("").trim(),
                entry.available_version.as_deref().unwrap_or("").trim(),
                entry.package_digest_sha256.as_deref().unwrap_or("").trim(),
                entry.signature_algorithm.as_deref().unwrap_or("").trim(),
                entry.signature_public_key.as_deref().unwrap_or("").trim(),
                entry.package_signature.as_deref().unwrap_or("").trim(),
                entry.publisher_id.as_deref().unwrap_or("").trim(),
            )
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

pub(crate) fn plugin_marketplace_catalog_refresh_bundle_message(
    bundle: &PluginMarketplaceCatalogRefreshBundle,
) -> Vec<u8> {
    format!(
        "{PLUGIN_MARKETPLACE_CATALOG_REFRESH_BUNDLE_DOMAIN}{}\nbundleId={}\nissuerId={}\nissuerLabel={}\nissuedAtMs={}\nexpiresAtMs={}\nrefreshedAtMs={}\nrefreshSource={}\nchannel={}\nplugins={}\n",
        bundle.catalog_id.trim(),
        bundle.id.trim(),
        bundle.issuer_id.trim(),
        bundle.issuer_label.as_deref().unwrap_or("").trim(),
        bundle.issued_at_ms.unwrap_or(0),
        bundle.expires_at_ms.unwrap_or(0),
        bundle.refreshed_at_ms.unwrap_or(0),
        bundle.refresh_source.as_deref().unwrap_or("").trim(),
        bundle.channel.as_deref().unwrap_or("").trim(),
        catalog_refresh_bundle_plugin_entries(&bundle.plugins).join(","),
    )
    .into_bytes()
}
