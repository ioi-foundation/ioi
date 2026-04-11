use crate::kernel::{capabilities, connectors, state};
use crate::models::{
    AppState, CapabilityRegistryEntry, CapabilityRegistrySnapshot, ExtensionManifestRecord,
    SessionPluginCatalogChannelRecord, SessionPluginCatalogSourceRecord,
    SessionPluginLifecycleReceipt, SessionPluginRecord, SessionPluginSnapshot,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::State;
use url::Url;

const PLUGIN_RUNTIME_STATE_FILE: &str = "plugin_runtime_state.json";
const MAX_PLUGIN_RUNTIME_RECEIPTS: usize = 24;
const MANAGED_PLUGIN_PACKAGES_DIR: &str = "managed_plugins";
const IGNORED_PACKAGE_COPY_DIRS: &[&str] =
    &[".git", ".tmp", "node_modules", "target", "dist", "build"];
const PLUGIN_MARKETPLACE_FIXTURE_ENV: &str = "IOI_PLUGIN_MARKETPLACE_FIXTURE_PATH";
const PLUGIN_SIGNATURE_DOMAIN: &str = "ioi-plugin-package-sha256:";
const PLUGIN_PUBLISHER_STATEMENT_DOMAIN: &str = "ioi-plugin-publisher-statement-v1:";
const PLUGIN_MARKETPLACE_AUTHORITY_BUNDLE_DOMAIN: &str =
    "ioi-plugin-marketplace-authority-bundle-v1:";
const PLUGIN_MARKETPLACE_AUTHORITY_TRUST_BUNDLE_DOMAIN: &str =
    "ioi-plugin-marketplace-authority-trust-bundle-v1:";
const PLUGIN_MARKETPLACE_CATALOG_REFRESH_BUNDLE_DOMAIN: &str =
    "ioi-plugin-marketplace-catalog-refresh-bundle-v1:";
const MARKETPLACE_CATALOG_STALE_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PluginRuntimeState {
    #[serde(default)]
    plugins: Vec<PluginRuntimeRecord>,
    #[serde(default)]
    recent_receipts: Vec<SessionPluginLifecycleReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceFixture {
    #[serde(default)]
    catalogs: Vec<PluginMarketplaceCatalog>,
    #[serde(default)]
    catalog_refresh_bundles: Vec<PluginMarketplaceCatalogRefreshBundle>,
    #[serde(default)]
    roots: Vec<PluginMarketplaceTrustRoot>,
    #[serde(default)]
    publishers: Vec<PluginMarketplacePublisher>,
    #[serde(default)]
    bundle_authorities: Vec<PluginMarketplaceBundleAuthority>,
    #[serde(default)]
    authority_bundles: Vec<PluginMarketplaceAuthorityBundle>,
    #[serde(default)]
    authority_trust_roots: Vec<PluginMarketplaceTrustRoot>,
    #[serde(default)]
    authority_trust_bundles: Vec<PluginMarketplaceAuthorityTrustBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceCatalog {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    source_uri: Option<String>,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    refreshed_at_ms: Option<u64>,
    #[serde(default)]
    refresh_source: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    plugins: Vec<PluginMarketplaceCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceCatalogDistributionFixture {
    #[serde(default)]
    sources: Vec<PluginMarketplaceCatalogSourceFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceCatalogSourceFixture {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    source_uri: Option<String>,
    #[serde(default)]
    fixture_path: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    authority_bundle_id: Option<String>,
    #[serde(default)]
    authority_bundle_label: Option<String>,
    #[serde(default)]
    last_successful_refresh_at_ms: Option<u64>,
    #[serde(default)]
    last_failed_refresh_at_ms: Option<u64>,
    #[serde(default)]
    refresh_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceCatalogEntry {
    manifest_path: String,
    #[serde(default)]
    package_url: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    installation_policy: Option<String>,
    #[serde(default)]
    authentication_policy: Option<String>,
    #[serde(default)]
    products: Vec<String>,
    #[serde(default)]
    available_version: Option<String>,
    #[serde(default)]
    package_digest_sha256: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    signature_public_key: Option<String>,
    #[serde(default)]
    package_signature: Option<String>,
    #[serde(default)]
    verification_status: Option<String>,
    #[serde(default)]
    signer_identity: Option<String>,
    #[serde(default)]
    publisher_id: Option<String>,
    #[serde(default)]
    signing_key_id: Option<String>,
    #[serde(default)]
    publisher_label: Option<String>,
    #[serde(default)]
    verification_error: Option<String>,
    #[serde(default)]
    verified_at_ms: Option<u64>,
    #[serde(default)]
    trust_score_label: Option<String>,
    #[serde(default)]
    trust_score_source: Option<String>,
    #[serde(default)]
    trust_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceCatalogRefreshBundle {
    id: String,
    #[serde(default)]
    label: Option<String>,
    catalog_id: String,
    issuer_id: String,
    #[serde(default)]
    issuer_label: Option<String>,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    refreshed_at_ms: Option<u64>,
    #[serde(default)]
    refresh_source: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    plugins: Vec<PluginMarketplaceCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplacePublisher {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    trust_root_id: Option<String>,
    #[serde(default)]
    trust_status: Option<String>,
    #[serde(default)]
    trust_source: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
    #[serde(default)]
    statement_signature: Option<String>,
    #[serde(default)]
    statement_issued_at_ms: Option<u64>,
    #[serde(default)]
    signing_keys: Vec<PluginMarketplaceSigningKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceBundleAuthority {
    id: String,
    #[serde(default)]
    label: Option<String>,
    public_key: String,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    trust_source: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplacePublisherRevocation {
    publisher_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceAuthorityRevocation {
    authority_id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceAuthorityTrustBundle {
    id: String,
    #[serde(default)]
    label: Option<String>,
    issuer_id: String,
    #[serde(default)]
    issuer_label: Option<String>,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    trust_source: Option<String>,
    #[serde(default)]
    authorities: Vec<PluginMarketplaceBundleAuthority>,
    #[serde(default)]
    authority_revocations: Vec<PluginMarketplaceAuthorityRevocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceAuthorityBundle {
    id: String,
    #[serde(default)]
    label: Option<String>,
    authority_id: String,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    trust_source: Option<String>,
    #[serde(default)]
    roots: Vec<PluginMarketplaceTrustRoot>,
    #[serde(default)]
    publisher_revocations: Vec<PluginMarketplacePublisherRevocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceTrustRoot {
    id: String,
    #[serde(default)]
    label: Option<String>,
    public_key: String,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    trust_source: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PluginMarketplaceSigningKey {
    id: String,
    public_key: String,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct PluginComputedVerification {
    status: Option<String>,
    error: Option<String>,
    algorithm: Option<String>,
    source: Option<String>,
    digest_sha256: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PluginComputedPublisherTrust {
    publisher_id: Option<String>,
    signing_key_id: Option<String>,
    state: Option<String>,
    source: Option<String>,
    root_id: Option<String>,
    root_label: Option<String>,
    statement_issued_at_ms: Option<u64>,
    detail: Option<String>,
    revoked_at_ms: Option<u64>,
    authority_bundle_id: Option<String>,
    authority_bundle_label: Option<String>,
    authority_bundle_issued_at_ms: Option<u64>,
    authority_trust_bundle_id: Option<String>,
    authority_trust_bundle_label: Option<String>,
    authority_trust_bundle_issued_at_ms: Option<u64>,
    authority_trust_bundle_expires_at_ms: Option<u64>,
    authority_trust_bundle_status: Option<String>,
    authority_trust_issuer_id: Option<String>,
    authority_trust_issuer_label: Option<String>,
    authority_id: Option<String>,
    authority_label: Option<String>,
}

#[derive(Debug, Clone)]
struct PluginVerifiedAuthorityTrustBundle {
    bundle_id: String,
    bundle_label: Option<String>,
    bundle_issued_at_ms: Option<u64>,
    bundle_expires_at_ms: Option<u64>,
    bundle_status: String,
    issuer_id: String,
    issuer_label: Option<String>,
    trust_source: Option<String>,
    authorities: Vec<PluginMarketplaceBundleAuthority>,
    authority_revocations: Vec<PluginMarketplaceAuthorityRevocation>,
}

#[derive(Debug, Clone)]
struct PluginDistributedAuthority {
    authority: PluginMarketplaceBundleAuthority,
    trust_bundle_id: String,
    trust_bundle_label: Option<String>,
    trust_bundle_issued_at_ms: Option<u64>,
    trust_bundle_expires_at_ms: Option<u64>,
    trust_bundle_status: String,
    trust_bundle_issuer_id: String,
    trust_bundle_issuer_label: Option<String>,
    trust_source: Option<String>,
}

#[derive(Debug, Clone)]
struct PluginVerifiedAuthorityBundle {
    bundle_id: String,
    bundle_label: Option<String>,
    bundle_issued_at_ms: Option<u64>,
    authority_id: String,
    authority_label: Option<String>,
    trust_source: Option<String>,
    authority_trust_bundle_id: Option<String>,
    authority_trust_bundle_label: Option<String>,
    authority_trust_bundle_issued_at_ms: Option<u64>,
    authority_trust_bundle_expires_at_ms: Option<u64>,
    authority_trust_bundle_status: Option<String>,
    authority_trust_issuer_id: Option<String>,
    authority_trust_issuer_label: Option<String>,
    roots: Vec<PluginMarketplaceTrustRoot>,
    publisher_revocations: Vec<PluginMarketplacePublisherRevocation>,
}

#[derive(Debug, Clone)]
struct PluginVerifiedCatalogRefreshBundle {
    bundle_id: String,
    bundle_label: Option<String>,
    catalog_id: String,
    issued_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
    refreshed_at_ms: Option<u64>,
    refresh_source: Option<String>,
    channel: Option<String>,
    issuer_id: String,
    issuer_label: Option<String>,
    bundle_status: String,
    plugins: Vec<PluginMarketplaceCatalogEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct PluginCatalogRefreshTarget {
    bundle_id: String,
    bundle_label: Option<String>,
    bundle_issued_at_ms: Option<u64>,
    bundle_expires_at_ms: Option<u64>,
    catalog_issued_at_ms: Option<u64>,
    catalog_expires_at_ms: Option<u64>,
    catalog_refreshed_at_ms: Option<u64>,
    catalog_refresh_source: Option<String>,
    catalog_channel: Option<String>,
    available_version: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PluginCatalogRefreshFixtureEvaluation {
    targets: HashMap<String, PluginCatalogRefreshTarget>,
    plugin_errors: HashMap<String, String>,
    catalog_errors: HashMap<String, String>,
    active_bundle_counts: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
struct PluginMarketplaceManifestCandidate {
    manifest: ExtensionManifestRecord,
    status: String,
    channel_priority: u8,
    recency_ms: u64,
    conformance_penalty: bool,
}

#[derive(Debug, Clone)]
struct PluginMarketplaceFeedLoad {
    manifests: Vec<ExtensionManifestRecord>,
    catalog_channels: Vec<SessionPluginCatalogChannelRecord>,
    catalog_sources: Vec<SessionPluginCatalogSourceRecord>,
}

#[derive(Debug, Clone)]
struct PluginMarketplaceCatalogSourceContext {
    source_id: String,
    label: String,
    source_uri: String,
    load_target: PluginMarketplaceLoadTarget,
    transport_kind: String,
    channel: Option<String>,
    authority_bundle_id: Option<String>,
    authority_bundle_label: Option<String>,
    last_successful_refresh_at_ms: Option<u64>,
    last_failed_refresh_at_ms: Option<u64>,
    refresh_error: Option<String>,
}

#[derive(Debug, Clone)]
enum PluginMarketplaceLoadTarget {
    LocalPath(PathBuf),
    RemoteUri(String),
}

#[derive(Debug, Clone)]
enum PluginPackageVerificationTarget {
    LocalRoot(PathBuf),
    ArchiveUri(String),
}

mod authority_trust;
mod commands;
mod crypto;
mod io;
mod manager;
mod marketplace_feed;
mod marketplace_signals;
mod marketplace_sources;
mod publisher_trust;
mod runtime_state;
mod snapshot;
mod trust_verification;

use authority_trust::*;
pub use commands::*;
use crypto::*;
use io::*;
pub use manager::PluginRuntimeManager;
use marketplace_feed::*;
pub(crate) use marketplace_feed::{
    load_plugin_marketplace_catalog_refresh_target_from_path,
    load_plugin_marketplace_feed_manifests_from_path,
};
use marketplace_signals::*;
use marketplace_sources::*;
use publisher_trust::*;
pub(crate) use runtime_state::plugin_runtime_state_path_for;
use runtime_state::*;
pub(crate) use snapshot::build_session_plugin_snapshot_for_manifests_with_fixture_path;
use snapshot::*;
use trust_verification::*;

fn manifest_parent_root(manifest_path: &Path) -> Result<PathBuf, String> {
    manifest_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "Plugin manifest '{}' does not live under '.codex-plugin/'.",
                manifest_path.display()
            )
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginRuntimeRecord {
    plugin_id: String,
    trust_state: String,
    enabled: bool,
    remembered_trust: bool,
    #[serde(default)]
    load_error: Option<String>,
    #[serde(default)]
    last_trusted_at_ms: Option<u64>,
    #[serde(default)]
    last_reloaded_at_ms: Option<u64>,
    #[serde(default)]
    last_enabled_at_ms: Option<u64>,
    #[serde(default)]
    last_disabled_at_ms: Option<u64>,
    #[serde(default)]
    revoked_at_ms: Option<u64>,
    #[serde(default)]
    package_managed: bool,
    #[serde(default)]
    package_install_source: Option<String>,
    #[serde(default)]
    package_install_source_label: Option<String>,
    #[serde(default)]
    package_root_path: Option<String>,
    #[serde(default)]
    package_manifest_path: Option<String>,
    #[serde(default)]
    installed_version: Option<String>,
    #[serde(default)]
    available_version: Option<String>,
    #[serde(default)]
    last_installed_at_ms: Option<u64>,
    #[serde(default)]
    last_updated_at_ms: Option<u64>,
    #[serde(default)]
    last_removed_at_ms: Option<u64>,
    #[serde(default)]
    package_error: Option<String>,
    #[serde(default)]
    catalog_issued_at_ms: Option<u64>,
    #[serde(default)]
    catalog_expires_at_ms: Option<u64>,
    #[serde(default)]
    catalog_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    catalog_refresh_source: Option<String>,
    #[serde(default)]
    catalog_channel: Option<String>,
    #[serde(default)]
    catalog_refresh_bundle_id: Option<String>,
    #[serde(default)]
    catalog_refresh_bundle_label: Option<String>,
    #[serde(default)]
    catalog_refresh_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    catalog_refresh_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    catalog_refresh_error: Option<String>,
    #[serde(default)]
    last_catalog_refresh_at_ms: Option<u64>,
}

impl PluginRuntimeRecord {
    fn trust_required(plugin_id: &str) -> Self {
        Self {
            plugin_id: plugin_id.to_string(),
            trust_state: "trust_required".to_string(),
            enabled: false,
            remembered_trust: false,
            load_error: None,
            last_trusted_at_ms: None,
            last_reloaded_at_ms: None,
            last_enabled_at_ms: None,
            last_disabled_at_ms: None,
            revoked_at_ms: None,
            package_managed: false,
            package_install_source: None,
            package_install_source_label: None,
            package_root_path: None,
            package_manifest_path: None,
            installed_version: None,
            available_version: None,
            last_installed_at_ms: None,
            last_updated_at_ms: None,
            last_removed_at_ms: None,
            package_error: None,
            catalog_issued_at_ms: None,
            catalog_expires_at_ms: None,
            catalog_refreshed_at_ms: None,
            catalog_refresh_source: None,
            catalog_channel: None,
            catalog_refresh_bundle_id: None,
            catalog_refresh_bundle_label: None,
            catalog_refresh_bundle_issued_at_ms: None,
            catalog_refresh_bundle_expires_at_ms: None,
            catalog_refresh_error: None,
            last_catalog_refresh_at_ms: None,
        }
    }
}

#[cfg(test)]
mod tests;
