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

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn string_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .collect()
}

fn supported_remote_uri(raw: &str) -> Option<Url> {
    let url = Url::parse(raw.trim()).ok()?;
    match url.scheme() {
        "http" | "https" | "file" => Some(url),
        _ => None,
    }
}

fn normalized_location_text(raw: &str) -> String {
    let trimmed = raw.trim();
    if supported_remote_uri(trimmed).is_some() {
        return trimmed.to_string();
    }
    slash_path(Path::new(trimmed))
}

fn local_path_from_supported_uri(url: &Url, source: &str) -> Result<Option<PathBuf>, String> {
    if url.scheme() != "file" {
        return Ok(None);
    }
    url.to_file_path()
        .map(Some)
        .map_err(|_| format!("Failed to decode {} file URL '{}'.", source, url))
}

fn remote_text_client() -> Result<Client, String> {
    Client::builder()
        .redirect(RedirectPolicy::limited(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Failed to create marketplace HTTP client: {error}"))
}

fn read_text_from_location(location: &str, source: &str) -> Result<String, String> {
    if let Some(url) = supported_remote_uri(location) {
        if let Some(path) = local_path_from_supported_uri(&url, source)? {
            return fs::read_to_string(&path).map_err(|error| {
                format!("Failed to read {} ({}): {}", source, path.display(), error)
            });
        }
        let client = remote_text_client()?;
        let response = client
            .get(url.clone())
            .send()
            .map_err(|error| format!("Failed to fetch {} ({}): {}", source, url, error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "Failed to fetch {} ({}): HTTP {}.",
                source,
                url,
                status.as_u16()
            ));
        }
        return response.text().map_err(|error| {
            format!(
                "Failed to read {} response body ({}): {}",
                source, url, error
            )
        });
    }

    fs::read_to_string(location)
        .map_err(|error| format!("Failed to read {} ({}): {}", source, location, error))
}

fn read_bytes_from_location(location: &str, source: &str) -> Result<Vec<u8>, String> {
    if let Some(url) = supported_remote_uri(location) {
        if let Some(path) = local_path_from_supported_uri(&url, source)? {
            return fs::read(&path).map_err(|error| {
                format!("Failed to read {} ({}): {}", source, path.display(), error)
            });
        }
        let client = remote_text_client()?;
        let response = client
            .get(url.clone())
            .send()
            .map_err(|error| format!("Failed to fetch {} ({}): {}", source, url, error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "Failed to fetch {} ({}): HTTP {}.",
                source,
                url,
                status.as_u16()
            ));
        }
        return response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|error| {
                format!(
                    "Failed to read {} response bytes ({}): {}",
                    source, url, error
                )
            });
    }

    fs::read(location)
        .map_err(|error| format!("Failed to read {} ({}): {}", source, location, error))
}

fn normalize_sha256_hex(raw: &str, source: &str) -> Result<String, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    let normalized = normalized
        .strip_prefix("sha256:")
        .unwrap_or(normalized.as_str());
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid sha256 value for {}. Expected 64 hex characters.",
            source
        ));
    }
    Ok(normalized.to_string())
}

fn decode_signature_material(raw: &str, source: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{} is empty.", source));
    }
    if trimmed.len() % 2 == 0 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(trimmed)
            .map_err(|error| format!("Failed to decode {} as hex: {}", source, error));
    }
    BASE64_STANDARD
        .decode(trimmed)
        .map_err(|error| format!("Failed to decode {} as base64: {}", source, error))
}

fn collect_plugin_package_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("Failed to read {}: {}", current.display(), error))?;
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if path.is_dir() {
            if IGNORED_PACKAGE_COPY_DIRS.contains(&file_name) {
                continue;
            }
            collect_plugin_package_files(root, &path, files)?;
            continue;
        }
        if path.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| {
                format!(
                    "Failed to derive a relative package path for {}: {}",
                    path.display(),
                    error
                )
            })?;
            files.push(relative.to_path_buf());
        }
    }

    Ok(())
}

fn compute_plugin_package_digest_sha256(source_root: &Path) -> Result<String, String> {
    let mut relative_files = Vec::new();
    collect_plugin_package_files(source_root, source_root, &mut relative_files)?;
    relative_files.sort_by(|left, right| slash_path(left).cmp(&slash_path(right)));

    let mut preimage = Vec::new();
    for relative_path in relative_files {
        let absolute_path = source_root.join(&relative_path);
        let bytes = fs::read(&absolute_path)
            .map_err(|error| format!("Failed to read {}: {}", absolute_path.display(), error))?;
        let relative_text = slash_path(&relative_path);
        preimage.extend_from_slice(b"FILE\n");
        preimage.extend_from_slice(relative_text.as_bytes());
        preimage.extend_from_slice(b"\nSIZE\n");
        preimage.extend_from_slice(bytes.len().to_string().as_bytes());
        preimage.extend_from_slice(b"\nDATA\n");
        preimage.extend_from_slice(&bytes);
        preimage.extend_from_slice(b"\nEND\n");
    }

    sha256(&preimage).map(hex::encode).map_err(|error| {
        format!(
            "Failed to compute sha256 package digest for {}: {}",
            source_root.display(),
            error
        )
    })
}

fn extract_plugin_archive(bytes: &[u8], destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {}", destination.display(), error))?;
    let cursor = Cursor::new(bytes.to_vec());
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|error| format!("Failed to open plugin package archive: {}", error))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("Failed to read plugin package archive entry: {}", error))?;
        let Some(enclosed_path) = entry.enclosed_name().map(PathBuf::from) else {
            return Err("Plugin package archive contains an unsafe entry path.".to_string());
        };
        let output_path = destination.join(&enclosed_path);
        if entry.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| {
                format!("Failed to create {}: {}", output_path.display(), error)
            })?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create {}: {}", parent.display(), error))?;
        }
        let mut output = fs::File::create(&output_path)
            .map_err(|error| format!("Failed to create {}: {}", output_path.display(), error))?;
        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer).map_err(|error| {
            format!(
                "Failed to read archive entry '{}': {}",
                enclosed_path.display(),
                error
            )
        })?;
        output
            .write_all(&buffer)
            .map_err(|error| format!("Failed to write {}: {}", output_path.display(), error))?;
    }
    Ok(())
}

fn discovered_plugin_roots(root: &Path, matches: &mut Vec<PathBuf>) -> Result<(), String> {
    if root.join(".codex-plugin/plugin.json").exists() {
        matches.push(root.to_path_buf());
    }
    let entries = fs::read_dir(root)
        .map_err(|error| format!("Failed to read {}: {}", root.display(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if IGNORED_PACKAGE_COPY_DIRS
            .iter()
            .any(|ignored| ignored == &name)
        {
            continue;
        }
        discovered_plugin_roots(&path, matches)?;
    }
    Ok(())
}

fn find_plugin_root_in_extracted_archive(root: &Path) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    discovered_plugin_roots(root, &mut matches)?;
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [match_root] => Ok(match_root.clone()),
        [] => Err("Plugin package archive does not contain '.codex-plugin/plugin.json'.".to_string()),
        _ => Err("Plugin package archive contains multiple plugin roots and cannot be installed deterministically.".to_string()),
    }
}

fn with_extracted_plugin_archive<T>(
    archive_location: &str,
    source: &str,
    handler: impl FnOnce(&Path) -> Result<T, String>,
) -> Result<T, String> {
    let archive_bytes = read_bytes_from_location(archive_location, source)?;
    let staging_root =
        env::temp_dir().join(format!("autopilot-plugin-archive-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        extract_plugin_archive(&archive_bytes, &staging_root)?;
        let plugin_root = find_plugin_root_in_extracted_archive(&staging_root)?;
        handler(&plugin_root)
    })();
    let _ = fs::remove_dir_all(&staging_root);
    result
}

fn compute_plugin_package_digest_sha256_from_archive(
    archive_location: &str,
) -> Result<String, String> {
    with_extracted_plugin_archive(
        archive_location,
        "plugin marketplace package archive",
        compute_plugin_package_digest_sha256,
    )
}

fn plugin_signature_message(digest_sha256: &str) -> Vec<u8> {
    format!("{PLUGIN_SIGNATURE_DOMAIN}{digest_sha256}").into_bytes()
}

fn publisher_statement_signing_key_entries(publisher: &PluginMarketplacePublisher) -> Vec<String> {
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

fn plugin_publisher_statement_message(
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

fn authority_bundle_root_entries(roots: &[PluginMarketplaceTrustRoot]) -> Vec<String> {
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

fn authority_bundle_revocation_entries(
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

fn authority_trust_bundle_authority_entries(
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

fn authority_trust_bundle_revocation_entries(
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

fn plugin_marketplace_authority_bundle_message(
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

fn plugin_marketplace_authority_trust_bundle_message(
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

fn catalog_refresh_bundle_plugin_entries(entries: &[PluginMarketplaceCatalogEntry]) -> Vec<String> {
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

fn plugin_marketplace_catalog_refresh_bundle_message(
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

fn verify_plugin_marketplace_catalog_refresh_bundles(
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

fn compute_plugin_marketplace_verification(
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

fn normalize_registry_id(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn build_plugin_computed_publisher_trust(
    publisher_id: Option<String>,
    signing_key_id: Option<String>,
    state: &str,
    source: Option<String>,
    root_id: Option<String>,
    root_label: Option<String>,
    statement_issued_at_ms: Option<u64>,
    detail: Option<String>,
    revoked_at_ms: Option<u64>,
) -> PluginComputedPublisherTrust {
    PluginComputedPublisherTrust {
        publisher_id,
        signing_key_id,
        state: Some(state.to_string()),
        source,
        root_id,
        root_label,
        statement_issued_at_ms,
        detail,
        revoked_at_ms,
        ..Default::default()
    }
}

fn compute_plugin_local_registry_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if verification.status.as_deref() != Some("verified") {
        return None;
    }

    let publisher_id = normalize_registry_id(entry.publisher_id.clone());
    let signing_key_id = normalize_registry_id(entry.signing_key_id.clone());
    let trust_source = Some("local publisher registry".to_string());
    let publisher_label = entry
        .publisher_label
        .clone()
        .unwrap_or_else(|| "this publisher".to_string());

    let Some(publisher_id_value) = publisher_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            None,
            signing_key_id,
            "unknown",
            trust_source,
            None,
            None,
            None,
            Some(
                "Package signature is valid, but no publisher identity was supplied for trust-chain verification."
                    .to_string(),
            ),
            None,
        ));
    };

    let Some(publisher) = publishers
        .iter()
        .find(|candidate| candidate.id.trim() == publisher_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown",
            trust_source,
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not present in the trusted publisher registry.",
                publisher_label
            )),
            None,
        ));
    };

    let registry_label = publisher
        .label
        .clone()
        .unwrap_or_else(|| publisher_label.clone());

    if matches!(publisher.trust_status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "revoked",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Publisher '{}' has been revoked in the plugin trust registry.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    }

    let declared_key_material = entry
        .signature_public_key
        .as_deref()
        .and_then(|raw| decode_signature_material(raw, "signaturePublicKey").ok());
    let signing_key = if let Some(signing_key_id_value) = signing_key_id.as_deref() {
        publisher
            .signing_keys
            .iter()
            .find(|candidate| candidate.id.trim() == signing_key_id_value)
    } else if let Some(declared_bytes) = declared_key_material.as_ref() {
        publisher.signing_keys.iter().find(|candidate| {
            decode_signature_material(&candidate.public_key, "publisher signing key")
                .map(|bytes| bytes == *declared_bytes)
                .unwrap_or(false)
        })
    } else {
        None
    };

    let Some(signing_key) = signing_key else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but the signing key is not recognized for publisher '{}'.",
                registry_label
            )),
            None,
        ));
    };

    if matches!(signing_key.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            Some(signing_key.id.clone()),
            "revoked",
            publisher.trust_source.clone().or(trust_source),
            None,
            None,
            None,
            Some(format!(
                "Publisher '{}' signed this package with a revoked marketplace key.",
                registry_label
            )),
            signing_key.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    if let Some(declared_bytes) = declared_key_material {
        match decode_signature_material(&signing_key.public_key, "publisher signing key") {
            Ok(registry_bytes) if registry_bytes == declared_bytes => {}
            Ok(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown",
                    publisher.trust_source.clone().or(trust_source),
                    None,
                    None,
                    None,
                    Some(format!(
                        "Package signature is valid, but the declared signing key does not match publisher '{}' registry key '{}'.",
                        registry_label, signing_key.id
                    )),
                    None,
                ));
            }
            Err(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown",
                    publisher.trust_source.clone().or(trust_source),
                    None,
                    None,
                    None,
                    Some(format!(
                        "Package signature is valid, but publisher '{}' registry key '{}' could not be decoded.",
                        registry_label, signing_key.id
                    )),
                    None,
                ));
            }
        }
    }

    Some(build_plugin_computed_publisher_trust(
        Some(publisher_id_value),
        Some(signing_key.id.clone()),
        "trusted",
        publisher.trust_source.clone().or(trust_source),
        None,
        None,
        None,
        Some(format!(
            "Package signature is valid and publisher '{}' is trusted by the local marketplace registry.",
            registry_label
        )),
        None,
    ))
}

fn compute_plugin_rooted_publisher_trust(
    entry: &PluginMarketplaceCatalogEntry,
    publishers: &[PluginMarketplacePublisher],
    roots: &[PluginMarketplaceTrustRoot],
    verification: &PluginComputedVerification,
) -> Option<PluginComputedPublisherTrust> {
    if verification.status.as_deref() != Some("verified") {
        return None;
    }

    let publisher_id = normalize_registry_id(entry.publisher_id.clone());
    let signing_key_id = normalize_registry_id(entry.signing_key_id.clone());
    let trust_source = Some("marketplace root verification".to_string());
    let publisher_label = entry
        .publisher_label
        .clone()
        .unwrap_or_else(|| "this publisher".to_string());

    let Some(publisher_id_value) = publisher_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            None,
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            None,
            Some(
                "Package signature is valid, but no publisher identity was supplied for marketplace root verification."
                    .to_string(),
            ),
            None,
        ));
    };

    let Some(publisher) = publishers
        .iter()
        .find(|candidate| candidate.id.trim() == publisher_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            None,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not present in the marketplace publisher statement set.",
                publisher_label
            )),
            None,
        ));
    };

    let registry_label = publisher
        .label
        .clone()
        .unwrap_or_else(|| publisher_label.clone());
    let root_id = normalize_registry_id(publisher.trust_root_id.clone());
    let statement_issued_at_ms = publisher.statement_issued_at_ms;
    let statement_signature = publisher
        .statement_signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(root_id_value) = root_id.clone() else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            None,
            None,
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' is not anchored to a trusted marketplace root.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    let Some(root) = roots
        .iter()
        .find(|candidate| candidate.id.trim() == root_id_value)
    else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            trust_source,
            Some(root_id_value.clone()),
            Some(root_id_value.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' chains to unknown marketplace root '{}'.",
                registry_label, root_id_value
            )),
            publisher.revoked_at_ms,
        ));
    };

    let root_label = root.label.clone().unwrap_or_else(|| root.id.clone());
    if matches!(root.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "revoked_by_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Marketplace root '{}' has been revoked, so publisher '{}' can no longer be trusted.",
                root_label, registry_label
            )),
            root.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    let root_algorithm = root
        .algorithm
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    if !root_algorithm.eq_ignore_ascii_case("ed25519") {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' chains to marketplace root '{}', but the root uses unsupported algorithm '{}'.",
                registry_label, root_label, root_algorithm
            )),
            publisher.revoked_at_ms,
        ));
    }

    let Some(statement_signature_raw) = statement_signature else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' is missing a signed marketplace root statement.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    let root_public_key_bytes = match decode_signature_material(
        &root.public_key,
        "marketplace root public key",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Some(build_plugin_computed_publisher_trust(
                Some(publisher_id_value),
                signing_key_id,
                "unknown_root",
                root.trust_source
                    .clone()
                    .or_else(|| publisher.trust_source.clone())
                    .or(trust_source),
                Some(root.id.clone()),
                Some(root_label.clone()),
                statement_issued_at_ms,
                Some(format!(
                    "Publisher '{}' chains to marketplace root '{}', but the root key could not be decoded: {}",
                    registry_label, root_label, error
                )),
                publisher.revoked_at_ms,
            ));
        }
    };
    let root_public_key = match <Ed25519PublicKey as SerializableKey>::from_bytes(
        &root_public_key_bytes,
    ) {
        Ok(public_key) => public_key,
        Err(error) => {
            return Some(build_plugin_computed_publisher_trust(
                Some(publisher_id_value),
                signing_key_id,
                "unknown_root",
                root.trust_source
                    .clone()
                    .or_else(|| publisher.trust_source.clone())
                    .or(trust_source),
                Some(root.id.clone()),
                Some(root_label.clone()),
                statement_issued_at_ms,
                Some(format!(
                    "Publisher '{}' chains to marketplace root '{}', but the root key is invalid: {}",
                    registry_label, root_label, error
                )),
                publisher.revoked_at_ms,
            ));
        }
    };
    let statement_signature_bytes =
        match decode_signature_material(statement_signature_raw, "publisherStatementSignature") {
            Ok(bytes) => bytes,
            Err(error) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    signing_key_id,
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Publisher '{}' includes an unreadable marketplace root statement: {}",
                        registry_label, error
                    )),
                    publisher.revoked_at_ms,
                ));
            }
        };
    let statement_signature =
        match <Ed25519Signature as SerializableKey>::from_bytes(&statement_signature_bytes) {
            Ok(signature) => signature,
            Err(error) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    signing_key_id,
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                    "Publisher '{}' includes an invalid marketplace root statement signature: {}",
                    registry_label, error
                )),
                    publisher.revoked_at_ms,
                ));
            }
        };
    let statement_message = plugin_publisher_statement_message(&root.id, publisher);
    if root_public_key
        .verify(&statement_message, &statement_signature)
        .is_err()
    {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' includes a marketplace statement that did not validate against root '{}'.",
                registry_label, root_label
            )),
            publisher.revoked_at_ms,
        ));
    }

    let declared_key_material = entry
        .signature_public_key
        .as_deref()
        .and_then(|raw| decode_signature_material(raw, "signaturePublicKey").ok());
    let signing_key = if let Some(signing_key_id_value) = signing_key_id.as_deref() {
        publisher
            .signing_keys
            .iter()
            .find(|candidate| candidate.id.trim() == signing_key_id_value)
    } else if let Some(declared_bytes) = declared_key_material.as_ref() {
        publisher.signing_keys.iter().find(|candidate| {
            decode_signature_material(&candidate.public_key, "publisher signing key")
                .map(|bytes| bytes == *declared_bytes)
                .unwrap_or(false)
        })
    } else {
        None
    };

    let Some(signing_key) = signing_key else {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            signing_key_id,
            "unknown_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Package signature is valid, but publisher '{}' statement does not recognize this signing key.",
                registry_label
            )),
            publisher.revoked_at_ms,
        ));
    };

    if matches!(signing_key.status.as_deref(), Some("revoked")) {
        return Some(build_plugin_computed_publisher_trust(
            Some(publisher_id_value),
            Some(signing_key.id.clone()),
            "revoked_by_root",
            root.trust_source
                .clone()
                .or_else(|| publisher.trust_source.clone())
                .or(trust_source),
            Some(root.id.clone()),
            Some(root_label.clone()),
            statement_issued_at_ms,
            Some(format!(
                "Publisher '{}' signed this package with key '{}' that has been revoked by marketplace root '{}'.",
                registry_label, signing_key.id, root_label
            )),
            signing_key.revoked_at_ms.or(publisher.revoked_at_ms),
        ));
    }

    if let Some(declared_bytes) = declared_key_material {
        match decode_signature_material(&signing_key.public_key, "publisher signing key") {
            Ok(registry_bytes) if registry_bytes == declared_bytes => {}
            Ok(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Package signature is valid, but the declared signing key does not match publisher '{}' statement key '{}'.",
                        registry_label, signing_key.id
                    )),
                    publisher.revoked_at_ms,
                ));
            }
            Err(_) => {
                return Some(build_plugin_computed_publisher_trust(
                    Some(publisher_id_value),
                    Some(signing_key.id.clone()),
                    "unknown_root",
                    root.trust_source
                        .clone()
                        .or_else(|| publisher.trust_source.clone())
                        .or(trust_source),
                    Some(root.id.clone()),
                    Some(root_label.clone()),
                    statement_issued_at_ms,
                    Some(format!(
                        "Package signature is valid, but publisher '{}' statement key '{}' could not be decoded.",
                        registry_label, signing_key.id
                    )),
                    publisher.revoked_at_ms,
                ));
            }
        }
    }

    let publisher_state = match publisher.trust_status.as_deref() {
        Some("revoked") => "revoked_by_root",
        _ => "rooted",
    };
    let detail = if publisher_state == "revoked_by_root" {
        format!(
            "Package signature is valid, but publisher '{}' has been revoked by marketplace root '{}'.",
            registry_label, root_label
        )
    } else {
        format!(
            "Package signature is valid and publisher '{}' is rooted in trusted marketplace authority '{}'.",
            registry_label, root_label
        )
    };

    Some(build_plugin_computed_publisher_trust(
        Some(publisher_id_value),
        Some(signing_key.id.clone()),
        publisher_state,
        root.trust_source
            .clone()
            .or_else(|| publisher.trust_source.clone())
            .or(trust_source),
        Some(root.id.clone()),
        Some(root_label),
        statement_issued_at_ms,
        Some(detail),
        publisher.revoked_at_ms.or(root.revoked_at_ms),
    ))
}

fn verify_plugin_marketplace_authority_bundles(
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

fn verify_plugin_marketplace_authority_trust_bundles(
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

fn distributed_authorities_from_trust_bundles(
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

fn verified_authority_bundle_roots(
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

fn find_verified_authority_bundle_for_root<'a>(
    root_id: &str,
    bundles: &'a [PluginVerifiedAuthorityBundle],
) -> Option<&'a PluginVerifiedAuthorityBundle> {
    bundles
        .iter()
        .find(|bundle| bundle.roots.iter().any(|root| root.id.trim() == root_id))
}

fn compute_plugin_authority_bundle_publisher_trust(
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

fn compute_plugin_publisher_trust(
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

fn plugin_marketplace_fixture_path() -> Option<PathBuf> {
    env_text(PLUGIN_MARKETPLACE_FIXTURE_ENV).map(PathBuf::from)
}

fn load_target_display(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(path) => path.display().to_string(),
        PluginMarketplaceLoadTarget::RemoteUri(uri) => uri.clone(),
    }
}

fn load_target_transport_kind(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(_) => "local_path".to_string(),
        PluginMarketplaceLoadTarget::RemoteUri(_) => "remote_url".to_string(),
    }
}

fn load_target_source_uri(target: &PluginMarketplaceLoadTarget) -> String {
    match target {
        PluginMarketplaceLoadTarget::LocalPath(path) => slash_path(path),
        PluginMarketplaceLoadTarget::RemoteUri(uri) => uri.clone(),
    }
}

fn read_plugin_marketplace_value_from_target(
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

fn plugin_marketplace_distribution_fixture_from_value(
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

fn normalized_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_distribution_load_target(
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

fn catalog_source_identity(
    source: &PluginMarketplaceCatalogSourceFixture,
    source_fixture: &str,
) -> String {
    normalized_optional_text(source.id.clone())
        .or_else(|| normalized_optional_text(source.label.clone()))
        .or_else(|| normalized_optional_text(source.source_uri.clone()))
        .unwrap_or_else(|| format!("catalog-source:{}", source_fixture))
}

fn catalog_source_label(
    source: &PluginMarketplaceCatalogSourceFixture,
    source_fixture: &str,
) -> String {
    normalized_optional_text(source.label.clone())
        .or_else(|| normalized_optional_text(source.id.clone()))
        .or_else(|| normalized_optional_text(source.source_uri.clone()))
        .unwrap_or_else(|| format!("Catalog source ({})", source_fixture))
}

fn build_catalog_source_context(
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

fn catalog_identity(catalog: &PluginMarketplaceCatalog, fixture_source: &str) -> String {
    normalized_optional_text(catalog.id.clone()).unwrap_or_else(|| {
        normalized_optional_text(catalog.label.clone())
            .unwrap_or_else(|| format!("catalog:{}", fixture_source))
    })
}

fn catalog_label(catalog: &PluginMarketplaceCatalog, fixture_source: &str) -> String {
    normalized_optional_text(catalog.label.clone())
        .or_else(|| normalized_optional_text(catalog.id.clone()))
        .unwrap_or_else(|| format!("Plugin marketplace feed ({})", fixture_source))
}

fn catalog_channel_priority(channel: Option<&str>) -> u8 {
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

fn catalog_channel_key(catalog_id: &str, source_uri: &str, channel: Option<&str>) -> String {
    format!(
        "{}::{}::{}",
        catalog_id.trim(),
        source_uri.trim(),
        channel.unwrap_or_default().trim()
    )
}

fn catalog_recency_ms(catalog: &PluginMarketplaceCatalog) -> u64 {
    catalog
        .refreshed_at_ms
        .or(catalog.issued_at_ms)
        .unwrap_or(0)
}

fn catalog_channel_status_severity(status: &str) -> u8 {
    match status {
        "nonconformant" => 6,
        "refresh_failed" => 5,
        "refresh_available" => 4,
        "expired" => 3,
        "stale" | "timing_unavailable" => 2,
        _ => 1,
    }
}

fn catalog_candidate_should_replace(
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

fn catalog_base_conformance_error(catalog: &PluginMarketplaceCatalog) -> Option<String> {
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

fn catalog_entry_conformance_error(entry: &PluginMarketplaceCatalogEntry) -> Option<String> {
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

fn catalog_channel_status_from_metadata(
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

fn source_record_status_from_channels(
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

fn apply_catalog_source_to_manifest(
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

fn apply_catalog_source_to_channel(
    record: &mut SessionPluginCatalogChannelRecord,
    source: &PluginMarketplaceCatalogSourceContext,
) {
    record.source_uri = source.source_uri.clone();
    if record.channel.is_none() {
        record.channel = source.channel.clone();
    }
}

fn plugin_manifest_from_catalog_entry(
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

fn plugin_id_for_manifest_path(manifest_path: &str) -> Option<String> {
    let trimmed = manifest_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(format!("manifest:{}", normalized_location_text(trimmed)))
}

fn catalog_refresh_target_priority(target: &PluginCatalogRefreshTarget) -> u64 {
    target
        .catalog_refreshed_at_ms
        .or(target.bundle_issued_at_ms)
        .or(target.catalog_issued_at_ms)
        .unwrap_or(0)
}

fn apply_catalog_refresh_target(
    manifest: &mut ExtensionManifestRecord,
    target: &PluginCatalogRefreshTarget,
) {
    manifest.marketplace_catalog_refresh_bundle_id = Some(target.bundle_id.clone());
    manifest.marketplace_catalog_refresh_bundle_label = target.bundle_label.clone();
    manifest.marketplace_catalog_refresh_bundle_issued_at_ms = target.bundle_issued_at_ms;
    manifest.marketplace_catalog_refresh_bundle_expires_at_ms = target.bundle_expires_at_ms;
    manifest.marketplace_catalog_refresh_available_version = target.available_version.clone();
}

fn plugin_catalog_refresh_targets_from_fixture(
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

fn build_catalog_source_record(
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

fn manifest_candidate_from_record(
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

fn load_plugin_marketplace_feed_from_fixture(
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

fn load_plugin_marketplace_distribution_from_fixture(
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

fn load_plugin_marketplace_feed_from_target(
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

fn load_plugin_marketplace_feed_from_path(
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

fn load_plugin_marketplace_catalog_refresh_target_from_target(
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

fn load_plugin_marketplace_feed_manifests() -> Result<Vec<ExtensionManifestRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
}

fn load_plugin_marketplace_feed_catalog_channels(
) -> Result<Vec<SessionPluginCatalogChannelRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_catalog_channels_from_path(&fixture_path)
}

fn load_plugin_marketplace_feed_catalog_sources(
) -> Result<Vec<SessionPluginCatalogSourceRecord>, String> {
    let Some(fixture_path) = plugin_marketplace_fixture_path() else {
        return Ok(Vec::new());
    };
    load_plugin_marketplace_feed_catalog_sources_from_path(&fixture_path)
}

fn enrich_manifest_with_marketplace(
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

fn merge_plugin_marketplace_manifests(
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

struct PluginAuthenticitySignal {
    state: String,
    label: String,
    detail: String,
    verification_error: Option<String>,
    verification_algorithm: Option<String>,
    publisher_label: Option<String>,
    publisher_id: Option<String>,
    signer_identity: Option<String>,
    signing_key_id: Option<String>,
    verification_timestamp_ms: Option<u64>,
    verification_source: Option<String>,
    verified_digest_sha256: Option<String>,
    publisher_trust_state: Option<String>,
    publisher_trust_label: Option<String>,
    publisher_trust_detail: Option<String>,
    publisher_trust_source: Option<String>,
    publisher_root_id: Option<String>,
    publisher_root_label: Option<String>,
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
    publisher_statement_issued_at_ms: Option<u64>,
    publisher_revoked_at_ms: Option<u64>,
    trust_score_label: Option<String>,
    trust_score_source: Option<String>,
    trust_recommendation: Option<String>,
}

fn publisher_trust_label(state: Option<&str>) -> Option<String> {
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

fn plugin_authenticity_signal(manifest: &ExtensionManifestRecord) -> PluginAuthenticitySignal {
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

fn plugin_authenticity_block_reason(
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

#[derive(Debug, Clone)]
struct PluginCatalogSignal {
    status: String,
    label: String,
    detail: String,
    issued_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
    refreshed_at_ms: Option<u64>,
    refresh_source: Option<String>,
    channel: Option<String>,
}

fn plugin_catalog_signal(
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

fn parse_plugin_semver_triplet(version: &str) -> Option<(u64, u64, u64)> {
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

fn plugin_update_signal(
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

fn plugin_capability_review_flags(capabilities: &[String]) -> Vec<String> {
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

fn plugin_operator_review_signal(
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

#[derive(Debug, Clone)]
pub struct PluginRuntimeManager {
    path: Arc<PathBuf>,
    state: Arc<Mutex<PluginRuntimeState>>,
}

impl PluginRuntimeManager {
    pub fn new(path: PathBuf) -> Self {
        let state = load_plugin_runtime_state(&path).unwrap_or_default();
        Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub(crate) fn snapshot(&self) -> PluginRuntimeState {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    fn replace_state(&self, next_state: PluginRuntimeState) -> Result<PluginRuntimeState, String> {
        let normalized = normalize_plugin_runtime_state(next_state);
        persist_plugin_runtime_state(&self.path, &normalized)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Failed to lock plugin runtime state.".to_string())?;
        *state = normalized.clone();
        Ok(normalized)
    }

    fn update_plugin<F>(&self, plugin_id: &str, action: F) -> Result<PluginRuntimeState, String>
    where
        F: FnOnce(&mut PluginRuntimeState, &mut PluginRuntimeRecord),
    {
        let mut next_state = self.snapshot();
        let index = next_state
            .plugins
            .iter()
            .position(|record| record.plugin_id == plugin_id)
            .unwrap_or_else(|| {
                next_state
                    .plugins
                    .push(PluginRuntimeRecord::trust_required(plugin_id));
                next_state.plugins.len() - 1
            });
        let mut record = next_state.plugins.remove(index);
        action(&mut next_state, &mut record);
        next_state.plugins.push(record);
        self.replace_state(next_state)
    }

    pub(crate) fn trust_plugin(
        &self,
        manifest: &ExtensionManifestRecord,
        enable_after_trust: bool,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "trust") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.load_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "trust-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone()),
                            action: "trust".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.trust_state = "trusted".to_string();
            record.remembered_trust = true;
            record.last_trusted_at_ms = Some(now);
            record.revoked_at_ms = None;
            record.load_error = None;
            if enable_after_trust {
                record.enabled = manifest.enabled;
                record.last_enabled_at_ms = Some(now);
                record.last_reloaded_at_ms = Some(now);
                if !manifest.enabled {
                    record.load_error = Some(
                        "Tracked source is currently disabled, so the plugin cannot be loaded yet."
                            .to_string(),
                    );
                }
            }
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("trust:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: manifest
                        .display_name
                        .clone()
                        .unwrap_or_else(|| manifest.name.clone()),
                    action: "trust".to_string(),
                    status: "recorded".to_string(),
                    summary: if enable_after_trust {
                        format!(
                            "Remembered trust for {} and enabled it for runtime load.",
                            manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone())
                        )
                    } else {
                        format!(
                            "Remembered trust for {} without enabling runtime load yet.",
                            manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone())
                        )
                    },
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn set_plugin_enabled(
        &self,
        manifest: &ExtensionManifestRecord,
        enabled: bool,
    ) -> Result<(), String> {
        if enabled {
            if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "enable") {
                return self
                    .update_plugin(&manifest.extension_id, |state, record| {
                        let now = state::now();
                        record.enabled = false;
                        record.load_error = Some(block_reason.clone());
                        push_plugin_receipt(
                            state,
                            SessionPluginLifecycleReceipt {
                                receipt_id: format!(
                                    "enable-blocked-signature:{}:{now}",
                                    manifest.extension_id
                                ),
                                timestamp_ms: now,
                                plugin_id: manifest.extension_id.clone(),
                                plugin_label: manifest
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| manifest.name.clone()),
                                action: "enable".to_string(),
                                status: "blocked".to_string(),
                                summary: block_reason.clone(),
                            },
                        );
                    })
                    .map(|_| ());
            }
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            let label = manifest
                .display_name
                .clone()
                .unwrap_or_else(|| manifest.name.clone());
            if enabled {
                if record.trust_state != "trusted" {
                    record.enabled = false;
                    record.load_error =
                        Some("Trust this plugin before enabling it in runtime.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("enable-blocked:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "enable".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked enabling {} because runtime trust has not been granted yet.",
                                manifest.name
                            ),
                        },
                    );
                    return;
                }
                if !manifest.enabled {
                    record.enabled = false;
                    record.load_error = Some(
                        "The tracked source is disabled, so runtime load cannot start yet."
                            .to_string(),
                    );
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("enable-source-disabled:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "enable".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked enabling {} because its tracked source is disabled.",
                                manifest.name
                            ),
                        },
                    );
                    return;
                }

                record.enabled = true;
                record.load_error = None;
                record.last_enabled_at_ms = Some(now);
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("enable:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "enable".to_string(),
                        status: "applied".to_string(),
                        summary: format!("Enabled {} in the runtime plugin roster.", manifest.name),
                    },
                );
                return;
            }

            record.enabled = false;
            record.load_error = None;
            record.last_disabled_at_ms = Some(now);
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("disable:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label,
                    action: "disable".to_string(),
                    status: "applied".to_string(),
                    summary: format!("Disabled {} without revoking remembered trust.", manifest.name),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn reload_plugin(&self, manifest: &ExtensionManifestRecord) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "reload") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.load_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "reload-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone()),
                            action: "reload".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            let label = manifest
                .display_name
                .clone()
                .unwrap_or_else(|| manifest.name.clone());
            if record.trust_state != "trusted" {
                record.load_error =
                    Some("Trust this plugin before reloading it in runtime.".to_string());
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("reload-untrusted:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because remembered trust is not active.",
                            manifest.name
                        ),
                    },
                );
                return;
            }
            if !record.enabled {
                record.load_error =
                    Some("Enable this plugin before asking runtime to reload it.".to_string());
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("reload-disabled:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because it is currently disabled in runtime.",
                            manifest.name
                        ),
                    },
                );
                return;
            }
            if !reloadable(manifest) {
                record.load_error = Some(
                    "Tracked source is unavailable, so runtime reload could not be completed."
                        .to_string(),
                );
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!(
                            "reload-missing-source:{}:{now}",
                            manifest.extension_id
                        ),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because the tracked source is unavailable.",
                            manifest.name
                        ),
                    },
                );
                return;
            }

            record.last_reloaded_at_ms = Some(now);
            record.load_error = None;
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("reload:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label,
                    action: "reload".to_string(),
                    status: "matched".to_string(),
                    summary: format!(
                        "Used remembered trust to reload {} from its tracked source.",
                        manifest.name
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn revoke_plugin_trust(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.trust_state = "revoked".to_string();
            record.enabled = false;
            record.remembered_trust = false;
            record.revoked_at_ms = Some(now);
            record.load_error = Some(
                "Trust revoked. Grant trust again before enabling or reloading this plugin."
                    .to_string(),
            );
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("revoke:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: manifest
                        .display_name
                        .clone()
                        .unwrap_or_else(|| manifest.name.clone()),
                    action: "revoke".to_string(),
                    status: "revoked".to_string(),
                    summary: format!(
                        "Revoked remembered trust for {} and removed it from the runtime roster.",
                        manifest.name
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn install_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "install") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    let label = plugin_display_label(manifest);
                    record.package_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "install-package-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "install".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        let label = plugin_display_label(manifest);
        let managed_root = managed_plugin_root_for(self.path.as_ref(), &manifest.extension_id);
        let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
        let copy_result = if let Some(package_url) = manifest
            .marketplace_package_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            install_managed_plugin_package_from_archive(
                package_url,
                &managed_root,
                managed_manifest.as_path(),
                manifest.version.as_deref(),
            )
        } else {
            let source_root = PathBuf::from(&manifest.root_path);
            install_managed_plugin_package(
                &source_root,
                &managed_root,
                managed_manifest.as_path(),
                manifest.version.as_deref(),
            )
        };
        let (install_source, install_source_label) = package_install_source(manifest);

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &copy_result {
                Ok(()) => {
                    record.package_managed = true;
                    record.package_install_source = Some(install_source.clone());
                    record.package_install_source_label = Some(install_source_label.clone());
                    record.package_root_path = Some(slash_path(&managed_root));
                    record.package_manifest_path = Some(slash_path(&managed_manifest));
                    record.installed_version = manifest.version.clone();
                    record.last_installed_at_ms = Some(now);
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("install-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "install".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Installed a managed package copy for {} from its tracked source.",
                                label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "install-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "install".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to install a managed package copy for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn stage_plugin_update(
        &self,
        manifest: &ExtensionManifestRecord,
        available_version: &str,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        let available_version = available_version.trim().to_string();
        if available_version.is_empty() {
            return Err("Available version is required.".to_string());
        }

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.available_version = Some(available_version.clone());
            record.package_error = None;
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("update-detected:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label.clone(),
                    action: "update_detected".to_string(),
                    status: "available".to_string(),
                    summary: format!(
                        "Marked {} package update {} as available for review.",
                        label, available_version
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn refresh_plugin_catalog(
        &self,
        manifest: &ExtensionManifestRecord,
        refresh_target: Result<PluginCatalogRefreshTarget, String>,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &refresh_target {
                Ok(target) => {
                    record.catalog_issued_at_ms = target.catalog_issued_at_ms;
                    record.catalog_expires_at_ms = target.catalog_expires_at_ms;
                    record.catalog_refreshed_at_ms = target.catalog_refreshed_at_ms;
                    record.catalog_refresh_source = target.catalog_refresh_source.clone();
                    record.catalog_channel = target.catalog_channel.clone();
                    record.catalog_refresh_bundle_id = Some(target.bundle_id.clone());
                    record.catalog_refresh_bundle_label = target.bundle_label.clone();
                    record.catalog_refresh_bundle_issued_at_ms = target.bundle_issued_at_ms;
                    record.catalog_refresh_bundle_expires_at_ms = target.bundle_expires_at_ms;
                    if let Some(available_version) = target.available_version.clone() {
                        record.available_version = Some(available_version);
                    }
                    record.catalog_refresh_error = None;
                    record.last_catalog_refresh_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "catalog-refresh:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "catalog_refresh".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Applied signed catalog refresh for {} from {}.",
                                label,
                                target
                                    .bundle_label
                                    .clone()
                                    .unwrap_or_else(|| target.bundle_id.clone())
                            ),
                        },
                    );
                }
                Err(error) => {
                    let missing_refresh = error.starts_with(
                        "No signed catalog refresh bundle is currently available",
                    );
                    record.catalog_refresh_error = if missing_refresh {
                        None
                    } else {
                        Some(error.clone())
                    };
                    record.last_catalog_refresh_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "catalog-refresh-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "catalog_refresh".to_string(),
                            status: if missing_refresh {
                                "matched".to_string()
                            } else {
                                "failed".to_string()
                            },
                            summary: if missing_refresh {
                                format!(
                                    "No newer signed catalog refresh is currently available for {}.",
                                    label
                                )
                            } else {
                                format!("Failed to refresh the signed catalog for {}: {}", label, error)
                            },
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn update_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "update") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    let label = plugin_display_label(manifest);
                    record.package_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        let label = plugin_display_label(manifest);
        let current_record = self
            .snapshot()
            .plugins
            .into_iter()
            .find(|record| record.plugin_id == manifest.extension_id)
            .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));

        let Some(package_root_path) = current_record.package_root_path.clone() else {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error =
                        Some("Install a managed package copy before applying updates.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-unmanaged:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked updating {} because it is not installed as a managed package yet.",
                                label
                            ),
                        },
                    );
                })
                .map(|_| ());
        };

        let installed_version = current_record
            .installed_version
            .clone()
            .or_else(|| manifest.version.clone());
        let Some(available_version) = current_record
            .available_version
            .clone()
            .or_else(|| manifest.marketplace_available_version.clone())
        else {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error =
                        Some("No packaged update is currently staged for this plugin.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-none:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked updating {} because no newer packaged version is available yet.",
                                label
                            ),
                        },
                    );
                })
                .map(|_| ());
        };
        if installed_version.as_deref() == Some(available_version.as_str()) {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-current:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "matched".to_string(),
                            summary: format!(
                                "{} is already installed at packaged version {}.",
                                label, available_version
                            ),
                        },
                    );
                })
                .map(|_| ());
        }

        let managed_root = PathBuf::from(&package_root_path);
        let managed_manifest = current_record
            .package_manifest_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| managed_root.join(".codex-plugin/plugin.json"));
        let copy_result = if let Some(package_url) = manifest
            .marketplace_package_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            install_managed_plugin_package_from_archive(
                package_url,
                &managed_root,
                managed_manifest.as_path(),
                Some(available_version.as_str()),
            )
        } else {
            let source_root = PathBuf::from(&manifest.root_path);
            install_managed_plugin_package(
                &source_root,
                &managed_root,
                managed_manifest.as_path(),
                Some(available_version.as_str()),
            )
        };

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &copy_result {
                Ok(()) => {
                    record.package_managed = true;
                    record.installed_version = Some(available_version.clone());
                    record.last_updated_at_ms = Some(now);
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("update-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Applied packaged update {} for {}.",
                                available_version, label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to apply packaged update for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn remove_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        let current_record = self
            .snapshot()
            .plugins
            .into_iter()
            .find(|record| record.plugin_id == manifest.extension_id)
            .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));
        let removal_result = current_record
            .package_root_path
            .as_ref()
            .map(PathBuf::from)
            .map(remove_managed_plugin_package)
            .unwrap_or(Ok(()));

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &removal_result {
                Ok(()) => {
                    record.package_managed = false;
                    record.package_root_path = None;
                    record.package_manifest_path = None;
                    record.installed_version = None;
                    record.package_error = None;
                    record.last_removed_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("remove-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "remove".to_string(),
                            status: "removed".to_string(),
                            summary: format!(
                                "Removed the managed package copy for {} without deleting the tracked source manifest.",
                                label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "remove-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "remove".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to remove the managed package copy for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }
}

fn plugin_display_label(manifest: &ExtensionManifestRecord) -> String {
    manifest
        .display_name
        .clone()
        .unwrap_or_else(|| manifest.name.clone())
}

fn safe_plugin_fs_segment(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_dash = false;
    for ch in value.chars() {
        let allowed = ch.is_ascii_alphanumeric();
        if allowed {
            output.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}

fn managed_plugin_root_for(state_path: &Path, plugin_id: &str) -> PathBuf {
    let safe_id = safe_plugin_fs_segment(plugin_id);
    let slug = if safe_id.is_empty() {
        "plugin".to_string()
    } else {
        safe_id
    };
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(MANAGED_PLUGIN_PACKAGES_DIR)
        .join(slug)
}

fn copy_directory_contents(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|error| format!("Failed to create {}: {}", destination.display(), error))?;
    let entries = fs::read_dir(source)
        .map_err(|error| format!("Failed to read {}: {}", source.display(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_name = entry.file_name();
        let destination_path = destination.join(&file_name);
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if IGNORED_PACKAGE_COPY_DIRS
                .iter()
                .any(|ignored| ignored == &name)
            {
                continue;
            }
            copy_directory_contents(&path, &destination_path)?;
            continue;
        }
        if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("Failed to create {}: {}", parent.display(), error))?;
            }
            fs::copy(&path, &destination_path).map_err(|error| {
                format!(
                    "Failed to copy {} to {}: {}",
                    path.display(),
                    destination_path.display(),
                    error
                )
            })?;
        }
    }
    Ok(())
}

fn write_manifest_version(manifest_path: &Path, version: Option<&str>) -> Result<(), String> {
    let Some(version) = version.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let raw = fs::read_to_string(manifest_path)
        .map_err(|error| format!("Failed to read {}: {}", manifest_path.display(), error))?;
    let mut parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", manifest_path.display(), error))?;
    let object = parsed
        .as_object_mut()
        .ok_or_else(|| format!("Manifest {} is not a JSON object.", manifest_path.display()))?;
    object.insert(
        "version".to_string(),
        serde_json::Value::String(version.to_string()),
    );
    let next = serde_json::to_vec_pretty(&parsed)
        .map_err(|error| format!("Failed to encode {}: {}", manifest_path.display(), error))?;
    fs::write(manifest_path, next)
        .map_err(|error| format!("Failed to write {}: {}", manifest_path.display(), error))?;
    Ok(())
}

fn install_managed_plugin_package(
    source_root: &Path,
    managed_root: &Path,
    managed_manifest_path: &Path,
    version_override: Option<&str>,
) -> Result<(), String> {
    if !source_root.exists() {
        return Err(format!(
            "Tracked source '{}' is unavailable, so the managed package copy could not be prepared.",
            source_root.display()
        ));
    }
    if managed_root.exists() {
        fs::remove_dir_all(managed_root)
            .map_err(|error| format!("Failed to clear {}: {}", managed_root.display(), error))?;
    }
    copy_directory_contents(source_root, managed_root)?;
    write_manifest_version(managed_manifest_path, version_override)?;
    Ok(())
}

fn install_managed_plugin_package_from_archive(
    archive_location: &str,
    managed_root: &Path,
    managed_manifest_path: &Path,
    version_override: Option<&str>,
) -> Result<(), String> {
    with_extracted_plugin_archive(
        archive_location,
        "plugin marketplace package archive",
        |plugin_root| {
            install_managed_plugin_package(
                plugin_root,
                managed_root,
                managed_manifest_path,
                version_override,
            )
        },
    )
}

fn remove_managed_plugin_package(managed_root: PathBuf) -> Result<(), String> {
    if !managed_root.exists() {
        return Ok(());
    }
    fs::remove_dir_all(&managed_root)
        .map_err(|error| format!("Failed to remove {}: {}", managed_root.display(), error))
}

fn package_install_source(manifest: &ExtensionManifestRecord) -> (String, String) {
    if let Some(display_name) = manifest
        .marketplace_display_name
        .clone()
        .or_else(|| manifest.marketplace_name.clone())
    {
        if manifest.marketplace_package_url.is_some() {
            return ("marketplace_remote".to_string(), display_name);
        }
        return ("marketplace".to_string(), display_name);
    }
    if manifest.source_kind.contains("home") {
        return ("home_plugins".to_string(), "Home plugins".to_string());
    }
    if manifest.source_kind.contains("workspace") {
        return ("workspace".to_string(), "Workspace source".to_string());
    }
    ("tracked_source".to_string(), manifest.source_label.clone())
}

fn normalize_path_like(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    let normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.studio_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn scope_matches_workspace(
    workspace_root: Option<&str>,
    manifest: &ExtensionManifestRecord,
) -> bool {
    let Some(workspace_root) = workspace_root.and_then(normalize_path_like) else {
        return false;
    };
    let manifest_roots = [
        manifest.root_path.as_str(),
        manifest.source_uri.as_str(),
        manifest.manifest_path.as_str(),
    ];

    manifest_roots.iter().any(|candidate| {
        let Some(candidate) = normalize_path_like(candidate) else {
            return false;
        };
        workspace_root.starts_with(&candidate) || candidate.starts_with(&workspace_root)
    })
}

fn reloadable(manifest: &ExtensionManifestRecord) -> bool {
    Path::new(&manifest.root_path).exists() || Path::new(&manifest.manifest_path).exists()
}

fn session_scope_label(workspace_root: Option<&str>, manifest: &ExtensionManifestRecord) -> String {
    if scope_matches_workspace(workspace_root, manifest) {
        "Matches current workspace".to_string()
    } else if manifest.source_kind.contains("home") {
        "Home plugin source".to_string()
    } else if manifest.source_kind.contains("workspace") {
        "Workspace plugin source".to_string()
    } else {
        "Shared runtime inventory".to_string()
    }
}

fn reloadability_label(manifest: &ExtensionManifestRecord, can_reload: bool) -> String {
    if can_reload && manifest.enabled {
        "Reloadable from tracked source".to_string()
    } else if can_reload {
        "Source present for enable or reload".to_string()
    } else {
        "Static manifest inventory".to_string()
    }
}

pub fn plugin_runtime_state_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join(PLUGIN_RUNTIME_STATE_FILE)
}

fn load_plugin_runtime_state(path: &Path) -> Result<PluginRuntimeState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read plugin runtime state: {}", error))?;
    let parsed: PluginRuntimeState = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse plugin runtime state: {}", error))?;
    Ok(normalize_plugin_runtime_state(parsed))
}

fn persist_plugin_runtime_state(path: &Path, state: &PluginRuntimeState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create plugin runtime directory: {}", error))?;
    }
    let raw = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("Failed to serialize plugin runtime state: {}", error))?;
    fs::write(path, raw)
        .map_err(|error| format!("Failed to persist plugin runtime state: {}", error))?;
    Ok(())
}

fn normalize_plugin_runtime_state(input: PluginRuntimeState) -> PluginRuntimeState {
    let mut plugins = BTreeMap::new();
    for record in input.plugins {
        plugins.insert(record.plugin_id.clone(), record);
    }
    let mut recent_receipts = input.recent_receipts;
    recent_receipts.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    if recent_receipts.len() > MAX_PLUGIN_RUNTIME_RECEIPTS {
        recent_receipts.truncate(MAX_PLUGIN_RUNTIME_RECEIPTS);
    }
    PluginRuntimeState {
        plugins: plugins.into_values().collect(),
        recent_receipts,
    }
}

fn push_plugin_receipt(state: &mut PluginRuntimeState, receipt: SessionPluginLifecycleReceipt) {
    state.recent_receipts.insert(0, receipt);
    if state.recent_receipts.len() > MAX_PLUGIN_RUNTIME_RECEIPTS {
        state.recent_receipts.truncate(MAX_PLUGIN_RUNTIME_RECEIPTS);
    }
}

fn runtime_record_lookup(state: &PluginRuntimeState) -> HashMap<String, PluginRuntimeRecord> {
    state
        .plugins
        .iter()
        .map(|record| (record.plugin_id.clone(), record.clone()))
        .collect()
}

fn plugin_runtime_trust_label(trust_state: &str) -> String {
    match trust_state {
        "trusted" => "Remembered trust granted".to_string(),
        "revoked" => "Trust revoked".to_string(),
        _ => "Trust required".to_string(),
    }
}

fn plugin_runtime_load_state(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
    can_reload: bool,
) -> (bool, String, String, String, Option<String>) {
    let record = runtime_record
        .cloned()
        .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));
    let trust_state = record.trust_state.as_str();
    let trusted = trust_state == "trusted";

    if trust_state == "revoked" {
        return (
            false,
            "blocked".to_string(),
            "Blocked by revoked trust".to_string(),
            "Runtime trust was revoked, so this plugin will not load until an operator trusts it again.".to_string(),
            record.load_error.or_else(|| {
                Some("Trust revoked. Grant trust again before enabling or reloading this plugin.".to_string())
            }),
        );
    }

    if !trusted {
        return (
            false,
            "blocked".to_string(),
            "Trust required before load".to_string(),
            "Manifest inventory is present, but runtime load is gated until an operator grants remembered trust.".to_string(),
            record
                .load_error
                .or_else(|| Some("Trust this plugin before enabling or reloading it in runtime.".to_string())),
        );
    }

    if !record.enabled {
        return (
            false,
            "disabled".to_string(),
            "Trusted but disabled".to_string(),
            "Remembered trust exists, but runtime load is currently disabled for this plugin."
                .to_string(),
            record.load_error,
        );
    }

    if !manifest.enabled {
        return (
            false,
            "blocked".to_string(),
            "Tracked source disabled".to_string(),
            "The tracked source is disabled, so runtime load is paused even though remembered trust exists.".to_string(),
            record.load_error.or_else(|| {
                Some("The tracked source is disabled, so runtime load cannot start yet.".to_string())
            }),
        );
    }

    if can_reload {
        return (
            true,
            "ready".to_string(),
            "Loaded from remembered trust".to_string(),
            "Runtime load is active and the tracked source is available for safe reloads."
                .to_string(),
            record.load_error,
        );
    }

    (
        true,
        "degraded".to_string(),
        "Loaded without a reloadable source".to_string(),
        "Runtime load is active, but the tracked source is not currently available for reload."
            .to_string(),
        record.load_error.or_else(|| {
            Some(
                "Tracked source is unavailable, so runtime reload could not be completed."
                    .to_string(),
            )
        }),
    )
}

fn marketplace_available_version(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
) -> Option<String> {
    runtime_record
        .and_then(|record| record.available_version.clone())
        .or_else(|| manifest.marketplace_available_version.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn package_update_available(
    runtime_record: Option<&PluginRuntimeRecord>,
    manifest: &ExtensionManifestRecord,
) -> bool {
    let Some(available_version) = marketplace_available_version(manifest, runtime_record) else {
        return false;
    };
    let installed_version = runtime_record
        .and_then(|record| record.installed_version.clone())
        .or_else(|| manifest.version.clone())
        .unwrap_or_default();
    available_version != installed_version.trim()
}

#[allow(clippy::type_complexity)]
fn plugin_package_state(
    manifest: &ExtensionManifestRecord,
    runtime_record: Option<&PluginRuntimeRecord>,
) -> (
    bool,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    let update_available = package_update_available(runtime_record, manifest);
    let record = runtime_record.cloned();
    let package_managed = record
        .as_ref()
        .map(|item| item.package_managed)
        .unwrap_or(false);
    let installed_version = record
        .as_ref()
        .and_then(|item| item.installed_version.clone());
    let available_version = marketplace_available_version(manifest, runtime_record);
    let package_install_source_value = record
        .as_ref()
        .and_then(|item| item.package_install_source.clone());
    let package_install_source_label = record
        .as_ref()
        .and_then(|item| item.package_install_source_label.clone());
    let package_root_path = record
        .as_ref()
        .and_then(|item| item.package_root_path.clone());
    let package_manifest_path = record
        .as_ref()
        .and_then(|item| item.package_manifest_path.clone());
    let package_error = record.as_ref().and_then(|item| item.package_error.clone());
    let last_installed_at_ms = record.as_ref().and_then(|item| item.last_installed_at_ms);
    let last_updated_at_ms = record.as_ref().and_then(|item| item.last_updated_at_ms);
    let last_removed_at_ms = record.as_ref().and_then(|item| item.last_removed_at_ms);

    if package_managed {
        let install_label = if update_available {
            "Package update available".to_string()
        } else {
            "Managed package installed".to_string()
        };
        let install_detail = if update_available {
            format!(
                "A profile-local managed package copy is installed at {} and update {} is ready to apply.",
                installed_version
                    .clone()
                    .or_else(|| manifest.version.clone())
                    .unwrap_or_else(|| "an unknown version".to_string()),
                available_version
                    .clone()
                    .unwrap_or_else(|| "a newer version".to_string())
            )
        } else {
            format!(
                "A profile-local managed package copy is installed so this plugin can move into packaged update flow without changing the tracked source manifest."
            )
        };
        return (
            true,
            if update_available {
                "update_available".to_string()
            } else {
                "installed".to_string()
            },
            install_label,
            install_detail,
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
        );
    }

    if last_removed_at_ms.is_some() {
        return (
            false,
            "removed".to_string(),
            "Managed package removed".to_string(),
            "The profile-local managed package copy was removed. The tracked source manifest still exists and can be installed again later.".to_string(),
            package_install_source_value,
            package_install_source_label,
            None,
            None,
            None,
            available_version,
            false,
            package_error,
            last_installed_at_ms,
            last_updated_at_ms,
            last_removed_at_ms,
        );
    }

    let (install_source, install_source_label) = package_install_source(manifest);
    let install_label = if manifest.marketplace_installation_policy.is_some() {
        "Ready for managed install".to_string()
    } else {
        "Tracked source only".to_string()
    };
    let install_detail = if let Some(policy) = manifest.marketplace_installation_policy.as_ref() {
        format!(
            "{} advertises {} installation policy. Install a profile-local managed package copy to track updates and trust posture without mutating the tracked source manifest.",
            plugin_display_label(manifest),
            policy.replace('_', " ")
        )
    } else {
        "This plugin is currently visible from its tracked source only. Install a profile-local managed package copy to track packaged updates and removal separately from runtime trust."
            .to_string()
    };
    (
        false,
        "installable".to_string(),
        install_label,
        install_detail,
        Some(install_source),
        Some(install_source_label),
        None,
        None,
        None,
        available_version,
        false,
        package_error,
        last_installed_at_ms,
        last_updated_at_ms,
        last_removed_at_ms,
    )
}

fn entry_lookup(entries: &[CapabilityRegistryEntry]) -> HashMap<String, CapabilityRegistryEntry> {
    entries
        .iter()
        .filter(|entry| entry.kind == "extension")
        .map(|entry| (entry.entry_id.clone(), entry.clone()))
        .collect()
}

fn merge_catalog_channel_record(
    existing: &mut SessionPluginCatalogChannelRecord,
    incoming: SessionPluginCatalogChannelRecord,
) {
    if catalog_channel_status_severity(&incoming.status)
        > catalog_channel_status_severity(&existing.status)
    {
        existing.status = incoming.status;
        existing.status_label = incoming.status_label;
        existing.status_detail = incoming.status_detail;
    }
    existing.plugin_count = existing.plugin_count.max(incoming.plugin_count);
    existing.valid_plugin_count = existing.valid_plugin_count.max(incoming.valid_plugin_count);
    existing.invalid_plugin_count = existing
        .invalid_plugin_count
        .max(incoming.invalid_plugin_count);
    existing.refresh_bundle_count = existing
        .refresh_bundle_count
        .max(incoming.refresh_bundle_count);
    if existing.refresh_error.is_none() {
        existing.refresh_error = incoming.refresh_error;
    }
    if existing.refresh_source.is_none() {
        existing.refresh_source = incoming.refresh_source;
    }
    if existing.issued_at_ms.is_none() {
        existing.issued_at_ms = incoming.issued_at_ms;
    }
    if existing.expires_at_ms.is_none() {
        existing.expires_at_ms = incoming.expires_at_ms;
    }
    existing.refreshed_at_ms = existing.refreshed_at_ms.max(incoming.refreshed_at_ms);
    if incoming.conformance_status != "conformant" {
        existing.conformance_status = incoming.conformance_status;
        existing.conformance_label = incoming.conformance_label;
        if existing.conformance_error.is_none() {
            existing.conformance_error = incoming.conformance_error;
        }
        if catalog_channel_status_severity("nonconformant")
            > catalog_channel_status_severity(&existing.status)
        {
            existing.status = "nonconformant".to_string();
            existing.status_label = "Nonconformant channel".to_string();
            existing.status_detail = existing.conformance_error.clone().unwrap_or_else(|| {
                format!(
                    "Marketplace catalog '{}' is not conformant yet.",
                    existing.label
                )
            });
        }
    }
}

fn catalog_channel_records_from_manifests(
    extension_manifests: &[ExtensionManifestRecord],
    runtime_lookup: &HashMap<String, PluginRuntimeRecord>,
    now_ms: u64,
) -> Vec<SessionPluginCatalogChannelRecord> {
    let mut grouped = BTreeMap::<String, SessionPluginCatalogChannelRecord>::new();
    for manifest in extension_manifests {
        let Some(catalog_id) = manifest.marketplace_name.clone() else {
            continue;
        };
        let source_uri = manifest.source_uri.clone();
        let channel = manifest.marketplace_catalog_channel.clone();
        let key = catalog_channel_key(&catalog_id, &source_uri, channel.as_deref());
        let signal =
            plugin_catalog_signal(manifest, runtime_lookup.get(&manifest.extension_id), now_ms);
        let record = SessionPluginCatalogChannelRecord {
            catalog_id,
            label: manifest
                .marketplace_display_name
                .clone()
                .unwrap_or_else(|| manifest.source_label.clone()),
            source_uri,
            refresh_source: signal.refresh_source.clone(),
            channel,
            status: signal.status,
            status_label: signal.label,
            status_detail: signal.detail,
            issued_at_ms: signal.issued_at_ms,
            expires_at_ms: signal.expires_at_ms,
            refreshed_at_ms: signal.refreshed_at_ms,
            plugin_count: 1,
            valid_plugin_count: 1,
            invalid_plugin_count: 0,
            refresh_bundle_count: usize::from(
                manifest.marketplace_catalog_refresh_bundle_id.is_some(),
            ),
            refresh_error: runtime_lookup
                .get(&manifest.extension_id)
                .and_then(|record| record.catalog_refresh_error.clone()),
            conformance_status: "conformant".to_string(),
            conformance_label: "Conformant channel".to_string(),
            conformance_error: None,
        };
        if let Some(existing) = grouped.get_mut(&key) {
            existing.plugin_count += 1;
            existing.valid_plugin_count += 1;
            existing.refresh_bundle_count += record.refresh_bundle_count;
            merge_catalog_channel_record(existing, record);
        } else {
            grouped.insert(key, record);
        }
    }
    grouped.into_values().collect()
}

fn marketplace_catalog_channel_records_for_fixture_path(
    fixture_path: Option<&Path>,
) -> Vec<SessionPluginCatalogChannelRecord> {
    fixture_path
        .and_then(|path| load_plugin_marketplace_feed_catalog_channels_from_path(path).ok())
        .unwrap_or_default()
}

fn merge_catalog_channels(
    mut derived: Vec<SessionPluginCatalogChannelRecord>,
    overlays: Vec<SessionPluginCatalogChannelRecord>,
) -> Vec<SessionPluginCatalogChannelRecord> {
    let mut grouped = BTreeMap::<String, SessionPluginCatalogChannelRecord>::new();
    for record in derived.drain(..) {
        let key = catalog_channel_key(
            &record.catalog_id,
            &record.source_uri,
            record.channel.as_deref(),
        );
        grouped.insert(key, record);
    }
    for overlay in overlays {
        let key = catalog_channel_key(
            &overlay.catalog_id,
            &overlay.source_uri,
            overlay.channel.as_deref(),
        );
        if let Some(existing) = grouped.get_mut(&key) {
            merge_catalog_channel_record(existing, overlay);
        } else {
            grouped.insert(key, overlay);
        }
    }
    let mut records = grouped.into_values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        catalog_channel_status_severity(&right.status)
            .cmp(&catalog_channel_status_severity(&left.status))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.channel.cmp(&right.channel))
    });
    records
}

fn build_session_plugin_snapshot_from_parts(
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

fn build_session_plugin_snapshot(
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

async fn plugin_capability_snapshot(
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

#[tauri::command]
pub async fn get_session_plugin_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let current_task = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .current_task
        .clone();

    let session_id = normalized_optional_text(session_id).or_else(|| {
        current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())))
    });
    let workspace_root = normalized_optional_text(workspace_root)
        .or_else(|| current_task.as_ref().and_then(workspace_root_from_task));

    let snapshot = plugin_capability_snapshot(state, policy_manager).await?;
    Ok(build_session_plugin_snapshot(
        snapshot,
        plugin_runtime.snapshot(),
        session_id,
        workspace_root,
    ))
}

fn find_manifest<'a>(
    snapshot: &'a CapabilityRegistrySnapshot,
    plugin_id: &str,
) -> Result<&'a ExtensionManifestRecord, String> {
    snapshot
        .extension_manifests
        .iter()
        .find(|manifest| manifest.extension_id == plugin_id)
        .ok_or_else(|| {
            format!(
                "Plugin '{}' is not present in the manifest inventory.",
                plugin_id
            )
        })
}

fn normalize_plugin_id(value: String) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Plugin id is required.".to_string());
    }
    Ok(trimmed.to_string())
}

async fn plugin_snapshot_for_context(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    get_session_plugin_snapshot(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn trust_session_plugin(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    enable_after_trust: Option<bool>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.trust_plugin(&manifest, enable_after_trust.unwrap_or(true))?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn set_session_plugin_enabled(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    enabled: bool,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.set_plugin_enabled(&manifest, enabled)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn reload_session_plugin(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.reload_plugin(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn refresh_session_plugin_catalog(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    let refresh_target = plugin_marketplace_fixture_path()
        .ok_or_else(|| {
            "Signed plugin catalog refresh requires IOI_PLUGIN_MARKETPLACE_FIXTURE_PATH."
                .to_string()
        })
        .and_then(|fixture_path| {
            load_plugin_marketplace_catalog_refresh_target_from_path(&fixture_path, &plugin_id)
        });
    plugin_runtime.refresh_plugin_catalog(&manifest, refresh_target)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn revoke_session_plugin_trust(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.revoke_plugin_trust(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn install_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.install_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn update_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.update_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[tauri::command]
pub async fn remove_session_plugin_package(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    plugin_runtime: State<'_, PluginRuntimeManager>,
    plugin_id: String,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionPluginSnapshot, String> {
    let plugin_id = normalize_plugin_id(plugin_id)?;
    let snapshot = plugin_capability_snapshot(state.clone(), policy_manager.clone()).await?;
    let manifest = find_manifest(&snapshot, &plugin_id)?.clone();
    plugin_runtime.remove_plugin_package(&manifest)?;
    plugin_snapshot_for_context(
        state,
        policy_manager,
        plugin_runtime,
        session_id,
        workspace_root,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::build_session_plugin_snapshot;
    use super::*;
    use crate::models::{
        CapabilityAuthorityDescriptor, CapabilityLeaseDescriptor, CapabilityRegistrySummary,
        ExtensionContributionRecord, LocalEngineApiConfig, LocalEngineBackendPolicyConfig,
        LocalEngineControlPlane, LocalEngineMemoryConfig, LocalEngineResponseConfig,
        LocalEngineRuntimeProfile, LocalEngineSnapshot, LocalEngineStorageConfig,
        LocalEngineWatchdogConfig, SkillSourceDiscoveredSkill,
    };
    use ioi_api::crypto::SigningKeyPair as _;
    use ioi_crypto::sign::eddsa::Ed25519KeyPair;

    fn empty_local_engine_snapshot() -> LocalEngineSnapshot {
        LocalEngineSnapshot {
            generated_at_ms: 0,
            total_native_tools: 0,
            pending_control_count: 0,
            pending_approval_count: 0,
            active_issue_count: 0,
            capabilities: Vec::new(),
            compatibility_routes: Vec::new(),
            pending_controls: Vec::new(),
            jobs: Vec::new(),
            recent_activity: Vec::new(),
            registry_models: Vec::new(),
            managed_backends: Vec::new(),
            gallery_catalogs: Vec::new(),
            worker_templates: Vec::new(),
            agent_playbooks: Vec::new(),
            parent_playbook_runs: Vec::new(),
            control_plane_schema_version: 1,
            control_plane_profile_id: "test".to_string(),
            control_plane_migrations: Vec::new(),
            control_plane: LocalEngineControlPlane {
                runtime: LocalEngineRuntimeProfile {
                    mode: "local".to_string(),
                    endpoint: "http://127.0.0.1:11434/v1".to_string(),
                    default_model: "none".to_string(),
                    baseline_role: "operator".to_string(),
                    kernel_authority: "contained_local".to_string(),
                },
                storage: LocalEngineStorageConfig {
                    models_path: ".".to_string(),
                    backends_path: ".".to_string(),
                    artifacts_path: ".".to_string(),
                    cache_path: ".".to_string(),
                },
                watchdog: LocalEngineWatchdogConfig {
                    enabled: false,
                    idle_check_enabled: false,
                    idle_timeout: "0s".to_string(),
                    busy_check_enabled: false,
                    busy_timeout: "0s".to_string(),
                    check_interval: "0s".to_string(),
                    force_eviction_when_busy: false,
                    lru_eviction_max_retries: 0,
                    lru_eviction_retry_interval: "0s".to_string(),
                },
                memory: LocalEngineMemoryConfig {
                    reclaimer_enabled: false,
                    threshold_percent: 0,
                    prefer_gpu: false,
                    target_resource: "cpu".to_string(),
                },
                backend_policy: LocalEngineBackendPolicyConfig {
                    max_concurrency: 1,
                    max_queued_requests: 1,
                    parallel_backend_loads: 1,
                    allow_parallel_requests: false,
                    health_probe_interval: "0s".to_string(),
                    log_level: "info".to_string(),
                    auto_shutdown_on_idle: false,
                },
                responses: LocalEngineResponseConfig {
                    retain_receipts_days: 1,
                    persist_artifacts: false,
                    allow_streaming: false,
                    store_request_previews: false,
                },
                api: LocalEngineApiConfig {
                    bind_address: "127.0.0.1:0".to_string(),
                    remote_access_enabled: false,
                    expose_compat_routes: false,
                    cors_mode: "off".to_string(),
                    auth_mode: "none".to_string(),
                },
                launcher: Default::default(),
                galleries: Vec::new(),
                environment: Vec::new(),
                notes: Vec::new(),
            },
            managed_settings: crate::models::LocalEngineManagedSettingsSnapshot {
                sync_status: "local_only".to_string(),
                summary: "No managed settings active.".to_string(),
                ..Default::default()
            },
            staged_operations: Vec::new(),
        }
    }

    fn test_entry(entry_id: &str, label: &str) -> CapabilityRegistryEntry {
        CapabilityRegistryEntry {
            entry_id: entry_id.to_string(),
            kind: "extension".to_string(),
            label: label.to_string(),
            summary: format!("{label} summary"),
            source_kind: "tracked_source".to_string(),
            source_label: "Workspace source".to_string(),
            source_uri: Some("/workspace/plugin".to_string()),
            trust_posture: "contained_local".to_string(),
            governed_profile: Some("governed_extension".to_string()),
            availability: "ready".to_string(),
            status_label: "Ready".to_string(),
            why_selectable: format!("{label} is selectable in the runtime inventory."),
            governing_family_id: None,
            related_governing_entry_ids: Vec::new(),
            governing_family_hints: Vec::new(),
            runtime_target: Some("runtime_bridge".to_string()),
            lease_mode: Some("governed_extension".to_string()),
            authority: CapabilityAuthorityDescriptor {
                tier_id: "extension".to_string(),
                tier_label: "Governed extension".to_string(),
                governed_profile_id: Some("governed_extension".to_string()),
                governed_profile_label: Some("Governed extension".to_string()),
                summary: "summary".to_string(),
                detail: "detail".to_string(),
                signals: Vec::new(),
            },
            lease: CapabilityLeaseDescriptor {
                availability: "ready".to_string(),
                availability_label: "Ready".to_string(),
                runtime_target_id: Some("runtime_bridge".to_string()),
                runtime_target_label: Some("Runtime bridge".to_string()),
                mode_id: Some("governed_extension".to_string()),
                mode_label: Some("Governed extension".to_string()),
                summary: "summary".to_string(),
                detail: "detail".to_string(),
                requires_auth: false,
                signals: Vec::new(),
            },
        }
    }

    fn plugin_snapshot_fixture(
        manifest_path: &std::path::Path,
        plugin_root: &std::path::Path,
    ) -> CapabilityRegistrySnapshot {
        CapabilityRegistrySnapshot {
            generated_at_ms: 1,
            summary: CapabilityRegistrySummary {
                generated_at_ms: 1,
                total_entries: 1,
                connector_count: 0,
                connected_connector_count: 0,
                runtime_skill_count: 0,
                tracked_source_count: 1,
                filesystem_skill_count: 1,
                extension_count: 1,
                model_count: 0,
                backend_count: 0,
                native_family_count: 0,
                pending_engine_control_count: 0,
                active_issue_count: 0,
                authoritative_source_count: 1,
            },
            entries: vec![test_entry("extension:manifest:alpha", "Alpha Plugin")],
            connectors: Vec::new(),
            skill_catalog: Vec::new(),
            skill_sources: Vec::new(),
            extension_manifests: vec![ExtensionManifestRecord {
                extension_id: "manifest:alpha".to_string(),
                manifest_kind: "codex_plugin".to_string(),
                manifest_path: manifest_path.to_string_lossy().to_string(),
                root_path: plugin_root.to_string_lossy().to_string(),
                source_label: "Workspace source".to_string(),
                source_uri: plugin_root.to_string_lossy().to_string(),
                source_kind: "tracked_source".to_string(),
                enabled: true,
                name: "alpha-plugin".to_string(),
                display_name: Some("Alpha Plugin".to_string()),
                version: Some("1.0.0".to_string()),
                description: Some("Workspace plugin".to_string()),
                developer_name: None,
                author_name: None,
                author_email: None,
                author_url: None,
                category: Some("Automation".to_string()),
                trust_posture: "contained_local".to_string(),
                governed_profile: "governed_extension".to_string(),
                homepage: None,
                repository: None,
                license: None,
                keywords: Vec::new(),
                capabilities: vec!["hooks".to_string(), "runtime".to_string()],
                default_prompts: Vec::new(),
                contributions: vec![ExtensionContributionRecord {
                    kind: "hooks".to_string(),
                    label: "Hooks".to_string(),
                    path: Some("hooks/main.ts".to_string()),
                    item_count: Some(1),
                    detail: Some("Hook contribution".to_string()),
                }],
                filesystem_skills: vec![SkillSourceDiscoveredSkill {
                    name: "Skill".to_string(),
                    description: None,
                    relative_path: "skills/example/SKILL.md".to_string(),
                }],
                marketplace_name: None,
                marketplace_display_name: None,
                marketplace_category: None,
                marketplace_installation_policy: None,
                marketplace_authentication_policy: None,
                marketplace_products: Vec::new(),
                marketplace_available_version: None,
                marketplace_catalog_issued_at_ms: None,
                marketplace_catalog_expires_at_ms: None,
                marketplace_catalog_refreshed_at_ms: None,
                marketplace_catalog_refresh_source: None,
                marketplace_catalog_channel: None,
                marketplace_catalog_source_id: None,
                marketplace_catalog_source_label: None,
                marketplace_catalog_source_uri: None,
                marketplace_package_url: None,
                marketplace_catalog_refresh_bundle_id: None,
                marketplace_catalog_refresh_bundle_label: None,
                marketplace_catalog_refresh_bundle_issued_at_ms: None,
                marketplace_catalog_refresh_bundle_expires_at_ms: None,
                marketplace_catalog_refresh_available_version: None,
                marketplace_verification_status: None,
                marketplace_signature_algorithm: None,
                marketplace_signer_identity: None,
                marketplace_publisher_id: None,
                marketplace_signing_key_id: None,
                marketplace_publisher_label: None,
                marketplace_publisher_trust_status: None,
                marketplace_publisher_trust_source: None,
                marketplace_publisher_root_id: None,
                marketplace_publisher_root_label: None,
                marketplace_authority_bundle_id: None,
                marketplace_authority_bundle_label: None,
                marketplace_authority_bundle_issued_at_ms: None,
                marketplace_authority_trust_bundle_id: None,
                marketplace_authority_trust_bundle_label: None,
                marketplace_authority_trust_bundle_issued_at_ms: None,
                marketplace_authority_trust_bundle_expires_at_ms: None,
                marketplace_authority_trust_bundle_status: None,
                marketplace_authority_trust_issuer_id: None,
                marketplace_authority_trust_issuer_label: None,
                marketplace_authority_id: None,
                marketplace_authority_label: None,
                marketplace_publisher_statement_issued_at_ms: None,
                marketplace_publisher_trust_detail: None,
                marketplace_publisher_revoked_at_ms: None,
                marketplace_verification_error: None,
                marketplace_verified_at_ms: None,
                marketplace_verification_source: None,
                marketplace_verified_digest_sha256: None,
                marketplace_trust_score_label: None,
                marketplace_trust_score_source: None,
                marketplace_trust_recommendation: None,
            }],
            local_engine: empty_local_engine_snapshot(),
        }
    }

    fn write_test_plugin_manifest(
        root: &std::path::Path,
        name: &str,
        display_name: &str,
    ) -> std::path::PathBuf {
        let manifest_dir = root.join(".codex-plugin");
        std::fs::create_dir_all(&manifest_dir).expect("create plugin root");
        let manifest_path = manifest_dir.join("plugin.json");
        std::fs::write(
            &manifest_path,
            format!(
                r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "interface": {{
    "displayName": "{display_name}",
    "category": "Validation",
    "capabilities": ["Inspect", "Write"]
  }}
}}"#
            ),
        )
        .expect("write plugin manifest");
        std::fs::write(
            root.join("README.md"),
            format!("{display_name} packaged payload\n"),
        )
        .expect("write plugin readme");
        manifest_path
    }

    fn sign_plugin_package(root: &std::path::Path) -> (String, String, String) {
        let keypair = Ed25519KeyPair::generate().expect("generate ed25519 keypair");
        let digest_sha256 =
            compute_plugin_package_digest_sha256(root).expect("compute plugin package digest");
        let message = plugin_signature_message(&digest_sha256);
        let signature = keypair.sign(&message).expect("sign plugin package digest");
        (
            digest_sha256,
            hex::encode(keypair.public_key().to_bytes()),
            hex::encode(signature.to_bytes()),
        )
    }

    fn write_test_plugin_archive(source_root: &std::path::Path, archive_path: &std::path::Path) {
        let parent = archive_path.parent().expect("archive parent");
        std::fs::create_dir_all(parent).expect("create archive parent");
        let file = std::fs::File::create(archive_path).expect("create plugin archive");
        let mut writer = zip::ZipWriter::new(file);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut relative_files = Vec::new();
        collect_plugin_package_files(source_root, source_root, &mut relative_files)
            .expect("collect plugin package files");
        relative_files.sort_by(|left, right| slash_path(left).cmp(&slash_path(right)));
        for relative_path in relative_files {
            let absolute_path = source_root.join(&relative_path);
            let bytes = std::fs::read(&absolute_path).expect("read archive source file");
            writer
                .start_file(slash_path(&relative_path), options)
                .expect("start archive file");
            use std::io::Write as _;
            writer.write_all(&bytes).expect("write archive file");
        }
        writer.finish().expect("finish plugin archive");
    }

    struct TestStaticHttpServer {
        base_url: String,
        shutdown: Option<std::sync::mpsc::Sender<()>>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestStaticHttpServer {
        fn url(&self, relative_path: &str) -> String {
            format!(
                "{}/{}",
                self.base_url,
                relative_path.trim_start_matches('/')
            )
        }
    }

    impl Drop for TestStaticHttpServer {
        fn drop(&mut self) {
            if let Some(sender) = self.shutdown.take() {
                let _ = sender.send(());
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve_static_http_response(
        root: &std::path::Path,
        stream: &mut std::net::TcpStream,
    ) -> Result<(), String> {
        use std::io::{Read as _, Write as _};

        let mut buffer = [0u8; 8192];
        let bytes_read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read request: {}", error))?;
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        let request_line = request
            .lines()
            .next()
            .ok_or_else(|| "request missing first line".to_string())?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        if method != "GET" {
            let response =
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream
                .write_all(response.as_bytes())
                .map_err(|error| format!("write 405 response: {}", error))?;
            return Ok(());
        }
        let relative_path = path.trim_start_matches('/');
        let requested_path = std::path::Path::new(relative_path);
        if requested_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            let response =
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream
                .write_all(response.as_bytes())
                .map_err(|error| format!("write 400 response: {}", error))?;
            return Ok(());
        }
        let file_path = root.join(requested_path);
        if !file_path.exists() || !file_path.is_file() {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream
                .write_all(response.as_bytes())
                .map_err(|error| format!("write 404 response: {}", error))?;
            return Ok(());
        }
        let body = std::fs::read(&file_path)
            .map_err(|error| format!("read {}: {}", file_path.display(), error))?;
        let content_type = match file_path.extension().and_then(|value| value.to_str()) {
            Some("json") => "application/json",
            Some("zip") => "application/zip",
            _ => "application/octet-stream",
        };
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
            body.len(),
            content_type
        );
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .map_err(|error| format!("write response: {}", error))?;
        Ok(())
    }

    fn spawn_static_http_server(root: std::path::PathBuf) -> TestStaticHttpServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind static HTTP server");
        listener
            .set_nonblocking(true)
            .expect("set server nonblocking");
        let address = listener.local_addr().expect("read server address");
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = serve_static_http_response(&root, &mut stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        });
        TestStaticHttpServer {
            base_url: format!("http://{}", address),
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn rooted_publisher_fixture(
        root_id: &str,
        root_label: &str,
        root_status: Option<&str>,
        root_trust_source: &str,
        root_revoked_at_ms: Option<u64>,
        publisher_id: &str,
        publisher_label: &str,
        publisher_status: Option<&str>,
        publisher_trust_source: &str,
        publisher_revoked_at_ms: Option<u64>,
        signing_key_id: &str,
        signing_key_public_key: &str,
        signing_key_status: Option<&str>,
        signing_key_revoked_at_ms: Option<u64>,
        statement_issued_at_ms: u64,
    ) -> (PluginMarketplaceTrustRoot, PluginMarketplacePublisher) {
        let root_keypair = Ed25519KeyPair::generate().expect("generate marketplace root keypair");
        let mut publisher = PluginMarketplacePublisher {
            id: publisher_id.to_string(),
            label: Some(publisher_label.to_string()),
            trust_root_id: Some(root_id.to_string()),
            trust_status: publisher_status.map(str::to_string),
            trust_source: Some(publisher_trust_source.to_string()),
            revoked_at_ms: publisher_revoked_at_ms,
            statement_signature: None,
            statement_issued_at_ms: Some(statement_issued_at_ms),
            signing_keys: vec![PluginMarketplaceSigningKey {
                id: signing_key_id.to_string(),
                public_key: signing_key_public_key.to_string(),
                algorithm: Some("ed25519".to_string()),
                status: signing_key_status.map(str::to_string),
                revoked_at_ms: signing_key_revoked_at_ms,
            }],
        };
        let statement_message = plugin_publisher_statement_message(root_id, &publisher);
        let statement_signature = root_keypair
            .sign(&statement_message)
            .expect("sign marketplace root statement");
        publisher.statement_signature = Some(hex::encode(statement_signature.to_bytes()));

        (
            PluginMarketplaceTrustRoot {
                id: root_id.to_string(),
                label: Some(root_label.to_string()),
                public_key: hex::encode(root_keypair.public_key().to_bytes()),
                algorithm: Some("ed25519".to_string()),
                status: root_status.map(str::to_string),
                trust_source: Some(root_trust_source.to_string()),
                revoked_at_ms: root_revoked_at_ms,
            },
            publisher,
        )
    }

    fn authority_bundle_fixture(
        authority_id: &str,
        authority_label: &str,
        authority_status: Option<&str>,
        authority_trust_source: &str,
        bundle_id: &str,
        bundle_label: &str,
        roots: Vec<PluginMarketplaceTrustRoot>,
        publisher_revocations: Vec<PluginMarketplacePublisherRevocation>,
        issued_at_ms: u64,
    ) -> (
        PluginMarketplaceBundleAuthority,
        PluginMarketplaceAuthorityBundle,
    ) {
        let authority_keypair =
            Ed25519KeyPair::generate().expect("generate marketplace authority keypair");
        let mut bundle = PluginMarketplaceAuthorityBundle {
            id: bundle_id.to_string(),
            label: Some(bundle_label.to_string()),
            authority_id: authority_id.to_string(),
            issued_at_ms: Some(issued_at_ms),
            signature: None,
            signature_algorithm: Some("ed25519".to_string()),
            trust_source: Some("marketplace authority bundle verification".to_string()),
            roots,
            publisher_revocations,
        };
        let message = plugin_marketplace_authority_bundle_message(&bundle);
        let signature = authority_keypair
            .sign(&message)
            .expect("sign marketplace authority bundle");
        bundle.signature = Some(hex::encode(signature.to_bytes()));

        (
            PluginMarketplaceBundleAuthority {
                id: authority_id.to_string(),
                label: Some(authority_label.to_string()),
                public_key: hex::encode(authority_keypair.public_key().to_bytes()),
                algorithm: Some("ed25519".to_string()),
                status: authority_status.map(str::to_string),
                trust_source: Some(authority_trust_source.to_string()),
                revoked_at_ms: None,
            },
            bundle,
        )
    }

    fn authority_trust_bundle_fixture(
        root_id: &str,
        root_label: &str,
        root_status: Option<&str>,
        root_trust_source: &str,
        root_revoked_at_ms: Option<u64>,
        bundle_id: &str,
        bundle_label: &str,
        bundle_trust_source: &str,
        authorities: Vec<PluginMarketplaceBundleAuthority>,
        authority_revocations: Vec<PluginMarketplaceAuthorityRevocation>,
        issued_at_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> (
        PluginMarketplaceTrustRoot,
        PluginMarketplaceAuthorityTrustBundle,
    ) {
        let root_keypair =
            Ed25519KeyPair::generate().expect("generate authority trust root keypair");
        let mut bundle = PluginMarketplaceAuthorityTrustBundle {
            id: bundle_id.to_string(),
            label: Some(bundle_label.to_string()),
            issuer_id: root_id.to_string(),
            issuer_label: Some(root_label.to_string()),
            issued_at_ms: Some(issued_at_ms),
            expires_at_ms,
            signature: None,
            signature_algorithm: Some("ed25519".to_string()),
            trust_source: Some(bundle_trust_source.to_string()),
            authorities,
            authority_revocations,
        };
        let message = plugin_marketplace_authority_trust_bundle_message(&bundle);
        let signature = root_keypair
            .sign(&message)
            .expect("sign marketplace authority trust bundle");
        bundle.signature = Some(hex::encode(signature.to_bytes()));

        (
            PluginMarketplaceTrustRoot {
                id: root_id.to_string(),
                label: Some(root_label.to_string()),
                public_key: hex::encode(root_keypair.public_key().to_bytes()),
                algorithm: Some("ed25519".to_string()),
                status: root_status.map(str::to_string),
                trust_source: Some(root_trust_source.to_string()),
                revoked_at_ms: root_revoked_at_ms,
            },
            bundle,
        )
    }

    fn catalog_refresh_bundle_fixture(
        root_id: &str,
        root_label: &str,
        bundle_id: &str,
        bundle_label: &str,
        catalog_id: &str,
        refresh_source: &str,
        channel: &str,
        plugins: Vec<PluginMarketplaceCatalogEntry>,
        issued_at_ms: u64,
        refreshed_at_ms: u64,
        expires_at_ms: Option<u64>,
        tamper_signature: bool,
    ) -> (
        PluginMarketplaceTrustRoot,
        PluginMarketplaceCatalogRefreshBundle,
    ) {
        let root_keypair =
            Ed25519KeyPair::generate().expect("generate catalog refresh root keypair");
        let mut bundle = PluginMarketplaceCatalogRefreshBundle {
            id: bundle_id.to_string(),
            label: Some(bundle_label.to_string()),
            catalog_id: catalog_id.to_string(),
            issuer_id: root_id.to_string(),
            issuer_label: Some(root_label.to_string()),
            issued_at_ms: Some(issued_at_ms),
            expires_at_ms,
            refreshed_at_ms: Some(refreshed_at_ms),
            refresh_source: Some(refresh_source.to_string()),
            channel: Some(channel.to_string()),
            signature: None,
            signature_algorithm: Some("ed25519".to_string()),
            plugins,
        };
        let message = plugin_marketplace_catalog_refresh_bundle_message(&bundle);
        let signature = root_keypair
            .sign(&message)
            .expect("sign plugin catalog refresh bundle");
        let mut signature_hex = hex::encode(signature.to_bytes());
        if tamper_signature {
            let replacement = if signature_hex.ends_with('0') {
                '1'
            } else {
                '0'
            };
            signature_hex.pop();
            signature_hex.push(replacement);
        }
        bundle.signature = Some(signature_hex);

        (
            PluginMarketplaceTrustRoot {
                id: root_id.to_string(),
                label: Some(root_label.to_string()),
                public_key: hex::encode(root_keypair.public_key().to_bytes()),
                algorithm: Some("ed25519".to_string()),
                status: Some("active".to_string()),
                trust_source: Some("signed catalog refresh verification".to_string()),
                revoked_at_ms: None,
            },
            bundle,
        )
    }

    fn catalog_refresh_entry(
        manifest_path: &std::path::Path,
        display_name: &str,
        description: &str,
        available_version: &str,
        digest_sha256: &str,
        signature_public_key: &str,
        package_signature: &str,
        publisher_id: &str,
        signing_key_id: &str,
        publisher_label: &str,
        signer_identity: &str,
    ) -> PluginMarketplaceCatalogEntry {
        PluginMarketplaceCatalogEntry {
            manifest_path: slash_path(manifest_path),
            package_url: None,
            display_name: Some(display_name.to_string()),
            description: Some(description.to_string()),
            category: Some("Validation".to_string()),
            installation_policy: Some("managed_copy".to_string()),
            authentication_policy: Some("operator_trust".to_string()),
            products: vec!["Autopilot".to_string()],
            available_version: Some(available_version.to_string()),
            package_digest_sha256: Some(digest_sha256.to_string()),
            signature_algorithm: Some("ed25519".to_string()),
            signature_public_key: Some(signature_public_key.to_string()),
            package_signature: Some(package_signature.to_string()),
            verification_status: None,
            signer_identity: Some(signer_identity.to_string()),
            publisher_id: Some(publisher_id.to_string()),
            signing_key_id: Some(signing_key_id.to_string()),
            publisher_label: Some(publisher_label.to_string()),
            verification_error: None,
            verified_at_ms: None,
            trust_score_label: None,
            trust_score_source: None,
            trust_recommendation: None,
        }
    }

    #[test]
    fn session_plugin_snapshot_collects_manifest_inventory() {
        let temp_root =
            std::env::temp_dir().join(format!("autopilot-plugin-snapshot-{}", std::process::id()));
        let plugin_root = temp_root.join("plugin-alpha");
        std::fs::create_dir_all(plugin_root.join(".codex-plugin")).expect("create plugin root");
        let manifest_path = plugin_root.join(".codex-plugin/plugin.json");
        std::fs::write(&manifest_path, "{}").expect("write manifest");

        let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);

        let plugin_snapshot = build_session_plugin_snapshot(
            snapshot,
            PluginRuntimeState::default(),
            Some("session-123".to_string()),
            Some(temp_root.to_string_lossy().to_string()),
        );

        assert_eq!(plugin_snapshot.plugin_count, 1);
        assert_eq!(plugin_snapshot.enabled_plugin_count, 0);
        assert_eq!(plugin_snapshot.trusted_plugin_count, 0);
        assert_eq!(plugin_snapshot.blocked_plugin_count, 1);
        assert_eq!(plugin_snapshot.reloadable_plugin_count, 1);
        assert_eq!(plugin_snapshot.hook_contribution_count, 1);
        assert_eq!(plugin_snapshot.filesystem_skill_count, 1);
        assert_eq!(
            plugin_snapshot.plugins[0].authority_tier_label,
            "Governed extension"
        );
        assert_eq!(
            plugin_snapshot.plugins[0].session_scope_label,
            "Matches current workspace"
        );
        assert_eq!(
            plugin_snapshot.plugins[0].runtime_trust_state,
            "trust_required"
        );
        assert_eq!(
            plugin_snapshot.plugins[0].requested_capabilities,
            vec!["hooks".to_string(), "runtime".to_string()]
        );

        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn plugin_runtime_lifecycle_tracks_trust_reload_and_revocation() {
        let temp_root =
            std::env::temp_dir().join(format!("autopilot-plugin-runtime-{}", std::process::id()));
        let plugin_root = temp_root.join("plugin-alpha");
        std::fs::create_dir_all(plugin_root.join(".codex-plugin")).expect("create plugin root");
        let manifest_path = plugin_root.join(".codex-plugin/plugin.json");
        std::fs::write(&manifest_path, "{}").expect("write manifest");
        let runtime_path = temp_root.join("plugin_runtime_state.json");
        let manager = PluginRuntimeManager::new(runtime_path);
        let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);
        let manifest = snapshot.extension_manifests[0].clone();

        manager
            .trust_plugin(&manifest, true)
            .expect("trust plugin should persist");
        manager
            .reload_plugin(&manifest)
            .expect("trusted reload should succeed");
        manager
            .revoke_plugin_trust(&manifest)
            .expect("revoking trust should persist");
        manager
            .reload_plugin(&manifest)
            .expect("blocked reload should still persist receipts");

        let plugin_snapshot = build_session_plugin_snapshot(
            snapshot,
            manager.snapshot(),
            Some("session-123".to_string()),
            Some(temp_root.to_string_lossy().to_string()),
        );

        assert_eq!(plugin_snapshot.enabled_plugin_count, 0);
        assert_eq!(plugin_snapshot.trusted_plugin_count, 0);
        assert_eq!(plugin_snapshot.plugins[0].runtime_trust_state, "revoked");
        assert_eq!(plugin_snapshot.plugins[0].runtime_load_state, "blocked");
        assert!(plugin_snapshot.plugins[0].load_error.is_some());
        assert_eq!(plugin_snapshot.recent_receipts[0].action, "reload");
        assert_eq!(plugin_snapshot.recent_receipts[0].status, "blocked");
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "reload" && receipt.status == "matched"));
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "trust" && receipt.status == "recorded"));
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "revoke" && receipt.status == "revoked"));

        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn plugin_package_lifecycle_tracks_install_update_and_remove() {
        let temp_root =
            std::env::temp_dir().join(format!("autopilot-plugin-package-{}", std::process::id()));
        let plugin_root = temp_root.join("plugin-alpha");
        let manifest_dir = plugin_root.join(".codex-plugin");
        std::fs::create_dir_all(&manifest_dir).expect("create plugin root");
        let manifest_path = manifest_dir.join("plugin.json");
        std::fs::write(
            &manifest_path,
            r#"{
  "name": "alpha-plugin",
  "version": "1.0.0",
  "interface": {
    "displayName": "Alpha Plugin",
    "category": "Automation"
  }
}"#,
        )
        .expect("write manifest");
        std::fs::write(plugin_root.join("README.md"), "# Alpha").expect("write source file");

        let runtime_path = temp_root.join("plugin_runtime_state.json");
        let manager = PluginRuntimeManager::new(runtime_path);
        let snapshot = plugin_snapshot_fixture(&manifest_path, &plugin_root);
        let manifest = snapshot.extension_manifests[0].clone();

        manager
            .install_plugin_package(&manifest)
            .expect("package install should persist");
        manager
            .stage_plugin_update(&manifest, "1.1.0")
            .expect("staged update should persist");
        manager
            .update_plugin_package(&manifest)
            .expect("apply update should persist");

        let managed_root = managed_plugin_root_for(manager.path.as_ref(), &manifest.extension_id);
        let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
        assert!(managed_manifest.exists(), "managed manifest should exist");
        let managed_manifest_raw =
            std::fs::read_to_string(&managed_manifest).expect("read managed manifest");
        assert!(
            managed_manifest_raw.contains("\"version\": \"1.1.0\""),
            "managed package manifest should carry the updated version"
        );

        manager
            .remove_plugin_package(&manifest)
            .expect("remove package should persist");

        let plugin_snapshot = build_session_plugin_snapshot(
            snapshot,
            manager.snapshot(),
            Some("session-123".to_string()),
            Some(temp_root.to_string_lossy().to_string()),
        );

        assert_eq!(plugin_snapshot.managed_package_count, 0);
        assert_eq!(plugin_snapshot.update_available_count, 0);
        assert_eq!(plugin_snapshot.plugins[0].package_install_state, "removed");
        assert!(!plugin_snapshot.plugins[0].package_managed);
        assert_eq!(
            plugin_snapshot.recent_receipts[0].action, "remove",
            "latest receipt should describe package removal"
        );
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "install" && receipt.status == "applied"));
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "update_detected" && receipt.status == "available"));
        assert!(plugin_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "update" && receipt.status == "applied"));
        assert!(
            !managed_root.exists(),
            "managed package copy should be removed from disk"
        );

        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_feed_manifest_supports_catalog_install_and_update_signal() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-feed-{}",
            std::process::id()
        ));
        let plugin_root = temp_root.join("plugin-marketplace-alpha");
        let manifest_dir = plugin_root.join(".codex-plugin");
        std::fs::create_dir_all(&manifest_dir).expect("create plugin root");
        let manifest_path = manifest_dir.join("plugin.json");
        std::fs::write(
            &manifest_path,
            r#"{
  "name": "alpha-plugin",
  "version": "1.0.0",
  "interface": {
    "displayName": "Alpha Plugin",
    "category": "Automation",
    "capabilities": ["filesystem", "hooks"]
  }
}"#,
        )
        .expect("write manifest");
        std::fs::write(plugin_root.join("README.md"), "# Alpha").expect("write source file");

        let fixture_path = temp_root.join("plugin-marketplace-feed.json");
        std::fs::write(
            &fixture_path,
            format!(
                r#"{{
  "catalogs": [
    {{
      "id": "local-dev-marketplace",
      "label": "Local Dev Marketplace",
      "plugins": [
        {{
          "manifestPath": "{}",
          "installationPolicy": "managed_copy",
          "authenticationPolicy": "operator_trust",
          "products": ["plugin", "validation"],
          "availableVersion": "9.9.9"
        }}
      ]
    }}
  ]
}}"#,
                slash_path(&manifest_path)
            ),
        )
        .expect("write marketplace fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load marketplace manifests");
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0].marketplace_display_name.as_deref(),
            Some("Local Dev Marketplace")
        );
        assert_eq!(
            manifests[0].marketplace_available_version.as_deref(),
            Some("9.9.9")
        );

        let runtime_path = temp_root.join("plugin_runtime_state.json");
        let manager = PluginRuntimeManager::new(runtime_path);
        let initial_snapshot =
            build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
        assert_eq!(initial_snapshot.plugin_count, 1);
        assert_eq!(initial_snapshot.installable_package_count, 1);
        assert_eq!(
            initial_snapshot.plugins[0].available_version.as_deref(),
            Some("9.9.9")
        );
        assert_eq!(
            initial_snapshot.plugins[0].package_install_state,
            "installable"
        );

        manager
            .install_plugin_package(&manifests[0])
            .expect("catalog install should reuse managed package path");

        let installed_snapshot =
            build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
        assert!(installed_snapshot.plugins[0].package_managed);
        assert_eq!(
            installed_snapshot.plugins[0].installed_version.as_deref(),
            Some("1.0.0")
        );
        assert_eq!(
            installed_snapshot.plugins[0].available_version.as_deref(),
            Some("9.9.9")
        );
        assert!(installed_snapshot.plugins[0].update_available);
        assert_eq!(
            installed_snapshot.recent_receipts[0].action, "install",
            "catalog install should emit the existing managed-package install receipt"
        );

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_channel_precedence_prefers_health_before_channel_priority() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-channel-precedence-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let manifest_path = write_test_plugin_manifest(
            &temp_root.join("shared-plugin"),
            "shared-plugin",
            "Shared Channel Plugin",
        );
        let now_ms = state::now();
        let fixture_path = temp_root.join("plugin-marketplace-channel-precedence.json");
        let fixture = serde_json::json!({
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "channel": "stable",
                    "issuedAtMs": now_ms.saturating_sub(172_800_000),
                    "refreshedAtMs": now_ms.saturating_sub(172_800_000),
                    "expiresAtMs": now_ms.saturating_sub(60_000),
                    "plugins": [
                        {
                            "manifestPath": slash_path(&manifest_path),
                            "displayName": "Shared Channel Plugin",
                            "availableVersion": "9.9.9"
                        }
                    ]
                },
                {
                    "id": "community-release",
                    "label": "Community Release Catalog",
                    "channel": "community",
                    "issuedAtMs": now_ms.saturating_sub(60_000),
                    "refreshedAtMs": now_ms.saturating_sub(30_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "plugins": [
                        {
                            "manifestPath": slash_path(&manifest_path),
                            "displayName": "Shared Channel Plugin",
                            "availableVersion": "1.1.0"
                        }
                    ]
                }
            ]
        });
        std::fs::write(
            &fixture_path,
            serde_json::to_vec_pretty(&fixture).expect("encode channel precedence fixture"),
        )
        .expect("write channel precedence fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load channel precedence manifests");
        assert_eq!(
            manifests.len(),
            1,
            "duplicate plugin ids should collapse to one manifest"
        );
        assert_eq!(
            manifests[0].marketplace_catalog_channel.as_deref(),
            Some("community"),
            "a healthy lower-priority channel should win over an expired higher-priority channel"
        );
        assert_eq!(
            manifests[0].marketplace_display_name.as_deref(),
            Some("Community Release Catalog")
        );

        let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
            Some(&fixture_path),
        );
        let plugin = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Shared Channel Plugin")
            .expect("shared plugin present");
        assert_eq!(plugin.catalog_channel.as_deref(), Some("community"));
        assert_eq!(plugin.catalog_status, "active");
        assert_eq!(snapshot.catalog_channel_count, 2);
        assert!(snapshot
            .catalog_channels
            .iter()
            .any(|channel| channel.catalog_id == "stable-release" && channel.status == "expired"));
        assert!(snapshot.catalog_channels.iter().any(|channel| {
            channel.catalog_id == "community-release" && channel.status == "active"
        }));

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_nonconformant_channel_surfaces_without_breaking_valid_channels() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-nonconformant-channel-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let valid_manifest = write_test_plugin_manifest(
            &temp_root.join("valid-plugin"),
            "valid-plugin",
            "Valid Channel Plugin",
        );
        let fixture_path = temp_root.join("plugin-marketplace-nonconformant-channel.json");
        let fixture = serde_json::json!({
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "channel": "stable",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&valid_manifest),
                            "displayName": "Valid Channel Plugin",
                            "availableVersion": "1.0.0"
                        }
                    ]
                },
                {
                    "id": "security-release",
                    "label": "Security Release Catalog",
                    "channel": "security",
                    "plugins": [
                        {
                            "manifestPath": "",
                            "displayName": "Broken Channel Plugin",
                            "availableVersion": "9.9.9"
                        }
                    ]
                }
            ]
        });
        std::fs::write(
            &fixture_path,
            serde_json::to_vec_pretty(&fixture).expect("encode nonconformant channel fixture"),
        )
        .expect("write nonconformant channel fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load nonconformant channel manifests");
        assert_eq!(
            manifests.len(),
            1,
            "valid catalog entries should still load"
        );

        let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
            Some(&fixture_path),
        );
        assert_eq!(snapshot.plugin_count, 1);
        assert_eq!(snapshot.catalog_channel_count, 2);
        assert_eq!(snapshot.nonconformant_channel_count, 1);
        let nonconformant = snapshot
            .catalog_channels
            .iter()
            .find(|channel| channel.catalog_id == "security-release")
            .expect("nonconformant security channel present");
        assert_eq!(nonconformant.status, "nonconformant");
        assert_eq!(nonconformant.conformance_status, "nonconformant");
        assert_eq!(nonconformant.invalid_plugin_count, 1);
        assert!(nonconformant
            .conformance_error
            .as_deref()
            .is_some_and(|error| error.contains("manifestPath")));

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_distribution_prefers_healthy_source_and_surfaces_source_health() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-distribution-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let shared_manifest = write_test_plugin_manifest(
            &temp_root.join("shared-plugin"),
            "shared-plugin",
            "Shared Channel Plugin",
        );
        let now_ms = state::now();

        let stable_feed = temp_root.join("stable-feed.json");
        let community_feed = temp_root.join("community-feed.json");
        let security_feed = temp_root.join("security-feed.json");
        let distribution_path = temp_root.join("plugin-marketplace-distribution.json");

        std::fs::write(
            &stable_feed,
            serde_json::to_vec_pretty(&serde_json::json!({
                "catalogs": [
                    {
                        "id": "stable-release",
                        "label": "Stable Release Catalog",
                        "channel": "stable",
                        "issuedAtMs": now_ms.saturating_sub(172_800_000),
                        "refreshedAtMs": now_ms.saturating_sub(172_800_000),
                        "expiresAtMs": now_ms.saturating_sub(60_000),
                        "plugins": [
                            {
                                "manifestPath": slash_path(&shared_manifest),
                                "displayName": "Shared Channel Plugin",
                                "availableVersion": "9.9.9"
                            }
                        ]
                    }
                ]
            }))
            .expect("encode stable feed"),
        )
        .expect("write stable feed");
        std::fs::write(
            &community_feed,
            serde_json::to_vec_pretty(&serde_json::json!({
                "catalogs": [
                    {
                        "id": "community-release",
                        "label": "Community Release Catalog",
                        "channel": "community",
                        "issuedAtMs": now_ms.saturating_sub(60_000),
                        "refreshedAtMs": now_ms.saturating_sub(30_000),
                        "expiresAtMs": now_ms.saturating_add(86_400_000),
                        "plugins": [
                            {
                                "manifestPath": slash_path(&shared_manifest),
                                "displayName": "Shared Channel Plugin",
                                "availableVersion": "1.1.0"
                            }
                        ]
                    }
                ]
            }))
            .expect("encode community feed"),
        )
        .expect("write community feed");
        std::fs::write(
            &security_feed,
            serde_json::to_vec_pretty(&serde_json::json!({
                "catalogs": [
                    {
                        "id": "security-release",
                        "label": "Security Release Catalog",
                        "channel": "security",
                        "issuedAtMs": now_ms.saturating_sub(60_000),
                        "refreshedAtMs": now_ms.saturating_sub(30_000),
                        "expiresAtMs": now_ms.saturating_add(86_400_000),
                        "plugins": [
                            {
                                "manifestPath": "",
                                "displayName": "Broken Channel Plugin",
                                "availableVersion": "9.9.9"
                            }
                        ]
                    }
                ]
            }))
            .expect("encode security feed"),
        )
        .expect("write security feed");
        std::fs::write(
            &distribution_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "sources": [
                    {
                        "id": "stable-source",
                        "label": "Stable Channel Source",
                        "sourceUri": "fixture://stable-channel",
                        "fixturePath": "stable-feed.json",
                        "channel": "stable",
                        "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(172_800_000)
                    },
                    {
                        "id": "community-source",
                        "label": "Community Channel Source",
                        "sourceUri": "fixture://community-channel",
                        "fixturePath": "community-feed.json",
                        "channel": "community",
                        "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                    },
                    {
                        "id": "security-source",
                        "label": "Security Channel Source",
                        "sourceUri": "fixture://security-channel",
                        "fixturePath": "security-feed.json",
                        "channel": "security",
                        "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                    }
                ]
            }))
            .expect("encode distribution"),
        )
        .expect("write distribution");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
            .expect("load distribution manifests");
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0].marketplace_catalog_channel.as_deref(),
            Some("community")
        );
        assert_eq!(
            manifests[0].marketplace_catalog_source_id.as_deref(),
            Some("community-source")
        );
        assert_eq!(
            manifests[0].marketplace_catalog_source_label.as_deref(),
            Some("Community Channel Source")
        );
        assert_eq!(
            manifests[0].marketplace_catalog_source_uri.as_deref(),
            Some("fixture://community-channel")
        );

        let source_records =
            load_plugin_marketplace_feed_catalog_sources_from_path(&distribution_path)
                .expect("load distribution sources");
        assert_eq!(source_records.len(), 3);
        assert!(source_records
            .iter()
            .any(|source| { source.source_id == "stable-source" && source.status == "expired" }));
        assert!(source_records
            .iter()
            .any(|source| { source.source_id == "community-source" && source.status == "active" }));
        assert!(source_records.iter().any(|source| {
            source.source_id == "security-source"
                && source.status == "nonconformant"
                && source.conformance_status == "nonconformant"
        }));

        let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
            Some(&distribution_path),
        );
        assert_eq!(snapshot.plugin_count, 1);
        assert_eq!(snapshot.catalog_channel_count, 3);
        assert_eq!(snapshot.catalog_source_count, 3);
        assert_eq!(snapshot.failed_catalog_source_count, 0);
        assert_eq!(snapshot.nonconformant_source_count, 1);
        let plugin = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Shared Channel Plugin")
            .expect("shared plugin present");
        assert_eq!(plugin.catalog_channel.as_deref(), Some("community"));
        assert_eq!(
            plugin.catalog_source_label.as_deref(),
            Some("Community Channel Source")
        );
        assert_eq!(
            plugin.catalog_source_uri.as_deref(),
            Some("fixture://community-channel")
        );

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_distribution_source_failures_surface_without_hiding_valid_sources() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-distribution-failure-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let valid_manifest = write_test_plugin_manifest(
            &temp_root.join("valid-plugin"),
            "valid-plugin",
            "Valid Source Plugin",
        );
        let stable_feed = temp_root.join("stable-feed.json");
        let distribution_path = temp_root.join("plugin-marketplace-distribution-failure.json");

        std::fs::write(
            &stable_feed,
            serde_json::to_vec_pretty(&serde_json::json!({
                "catalogs": [
                    {
                        "id": "stable-release",
                        "label": "Stable Release Catalog",
                        "channel": "stable",
                        "plugins": [
                            {
                                "manifestPath": slash_path(&valid_manifest),
                                "displayName": "Valid Source Plugin",
                                "availableVersion": "1.0.0"
                            }
                        ]
                    }
                ]
            }))
            .expect("encode valid stable feed"),
        )
        .expect("write valid stable feed");
        std::fs::write(
            &distribution_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "sources": [
                    {
                        "id": "stable-source",
                        "label": "Stable Channel Source",
                        "sourceUri": "fixture://stable-channel",
                        "fixturePath": "stable-feed.json",
                        "channel": "stable"
                    },
                    {
                        "id": "missing-source",
                        "label": "Missing Security Source",
                        "sourceUri": "fixture://missing-security",
                        "fixturePath": "missing-security-feed.json",
                        "channel": "security"
                    }
                ]
            }))
            .expect("encode distribution failure fixture"),
        )
        .expect("write distribution failure fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
            .expect("load distribution manifests with one valid source");
        assert_eq!(manifests.len(), 1);

        let source_records =
            load_plugin_marketplace_feed_catalog_sources_from_path(&distribution_path)
                .expect("load distribution source records");
        assert_eq!(source_records.len(), 2);
        let missing = source_records
            .iter()
            .find(|source| source.source_id == "missing-source")
            .expect("missing source record present");
        assert_eq!(missing.status, "refresh_failed");
        assert!(missing
            .refresh_error
            .as_deref()
            .is_some_and(|error| error.contains("does not exist")));

        let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
            Some(&distribution_path),
        );
        assert_eq!(snapshot.plugin_count, 1);
        assert_eq!(snapshot.catalog_source_count, 2);
        assert_eq!(snapshot.failed_catalog_source_count, 1);

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_remote_distribution_supports_http_sources_and_remote_package_lifecycle() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-remote-distribution-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let plugin_root = temp_root.join("remote-plugin-source");
        let manifest_path =
            write_test_plugin_manifest(&plugin_root, "remote-plugin", "Remote Package Plugin");
        let (digest_sha256, signature_public_key, package_signature) =
            sign_plugin_package(&plugin_root);
        let server_root = temp_root.join("server-root");
        let remote_plugin_root = server_root.join("remote-plugin");
        copy_directory_contents(&plugin_root, &remote_plugin_root)
            .expect("copy remote plugin fixture");
        let archive_path = server_root.join("packages/remote-plugin.zip");
        write_test_plugin_archive(&plugin_root, &archive_path);

        let server = spawn_static_http_server(server_root.clone());
        let remote_manifest_url = server.url("remote-plugin/.codex-plugin/plugin.json");
        let remote_archive_url = server.url("packages/remote-plugin.zip");
        let remote_feed_url = server.url("feeds/remote-release.json");
        let now_ms = state::now();

        std::fs::create_dir_all(server_root.join("feeds")).expect("create feeds directory");
        std::fs::write(
            server_root.join("feeds/remote-release.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "catalogs": [
                    {
                        "id": "remote-release",
                        "label": "Remote Release Catalog",
                        "sourceUri": remote_feed_url,
                        "channel": "stable",
                        "issuedAtMs": now_ms.saturating_sub(60_000),
                        "refreshedAtMs": now_ms.saturating_sub(30_000),
                        "expiresAtMs": now_ms.saturating_add(86_400_000),
                        "plugins": [
                            {
                                "manifestPath": remote_manifest_url,
                                "packageUrl": remote_archive_url,
                                "displayName": "Remote Package Plugin",
                                "installationPolicy": "managed_copy",
                                "authenticationPolicy": "operator_trust",
                                "products": ["Autopilot"],
                                "availableVersion": "1.2.0",
                                "packageDigestSha256": digest_sha256,
                                "signatureAlgorithm": "ed25519",
                                "signaturePublicKey": signature_public_key,
                                "packageSignature": package_signature,
                                "publisherLabel": "Remote Publisher",
                                "signerIdentity": "remote-release-signing"
                            }
                        ]
                    }
                ]
            }))
            .expect("encode remote feed"),
        )
        .expect("write remote feed");

        let distribution_path = temp_root.join("plugin-marketplace-remote-distribution.json");
        std::fs::write(
            &distribution_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "sources": [
                    {
                        "id": "remote-source",
                        "label": "Remote Release Source",
                        "sourceUri": remote_feed_url,
                        "fixturePath": remote_feed_url,
                        "channel": "stable",
                        "lastSuccessfulRefreshAtMs": now_ms.saturating_sub(30_000)
                    }
                ]
            }))
            .expect("encode remote distribution"),
        )
        .expect("write remote distribution");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&distribution_path)
            .expect("load remote distribution manifests");
        assert_eq!(manifests.len(), 1);
        let manifest = manifests[0].clone();
        assert_eq!(manifest.manifest_path, remote_manifest_url);
        assert_eq!(
            manifest.marketplace_package_url.as_deref(),
            Some(remote_archive_url.as_str())
        );
        assert_eq!(
            manifest.marketplace_catalog_source_id.as_deref(),
            Some("remote-source")
        );

        let snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
            Some(&distribution_path),
        );
        assert_eq!(snapshot.catalog_source_count, 1);
        assert_eq!(snapshot.local_catalog_source_count, 0);
        assert_eq!(snapshot.remote_catalog_source_count, 1);
        let source = snapshot
            .catalog_sources
            .iter()
            .find(|source| source.source_id == "remote-source")
            .expect("remote source present");
        assert_eq!(source.transport_kind, "remote_url");
        let plugin = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Remote Package Plugin")
            .expect("remote plugin present");
        assert_eq!(plugin.authenticity_state, "verified");
        assert_eq!(
            plugin.marketplace_package_url.as_deref(),
            Some(remote_archive_url.as_str())
        );

        let runtime_path = temp_root.join("plugin_runtime_state.json");
        let manager = PluginRuntimeManager::new(runtime_path);
        manager
            .install_plugin_package(&manifest)
            .expect("install remote package archive");
        manager
            .stage_plugin_update(&manifest, "1.2.0")
            .expect("stage remote update");
        manager
            .update_plugin_package(&manifest)
            .expect("apply remote archive update");

        let managed_root = managed_plugin_root_for(manager.path.as_ref(), &manifest.extension_id);
        let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
        assert!(managed_manifest.exists(), "managed manifest should exist");
        let managed_manifest_raw =
            std::fs::read_to_string(&managed_manifest).expect("read managed manifest");
        assert!(
            managed_manifest_raw.contains("\"version\": \"1.2.0\""),
            "remote archive update should rewrite the installed version"
        );
        assert!(
            managed_root.join("README.md").exists(),
            "remote archive payload should be unpacked into the managed package root"
        );

        let installed_snapshot = build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            manager.snapshot(),
            None,
            None,
            Some(&distribution_path),
        );
        let installed_plugin = installed_snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Remote Package Plugin")
            .expect("installed remote plugin present");
        assert!(installed_plugin.package_managed);
        assert_eq!(
            installed_plugin.package_install_source.as_deref(),
            Some("marketplace_remote")
        );
        assert_eq!(installed_plugin.installed_version.as_deref(), Some("1.2.0"));

        drop(server);
        let _ = std::fs::remove_file(manifest_path);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_trust_scoring_and_catalog_refresh_states_flow_into_snapshot() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-scoring-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let recommended_manifest = write_test_plugin_manifest(
            &temp_root.join("recommended-plugin"),
            "recommended-plugin",
            "Recommended Plugin",
        );
        let unknown_manifest = write_test_plugin_manifest(
            &temp_root.join("unknown-plugin"),
            "unknown-plugin",
            "Unknown Root Plugin",
        );
        let stale_manifest = write_test_plugin_manifest(
            &temp_root.join("stale-plugin"),
            "stale-plugin",
            "Stale Feed Plugin",
        );
        let expired_manifest = write_test_plugin_manifest(
            &temp_root.join("expired-plugin"),
            "expired-plugin",
            "Expired Catalog Plugin",
        );

        let recommended_root =
            manifest_parent_root(&recommended_manifest).expect("recommended root");
        let unknown_root = manifest_parent_root(&unknown_manifest).expect("unknown root");
        let stale_root = manifest_parent_root(&stale_manifest).expect("stale root");
        let expired_root = manifest_parent_root(&expired_manifest).expect("expired root");

        let (recommended_digest, recommended_public_key, recommended_signature) =
            sign_plugin_package(&recommended_root);
        let (unknown_digest, unknown_public_key, unknown_signature) =
            sign_plugin_package(&unknown_root);
        let (stale_digest, stale_public_key, stale_signature) = sign_plugin_package(&stale_root);
        let (expired_digest, expired_public_key, expired_signature) =
            sign_plugin_package(&expired_root);

        let (recommended_marketplace_root, recommended_publisher) = rooted_publisher_fixture(
            "recommended-marketplace-root",
            "Recommended Marketplace Root",
            Some("active"),
            "trusted marketplace root store",
            None,
            "recommended-publisher",
            "IOI Labs",
            Some("trusted"),
            "marketplace publisher chain",
            None,
            "recommended-ed25519",
            &recommended_public_key,
            Some("active"),
            None,
            1775440000000,
        );
        let (_missing_marketplace_root, unknown_publisher) = rooted_publisher_fixture(
            "community-marketplace-root",
            "Community Marketplace Root",
            Some("active"),
            "community marketplace root store",
            None,
            "unknown-publisher",
            "Community Labs",
            Some("trusted"),
            "community marketplace chain",
            None,
            "unknown-ed25519",
            &unknown_public_key,
            Some("active"),
            None,
            1775440600000,
        );
        let (stale_marketplace_root, stale_publisher) = rooted_publisher_fixture(
            "stale-marketplace-root",
            "Stale Marketplace Root",
            Some("active"),
            "trusted marketplace root store",
            None,
            "stale-publisher",
            "Stale Labs",
            Some("trusted"),
            "marketplace publisher chain",
            None,
            "stale-ed25519",
            &stale_public_key,
            Some("active"),
            None,
            1775441200000,
        );
        let (expired_marketplace_root, expired_publisher) = rooted_publisher_fixture(
            "expired-marketplace-root",
            "Expired Marketplace Root",
            Some("active"),
            "trusted marketplace root store",
            None,
            "expired-publisher",
            "Expiry Labs",
            Some("trusted"),
            "marketplace publisher chain",
            None,
            "expired-ed25519",
            &expired_public_key,
            Some("active"),
            None,
            1775441800000,
        );

        let now_ms = state::now();
        let stale_refreshed_at_ms =
            now_ms.saturating_sub(MARKETPLACE_CATALOG_STALE_AFTER_MS + 60_000);
        let stale_issued_at_ms = stale_refreshed_at_ms.saturating_sub(3_600_000);

        let fixture_path = temp_root.join("plugin-marketplace-scoring.json");
        let (recommended_refresh_root, recommended_refresh_bundle) = catalog_refresh_bundle_fixture(
            "stable-refresh-root",
            "Stable Refresh Root",
            "stable-release-refresh-1",
            "Stable Release Refresh",
            "stable-release",
            "signed catalog refresh",
            "stable",
            vec![catalog_refresh_entry(
                &recommended_manifest,
                "Recommended Plugin",
                "Healthy rooted plugin with a signed catalog refresh ready to apply.",
                "1.1.0",
                &recommended_digest,
                &recommended_public_key,
                &recommended_signature,
                "recommended-publisher",
                "recommended-ed25519",
                "IOI Labs",
                "ioi-release-signing",
            )],
            now_ms.saturating_sub(30_000),
            now_ms.saturating_sub(10_000),
            Some(now_ms.saturating_add(86_400_000)),
            false,
        );
        let (stale_refresh_root, stale_refresh_bundle) = catalog_refresh_bundle_fixture(
            "stale-refresh-root",
            "Stale Refresh Root",
            "canary-release-refresh-1",
            "Canary Release Refresh",
            "canary-release",
            "signed catalog refresh",
            "canary",
            vec![catalog_refresh_entry(
                &stale_manifest,
                "Stale Feed Plugin",
                "Tampered refresh bundle to prove refresh failures surface in the snapshot.",
                "1.2.0",
                &stale_digest,
                &stale_public_key,
                &stale_signature,
                "stale-publisher",
                "stale-ed25519",
                "Stale Labs",
                "stale-release-signing",
            )],
            now_ms.saturating_sub(45_000),
            now_ms.saturating_sub(15_000),
            Some(now_ms.saturating_add(86_400_000)),
            true,
        );

        let fixture = serde_json::json!({
            "roots": [
                recommended_marketplace_root,
                stale_marketplace_root,
                expired_marketplace_root,
                recommended_refresh_root,
                stale_refresh_root
            ],
            "publishers": [
                recommended_publisher,
                unknown_publisher,
                stale_publisher,
                expired_publisher
            ],
            "catalogRefreshBundles": [
                recommended_refresh_bundle,
                stale_refresh_bundle
            ],
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "issuedAtMs": now_ms.saturating_sub(3_600_000),
                    "refreshedAtMs": now_ms.saturating_sub(60_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "refreshSource": "signed fixture refresh",
                    "channel": "stable",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&recommended_manifest),
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.0.0",
                            "packageDigestSha256": recommended_digest,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": recommended_public_key,
                            "packageSignature": recommended_signature,
                            "publisherId": "recommended-publisher",
                            "signingKeyId": "recommended-ed25519",
                            "publisherLabel": "IOI Labs",
                            "signerIdentity": "ioi-release-signing"
                        }
                    ]
                },
                {
                    "id": "community-release",
                    "label": "Community Release Catalog",
                    "issuedAtMs": now_ms.saturating_sub(3_600_000),
                    "refreshedAtMs": now_ms.saturating_sub(60_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "refreshSource": "community mirror",
                    "channel": "community",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&unknown_manifest),
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.0.0",
                            "packageDigestSha256": unknown_digest,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": unknown_public_key,
                            "packageSignature": unknown_signature,
                            "publisherId": "unknown-publisher",
                            "signingKeyId": "unknown-ed25519",
                            "publisherLabel": "Community Labs",
                            "signerIdentity": "community-release-signing"
                        }
                    ]
                },
                {
                    "id": "canary-release",
                    "label": "Canary Release Catalog",
                    "issuedAtMs": stale_issued_at_ms,
                    "refreshedAtMs": stale_refreshed_at_ms,
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "refreshSource": "background refresh",
                    "channel": "canary",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&stale_manifest),
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.1.0",
                            "packageDigestSha256": stale_digest,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": stale_public_key,
                            "packageSignature": stale_signature,
                            "publisherId": "stale-publisher",
                            "signingKeyId": "stale-ed25519",
                            "publisherLabel": "Stale Labs",
                            "signerIdentity": "stale-release-signing"
                        }
                    ]
                },
                {
                    "id": "security-release",
                    "label": "Security Release Catalog",
                    "issuedAtMs": now_ms.saturating_sub(172_800_000),
                    "refreshedAtMs": now_ms.saturating_sub(86_400_000),
                    "expiresAtMs": now_ms.saturating_sub(1_000),
                    "refreshSource": "security mirror",
                    "channel": "security",
                    "plugins": [
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
                            "publisherId": "expired-publisher",
                            "signingKeyId": "expired-ed25519",
                            "publisherLabel": "Expiry Labs",
                            "signerIdentity": "expiry-release-signing"
                        }
                    ]
                }
            ]
        });
        std::fs::write(
            &fixture_path,
            serde_json::to_vec_pretty(&fixture).expect("encode scoring marketplace fixture"),
        )
        .expect("write scoring marketplace fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load scoring marketplace manifests");
        let snapshot = build_session_plugin_snapshot_for_manifests(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
        );

        assert_eq!(snapshot.plugin_count, 4);
        assert_eq!(snapshot.recommended_plugin_count, 1);
        assert_eq!(snapshot.review_required_plugin_count, 2);
        assert_eq!(
            snapshot
                .plugins
                .iter()
                .filter(|plugin| plugin.operator_review_state == "blocked")
                .count(),
            1
        );
        assert_eq!(snapshot.stale_catalog_count, 1);
        assert_eq!(snapshot.expired_catalog_count, 1);
        assert_eq!(snapshot.critical_update_count, 2);
        assert_eq!(snapshot.refresh_available_count, 1);
        assert_eq!(snapshot.refresh_failed_count, 0);

        let recommended = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Recommended Plugin")
            .expect("recommended plugin present");
        assert_eq!(recommended.operator_review_state, "recommended");
        assert_eq!(recommended.operator_review_label, "Recommended");
        assert_eq!(recommended.catalog_status, "refresh_available");
        assert_eq!(recommended.catalog_status_label, "Refresh available");
        assert_eq!(recommended.catalog_channel.as_deref(), Some("stable"));
        assert_eq!(
            recommended.catalog_refresh_source.as_deref(),
            Some("signed fixture refresh")
        );
        assert_eq!(
            recommended.catalog_refresh_bundle_id.as_deref(),
            Some("stable-release-refresh-1")
        );
        assert_eq!(
            recommended.catalog_refresh_available_version.as_deref(),
            Some("1.1.0")
        );
        assert_eq!(recommended.update_severity, None);
        assert_eq!(recommended.publisher_trust_state.as_deref(), Some("rooted"));

        let unknown = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Unknown Root Plugin")
            .expect("unknown plugin present");
        assert_eq!(unknown.operator_review_state, "review_required");
        assert_eq!(unknown.operator_review_label, "Review required");
        assert_eq!(unknown.catalog_status, "active");
        assert_eq!(
            unknown.publisher_trust_state.as_deref(),
            Some("unknown_root")
        );
        assert_eq!(unknown.update_severity, None);
        assert!(!unknown.operator_review_reason.trim().is_empty());

        let stale = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Stale Feed Plugin")
            .expect("stale plugin present");
        assert_eq!(stale.catalog_status, "stale");
        assert_eq!(stale.catalog_status_label, "Catalog refresh stale");
        assert_eq!(stale.update_severity.as_deref(), Some("review_stale_feed"));
        assert_eq!(
            stale.update_severity_label.as_deref(),
            Some("Review stale feed")
        );
        assert_eq!(stale.operator_review_state, "review_required");
        assert!(stale
            .operator_review_reason
            .contains("catalog freshness window is stale"));

        let expired = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Expired Catalog Plugin")
            .expect("expired plugin present");
        assert_eq!(expired.catalog_status, "expired");
        assert_eq!(expired.catalog_status_label, "Catalog expired");
        assert_eq!(expired.update_severity.as_deref(), Some("blocked"));
        assert_eq!(
            expired.update_severity_label.as_deref(),
            Some("Blocked update channel")
        );
        assert_eq!(expired.operator_review_state, "blocked");
        assert!(expired
            .operator_review_reason
            .contains("catalog has expired"));

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn signed_catalog_refresh_runtime_flow_updates_snapshot_and_failures_surface() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-refresh-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        let recommended_manifest = write_test_plugin_manifest(
            &temp_root.join("recommended-plugin"),
            "recommended-plugin",
            "Recommended Plugin",
        );
        let stale_manifest = write_test_plugin_manifest(
            &temp_root.join("stale-plugin"),
            "stale-plugin",
            "Stale Feed Plugin",
        );

        let recommended_root =
            manifest_parent_root(&recommended_manifest).expect("recommended root");
        let stale_root = manifest_parent_root(&stale_manifest).expect("stale root");

        let (recommended_digest, recommended_public_key, recommended_signature) =
            sign_plugin_package(&recommended_root);
        let (stale_digest, stale_public_key, stale_signature) = sign_plugin_package(&stale_root);

        let (recommended_marketplace_root, recommended_publisher) = rooted_publisher_fixture(
            "recommended-marketplace-root",
            "Recommended Marketplace Root",
            Some("active"),
            "trusted marketplace root store",
            None,
            "recommended-publisher",
            "IOI Labs",
            Some("trusted"),
            "marketplace publisher chain",
            None,
            "recommended-ed25519",
            &recommended_public_key,
            Some("active"),
            None,
            1775440000000,
        );
        let (stale_marketplace_root, stale_publisher) = rooted_publisher_fixture(
            "stale-marketplace-root",
            "Stale Marketplace Root",
            Some("active"),
            "trusted marketplace root store",
            None,
            "stale-publisher",
            "Stale Labs",
            Some("trusted"),
            "marketplace publisher chain",
            None,
            "stale-ed25519",
            &stale_public_key,
            Some("active"),
            None,
            1775441200000,
        );

        let now_ms = state::now();
        let stale_refreshed_at_ms =
            now_ms.saturating_sub(MARKETPLACE_CATALOG_STALE_AFTER_MS + 60_000);
        let stale_issued_at_ms = stale_refreshed_at_ms.saturating_sub(3_600_000);
        let (recommended_refresh_root, recommended_refresh_bundle) = catalog_refresh_bundle_fixture(
            "stable-refresh-root",
            "Stable Refresh Root",
            "stable-release-refresh-1",
            "Stable Release Refresh",
            "stable-release",
            "signed catalog refresh",
            "stable",
            vec![catalog_refresh_entry(
                &recommended_manifest,
                "Recommended Plugin",
                "Healthy rooted plugin with a signed refresh.",
                "1.1.0",
                &recommended_digest,
                &recommended_public_key,
                &recommended_signature,
                "recommended-publisher",
                "recommended-ed25519",
                "IOI Labs",
                "ioi-release-signing",
            )],
            now_ms.saturating_sub(30_000),
            now_ms.saturating_sub(10_000),
            Some(now_ms.saturating_add(86_400_000)),
            false,
        );
        let (stale_refresh_root, stale_refresh_bundle) = catalog_refresh_bundle_fixture(
            "stale-refresh-root",
            "Stale Refresh Root",
            "canary-release-refresh-1",
            "Canary Release Refresh",
            "canary-release",
            "signed catalog refresh",
            "canary",
            vec![catalog_refresh_entry(
                &stale_manifest,
                "Stale Feed Plugin",
                "Tampered refresh bundle.",
                "1.2.0",
                &stale_digest,
                &stale_public_key,
                &stale_signature,
                "stale-publisher",
                "stale-ed25519",
                "Stale Labs",
                "stale-release-signing",
            )],
            now_ms.saturating_sub(45_000),
            now_ms.saturating_sub(15_000),
            Some(now_ms.saturating_add(86_400_000)),
            true,
        );

        let fixture_path = temp_root.join("plugin-marketplace-refresh.json");
        let fixture = serde_json::json!({
            "roots": [
                recommended_marketplace_root,
                stale_marketplace_root,
                recommended_refresh_root,
                stale_refresh_root
            ],
            "publishers": [
                recommended_publisher,
                stale_publisher
            ],
            "catalogRefreshBundles": [
                recommended_refresh_bundle,
                stale_refresh_bundle
            ],
            "catalogs": [
                {
                    "id": "stable-release",
                    "label": "Stable Release Catalog",
                    "issuedAtMs": now_ms.saturating_sub(3_600_000),
                    "refreshedAtMs": now_ms.saturating_sub(60_000),
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "refreshSource": "signed fixture refresh",
                    "channel": "stable",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&recommended_manifest),
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.0.0",
                            "packageDigestSha256": recommended_digest,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": recommended_public_key,
                            "packageSignature": recommended_signature,
                            "publisherId": "recommended-publisher",
                            "signingKeyId": "recommended-ed25519",
                            "publisherLabel": "IOI Labs",
                            "signerIdentity": "ioi-release-signing"
                        }
                    ]
                },
                {
                    "id": "canary-release",
                    "label": "Canary Release Catalog",
                    "issuedAtMs": stale_issued_at_ms,
                    "refreshedAtMs": stale_refreshed_at_ms,
                    "expiresAtMs": now_ms.saturating_add(86_400_000),
                    "refreshSource": "background refresh",
                    "channel": "canary",
                    "plugins": [
                        {
                            "manifestPath": slash_path(&stale_manifest),
                            "installationPolicy": "managed_copy",
                            "authenticationPolicy": "operator_trust",
                            "products": ["Autopilot"],
                            "availableVersion": "1.1.0",
                            "packageDigestSha256": stale_digest,
                            "signatureAlgorithm": "ed25519",
                            "signaturePublicKey": stale_public_key,
                            "packageSignature": stale_signature,
                            "publisherId": "stale-publisher",
                            "signingKeyId": "stale-ed25519",
                            "publisherLabel": "Stale Labs",
                            "signerIdentity": "stale-release-signing"
                        }
                    ]
                }
            ]
        });
        std::fs::write(
            &fixture_path,
            serde_json::to_vec_pretty(&fixture).expect("encode refresh marketplace fixture"),
        )
        .expect("write refresh marketplace fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load refresh marketplace manifests");
        let runtime_path = temp_root.join("plugin_runtime_state.json");
        let manager = PluginRuntimeManager::new(runtime_path);

        let initial_snapshot =
            build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
        assert_eq!(initial_snapshot.refresh_available_count, 1);
        assert_eq!(initial_snapshot.refresh_failed_count, 0);
        let initial_recommended = initial_snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Recommended Plugin")
            .expect("recommended plugin present");
        assert_eq!(initial_recommended.catalog_status, "refresh_available");
        assert_eq!(
            initial_recommended
                .catalog_refresh_available_version
                .as_deref(),
            Some("1.1.0")
        );
        assert!(!initial_recommended.update_available);

        let recommended_manifest = manifests
            .iter()
            .find(|manifest| manifest.display_name.as_deref() == Some("Recommended Plugin"))
            .expect("recommended manifest present");
        let stale_manifest = manifests
            .iter()
            .find(|manifest| manifest.display_name.as_deref() == Some("Stale Feed Plugin"))
            .expect("stale manifest present");

        let recommended_target = load_plugin_marketplace_catalog_refresh_target_from_path(
            &fixture_path,
            &recommended_manifest.extension_id,
        );
        manager
            .refresh_plugin_catalog(recommended_manifest, recommended_target)
            .expect("apply recommended refresh");

        let refreshed_snapshot =
            build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
        let refreshed_recommended = refreshed_snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Recommended Plugin")
            .expect("recommended plugin present after refresh");
        assert_eq!(refreshed_recommended.catalog_status, "active");
        assert_eq!(refreshed_recommended.catalog_status_label, "Catalog fresh");
        assert_eq!(
            refreshed_recommended.available_version.as_deref(),
            Some("1.1.0")
        );
        assert!(!refreshed_recommended.update_available);
        assert_eq!(
            refreshed_recommended.update_severity.as_deref(),
            Some("recommended")
        );
        assert_eq!(refreshed_snapshot.refresh_available_count, 0);
        assert!(refreshed_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "catalog_refresh" && receipt.status == "applied"));

        let stale_target = load_plugin_marketplace_catalog_refresh_target_from_path(
            &fixture_path,
            &stale_manifest.extension_id,
        );
        manager
            .refresh_plugin_catalog(stale_manifest, stale_target)
            .expect("stale refresh failure should still persist a snapshot");

        let failed_snapshot =
            build_session_plugin_snapshot_for_manifests(&manifests, manager.snapshot(), None, None);
        let failed_stale = failed_snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Stale Feed Plugin")
            .expect("stale plugin present after failed refresh");
        assert_eq!(failed_stale.catalog_status, "refresh_failed");
        assert_eq!(failed_stale.catalog_status_label, "Refresh failed");
        assert_eq!(
            failed_stale.update_severity.as_deref(),
            Some("review_refresh_failure")
        );
        assert_eq!(failed_stale.operator_review_state, "review_required");
        assert!(failed_stale.catalog_refresh_error.is_some());
        assert_eq!(failed_snapshot.refresh_failed_count, 1);
        assert!(failed_snapshot
            .recent_receipts
            .iter()
            .any(|receipt| receipt.action == "catalog_refresh" && receipt.status == "failed"));

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn marketplace_feed_signature_verification_flows_into_snapshot() {
        let temp_root = std::env::temp_dir().join(format!(
            "autopilot-plugin-marketplace-verification-{}",
            std::process::id()
        ));
        let verified_manifest = write_test_plugin_manifest(
            &temp_root.join("verified-plugin"),
            "verified-plugin",
            "Verified Plugin",
        );
        let unverified_manifest = write_test_plugin_manifest(
            &temp_root.join("unverified-plugin"),
            "unverified-plugin",
            "Unverified Plugin",
        );
        let mismatch_manifest = write_test_plugin_manifest(
            &temp_root.join("mismatch-plugin"),
            "mismatch-plugin",
            "Mismatch Plugin",
        );
        let verified_root = manifest_parent_root(&verified_manifest).expect("verified root");
        let unsigned_root = manifest_parent_root(&unverified_manifest).expect("unsigned root");
        let mismatch_root = manifest_parent_root(&mismatch_manifest).expect("mismatch root");
        let (verified_digest, verified_public_key, verified_signature) =
            sign_plugin_package(&verified_root);
        let (mismatch_digest, mismatch_public_key, mismatch_signature) =
            sign_plugin_package(&mismatch_root);
        std::fs::write(
            mismatch_root.join("README.md"),
            "Mismatch Plugin tampered payload\n",
        )
        .expect("tamper mismatch plugin payload");
        let unsigned_digest =
            compute_plugin_package_digest_sha256(&unsigned_root).expect("compute unsigned digest");

        let fixture_path = temp_root.join("plugin-marketplace-verification.json");
        std::fs::write(
            &fixture_path,
            format!(
                r#"{{
  "publishers": [
    {{
      "id": "ioi-labs",
      "label": "IOI Labs",
      "trustStatus": "trusted",
      "trustSource": "local test registry",
      "signingKeys": [
        {{
          "id": "ioi-release-key",
          "algorithm": "ed25519",
          "publicKey": "{verified_public_key}",
          "status": "active"
        }}
      ]
    }}
  ],
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
          "packageDigestSha256": "{verified_digest}",
          "signatureAlgorithm": "ed25519",
          "signaturePublicKey": "{verified_public_key}",
          "packageSignature": "{verified_signature}",
          "publisherId": "ioi-labs",
          "signingKeyId": "ioi-release-key",
          "publisherLabel": "IOI Labs",
          "signerIdentity": "ioi-release-signing",
          "verifiedAtMs": 1775419000000
        }},
        {{
          "manifestPath": "{}",
          "installationPolicy": "managed_copy",
          "authenticationPolicy": "operator_trust",
          "products": ["Autopilot"],
          "availableVersion": "2.0.0",
          "packageDigestSha256": "{unsigned_digest}",
          "publisherLabel": "Community Labs"
        }},
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
          "publisherLabel": "Unknown Publisher",
          "signerIdentity": "tampered-signer"
        }}
      ]
    }}
  ]
}}"#,
                slash_path(&verified_manifest),
                slash_path(&unverified_manifest),
                slash_path(&mismatch_manifest)
            ),
        )
        .expect("write verification marketplace fixture");

        let manifests = load_plugin_marketplace_feed_manifests_from_path(&fixture_path)
            .expect("load verification marketplace manifests");
        let snapshot = build_session_plugin_snapshot_for_manifests(
            &manifests,
            PluginRuntimeState::default(),
            None,
            None,
        );

        assert_eq!(snapshot.plugin_count, 3);
        assert_eq!(snapshot.verified_plugin_count, 1);
        assert_eq!(snapshot.unverified_plugin_count, 1);
        assert_eq!(snapshot.signature_mismatch_plugin_count, 1);

        let verified = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Verified Plugin")
            .expect("verified plugin present");
        assert_eq!(verified.authenticity_state, "verified");
        assert_eq!(verified.authenticity_label, "Signature verified");
        assert_eq!(verified.verification_algorithm.as_deref(), Some("ed25519"));
        assert_eq!(verified.publisher_label.as_deref(), Some("IOI Labs"));
        assert_eq!(
            verified.signer_identity.as_deref(),
            Some("ioi-release-signing")
        );
        assert_eq!(verified.verification_timestamp_ms, Some(1775419000000));
        assert_eq!(
            verified.verification_source.as_deref(),
            Some("runtime signature verification")
        );
        assert_eq!(verified.publisher_id.as_deref(), Some("ioi-labs"));
        assert_eq!(verified.signing_key_id.as_deref(), Some("ioi-release-key"));
        assert_eq!(verified.publisher_trust_state.as_deref(), Some("trusted"));
        assert_eq!(
            verified.publisher_trust_label.as_deref(),
            Some("Trusted publisher")
        );
        assert_eq!(
            verified.verified_digest_sha256.as_deref(),
            Some(verified_digest.as_str())
        );
        assert_eq!(
            verified.trust_score_label.as_deref(),
            Some("High confidence")
        );

        let unverified = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Unverified Plugin")
            .expect("unverified plugin present");
        assert_eq!(unverified.authenticity_state, "unsigned");
        assert_eq!(unverified.authenticity_label, "Unsigned package");
        assert_eq!(
            unverified.verification_source.as_deref(),
            Some("runtime package digest")
        );
        assert_eq!(
            unverified.verified_digest_sha256.as_deref(),
            Some(unsigned_digest.as_str())
        );
        assert_eq!(
            unverified.trust_recommendation.as_deref(),
            Some("Review the publisher, signer, and requested capabilities before granting trust.")
        );

        let mismatch = snapshot
            .plugins
            .iter()
            .find(|plugin| plugin.label == "Mismatch Plugin")
            .expect("mismatch plugin present");
        let tampered_mismatch_digest = compute_plugin_package_digest_sha256(&mismatch_root)
            .expect("compute tampered mismatch digest");
        let expected_mismatch_error = format!(
            "Computed package digest sha256:{} did not match the published digest sha256:{}.",
            tampered_mismatch_digest, mismatch_digest
        );
        assert_eq!(mismatch.authenticity_state, "signature_mismatch");
        assert_eq!(mismatch.verification_algorithm.as_deref(), Some("ed25519"));
        assert_eq!(
            mismatch.verification_error.as_deref(),
            Some(expected_mismatch_error.as_str())
        );
        assert_eq!(mismatch.trust_score_label.as_deref(), Some("Blocked"));

        let _ = std::fs::remove_dir_all(temp_root);
    }

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
            serde_json::to_vec_pretty(&fixture)
                .expect("encode publisher chain marketplace fixture"),
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
        let (rooted_digest, rooted_public_key, rooted_signature) =
            sign_plugin_package(&rooted_root);
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
            serde_json::to_vec_pretty(&fixture)
                .expect("encode authority bundle marketplace fixture"),
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
        let unknown_root =
            manifest_parent_root(&unknown_manifest).expect("unknown distributed root");
        let expired_root =
            manifest_parent_root(&expired_manifest).expect("expired distributed root");
        let (rooted_digest, rooted_public_key, rooted_signature) =
            sign_plugin_package(&rooted_root);
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
}
