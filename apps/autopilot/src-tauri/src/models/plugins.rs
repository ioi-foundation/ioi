use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginLifecycleReceipt {
    pub receipt_id: String,
    pub timestamp_ms: u64,
    pub plugin_id: String,
    pub plugin_label: String,
    pub action: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginRecord {
    pub plugin_id: String,
    #[serde(default)]
    pub entry_id: Option<String>,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub source_enabled: bool,
    pub enabled: bool,
    pub status_label: String,
    pub source_label: String,
    pub source_kind: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub marketplace_display_name: Option<String>,
    #[serde(default)]
    pub marketplace_installation_policy: Option<String>,
    #[serde(default)]
    pub marketplace_authentication_policy: Option<String>,
    #[serde(default)]
    pub marketplace_products: Vec<String>,
    pub authenticity_state: String,
    pub authenticity_label: String,
    pub authenticity_detail: String,
    #[serde(default)]
    pub verification_error: Option<String>,
    #[serde(default)]
    pub verification_algorithm: Option<String>,
    #[serde(default)]
    pub publisher_label: Option<String>,
    #[serde(default)]
    pub publisher_id: Option<String>,
    #[serde(default)]
    pub signer_identity: Option<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub verification_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub verification_source: Option<String>,
    #[serde(default)]
    pub verified_digest_sha256: Option<String>,
    #[serde(default)]
    pub publisher_trust_state: Option<String>,
    #[serde(default)]
    pub publisher_trust_label: Option<String>,
    #[serde(default)]
    pub publisher_trust_detail: Option<String>,
    #[serde(default)]
    pub publisher_trust_source: Option<String>,
    #[serde(default)]
    pub publisher_root_id: Option<String>,
    #[serde(default)]
    pub publisher_root_label: Option<String>,
    #[serde(default)]
    pub authority_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_bundle_label: Option<String>,
    #[serde(default)]
    pub authority_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_trust_bundle_label: Option<String>,
    #[serde(default)]
    pub authority_trust_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_status: Option<String>,
    #[serde(default)]
    pub authority_trust_issuer_id: Option<String>,
    #[serde(default)]
    pub authority_trust_issuer_label: Option<String>,
    #[serde(default)]
    pub authority_id: Option<String>,
    #[serde(default)]
    pub authority_label: Option<String>,
    #[serde(default)]
    pub publisher_statement_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub publisher_revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub trust_score_label: Option<String>,
    #[serde(default)]
    pub trust_score_source: Option<String>,
    #[serde(default)]
    pub trust_recommendation: Option<String>,
    pub operator_review_state: String,
    pub operator_review_label: String,
    pub operator_review_reason: String,
    pub catalog_status: String,
    pub catalog_status_label: String,
    pub catalog_status_detail: String,
    #[serde(default)]
    pub catalog_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_source: Option<String>,
    #[serde(default)]
    pub catalog_channel: Option<String>,
    #[serde(default)]
    pub catalog_source_id: Option<String>,
    #[serde(default)]
    pub catalog_source_label: Option<String>,
    #[serde(default)]
    pub catalog_source_uri: Option<String>,
    #[serde(default)]
    pub marketplace_package_url: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_id: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_label: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_available_version: Option<String>,
    #[serde(default)]
    pub catalog_refresh_error: Option<String>,
    #[serde(default)]
    pub last_catalog_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub update_severity: Option<String>,
    #[serde(default)]
    pub update_severity_label: Option<String>,
    #[serde(default)]
    pub update_detail: Option<String>,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    pub trust_posture: String,
    pub governed_profile: String,
    pub authority_tier_label: String,
    pub availability_label: String,
    pub session_scope_label: String,
    #[serde(default)]
    pub reloadable: bool,
    pub reloadability_label: String,
    #[serde(default)]
    pub contribution_count: usize,
    #[serde(default)]
    pub hook_contribution_count: usize,
    #[serde(default)]
    pub filesystem_skill_count: usize,
    #[serde(default)]
    pub capability_count: usize,
    pub runtime_trust_state: String,
    pub runtime_trust_label: String,
    pub runtime_load_state: String,
    pub runtime_load_label: String,
    pub runtime_status_detail: String,
    #[serde(default)]
    pub load_error: Option<String>,
    #[serde(default)]
    pub last_trusted_at_ms: Option<u64>,
    #[serde(default)]
    pub last_reloaded_at_ms: Option<u64>,
    #[serde(default)]
    pub last_installed_at_ms: Option<u64>,
    #[serde(default)]
    pub last_updated_at_ms: Option<u64>,
    #[serde(default)]
    pub last_removed_at_ms: Option<u64>,
    #[serde(default)]
    pub trust_remembered: bool,
    #[serde(default)]
    pub package_managed: bool,
    pub package_install_state: String,
    pub package_install_label: String,
    pub package_install_detail: String,
    #[serde(default)]
    pub package_install_source: Option<String>,
    #[serde(default)]
    pub package_install_source_label: Option<String>,
    #[serde(default)]
    pub package_root_path: Option<String>,
    #[serde(default)]
    pub package_manifest_path: Option<String>,
    #[serde(default)]
    pub installed_version: Option<String>,
    #[serde(default)]
    pub available_version: Option<String>,
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub package_error: Option<String>,
    pub why_available: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginCatalogChannelRecord {
    pub catalog_id: String,
    pub label: String,
    pub source_uri: String,
    #[serde(default)]
    pub refresh_source: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    pub status: String,
    pub status_label: String,
    pub status_detail: String,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub plugin_count: usize,
    #[serde(default)]
    pub valid_plugin_count: usize,
    #[serde(default)]
    pub invalid_plugin_count: usize,
    #[serde(default)]
    pub refresh_bundle_count: usize,
    #[serde(default)]
    pub refresh_error: Option<String>,
    pub conformance_status: String,
    pub conformance_label: String,
    #[serde(default)]
    pub conformance_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginCatalogSourceRecord {
    pub source_id: String,
    pub label: String,
    pub source_uri: String,
    pub transport_kind: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub authority_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_bundle_label: Option<String>,
    pub status: String,
    pub status_label: String,
    pub status_detail: String,
    #[serde(default)]
    pub last_successful_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub last_failed_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub refresh_error: Option<String>,
    pub conformance_status: String,
    pub conformance_label: String,
    #[serde(default)]
    pub conformance_error: Option<String>,
    #[serde(default)]
    pub catalog_count: usize,
    #[serde(default)]
    pub valid_catalog_count: usize,
    #[serde(default)]
    pub invalid_catalog_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub plugin_count: usize,
    #[serde(default)]
    pub enabled_plugin_count: usize,
    #[serde(default)]
    pub disabled_plugin_count: usize,
    #[serde(default)]
    pub trusted_plugin_count: usize,
    #[serde(default)]
    pub untrusted_plugin_count: usize,
    #[serde(default)]
    pub blocked_plugin_count: usize,
    #[serde(default)]
    pub reloadable_plugin_count: usize,
    #[serde(default)]
    pub managed_package_count: usize,
    #[serde(default)]
    pub update_available_count: usize,
    #[serde(default)]
    pub installable_package_count: usize,
    #[serde(default)]
    pub verified_plugin_count: usize,
    #[serde(default)]
    pub unverified_plugin_count: usize,
    #[serde(default)]
    pub signature_mismatch_plugin_count: usize,
    #[serde(default)]
    pub recommended_plugin_count: usize,
    #[serde(default)]
    pub review_required_plugin_count: usize,
    #[serde(default)]
    pub stale_catalog_count: usize,
    #[serde(default)]
    pub expired_catalog_count: usize,
    #[serde(default)]
    pub critical_update_count: usize,
    #[serde(default)]
    pub refresh_available_count: usize,
    #[serde(default)]
    pub refresh_failed_count: usize,
    #[serde(default)]
    pub catalog_channel_count: usize,
    #[serde(default)]
    pub nonconformant_channel_count: usize,
    #[serde(default)]
    pub catalog_source_count: usize,
    #[serde(default)]
    pub local_catalog_source_count: usize,
    #[serde(default)]
    pub remote_catalog_source_count: usize,
    #[serde(default)]
    pub failed_catalog_source_count: usize,
    #[serde(default)]
    pub nonconformant_source_count: usize,
    #[serde(default)]
    pub hook_contribution_count: usize,
    #[serde(default)]
    pub filesystem_skill_count: usize,
    #[serde(default)]
    pub recent_receipt_count: usize,
    #[serde(default)]
    pub recent_receipts: Vec<SessionPluginLifecycleReceipt>,
    #[serde(default)]
    pub catalog_sources: Vec<SessionPluginCatalogSourceRecord>,
    #[serde(default)]
    pub catalog_channels: Vec<SessionPluginCatalogChannelRecord>,
    #[serde(default)]
    pub plugins: Vec<SessionPluginRecord>,
}
