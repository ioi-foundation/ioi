use ioi_types::app::agentic::LlmToolDefinition;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SkillCatalogEntry {
    pub skill_hash: String,
    pub name: String,
    pub description: String,
    pub lifecycle_state: String,
    pub source_type: String,
    pub success_rate_bps: u32,
    pub sample_size: u32,
    pub archival_record_id: i64,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    pub stale: bool,
    #[ts(type = "{ name: string; description: string; parameters: string }")]
    pub definition: LlmToolDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionSourceRecord {
    pub source_id: String,
    pub kind: String,
    pub uri: String,
    #[serde(default)]
    pub poll_interval_minutes: Option<u64>,
    pub enabled: bool,
    pub sync_status: String,
    #[serde(default)]
    pub last_synced_at_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionEntryRecord {
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub scope: String,
    pub artifact_id: String,
    pub byte_count: usize,
    pub chunk_count: usize,
    #[serde(default)]
    pub archival_record_ids: Vec<i64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub content_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionRecord {
    pub collection_id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub active: bool,
    #[serde(default)]
    pub entries: Vec<KnowledgeCollectionEntryRecord>,
    #[serde(default)]
    pub sources: Vec<KnowledgeCollectionSourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionEntryContent {
    pub collection_id: String,
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub artifact_id: String,
    pub byte_count: usize,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionSearchHit {
    pub collection_id: String,
    pub entry_id: String,
    pub title: String,
    pub scope: String,
    pub score: f32,
    pub lexical_score: f32,
    #[serde(default)]
    pub semantic_score: Option<f32>,
    pub trust_level: String,
    pub snippet: String,
    pub archival_record_id: i64,
    #[serde(default)]
    pub inspect_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ActiveContextItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub badge: Option<String>,
    #[serde(default)]
    pub secondary_badge: Option<String>,
    #[serde(default)]
    pub success_rate_bps: Option<u32>,
    #[serde(default)]
    pub sample_size: Option<u32>,
    #[serde(default)]
    pub focus_id: Option<String>,
    #[serde(default)]
    pub skill_hash: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub stale: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SkillSourceDiscoveredSkill {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SkillSourceRecord {
    pub source_id: String,
    pub label: String,
    pub uri: String,
    pub kind: String,
    pub enabled: bool,
    pub sync_status: String,
    #[serde(default)]
    pub last_synced_at_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub discovered_skills: Vec<SkillSourceDiscoveredSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionContributionRecord {
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub item_count: Option<u32>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionManifestRecord {
    pub extension_id: String,
    pub manifest_kind: String,
    pub manifest_path: String,
    pub root_path: String,
    pub source_label: String,
    pub source_uri: String,
    pub source_kind: String,
    pub enabled: bool,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub developer_name: Option<String>,
    #[serde(default)]
    pub author_name: Option<String>,
    #[serde(default)]
    pub author_email: Option<String>,
    #[serde(default)]
    pub author_url: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    pub trust_posture: String,
    pub governed_profile: String,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub default_prompts: Vec<String>,
    #[serde(default)]
    pub contributions: Vec<ExtensionContributionRecord>,
    #[serde(default)]
    pub filesystem_skills: Vec<SkillSourceDiscoveredSkill>,
    #[serde(default)]
    pub marketplace_name: Option<String>,
    #[serde(default)]
    pub marketplace_display_name: Option<String>,
    #[serde(default)]
    pub marketplace_category: Option<String>,
    #[serde(default)]
    pub marketplace_installation_policy: Option<String>,
    #[serde(default)]
    pub marketplace_authentication_policy: Option<String>,
    #[serde(default)]
    pub marketplace_products: Vec<String>,
    #[serde(default)]
    pub marketplace_available_version: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_source: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_channel: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_id: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_label: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_uri: Option<String>,
    #[serde(default)]
    pub marketplace_package_url: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_available_version: Option<String>,
    #[serde(default)]
    pub marketplace_verification_status: Option<String>,
    #[serde(default)]
    pub marketplace_signature_algorithm: Option<String>,
    #[serde(default)]
    pub marketplace_signer_identity: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_id: Option<String>,
    #[serde(default)]
    pub marketplace_signing_key_id: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_label: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_trust_status: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_trust_source: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_root_id: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_root_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_status: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_issuer_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_issuer_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_label: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_statement_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_publisher_trust_detail: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_verification_error: Option<String>,
    #[serde(default)]
    pub marketplace_verified_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_verification_source: Option<String>,
    #[serde(default)]
    pub marketplace_verified_digest_sha256: Option<String>,
    #[serde(default)]
    pub marketplace_trust_score_label: Option<String>,
    #[serde(default)]
    pub marketplace_trust_score_source: Option<String>,
    #[serde(default)]
    pub marketplace_trust_recommendation: Option<String>,
}
