use crate::kernel::connectors::{ConnectorCatalogEntry, ShieldPolicyState};
use serde::{Deserialize, Serialize};

use super::knowledge::{ExtensionManifestRecord, SkillCatalogEntry, SkillSourceRecord};
use super::local_engine::LocalEngineSnapshot;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAuthorityDescriptor {
    pub tier_id: String,
    pub tier_label: String,
    #[serde(default)]
    pub governed_profile_id: Option<String>,
    #[serde(default)]
    pub governed_profile_label: Option<String>,
    pub summary: String,
    pub detail: String,
    #[serde(default)]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityLeaseDescriptor {
    pub availability: String,
    pub availability_label: String,
    #[serde(default)]
    pub runtime_target_id: Option<String>,
    #[serde(default)]
    pub runtime_target_label: Option<String>,
    #[serde(default)]
    pub mode_id: Option<String>,
    #[serde(default)]
    pub mode_label: Option<String>,
    pub summary: String,
    pub detail: String,
    #[serde(default)]
    pub requires_auth: bool,
    #[serde(default)]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistryEntry {
    pub entry_id: String,
    pub kind: String,
    pub label: String,
    pub summary: String,
    pub source_kind: String,
    pub source_label: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    pub trust_posture: String,
    #[serde(default)]
    pub governed_profile: Option<String>,
    pub availability: String,
    pub status_label: String,
    pub why_selectable: String,
    #[serde(default)]
    pub governing_family_id: Option<String>,
    #[serde(default)]
    pub related_governing_entry_ids: Vec<String>,
    #[serde(default)]
    pub governing_family_hints: Vec<String>,
    #[serde(default)]
    pub runtime_target: Option<String>,
    #[serde(default)]
    pub lease_mode: Option<String>,
    pub authority: CapabilityAuthorityDescriptor,
    pub lease: CapabilityLeaseDescriptor,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistrySummary {
    pub generated_at_ms: u64,
    pub total_entries: usize,
    pub connector_count: usize,
    pub connected_connector_count: usize,
    pub runtime_skill_count: usize,
    pub tracked_source_count: usize,
    pub filesystem_skill_count: usize,
    pub extension_count: usize,
    pub model_count: usize,
    pub backend_count: usize,
    pub native_family_count: usize,
    pub pending_engine_control_count: usize,
    pub active_issue_count: usize,
    pub authoritative_source_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistrySnapshot {
    pub generated_at_ms: u64,
    pub summary: CapabilityRegistrySummary,
    pub entries: Vec<CapabilityRegistryEntry>,
    pub connectors: Vec<ConnectorCatalogEntry>,
    pub skill_catalog: Vec<SkillCatalogEntry>,
    pub skill_sources: Vec<SkillSourceRecord>,
    pub extension_manifests: Vec<ExtensionManifestRecord>,
    pub local_engine: LocalEngineSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGovernanceRequestAction {
    Widen,
    Baseline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceRequest {
    pub request_id: String,
    pub created_at_ms: u64,
    pub status: String,
    pub action: CapabilityGovernanceRequestAction,
    pub capability_entry_id: String,
    pub capability_label: String,
    pub capability_kind: String,
    #[serde(default)]
    pub governing_entry_id: Option<String>,
    #[serde(default)]
    pub governing_label: Option<String>,
    #[serde(default)]
    pub governing_kind: Option<String>,
    pub connector_id: String,
    pub connector_label: String,
    pub source_label: String,
    pub authority_tier_label: String,
    #[serde(default)]
    pub governed_profile_label: Option<String>,
    #[serde(default)]
    pub lease_mode_label: Option<String>,
    pub why_selectable: String,
    pub headline: String,
    pub detail: String,
    pub requested_state: ShieldPolicyState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceTargetOption {
    pub target_entry_id: String,
    pub target_label: String,
    pub target_kind: String,
    pub target_summary: String,
    pub recommendation_reason: String,
    pub delta_summary: String,
    pub request: CapabilityGovernanceRequest,
    #[serde(default)]
    pub delta_magnitude: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceProposal {
    pub capability_entry_id: String,
    pub capability_label: String,
    pub action: CapabilityGovernanceRequestAction,
    pub recommended_target_entry_id: String,
    pub targets: Vec<CapabilityGovernanceTargetOption>,
    #[serde(default)]
    pub compared_entry_id: Option<String>,
    #[serde(default)]
    pub compared_entry_label: Option<String>,
}
