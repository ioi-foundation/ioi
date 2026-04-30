use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use super::knowledge::ActiveContextItem;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ContextConstraint {
    pub id: String,
    pub label: String,
    pub value: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub summary: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub emphasis: Option<f32>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub weight: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasNeighborhood {
    pub lens: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub focus_id: Option<String>,
    #[serde(default)]
    pub nodes: Vec<AtlasNode>,
    #[serde(default)]
    pub edges: Vec<AtlasEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMacroStepView {
    pub index: u32,
    pub tool_name: String,
    pub target: String,
    pub params_json: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillBenchmarkView {
    pub sample_size: u32,
    pub success_rate_bps: u32,
    pub intervention_rate_bps: u32,
    pub policy_incident_rate_bps: u32,
    pub avg_cost: u64,
    pub avg_latency_ms: u64,
    pub passed: bool,
    pub last_evaluated_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDetailView {
    pub skill_hash: String,
    pub name: String,
    pub description: String,
    pub lifecycle_state: String,
    pub source_type: String,
    pub archival_record_id: i64,
    pub success_rate_bps: u32,
    pub sample_size: u32,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub source_registry_id: Option<String>,
    #[serde(default)]
    pub source_registry_label: Option<String>,
    #[serde(default)]
    pub source_registry_uri: Option<String>,
    #[serde(default)]
    pub source_registry_kind: Option<String>,
    #[serde(default)]
    pub source_registry_sync_status: Option<String>,
    #[serde(default)]
    pub source_registry_relative_path: Option<String>,
    pub stale: bool,
    #[serde(default)]
    pub used_tools: Vec<String>,
    #[serde(default)]
    pub steps: Vec<SkillMacroStepView>,
    #[serde(default)]
    pub benchmark: SkillBenchmarkView,
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub neighborhood: AtlasNeighborhood,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubstrateProofReceipt {
    pub event_id: String,
    pub timestamp: String,
    pub step_index: u32,
    pub tool_name: String,
    pub query_hash: String,
    pub index_root: String,
    pub k: u32,
    pub ef_search: u32,
    pub candidate_limit: u32,
    pub candidate_total: u32,
    pub candidate_reranked: u32,
    pub candidate_truncated: bool,
    pub distance_metric: String,
    pub embedding_normalized: bool,
    #[serde(default)]
    pub proof_hash: Option<String>,
    #[serde(default)]
    pub proof_ref: Option<String>,
    #[serde(default)]
    pub certificate_mode: Option<String>,
    pub success: bool,
    #[serde(default)]
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubstrateProofView {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub skill_hash: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub index_roots: Vec<String>,
    #[serde(default)]
    pub receipts: Vec<SubstrateProofReceipt>,
    #[serde(default)]
    pub neighborhood: AtlasNeighborhood,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ActiveContextSnapshot {
    pub session_id: String,
    pub goal: String,
    pub status: String,
    pub mode: String,
    pub current_tier: String,
    #[serde(default)]
    pub focus_id: String,
    #[serde(default)]
    pub active_skill_id: Option<String>,
    #[serde(default)]
    pub skills: Vec<ActiveContextItem>,
    #[serde(default)]
    pub tools: Vec<ActiveContextItem>,
    #[serde(default)]
    pub evidence: Vec<ActiveContextItem>,
    #[serde(default)]
    pub constraints: Vec<ContextConstraint>,
    #[serde(default)]
    pub recent_actions: Vec<String>,
    pub neighborhood: AtlasNeighborhood,
    #[serde(default)]
    pub substrate: Option<SubstrateProofView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasSearchResult {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub score: f32,
    pub lens: String,
}
