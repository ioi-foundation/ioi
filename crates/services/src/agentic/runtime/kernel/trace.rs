use serde::{Deserialize, Serialize};

use super::intervention::EvidenceTier;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSpanRef {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionTraceBundle {
    pub session_id: String,
    pub root_trace_id: String,
    #[serde(default)]
    pub projection_event_refs: Vec<String>,
    #[serde(default)]
    pub projection_receipts: Vec<String>,
    pub evidence_tier: EvidenceTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementTraceBundle {
    pub session_id: String,
    pub root_trace_id: String,
    #[serde(default)]
    pub spans: Vec<TraceSpanRef>,
    #[serde(default)]
    pub settlement_receipt_refs: Vec<[u8; 32]>,
    #[serde(default)]
    pub projection_event_refs: Vec<String>,
    #[serde(default)]
    pub missing_settlement_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub approval_refs: Vec<[u8; 32]>,
    #[serde(default)]
    pub evidence_tiers: Vec<EvidenceTier>,
}

impl SettlementTraceBundle {
    pub fn is_settlement_backed(&self) -> bool {
        !self.settlement_receipt_refs.is_empty() && self.missing_settlement_refs.is_empty()
    }
}
