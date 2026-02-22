use super::*;

#[derive(Debug, Clone)]
pub(crate) struct CitationCandidate {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) source_label: String,
    pub(crate) excerpt: String,
    pub(crate) timestamp_utc: String,
    pub(crate) note: String,
    pub(crate) from_successful_read: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InsightFeatureVector {
    pub(crate) relevance: i32,
    pub(crate) reliability: i32,
    pub(crate) recency: i32,
    pub(crate) independence: i32,
    pub(crate) risk: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InsightPolicyFlags {
    pub(crate) search_hub: bool,
    pub(crate) low_priority_coverage: bool,
    pub(crate) low_signal_excerpt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WeightedInsight {
    pub(crate) id: String,
    pub(crate) claim: String,
    pub(crate) source_url: String,
    pub(crate) source_label: String,
    pub(crate) support_excerpt: String,
    pub(crate) features: InsightFeatureVector,
    pub(crate) policy_flags: InsightPolicyFlags,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InsightHardPolicyGates {
    pub(crate) require_primary_status: bool,
    pub(crate) require_constraint_resolution: bool,
    pub(crate) reject_search_hub: bool,
    pub(crate) reject_low_priority_coverage: bool,
    pub(crate) reject_low_signal_excerpt: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct StoryDraft {
    pub(crate) title: String,
    pub(crate) what_happened: String,
    pub(crate) changed_last_hour: String,
    pub(crate) why_it_matters: String,
    pub(crate) user_impact: String,
    pub(crate) workaround: String,
    pub(crate) eta_confidence: String,
    pub(crate) citation_ids: Vec<String>,
    pub(crate) confidence: String,
    pub(crate) caveat: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SynthesisDraft {
    pub(crate) query: String,
    pub(crate) run_date: String,
    pub(crate) run_timestamp_ms: u64,
    pub(crate) run_timestamp_iso_utc: String,
    pub(crate) completion_reason: String,
    pub(crate) overall_confidence: String,
    pub(crate) overall_caveat: String,
    pub(crate) stories: Vec<StoryDraft>,
    pub(crate) citations_by_id: BTreeMap<String, CitationCandidate>,
    pub(crate) blocked_urls: Vec<String>,
    pub(crate) partial_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridSynthesisPayload {
    pub(crate) query: String,
    pub(crate) run_timestamp_ms: u64,
    pub(crate) run_timestamp_iso_utc: String,
    pub(crate) completion_reason: String,
    pub(crate) required_sections: Vec<HybridSectionSpec>,
    pub(crate) citation_candidates: Vec<HybridCitationCandidate>,
    pub(crate) deterministic_story_drafts: Vec<HybridStoryDraft>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HybridSectionSpec {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) required: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridCitationCandidate {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) source_label: String,
    pub(crate) excerpt: String,
    pub(crate) timestamp_utc: String,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridStoryDraft {
    pub(crate) title: String,
    pub(crate) sections: Vec<HybridSectionDraft>,
    pub(crate) citation_ids: Vec<String>,
    pub(crate) confidence: String,
    pub(crate) caveat: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HybridSectionDraft {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HybridSynthesisResponse {
    #[serde(default)]
    pub(crate) heading: String,
    pub(crate) items: Vec<HybridItemResponse>,
    #[serde(default)]
    pub(crate) overall_confidence: String,
    #[serde(default)]
    pub(crate) overall_caveat: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HybridItemResponse {
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) sections: Vec<HybridSectionResponse>,
    #[serde(default)]
    pub(crate) citation_ids: Vec<String>,
    #[serde(default)]
    pub(crate) confidence: String,
    #[serde(default)]
    pub(crate) caveat: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HybridSectionResponse {
    #[serde(default)]
    pub(crate) key: String,
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) content: String,
}
