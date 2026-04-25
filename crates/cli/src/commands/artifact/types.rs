use ioi_api::chat::{
    ChatAdaptiveSearchBudget, ChatArtifactBlueprint, ChatArtifactBrief,
    ChatArtifactCandidateSummary, ChatArtifactEditIntent, ChatArtifactIR, ChatArtifactOutputOrigin,
    ChatArtifactRenderEvaluation, ChatArtifactRuntimePolicy, ChatArtifactSelectedSkill,
    ChatArtifactTasteMemory, ChatArtifactUxLifecycle, ChatGeneratedArtifactFile,
};
use ioi_types::app::{
    ChatArtifactFailure, ChatArtifactManifest, ChatOutcomePlanningPayload, ChatRendererKind,
    ChatRuntimeProvenance,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ArtifactInspection {
    pub(crate) artifact_id: String,
    pub(crate) title: String,
    pub(crate) artifact_class: String,
    pub(crate) renderer: String,
    pub(crate) verification_status: String,
    pub(crate) lifecycle_state: String,
    pub(crate) verification_summary: String,
    pub(crate) primary_tab: String,
    pub(crate) tab_count: usize,
    pub(crate) file_count: usize,
    pub(crate) renderable_file_count: usize,
    pub(crate) downloadable_file_count: usize,
    pub(crate) repo_centric_package: bool,
    pub(crate) render_surface_available: bool,
    pub(crate) preferred_stage_mode: String,
    pub(crate) production_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) failure: Option<ChatArtifactFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ComposedVerifiedReply {
    pub(crate) status: String,
    pub(crate) lifecycle_state: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) production_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) failure: Option<ChatArtifactFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactLaneReceipt {
    pub(crate) receipt_id: String,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    #[serde(default)]
    pub(crate) details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeneratedArtifactEvidence {
    pub(crate) prompt: String,
    pub(crate) title: String,
    pub(crate) route: ChatOutcomePlanningPayload,
    #[serde(default)]
    pub(crate) artifact_brief: Option<ChatArtifactBrief>,
    #[serde(default)]
    pub(crate) blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub(crate) artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub(crate) selected_skills: Vec<ChatArtifactSelectedSkill>,
    #[serde(default)]
    pub(crate) edit_intent: Option<ChatArtifactEditIntent>,
    #[serde(default)]
    pub(crate) candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    #[serde(default)]
    pub(crate) winning_candidate_id: Option<String>,
    #[serde(default)]
    pub(crate) winning_candidate_rationale: Option<String>,
    #[serde(default)]
    pub(crate) render_evaluation: Option<ChatArtifactRenderEvaluation>,
    #[serde(default)]
    pub(crate) validation: Option<ioi_api::chat::ChatArtifactValidationResult>,
    #[serde(default)]
    pub(crate) output_origin: Option<ChatArtifactOutputOrigin>,
    #[serde(default)]
    pub(crate) runtime_policy: Option<ChatArtifactRuntimePolicy>,
    #[serde(default)]
    pub(crate) adaptive_search_budget: Option<ChatAdaptiveSearchBudget>,
    #[serde(default)]
    pub(crate) artifact_lane_receipts: Vec<ArtifactLaneReceipt>,
    #[serde(default)]
    pub(crate) production_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub(crate) acceptance_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) fallback_used: bool,
    #[serde(default)]
    pub(crate) ux_lifecycle: Option<ChatArtifactUxLifecycle>,
    #[serde(default)]
    pub(crate) failure: Option<ChatArtifactFailure>,
    pub(crate) manifest: ChatArtifactManifest,
    pub(crate) verified_reply: ComposedVerifiedReply,
    pub(crate) materialized_files: Vec<String>,
    pub(crate) renderable_files: Vec<String>,
    #[serde(default)]
    pub(crate) refinement: Option<LoadedRefinementEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoadedRefinementEvidence {
    pub(crate) artifact_id: Option<String>,
    pub(crate) revision_id: Option<String>,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) renderer: ChatRendererKind,
    pub(crate) files: Vec<ChatGeneratedArtifactFile>,
    pub(crate) selected_targets: Vec<ioi_api::chat::ChatArtifactSelectionTarget>,
    pub(crate) taste_memory: Option<ChatArtifactTasteMemory>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactCommandErrorEnvelope {
    pub(crate) error: ChatArtifactFailure,
    pub(crate) production_provenance: Option<ChatRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<ChatRuntimeProvenance>,
}
