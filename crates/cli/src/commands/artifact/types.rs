use ioi_api::studio::{
    StudioArtifactBrief, StudioArtifactCandidateSummary, StudioArtifactEditIntent,
    StudioArtifactOutputOrigin, StudioArtifactTasteMemory, StudioArtifactUxLifecycle,
    StudioGeneratedArtifactFile,
};
use ioi_types::app::{
    StudioArtifactFailure, StudioArtifactManifest, StudioOutcomePlanningPayload,
    StudioRendererKind, StudioRuntimeProvenance,
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
    pub(crate) production_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) failure: Option<StudioArtifactFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ComposedVerifiedReply {
    pub(crate) status: String,
    pub(crate) lifecycle_state: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) production_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) failure: Option<StudioArtifactFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeneratedArtifactEvidence {
    pub(crate) prompt: String,
    pub(crate) title: String,
    pub(crate) route: StudioOutcomePlanningPayload,
    #[serde(default)]
    pub(crate) artifact_brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub(crate) edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub(crate) candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    #[serde(default)]
    pub(crate) winning_candidate_id: Option<String>,
    #[serde(default)]
    pub(crate) winning_candidate_rationale: Option<String>,
    #[serde(default)]
    pub(crate) judge: Option<ioi_api::studio::StudioArtifactJudgeResult>,
    #[serde(default)]
    pub(crate) output_origin: Option<StudioArtifactOutputOrigin>,
    #[serde(default)]
    pub(crate) production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub(crate) acceptance_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) fallback_used: bool,
    #[serde(default)]
    pub(crate) ux_lifecycle: Option<StudioArtifactUxLifecycle>,
    #[serde(default)]
    pub(crate) failure: Option<StudioArtifactFailure>,
    pub(crate) manifest: StudioArtifactManifest,
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
    pub(crate) renderer: StudioRendererKind,
    pub(crate) files: Vec<StudioGeneratedArtifactFile>,
    pub(crate) selected_targets: Vec<ioi_api::studio::StudioArtifactSelectionTarget>,
    pub(crate) taste_memory: Option<StudioArtifactTasteMemory>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ArtifactCommandErrorEnvelope {
    pub(crate) error: StudioArtifactFailure,
    pub(crate) production_provenance: Option<StudioRuntimeProvenance>,
    pub(crate) acceptance_provenance: Option<StudioRuntimeProvenance>,
}
