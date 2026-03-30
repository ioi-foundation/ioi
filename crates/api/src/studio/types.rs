use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioGeneratedArtifactEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioGeneratedArtifactFile {
    pub path: String,
    pub mime: String,
    pub role: StudioArtifactFileRole,
    pub renderable: bool,
    pub downloadable: bool,
    #[serde(default)]
    pub encoding: Option<StudioGeneratedArtifactEncoding>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioGeneratedArtifactPayload {
    pub summary: String,
    #[serde(default)]
    pub notes: Vec<String>,
    pub files: Vec<StudioGeneratedArtifactFile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactEditMode {
    Create,
    Patch,
    Replace,
    Branch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactJudgeClassification {
    Pass,
    Repairable,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactOutputOrigin {
    LiveInference,
    MockInference,
    DeterministicFallback,
    FixtureRuntime,
    InferenceUnavailable,
    OpaqueRuntime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactUxLifecycle {
    Draft,
    Refining,
    Judged,
    Locked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSelectionTarget {
    pub source_surface: String,
    #[serde(default)]
    pub path: Option<String>,
    pub label: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactTasteMemory {
    #[serde(default)]
    pub directives: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactBrief {
    pub audience: String,
    pub job_to_be_done: String,
    pub subject_domain: String,
    pub artifact_thesis: String,
    #[serde(default)]
    pub required_concepts: Vec<String>,
    #[serde(default)]
    pub required_interactions: Vec<String>,
    #[serde(default)]
    pub visual_tone: Vec<String>,
    #[serde(default)]
    pub factual_anchors: Vec<String>,
    #[serde(default)]
    pub style_directives: Vec<String>,
    #[serde(default)]
    pub reference_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactEditIntent {
    pub mode: StudioArtifactEditMode,
    pub summary: String,
    pub patch_existing_artifact: bool,
    pub preserve_structure: bool,
    pub target_scope: String,
    #[serde(default)]
    pub target_paths: Vec<String>,
    #[serde(default)]
    pub requested_operations: Vec<String>,
    #[serde(default)]
    pub tone_directives: Vec<String>,
    #[serde(default)]
    pub selected_targets: Vec<StudioArtifactSelectionTarget>,
    #[serde(default)]
    pub style_directives: Vec<String>,
    pub branch_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactJudgeResult {
    pub classification: StudioArtifactJudgeClassification,
    pub request_faithfulness: u8,
    pub concept_coverage: u8,
    pub interaction_relevance: u8,
    pub layout_coherence: u8,
    pub visual_hierarchy: u8,
    pub completeness: u8,
    pub generic_shell_detected: bool,
    pub trivial_shell_detected: bool,
    pub deserves_primary_artifact_view: bool,
    #[serde(default)]
    pub patched_existing_artifact: Option<bool>,
    #[serde(default)]
    pub continuity_revision_ux: Option<u8>,
    #[serde(default)]
    pub strongest_contradiction: Option<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactCandidateSummary {
    pub candidate_id: String,
    pub seed: u64,
    pub model: String,
    pub temperature: f32,
    pub strategy: String,
    pub origin: StudioArtifactOutputOrigin,
    #[serde(default)]
    pub provenance: Option<StudioRuntimeProvenance>,
    pub summary: String,
    #[serde(default)]
    pub renderable_paths: Vec<String>,
    pub selected: bool,
    pub fallback: bool,
    #[serde(default)]
    pub failure: Option<String>,
    #[serde(default)]
    pub raw_output_preview: Option<String>,
    pub judge: StudioArtifactJudgeResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactGenerationError {
    pub message: String,
    #[serde(default)]
    pub brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<StudioArtifactCandidateSummary>,
}

impl std::fmt::Display for StudioArtifactGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StudioArtifactGenerationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRefinementContext {
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub revision_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub renderer: StudioRendererKind,
    #[serde(default)]
    pub files: Vec<StudioGeneratedArtifactFile>,
    #[serde(default)]
    pub selected_targets: Vec<StudioArtifactSelectionTarget>,
    #[serde(default)]
    pub taste_memory: Option<StudioArtifactTasteMemory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactGenerationBundle {
    pub brief: StudioArtifactBrief,
    #[serde(default)]
    pub edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    pub winning_candidate_id: String,
    pub winning_candidate_rationale: String,
    pub winner: StudioGeneratedArtifactPayload,
    pub judge: StudioArtifactJudgeResult,
    pub origin: StudioArtifactOutputOrigin,
    pub production_provenance: StudioRuntimeProvenance,
    pub acceptance_provenance: StudioRuntimeProvenance,
    pub fallback_used: bool,
    pub ux_lifecycle: StudioArtifactUxLifecycle,
    #[serde(default)]
    pub taste_memory: Option<StudioArtifactTasteMemory>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
}
