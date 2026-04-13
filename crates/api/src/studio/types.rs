use super::*;
pub use crate::execution::*;

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
pub enum StudioArtifactRenderCaptureViewport {
    Desktop,
    Mobile,
    Interaction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactRenderFindingSeverity {
    Info,
    Warning,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRenderCapture {
    pub viewport: StudioArtifactRenderCaptureViewport,
    pub width: u32,
    pub height: u32,
    pub screenshot_sha256: String,
    pub screenshot_byte_count: usize,
    pub visible_element_count: usize,
    pub visible_text_chars: usize,
    pub interactive_element_count: usize,
    #[serde(default)]
    pub screenshot_changed_from_previous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRenderFinding {
    pub code: String,
    pub severity: StudioArtifactRenderFindingSeverity,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactExecutionWitnessStatus {
    Passed,
    Failed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactAcceptanceObligationStatus {
    Passed,
    Failed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactExecutionWitness {
    pub witness_id: String,
    #[serde(default)]
    pub obligation_id: Option<String>,
    pub action_kind: String,
    pub status: StudioArtifactExecutionWitnessStatus,
    pub summary: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub console_errors: Vec<String>,
    #[serde(default)]
    pub state_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactAcceptanceObligation {
    pub obligation_id: String,
    pub family: String,
    pub required: bool,
    pub status: StudioArtifactAcceptanceObligationStatus,
    pub summary: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub witness_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRenderEvaluation {
    pub supported: bool,
    pub first_paint_captured: bool,
    pub interaction_capture_attempted: bool,
    #[serde(default)]
    pub captures: Vec<StudioArtifactRenderCapture>,
    pub layout_density_score: u8,
    pub spacing_alignment_score: u8,
    pub typography_contrast_score: u8,
    pub visual_hierarchy_score: u8,
    pub blueprint_consistency_score: u8,
    pub overall_score: u8,
    #[serde(default)]
    pub findings: Vec<StudioArtifactRenderFinding>,
    #[serde(default)]
    pub acceptance_obligations: Vec<StudioArtifactAcceptanceObligation>,
    #[serde(default)]
    pub execution_witnesses: Vec<StudioArtifactExecutionWitness>,
    pub summary: String,
}

impl StudioArtifactRenderEvaluation {
    pub fn required_obligation_count(&self) -> usize {
        self.acceptance_obligations
            .iter()
            .filter(|obligation| obligation.required)
            .count()
    }

    pub fn cleared_required_obligation_count(&self) -> usize {
        self.acceptance_obligations
            .iter()
            .filter(|obligation| {
                obligation.required
                    && obligation.status == StudioArtifactAcceptanceObligationStatus::Passed
            })
            .count()
    }

    pub fn failed_required_obligation_count(&self) -> usize {
        self.acceptance_obligations
            .iter()
            .filter(|obligation| {
                obligation.required
                    && matches!(
                        obligation.status,
                        StudioArtifactAcceptanceObligationStatus::Failed
                            | StudioArtifactAcceptanceObligationStatus::Blocked
                    )
            })
            .count()
    }

    pub fn has_failed_required_obligations(&self) -> bool {
        self.failed_required_obligation_count() > 0
    }
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
pub struct StudioArtifactRuntimePreviewSnapshot {
    pub label: String,
    pub content: String,
    pub status: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub is_final: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRuntimeNarrationEvent {
    pub event_id: String,
    pub event_type: String,
    pub step_id: String,
    #[serde(default)]
    pub event_kind: String,
    #[serde(default)]
    pub attempt_id: Option<String>,
    pub title: String,
    pub detail: String,
    pub status: String,
    pub occurred_at_ms: u64,
    #[serde(default)]
    pub preview: Option<StudioArtifactRuntimePreviewSnapshot>,
}

impl StudioArtifactRuntimeNarrationEvent {
    pub fn new(
        event_type: impl Into<String>,
        step_id: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};

        static STUDIO_RUNTIME_EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

        let occurred_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();
        let event_type = event_type.into();
        let event_sequence = STUDIO_RUNTIME_EVENT_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self {
            event_id: format!("{event_type}:{occurred_at_ms}:{event_sequence}"),
            event_type,
            step_id: step_id.into(),
            event_kind: "step".to_string(),
            attempt_id: None,
            title: title.into(),
            detail: detail.into(),
            status: status.into(),
            occurred_at_ms,
            preview: None,
        }
    }

    pub fn with_attempt_id(mut self, attempt_id: impl Into<String>) -> Self {
        self.attempt_id = Some(attempt_id.into());
        self
    }

    pub fn with_preview_snapshot(mut self, preview: StudioArtifactRuntimePreviewSnapshot) -> Self {
        self.event_kind = "preview".to_string();
        self.preview = Some(preview);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactExemplar {
    pub record_id: i64,
    pub title: String,
    pub summary: String,
    pub renderer: StudioRendererKind,
    pub scaffold_family: String,
    pub thesis: String,
    pub quality_rationale: String,
    pub score_total: i32,
    #[serde(default)]
    pub design_cues: Vec<String>,
    #[serde(default)]
    pub component_patterns: Vec<String>,
    #[serde(default)]
    pub anti_patterns: Vec<String>,
    #[serde(default)]
    pub source_revision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactTasteMemory {
    #[serde(default)]
    pub directives: Vec<String>,
    pub summary: String,
    #[serde(default)]
    pub typography_preferences: Vec<String>,
    #[serde(default)]
    pub density_preference: Option<String>,
    #[serde(default)]
    pub tone_family: Vec<String>,
    #[serde(default)]
    pub motion_tolerance: Option<String>,
    #[serde(default)]
    pub preferred_scaffold_families: Vec<String>,
    #[serde(default)]
    pub preferred_component_patterns: Vec<String>,
    #[serde(default)]
    pub anti_patterns: Vec<String>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactSkillNeedKind {
    VisualArtDirection,
    EditorialLayout,
    MotionHierarchy,
    InteractionCopyDiscipline,
    AccessibilityReview,
    DataStorytelling,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactSkillNeedPriority {
    Required,
    Recommended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSkillNeed {
    pub kind: StudioArtifactSkillNeedKind,
    pub priority: StudioArtifactSkillNeedPriority,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSectionPlan {
    pub id: String,
    pub role: String,
    pub visible_purpose: String,
    #[serde(default)]
    pub content_requirements: Vec<String>,
    #[serde(default)]
    pub interaction_hooks: Vec<String>,
    #[serde(default)]
    pub first_paint_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactInteractionPlan {
    pub id: String,
    pub family: String,
    #[serde(default)]
    pub source_controls: Vec<String>,
    #[serde(default)]
    pub target_surfaces: Vec<String>,
    pub default_state: String,
    #[serde(default)]
    pub required_first_paint_affordances: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactEvidencePlanEntry {
    pub id: String,
    pub kind: String,
    pub purpose: String,
    #[serde(default)]
    pub concept_bindings: Vec<String>,
    #[serde(default)]
    pub first_paint_elements: Vec<String>,
    #[serde(default)]
    pub detail_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactDesignSystem {
    pub color_strategy: String,
    pub typography_strategy: String,
    pub density: String,
    pub motion_style: String,
    #[serde(default)]
    pub emphasis_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactComponentPlanEntry {
    pub id: String,
    pub component_family: String,
    pub role: String,
    #[serde(default)]
    pub section_ids: Vec<String>,
    #[serde(default)]
    pub interaction_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactAccessibilityPlan {
    #[serde(default)]
    pub obligations: Vec<String>,
    #[serde(default)]
    pub focus_order: Vec<String>,
    #[serde(default)]
    pub aria_expectations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactAcceptanceTargets {
    pub minimum_section_count: u8,
    pub minimum_interactive_regions: u8,
    pub require_first_paint_evidence: bool,
    pub require_persistent_detail_region: bool,
    pub require_distinct_typography: bool,
    pub require_keyboard_affordances: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactBlueprint {
    pub version: u32,
    pub renderer: StudioRendererKind,
    pub narrative_arc: String,
    #[serde(default)]
    pub section_plan: Vec<StudioArtifactSectionPlan>,
    #[serde(default)]
    pub interaction_plan: Vec<StudioArtifactInteractionPlan>,
    #[serde(default)]
    pub evidence_plan: Vec<StudioArtifactEvidencePlanEntry>,
    pub design_system: StudioArtifactDesignSystem,
    #[serde(default)]
    pub component_plan: Vec<StudioArtifactComponentPlanEntry>,
    pub accessibility_plan: StudioArtifactAccessibilityPlan,
    pub acceptance_targets: StudioArtifactAcceptanceTargets,
    pub scaffold_family: String,
    pub variation_strategy: String,
    #[serde(default)]
    pub skill_needs: Vec<StudioArtifactSkillNeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSelectedSkill {
    pub skill_hash: String,
    pub name: String,
    pub description: String,
    pub lifecycle_state: String,
    pub source_type: String,
    pub reliability_bps: u32,
    pub semantic_score_bps: u32,
    pub adjusted_score_bps: u32,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub matched_need_ids: Vec<String>,
    #[serde(default)]
    pub matched_need_kinds: Vec<StudioArtifactSkillNeedKind>,
    pub match_rationale: String,
    #[serde(default)]
    pub guidance_markdown: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactIRNode {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub section_id: Option<String>,
    pub label: String,
    #[serde(default)]
    pub bindings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactIRInteractionEdge {
    pub id: String,
    pub family: String,
    #[serde(default)]
    pub control_node_ids: Vec<String>,
    #[serde(default)]
    pub target_node_ids: Vec<String>,
    pub default_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactIREvidenceSurface {
    pub id: String,
    pub kind: String,
    pub section_id: String,
    #[serde(default)]
    pub bound_concepts: Vec<String>,
    #[serde(default)]
    pub first_paint_expectations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactDesignToken {
    pub name: String,
    pub category: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactIR {
    pub version: u32,
    pub renderer: StudioRendererKind,
    pub scaffold_family: String,
    #[serde(default)]
    pub semantic_structure: Vec<StudioArtifactIRNode>,
    #[serde(default)]
    pub interaction_graph: Vec<StudioArtifactIRInteractionEdge>,
    #[serde(default)]
    pub evidence_surfaces: Vec<StudioArtifactIREvidenceSurface>,
    #[serde(default)]
    pub design_tokens: Vec<StudioArtifactDesignToken>,
    #[serde(default)]
    pub motion_plan: Vec<String>,
    #[serde(default)]
    pub accessibility_obligations: Vec<String>,
    #[serde(default)]
    pub responsive_layout_rules: Vec<String>,
    #[serde(default)]
    pub component_bindings: Vec<String>,
    #[serde(default)]
    pub static_audit_expectations: Vec<String>,
    #[serde(default)]
    pub render_eval_checklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactPreparationNeeds {
    pub renderer: StudioRendererKind,
    #[serde(default)]
    pub required_concepts: Vec<String>,
    #[serde(default)]
    pub required_interactions: Vec<String>,
    #[serde(default)]
    pub skill_needs: Vec<StudioArtifactSkillNeed>,
    #[serde(default)]
    pub require_blueprint: bool,
    #[serde(default)]
    pub require_artifact_ir: bool,
    #[serde(default)]
    pub exemplar_discovery_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactPreparedContextResolution {
    pub status: String,
    pub renderer: StudioRendererKind,
    #[serde(default)]
    pub require_blueprint: bool,
    #[serde(default)]
    pub require_artifact_ir: bool,
    #[serde(default)]
    pub skill_need_count: u32,
    #[serde(default)]
    pub selected_skill_count: u32,
    #[serde(default)]
    pub exemplar_count: u32,
    #[serde(default)]
    pub selected_skill_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSkillDiscoveryResolution {
    pub status: String,
    #[serde(default)]
    pub guidance_evaluated: bool,
    #[serde(default)]
    pub guidance_recommended: bool,
    #[serde(default)]
    pub guidance_found: bool,
    #[serde(default)]
    pub guidance_attached: bool,
    #[serde(default)]
    pub skill_need_count: u32,
    #[serde(default)]
    pub selected_skill_count: u32,
    #[serde(default)]
    pub selected_skill_names: Vec<String>,
    #[serde(default)]
    pub search_scope: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactPlanningContext {
    pub brief: StudioArtifactBrief,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub preparation_needs: Option<StudioArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactRuntimePolicyProfile {
    Auto,
    FullyLocal,
    LocalGenerationRemoteAcceptance,
    PremiumPlanningLocalGeneration,
    PremiumEndToEnd,
}

impl StudioArtifactRuntimePolicyProfile {
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        serde_json::from_str(&format!("\"{normalized}\"")).ok()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactRuntimeStep {
    OutcomeRouting,
    BlueprintPlanning,
    CandidateGeneration,
    AcceptanceJudge,
    RepairPlanning,
    MemoryDistillation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactRuntimeTier {
    Deterministic,
    Local,
    CostEffective,
    Premium,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRuntimeStepPolicy {
    pub step: StudioArtifactRuntimeStep,
    pub preferred_tier: StudioArtifactRuntimeTier,
    pub fallback_to_generation_runtime: bool,
    pub require_distinct_runtime: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRuntimeBinding {
    pub step: StudioArtifactRuntimeStep,
    pub preferred_tier: StudioArtifactRuntimeTier,
    pub selected_tier: StudioArtifactRuntimeTier,
    pub fallback_applied: bool,
    #[serde(default)]
    pub fallback_reason: Option<String>,
    pub provenance: StudioRuntimeProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRuntimePolicy {
    pub profile: StudioArtifactRuntimePolicyProfile,
    #[serde(default)]
    pub step_policies: Vec<StudioArtifactRuntimeStepPolicy>,
    #[serde(default)]
    pub bindings: Vec<StudioArtifactRuntimeBinding>,
}

pub type StudioArtifactWorkerRole = SwarmWorkerRole;
pub type StudioArtifactWorkItemStatus = SwarmWorkItemStatus;
pub type StudioArtifactWorkItem = SwarmWorkItem;
pub type StudioArtifactSwarmPlan = SwarmPlan;
pub type StudioArtifactSwarmExecutionSummary = SwarmExecutionSummary;
pub type StudioArtifactWorkerReceipt = SwarmWorkerReceipt;
pub type StudioArtifactPatchReceipt = SwarmChangeReceipt;
pub type StudioArtifactMergeReceipt = SwarmMergeReceipt;
pub type StudioArtifactVerificationReceipt = SwarmVerificationReceipt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioAdaptiveSearchSignal {
    RendererComplexity,
    BriefInteractionLoad,
    BriefConceptLoad,
    SkillBackedDesign,
    ExemplarSupport,
    ContinuationEdit,
    LocalGenerationConstraint,
    HighCandidateVariance,
    LowCandidateVariance,
    NoPrimaryViewCandidate,
    NearMissPrimaryView,
    GenerationFailureObserved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioAdaptiveSearchBudget {
    pub initial_candidate_count: usize,
    pub max_candidate_count: usize,
    pub shortlist_limit: usize,
    pub max_semantic_refinement_passes: usize,
    pub plateau_limit: usize,
    pub min_score_delta: i32,
    pub target_judge_score_for_early_stop: i32,
    pub expansion_score_margin: i32,
    #[serde(default)]
    pub signals: Vec<StudioAdaptiveSearchSignal>,
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
    pub issue_classes: Vec<String>,
    #[serde(default)]
    pub repair_hints: Vec<String>,
    #[serde(default)]
    pub strengths: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub file_findings: Vec<String>,
    #[serde(default)]
    pub aesthetic_verdict: String,
    #[serde(default)]
    pub interaction_verdict: String,
    #[serde(default)]
    pub truthfulness_warnings: Vec<String>,
    #[serde(default)]
    pub recommended_next_pass: Option<String>,
    #[serde(default)]
    pub strongest_contradiction: Option<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactCandidateConvergenceTrace {
    pub lineage_root_id: String,
    #[serde(default)]
    pub parent_candidate_id: Option<String>,
    pub pass_kind: String,
    pub pass_index: u32,
    pub score_total: i32,
    #[serde(default)]
    pub score_delta_from_parent: Option<i32>,
    #[serde(default)]
    pub terminated_reason: Option<String>,
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
    #[serde(default)]
    pub convergence: Option<StudioArtifactCandidateConvergenceTrace>,
    #[serde(default)]
    pub render_evaluation: Option<StudioArtifactRenderEvaluation>,
    pub judge: StudioArtifactJudgeResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactGenerationError {
    pub message: String,
    #[serde(default)]
    pub brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
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
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactGenerationProgress {
    pub current_step: String,
    #[serde(default)]
    pub artifact_brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub preparation_needs: Option<StudioArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default, alias = "swarmPatchReceipts")]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<StudioArtifactRenderEvaluation>,
    #[serde(default)]
    pub judge: Option<StudioArtifactJudgeResult>,
    #[serde(default)]
    pub runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactGenerationBundle {
    pub brief: StudioArtifactBrief,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
    #[serde(default)]
    pub edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    #[serde(default)]
    pub winning_candidate_id: Option<String>,
    #[serde(default)]
    pub winning_candidate_rationale: Option<String>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default, alias = "swarmPatchReceipts")]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    pub winner: StudioGeneratedArtifactPayload,
    #[serde(default)]
    pub render_evaluation: Option<StudioArtifactRenderEvaluation>,
    pub judge: StudioArtifactJudgeResult,
    pub origin: StudioArtifactOutputOrigin,
    pub production_provenance: StudioRuntimeProvenance,
    pub acceptance_provenance: StudioRuntimeProvenance,
    #[serde(default)]
    pub runtime_policy: Option<StudioArtifactRuntimePolicy>,
    #[serde(default)]
    pub adaptive_search_budget: Option<StudioAdaptiveSearchBudget>,
    pub fallback_used: bool,
    pub ux_lifecycle: StudioArtifactUxLifecycle,
    #[serde(default)]
    pub taste_memory: Option<StudioArtifactTasteMemory>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
}
