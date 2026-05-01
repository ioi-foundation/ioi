use super::*;
pub use crate::execution::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatGeneratedArtifactEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatGeneratedArtifactFile {
    pub path: String,
    pub mime: String,
    pub role: ChatArtifactFileRole,
    pub renderable: bool,
    pub downloadable: bool,
    #[serde(default)]
    pub encoding: Option<ChatGeneratedArtifactEncoding>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatGeneratedArtifactPayload {
    pub summary: String,
    #[serde(default)]
    pub notes: Vec<String>,
    pub files: Vec<ChatGeneratedArtifactFile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRenderCaptureViewport {
    Desktop,
    Mobile,
    Interaction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRenderFindingSeverity {
    Info,
    Warning,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRenderCapture {
    pub viewport: ChatArtifactRenderCaptureViewport,
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
pub struct ChatArtifactRenderFinding {
    pub code: String,
    pub severity: ChatArtifactRenderFindingSeverity,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRenderPolicyMode {
    #[default]
    Balanced,
    ObservationOnly,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRenderObservation {
    pub primary_region_present: bool,
    pub first_paint_visible_text_chars: usize,
    pub mobile_visible_text_chars: usize,
    pub semantic_region_count: usize,
    pub evidence_surface_count: usize,
    pub response_region_count: usize,
    pub actionable_affordance_count: usize,
    pub active_affordance_count: usize,
    pub runtime_error_count: usize,
    pub interaction_state_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRenderAcceptancePolicy {
    pub mode: ChatArtifactRenderPolicyMode,
    pub minimum_first_paint_text_chars: usize,
    pub minimum_semantic_regions: usize,
    pub minimum_evidence_surfaces: usize,
    pub minimum_actionable_affordances: usize,
    pub blocked_score_threshold: u8,
    pub primary_view_score_threshold: u8,
    pub require_primary_region: bool,
    pub require_response_region_when_interactive: bool,
    pub require_state_change_when_interactive: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactExecutionWitnessStatus {
    Passed,
    Failed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactAcceptanceObligationStatus {
    Passed,
    Failed,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactExecutionWitness {
    pub witness_id: String,
    #[serde(default)]
    pub obligation_id: Option<String>,
    pub action_kind: String,
    pub status: ChatArtifactExecutionWitnessStatus,
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
pub struct ChatArtifactAcceptanceObligation {
    pub obligation_id: String,
    pub family: String,
    pub required: bool,
    pub status: ChatArtifactAcceptanceObligationStatus,
    pub summary: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub witness_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRenderEvaluation {
    pub supported: bool,
    pub first_paint_captured: bool,
    pub interaction_capture_attempted: bool,
    #[serde(default)]
    pub captures: Vec<ChatArtifactRenderCapture>,
    #[serde(default)]
    pub observation: Option<ChatArtifactRenderObservation>,
    #[serde(default)]
    pub acceptance_policy: Option<ChatArtifactRenderAcceptancePolicy>,
    pub layout_density_score: u8,
    pub spacing_alignment_score: u8,
    pub typography_contrast_score: u8,
    pub visual_hierarchy_score: u8,
    pub blueprint_consistency_score: u8,
    pub overall_score: u8,
    #[serde(default)]
    pub findings: Vec<ChatArtifactRenderFinding>,
    #[serde(default)]
    pub acceptance_obligations: Vec<ChatArtifactAcceptanceObligation>,
    #[serde(default)]
    pub execution_witnesses: Vec<ChatArtifactExecutionWitness>,
    pub summary: String,
}

impl ChatArtifactRenderEvaluation {
    pub fn blocked_score_threshold(&self) -> u8 {
        self.acceptance_policy
            .as_ref()
            .map(|policy| policy.blocked_score_threshold)
            .unwrap_or(9)
    }

    pub fn primary_view_score_threshold(&self) -> u8 {
        self.acceptance_policy
            .as_ref()
            .map(|policy| policy.primary_view_score_threshold)
            .unwrap_or(18)
    }

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
                    && obligation.status == ChatArtifactAcceptanceObligationStatus::Passed
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
                        ChatArtifactAcceptanceObligationStatus::Failed
                            | ChatArtifactAcceptanceObligationStatus::Blocked
                    )
            })
            .count()
    }

    pub fn has_failed_required_obligations(&self) -> bool {
        self.failed_required_obligation_count() > 0
    }

    pub fn blocked_by_policy(&self) -> bool {
        !self.first_paint_captured
            || self
                .findings
                .iter()
                .any(|finding| finding.severity == ChatArtifactRenderFindingSeverity::Blocked)
            || self.has_failed_required_obligations()
            || self.overall_score <= self.blocked_score_threshold()
    }

    pub fn clears_required_runtime_contract(&self) -> bool {
        self.first_paint_captured
            && !self.has_failed_required_obligations()
            && self
                .findings
                .iter()
                .all(|finding| finding.severity != ChatArtifactRenderFindingSeverity::Blocked)
            && self.overall_score > self.blocked_score_threshold()
    }

    pub fn clears_primary_view_by_policy(&self) -> bool {
        self.clears_required_runtime_contract()
    }

    pub fn clears_visual_primary_threshold(&self) -> bool {
        self.first_paint_captured
            && !self.has_failed_required_obligations()
            && self
                .findings
                .iter()
                .all(|finding| finding.severity != ChatArtifactRenderFindingSeverity::Blocked)
            && self.overall_score >= self.primary_view_score_threshold()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactValidationStatus {
    #[default]
    Pass,
    Repairable,
    Blocked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactValidationResult {
    pub classification: ChatArtifactValidationStatus,
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
    pub score_total: i32,
    pub proof_kind: String,
    pub primary_view_cleared: bool,
    #[serde(default)]
    pub validated_paths: Vec<String>,
    #[serde(default)]
    pub issue_codes: Vec<String>,
    #[serde(default)]
    pub repair_hints: Vec<String>,
    #[serde(default)]
    pub blocked_reasons: Vec<String>,
    #[serde(default)]
    pub issue_classes: Vec<String>,
    #[serde(default)]
    pub strengths: Vec<String>,
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
    pub summary: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactEditMode {
    Create,
    Patch,
    Replace,
    Branch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactOutputOrigin {
    LiveInference,
    MockInference,
    DeterministicFallback,
    FixtureRuntime,
    InferenceUnavailable,
    OpaqueRuntime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactUxLifecycle {
    Draft,
    Refining,
    Validated,
    Locked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSelectionTarget {
    pub source_surface: String,
    #[serde(default)]
    pub path: Option<String>,
    pub label: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRuntimePreviewSnapshot {
    pub label: String,
    pub content: String,
    pub status: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub origin_prompt_event_id: Option<String>,
    #[serde(default)]
    pub is_final: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeEventType {
    UnderstandRequest,
    ArtifactRouteCommitted,
    SkillDiscovery,
    SkillRead,
    ArtifactBrief,
    AuthorArtifact,
    AuthorPreview,
    ReplanExecution,
    VerifyArtifact,
    PresentArtifact,
    #[default]
    Other,
}

impl ChatArtifactRuntimeEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnderstandRequest => "understand_request",
            Self::ArtifactRouteCommitted => "artifact_route_committed",
            Self::SkillDiscovery => "skill_discovery",
            Self::SkillRead => "skill_read",
            Self::ArtifactBrief => "artifact_brief",
            Self::AuthorArtifact => "author_artifact",
            Self::AuthorPreview => "author_preview",
            Self::ReplanExecution => "replan_execution",
            Self::VerifyArtifact => "verify_artifact",
            Self::PresentArtifact => "present_artifact",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Self {
        serde_json::from_str(&format!("\"{}\"", value.trim().to_ascii_lowercase()))
            .unwrap_or(Self::Other)
    }
}

impl From<&str> for ChatArtifactRuntimeEventType {
    fn from(value: &str) -> Self {
        Self::parse(value)
    }
}

impl From<String> for ChatArtifactRuntimeEventType {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeStepId {
    UnderstandRequest,
    ArtifactRouteCommitted,
    SkillDiscovery,
    SkillRead,
    ArtifactBrief,
    AuthorArtifact,
    ReplanExecution,
    VerifyArtifact,
    PresentArtifact,
    #[default]
    Other,
}

impl ChatArtifactRuntimeStepId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnderstandRequest => "understand_request",
            Self::ArtifactRouteCommitted => "artifact_route_committed",
            Self::SkillDiscovery => "skill_discovery",
            Self::SkillRead => "skill_read",
            Self::ArtifactBrief => "artifact_brief",
            Self::AuthorArtifact => "author_artifact",
            Self::ReplanExecution => "replan_execution",
            Self::VerifyArtifact => "verify_artifact",
            Self::PresentArtifact => "present_artifact",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Self {
        serde_json::from_str(&format!("\"{}\"", value.trim().to_ascii_lowercase()))
            .unwrap_or(Self::Other)
    }

    pub fn phase_kind(self) -> ChatArtifactRuntimeStepKind {
        match self {
            Self::UnderstandRequest => ChatArtifactRuntimeStepKind::Intake,
            Self::ArtifactRouteCommitted => ChatArtifactRuntimeStepKind::Routing,
            Self::SkillDiscovery | Self::SkillRead => ChatArtifactRuntimeStepKind::Guidance,
            Self::ArtifactBrief => ChatArtifactRuntimeStepKind::Planning,
            Self::AuthorArtifact => ChatArtifactRuntimeStepKind::Authoring,
            Self::ReplanExecution => ChatArtifactRuntimeStepKind::Strategy,
            Self::VerifyArtifact => ChatArtifactRuntimeStepKind::Verification,
            Self::PresentArtifact => ChatArtifactRuntimeStepKind::Presentation,
            Self::Other => ChatArtifactRuntimeStepKind::Other,
        }
    }
}

impl From<&str> for ChatArtifactRuntimeStepId {
    fn from(value: &str) -> Self {
        Self::parse(value)
    }
}

impl From<String> for ChatArtifactRuntimeStepId {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeStepKind {
    Intake,
    Routing,
    Guidance,
    Planning,
    Authoring,
    Strategy,
    Verification,
    Presentation,
    #[default]
    Other,
}

impl ChatArtifactRuntimeStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "intake",
            Self::Routing => "routing",
            Self::Guidance => "guidance",
            Self::Planning => "planning",
            Self::Authoring => "authoring",
            Self::Strategy => "strategy",
            Self::Verification => "verification",
            Self::Presentation => "presentation",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeEventKind {
    #[default]
    Step,
    Preview,
}

impl ChatArtifactRuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Step => "step",
            Self::Preview => "preview",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeEventStatus {
    Pending,
    Active,
    Complete,
    Failed,
    Blocked,
    Interrupted,
    #[default]
    Other,
}

impl ChatArtifactRuntimeEventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Interrupted => "interrupted",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Self {
        serde_json::from_str(&format!("\"{}\"", value.trim().to_ascii_lowercase()))
            .unwrap_or(Self::Other)
    }
}

impl From<&str> for ChatArtifactRuntimeEventStatus {
    fn from(value: &str) -> Self {
        Self::parse(value)
    }
}

impl From<String> for ChatArtifactRuntimeEventStatus {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactOperatorRunMode {
    #[default]
    Create,
    Edit,
}
pub type ChatArtifactOperatorRunMode = ArtifactOperatorRunMode;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactOperatorRunStatus {
    Pending,
    Active,
    Complete,
    Blocked,
    Failed,
    #[default]
    Other,
}
pub type ChatArtifactOperatorRunStatus = ArtifactOperatorRunStatus;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactOperatorPhase {
    UnderstandRequest,
    RouteArtifact,
    ReopenArtifactContext,
    SearchSources,
    ReadSources,
    AuthorArtifact,
    InspectArtifact,
    VerifyArtifact,
    RepairArtifact,
    PresentArtifact,
    #[default]
    Other,
}
pub type ChatArtifactOperatorPhase = ArtifactOperatorPhase;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactOperatorPreview {
    #[serde(default)]
    pub origin_prompt_event_id: String,
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
pub struct ArtifactSourceReference {
    pub source_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub excerpt: Option<String>,
    #[serde(default)]
    pub retrieved_at_ms: Option<u64>,
    #[serde(default)]
    pub freshness: Option<String>,
    #[serde(default)]
    pub reason: String,
}
pub type ChatArtifactSourceReference = ArtifactSourceReference;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSourcePack {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub items: Vec<ArtifactSourceReference>,
}
pub type ChatArtifactSourcePack = ArtifactSourcePack;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactFileRef {
    pub file_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: String,
    pub path: String,
    pub role: ChatArtifactFileRole,
    pub mime: String,
    #[serde(default)]
    pub summary: String,
}
pub type ChatArtifactFileRef = ArtifactFileRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactVerificationRef {
    pub verification_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: String,
    pub family: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub selector: Option<String>,
}
pub type ChatArtifactVerificationRef = ArtifactVerificationRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactVerificationOutcome {
    #[serde(default)]
    pub status: ArtifactOperatorRunStatus,
    pub summary: String,
    #[serde(default)]
    pub required_obligation_count: usize,
    #[serde(default)]
    pub cleared_obligation_count: usize,
    #[serde(default)]
    pub failed_obligation_count: usize,
}
pub type ChatArtifactVerificationOutcome = ArtifactVerificationOutcome;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactOperatorStep {
    pub step_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: String,
    #[serde(default)]
    pub phase: ArtifactOperatorPhase,
    pub engine: String,
    #[serde(default)]
    pub status: ArtifactOperatorRunStatus,
    pub label: String,
    pub detail: String,
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: Option<u64>,
    #[serde(default)]
    pub preview: Option<ChatArtifactOperatorPreview>,
    #[serde(default)]
    pub file_refs: Vec<ArtifactFileRef>,
    #[serde(default)]
    pub source_refs: Vec<ArtifactSourceReference>,
    #[serde(default)]
    pub verification_refs: Vec<ArtifactVerificationRef>,
    #[serde(default)]
    pub attempt: u32,
}
pub type ChatArtifactOperatorStep = ArtifactOperatorStep;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactOperatorRun {
    pub run_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: String,
    pub artifact_session_id: String,
    #[serde(default)]
    pub mode: ArtifactOperatorRunMode,
    #[serde(default)]
    pub status: ArtifactOperatorRunStatus,
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: Option<u64>,
    pub engine_summary: String,
    #[serde(default)]
    pub source_pack: ArtifactSourcePack,
    #[serde(default)]
    pub steps: Vec<ArtifactOperatorStep>,
    #[serde(default)]
    pub final_artifacts: Vec<ArtifactFileRef>,
    #[serde(default)]
    pub verification_outcome: Option<ArtifactVerificationOutcome>,
    #[serde(default)]
    pub repair_count: u32,
}
pub type ChatArtifactOperatorRun = ArtifactOperatorRun;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactExemplar {
    pub record_id: i64,
    pub title: String,
    pub summary: String,
    pub renderer: ChatRendererKind,
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
pub struct ChatArtifactTasteMemory {
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
pub struct ChatArtifactBrief {
    pub audience: String,
    pub job_to_be_done: String,
    pub subject_domain: String,
    pub artifact_thesis: String,
    #[serde(default)]
    pub required_concepts: Vec<String>,
    #[serde(default)]
    pub required_interactions: Vec<String>,
    #[serde(default)]
    pub query_profile: Option<ChatArtifactQueryProfile>,
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
pub struct ArtifactConnectorGrounding {
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub provider_family: Option<String>,
    #[serde(default)]
    pub target_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRetrievalPlan {
    pub normalized_topic: String,
    #[serde(default)]
    pub queries: Vec<String>,
    #[serde(default)]
    pub desired_source_kinds: Vec<String>,
    #[serde(default)]
    pub avoid_source_kinds: Vec<String>,
    #[serde(default)]
    pub freshness_mode: Option<String>,
    pub reason: String,
}

impl ChatArtifactBrief {
    pub fn required_interaction_summaries(&self) -> Vec<String> {
        if let Some(profile) = self.query_profile.as_ref() {
            return profile
                .interaction_goals
                .iter()
                .filter(|goal| goal.required)
                .map(|goal| goal.summary.trim())
                .filter(|summary| !summary.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        }

        self.required_interactions
            .iter()
            .map(|interaction| interaction.trim())
            .filter(|interaction| !interaction.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }

    pub fn required_interaction_goal_count(&self) -> usize {
        self.query_profile
            .as_ref()
            .map(|profile| profile.required_interaction_goal_count())
            .unwrap_or_else(|| self.required_interaction_summaries().len())
    }

    pub fn has_required_interaction_goals(&self) -> bool {
        self.required_interaction_goal_count() > 0
    }

    pub fn requires_response_region(&self) -> bool {
        self.query_profile
            .as_ref()
            .map(|profile| profile.requires_response_region())
            .unwrap_or_else(|| self.has_required_interaction_goals())
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactContentGoalKind {
    #[default]
    Orient,
    Explain,
    Compare,
    Evidence,
    Example,
    Summary,
    Implementation,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactInteractionGoalKind {
    StateSwitch,
    DetailInspect,
    SequenceBrowse,
    StateAdjust,
    #[default]
    GuidedResponse,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactEvidenceGoalKind {
    #[default]
    PrimarySurface,
    ComparisonSurface,
    DetailSurface,
    SupportingSurface,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactPresentationConstraintKind {
    #[default]
    SemanticStructure,
    FirstPaintEvidence,
    ResponseRegion,
    KeyboardAffordances,
    RuntimeSelfContainment,
    TypographySeparation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactContentGoal {
    pub kind: ChatArtifactContentGoalKind,
    pub summary: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactInteractionGoal {
    pub kind: ChatArtifactInteractionGoalKind,
    pub summary: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactEvidenceGoal {
    pub kind: ChatArtifactEvidenceGoalKind,
    pub summary: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactPresentationConstraint {
    pub kind: ChatArtifactPresentationConstraintKind,
    pub summary: String,
    pub required: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactQueryProfile {
    #[serde(default)]
    pub content_goals: Vec<ChatArtifactContentGoal>,
    #[serde(default)]
    pub interaction_goals: Vec<ChatArtifactInteractionGoal>,
    #[serde(default)]
    pub evidence_goals: Vec<ChatArtifactEvidenceGoal>,
    #[serde(default)]
    pub presentation_constraints: Vec<ChatArtifactPresentationConstraint>,
}

impl ChatArtifactQueryProfile {
    pub fn has_interaction_kind(&self, kind: ChatArtifactInteractionGoalKind) -> bool {
        self.interaction_goals.iter().any(|goal| goal.kind == kind)
    }

    pub fn required_interaction_goal_count(&self) -> usize {
        self.interaction_goals
            .iter()
            .filter(|goal| goal.required)
            .count()
    }

    pub fn requires_response_region(&self) -> bool {
        self.presentation_constraints.iter().any(|constraint| {
            constraint.kind == ChatArtifactPresentationConstraintKind::ResponseRegion
                && constraint.required
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactSkillNeedKind {
    VisualArtDirection,
    EditorialLayout,
    MotionHierarchy,
    InteractionCopyDiscipline,
    AccessibilityReview,
    DataStorytelling,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactSkillNeedPriority {
    Required,
    Recommended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSkillNeed {
    pub kind: ChatArtifactSkillNeedKind,
    pub priority: ChatArtifactSkillNeedPriority,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSectionPlan {
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
pub struct ChatArtifactInteractionPlan {
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
pub struct ChatArtifactEvidencePlanEntry {
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
pub struct ChatArtifactDesignSystem {
    pub color_strategy: String,
    pub typography_strategy: String,
    pub density: String,
    pub motion_style: String,
    #[serde(default)]
    pub emphasis_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactComponentPlanEntry {
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
pub struct ChatArtifactAccessibilityPlan {
    #[serde(default)]
    pub obligations: Vec<String>,
    #[serde(default)]
    pub focus_order: Vec<String>,
    #[serde(default)]
    pub aria_expectations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactAcceptanceTargets {
    pub minimum_section_count: u8,
    pub minimum_interactive_regions: u8,
    pub require_first_paint_evidence: bool,
    pub require_persistent_detail_region: bool,
    pub require_distinct_typography: bool,
    pub require_keyboard_affordances: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactBlueprint {
    pub version: u32,
    pub renderer: ChatRendererKind,
    pub narrative_arc: String,
    #[serde(default)]
    pub section_plan: Vec<ChatArtifactSectionPlan>,
    #[serde(default)]
    pub interaction_plan: Vec<ChatArtifactInteractionPlan>,
    #[serde(default)]
    pub evidence_plan: Vec<ChatArtifactEvidencePlanEntry>,
    pub design_system: ChatArtifactDesignSystem,
    #[serde(default)]
    pub component_plan: Vec<ChatArtifactComponentPlanEntry>,
    pub accessibility_plan: ChatArtifactAccessibilityPlan,
    pub acceptance_targets: ChatArtifactAcceptanceTargets,
    pub scaffold_family: String,
    pub variation_strategy: String,
    #[serde(default)]
    pub skill_needs: Vec<ChatArtifactSkillNeed>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSelectedSkill {
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
    pub matched_need_kinds: Vec<ChatArtifactSkillNeedKind>,
    pub match_rationale: String,
    #[serde(default)]
    pub guidance_markdown: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactIRNode {
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
pub struct ChatArtifactIRInteractionEdge {
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
pub struct ChatArtifactIREvidenceSurface {
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
pub struct ChatArtifactDesignToken {
    pub name: String,
    pub category: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactIR {
    pub version: u32,
    pub renderer: ChatRendererKind,
    pub scaffold_family: String,
    #[serde(default)]
    pub semantic_structure: Vec<ChatArtifactIRNode>,
    #[serde(default)]
    pub interaction_graph: Vec<ChatArtifactIRInteractionEdge>,
    #[serde(default)]
    pub evidence_surfaces: Vec<ChatArtifactIREvidenceSurface>,
    #[serde(default)]
    pub design_tokens: Vec<ChatArtifactDesignToken>,
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
pub struct ChatArtifactPreparationNeeds {
    pub renderer: ChatRendererKind,
    #[serde(default)]
    pub required_concepts: Vec<String>,
    #[serde(default)]
    pub required_interactions: Vec<String>,
    #[serde(default)]
    pub skill_needs: Vec<ChatArtifactSkillNeed>,
    #[serde(default)]
    pub require_blueprint: bool,
    #[serde(default)]
    pub require_artifact_ir: bool,
    #[serde(default)]
    pub exemplar_discovery_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactPreparedContextResolution {
    pub status: String,
    pub renderer: ChatRendererKind,
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
    pub source_count: u32,
    #[serde(default)]
    pub selected_skill_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSkillDiscoveryResolution {
    pub status: String,
    #[serde(default = "default_chat_guidance_status")]
    pub guidance_status: String,
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

fn default_chat_guidance_status() -> String {
    "pending".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactPlanningContext {
    pub brief: ChatArtifactBrief,
    #[serde(default)]
    pub blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub preparation_needs: Option<ChatArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<ChatArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<ChatArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub selected_skills: Vec<ChatArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<ChatArtifactExemplar>,
    #[serde(default)]
    pub retrieved_sources: Vec<ChatArtifactSourceReference>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimePolicyProfile {
    Auto,
    FullyLocal,
    LocalGenerationRemoteAcceptance,
    PremiumPlanningLocalGeneration,
    PremiumEndToEnd,
}

impl ChatArtifactRuntimePolicyProfile {
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        serde_json::from_str(&format!("\"{normalized}\"")).ok()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeStep {
    OutcomeRouting,
    BlueprintPlanning,
    CandidateGeneration,
    ArtifactValidation,
    RepairPlanning,
    MemoryDistillation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactRuntimeTier {
    Deterministic,
    Local,
    CostEffective,
    Premium,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRuntimeStepPolicy {
    pub step: ChatArtifactRuntimeStep,
    pub preferred_tier: ChatArtifactRuntimeTier,
    pub fallback_to_generation_runtime: bool,
    pub require_distinct_runtime: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRuntimeBinding {
    pub step: ChatArtifactRuntimeStep,
    pub preferred_tier: ChatArtifactRuntimeTier,
    pub selected_tier: ChatArtifactRuntimeTier,
    pub fallback_applied: bool,
    #[serde(default)]
    pub degradation_reason: Option<String>,
    pub provenance: ChatRuntimeProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRuntimePolicy {
    pub profile: ChatArtifactRuntimePolicyProfile,
    #[serde(default)]
    pub step_policies: Vec<ChatArtifactRuntimeStepPolicy>,
    #[serde(default)]
    pub bindings: Vec<ChatArtifactRuntimeBinding>,
}

pub type ChatArtifactWorkerRole = WorkGraphWorkerRole;
pub type ChatArtifactWorkItemStatus = WorkGraphWorkItemStatus;
pub type ChatArtifactWorkItem = WorkGraphWorkItem;
pub type ChatArtifactWorkGraphPlan = WorkGraphPlan;
pub type ChatArtifactWorkGraphExecutionSummary = WorkGraphExecutionSummary;
pub type ChatArtifactWorkerReceipt = WorkGraphWorkerReceipt;
pub type ChatArtifactPatchReceipt = WorkGraphChangeReceipt;
pub type ChatArtifactMergeReceipt = WorkGraphMergeReceipt;
pub type ChatArtifactVerificationReceipt = WorkGraphVerificationReceipt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatAdaptiveSearchSignal {
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
pub struct ChatAdaptiveSearchBudget {
    pub initial_candidate_count: usize,
    pub max_candidate_count: usize,
    pub shortlist_limit: usize,
    pub max_semantic_refinement_passes: usize,
    pub plateau_limit: usize,
    pub min_score_delta: i32,
    pub target_validation_score_for_early_stop: i32,
    pub expansion_score_margin: i32,
    #[serde(default)]
    pub signals: Vec<ChatAdaptiveSearchSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactEditIntent {
    pub mode: ChatArtifactEditMode,
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
    pub selected_targets: Vec<ChatArtifactSelectionTarget>,
    #[serde(default)]
    pub style_directives: Vec<String>,
    pub branch_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactCandidateConvergenceTrace {
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
pub struct ChatArtifactCandidateSummary {
    pub candidate_id: String,
    pub seed: u64,
    pub model: String,
    pub temperature: f32,
    pub strategy: String,
    pub origin: ChatArtifactOutputOrigin,
    #[serde(default)]
    pub provenance: Option<ChatRuntimeProvenance>,
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
    pub convergence: Option<ChatArtifactCandidateConvergenceTrace>,
    #[serde(default)]
    pub render_evaluation: Option<ChatArtifactRenderEvaluation>,
    pub validation: ChatArtifactValidationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactGenerationError {
    pub message: String,
    #[serde(default)]
    pub brief: Option<ChatArtifactBrief>,
    #[serde(default)]
    pub blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<ChatArtifactSelectedSkill>,
    #[serde(default)]
    pub edit_intent: Option<ChatArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<ChatArtifactCandidateSummary>,
}

impl std::fmt::Display for ChatArtifactGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChatArtifactGenerationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRefinementContext {
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub revision_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub renderer: ChatRendererKind,
    #[serde(default)]
    pub files: Vec<ChatGeneratedArtifactFile>,
    #[serde(default)]
    pub selected_targets: Vec<ChatArtifactSelectionTarget>,
    #[serde(default)]
    pub taste_memory: Option<ChatArtifactTasteMemory>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<ChatArtifactExemplar>,
    #[serde(default)]
    pub blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<ChatArtifactSelectedSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactGenerationProgress {
    pub current_step: String,
    #[serde(default)]
    pub artifact_brief: Option<ChatArtifactBrief>,
    #[serde(default)]
    pub preparation_needs: Option<ChatArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<ChatArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<ChatArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<ChatArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<ChatArtifactExemplar>,
    #[serde(default)]
    pub retrieved_sources: Vec<ChatArtifactSourceReference>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default, alias = "swarmPlan")]
    pub work_graph_plan: Option<WorkGraphPlan>,
    #[serde(default, alias = "swarmExecution")]
    pub work_graph_execution: Option<WorkGraphExecutionSummary>,
    #[serde(default, alias = "swarmWorkerReceipts")]
    pub work_graph_worker_receipts: Vec<WorkGraphWorkerReceipt>,
    #[serde(default, alias = "swarmChangeReceipts")]
    pub work_graph_change_receipts: Vec<WorkGraphChangeReceipt>,
    #[serde(default, alias = "swarmMergeReceipts")]
    pub work_graph_merge_receipts: Vec<WorkGraphMergeReceipt>,
    #[serde(default, alias = "swarmVerificationReceipts")]
    pub work_graph_verification_receipts: Vec<WorkGraphVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<ChatArtifactRenderEvaluation>,
    #[serde(default)]
    pub validation: Option<ChatArtifactValidationResult>,
    #[serde(default)]
    pub operator_steps: Vec<ChatArtifactOperatorStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactGenerationBundle {
    pub brief: ChatArtifactBrief,
    #[serde(default)]
    pub blueprint: Option<ChatArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<ChatArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<ChatArtifactSelectedSkill>,
    #[serde(default)]
    pub edit_intent: Option<ChatArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    #[serde(default)]
    pub winning_candidate_id: Option<String>,
    #[serde(default)]
    pub winning_candidate_rationale: Option<String>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default, alias = "swarmPlan")]
    pub work_graph_plan: Option<WorkGraphPlan>,
    #[serde(default, alias = "swarmExecution")]
    pub work_graph_execution: Option<WorkGraphExecutionSummary>,
    #[serde(default, alias = "swarmWorkerReceipts")]
    pub work_graph_worker_receipts: Vec<WorkGraphWorkerReceipt>,
    #[serde(default, alias = "swarmChangeReceipts")]
    pub work_graph_change_receipts: Vec<WorkGraphChangeReceipt>,
    #[serde(default, alias = "swarmMergeReceipts")]
    pub work_graph_merge_receipts: Vec<WorkGraphMergeReceipt>,
    #[serde(default, alias = "swarmVerificationReceipts")]
    pub work_graph_verification_receipts: Vec<WorkGraphVerificationReceipt>,
    pub winner: ChatGeneratedArtifactPayload,
    #[serde(default)]
    pub render_evaluation: Option<ChatArtifactRenderEvaluation>,
    pub validation: ChatArtifactValidationResult,
    pub origin: ChatArtifactOutputOrigin,
    pub production_provenance: ChatRuntimeProvenance,
    pub acceptance_provenance: ChatRuntimeProvenance,
    #[serde(default)]
    pub runtime_policy: Option<ChatArtifactRuntimePolicy>,
    #[serde(default)]
    pub adaptive_search_budget: Option<ChatAdaptiveSearchBudget>,
    pub degraded_path_used: bool,
    pub ux_lifecycle: ChatArtifactUxLifecycle,
    #[serde(default)]
    pub taste_memory: Option<ChatArtifactTasteMemory>,
    #[serde(default)]
    pub failure: Option<ChatArtifactFailure>,
}
