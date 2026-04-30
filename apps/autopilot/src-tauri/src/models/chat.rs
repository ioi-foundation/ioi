use ioi_api::chat::{
    ChatArtifactBlueprint, ChatArtifactBrief, ChatArtifactCandidateSummary, ChatArtifactEditIntent,
    ChatArtifactExemplar, ChatArtifactIR, ChatArtifactOutputOrigin, ChatArtifactPreparationNeeds,
    ChatArtifactPreparedContextResolution, ChatArtifactRenderEvaluation, ChatArtifactSelectedSkill,
    ChatArtifactSelectionTarget, ChatArtifactSkillDiscoveryResolution, ChatArtifactTasteMemory,
    ChatArtifactUxLifecycle, ChatArtifactValidationResult, ExecutionEnvelope, ExecutionStage,
    SwarmChangeReceipt, SwarmExecutionSummary, SwarmMergeReceipt, SwarmPlan,
    SwarmVerificationReceipt, SwarmWorkerReceipt,
};
use ioi_api::runtime_harness::{
    ArtifactOperatorRun, ArtifactOperatorStep, ArtifactSourceReference,
};
use ioi_types::app::{
    ChatArtifactFailure, ChatArtifactLifecycleState, ChatArtifactManifest, ChatOutcomeRequest,
    ChatRendererKind, ChatRetainedWidgetState, ChatRuntimeProvenance, ChatVerifiedReply,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

// Structured chat message for persistent history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user", "agent", "system", "tool"

    // We map backend `content` to frontend `text` for compatibility with UI components
    #[serde(alias = "content")]
    pub text: String,

    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactNavigatorNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub badge: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub lens: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub children: Vec<ChatArtifactNavigatorNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactMaterializationFileWrite {
    pub path: String,
    pub kind: String,
    #[serde(default)]
    pub content_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactMaterializationCommandIntent {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactMaterializationPreviewIntent {
    pub label: String,
    pub url: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactPipelineStep {
    pub id: String,
    pub stage: ExecutionStage,
    pub label: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub verification_gate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactMaterializationContract {
    pub version: u32,
    pub request_kind: String,
    pub normalized_intent: String,
    pub summary: String,
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
    pub retrieved_sources: Vec<ArtifactSourceReference>,
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
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default)]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<ChatArtifactRenderEvaluation>,
    #[serde(default)]
    pub validation: Option<ChatArtifactValidationResult>,
    #[serde(default)]
    pub output_origin: Option<ChatArtifactOutputOrigin>,
    #[serde(default)]
    pub production_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub degraded_path_used: bool,
    #[serde(default)]
    pub ux_lifecycle: Option<ChatArtifactUxLifecycle>,
    #[serde(default)]
    pub failure: Option<ChatArtifactFailure>,
    #[serde(default)]
    pub navigator_nodes: Vec<ChatArtifactNavigatorNode>,
    #[serde(default)]
    pub file_writes: Vec<ChatArtifactMaterializationFileWrite>,
    #[serde(default)]
    pub command_intents: Vec<ChatArtifactMaterializationCommandIntent>,
    #[serde(default)]
    pub preview_intent: Option<ChatArtifactMaterializationPreviewIntent>,
    #[serde(default)]
    pub pipeline_steps: Vec<ChatArtifactPipelineStep>,
    #[serde(default)]
    pub operator_steps: Vec<ArtifactOperatorStep>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactRevision {
    pub revision_id: String,
    #[serde(default)]
    pub parent_revision_id: Option<String>,
    pub branch_id: String,
    pub branch_label: String,
    pub prompt: String,
    pub created_at: String,
    pub ux_lifecycle: ChatArtifactUxLifecycle,
    pub artifact_manifest: ChatArtifactManifest,
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
    pub retrieved_sources: Vec<ArtifactSourceReference>,
    #[serde(default)]
    pub edit_intent: Option<ChatArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<ChatArtifactCandidateSummary>,
    #[serde(default)]
    pub winning_candidate_id: Option<String>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default)]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<ChatArtifactRenderEvaluation>,
    #[serde(default)]
    pub validation: Option<ChatArtifactValidationResult>,
    #[serde(default)]
    pub output_origin: Option<ChatArtifactOutputOrigin>,
    #[serde(default)]
    pub production_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<ChatArtifactFailure>,
    #[serde(default)]
    pub file_writes: Vec<ChatArtifactMaterializationFileWrite>,
    #[serde(default)]
    pub taste_memory: Option<ChatArtifactTasteMemory>,
    #[serde(default)]
    pub selected_targets: Vec<ChatArtifactSelectionTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatBuildReceipt {
    pub receipt_id: String,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub summary: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub replay_classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatCodeWorkerLease {
    pub backend: String,
    pub planner_authority: String,
    #[serde(default)]
    pub allowed_mutation_scope: Vec<String>,
    #[serde(default)]
    pub allowed_command_classes: Vec<String>,
    pub execution_state: String,
    #[serde(default)]
    pub retry_classification: Option<String>,
    #[serde(default)]
    pub last_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatRendererSession {
    pub session_id: String,
    pub chat_session_id: String,
    pub renderer: ChatRendererKind,
    pub workspace_root: String,
    pub entry_document: String,
    #[serde(default)]
    pub preview_url: Option<String>,
    #[serde(default)]
    pub preview_process_id: Option<u32>,
    #[serde(default)]
    pub scaffold_recipe_id: Option<String>,
    #[serde(default)]
    pub presentation_variant_id: Option<String>,
    #[serde(default)]
    pub package_manager: Option<String>,
    pub status: String,
    pub verification_status: String,
    #[serde(default)]
    pub receipts: Vec<ChatBuildReceipt>,
    #[serde(default)]
    pub current_worker_execution: Option<ChatCodeWorkerLease>,
    pub current_tab: String,
    #[serde(default)]
    pub available_tabs: Vec<String>,
    #[serde(default)]
    pub ready_tabs: Vec<String>,
    pub retry_count: u32,
    #[serde(default)]
    pub last_failure_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactSession {
    pub session_id: String,
    pub thread_id: String,
    pub artifact_id: String,
    #[serde(default)]
    pub origin_prompt_event_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub current_lens: String,
    pub navigator_backing_mode: String,
    #[serde(default)]
    pub navigator_nodes: Vec<ChatArtifactNavigatorNode>,
    #[serde(default)]
    pub attached_artifact_ids: Vec<String>,
    #[serde(default)]
    pub available_lenses: Vec<String>,
    pub materialization: ChatArtifactMaterializationContract,
    pub outcome_request: ChatOutcomeRequest,
    pub artifact_manifest: ChatArtifactManifest,
    pub verified_reply: ChatVerifiedReply,
    pub lifecycle_state: ChatArtifactLifecycleState,
    pub status: String,
    #[serde(default)]
    pub active_revision_id: Option<String>,
    #[serde(default)]
    pub revisions: Vec<ChatArtifactRevision>,
    #[serde(default)]
    pub taste_memory: Option<ChatArtifactTasteMemory>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<ChatArtifactExemplar>,
    #[serde(default)]
    pub retrieved_sources: Vec<ArtifactSourceReference>,
    #[serde(default)]
    pub selected_targets: Vec<ChatArtifactSelectionTarget>,
    #[serde(default)]
    pub widget_state: Option<ChatRetainedWidgetState>,
    #[serde(default)]
    pub ux_lifecycle: Option<ChatArtifactUxLifecycle>,
    #[serde(default)]
    pub active_operator_run: Option<ArtifactOperatorRun>,
    #[serde(default)]
    pub operator_run_history: Vec<ArtifactOperatorRun>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub build_session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub renderer_session_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildArtifactSession {
    pub session_id: String,
    pub chat_session_id: String,
    pub workspace_root: String,
    pub entry_document: String,
    #[serde(default)]
    pub preview_url: Option<String>,
    #[serde(default)]
    pub preview_process_id: Option<u32>,
    pub scaffold_recipe_id: String,
    #[serde(default)]
    pub presentation_variant_id: Option<String>,
    pub package_manager: String,
    pub build_status: String,
    pub verification_status: String,
    #[serde(default)]
    pub receipts: Vec<ChatBuildReceipt>,
    pub current_worker_execution: ChatCodeWorkerLease,
    pub current_lens: String,
    #[serde(default)]
    pub available_lenses: Vec<String>,
    #[serde(default)]
    pub ready_lenses: Vec<String>,
    pub retry_count: u32,
    #[serde(default)]
    pub last_failure_summary: Option<String>,
}
